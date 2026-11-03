#!/usr/bin/env python3
"""darkride-world-check: tells a Darkride world server whether people outside its network can reach it.

A world server's "Check my world" (the overview of its admin pages) asks this service. The service knocks on the
world from the internet and says what answered:

- the world port (UDP, 40102 by default): a connect request whose protocol version can't match, labelled
  "darkride-world-check". The world server answers with one "denied" packet and nothing more;
- each service port (UDP): one ICE ping, which a running service answers with one reply of the same size;
- the admin ports (TCP, 40100 and 40101 by default): a plain connect, with nothing sent. These should be closed.

Safety, so the service can't be used against anyone else:
- it only checks the address the request comes from (behind a reverse proxy on this machine, the address the proxy
  passes on), never one named in the request;
- at most one check per address a minute, a few checks at once, a small request body, and a cap on ports;
- a few small packets per port, then it stops; nothing is kept but one log line per check.

Standard library only. Run: python3 world_check.py [--port 8711] [--trust-proxy] [--allow-private]
"""
import argparse
import ipaddress
import json
import logging
import socket
import struct
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.1.0"

# packet types and versions, from libraries/networking/src/udt/PacketHeaders.h
CONNECT_REQUEST, CONNECT_REQUEST_VERSION = 31, 26
CONNECTION_DENIED = 16
ICE_PING, ICE_PING_VERSION, ICE_PING_REPLY = 39, 18, 40
PING_TYPE_PUBLIC = 2
MARKER = b"darkride-world-check"

TRIES = 3
WAIT_SECONDS = 1.5
TCP_TIMEOUT_SECONDS = 3

MAX_BODY_BYTES = 4096
MAX_SERVICE_PORTS = 8
MAX_ADMIN_PORTS = 2
SECONDS_BETWEEN_CHECKS = 60
MAX_CHECKS_AT_ONCE = 4

log = logging.getLogger("world-check")


def data_packet(packet_type, version, payload):
    # an unreliable packet (sequence number 1, no flags); both types used here carry no source ID and no hash
    return struct.pack("<I", 1) + bytes([packet_type, version]) + payload


def packet_type(data):
    if len(data) < 6 or struct.unpack("<I", data[:4])[0] & 0x80000000:
        return None  # too short, or a control packet
    return data[4]


def knock(address, port, packet, expected_type):
    """Sends the packet up to TRIES times, waiting for one answer of the expected type from that port."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(WAIT_SECONDS)
        for attempt in range(1, TRIES + 1):
            started = time.monotonic()
            try:
                s.sendto(packet, (address, port))
                while True:
                    data, source = s.recvfrom(2048)
                    if source[1] == port and packet_type(data) == expected_type:
                        return {"answered": True, "tries": attempt, "ms": round((time.monotonic() - started) * 1000)}
            except socket.timeout:
                continue
            except ConnectionResetError:
                # the address said nothing listens on that port (an ICMP "port unreachable")
                return {"answered": False, "tries": attempt, "refused": True}
            except OSError as error:
                return {"answered": False, "tries": attempt, "error": error.strerror or str(error)}
        return {"answered": False, "tries": TRIES}


def tcp_open(address, port):
    try:
        with socket.create_connection((address, port), timeout=TCP_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def check(address, world_port, service_ports, admin_ports):
    connect = data_packet(CONNECT_REQUEST, CONNECT_REQUEST_VERSION,
                          uuid.uuid4().bytes + struct.pack(">I", len(MARKER)) + MARKER)
    with ThreadPoolExecutor(max_workers=1 + len(service_ports) + len(admin_ports)) as pool:
        world = pool.submit(knock, address, world_port, connect, CONNECTION_DENIED)
        services = [(port, pool.submit(knock, address, port,
                                       data_packet(ICE_PING, ICE_PING_VERSION,
                                                   uuid.uuid4().bytes + bytes([PING_TYPE_PUBLIC])),
                                       ICE_PING_REPLY))
                    for port in service_ports]
        admin = [(port, pool.submit(tcp_open, address, port)) for port in admin_ports]
        return {
            "address": address,
            "checked_at": int(time.time() * 1000),
            "world": dict(port=world_port, **world.result()),
            "services": [dict(port=port, **future.result()) for port, future in services],
            "admin": [{"port": port, "open": future.result()} for port, future in admin],
            "version": VERSION,
        }


def valid_port(value):
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def parse_request(body):
    """The ports to check, from the request's JSON; a ValueError says what's wrong."""
    try:
        request = json.loads(body or b"{}")
    except ValueError:
        raise ValueError("the request isn't JSON")
    if not isinstance(request, dict):
        raise ValueError("the request isn't a JSON object")
    world_port = request.get("world_port", 40102)
    service_ports = request.get("service_ports", [])
    admin_ports = request.get("admin_ports", [40100, 40101])
    if not valid_port(world_port):
        raise ValueError("world_port must be a port number")
    for name, ports, cap in (("service_ports", service_ports, MAX_SERVICE_PORTS),
                             ("admin_ports", admin_ports, MAX_ADMIN_PORTS)):
        if not isinstance(ports, list) or not all(valid_port(port) for port in ports):
            raise ValueError(name + " must be a list of port numbers")
        if len(ports) > cap:
            raise ValueError("at most %d %s" % (cap, name))
    return world_port, list(dict.fromkeys(service_ports)), list(dict.fromkeys(admin_ports))


class Limits:
    """One check per address per SECONDS_BETWEEN_CHECKS, and at most MAX_CHECKS_AT_ONCE at a time."""

    def __init__(self):
        self._lock = threading.Lock()
        self._last = {}
        self.running = threading.BoundedSemaphore(MAX_CHECKS_AT_ONCE)

    def wait_seconds(self, address):
        now = time.monotonic()
        with self._lock:
            # forget addresses whose wait is over, so the table stays small
            self._last = {a: t for a, t in self._last.items() if now - t < SECONDS_BETWEEN_CHECKS}
            last = self._last.get(address)
            if last is not None:
                return int(SECONDS_BETWEEN_CHECKS - (now - last)) + 1
            self._last[address] = now
            return 0


class Handler(BaseHTTPRequestHandler):
    server_version = "darkride-world-check/" + VERSION
    trust_proxy = False
    allow_private = False
    limits = None

    def log_message(self, format, *args):
        pass  # one line per check instead, below

    def reply(self, status, body, headers=None):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def caller_address(self):
        peer = self.client_address[0]
        if peer.startswith("::ffff:"):
            peer = peer[len("::ffff:"):]
        # behind a reverse proxy on this machine, the proxy names the caller; nobody else may
        if self.trust_proxy and ipaddress.ip_address(peer).is_loopback:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                peer = forwarded.split(",")[-1].strip()
        return str(ipaddress.ip_address(peer))

    def do_GET(self):
        if self.path == "/":
            self.reply(200, {"service": "darkride-world-check", "version": VERSION,
                             "check": "POST /check with {world_port, service_ports, admin_ports}"})
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/check":
            self.reply(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self.reply(413, {"error": "the request is too large"})
            return
        try:
            world_port, service_ports, admin_ports = parse_request(self.rfile.read(length))
            address = self.caller_address()
        except ValueError as error:
            self.reply(400, {"error": str(error)})
            return
        if not self.allow_private and not ipaddress.ip_address(address).is_global:
            self.reply(400, {"error": "this service only checks public addresses, and the request came from " +
                             address})
            return
        wait = self.limits.wait_seconds(address)
        if wait:
            self.reply(429, {"error": "one check a minute per address", "retry_after": wait},
                       {"Retry-After": str(wait)})
            return
        if not self.limits.running.acquire(blocking=False):
            self.reply(503, {"error": "busy, try again in a moment"}, {"Retry-After": "10"})
            return
        try:
            result = check(address, world_port, service_ports, admin_ports)
        finally:
            self.limits.running.release()
        log.info("checked %s: world %s, services %s, admin open %s", address,
                 "answered" if result["world"]["answered"] else "no answer",
                 "".join("+" if s["answered"] else "-" for s in result["services"]) or "none",
                 [a["port"] for a in result["admin"] if a["open"]] or "none")
        self.reply(200, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8711, help="port to listen on (default 8711)")
    parser.add_argument("--trust-proxy", action="store_true",
                        help="behind a reverse proxy on this machine: take the caller from X-Forwarded-For")
    parser.add_argument("--allow-private", action="store_true",
                        help="also check private and loopback callers (for testing on one network only)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    Handler.trust_proxy = args.trust_proxy
    Handler.allow_private = args.allow_private
    Handler.limits = Limits()
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    log.info("darkride-world-check %s listening on %s:%d", VERSION, args.bind, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
