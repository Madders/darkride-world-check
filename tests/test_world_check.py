import json
import os
import socket
import struct
import sys
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import world_check  # noqa: E402


class FakeServer(threading.Thread):
    """A UDP port that answers like a world server (connect request -> denied) or a service (ICE ping -> reply)."""

    def __init__(self, answer):
        super().__init__(daemon=True)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.answer = answer
        self.received = []
        self.running = True

    def run(self):
        while self.running:
            try:
                data, source = self.socket.recvfrom(2048)
            except (socket.timeout, ConnectionResetError):
                continue
            self.received.append(data)
            reply = self.answer(data)
            if reply:
                self.socket.sendto(reply, source)

    def stop(self):
        self.running = False
        self.join()
        self.socket.close()


def world_answer(data):
    if world_check.packet_type(data) == world_check.CONNECT_REQUEST:
        return struct.pack("<I", 1) + bytes([world_check.CONNECTION_DENIED, 17, 0])


def service_answer(data):
    if world_check.packet_type(data) == world_check.ICE_PING:
        return struct.pack("<I", 1) + bytes([world_check.ICE_PING_REPLY, 17]) + data[6:]


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CheckTests(unittest.TestCase):
    def setUp(self):
        world_check.WAIT_SECONDS = 0.3
        self.world = FakeServer(world_answer)
        self.service = FakeServer(service_answer)
        self.world.start()
        self.service.start()

    def tearDown(self):
        self.world.stop()
        self.service.stop()

    def test_answers_and_silence(self):
        quiet = free_udp_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as admin:
            admin.bind(("127.0.0.1", 0))
            admin.listen(1)
            admin_port = admin.getsockname()[1]
            result = world_check.check("127.0.0.1", self.world.port, [self.service.port, quiet],
                                       [admin_port, free_udp_port()])
        self.assertTrue(result["world"]["answered"])
        self.assertTrue(result["services"][0]["answered"])
        self.assertFalse(result["services"][1]["answered"])
        self.assertEqual([a["open"] for a in result["admin"]], [True, False])

    def test_sends_only_one_packet_to_a_port_that_answers(self):
        world_check.check("127.0.0.1", self.world.port, [self.service.port], [])
        self.assertEqual(len(self.world.received), 1)
        self.assertEqual(len(self.service.received), 1)
        self.assertIn(world_check.MARKER, self.world.received[0])

    def test_gives_up_after_a_few_tries(self):
        silent = FakeServer(lambda data: None)
        silent.start()
        try:
            result = world_check.check("127.0.0.1", silent.port, [], [])
        finally:
            silent.stop()
        self.assertFalse(result["world"]["answered"])
        self.assertEqual(len(silent.received), world_check.TRIES)


class RequestTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(world_check.parse_request(b""), (40102, [], [40100, 40101]))

    def test_refuses_bad_ports_and_too_many(self):
        for body in ({"world_port": 0}, {"world_port": "40102"}, {"world_port": True},
                     {"service_ports": [70000]}, {"service_ports": "40110"},
                     {"service_ports": list(range(40110, 40110 + world_check.MAX_SERVICE_PORTS + 1))},
                     {"admin_ports": [1, 2, 3]}, ["not", "an", "object"]):
            with self.assertRaises(ValueError, msg=body):
                world_check.parse_request(json.dumps(body).encode())

    def test_no_address_field_is_read(self):
        # whatever the request says, the address checked is the caller's (see HTTPTests)
        world_port, _, _ = world_check.parse_request(json.dumps({"address": "198.51.100.7"}).encode())
        self.assertEqual(world_port, 40102)


class HTTPTests(unittest.TestCase):
    def start(self, trust_proxy=False, allow_private=False):
        world_check.Handler.trust_proxy = trust_proxy
        world_check.Handler.allow_private = allow_private
        world_check.Handler.limits = world_check.Limits()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), world_check.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        return self.server.server_address[1]

    def post(self, port, body, headers=None):
        connection = HTTPConnection("127.0.0.1", port, timeout=20)
        connection.request("POST", "/check", json.dumps(body), headers or {})
        try:
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_refuses_a_private_caller(self):
        status, body = self.post(self.start(), {"admin_ports": []})
        self.assertEqual(status, 400)
        self.assertIn("127.0.0.1", body["error"])

    def test_checks_the_caller_and_limits_it(self):
        world_check.WAIT_SECONDS = 0.2
        port = self.start(allow_private=True)
        status, body = self.post(port, {"world_port": free_udp_port(), "admin_ports": []})
        self.assertEqual((status, body["address"]), (200, "127.0.0.1"))
        status, body = self.post(port, {"world_port": free_udp_port(), "admin_ports": []})
        self.assertEqual(status, 429)

    def test_forwarded_header_ignored_unless_trusted(self):
        port = self.start(allow_private=False)
        status, body = self.post(port, {}, {"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(status, 400)  # still the loopback caller, so refused

    def test_forwarded_header_from_a_local_proxy(self):
        world_check.WAIT_SECONDS = 0.2
        port = self.start(trust_proxy=True, allow_private=True)
        status, body = self.post(port, {"world_port": free_udp_port(), "admin_ports": []},
                                 {"X-Forwarded-For": "127.0.0.2"})
        self.assertEqual((status, body["address"]), (200, "127.0.0.2"))


if __name__ == "__main__":
    unittest.main()
