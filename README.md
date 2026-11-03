# darkride-world-check

A small service that tells a Darkride world server whether people outside its network can reach it. The world
server's **Check my world** (the overview of its admin pages) asks it, and shows the answer on its "Reachable from
outside" and "Service ports" lines.

A server can't find this out by itself: testing your own public address from inside your network is unreliable,
because some routers loop it back and some don't. Something on the internet has to knock.

## What it checks

It checks whatever address the request came from (the world server's own internet address):

| | How | A good result |
|---|---|---|
| World port (UDP, 40102 by default) | A connect request whose protocol version can't match, labelled `darkride-world-check`. The world server sends back one "denied" packet and logs `Protocol Version mismatch`. | Answered |
| Service ports (UDP, up to 8) | One ICE ping each. A running service sends back one reply of the same size. | Answered |
| Admin ports (TCP, 40100 and 40101 by default) | A plain connect, with nothing sent. | **Closed** |

Each port gets up to 3 small packets, 1.5 s apart, and then it stops.

## Safety

- **Only the caller's own address is checked.** The request names ports, never an address. Behind a reverse proxy on
  the same machine (`--trust-proxy`), the address comes from the proxy's `X-Forwarded-For`, and only when the
  connection comes from this machine.
- Public addresses only, unless it's started with `--allow-private` for testing on one network.
- One check per address a minute, 4 at once, requests up to 4 KB, at most 8 service ports and 2 admin ports.
- Nothing is stored but one log line per check (the address and what answered).

## Run

Python 3.9 or later, standard library only.

```bash
python3 world_check.py --bind 127.0.0.1 --port 8711 --trust-proxy
```

Put it behind a reverse proxy with HTTPS (Caddy: `reverse_proxy 127.0.0.1:8711`), and enter the URL in the world
server's settings (Settings > Connection > *Outside check service*).

```http
POST /check
{"world_port": 40102, "service_ports": [40110, 40111], "admin_ports": [40100, 40101]}
```

The answer looks like this:

```json
{"address": "203.0.113.5", "checked_at": 1793720000000,
 "world": {"port": 40102, "answered": true, "tries": 1, "ms": 33},
 "services": [{"port": 40110, "answered": true, "tries": 1, "ms": 35}],
 "admin": [{"port": 40100, "open": false}], "version": "0.1.0"}
```

## Tests

```bash
python3 -m unittest discover -s tests
```
