"""Detect the agent's primary LAN IPv4 (SPEC §6.1).

The agent is the sole source of its own LAN IP. 'auto' in a tunnel's localIP is
resolved here, never on the master.
"""

from __future__ import annotations

import socket


def detect_primary_ipv4() -> str:
    # Primary route trick: the OS picks the egress interface for this UDP dial;
    # no packet is actually sent. Gives the LAN IP that reaches the internet.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass

    # Fallback: first non-loopback IPv4 across interfaces.
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                return ip
    except OSError:
        pass

    return "127.0.0.1"


def resolve(local_ip: str) -> str:
    return detect_primary_ipv4() if local_ip == "auto" else local_ip
