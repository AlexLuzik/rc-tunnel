"""In-memory per-IP login throttle (single master process).

Shared by the JSON API (api/auth.py) and the HTML form (web/routes.py) so the
window is enforced across both login surfaces. The client IP is only meaningful
when uvicorn runs with proxy_headers + forwarded_allow_ips behind Caddy.
"""

from __future__ import annotations

import time

from fastapi import HTTPException, status

WINDOW = 300      # seconds
MAX = 8           # failures per IP per window before throttling
MAX_IPS = 50000   # cap tracked IPs so a distributed attacker can't grow this unbounded
_fails: dict[str, list[float]] = {}


def _sweep() -> None:
    """Drop entries whose failures have all aged out (bounds memory)."""
    cutoff = time.monotonic() - WINDOW
    for ip in [k for k, v in _fails.items() if not v or v[-1] <= cutoff]:
        _fails.pop(ip, None)


def _recent(ip: str) -> list[float]:
    cutoff = time.monotonic() - WINDOW
    fails = [t for t in _fails.get(ip, []) if t > cutoff]
    if fails:
        _fails[ip] = fails
    else:
        _fails.pop(ip, None)
    return fails


def guard(ip: str | None) -> None:
    if ip and len(_recent(ip)) >= MAX:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed attempts — try again later")


def record_fail(ip: str | None) -> None:
    if not ip:
        return
    if len(_fails) >= MAX_IPS:
        _sweep()
        if len(_fails) >= MAX_IPS:   # still full of live attackers → stop tracking new IPs
            return
    _fails.setdefault(ip, []).append(time.monotonic())


def clear(ip: str | None) -> None:
    if ip:
        _fails.pop(ip, None)
