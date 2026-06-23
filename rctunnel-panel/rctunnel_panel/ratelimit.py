"""In-memory per-IP login throttle (single master process).

Shared by the JSON API (api/auth.py) and the HTML form (web/routes.py) so the
window is enforced across both login surfaces. The client IP is only meaningful
when uvicorn runs with proxy_headers + forwarded_allow_ips behind Caddy.

Sync FastAPI endpoints run in a threadpool, so every access to the shared dict
is guarded by a lock (otherwise concurrent logins can corrupt it / raise
"dictionary changed size during iteration").
"""

from __future__ import annotations

import threading
import time

from fastapi import HTTPException, status

WINDOW = 300      # seconds
MAX = 8           # failures per IP per window before throttling
MAX_IPS = 50000   # cap tracked IPs so a distributed attacker can't grow this unbounded
_fails: dict[str, list[float]] = {}
_lock = threading.Lock()


def _sweep_locked() -> None:
    """Drop entries whose failures have all aged out (bounds memory). Call with _lock held."""
    cutoff = time.monotonic() - WINDOW
    for ip in [k for k, v in _fails.items() if not v or v[-1] <= cutoff]:
        _fails.pop(ip, None)


def _recent_locked(ip: str) -> list[float]:
    """Live failures for ip; prunes aged ones. Call with _lock held."""
    cutoff = time.monotonic() - WINDOW
    fails = [t for t in _fails.get(ip, []) if t > cutoff]
    if fails:
        _fails[ip] = fails
    else:
        _fails.pop(ip, None)
    return fails


def too_many(ip: str | None) -> bool:
    """True if this IP is currently throttled (non-raising; for HTML callers)."""
    if not ip:
        return False
    with _lock:
        return len(_recent_locked(ip)) >= MAX


def guard(ip: str | None) -> None:
    if too_many(ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed attempts — try again later")


def record_fail(ip: str | None) -> None:
    if not ip:
        return
    with _lock:
        if len(_fails) >= MAX_IPS:
            _sweep_locked()
            if len(_fails) >= MAX_IPS:   # still full of live attackers → stop tracking new IPs
                return
        _fails.setdefault(ip, []).append(time.monotonic())


def clear(ip: str | None) -> None:
    if not ip:
        return
    with _lock:
        _fails.pop(ip, None)
