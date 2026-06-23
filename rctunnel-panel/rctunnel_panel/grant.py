"""Panel-issued authorization grants for the data-plane engine.

A grant is a short, HMAC-signed token that tells rctd which tcp/udp ports and
http/https hosts a given agent identity (its mTLS cert CN) is allowed to
register. The engine verifies the signature + CN binding + expiry and refuses
any proxy outside the grant — this is what stops one tenant's agent from
hijacking another tenant's port or subdomain.

Wire format (must match internal/grant.Verify in the Go engine), '|'-separated:

    v1|<cn>|<exp-unix>|<port,port,...>|<host,host,...>|<sig>

sig = base64url-nopad( HMAC-SHA256(secret, "v1|<cn>|<exp>|<ports>|<hosts>") )
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

# 7-day lifetime: long enough to survive reconnects without a config push, short
# enough to bound a leaked grant. Every config change re-issues a fresh grant.
GRANT_TTL = 7 * 24 * 3600


def sign(secret: str, cn: str, ports: list[int], hosts: list[str], ttl: int = GRANT_TTL) -> str:
    """Return a signed grant for identity *cn* scoping *ports* and *hosts*."""
    exp = int(time.time()) + ttl
    ports_s = ",".join(str(p) for p in sorted({int(p) for p in ports}))
    hosts_s = ",".join(sorted({h.strip().lower() for h in hosts if h and h.strip()}))
    msg = f"v1|{cn}|{exp}|{ports_s}|{hosts_s}"
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{msg}|{sig}"
