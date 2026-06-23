"""Wave-1 hardening: server-cert auto-renewal, login rate-limit, reserved
subdomains, custom-domain validation."""

import os
import tempfile
from pathlib import Path

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "L" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"

from cryptography import x509  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel import pki, ratelimit  # noqa: E402
from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.deps import get_ca  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@x.io").first():
            db.add(User(email="admin@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def _serial(path) -> int:
    return x509.load_pem_x509_certificate(Path(path).read_bytes()).serial_number


def test_server_cert_auto_renews():
    ca = get_ca()
    crt1, _ = ca.ensure_server_cert(["x.io", "localhost", "127.0.0.1"])
    s1 = _serial(crt1)
    # fresh cert is NOT re-issued
    crt2, _ = ca.ensure_server_cert(["x.io", "localhost", "127.0.0.1"])
    assert _serial(crt2) == s1, "fresh cert should not be re-issued"
    # simulate near-expiry → must re-issue (new serial)
    orig = pki._RENEW_BEFORE_DAYS
    pki._RENEW_BEFORE_DAYS = 100000
    try:
        crt3, _ = ca.ensure_server_cert(["x.io", "localhost", "127.0.0.1"])
        assert _serial(crt3) != s1, "near-expiry cert must be re-issued"
    finally:
        pki._RENEW_BEFORE_DAYS = orig
    print("CERT-RENEW OK")


def test_login_rate_limit():
    _seed()
    ratelimit._fails.clear()
    with TestClient(app) as c:
        for _ in range(ratelimit.MAX):
            assert c.post("/api/auth/login",
                          json={"email": "admin@x.io", "password": "wrong"}).status_code == 401
        # next attempt is throttled — even a correct password is refused
        assert c.post("/api/auth/login",
                      json={"email": "admin@x.io", "password": "supersecret"}).status_code == 429
        # the HTML form shares the same window
        assert c.post("/login", data={"email": "admin@x.io", "password": "supersecret"},
                      follow_redirects=False).status_code == 429
    ratelimit._fails.clear()
    print("RATE-LIMIT OK")


def test_reserved_and_custom_domains():
    _seed()
    ratelimit._fails.clear()
    with TestClient(app) as c:
        c.post("/login", data={"email": "admin@x.io", "password": "supersecret"})
        c.post("/api/nodes", json={"name": "n1", "public_addr": "1.2.3.4", "subdomain_host": "rc-tunnel.com"})
        aid = c.post("/api/agents", json={"name": "a1", "node_id": 1}).json()["id"]

        # reserved subdomain rejected (DNS/infra name)
        r = c.post(f"/api/agents/{aid}/tunnels",
                   json={"name": "t-ns", "type": "http", "local_port": 80, "subdomain": "ns1"})
        assert r.status_code == 422, r.text

        # P0 REGRESSION: a comma in subdomain would inject extra hosts into the
        # signed grant (cross-tenant hijack) — must be rejected by charset gate.
        for bad in ["victim.rc-tunnel.com,x", "ok|y", "under_score", "-lead", "tr ail"]:
            r = c.post(f"/api/agents/{aid}/tunnels",
                       json={"name": f"t-{abs(hash(bad))}", "type": "http", "local_port": 80, "subdomain": bad})
            assert r.status_code == 422, f"injection subdomain {bad!r} not rejected: {r.text}"

        # custom domain under our apex rejected (must use subdomain field)
        r = c.post(f"/api/agents/{aid}/tunnels",
                   json={"name": "t-apex", "type": "http", "local_port": 80,
                         "custom_domains": "evil.victimteam.rc-tunnel.com"})
        assert r.status_code == 422, r.text

        # malformed domain rejected
        r = c.post(f"/api/agents/{aid}/tunnels",
                   json={"name": "t-bad", "type": "http", "local_port": 80, "custom_domains": "not a domain"})
        assert r.status_code == 422, r.text

        # a valid external custom domain is accepted
        r = c.post(f"/api/agents/{aid}/tunnels",
                   json={"name": "t-ext", "type": "http", "local_port": 80, "custom_domains": "shop.acme.io"})
        assert r.status_code == 200, r.text

        # a second tunnel claiming the same external domain is refused (global uniqueness)
        r = c.post(f"/api/agents/{aid}/tunnels",
                   json={"name": "t-dup", "type": "http", "local_port": 80, "custom_domains": "shop.acme.io"})
        assert r.status_code == 409, r.text
    ratelimit._fails.clear()
    print("RESERVED+DOMAINS OK")


if __name__ == "__main__":
    test_server_cert_auto_renews()
    test_login_rate_limit()
    test_reserved_and_custom_domains()
