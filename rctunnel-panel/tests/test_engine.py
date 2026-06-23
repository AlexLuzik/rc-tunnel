"""Engine flag: panel emits rctunnel config, agent renders matching rctc JSON."""

import argparse
import json
import os
import sys
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "L" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"
os.environ["RCTUNNEL_GRANT_SECRET"] = "shared-engine-secret"

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.control import manager  # noqa: E402
from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import rctunnel_agent  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@x.io").first():
            db.add(User(email="admin@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def test_engine_payload():
    _seed()
    with TestClient(app) as c:
        c.post("/login", data={"email": "admin@x.io", "password": "supersecret"})
        c.post("/api/nodes", json={"name": "n1", "public_addr": "1.2.3.4", "subdomain_host": "rc-tunnel.com"})
        aid = c.post("/api/agents", json={"name": "a1", "node_id": 1}).json()["id"]
        r = c.post(f"/api/agents/{aid}/tunnels", json={"name": "ssh", "type": "tcp",
                                                       "local_port": 22, "remote_port": 2222})
        assert r.status_code == 200, r.text

    cfg = manager.build_config(aid)
    assert cfg["node"]["workconn_port"] == 7001, cfg["node"]
    assert any(t["proxy_name"].startswith("t") for t in cfg["tunnels"]), cfg["tunnels"]

    # authorization grant: present, CN-bound to the agent, signed, scopes port 2222
    import base64
    import hashlib
    import hmac
    secret = os.environ["RCTUNNEL_GRANT_SECRET"]
    g = cfg["grant"]
    assert g, "grant must be present when grant_secret is set"
    parts = g.split("|")
    assert parts[0] == "v1" and parts[1] == f"agent.{aid}", g
    want = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), "|".join(parts[:5]).encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert parts[5] == want, "grant signature mismatch"
    assert "2222" in parts[3].split(","), f"port 2222 not scoped: {parts[3]}"
    print("ENGINE-PAYLOAD OK")


def test_render_rctc():
    args = argparse.Namespace(master_url="https://x", token="", work_dir=tempfile.mkdtemp(),
                              frpc="frpc", rctc="rctc", control_url="", control_port=8001)
    ag = rctunnel_agent.Agent(args)
    node = {"server_addr": "1.2.3.4", "server_port": 7000, "workconn_port": 7001, "token": "tok"}
    tunnels = [
        {"type": "tcp", "proxy_name": "t1", "local_ip": "127.0.0.1", "local_port": 22, "remote_port": 2222},
        {"type": "http", "proxy_name": "t2", "local_ip": "127.0.0.1", "local_port": 8080,
         "custom_domains": "news.test.rc-tunnel.com"},
        {"type": "stcp", "proxy_name": "t3", "local_ip": "127.0.0.1", "local_port": 5},  # skipped (unsupported)
    ]
    cfg = json.loads(ag._render_rctc(node, tunnels))
    assert cfg["controlAddr"] == "1.2.3.4:7000"
    assert cfg["workConnAddr"] == "1.2.3.4:7001"
    assert cfg["token"] == "tok"
    p = {x["name"]: x for x in cfg["proxies"]}
    assert "t3" not in p, "unsupported types must be skipped"
    assert p["t1"]["type"] == "tcp" and p["t1"]["remotePort"] == 2222 and p["t1"]["localAddr"] == "127.0.0.1:22"
    assert p["t2"]["customDomains"] == ["news.test.rc-tunnel.com"]
    print("RENDER-RCTC OK")


def test_agent_cert_renewal_trigger():
    """A near-expiry agent cert triggers re-enrollment; a fresh one does not."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    wd = tempfile.mkdtemp()
    args = argparse.Namespace(master_url="https://x", token="t", work_dir=wd,
                              frpc="frpc", rctc="rctc", control_url="", control_port=8001)
    ag = rctunnel_agent.Agent(args)

    def _issue(days: int) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        crt = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent.1")]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ca")]))
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(now - dt.timedelta(minutes=5))
               .not_valid_after(now + dt.timedelta(days=days))
               .sign(key, hashes.SHA256()))
        from cryptography.hazmat.primitives import serialization
        ag.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ag.crt_path.write_text(crt.public_bytes(serialization.Encoding.PEM).decode())
        ag.ca_path.write_text("ca")

    calls = []
    ag._enroll = lambda: calls.append(1)  # type: ignore[method-assign]

    _issue(5)  # near expiry
    assert ag._cert_days_left() <= 5
    ag.ensure_enrolled()
    assert calls, "near-expiry cert must trigger re-enroll"

    _issue(300)  # fresh
    calls.clear()
    ag.ensure_enrolled()
    assert not calls, "fresh cert must NOT re-enroll"
    print("AGENT-CERT-RENEW OK")


if __name__ == "__main__":
    test_engine_payload()
    test_render_rctc()
    test_agent_cert_renewal_trigger()
