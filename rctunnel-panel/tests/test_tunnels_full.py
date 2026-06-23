"""Tunnel completeness: supported types, per-proxy options, render correctness."""

import os
import sys
import tempfile
from pathlib import Path

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "z" * 40

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from rctunnel_panel.db import SessionLocal, _auto_migrate, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "a@b.io").first():
            db.add(User(email="a@b.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def test_migration_adds_columns():
    # simulate an OLD tunnels table missing the new columns, then migrate
    p = tempfile.mktemp(suffix=".db")
    eng = create_engine(f"sqlite:///{p}")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE tunnels (id INTEGER PRIMARY KEY, name VARCHAR, type VARCHAR)"))
    import rctunnel_panel.db as dbmod
    old = dbmod.engine
    dbmod.engine = eng
    try:
        dbmod._auto_migrate()
        cols = {r[1] for r in eng.connect().execute(text("PRAGMA table_info(tunnels)"))}
        assert {"use_encryption", "bandwidth_limit", "health_check_type", "http_user"} <= cols, cols
    finally:
        dbmod.engine = old
    print("migration OK:", sorted(cols))


def test_api_and_render():
    _seed()
    with TestClient(app) as c:
        tok = c.post("/api/auth/login", json={"email": "a@b.io", "password": "supersecret"}).json()["access_token"]
        H = {"Authorization": f"Bearer {tok}"}
        c.post("/api/nodes", headers=H, json={"name": "n1", "public_addr": "1.2.3.4", "subdomain_host": "rc-tunnel.com"})
        c.post("/api/agents", headers=H, json={"name": "ag", "node_id": 1})

        # supported proxy types + options
        assert c.post("/api/agents/1/tunnels", headers=H, json={
            "name": "ssh", "type": "tcp", "local_port": 22}).status_code == 200
        assert c.post("/api/agents/1/tunnels", headers=H, json={
            "name": "dns", "type": "udp", "local_port": 53}).status_code == 200
        assert c.post("/api/agents/1/tunnels", headers=H, json={
            "name": "web", "type": "http", "local_port": 8080, "subdomain": "web",
            "use_encryption": True, "use_compression": True, "bandwidth_limit": "1MB",
            "health_check_type": "http", "health_check_path": "/healthz",
            "http_user": "u", "http_password": "p"}).status_code == 200
        # validation: http without subdomain/custom_domains rejected
        assert c.post("/api/agents/1/tunnels", headers=H, json={
            "name": "bad", "type": "http", "local_port": 1}).status_code == 422

        # protocol config payload reflects everything
        from rctunnel_panel.control.manager import build_config
        cfg = build_config(1)
        names = {t["name"] for t in cfg["tunnels"]}
        assert names == {"ssh", "dns", "web"}, names
        web = next(t for t in cfg["tunnels"] if t["name"] == "web")
        assert web["use_encryption"] and web["bandwidth_limit"] == "1MB" and web["http_user"] == "u"

        # agent renders valid rctc.json from that payload
        import json as _json
        import rctunnel_agent
        ag = rctunnel_agent.Agent.__new__(rctunnel_agent.Agent)
        ag.ca_path, ag.crt_path, ag.key_path = Path("/c/ca.crt"), Path("/c/a.crt"), Path("/c/a.key")
        rctc = _json.loads(ag._render_rctc(cfg["node"], cfg["tunnels"], grant="g"))

    # assertions on rendered config — rctc supports tcp/udp/http/https only
    assert rctc["controlAddr"] and rctc["workConnAddr"] and rctc["token"] and rctc["grant"] == "g"
    assert all(p["type"] in ("tcp", "udp", "http", "https") for p in rctc["proxies"]), \
        "unsupported proxy types must be skipped"
    web = next(p for p in rctc["proxies"] if p["type"] == "http")
    assert web["customDomains"]   # http tunnel carries its FQDN(s)
    print("API + RENDER OK")


if __name__ == "__main__":
    test_migration_adds_columns()
    test_api_and_render()
    print("TUNNELS-FULL OK")
