"""N1-N4: proxy naming, subdomain namespace, auto-port, quota suspend."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "s" * 40
os.environ["RCTUNNEL_PUBLIC_DOMAIN"] = "rc-tunnel.com"
os.environ["RCTUNNEL_TCP_PORT_MIN"] = "10000"
os.environ["RCTUNNEL_TCP_PORT_MAX"] = "10005"

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.control.manager import build_config  # noqa: E402
from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, Team, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@x.io").first():
            db.add(User(email="admin@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def _login(c, e, p):
    return {"Authorization": "Bearer " + c.post("/api/auth/login", json={"email": e, "password": p}).json()["access_token"]}


def test_saas():
    _seed()
    with TestClient(app) as c:
        A = _login(c, "admin@x.io", "supersecret")
        c.post("/api/nodes", headers=A, json={"name": "n1", "public_addr": "1.2.3.4", "subdomain_host": "rc-tunnel.com"})
        ta = c.post("/api/teams", headers=A, json={"name": "Acme"}).json()
        assert ta["subdomain_label"] == "acme", ta            # auto-slug
        tb = c.post("/api/teams", headers=A, json={"name": "Beta"}).json()["id"]
        c.post("/api/auth/users", headers=A, json={"email": "ua@x.io", "password": "password1", "role": "team_admin", "team_id": ta["id"]})
        c.post("/api/auth/users", headers=A, json={"email": "ub@x.io", "password": "password1", "role": "team_admin", "team_id": tb})
        UA, UB = _login(c, "ua@x.io", "password1"), _login(c, "ub@x.io", "password1")

        aid = c.post("/api/agents", headers=UA, json={"name": "ag", "node_id": 1}).json()["id"]

        # http tunnel: namespaced under the team's subdomain label
        c.post(f"/api/agents/{aid}/tunnels", headers=UA, json={"name": "web", "type": "http", "local_port": 80, "subdomain": "app"})
        # auto-port: tcp without remote_port gets one from the pool
        p1 = c.post(f"/api/agents/{aid}/tunnels", headers=UA, json={"name": "t1", "type": "tcp", "local_port": 22}).json()
        p2 = c.post(f"/api/agents/{aid}/tunnels", headers=UA, json={"name": "t2", "type": "tcp", "local_port": 23}).json()
        assert 10000 <= p1["remote_port"] <= 10005 and p1["remote_port"] != p2["remote_port"]
        # manual port: out of range / taken
        assert c.post(f"/api/agents/{aid}/tunnels", headers=UA, json={"name": "t3", "type": "tcp", "local_port": 1, "remote_port": 99999}).status_code == 422
        assert c.post(f"/api/agents/{aid}/tunnels", headers=UA, json={"name": "t4", "type": "tcp", "local_port": 1, "remote_port": p1["remote_port"]}).status_code == 409

        # subdomain unique within team; another team may reuse it (namespaced)
        assert c.post(f"/api/agents/{aid}/tunnels", headers=UA, json={"name": "web2", "type": "http", "local_port": 81, "subdomain": "app"}).status_code == 409
        aid_b = c.post("/api/agents", headers=UB, json={"name": "agb", "node_id": 1}).json()["id"]
        assert c.post(f"/api/agents/{aid_b}/tunnels", headers=UB, json={"name": "web", "type": "http", "local_port": 80, "subdomain": "app"}).status_code == 200

        # --- inspect the generated control-plane config ---
        cfg = build_config(aid)
        tun = {t["name"]: t for t in cfg["tunnels"]}
        assert tun["web"]["proxy_name"].startswith("t") and tun["web"]["subdomain"] is None
        assert tun["web"]["custom_domains"] == "app.acme.rc-tunnel.com"    # team-namespaced FQDN

        # quota → suspend: empty config pushed
        with SessionLocal() as db:
            db.get(Team, ta["id"]).suspended = True
            db.commit()
        assert build_config(aid)["tunnels"] == []

    print("SAAS OK")


if __name__ == "__main__":
    test_saas()
