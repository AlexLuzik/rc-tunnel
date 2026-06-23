"""Team admin role: only admin/team_admin can connect agents to a team."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "L" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "root@x.io").first():
            db.add(User(email="root@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def _login(c, email, pw):
    return c.post("/api/auth/login", json={"email": email, "password": pw}).json()["access_token"]


def test_team_admin():
    _seed()
    with TestClient(app) as c:
        root = {"Authorization": f"Bearer {_login(c, 'root@x.io', 'supersecret')}"}
        # node (global) + team
        nid = c.post("/api/nodes", headers=root, json={"name": "n1", "public_addr": "1.2.3.4",
                                                       "subdomain_host": "rc-tunnel.com"}).json()["id"]
        tid = c.post("/api/teams", headers=root, json={"name": "acme"}).json()["id"]
        # a team_admin and a plain member in that team
        ta = c.post("/api/auth/users", headers=root, json={"email": "ta@x.io", "password": "password1",
                                                           "role": "team_admin", "team_id": tid}).json()
        mem = c.post("/api/auth/users", headers=root, json={"email": "m@x.io", "password": "password1",
                                                            "role": "user", "team_id": tid}).json()
        assert ta["role"] == "team_admin", ta

        # plain member CANNOT connect an agent
        mh = {"Authorization": f"Bearer {_login(c, 'm@x.io', 'password1')}"}
        assert c.post("/api/agents", headers=mh, json={"name": "a-mem", "node_id": nid}).status_code == 403

        # team admin CAN
        th = {"Authorization": f"Bearer {_login(c, 'ta@x.io', 'password1')}"}
        r = c.post("/api/agents", headers=th, json={"name": "a-ta", "node_id": nid})
        assert r.status_code == 200, r.text

        # global admin CAN; and can promote the member to team_admin
        assert c.patch(f"/api/auth/users/{mem['id']}", headers=root, json={"role": "team_admin"}).json()["role"] == "team_admin"
        mh2 = {"Authorization": f"Bearer {_login(c, 'm@x.io', 'password1')}"}
        assert c.post("/api/agents", headers=mh2, json={"name": "a-mem2", "node_id": nid}).status_code == 200

    print("TEAM-ADMIN OK")


if __name__ == "__main__":
    test_team_admin()
