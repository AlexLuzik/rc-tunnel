"""Multi-tenancy: team isolation, cross-team denial, global subdomain uniqueness."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "t" * 40

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402


def _seed_admin():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@x.io").first():
            db.add(User(email="admin@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def _login(c, email, pw):
    return {"Authorization": "Bearer " + c.post("/api/auth/login",
            json={"email": email, "password": pw}).json()["access_token"]}


def test_team_isolation():
    _seed_admin()
    with TestClient(app) as c:
        A = _login(c, "admin@x.io", "supersecret")

        # admin sets up infra + two teams + two users
        c.post("/api/nodes", headers=A, json={"name": "n1", "public_addr": "1.2.3.4", "subdomain_host": "rc-tunnel.com"})
        ta = c.post("/api/teams", headers=A, json={"name": "team-a"}).json()["id"]
        tb = c.post("/api/teams", headers=A, json={"name": "team-b"}).json()["id"]
        assert c.post("/api/auth/users", headers=A, json={"email": "ua@x.io", "password": "password1", "role": "team_admin", "team_id": ta}).status_code == 200
        assert c.post("/api/auth/users", headers=A, json={"email": "ub@x.io", "password": "password1", "role": "team_admin", "team_id": tb}).status_code == 200

        UA = _login(c, "ua@x.io", "password1")
        UB = _login(c, "ub@x.io", "password1")

        # userA creates an agent + http tunnel
        aid_a = c.post("/api/agents", headers=UA, json={"name": "a-agent", "node_id": 1}).json()["id"]
        assert c.post(f"/api/agents/{aid_a}/tunnels", headers=UA,
                      json={"name": "web", "type": "http", "local_port": 80, "subdomain": "alpha"}).status_code == 200

        # userB sees none of team-a's agents
        assert c.get("/api/agents", headers=UB).json() == []
        # userA sees their own
        assert [a["name"] for a in c.get("/api/agents", headers=UA).json()] == ["a-agent"]

        # userB cannot read or mutate team-a's agent/tunnels
        assert c.get(f"/api/agents/{aid_a}/tunnels", headers=UB).status_code == 404
        assert c.post(f"/api/agents/{aid_a}/tunnels", headers=UB,
                      json={"name": "x", "type": "tcp", "local_port": 1, "remote_port": 10001}).status_code == 404
        # find team-a's tunnel id (as userA) and try to delete as userB
        tid = c.get(f"/api/agents/{aid_a}/tunnels", headers=UA).json()[0]["id"]
        assert c.delete(f"/api/tunnels/{tid}", headers=UB).status_code == 404

        # subdomains are namespaced per team: team-b MAY reuse "alpha" (different namespace)
        aid_b = c.post("/api/agents", headers=UB, json={"name": "b-agent", "node_id": 1}).json()["id"]
        assert c.post(f"/api/agents/{aid_b}/tunnels", headers=UB,
                      json={"name": "web", "type": "http", "local_port": 80, "subdomain": "alpha"}).status_code == 200
        # but within team-b it must stay unique
        assert c.post(f"/api/agents/{aid_b}/tunnels", headers=UB,
                      json={"name": "web2", "type": "http", "local_port": 81, "subdomain": "alpha"}).status_code == 409

        # admin sees everything
        assert {a["name"] for a in c.get("/api/agents", headers=A).json()} == {"a-agent", "b-agent"}

        # agent created by a team member is owned by that team
        assert c.get("/api/agents", headers=UA).json()[0]["team_id"] == ta

    print("TEAMS OK")


if __name__ == "__main__":
    test_team_isolation()
