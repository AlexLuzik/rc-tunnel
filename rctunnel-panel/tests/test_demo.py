"""Public read-only demo account: passwordless sign-in, can view, cannot mutate."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "L" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"
os.environ["RCTUNNEL_DEMO_MODE"] = "true"  # this suite exercises the public demo seed

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, Team, User  # noqa: E402


def test_demo():
    init_db()  # seeds the Demo team + demo user (+ agent/tunnels if a node exists)
    with SessionLocal() as db:
        demo = db.query(User).filter(User.email == "demo@rc-tunnel.com").first()
        assert demo is not None and demo.role == Role.demo
        assert db.query(Team).filter(Team.name == "Demo").first() is not None

    with TestClient(app) as c:
        # passwordless public sign-in
        r = c.get("/demo", follow_redirects=False)
        assert r.status_code == 303
        assert "rctunnel_token" in c.cookies

        # can view
        assert c.get("/").status_code == 200
        assert c.get("/activity").status_code == 200

        # cannot mutate anything — every state change is blocked at the chokepoint
        assert c.post("/api/teams", json={"name": "hackteam"}).status_code == 403
        assert c.patch("/api/auth/me", json={"email": "x@y.io"}).status_code == 403
        assert c.post("/api/agents", json={"name": "x", "node_id": 1}).status_code == 403
        assert c.delete("/api/tunnels/1").status_code == 403

        # banner shows the demo is read-only
        assert "Read-only demo" in c.get("/").text
        # nothing was actually created
    with SessionLocal() as db:
        assert db.query(Team).filter(Team.name == "hackteam").first() is None

    print("DEMO OK")


if __name__ == "__main__":
    test_demo()
