"""Agent rename (PATCH) + empty-name is rejected on create and update."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "L" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@x.io").first():
            db.add(User(email="admin@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def test_agent_edit():
    _seed()
    with TestClient(app) as c:
        c.post("/login", data={"email": "admin@x.io", "password": "supersecret"})
        c.post("/api/nodes", json={"name": "n1", "public_addr": "1.2.3.4", "subdomain_host": "rc-tunnel.com"})

        # empty / whitespace name rejected on create (422 from schema)
        assert c.post("/api/agents", json={"name": "", "node_id": 1}).status_code == 422
        assert c.post("/api/agents", json={"name": "   ", "node_id": 1}).status_code == 422

        # valid create, name is stripped
        r = c.post("/api/agents", json={"name": "  edge1  ", "node_id": 1})
        assert r.status_code == 200, r.text
        aid = r.json()["id"]
        assert r.json()["name"] == "edge1"

        # rename works
        r = c.patch(f"/api/agents/{aid}", json={"name": "edge-renamed"})
        assert r.status_code == 200 and r.json()["name"] == "edge-renamed", r.text

        # empty rename rejected
        assert c.patch(f"/api/agents/{aid}", json={"name": ""}).status_code == 422

        # duplicate name rejected
        c.post("/api/agents", json={"name": "other", "node_id": 1})
        assert c.patch(f"/api/agents/{aid}", json={"name": "other"}).status_code == 409

        # dashboard shows the Edit control
        h = c.get("/").text
        assert "editAgent(" in h and "saveAgent(" in h

    print("AGENT-EDIT OK")


if __name__ == "__main__":
    test_agent_edit()
