"""Phase 4: UI flow — login sets cookie, dashboard renders, fetch-style mutations work."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "y" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"   # TestClient is http
os.environ["RCTUNNEL_NODE_PUBLIC_ADDR"] = "127.0.0.1"  # system node addr shown on agent detail

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@rc.io").first():
            db.add(User(email="admin@rc.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def test_ui():
    _seed()
    with TestClient(app) as c:
        # anonymous dashboard -> redirect to login
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"

        # login page renders
        assert "Sign in" in c.get("/login").text

        # bad login -> 401 with message
        r = c.post("/login", data={"email": "admin@rc.io", "password": "nope"}, follow_redirects=False)
        assert r.status_code == 401 and "Invalid credentials" in r.text

        # good login -> sets cookie, redirects
        r = c.post("/login", data={"email": "admin@rc.io", "password": "supersecret"}, follow_redirects=False)
        assert r.status_code == 303
        assert "rctunnel_token" in c.cookies

        # dashboard now renders for the logged-in admin (node is system-managed, not shown)
        html = c.get("/").text
        assert "Dashboard" in html and "Agents" in html

        # cookie authorizes the JSON API too (same-origin fetch model)
        assert c.post("/api/nodes", json={
            "name": "edge1", "public_addr": "127.0.0.1", "subdomain_host": "localhost"}).status_code == 200
        r = c.post("/api/agents", json={"name": "a1", "node_id": 1})
        assert r.status_code == 200
        assert "install.sh" in r.json()["install_command"]

        # dashboard shows the agent + offline badge
        html = c.get("/").text
        assert "a1" in html and "offline" in html

        # agent detail page: install command + tunnel form
        r = c.post("/api/agents/1/tunnels", json={
            "name": "ssh", "type": "tcp", "local_port": 22, "remote_port": 2222})
        assert r.status_code == 200
        detail = c.get("/agents/1").text
        assert "Install command" in detail and "curl -fsSL" in detail
        assert "ssh" in detail and "127.0.0.1:2222" in detail

        # logout clears cookie
        r = c.get("/logout", follow_redirects=False)
        assert r.status_code == 303

    print("PHASE 4 OK")


if __name__ == "__main__":
    test_ui()
