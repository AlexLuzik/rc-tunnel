"""Activity/Fleet screens + audit middleware. OpenSearch-down is handled gracefully."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "L" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"
os.environ["RCTUNNEL_OPENSEARCH_URL"] = "http://127.0.0.1:9"  # dead -> search/count degrade to empty

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@x.io").first():
            db.add(User(email="admin@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.add(User(email="u@x.io", password_hash=hash_password("password1"), role=Role.user))
            db.commit()


def test_activity_fleet():
    _seed()
    with TestClient(app) as c:
        c.post("/login", data={"email": "admin@x.io", "password": "supersecret"})
        c.post("/api/nodes", json={"name": "n1", "public_addr": "1.2.3.4", "subdomain_host": "rc-tunnel.com"})
        c.post("/api/agents", json={"name": "a1", "node_id": 1})

        for tab, need in [("uptime", "Device uptime"), ("audit", "Audit log"), ("conn", "Requests")]:
            r = c.get(f"/activity?tab={tab}")
            assert r.status_code == 200 and need in r.text, (tab, r.status_code)
        assert c.get("/activity/export?tab=audit").status_code == 200
        assert c.get("/activity/export?tab=conn").status_code == 200

        # fleet: admin only, lists the device
        f = c.get("/fleet")
        assert f.status_code == 200 and "Fleet audit" in f.text and "a1" in f.text

        # nav exposes Activity (all) + Fleet (admin, crown)
        h = c.get("/").text
        assert "/activity" in h and "/fleet" in h and "ti-crown" in h

        # non-admin: no Fleet link, /fleet redirects
        c.post("/login", data={"email": "u@x.io", "password": "password1"})
        assert "/fleet" not in c.get("/").text
        assert c.get("/fleet", follow_redirects=False).status_code == 303

    print("LOGS-UI OK")


if __name__ == "__main__":
    test_activity_fleet()
