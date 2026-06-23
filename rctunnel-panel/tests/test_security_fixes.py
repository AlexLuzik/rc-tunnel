"""Regression tests for the security review fixes:
   name charset allowlist, /enroll rate-limit, CSV formula-injection safing,
   and tojson escaping of names in inline JS.
"""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "S" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.models import Agent, Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.web.routes import _csv_safe  # noqa: E402


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@x.io").first():
            db.add(User(email="admin@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def test_security_fixes():
    _seed()

    # --- CSV formula-injection safing (pure function) ---
    assert _csv_safe("=cmd|'/C calc'!A1") == "'=cmd|'/C calc'!A1"
    assert _csv_safe("-2+3") == "'-2+3"
    assert _csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert _csv_safe("normal") == "normal"
    assert _csv_safe(None) == ""

    with TestClient(app) as c:
        c.post("/login", data={"email": "admin@x.io", "password": "supersecret"})

        # --- name charset allowlist: quote/angle/control chars rejected (422) ---
        for bad in ["x' onerror", 'a"b', "a<b", "ok`", "back\\slash"]:
            r = c.post("/api/agents", json={"name": bad})
            assert r.status_code == 422, (bad, r.status_code)
        # a clean name (incl. spaces/dots/dashes) is accepted
        r = c.post("/api/agents", json={"name": "edge-01 prod.v2"})
        assert r.status_code == 200, r.text
        aid = r.json()["id"]
        # bad tunnel + team names rejected too
        assert c.post(f"/api/agents/{aid}/tunnels",
                      json={"name": "t'x", "type": "tcp", "local_port": 22}).status_code == 422
        assert c.post("/api/teams", json={"name": "te<am"}).status_code == 422

        # --- tojson escaping: a stored hostile name never breaks out of the JS string ---
        with SessionLocal() as db:
            db.add(Agent(name="pwn\"'</script>", node_id=aid and 1, team_id=None))
            db.commit()
        html = c.get("/").text
        # delAgent args use a JSON (double-quoted, escaped) literal, not a raw '...'
        assert "delAgent(" in html
        assert "</script>" not in html.split("delAgent(")[1][:120]  # angle brackets escaped by tojson
        assert "'pwn" not in html  # no single-quote breakout form

        # --- /enroll rate-limit: bad tokens get throttled (429) after the window cap ---
        codes = []
        for _ in range(12):
            codes.append(c.post("/api/agents/enroll",
                                 json={"bootstrap_token": "nope", "csr_pem": "x", "os": "linux", "arch": "amd64"})
                         .status_code)
        assert 429 in codes, codes
        assert codes[0] == 401  # first attempts are auth failures, not throttled

    print("SECURITY-FIXES OK")


if __name__ == "__main__":
    test_security_fixes()
