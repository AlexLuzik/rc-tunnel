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
from rctunnel_panel.control.server import _clean_telemetry  # noqa: E402


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

    # --- agent telemetry sanitizer (markup/control chars stripped, type/len bound) ---
    assert _clean_telemetry("linux/amd64") == "linux/amd64"
    assert _clean_telemetry("a<b'c\"d`e\\f") == "abcdef"     # dangerous chars removed
    assert _clean_telemetry(1234) is None                    # non-str rejected
    assert _clean_telemetry("") is None
    assert len(_clean_telemetry("v" * 100, 16)) <= 16

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

        # --- /demo is gated on demo_mode (off here) -> redirects, no demo session ---
        r = c.get("/demo", follow_redirects=False)
        assert r.status_code == 303 and r.headers.get("location") == "/login"

        # --- update_tunnel re-checks subdomain depth (was create-only) ---
        rt = c.post(f"/api/agents/{aid}/tunnels",
                    json={"name": "web1", "type": "http", "local_port": 8080, "subdomain": "ok"})
        assert rt.status_code == 200, rt.text
        tid = rt.json()["id"]
        assert c.patch(f"/api/tunnels/{tid}", json={"subdomain": "a.b.c.d.e.f"}).status_code == 422

        # --- JWT revocation on password change (token_version) ---
        # (do this last with the cookie — it also invalidates the cookie session)
        tok = c.post("/api/auth/login", json={"email": "admin@x.io", "password": "supersecret"}).json()["access_token"]
        H = {"Authorization": f"Bearer {tok}"}
        assert c.get("/api/auth/me", headers=H).status_code == 200
        assert c.patch("/api/auth/me", headers=H,
                       json={"current_password": "supersecret", "new_password": "supersecret2"}).status_code == 200
        assert c.get("/api/auth/me", headers=H).status_code == 401   # old token revoked
        assert c.post("/api/auth/login",
                      json={"email": "admin@x.io", "password": "supersecret2"}).status_code == 200

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
