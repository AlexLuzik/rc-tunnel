"""Every interactive element of the design prototype, exercised against the real API.

Maps each onClick/onChange in rcpanel.dc.html to a working endpoint and asserts it.
"""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "g" * 40
os.environ["RCTUNNEL_DOWNLOAD_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"
os.environ["RCTUNNEL_PUBLIC_DOMAIN"] = "rc-tunnel.com"

from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402

OK = []


def check(name, cond):
    OK.append((name, bool(cond)))
    assert cond, f"FAILED: {name}"


def test_every_design_action():
    init_db()
    with SessionLocal() as db:
        db.add(User(email="admin@rc.io", password_hash=hash_password("supersecret"), role=Role.admin))
        db.commit()
    c = TestClient(app)

    # --- LOGIN screen: form sets cookie ---
    r = c.post("/login", data={"email": "admin@rc.io", "password": "supersecret"}, follow_redirects=False)
    check("login form -> cookie", r.status_code == 303 and "rctunnel_token" in c.cookies)
    check("login page renders (RC-Tunnel)", "RC-Tunnel" in c.get("/login").text)

    # --- DASHBOARD: add node, add agent, view, delete ---
    check("Add node", c.post("/api/nodes", json={"name": "edge1", "public_addr": "127.0.0.1", "subdomain_host": "rc-tunnel.com"}).status_code == 200)
    aid = c.post("/api/agents", json={"name": "a1", "node_id": 1}).json()["id"]
    check("Add agent", aid is not None)
    check("Agent onView page", c.get(f"/agents/{aid}").status_code == 200)
    a2 = c.post("/api/agents", json={"name": "tmp", "node_id": 1}).json()["id"]
    check("Agent onDelete", c.delete(f"/api/agents/{a2}").status_code == 204)

    # --- AGENT DETAIL: tunnels (add web + tcp), toggle, edit, delete ---
    th = c.post(f"/api/agents/{aid}/tunnels", json={"name": "web", "type": "http", "local_port": 8080, "subdomain": "app"})
    check("Add tunnel (http+subdomain)", th.status_code == 200)
    tid = th.json()["id"]
    tt = c.post(f"/api/agents/{aid}/tunnels", json={"name": "ssh", "type": "tcp", "local_port": 22})
    check("Add tunnel (tcp auto-port)", tt.status_code == 200 and tt.json()["remote_port"])
    check("Tunnel onToggle (disable)", c.patch(f"/api/tunnels/{tid}", json={"enabled": False}).status_code == 200)
    check("Tunnel onSave (edit fields)", c.patch(f"/api/tunnels/{tid}", json={"local_ip": "10.0.0.5", "local_port": 9090, "subdomain": "web2", "bandwidth_limit": "1MB", "use_encryption": True}).json()["bandwidth_limit"] == "1MB")
    check("Tunnel onDelete", c.delete(f"/api/tunnels/{tid}").status_code == 204)
    check("Install command present on agent page", "curl -fsSL" in c.get(f"/agents/{aid}").text)

    # --- ADMIN: teams (add/rename/quota/delete) + users (add/reassign/delete) ---
    tm = c.post("/api/teams", json={"name": "Acme"})
    check("Add team", tm.status_code == 200)
    team_id = tm.json()["id"]
    check("Team rename", c.patch(f"/api/teams/{team_id}", json={"name": "AcmeCorp"}).json()["name"] == "AcmeCorp")
    check("Team quota save", c.patch(f"/api/teams/{team_id}", json={"quota_bytes": 1048576}).json()["quota_bytes"] == 1048576)
    uu = c.post("/api/auth/users", json={"email": "u@rc.io", "password": "password1", "role": "user", "team_id": team_id})
    check("Add user", uu.status_code == 200)
    uid = uu.json()["id"]
    tm2 = c.post("/api/teams", json={"name": "Beta"}).json()["id"]
    check("User team reassign", c.post(f"/api/teams/{tm2}/members/{uid}").status_code == 200)
    check("Delete user", c.delete(f"/api/auth/users/{uid}").status_code == 204)
    check("Delete team", c.delete(f"/api/teams/{team_id}").status_code == 204)
    check("Admin page renders", "Teams" in c.get("/admin").text and "Users" in c.get("/admin").text)

    # --- PROFILE: change email + password ---
    check("Profile save email", c.patch("/api/auth/me", json={"email": "admin2@rc.io"}).status_code == 200)
    check("Profile change password", c.patch("/api/auth/me", json={"current_password": "supersecret", "new_password": "newpass12"}).status_code == 200)

    # --- ERROR PAGES (served via /_offline): not-found branch reachable ---
    check("Offline/error page", c.get("/_offline", headers={"X-Tunnel-Host": "nope.rc-tunnel.com"}).status_code in (404, 502, 503))

    # --- THEME + toasts are client-side; verify the assets are wired in the shell ---
    shell = c.get("/admin").text
    check("Theme toggle present", "toggleTheme" in shell and "data-bs-theme" in shell)
    check("Toast container present", 'id="rc-toasts"' in shell)

    print("\n=== DESIGN ACTION COVERAGE ===")
    for n, ok in OK:
        print(("  ok  " if ok else " FAIL ") + n)
    print(f"\n{sum(1 for _, o in OK if o)}/{len(OK)} design actions wired & working")


if __name__ == "__main__":
    test_every_design_action()
    print("DESIGN-E2E OK")
