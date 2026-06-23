"""Phase 1 end-to-end: auth, CRUD, enrollment (CSR signing), config generation."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "test-secret-please-change"
os.environ["RCTUNNEL_PUBLIC_BASE_URL"] = "https://rc-tunnel.com"

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.models import Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402


def _seed_admin():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@rc-tunnel.com").first():
            db.add(User(email="admin@rc-tunnel.com", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def test_phase1_flow():
    _seed_admin()
    with TestClient(app) as c:
        # login
        r = c.post("/api/auth/login", json={"email": "admin@rc-tunnel.com", "password": "supersecret"})
        assert r.status_code == 200, r.text
        tok = r.json()["access_token"]
        H = {"Authorization": f"Bearer {tok}"}

        # wrong password rejected
        assert c.post("/api/auth/login", json={"email": "admin@rc-tunnel.com", "password": "nope"}).status_code == 401
        # unauth list rejected
        assert c.get("/api/nodes").status_code == 401

        # create node
        r = c.post("/api/nodes", headers=H, json={
            "name": "edge1", "public_addr": "185.230.138.218", "subdomain_host": "rc-tunnel.com"})
        assert r.status_code == 200, r.text
        node = r.json()
        assert node["control_port"] == 7000

        # rctd.yml export (rctunnel-engine data-plane config — flat YAML)
        r = c.get(f"/api/nodes/{node['id']}/rctd.yml", headers=H)
        assert r.status_code == 200
        assert 'control: ":7000"' in r.text
        assert "127.0.0.1:8090" in r.text          # vhost
        assert "cert:" in r.text and "ca:" in r.text

        # create agent → get token + install command
        r = c.post("/api/agents", headers=H, json={"name": "srv-dev-01", "node_id": node["id"]})
        assert r.status_code == 200, r.text
        agent = r.json()
        assert agent["status"] == "offline"
        assert "curl -fsSL https://rc-tunnel.com/dl/install.sh" in agent["install_command"]
        assert "--token" in agent["install_command"]
        bootstrap = agent["agent_token"]

        # create tunnels of several types
        assert c.post(f"/api/agents/{agent['id']}/tunnels", headers=H, json={
            "name": "ssh", "type": "tcp", "local_port": 22, "remote_port": 2222}).status_code == 200
        assert c.post(f"/api/agents/{agent['id']}/tunnels", headers=H, json={
            "name": "news", "type": "http", "local_port": 8080, "subdomain": "news"}).status_code == 200
        # invalid: http without subdomain/custom_domains (tcp w/o remote_port now auto-allocates)
        assert c.post(f"/api/agents/{agent['id']}/tunnels", headers=H, json={
            "name": "bad", "type": "http", "local_port": 1}).status_code == 422

        tunnels = c.get(f"/api/agents/{agent['id']}/tunnels", headers=H).json()
        assert {t["name"] for t in tunnels} == {"ssh", "news"}

        # --- enrollment: agent generates key+CSR locally, master signs ---
        akey = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
               .sign(akey, hashes.SHA256()))
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        # wrong bootstrap token rejected
        assert c.post("/api/agents/enroll", json={"bootstrap_token": "wrong", "csr_pem": csr_pem}).status_code == 401

        r = c.post("/api/agents/enroll", json={
            "bootstrap_token": bootstrap, "csr_pem": csr_pem, "os": "linux", "arch": "amd64"})
        assert r.status_code == 200, r.text
        enr = r.json()
        cert = x509.load_pem_x509_certificate(enr["agent_cert_pem"].encode())
        assert cert.subject.rfc4514_string() == f"CN=agent.{agent['id']}"
        # cert bound to the agent's locally-generated key (private key never sent)
        cert_pub = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        akey_pub = akey.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        assert cert_pub == akey_pub
        assert enr["node_token"] and len(enr["node_token"]) > 10   # secret returned to agent, hidden in NodeOut

        # agent now reflects os/arch
        agents = c.get("/api/agents", headers=H).json()
        assert agents[0]["os"] == "linux" and agents[0]["arch"] == "amd64"

    print("PHASE 1 OK")


if __name__ == "__main__":
    test_phase1_flow()
