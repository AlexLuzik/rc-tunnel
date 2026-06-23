"""Single-use bootstrap token, admin reissue, and mTLS cert renewal (no token)."""

import os
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "E" * 40
os.environ["RCTUNNEL_COOKIE_SECURE"] = "false"

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.models import Agent, Role, User  # noqa: E402
from rctunnel_panel.security import hash_password  # noqa: E402
from rctunnel_panel.main import app  # noqa: E402
from rctunnel_panel.control.server import _renew_cert  # noqa: E402


def _csr() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _seed():
    init_db()
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == "admin@x.io").first():
            db.add(User(email="admin@x.io", password_hash=hash_password("supersecret"), role=Role.admin))
            db.commit()


def test_enroll_lifecycle():
    _seed()
    with TestClient(app) as c:
        c.post("/login", data={"email": "admin@x.io", "password": "supersecret"})
        a2 = c.post("/api/agents", json={"name": "edge1"}).json()
        tok = a2["agent_token"]
        a2id = a2["id"]

        # --- single use: first enroll OK, second with same token -> 409 ---
        r1 = c.post("/api/agents/enroll", json={"bootstrap_token": tok, "csr_pem": _csr(),
                                                "os": "linux", "arch": "amd64"})
        assert r1.status_code == 200, r1.text
        serial1 = x509.load_pem_x509_certificate(r1.json()["agent_cert_pem"].encode()).serial_number
        r2 = c.post("/api/agents/enroll", json={"bootstrap_token": tok, "csr_pem": _csr()})
        assert r2.status_code == 409, r2.status_code   # token already used

        with SessionLocal() as db:
            ag = db.get(Agent, a2id)
            assert ag.token_used is True
            assert ag.cert_serial == str(serial1)

        # --- admin reissue mints a fresh single-use token ---
        rr = c.post(f"/api/agents/{a2id}/reissue-token")
        assert rr.status_code == 200, rr.text
        newtok = rr.json()["agent_token"]
        assert newtok != tok
        # the superseded token now matches no agent at all
        assert c.post("/api/agents/enroll", json={"bootstrap_token": tok, "csr_pem": _csr()}).status_code == 401
        assert c.post("/api/agents/enroll", json={"bootstrap_token": newtok, "csr_pem": _csr(),
                                                  "os": "linux", "arch": "amd64"}).status_code == 200

        # --- mTLS renewal (no token): server signs for the cert-derived identity,
        #     re-pins the serial. _renew_cert is what the control plane calls. ---
        renewed = _renew_cert(a2id, _csr())
        assert renewed and renewed["type"] == "renewed"
        rc = x509.load_pem_x509_certificate(renewed["agent_cert_pem"].encode())
        assert rc.subject.rfc4514_string() == f"CN=agent.{a2id}"
        with SessionLocal() as db:
            assert db.get(Agent, a2id).cert_serial == str(rc.serial_number)
        # a renewal CSR for nothing / bad input is refused
        assert _renew_cert(a2id, "") is None
        assert _renew_cert(a2id, "not a csr") is None

    print("ENROLL-LIFECYCLE OK")


if __name__ == "__main__":
    test_enroll_lifecycle()
