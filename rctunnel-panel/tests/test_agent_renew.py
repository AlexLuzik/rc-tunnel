"""Agent-side mTLS cert renewal: request a renew over the link, install the reply."""

import asyncio
import datetime as dt
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import rctunnel_agent as A  # noqa: E402


class _FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, data):
        self.sent.append(json.loads(data))


def _issue(ag, days):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    crt = (x509.CertificateBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent.1")]))
           .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ca")]))
           .public_key(key.public_key()).serial_number(1)
           .not_valid_before(now - dt.timedelta(minutes=5))
           .not_valid_after(now + dt.timedelta(days=days)).sign(key, hashes.SHA256()))
    ag.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ag.crt_path.write_text(crt.public_bytes(serialization.Encoding.PEM).decode())
    ag.ca_path.write_text("oldca")


def test_agent_renew():
    work = Path(tempfile.mkdtemp())
    ag = A.Agent.__new__(A.Agent)
    ag.work = work
    ag.key_path, ag.crt_path, ag.ca_path = work / "agent.key", work / "agent.crt", work / "ca.crt"
    ag._renew_key = None
    ag.shutdown = lambda: None

    # fresh cert → no renewal requested
    _issue(ag, 300)
    ws = _FakeWS()
    asyncio.run(ag._maybe_request_renew(ws))
    assert not ws.sent and ag._renew_key is None

    # near-expiry cert → a renew request is sent and a new key is staged (in memory)
    _issue(ag, 5)
    ws = _FakeWS()
    asyncio.run(ag._maybe_request_renew(ws))
    assert len(ws.sent) == 1 and ws.sent[0]["type"] == "renew" and "csr_pem" in ws.sent[0]
    assert ag._renew_key is not None
    assert "BEGIN CERTIFICATE REQUEST" in ws.sent[0]["csr_pem"]
    # the new key is NOT written to disk until the signed cert arrives
    old_key = ag.key_path.read_bytes()

    # a second call while a renewal is in-flight does nothing (no duplicate request)
    ws2 = _FakeWS()
    asyncio.run(ag._maybe_request_renew(ws2))
    assert not ws2.sent

    # installing the reply swaps key+cert+ca and re-execs
    execd = {}
    A.os.execv = lambda exe, argv: execd.setdefault("x", (exe, argv)) or (_ for _ in ()).throw(SystemExit())
    try:
        ag._install_renewed({"agent_cert_pem": "NEWCERT\n", "ca_cert_pem": "NEWCA\n"})
    except SystemExit:
        pass
    assert ag.crt_path.read_text() == "NEWCERT\n"
    assert ag.ca_path.read_text() == "NEWCA\n"
    assert ag.key_path.read_bytes() != old_key      # staged key now persisted
    assert ag._renew_key is None and "x" in execd
    print("AGENT-RENEW OK")


if __name__ == "__main__":
    test_agent_renew()
