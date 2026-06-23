"""Phase 2: mTLS control plane + desired-state push (no frpc needed here)."""

import asyncio
import json
import os
import ssl
import tempfile

os.environ["RCTUNNEL_DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"
os.environ["RCTUNNEL_PKI_DIR"] = tempfile.mkdtemp()
os.environ["RCTUNNEL_JWT_SECRET"] = "x" * 40
os.environ["RCTUNNEL_CONTROL_HOST"] = "127.0.0.1"
os.environ["RCTUNNEL_CONTROL_PORT"] = "18001"
os.environ["RCTUNNEL_DOWNLOAD_DIR"] = tempfile.mkdtemp()   # isolate from any real /dl manifest (OTA)
os.environ["RCTUNNEL_PUBLIC_DOMAIN"] = "localhost"

import websockets  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from rctunnel_panel.control import bus  # noqa: E402
from rctunnel_panel.control.manager import get_manager  # noqa: E402
from rctunnel_panel.control.server import serve_control  # noqa: E402
from rctunnel_panel.db import SessionLocal, init_db  # noqa: E402
from rctunnel_panel.deps import get_ca  # noqa: E402
from rctunnel_panel.models import Agent, Node, Tunnel, TunnelType  # noqa: E402

PORT = 18001


def _seed():
    init_db()
    with SessionLocal() as db:
        node = Node(name="edge1", public_addr="127.0.0.1", subdomain_host="localhost")
        db.add(node)
        db.flush()
        agent = Agent(name="a1", node_id=node.id)
        db.add(agent)
        db.flush()
        db.add(Tunnel(agent_id=agent.id, name="ssh", type=TunnelType.tcp,
                      local_ip="auto", local_port=22, remote_port=2222))
        db.commit()
        return agent.id


def _issue_cert(agent_id, d):
    ca = get_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a")]))
           .sign(key, hashes.SHA256()))
    cert = ca.sign_csr(csr.public_bytes(serialization.Encoding.PEM),
                       identity=f"agent.{agent_id}", days=1, client=True)
    (d / "agent.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (d / "agent.crt").write_bytes(cert)
    (d / "ca.crt").write_bytes(ca.cert_pem)


def _client_ctx(d):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(d / "agent.crt", d / "agent.key")
    ctx.load_verify_locations(d / "ca.crt")
    return ctx


async def _run():
    from pathlib import Path
    agent_id = _seed()
    d = Path(tempfile.mkdtemp())
    _issue_cert(agent_id, d)
    bus.set_handler(get_manager().notify)

    stop = asyncio.get_event_loop().create_future()
    srv = asyncio.create_task(serve_control(stop))
    await asyncio.sleep(0.5)  # let it bind

    ctx = _client_ctx(d)
    async with websockets.connect(f"wss://127.0.0.1:{PORT}/agent-ws", ssl=ctx,
                                  server_hostname="localhost") as ws:
        await ws.send(json.dumps({"type": "hello", "os": "linux", "arch": "amd64",
                                  "detected_ip": "10.0.0.205"}))
        welcome = json.loads(await asyncio.wait_for(ws.recv(), 5))
        assert welcome["type"] == "welcome" and welcome["agent_id"] == agent_id, welcome
        cfg = json.loads(await asyncio.wait_for(ws.recv(), 5))
        assert cfg["type"] == "config", cfg
        assert [t["name"] for t in cfg["tunnels"]] == ["ssh"], cfg
        gen0 = cfg["generation"]

        # online reflected in DB + HELLO stored
        await asyncio.sleep(0.2)
        with SessionLocal() as db:
            a = db.get(Agent, agent_id)
            assert a.status.value == "online", a.status
            assert a.lan_ip == "10.0.0.205"
        assert get_manager().is_online(agent_id)

        # add a tunnel, bump generation, notify -> expect a pushed CONFIG
        with SessionLocal() as db:
            a = db.get(Agent, agent_id)
            db.add(Tunnel(agent_id=agent_id, name="web", type=TunnelType.http,
                          local_ip="auto", local_port=8080, subdomain="news"))
            a.generation += 1
            db.commit()
        bus.notify_agent(agent_id)
        cfg2 = json.loads(await asyncio.wait_for(ws.recv(), 5))
        assert cfg2["type"] == "config" and cfg2["generation"] == gen0 + 1, cfg2
        assert sorted(t["name"] for t in cfg2["tunnels"]) == ["ssh", "web"], cfg2

    # after disconnect -> offline
    await asyncio.sleep(0.4)
    with SessionLocal() as db:
        assert db.get(Agent, agent_id).status.value == "offline"
    assert not get_manager().is_online(agent_id)

    stop.set_result(None)
    await srv
    print("PHASE 2 OK")


if __name__ == "__main__":
    asyncio.run(_run())
