"""mTLS WebSocket control server (SPEC §4, §13). Agents authenticate by client cert."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import ssl
from pathlib import Path

import websockets

# control/markup chars in agent-reported os/arch/version (rendered to operators)
_TELEMETRY_BAD = re.compile(r"""[\x00-\x1f<>"'`\\]""")

from ..config import get_settings
from ..db import SessionLocal
from ..deps import get_ca
from ..models import Agent
from . import protocol
from .manager import ConnectionManager, get_manager, json_sender

log = logging.getLogger("rctunnel_panel.control")


def build_ssl_context() -> ssl.SSLContext:
    """Server-side mTLS: present our server cert, require + verify client certs."""
    s = get_settings()
    ca = get_ca()
    crt, key = ca.ensure_server_cert([s.public_domain, "localhost", "127.0.0.1"])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.load_verify_locations(ca.ca_crt_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _vtuple(s: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in str(s).split("."))
    except ValueError:
        return (0,)


def _target_manifest() -> dict:
    """Latest published agent manifest (version + files), written by publish.py."""
    p = Path(get_settings().download_dir) / "manifest.json"
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


async def _maybe_upgrade(send, hello: dict) -> None:
    manifest = _target_manifest()
    target = manifest.get("agent_version")
    current = hello.get("agent_version", "0")
    if target and _vtuple(current) < _vtuple(target):
        base = get_settings().public_base_url.rstrip("/") + "/dl"
        log.info("OTA: telling agent (%s) to upgrade to %s", current, target)
        # use the manifest's file list (only files that actually exist in /dl) and
        # ship the trusted SHA-256 map so the agent can verify the /dl download
        await send(protocol.upgrade_payload(target, base, files=manifest.get("files"),
                                            sha256=manifest.get("sha256")))


def _agent_id_from_cert(ssl_object: ssl.SSLObject | None) -> int | None:
    if ssl_object is None:
        return None
    cert = ssl_object.getpeercert()
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName" and value.startswith("agent."):
                try:
                    return int(value.split(".", 1)[1])
                except ValueError:
                    return None
    return None


def _peer_serial(ssl_object: ssl.SSLObject | None) -> int | None:
    """Serial of the verified peer cert, or None if unavailable."""
    try:
        cert = ssl_object.getpeercert() if ssl_object else None
        s = cert.get("serialNumber") if cert else None
        return int(s, 16) if s else None
    except Exception:  # noqa: BLE001
        return None


async def _handle(websocket, manager: ConnectionManager) -> None:
    ssl_object = websocket.transport.get_extra_info("ssl_object")
    agent_id = _agent_id_from_cert(ssl_object)
    if agent_id is None:
        await websocket.close(code=4001, reason="no agent identity in client cert")
        return

    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        if agent is None:
            await websocket.close(code=4004, reason="unknown agent")
            return
        # Reject a superseded/stolen cert: if we've pinned a serial for this agent,
        # the presented cert must match it. Legacy agents (no pinned serial) pass
        # until they next enroll. If we can't read the peer serial, don't lock out.
        if agent.cert_serial:
            peer = _peer_serial(ssl_object)
            if peer is not None and str(peer) != agent.cert_serial:
                await websocket.close(code=4003, reason="superseded certificate")
                return
        welcome = protocol.welcome_payload(agent, agent.node)
        welcome["artifacts"] = _target_manifest().get("sha256", {})   # trusted hashes for rctc verify
        aname, ateam = agent.name, agent.team_id

    send = json_sender(websocket)
    manager.register(agent_id, send)
    log.info("agent %s connected", agent_id)
    from .. import logs
    logs.uptime(agent_id=agent_id, agent=aname, event="connect", team_id=ateam)
    ping_task = asyncio.create_task(_ping_loop(websocket, agent_id))
    try:
        await send(welcome)
        await manager.push(agent_id)  # initial desired state
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            mtype = msg.get("type")
            if mtype == protocol.HELLO:
                _store_hello(agent_id, msg)
                await _maybe_upgrade(send, msg)
            elif mtype in (protocol.HEARTBEAT, protocol.APPLIED):
                manager.touch(agent_id)
                d = msg.get("cert_days_left")
                if isinstance(d, int) and not isinstance(d, bool) and -36500 < d < 36500:
                    _set_cert_days(agent_id, d)
                ip = msg.get("detected_ip")
                if isinstance(ip, str):
                    _set_lan_ip(agent_id, ip)   # reflect a live LAN-IP change
            elif mtype == protocol.LOG:
                log.info("agent %s: %s", agent_id, msg.get("msg"))
    except websockets.ConnectionClosed:
        pass
    finally:
        ping_task.cancel()
        _set_ping(agent_id, None)            # clear stale RTT on disconnect
        manager.unregister(agent_id, send)
        from .. import logs
        logs.uptime(agent_id=agent_id, agent=aname, event="disconnect", team_id=ateam)
        log.info("agent %s disconnected", agent_id)


PING_SECS = 20


async def _ping_loop(websocket, agent_id: int) -> None:
    """Measure control-plane RTT via WebSocket ping/pong (no agent change needed).
    Pings immediately on connect, then every PING_SECS."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            t0 = loop.time()
            pong = await websocket.ping()
            await asyncio.wait_for(pong, timeout=10)
            _set_ping(agent_id, round((loop.time() - t0) * 1000))
        except Exception:  # noqa: BLE001  (connection closing / timeout)
            return
        await asyncio.sleep(PING_SECS)


def _set_ping(agent_id: int, ms: int | None) -> None:
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        if agent is not None:
            agent.last_ping_ms = ms
            db.commit()


def _set_cert_days(agent_id: int, days: int) -> None:
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        if agent is not None and agent.cert_days_left != days:
            agent.cert_days_left = days
            db.commit()


def _clean_telemetry(v, maxlen: int = 64) -> str | None:
    """Agent-supplied telemetry is untrusted and rendered on operator pages.
    Strip control/markup chars and length-cap it (defense-in-depth atop autoescape)."""
    if not isinstance(v, str):
        return None
    v = _TELEMETRY_BAD.sub("", v).strip()[:maxlen]
    return v or None


def _set_lan_ip(agent_id: int, ip: str) -> None:
    try:
        valid = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        if agent is not None and agent.lan_ip != valid:
            agent.lan_ip = valid
            db.commit()


def _store_hello(agent_id: int, msg: dict) -> None:
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        if agent is None:
            return
        agent.os = _clean_telemetry(msg.get("os")) or agent.os
        agent.arch = _clean_telemetry(msg.get("arch")) or agent.arch
        agent.agent_version = _clean_telemetry(msg.get("agent_version"), 16) or agent.agent_version
        ip = msg.get("detected_ip")
        if isinstance(ip, str):
            try:
                agent.lan_ip = str(ipaddress.ip_address(ip.strip()))   # only store a valid IP
            except ValueError:
                pass
        db.commit()


async def _server_cert_renewal(ctx: ssl.SSLContext) -> None:
    """Periodically re-issue the mTLS server cert when near expiry and hot-swap
    it into the live SSL context — new handshakes pick up the fresh cert with no
    listener restart. Reloading an unchanged cert is a harmless no-op."""
    s = get_settings()
    ca = get_ca()
    while True:
        await asyncio.sleep(12 * 3600)
        try:
            crt, key = ca.ensure_server_cert([s.public_domain, "localhost", "127.0.0.1"])
            ctx.load_cert_chain(crt, key)
        except Exception as e:  # noqa: BLE001
            log.warning("server cert renewal failed: %s", e)


async def serve_control(stop: asyncio.Future | None = None) -> None:
    s = get_settings()
    manager = get_manager()
    manager.bind_loop(asyncio.get_running_loop())
    ctx = build_ssl_context()
    asyncio.create_task(_server_cert_renewal(ctx))

    async def handler(ws):
        await _handle(ws, manager)

    async with websockets.serve(handler, s.control_host, s.control_port, ssl=ctx):
        log.info("control plane (mTLS) on %s:%s", s.control_host, s.control_port)
        if stop is not None:
            await stop
        else:
            await asyncio.Future()  # run forever
