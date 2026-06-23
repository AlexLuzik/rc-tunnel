"""Caddy access-log shipper -> OpenSearch (rctunnel-conn).

Tails Caddy's JSON access log, maps each HTTP request to its tunnel/agent/team
(by vhost), and indexes a connection document. Run as a service:

    python -m rctunnel_panel.logship
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import time

from sqlalchemy import select

from . import logs
from .config import get_settings
from .db import SessionLocal
from .models import Agent, Team, Tunnel, TunnelType

log = logging.getLogger("rctunnel_panel.logship")

ACCESS_LOG = os.environ.get("RCTUNNEL_CADDY_ACCESS_LOG", "/var/log/caddy/access.log")
_DOMAIN_TYPES = (TunnelType.http, TunnelType.https)


def _build_hostmap() -> dict[str, dict]:
    """host(FQDN) -> {agent, tunnel, team_id}. Rebuilt periodically."""
    s = get_settings()
    apex = s.public_domain
    out: dict[str, dict] = {}
    with SessionLocal() as db:
        for t in db.scalars(select(Tunnel).where(Tunnel.type.in_(_DOMAIN_TYPES))):
            agent = t.agent
            team = db.get(Team, agent.team_id) if agent.team_id else None
            label = team.subdomain_label if team else None
            fqdns = []
            if t.subdomain:
                suffix = f"{label}.{apex}" if label else apex
                fqdns.append(f"{t.subdomain}.{suffix}".lower())
            if t.custom_domains:
                fqdns += [d.strip().lower() for d in t.custom_domains.split(",") if d.strip()]
            for f in fqdns:
                out[f] = {"agent": agent.name, "tunnel": t.name, "team_id": agent.team_id}
    return out


def _cap(v, n: int):
    return v[:n] if isinstance(v, str) else v


def _to_doc(entry: dict, hostmap: dict) -> dict | None:
    req = entry.get("request") or {}
    host = (req.get("host") or "").lower().split(":")[0][:255]
    meta = hostmap.get(host, {})
    ts = entry.get("ts")
    iso = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
           if isinstance(ts, (int, float)) else logs.now_iso())
    dur = entry.get("duration") or 0
    # host/method/src/target are attacker-controlled (Host header, request line,
    # URI) — cap their length so a flood can't amplify OpenSearch storage/ingest.
    return {
        "ts": iso,
        "host": host,
        "agent": meta.get("agent"),
        "tunnel": meta.get("tunnel"),
        "team_id": meta.get("team_id"),
        "method": _cap(req.get("method"), 16),
        "src": _cap(req.get("client_ip") or req.get("remote_ip"), 64),
        "target": _cap(req.get("uri"), 2048),
        "status": entry.get("status"),
        "latency_ms": round(float(dur) * 1000, 1),
        "bytes": entry.get("size") or 0,
    }


def _tail(path: str):
    """Yield new lines, tolerant of the file not existing yet / rotation."""
    while not os.path.exists(path):
        time.sleep(2)
    f = open(path, "r")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(1)
        try:  # detect rotation (file replaced/truncated)
            if os.stat(path).st_ino != inode or os.path.getsize(path) < f.tell():
                f.close(); f = open(path, "r"); inode = os.fstat(f.fileno()).st_ino
        except OSError:
            pass


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not get_settings().logs_enabled:
        log.warning("logs disabled; shipper idle"); return
    log.info("shipping Caddy access log %s -> OpenSearch (rctunnel-conn)", ACCESS_LOG)
    hostmap = _build_hostmap()
    last_refresh = time.monotonic()
    for line in _tail(ACCESS_LOG):
        if time.monotonic() - last_refresh > 30:
            try:
                hostmap = _build_hostmap()
            except Exception as e:  # noqa: BLE001
                log.debug("hostmap refresh failed: %s", e)
            last_refresh = time.monotonic()
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            doc = _to_doc(json.loads(line), hostmap)
        except Exception:  # noqa: BLE001
            continue
        if doc:
            logs.index(logs.CONN, doc)


if __name__ == "__main__":
    main()
