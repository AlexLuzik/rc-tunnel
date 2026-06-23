"""Traffic accounting + quota enforcement.

Polls the rctd /api/stats endpoint for per-proxy traffic, accumulates cumulative
bytes per tunnel (proxy name = t{id}), sums per team, and suspends teams over
quota (suspended teams get an empty config pushed to their agents).
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.request

from sqlalchemy import func, select

from ..config import get_settings
from ..db import SessionLocal
from ..models import Agent, Team, Tunnel
from .manager import get_manager

log = logging.getLogger("rctunnel_panel.traffic")


def _fetch_proxy_traffic() -> dict[tuple[str, str], tuple[int, int]]:
    """Return {(owner_cn, proxy_name): (cumulativeIn, cumulativeOut)} from rctd
    /api/stats. Keyed by owner CN so traffic is attributed to the agent that
    actually produced it — a proxy name spoofed by another tenant lands under a
    different CN and is never billed to the victim."""
    s = get_settings()
    out: dict[tuple[str, str], tuple[int, int]] = {}
    req = urllib.request.Request(f"{s.rctd_stats_url}/api/stats")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
    except Exception:  # noqa: BLE001  (engine down)
        return out
    for e in (data or []):
        out[(e.get("cn") or "", e.get("name") or "")] = (int(e.get("in") or 0), int(e.get("out") or 0))
    return out


def poll_once() -> None:
    traffic = _fetch_proxy_traffic()
    manager = get_manager()
    with SessionLocal() as db:
        # accumulate per-tunnel cumulative bytes — bill only the sample produced by
        # the agent that OWNS the tunnel (CN agent.<agent_id>), so a tenant can't
        # inflate another tenant's usage by reusing the t{id} proxy name.
        for t in db.scalars(select(Tunnel)):
            sample = traffic.get((f"agent.{t.agent_id}", f"t{t.id}"))
            if sample is None:
                continue
            ti, to = sample
            t.bytes_in += (ti - t.last_today_in) if ti >= t.last_today_in else ti  # reset-safe delta
            t.bytes_out += (to - t.last_today_out) if to >= t.last_today_out else to
            t.last_today_in, t.last_today_out = ti, to
        db.commit()

        # quota enforcement — quota is the single source of truth for suspension.
        # Teams without a quota (unlimited) are always active (self-heals stuck flags).
        flipped: list[int] = []
        for team in db.scalars(select(Team)):
            usage = db.scalar(
                select(func.coalesce(func.sum(Tunnel.bytes_in + Tunnel.bytes_out), 0))
                .join(Agent, Tunnel.agent_id == Agent.id).where(Agent.team_id == team.id)
            ) or 0
            over = team.quota_bytes is not None and usage > team.quota_bytes
            if over != team.suspended:
                team.suspended = over
                flipped.append(team.id)
                log.info("team %s %s (usage=%d quota=%d)", team.name,
                         "SUSPENDED" if over else "resumed", usage, team.quota_bytes)
        db.commit()

        # push config to agents of teams whose suspend state changed
        if flipped:
            for agent_id in db.scalars(select(Agent.id).where(Agent.team_id.in_(flipped))):
                manager.notify(agent_id)


async def poll_loop() -> None:
    s = get_settings()
    log.info("traffic poller every %ss", s.traffic_poll_secs)
    while True:
        await asyncio.sleep(s.traffic_poll_secs)
        try:
            await asyncio.to_thread(poll_once)
        except Exception as e:  # noqa: BLE001
            log.warning("traffic poll failed: %s", e)
