"""In-process registry of connected agents + desired-config push.

A single ConnectionManager is shared by the control server (asyncio) and the
REST layer (threadpool). REST mutations call notify() from a worker thread;
we hop back onto the event loop with call_soon_threadsafe.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from functools import lru_cache

from sqlalchemy import select

from ..config import get_settings
from ..db import SessionLocal
from ..models import Agent, AgentStatus, Team, Tunnel
from . import protocol

SendFn = Callable[[dict], Awaitable[None]]


def build_config(agent_id: int) -> dict | None:
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        if agent is None:
            return None
        tunnels = list(db.scalars(select(Tunnel).where(Tunnel.agent_id == agent_id)))
        team = db.get(Team, agent.team_id) if agent.team_id else None
        label = team.subdomain_label if team else None
        # a suspended team's agents get an empty config (tunnels dropped)
        if team is not None and team.suspended:
            tunnels = []
        s = get_settings()
        return protocol.config_payload(agent, agent.node, tunnels, team_label=label,
                                       workconn_port=s.rctd_workconn_port,
                                       grant_secret=s.grant_secret)


def _set_status(agent_id: int, status: AgentStatus, *, touch: bool = True) -> None:
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        if agent is None:
            return
        agent.status = status
        if touch:
            agent.last_seen = datetime.now(timezone.utc)
        db.commit()


class ConnectionManager:
    def __init__(self) -> None:
        self._conns: dict[int, SendFn] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    # -- connection lifecycle (called from the control server) --------------

    def register(self, agent_id: int, send: SendFn) -> None:
        self._conns[agent_id] = send
        _set_status(agent_id, AgentStatus.online)

    def unregister(self, agent_id: int, send: SendFn) -> None:
        if self._conns.get(agent_id) is send:
            del self._conns[agent_id]
            _set_status(agent_id, AgentStatus.offline)

    def is_online(self, agent_id: int) -> bool:
        return agent_id in self._conns

    def touch(self, agent_id: int) -> None:
        _set_status(agent_id, AgentStatus.online)

    # -- push ---------------------------------------------------------------

    async def push(self, agent_id: int) -> None:
        send = self._conns.get(agent_id)
        if send is None:
            return
        cfg = build_config(agent_id)
        if cfg is not None:
            await send(cfg)

    def notify(self, agent_id: int) -> None:
        """Thread-safe: schedule a push onto the event loop from any thread."""
        if self._loop is None:
            return
        self._loop.call_soon_threadsafe(lambda: asyncio.create_task(self.push(agent_id)))


@lru_cache
def get_manager() -> ConnectionManager:
    return ConnectionManager()


def json_sender(websocket) -> SendFn:
    async def _send(msg: dict) -> None:
        await websocket.send(json.dumps(msg))
    return _send
