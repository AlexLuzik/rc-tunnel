"""Tiny decoupling hook so the REST layer can poke the control plane.

Phase 1 ships a no-op. Phase 2's ConnectionManager installs a real handler
that pushes the new desired config to a connected agent (thread-safe).
"""

from __future__ import annotations

from collections.abc import Callable

_handler: Callable[[int], None] | None = None


def set_handler(fn: Callable[[int], None]) -> None:
    global _handler
    _handler = fn


def notify_agent(agent_id: int) -> None:
    if _handler is not None:
        _handler(agent_id)
