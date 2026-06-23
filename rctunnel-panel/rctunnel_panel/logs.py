"""OpenSearch logging client — audit / uptime / connection logs.

Thin urllib client (no extra deps). Writes are fire-and-forget on a small thread
pool so they never block or fail a request. Reads (search/count/aggs) are sync.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import logging
import urllib.request

from .config import get_settings

log = logging.getLogger("rctunnel_panel.logs")

AUDIT = "rctunnel-audit"
CONN = "rctunnel-conn"
UPTIME = "rctunnel-uptime"

_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="oslog")


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _request(path: str, body: dict | None, method: str = "POST") -> dict:
    s = get_settings()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        s.opensearch_url.rstrip("/") + path, data=data,
        headers={"content-type": "application/json"}, method=method,
    )
    with urllib.request.urlopen(req, timeout=6) as r:
        return json.load(r)


def index(idx: str, doc: dict) -> None:
    """Fire-and-forget index (best-effort; errors swallowed)."""
    if not get_settings().logs_enabled:
        return

    def _do():
        try:
            _request(f"/{idx}/_doc", doc)
        except Exception as e:  # noqa: BLE001
            log.debug("index %s failed: %s", idx, e)

    try:
        _pool.submit(_do)
    except Exception:  # noqa: BLE001
        pass


def audit(*, actor: str, action: str, label: str, target: str,
          ip: str | None = None, team_id: int | None = None) -> None:
    index(AUDIT, {"ts": now_iso(), "actor": actor, "action": action,
                  "label": label, "target": target, "ip": ip, "team_id": team_id})


def uptime(*, agent_id: int, agent: str, event: str, team_id: int | None = None) -> None:
    index(UPTIME, {"ts": now_iso(), "agent_id": agent_id, "agent": agent,
                   "event": event, "team_id": team_id})


def search(idx: str, query: dict) -> dict:
    try:
        return _request(f"/{idx}/_search", query)
    except Exception as e:  # noqa: BLE001
        log.warning("search %s failed: %s", idx, e)
        return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}


def count(idx: str, query: dict | None = None) -> int:
    try:
        return _request(f"/{idx}/_count", query or {"query": {"match_all": {}}}).get("count", 0)
    except Exception:  # noqa: BLE001
        return 0
