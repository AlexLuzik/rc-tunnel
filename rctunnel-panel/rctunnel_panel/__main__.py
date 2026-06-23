"""Run the master: FastAPI web/API (uvicorn) + mTLS control plane, one process.

    python -m rctunnel_panel
"""

from __future__ import annotations

import asyncio
import logging

import uvicorn

from .config import get_settings
from .control import bus, traffic
from .control.manager import get_manager
from .control.server import serve_control
from .main import app


async def _amain() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    s = get_settings()

    # REST mutations -> push to the connected agent over the control plane.
    bus.set_handler(get_manager().notify)

    # Trust X-Forwarded-For only from the local Caddy reverse proxy, so per-IP
    # rate-limiting and audit logs see the real client IP, not 127.0.0.1.
    config = uvicorn.Config(app, host=s.api_host, port=s.api_port, log_level="info", lifespan="on",
                            proxy_headers=True, forwarded_allow_ips="127.0.0.1")
    web = uvicorn.Server(config)

    await asyncio.gather(web.serve(), serve_control(), traffic.poll_loop())


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
