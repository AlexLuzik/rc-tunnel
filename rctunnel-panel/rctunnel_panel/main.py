"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, logs
from .api import agents, auth, nodes, teams, tunnels
from .config import get_settings
from .db import SessionLocal, init_db
from .deps import get_ca
from .models import User
from .security import decode_token
from .web import routes as web_routes


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    if s.jwt_secret in ("", "change-me"):
        raise RuntimeError("RCTUNNEL_JWT_SECRET is unset/default — refusing to start with a forgeable signing key")
    # Without a grant secret, rctd skips all per-agent ownership checks (cross-tenant
    # data-plane isolation is OFF). Refuse to start in production (Postgres) and warn
    # loudly in dev (SQLite), where the suite/quickstart legitimately run without it.
    if not s.grant_secret:
        # Fail closed for any real datastore; only the SQLite dev/test default may
        # run without it (DSN-scheme allowlist, not a "looks like prod" guess).
        if not s.database_url.startswith("sqlite"):
            raise RuntimeError("RCTUNNEL_GRANT_SECRET is unset — data-plane tenant isolation would be "
                               "disabled; refusing to start. Set it (and the matching rctd grant_secret).")
        logging.getLogger(__name__).warning(
            "RCTUNNEL_GRANT_SECRET is unset — data-plane tenant isolation is DISABLED (dev only).")
    init_db()       # clean-slate MVP; Alembic later
    get_ca()        # create/load the panel CA on startup
    yield


app = FastAPI(title="rctunnel-panel", version=__version__, lifespan=lifespan)


def _actor(request: Request) -> tuple[str, int | None]:
    h = request.headers.get("authorization", "")
    tok = h[7:] if h.startswith("Bearer ") else request.cookies.get("rctunnel_token")
    if not tok:
        return "anonymous", None
    try:
        sub = int(decode_token(tok)["sub"])
    except Exception:
        return "anonymous", None
    with SessionLocal() as db:
        u = db.get(User, sub)
        return (u.email, u.team_id) if u else ("anonymous", None)


def _token_role(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    tok = h[7:] if h.startswith("Bearer ") else request.cookies.get("rctunnel_token")
    if not tok:
        return None
    try:
        return decode_token(tok).get("role")
    except Exception:
        return None


def _resource(path: str) -> str:
    for needle, res in (("/tunnels", "tunnel"), ("/members/", "team.member"),
                        ("/agents", "agent"), ("/nodes", "node"), ("/teams", "team"),
                        ("/auth/users", "user"), ("/auth/me", "profile")):
        if needle in path:
            return res
    return "resource"


@app.middleware("http")
async def _audit_mw(request: Request, call_next):
    m, p = request.method, request.url.path
    mutating_api = (m in ("POST", "PATCH", "PUT", "DELETE") and p.startswith("/api/")
                    and not p.startswith("/api/agents/enroll") and p != "/api/auth/login")
    # demo accounts are strictly read-only — block every state change
    if mutating_api and _token_role(request) == "demo":
        return JSONResponse({"detail": "Demo account is read-only — ask your admin for an account."}, status_code=403)
    resp = await call_next(request)
    try:
        if mutating_api and resp.status_code < 400:
            action = "update" if "/members/" in p else {"POST": "create", "PATCH": "update",
                                                         "PUT": "update", "DELETE": "delete"}[m]
            actor, team = _actor(request)
            logs.audit(actor=actor, action=action, label=f"{_resource(p)}.{action}", target=p,
                       ip=(request.client.host if request.client else None), team_id=team)
    except Exception:  # noqa: BLE001  (auditing must never break the request)
        pass
    return resp


app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(nodes.router, prefix="/api/nodes", tags=["nodes"])
app.include_router(agents.router, prefix="/api/agents", tags=["agents"])
app.include_router(tunnels.router, prefix="/api", tags=["tunnels"])
app.include_router(teams.router, prefix="/api/teams", tags=["teams"])
app.include_router(web_routes.router, include_in_schema=False)

# Serve agent installer + binaries from /dl (Caddy may also front this in prod).
_dl = Path(get_settings().download_dir)
if _dl.is_dir():
    app.mount("/dl", StaticFiles(directory=str(_dl)), name="dl")


@app.get("/healthz")
def healthz() -> dict:
    s = get_settings()
    return {"status": "ok", "version": __version__, "domain": s.public_domain}
