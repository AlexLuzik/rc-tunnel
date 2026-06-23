"""Server-rendered UI (Jinja, English-only). Mutations call the JSON API via fetch."""

from __future__ import annotations

import csv
import datetime
import io
import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import logs
from ..config import get_settings
from ..db import get_db
from ..models import Agent, Node, Team, Tunnel, TunnelType, User
from ..security import create_token, verify_password

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

COOKIE = "rctunnel_token"


def _filesize(n: int | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


templates.env.filters["filesize"] = _filesize


def _user(request: Request, db: Session) -> User | None:
    from ..security import decode_token
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    try:
        return db.get(User, int(decode_token(token)["sub"]))
    except Exception:
        return None


def _lookup_by_host(db: Session, host: str) -> tuple[Tunnel | None, Team | None]:
    """Reverse a public vhost back to its tunnel (mirrors protocol._domainize FQDNs)."""
    host = (host or "").lower().split(":")[0]
    apex = get_settings().public_domain
    domain_types = (TunnelType.http, TunnelType.https)
    for t in db.scalars(select(Tunnel).where(Tunnel.type.in_(domain_types))):
        team = db.get(Team, t.agent.team_id) if t.agent.team_id else None
        label = team.subdomain_label if team else None
        fqdns: list[str] = []
        if t.subdomain:
            suffix = f"{label}.{apex}" if label else apex
            fqdns.append(f"{t.subdomain}.{suffix}".lower())
        if t.custom_domains:
            fqdns += [d.strip().lower() for d in t.custom_domains.split(",") if d.strip()]
        if host in fqdns:
            return t, team
    return None, None


@router.get("/_ondemand")
def ondemand_check(domain: str = "", db: Session = Depends(get_db)):
    """Caddy on-demand-TLS authorizer: only issue a cert if the host is a real
    tunnel (or the apex). Stops attackers forcing Let's Encrypt issuance for
    arbitrary *.rc-tunnel.com names (ACME rate-limit DoS)."""
    apex = get_settings().public_domain
    host = (domain or "").lower().strip().rstrip(".")
    if host == apex:
        return Response(status_code=200)
    if not host.endswith("." + apex):
        return Response(status_code=403)
    tunnel, _ = _lookup_by_host(db, host)
    return Response(status_code=200 if tunnel is not None else 403)


@router.get("/_offline", response_class=HTMLResponse)
def offline_page(request: Request, db: Session = Depends(get_db)):
    """Served by Caddy when the frps vhost returns 404/502/503 — explains why."""
    host = request.headers.get("x-tunnel-host") or request.headers.get("host", "")
    tunnel, team = _lookup_by_host(db, host)
    retry = False  # auto-reload only for transient states (agent offline / starting)
    if tunnel is not None and team is not None and team.suspended:
        code, icon, title, msg = 503, "🚦", "Traffic limit reached", \
            "This tunnel is temporarily unavailable because the team's traffic quota has been used up. It will resume once the quota is raised or reset."
    elif tunnel is not None and not tunnel.enabled:
        code, icon, title, msg = 503, "⏸️", "Tunnel disabled", \
            "This tunnel is currently turned off in the panel. Enable it to bring it back online."
    elif tunnel is not None and not (tunnel.agent and tunnel.agent.status.value == "online"):
        code, icon, title, msg = 502, "🔌", "Agent offline", \
            "This tunnel's agent is currently offline. It will be back when the agent reconnects."
        retry = True
    elif tunnel is not None:
        code, icon, title, msg = 502, "⏳", "Tunnel starting", \
            "The agent is online and the tunnel is configured — it should be reachable momentarily."
        retry = True
    else:
        code, icon, title, msg = 404, "🔍", "Tunnel not found", \
            "No tunnel is configured for this address."
    return templates.TemplateResponse(request, "offline.html",
                                      {"icon": icon, "title": title, "message": msg, "host": host, "retry": retry},
                                      status_code=code)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(request: Request, email: str = Form(...), password: str = Form(...),
                 db: Session = Depends(get_db)):
    from .. import logs, ratelimit
    ip = request.client.host if request.client else None
    if ip and len(ratelimit._recent(ip)) >= ratelimit.MAX:
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Too many attempts — try again later"}, status_code=429)
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(password, user.password_hash):
        ratelimit.record_fail(ip)
        logs.audit(actor=email, action="auth", label="auth.fail", target="session", ip=ip)
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Invalid credentials"}, status_code=401)
    ratelimit.clear(ip)
    logs.audit(actor=user.email, action="auth", label="auth.login", target="session", ip=ip, team_id=user.team_id)
    token = create_token(user_id=user.id, role=user.role.value)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(COOKIE, token, httponly=True, samesite="lax",
                    secure=get_settings().cookie_secure)
    return resp


@router.get("/demo")
def demo_login(request: Request, db: Session = Depends(get_db)):
    """Public, passwordless sign-in to the read-only demo account."""
    user = db.scalar(select(User).where(User.email == "demo@rc-tunnel.com"))
    if user is None:
        return RedirectResponse("/login", status_code=303)
    token = create_token(user_id=user.id, role=user.role.value)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(COOKIE, token, httponly=True, samesite="lax", secure=get_settings().cookie_secure)
    return resp


@router.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        s = get_settings()
        if s.demo_mode:   # public demo deployment: anonymous visitors see the landing page
            return templates.TemplateResponse(request, "landing.html", {
                "domain": s.public_domain, "base_url": s.public_base_url.rstrip("/"),
            })
        return RedirectResponse("/login", status_code=303)
    agents_q = select(Agent)
    if user.role.value != "admin":
        agents_q = agents_q.where(Agent.team_id == user.team_id)
    agents = list(db.scalars(agents_q))
    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user, "agents": agents,
    })


@router.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "profile.html", {"user": user})


@router.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.role.value != "admin":
        return RedirectResponse("/", status_code=303)
    teams = list(db.scalars(select(Team)))
    users = list(db.scalars(select(User)))
    team_names = {t.id: t.name for t in teams}
    member_counts: dict[int | None, int] = {}
    for u in users:
        member_counts[u.team_id] = member_counts.get(u.team_id, 0) + 1
    # traffic usage per team (bytes)
    usage: dict[int, int] = {}
    for t, ag in db.execute(select(Tunnel, Agent).join(Agent, Tunnel.agent_id == Agent.id)):
        usage[ag.team_id] = usage.get(ag.team_id, 0) + t.bytes_in + t.bytes_out
    return templates.TemplateResponse(request, "admin.html", {
        "user": user, "teams": teams, "users": users,
        "team_names": team_names, "member_counts": member_counts, "usage": usage,
        "domain": get_settings().public_domain,
    })


@router.get("/agents/{agent_id}", response_class=HTMLResponse)
def agent_detail(agent_id: int, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    agent = db.get(Agent, agent_id)
    if agent is None:
        return RedirectResponse("/", status_code=303)
    if user.role.value != "admin" and agent.team_id != user.team_id:
        return RedirectResponse("/", status_code=303)   # not this team's agent
    tunnels = list(db.scalars(select(Tunnel).where(Tunnel.agent_id == agent_id)))
    s = get_settings()
    team = db.get(Team, agent.team_id) if agent.team_id else None
    team_label = team.subdomain_label if team else None
    base = s.public_base_url.rstrip("/")
    install_cmd = (f"curl -fsSL {base}/dl/install.sh | bash -s -- "
                   f"--base-url {base}/dl --token {agent.agent_token}")
    return templates.TemplateResponse(request, "agent.html", {
        "user": user, "agent": agent, "node": agent.node, "tunnels": tunnels,
        "install_cmd": install_cmd, "domain": s.public_domain,
        "team_label": team_label, "subdomain_max_depth": s.subdomain_max_depth,
    })


# ===================== Activity / Fleet (OpenSearch-backed) =====================

def _ago(iso: str) -> str:
    try:
        dt = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return iso or "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    secs = (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds()
    if secs < 60: return f"{int(secs)}s ago"
    if secs < 3600: return f"{int(secs//60)}m ago"
    if secs < 86400: return f"{int(secs//3600)}h ago"
    return f"{int(secs//86400)}d ago"


def _hhmm(iso: str) -> str:
    try:
        return datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%m-%d %H:%M:%S")
    except Exception:
        return iso or ""


def _team_filter(user: User) -> list:
    return [] if user.role.value == "admin" else [{"term": {"team_id": user.team_id}}]


def _recent(index: str, user: User, size: int = 100, extra: list | None = None) -> list[dict]:
    q = {"size": size, "sort": [{"ts": "desc"}],
         "query": {"bool": {"filter": _team_filter(user) + (extra or [])}}}
    return [h["_source"] for h in logs.search(index, q)["hits"]["hits"]]


def _count_since(index: str, user: User, hours: int) -> int:
    since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)).isoformat()
    q = {"query": {"bool": {"filter": _team_filter(user) + [{"range": {"ts": {"gte": since}}}]}}}
    return logs.count(index, q)


def _online_intervals(events: list[tuple], window_start, now, online_now: bool) -> list[tuple]:
    """Reconstruct online time windows from sorted (ts, event) connect/disconnect
    events, clamped to [window_start, now]."""
    intervals = []
    start = window_start if (events and events[0][1] == "disconnect") else None  # online coming in
    for ts, ev in events:
        if ev == "connect":
            if start is None:
                start = ts
        elif ev == "disconnect":
            if start is not None:
                intervals.append((start, ts))
                start = None
    if start is not None:  # still open -> online until now
        intervals.append((start, now))
    out = []
    for s, e in intervals:
        s, e = max(s, window_start), min(e, now)
        if e > s:
            out.append((s, e))
    return out


def _uptime_rows(user: User, db: Session) -> list[dict]:
    """40-day availability strip + real uptime% (online time / observed window)."""
    q = select(Agent)
    if user.role.value != "admin":
        q = q.where(Agent.team_id == user.team_id)
    agents = list(db.scalars(q))
    node_names = {n.id: n.name for n in db.scalars(select(Node))}
    now = datetime.datetime.now(datetime.timezone.utc)
    window_start = now - datetime.timedelta(days=40)
    today = datetime.date.today()

    def _parse(ts):
        try:
            return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            return None

    rows = []
    for a in agents:
        hits = logs.search(logs.UPTIME, {"size": 2000, "sort": [{"ts": "asc"}],
            "query": {"bool": {"filter": [{"term": {"agent_id": a.id}},
                                          {"range": {"ts": {"gte": window_start.isoformat()}}}]}}})["hits"]["hits"]
        events = [(_parse(h["_source"].get("ts")), h["_source"].get("event")) for h in hits]
        events = [(t, e) for t, e in events if t is not None]
        online_now = a.status.value == "online"
        intervals = _online_intervals(events, window_start, now, online_now)
        observed = events[0][0] if events else None  # first signal we have

        # overall uptime% over the observed window
        if observed is None:
            up = 100.0 if online_now else 0.0
        else:
            online_sec = sum((e - s).total_seconds() for s, e in intervals)
            denom = max((now - observed).total_seconds(), 1.0)
            up = min(100.0, online_sec / denom * 100)

        # per-day cells: green >=99% online, amber partial, gray = no data (pre-existence)
        cells = []
        for i in range(39, -1, -1):
            d = today - datetime.timedelta(days=i)
            ds = datetime.datetime(d.year, d.month, d.day, tzinfo=datetime.timezone.utc)
            de = min(ds + datetime.timedelta(days=1), now)
            iso = d.isoformat()
            if observed is None or de <= observed:
                cells.append(("var(--bs-border-color)", iso))
                continue
            lo = max(ds, observed)
            span = (de - lo).total_seconds()
            ov = sum(max(0.0, (min(e, de) - max(s, lo)).total_seconds()) for s, e in intervals)
            frac = (ov / span) if span > 0 else 0.0
            cells.append((("rgba(16,185,129,.8)" if frac >= 0.99 else "#f59e0b"), iso))

        rows.append({"name": a.name, "node": node_names.get(a.node_id, "—"),
                     "online": online_now, "cells": cells,
                     "up": f"{up:.2f}%", "up_ok": up >= 99})
    return rows


def _target_version() -> str | None:
    try:
        return json.loads((Path(get_settings().download_dir) / "manifest.json").read_text()).get("agent_version")
    except Exception:
        return None


def _device_rows(db: Session, user: User, glob: bool, tv: str | None) -> list[dict]:
    """Device overview rows; team-scoped unless glob (super-admin, all teams)."""
    node_names = {n.id: n.name for n in db.scalars(select(Node))}
    team_names = {t.id: t.name for t in db.scalars(select(Team))}
    aq = select(Agent)
    if not glob:
        aq = aq.where(Agent.team_id == user.team_id)
    devices = []
    for a in db.scalars(aq):
        bytes_total = db.scalar(select(func.coalesce(func.sum(Tunnel.bytes_in + Tunnel.bytes_out), 0))
                                .where(Tunnel.agent_id == a.id)) or 0
        ntun = db.scalar(select(func.count(Tunnel.id)).where(Tunnel.agent_id == a.id)) or 0
        ev_hits = logs.search(logs.UPTIME, {"size": 5, "sort": [{"ts": "desc"}],
                                            "query": {"term": {"agent_id": a.id}}})["hits"]["hits"]
        evs = [{"time": _ago(h["_source"].get("ts", "")), "event": h["_source"].get("event")} for h in ev_hits]
        devices.append({
            "id": a.id, "name": a.name, "team": team_names.get(a.team_id, "—"),
            "node": node_names.get(a.node_id, "—"), "online": a.status.value == "online",
            "version": a.agent_version or "—", "outdated": bool(tv and a.agent_version and a.agent_version != tv),
            "os": f"{a.os or '—'}/{a.arch or '—'}", "seen": _ago(a.last_seen.isoformat()) if a.last_seen else "never",
            "lan": a.lan_ip or "—", "ping": a.last_ping_ms, "data": _filesize(bytes_total), "tunnels": ntun,
            "events": evs,
        })
    return devices


def _activity_ctx(request: Request, user: User, db: Session, tab: str, base: str, glob: bool) -> dict:
    """Shared builder for the tabbed audit view (/activity scoped, /fleet global)."""
    tab = tab if tab in ("devices", "uptime", "audit", "conn") else "devices"
    tv = _target_version()
    aq = select(Agent)
    if not glob:
        aq = aq.where(Agent.team_id == user.team_id)
    agents = list(db.scalars(aq))
    ctx = {"user": user, "tab": tab, "base": base, "global_view": glob, "target_version": tv,
           "title": "Fleet audit" if glob else "Activity",
           "subtitle": ("Devices, audit trail and connections across all teams." if glob
                        else "Your devices, uptime, audit trail and connection logs."),
           "online": sum(1 for a in agents if a.status.value == "online"), "total": len(agents),
           "req24": _count_since(logs.CONN, user, 24), "audit24": _count_since(logs.AUDIT, user, 24)}
    if tab == "devices":
        ctx["devices"] = _device_rows(db, user, glob, tv)
    elif tab == "uptime":
        ctx["uptime"] = _uptime_rows(user, db)
    elif tab == "audit":
        ctx["audit"] = [{"time": _hhmm(s.get("ts", "")), "actor": s.get("actor"),
                         "action": s.get("action"), "label": s.get("label"),
                         "target": s.get("target"), "ip": s.get("ip")} for s in _recent(logs.AUDIT, user)]
    else:
        ctx["conn"] = [{"time": _hhmm(s.get("ts", "")), "agent": s.get("agent"), "tunnel": s.get("tunnel"),
                        "method": s.get("method"), "src": s.get("src"), "target": s.get("target"),
                        "status": s.get("status"), "lat": s.get("latency_ms"),
                        "bytes": _filesize(s.get("bytes"))} for s in _recent(logs.CONN, user)]
    return ctx


@router.get("/activity", response_class=HTMLResponse)
def activity_page(request: Request, tab: str = "devices", db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ctx = _activity_ctx(request, user, db, tab, "/activity", glob=(user.role.value == "admin"))
    return templates.TemplateResponse(request, "activity.html", ctx)


@router.get("/fleet", response_class=HTMLResponse)
def fleet_page(request: Request, tab: str = "devices", db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.role.value != "admin":
        return RedirectResponse("/", status_code=303)
    ctx = _activity_ctx(request, user, db, tab, "/fleet", glob=True)
    return templates.TemplateResponse(request, "activity.html", ctx)


def _export(request: Request, db: Session, tab: str, fname: str):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    index = logs.CONN if tab == "conn" else logs.AUDIT
    rows = _recent(index, user, size=1000)
    buf = io.StringIO()
    if rows:
        cols = sorted({k for r in rows for k in r.keys()})
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return StreamingResponse(io.BytesIO(buf.getvalue().encode()), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.get("/activity/export")
def activity_export(request: Request, tab: str = "audit", db: Session = Depends(get_db)):
    return _export(request, db, tab, f"rc-{tab}-log.csv")


@router.get("/fleet/export")
def fleet_export(request: Request, tab: str = "audit", db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None or user.role.value != "admin":
        return RedirectResponse("/", status_code=303)
    return _export(request, db, tab, f"rc-fleet-{tab}-log.csv")
