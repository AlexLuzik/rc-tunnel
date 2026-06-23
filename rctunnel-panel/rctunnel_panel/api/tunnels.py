"""Tunnel CRUD. Team-scoped; mutations bump the agent's generation and notify it."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..control.bus import notify_agent
from ..db import get_db
from ..deps import check_team_access, current_user
from ..models import Agent, Tunnel, TunnelType, User
from ..schemas import TunnelCreate, TunnelOut, TunnelUpdate

router = APIRouter()

_DOMAIN_TYPES = (TunnelType.http, TunnelType.https)

# Subdomain first-labels we refuse: DNS/mail special records and provider-brand
# names. Kept minimal — tenant subdomains are already team-namespaced, so common
# app names (app, api, admin, …) are legitimately usable inside a team.
_RESERVED_LABELS = {
    "_dmarc", "_domainkey", "autodiscover", "autoconfig",
    "ns", "ns1", "ns2", "mx", "mx1", "mx2", "dkim",
    "www", "rctunnel", "rc-tunnel", "rc",
}
_FQDN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+(xn--[a-z0-9-]{2,}|[a-z]{2,})$")
# A single DNS label: letters/digits/hyphen, no leading/trailing hyphen. This is
# the charset gate for the subdomain field — it MUST reject ',' and '|' so a
# tenant cannot inject extra hosts into the signed authorization grant.
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def _validate(body: TunnelCreate, *, team_has_label: bool) -> None:
    from ..config import get_settings
    if body.type in _DOMAIN_TYPES and not (body.subdomain or body.custom_domains):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{body.type.value} requires subdomain or custom_domains")
    if body.health_check_type and body.health_check_type not in ("tcp", "http"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "health_check_type must be tcp or http")
    if body.subdomain:
        _check_subdomain_labels(body.subdomain)
        _check_subdomain_depth(body.subdomain, team_has_label)


def _check_subdomain_depth(subdomain: str, team_has_label: bool) -> None:
    from ..config import get_settings
    # team label (if any) consumes one of the allowed labels before the apex
    labels = [p for p in subdomain.split(".") if p]
    depth = len(labels) + (1 if team_has_label else 0)
    maxd = get_settings().subdomain_max_depth
    if depth > maxd:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"subdomain too deep ({depth} labels incl. team); max {maxd}")


def _check_subdomain_labels(subdomain: str | None) -> None:
    """Strict per-label charset gate + reserved-name check. CRITICAL for grant
    integrity: an unvalidated subdomain flows into the signed grant's host list,
    so a ',' or '|' would forge extra authorized hosts (cross-tenant hijack)."""
    if not subdomain:
        return
    labels = [p for p in subdomain.split(".") if p]
    for lab in labels:
        if not _LABEL_RE.match(lab.lower()):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"invalid subdomain label '{lab}'")
    if labels and labels[0].lower() in _RESERVED_LABELS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"subdomain '{labels[0]}' is reserved")


def _check_custom_domains(db: Session, custom_domains: str | None,
                          exclude_id: int | None = None) -> None:
    """Validate explicit custom domains: well-formed FQDNs, never under our own
    apex (those must go through the team-namespaced subdomain field, not a raw
    custom domain — otherwise a tenant could claim another tenant's subdomain),
    and globally unique across all tunnels."""
    if not custom_domains:
        return
    from ..config import get_settings
    apex = get_settings().public_domain.lower()
    doms = [d.strip().lower() for d in custom_domains.split(",") if d.strip()]
    for d in doms:
        if not _FQDN_RE.match(d):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"invalid domain '{d}'")
        if d == apex or d.endswith("." + apex):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"domains under {apex} must use the subdomain field, not custom_domains")
    wanted = set(doms)
    q = select(Tunnel).where(Tunnel.custom_domains.isnot(None))
    if exclude_id is not None:
        q = q.where(Tunnel.id != exclude_id)
    for t in db.scalars(q):
        owned = {x.strip().lower() for x in (t.custom_domains or "").split(",") if x.strip()}
        clash = wanted & owned
        if clash:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"domain '{sorted(clash)[0]}' is already claimed by another tunnel")


def _check_subdomain_unique(db: Session, subdomain: str | None, team_id: int | None,
                            exclude_id: int | None = None) -> None:
    """Subdomain must be unique within the team (the team label namespaces tenants)."""
    if not subdomain:
        return
    q = (select(Tunnel).join(Agent, Tunnel.agent_id == Agent.id)
         .where(func.lower(Tunnel.subdomain) == subdomain.lower(), Agent.team_id == team_id))
    if exclude_id is not None:
        q = q.where(Tunnel.id != exclude_id)
    if db.scalar(q):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"subdomain '{subdomain}' is already taken in your team")


def _allocate_port(db: Session, node_id: int, preferred: int | None,
                   exclude_tunnel_id: int | None = None) -> int:
    """Pick a free remote port on the node (unique across all tunnels on that node)."""
    from ..config import get_settings
    s = get_settings()
    q = (select(Tunnel.remote_port).join(Agent, Tunnel.agent_id == Agent.id)
         .where(Agent.node_id == node_id, Tunnel.remote_port.is_not(None)))
    if exclude_tunnel_id is not None:
        q = q.where(Tunnel.id != exclude_tunnel_id)
    used = set(db.scalars(q))
    if preferred is not None:   # manual choice: wide allowed range
        if not (s.port_allow_min <= preferred <= s.port_allow_max):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"remote_port out of range {s.port_allow_min}-{s.port_allow_max}")
        if preferred in used:
            raise HTTPException(status.HTTP_409_CONFLICT, f"remote_port {preferred} is taken")
        return preferred
    for p in range(s.tcp_port_min, s.tcp_port_max + 1):
        if p not in used:
            return p
    raise HTTPException(status.HTTP_409_CONFLICT, "no free remote ports on node")


def _bump(agent: Agent, db: Session) -> None:
    agent.generation += 1
    db.commit()
    notify_agent(agent.id)


def _agent_or_404(agent_id: int, db: Session, user: User) -> Agent:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    check_team_access(agent.team_id, user)
    return agent


@router.get("/agents/{agent_id}/tunnels", response_model=list[TunnelOut])
def list_tunnels(agent_id: int, db: Session = Depends(get_db),
                 user: User = Depends(current_user)) -> list[Tunnel]:
    _agent_or_404(agent_id, db, user)
    return list(db.scalars(select(Tunnel).where(Tunnel.agent_id == agent_id)))


@router.post("/agents/{agent_id}/tunnels", response_model=TunnelOut)
def create_tunnel(agent_id: int, body: TunnelCreate, db: Session = Depends(get_db),
                  user: User = Depends(current_user)) -> Tunnel:
    from ..models import Team
    agent = _agent_or_404(agent_id, db, user)
    team = db.get(Team, agent.team_id) if agent.team_id else None
    _validate(body, team_has_label=bool(team and team.subdomain_label))
    if db.scalar(select(Tunnel).where(Tunnel.agent_id == agent_id, Tunnel.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "tunnel name exists for agent")
    _check_subdomain_unique(db, body.subdomain, agent.team_id)
    _check_custom_domains(db, body.custom_domains)
    data = body.model_dump()
    if body.type in (TunnelType.tcp, TunnelType.udp):
        data["remote_port"] = _allocate_port(db, agent.node_id, body.remote_port)
    tunnel = Tunnel(agent_id=agent_id, **data)
    db.add(tunnel)
    db.flush()
    _bump(agent, db)
    db.refresh(tunnel)
    return tunnel


@router.patch("/tunnels/{tunnel_id}", response_model=TunnelOut)
def update_tunnel(tunnel_id: int, body: TunnelUpdate, db: Session = Depends(get_db),
                  user: User = Depends(current_user)) -> Tunnel:
    tunnel = db.get(Tunnel, tunnel_id)
    if tunnel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tunnel not found")
    check_team_access(tunnel.agent.team_id, user)
    fields = body.model_dump(exclude_unset=True)
    if fields.get("health_check_type") and fields["health_check_type"] not in ("tcp", "http"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "health_check_type must be tcp or http")
    if "subdomain" in fields and fields["subdomain"]:
        from ..models import Team
        _check_subdomain_labels(fields["subdomain"])
        team = db.get(Team, tunnel.agent.team_id) if tunnel.agent.team_id else None
        _check_subdomain_depth(fields["subdomain"], bool(team and team.subdomain_label))
        _check_subdomain_unique(db, fields["subdomain"], tunnel.agent.team_id, exclude_id=tunnel.id)
    elif "subdomain" in fields:
        _check_subdomain_unique(db, fields["subdomain"], tunnel.agent.team_id, exclude_id=tunnel.id)
    if "custom_domains" in fields:
        _check_custom_domains(db, fields["custom_domains"], exclude_id=tunnel.id)
    if fields.get("remote_port") is not None:
        fields["remote_port"] = _allocate_port(db, tunnel.agent.node_id, fields["remote_port"],
                                               exclude_tunnel_id=tunnel.id)
    for k, v in fields.items():
        setattr(tunnel, k, v)
    db.flush()
    _bump(tunnel.agent, db)
    db.refresh(tunnel)
    return tunnel


@router.delete("/tunnels/{tunnel_id}")
def delete_tunnel(tunnel_id: int, db: Session = Depends(get_db),
                  user: User = Depends(current_user)) -> Response:
    tunnel = db.get(Tunnel, tunnel_id)
    if tunnel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tunnel not found")
    check_team_access(tunnel.agent.team_id, user)
    agent = tunnel.agent
    db.delete(tunnel)
    db.flush()
    _bump(agent, db)
    return Response(status_code=204)
