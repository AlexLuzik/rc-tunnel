"""Team (tenant) management — global-admin only."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, require_admin
from ..models import Team, User
from ..schemas import TeamCreate, TeamOut, TeamUpdate, UserOut

router = APIRouter()


def _slug(name: str) -> str | None:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:63]
    return s or None


@router.get("", response_model=list[TeamOut], dependencies=[Depends(require_admin)])
def list_teams(db: Session = Depends(get_db)) -> list[Team]:
    return list(db.scalars(select(Team)))


@router.post("", response_model=TeamOut, dependencies=[Depends(require_admin)])
def create_team(body: TeamCreate, db: Session = Depends(get_db)) -> Team:
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "team name required")
    if db.scalar(select(Team).where(Team.name == name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "team name exists")
    label = _slug(body.subdomain_label) if body.subdomain_label else _slug(name)
    if label and db.scalar(select(Team).where(Team.subdomain_label == label)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"subdomain label '{label}' is taken")
    team = Team(name=name, subdomain_label=label, quota_bytes=body.quota_bytes)
    db.add(team)
    db.commit()
    db.refresh(team)
    return team


@router.patch("/{team_id}", response_model=TeamOut, dependencies=[Depends(require_admin)])
def update_team(team_id: int, body: TeamUpdate, db: Session = Depends(get_db)) -> Team:
    team = db.get(Team, team_id)
    if team is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "team not found")
    old_label = team.subdomain_label
    fields = body.model_dump(exclude_unset=True)
    if "name" in fields:
        fields["name"] = (fields["name"] or "").strip()
        if not fields["name"]:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "team name required")
        if db.scalar(select(Team).where(Team.name == fields["name"], Team.id != team_id)):
            raise HTTPException(status.HTTP_409_CONFLICT, "team name exists")
        # subdomain follows the name on rename (team label is mandatory, always derived)
        if "subdomain_label" not in fields:
            fields["subdomain_label"] = _slug(fields["name"])
    if "subdomain_label" in fields and fields["subdomain_label"]:
        fields["subdomain_label"] = _slug(fields["subdomain_label"])
    if fields.get("subdomain_label") and db.scalar(
            select(Team).where(Team.subdomain_label == fields["subdomain_label"], Team.id != team_id)):
        raise HTTPException(status.HTTP_409_CONFLICT, "subdomain label is taken")
    for k, v in fields.items():
        setattr(team, k, v)
    db.flush()
    # suspension is derived from quota immediately (raising/clearing quota resumes the team)
    from sqlalchemy import func
    from ..models import Agent, Tunnel
    usage = db.scalar(
        select(func.coalesce(func.sum(Tunnel.bytes_in + Tunnel.bytes_out), 0))
        .join(Agent, Tunnel.agent_id == Agent.id).where(Agent.team_id == team_id)
    ) or 0
    was = team.suspended
    team.suspended = team.quota_bytes is not None and usage > team.quota_bytes
    label_changed = old_label != team.subdomain_label
    # subdomain change re-routes every http tunnel's FQDN -> agents must re-register.
    if label_changed:
        for ag in db.scalars(select(Agent).where(Agent.team_id == team_id)):
            ag.generation += 1
    db.commit()
    db.refresh(team)
    # push fresh config when suspension or subdomain changed
    if was != team.suspended or label_changed:
        from ..control.bus import notify_agent
        for aid in db.scalars(select(Agent.id).where(Agent.team_id == team_id)):
            notify_agent(aid)
    return team


@router.delete("/{team_id}", dependencies=[Depends(require_admin)])
def delete_team(team_id: int, db: Session = Depends(get_db)) -> Response:
    team = db.get(Team, team_id)
    if team is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "team not found")
    from ..models import Agent
    if db.scalar(select(User).where(User.team_id == team_id)):
        raise HTTPException(status.HTTP_409_CONFLICT, "team has members; reassign them first")
    if db.scalar(select(Agent).where(Agent.team_id == team_id)):
        raise HTTPException(status.HTTP_409_CONFLICT, "team has agents; delete them first")
    db.delete(team)
    db.commit()
    return Response(status_code=204)


@router.post("/{team_id}/members/{user_id}", response_model=UserOut,
             dependencies=[Depends(require_admin)])
def add_member(team_id: int, user_id: int, db: Session = Depends(get_db)) -> User:
    if db.get(Team, team_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "team not found")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    user.team_id = team_id
    db.commit()
    db.refresh(user)
    return user


@router.get("/me", response_model=TeamOut | None)
def my_team(db: Session = Depends(get_db), user: User = Depends(current_user)) -> Team | None:
    return db.get(Team, user.team_id) if user.team_id else None
