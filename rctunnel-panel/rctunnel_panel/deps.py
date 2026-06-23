"""Shared FastAPI dependencies: auth, CA singleton."""

from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Role, User
from .pki import CA
from .security import decode_token


@lru_cache
def get_ca() -> CA:
    ca = CA(get_settings().pki_dir)
    ca.ensure()
    return ca


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("rctunnel_token")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    user = db.get(User, int(payload["sub"]))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    if payload.get("tv", 0) != user.token_version:   # revoked (e.g. password changed)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin required")
    return user


def check_team_access(resource_team_id: int | None, user: User) -> None:
    """Global admins see everything; others only their own team's resources."""
    if user.role == Role.admin:
        return
    if resource_team_id is None or resource_team_id != user.team_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
