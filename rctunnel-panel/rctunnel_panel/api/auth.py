"""Auth + user management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import logs, ratelimit
from ..db import get_db
from ..deps import current_user, require_admin
from ..models import Role, User
from ..schemas import LoginRequest, ProfileUpdate, TokenResponse, UserCreate, UserOut, UserRoleUpdate
from ..security import create_token, hash_password, verify_password

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    ip = request.client.host if request.client else None
    ratelimit.guard(ip)
    user = db.scalar(select(User).where(User.email == body.email))
    if user is None or not verify_password(body.password, user.password_hash):
        ratelimit.record_fail(ip)
        logs.audit(actor=body.email, action="auth", label="auth.fail", target="session", ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    ratelimit.clear(ip)  # clear on success
    logs.audit(actor=user.email, action="auth", label="auth.login", target="session",
               ip=ip, team_id=user.team_id)
    return TokenResponse(access_token=create_token(user_id=user.id, role=user.role.value))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> User:
    return user


@router.patch("/me", response_model=UserOut)
def update_me(body: ProfileUpdate, db: Session = Depends(get_db),
              user: User = Depends(current_user)) -> User:
    if body.email and body.email != user.email:
        if db.scalar(select(User).where(User.email == body.email, User.id != user.id)):
            raise HTTPException(status.HTTP_409_CONFLICT, "email already in use")
        user.email = body.email
    if body.new_password:
        if not body.current_password or not verify_password(body.current_password, user.password_hash):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "current password is incorrect")
        user.password_hash = hash_password(body.new_password)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)) -> Response:
    if user_id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "you cannot delete your own account")
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    db.delete(u)
    db.commit()
    return Response(status_code=204)


@router.patch("/users/{user_id}", response_model=UserOut, dependencies=[Depends(require_admin)])
def update_user_role(user_id: int, body: UserRoleUpdate, db: Session = Depends(get_db)) -> User:
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if u.role == Role.admin and body.role != Role.admin:
        others = db.scalar(select(func.count()).select_from(User)
                           .where(User.role == Role.admin, User.id != user_id)) or 0
        if others == 0:
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot remove the last global admin")
    u.role = body.role
    db.commit()
    db.refresh(u)
    return u


@router.post("/users", response_model=UserOut, dependencies=[Depends(require_admin)])
def create_user(body: UserCreate, db: Session = Depends(get_db)) -> User:
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already exists")
    user = User(email=body.email, password_hash=hash_password(body.password),
                role=body.role, team_id=body.team_id)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
