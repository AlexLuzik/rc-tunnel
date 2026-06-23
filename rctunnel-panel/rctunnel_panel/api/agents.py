"""Agent CRUD + CSR enrollment (PKI, SPEC §13)."""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import ratelimit
from ..config import get_settings
from ..db import get_db
from ..deps import check_team_access, current_user, get_ca
from ..models import Agent, Node, Role, User, _token
from ..pki import CA
from ..schemas import (
    AgentCreate,
    AgentCreated,
    AgentOut,
    AgentUpdate,
    EnrollRequest,
    EnrollResponse,
    NodeOut,
)

router = APIRouter()


def _revoke_serial(serial: str | None) -> None:
    """Append a cert serial to the revoked-serials file the data-plane (rctd) reads,
    so a stolen/replaced cert is rejected at rctd too, not just the panel control
    plane. Best-effort: a write failure must not block the API action."""
    if not serial or serial == "revoked":
        return
    try:
        from pathlib import Path
        p = Path(get_settings().pki_dir) / "revoked-serials"
        with p.open("a", encoding="ascii") as f:
            f.write(serial.strip() + "\n")
    except Exception:  # noqa: BLE001
        pass


def _install_command(token: str) -> str:
    s = get_settings()
    base = s.public_base_url.rstrip("/")
    return (
        f"curl -fsSL {base}/dl/install.sh | bash -s -- "
        f"--base-url {base}/dl --token {token}"
    )


@router.get("", response_model=list[AgentOut])
def list_agents(db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[Agent]:
    q = select(Agent)
    if user.role.value != "admin":
        q = q.where(Agent.team_id == user.team_id)
    return list(db.scalars(q))


@router.post("", response_model=AgentCreated)
def create_agent(body: AgentCreate, db: Session = Depends(get_db),
                 user: User = Depends(current_user)) -> AgentCreated:
    if user.role not in (Role.admin, Role.team_admin):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "only a team admin can connect new agents")
    if db.scalar(select(Agent).where(Agent.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "agent name exists")
    # single system node: use it by default; honour an explicit id if still passed.
    node = db.get(Node, body.node_id) if body.node_id else db.scalars(
        select(Node).order_by(Node.id)).first()
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "node not found")
    agent = Agent(name=body.name, node_id=node.id, team_id=user.team_id)
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return AgentCreated(
        **AgentOut.model_validate(agent).model_dump(),
        agent_token=agent.agent_token,
        install_command=_install_command(agent.agent_token),
    )


@router.patch("/{agent_id}", response_model=AgentOut)
def update_agent(agent_id: int, body: AgentUpdate, db: Session = Depends(get_db),
                 user: User = Depends(current_user)) -> Agent:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    check_team_access(agent.team_id, user)
    if db.scalar(select(Agent).where(Agent.name == body.name, Agent.id != agent_id)):
        raise HTTPException(status.HTTP_409_CONFLICT, "agent name exists")
    agent.name = body.name
    db.commit()
    db.refresh(agent)
    return agent


@router.delete("/{agent_id}")
def delete_agent(agent_id: int, db: Session = Depends(get_db),
                 user: User = Depends(current_user)) -> Response:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    check_team_access(agent.team_id, user)
    _revoke_serial(agent.cert_serial)   # reject the deleted agent's cert at rctd too
    db.delete(agent)
    db.commit()
    return Response(status_code=204)


@router.post("/{agent_id}/reissue-token", response_model=AgentCreated)
def reissue_token(agent_id: int, db: Session = Depends(get_db),
                  user: User = Depends(current_user)) -> AgentCreated:
    """Mint a fresh single-use bootstrap token (re-provision a host). The old
    token stops working; the agent must be reinstalled with the new command."""
    if user.role not in (Role.admin, Role.team_admin):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only a team admin can reissue tokens")
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    check_team_access(agent.team_id, user)
    _revoke_serial(agent.cert_serial)   # add the old serial to the data-plane denylist
    agent.agent_token = _token()
    agent.token_used = False
    # Force-revoke the current cert too: a non-empty sentinel serial matches no real
    # cert, so the existing (possibly stolen) cert is rejected on its next connect.
    # The reinstall re-enrolls and pins a fresh real serial.
    agent.cert_serial = "revoked"
    agent.prev_cert_serial = None
    db.commit()
    db.refresh(agent)
    return AgentCreated(
        **AgentOut.model_validate(agent).model_dump(),
        agent_token=agent.agent_token,
        install_command=_install_command(agent.agent_token),
    )


@router.post("/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, request: Request, db: Session = Depends(get_db),
           ca: CA = Depends(get_ca)) -> EnrollResponse:
    """Public endpoint authenticated by the one-time bootstrap token.

    Agent sends a CSR (its public key); we sign it with the panel CA and return
    the agent cert + CA cert. The agent's private key never reaches us.
    """
    # This is the only internet-facing endpoint that mints a cert; throttle bad
    # tokens per-IP just like login, so it can't be used as a token-guessing oracle.
    ip = request.client.host if request.client else None
    ratelimit.guard(ip)
    agent = db.scalar(select(Agent).where(Agent.agent_token == body.bootstrap_token))
    if agent is None:
        ratelimit.record_fail(ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid bootstrap token")
    # Single-use: the bootstrap token is good for the FIRST enrollment only. Cert
    # renewals authenticate via the existing mTLS cert over the control plane, so a
    # leaked install-command token is useless once the agent has enrolled.
    if agent.token_used:
        ratelimit.record_fail(ip)
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "bootstrap token already used — reissue it from the panel")
    # NB: do NOT clear the throttle on success — a single valid-token holder must
    # not be able to reset the bucket and brute-force other tokens from one IP.
    s = get_settings()
    try:
        cert_pem = ca.sign_csr(
            body.csr_pem.encode(),
            identity=f"agent.{agent.id}",
            days=s.agent_cert_days,
            client=True,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"bad CSR: {e}")

    # Burn the token ATOMICALLY: a single conditional UPDATE (token_used 0->1) so
    # that concurrent enrolls with the same token can't all succeed (TOCTOU). Only
    # the row-winner proceeds; everyone else gets 409. Pin the new cert's serial in
    # the same write. Done after signing so a bad CSR doesn't waste the token.
    serial = str(x509.load_pem_x509_certificate(cert_pem).serial_number)
    burned = db.execute(
        update(Agent).where(Agent.id == agent.id, Agent.token_used.is_(False))
        .values(token_used=True, cert_serial=serial, prev_cert_serial=None,
                os=body.os, arch=body.arch, last_seen=datetime.now(timezone.utc)))
    db.commit()
    if burned.rowcount != 1:
        ratelimit.record_fail(ip)
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "bootstrap token already used — reissue it from the panel")
    db.refresh(agent)
    node = agent.node
    return EnrollResponse(
        agent_id=agent.id,
        agent_cert_pem=cert_pem.decode(),
        ca_cert_pem=ca.cert_pem.decode(),
        node=NodeOut.model_validate(node),
        node_token=node.node_token,
    )
