"""Domain model (SPEC §3)."""

from __future__ import annotations

import enum
import secrets
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


class Role(str, enum.Enum):
    admin = "admin"            # global superuser
    team_admin = "team_admin"  # manages own team: can connect agents to it
    user = "user"              # regular member
    demo = "demo"              # public read-only demo account


class TunnelType(str, enum.Enum):
    tcp = "tcp"
    udp = "udp"
    http = "http"
    https = "https"


class AgentStatus(str, enum.Enum):
    online = "online"
    offline = "offline"


class Team(Base):
    """Tenant boundary — agents/tunnels are scoped to a team; members share them."""

    __tablename__ = "teams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    subdomain_label: Mapped[str | None] = mapped_column(String(63), unique=True, nullable=True)  # DNS label; None = root
    quota_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)   # cumulative cap; None = unlimited
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    members: Mapped[list["User"]] = relationship(back_populates="team")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.user)   # admin = global superuser
    team_id: Mapped[int | None] = mapped_column(ForeignKey("teams.id"), nullable=True)
    # bumped on password change → invalidates all previously-issued JWTs (logout-everywhere)
    token_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    team: Mapped["Team | None"] = relationship(back_populates="members")


class Node(Base):
    """A server with a public IP running frps."""

    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    public_addr: Mapped[str] = mapped_column(String(255))            # IP or hostname
    control_port: Mapped[int] = mapped_column(Integer, default=7000)
    vhost_http_port: Mapped[int] = mapped_column(Integer, default=8090)
    subdomain_host: Mapped[str] = mapped_column(String(255))         # e.g. rc-tunnel.com
    node_token: Mapped[str] = mapped_column(String(255), default=_token)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    agents: Mapped[list["Agent"]] = relationship(back_populates="node")


class Agent(Base):
    """A machine behind NAT running our supervisor + vanilla frpc."""

    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    agent_token: Mapped[str] = mapped_column(String(255), unique=True, index=True, default=_token)
    # single-use: consumed on first enrollment; renewals authenticate via mTLS instead
    token_used: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"))
    team_id: Mapped[int | None] = mapped_column(ForeignKey("teams.id"), nullable=True)
    status: Mapped[AgentStatus] = mapped_column(Enum(AgentStatus), default=AgentStatus.offline)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lan_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os: Mapped[str | None] = mapped_column(String(32), nullable=True)
    arch: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_ping_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)   # control-plane RTT
    cert_days_left: Mapped[int | None] = mapped_column(Integer, nullable=True)  # mTLS cert lifetime (heartbeat)
    cert_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)  # current issued cert serial (revokes superseded certs)
    prev_cert_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)  # still-accepted during a renewal handoff
    generation: Mapped[int] = mapped_column(Integer, default=0)      # bumped on config change
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    node: Mapped[Node] = relationship(back_populates="agents")
    tunnels: Mapped[list["Tunnel"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )


class Tunnel(Base):
    """A single proxy (SPEC §3.1)."""

    __tablename__ = "tunnels"
    __table_args__ = (UniqueConstraint("agent_id", "name", name="uq_tunnel_agent_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id"))
    name: Mapped[str] = mapped_column(String(100))
    type: Mapped[TunnelType] = mapped_column(Enum(TunnelType))
    local_ip: Mapped[str] = mapped_column(String(64), default="auto")   # "auto" → resolved on agent
    local_port: Mapped[int] = mapped_column(Integer)
    remote_port: Mapped[int | None] = mapped_column(Integer, nullable=True)   # tcp/udp
    subdomain: Mapped[str | None] = mapped_column(String(100), nullable=True)  # http/https
    custom_domains: Mapped[str | None] = mapped_column(Text, nullable=True)    # CSV
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    # per-proxy options (frp transport / healthCheck / http)
    use_encryption: Mapped[bool] = mapped_column(Boolean, default=False)
    use_compression: Mapped[bool] = mapped_column(Boolean, default=False)
    bandwidth_limit: Mapped[str | None] = mapped_column(String(32), nullable=True)   # e.g. "1MB"
    health_check_type: Mapped[str | None] = mapped_column(String(8), nullable=True)   # tcp|http
    health_check_path: Mapped[str | None] = mapped_column(String(255), nullable=True)  # http
    http_user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    http_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    host_header_rewrite: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # traffic accounting (cumulative; deltas derived from frps "today" counters)
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0)
    last_today_in: Mapped[int] = mapped_column(BigInteger, default=0)
    last_today_out: Mapped[int] = mapped_column(BigInteger, default=0)

    agent: Mapped[Agent] = relationship(back_populates="tunnels")
