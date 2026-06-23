"""Pydantic request/response schemas (API boundary)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .models import AgentStatus, Role, TunnelType


# --- auth ---
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    role: Role = Role.user
    team_id: int | None = None


class UserRoleUpdate(BaseModel):
    role: Role


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    role: Role
    team_id: int | None
    created_at: datetime


class ProfileUpdate(BaseModel):
    email: EmailStr | None = None
    current_password: str | None = None        # required to set a new password
    new_password: str | None = Field(default=None, min_length=8)


# --- teams ---
class TeamCreate(BaseModel):
    name: str
    subdomain_label: str | None = None      # auto-slugged from name if omitted
    quota_bytes: int | None = None


class TeamUpdate(BaseModel):
    name: str | None = None
    subdomain_label: str | None = None
    quota_bytes: int | None = None      # suspension is derived from this (set 0 to force-suspend)


class TeamOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    subdomain_label: str | None
    quota_bytes: int | None
    suspended: bool
    created_at: datetime


# --- nodes ---
class NodeCreate(BaseModel):
    name: str
    public_addr: str
    subdomain_host: str
    control_port: int = 7000
    vhost_http_port: int = 8090


class NodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    public_addr: str
    subdomain_host: str
    control_port: int
    vhost_http_port: int
    created_at: datetime


# --- agents ---
def _require_name(v: str) -> str:
    v = (v or "").strip()
    if not v:
        raise ValueError("name must not be empty")
    return v


class AgentCreate(BaseModel):
    name: str
    node_id: int | None = None   # optional: defaults to the single system node

    _strip_name = field_validator("name")(_require_name)


class AgentUpdate(BaseModel):
    name: str

    _strip_name = field_validator("name")(_require_name)


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    node_id: int
    team_id: int | None
    status: AgentStatus
    last_seen: datetime | None
    lan_ip: str | None
    os: str | None
    arch: str | None
    agent_version: str | None
    last_ping_ms: int | None
    created_at: datetime


class AgentCreated(AgentOut):
    agent_token: str
    install_command: str


# --- tunnels ---
class _TunnelOpts(BaseModel):
    use_encryption: bool = False
    use_compression: bool = False
    bandwidth_limit: str | None = None            # e.g. "1MB", "100KB"
    health_check_type: str | None = None          # "tcp" | "http"
    health_check_path: str | None = None          # for http
    http_user: str | None = None
    http_password: str | None = None
    host_header_rewrite: str | None = None


class TunnelCreate(_TunnelOpts):
    name: str
    type: TunnelType
    local_port: int
    local_ip: str = "auto"
    remote_port: int | None = None
    subdomain: str | None = None
    custom_domains: str | None = None


class TunnelUpdate(BaseModel):
    enabled: bool | None = None
    local_ip: str | None = None
    local_port: int | None = None
    remote_port: int | None = None
    subdomain: str | None = None
    use_encryption: bool | None = None
    use_compression: bool | None = None
    bandwidth_limit: str | None = None
    health_check_type: str | None = None
    health_check_path: str | None = None
    http_user: str | None = None
    http_password: str | None = None
    host_header_rewrite: str | None = None


class TunnelOut(_TunnelOpts):
    model_config = ConfigDict(from_attributes=True)
    id: int
    agent_id: int
    name: str
    type: TunnelType
    local_ip: str
    local_port: int
    remote_port: int | None
    subdomain: str | None
    custom_domains: str | None
    enabled: bool
    bytes_in: int
    bytes_out: int


# --- enrollment (PKI) ---
class EnrollRequest(BaseModel):
    bootstrap_token: str
    csr_pem: str
    os: str | None = None
    arch: str | None = None


class EnrollResponse(BaseModel):
    agent_id: int
    agent_cert_pem: str
    ca_cert_pem: str
    node: NodeOut
    node_token: str
