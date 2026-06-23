"""Database engine, session factory, and declarative base."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings

_settings = get_settings()

_is_sqlite = _settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}
# pool_pre_ping recycles dead connections (e.g. after a Postgres restart) instead
# of handing the request a stale socket; recycle hourly. No-op cost on SQLite.
_engine_kw = {} if _is_sqlite else {"pool_pre_ping": True, "pool_recycle": 1800}
engine = create_engine(_settings.database_url, connect_args=_connect_args, future=True, **_engine_kw)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yields a session, closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# columns added after the initial release; applied to live DBs without Alembic.
_ADDED_COLUMNS = {
    "users": {
        "team_id": "INTEGER",
        "token_version": "INTEGER NOT NULL DEFAULT 0",
    },
    "teams": {
        "subdomain_label": "VARCHAR(63)",
        "quota_bytes": "INTEGER",
        "suspended": "BOOLEAN NOT NULL DEFAULT false",
    },
    "agents": {
        "agent_version": "VARCHAR(16)",
        "team_id": "INTEGER",
        "last_ping_ms": "INTEGER",
        "cert_days_left": "INTEGER",
        "cert_serial": "VARCHAR(64)",
        "prev_cert_serial": "VARCHAR(64)",
        "token_used": "BOOLEAN NOT NULL DEFAULT false",
    },
    "tunnels": {
        "bytes_in": "INTEGER NOT NULL DEFAULT 0",
        "bytes_out": "INTEGER NOT NULL DEFAULT 0",
        "last_today_in": "INTEGER NOT NULL DEFAULT 0",
        "last_today_out": "INTEGER NOT NULL DEFAULT 0",
        "use_encryption": "BOOLEAN NOT NULL DEFAULT false",
        "use_compression": "BOOLEAN NOT NULL DEFAULT false",
        "bandwidth_limit": "VARCHAR(32)",
        "health_check_type": "VARCHAR(8)",
        "health_check_path": "VARCHAR(255)",
        "http_user": "VARCHAR(128)",
        "http_password": "VARCHAR(255)",
        "host_header_rewrite": "VARCHAR(255)",
    },
}


def _auto_migrate() -> None:
    """Idempotently add missing columns to existing tables (SQLite ADD COLUMN)."""
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    pre_agents = {c["name"] for c in insp.get_columns("agents")} if "agents" in existing_tables else set()
    with engine.begin() as conn:
        for table, cols in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue  # create_all will build it fresh with all columns
            have = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols.items():
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        # One-time when token_used is first added: burn the token of agents that
        # already enrolled (they renew over mTLS now and would never re-enroll to
        # set it). Runs only on the add, so it won't clobber a later reissue.
        if "agents" in existing_tables and "token_used" not in pre_agents:
            conn.execute(text("UPDATE agents SET token_used=true "
                              "WHERE agent_version IS NOT NULL OR last_seen IS NOT NULL"))
        # rename legacy frp-named node columns -> engine-neutral (idempotent)
        if "nodes" in existing_tables:
            ncols = {c["name"] for c in insp.get_columns("nodes")}
            if "frps_control_port" in ncols and "control_port" not in ncols:
                conn.execute(text("ALTER TABLE nodes RENAME COLUMN frps_control_port TO control_port"))
            if "frp_token" in ncols and "node_token" not in ncols:
                conn.execute(text("ALTER TABLE nodes RENAME COLUMN frp_token TO node_token"))


def _seed_default_team() -> None:
    """Ensure a default team exists and backfill any rows with NULL team_id."""
    from .models import Agent, Team, User

    with SessionLocal() as db:
        if db.query(User).count() == 0:
            return  # fresh DB; nothing to backfill
        team = db.query(Team).filter(Team.name == "default").first()
        if team is None:
            team = Team(name="default", subdomain_label="default")
            db.add(team)
            db.flush()
        if not team.subdomain_label:  # mandatory team label at the 2nd level
            team.subdomain_label = "default"
        for row in db.query(User).filter(User.team_id.is_(None)):
            row.team_id = team.id
        for row in db.query(Agent).filter(Agent.team_id.is_(None)):
            row.team_id = team.id
        db.commit()


SYSTEM_NODE_NAME = "system"


def _seed_system_node() -> None:
    """Maintain exactly one data-plane node, derived from settings.

    The service runs a single node (this host), so the node is not user-managed:
    it is provisioned and kept in sync from the install config on every startup.
    An existing (e.g. legacy hand-added) node is adopted in place so agents keep
    their node_id; otherwise one is created.
    """
    from .models import Node

    s = get_settings()
    with SessionLocal() as db:
        node = db.query(Node).order_by(Node.id).first()
        if node is None:
            node = Node(name=SYSTEM_NODE_NAME)
            db.add(node)
        node.name = SYSTEM_NODE_NAME
        node.public_addr = s.node_public_addr or s.public_domain
        node.subdomain_host = s.public_domain
        node.control_port = s.rctd_control_port
        node.vhost_http_port = s.rctd_vhost_port
        if s.node_token:                 # keep the existing/random token if none configured
            node.node_token = s.node_token
        db.commit()


def _seed_demo() -> None:
    """Create a public read-only demo: Demo team + demo user + sample agent/tunnels."""
    import datetime as _dt
    import secrets

    from .models import Agent, AgentStatus, Node, Role, Team, Tunnel, TunnelType, User
    from .security import hash_password

    with SessionLocal() as db:
        if db.query(User).filter(User.email == "demo@rc-tunnel.com").first():
            return  # already seeded
        team = db.query(Team).filter(Team.name == "Demo").first()
        if team is None:
            team = Team(name="Demo", subdomain_label="demo")
            db.add(team)
            db.flush()
        db.add(User(email="demo@rc-tunnel.com", password_hash=hash_password(secrets.token_hex(16)),
                    role=Role.demo, team_id=team.id))
        node = db.query(Node).first()
        if node is not None:
            agent = Agent(name="demo-edge", node_id=node.id, team_id=team.id,
                          status=AgentStatus.online, os="linux", arch="x86_64",
                          agent_version="0.6.0", lan_ip="10.0.0.42", last_ping_ms=23,
                          last_seen=_dt.datetime.now(_dt.timezone.utc))
            db.add(agent)
            db.flush()
            db.add(Tunnel(agent_id=agent.id, name="demo-site", type=TunnelType.http,
                          local_ip="auto", local_port=8080, subdomain="demo", enabled=True))
            db.add(Tunnel(agent_id=agent.id, name="demo-ssh", type=TunnelType.tcp,
                          local_ip="auto", local_port=22, remote_port=12022, enabled=True,
                          health_check_type="tcp"))
        db.commit()


def init_db() -> None:
    """Create missing tables, add missing columns, backfill tenancy."""
    from . import models  # noqa: F401  (register mappers)

    _auto_migrate()                        # ALTER existing tables before...
    Base.metadata.create_all(bind=engine)  # ...creating brand-new ones (teams, agents)
    _seed_default_team()
    _seed_system_node()                    # single system node before demo can attach to it
    if _settings.demo_mode:                # public demo deployment only; off for normal installs
        _seed_demo()
