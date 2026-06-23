"""Control-plane message shapes (SPEC §4). JSON over the mTLS WebSocket."""

from __future__ import annotations

from .. import grant
from ..models import Agent, Node, Tunnel

# message types
HELLO = "hello"          # agent -> master
WELCOME = "welcome"      # master -> agent
CONFIG = "config"        # master -> agent (desired state)
APPLIED = "applied"      # agent -> master
HEARTBEAT = "heartbeat"  # agent -> master
LOG = "log"              # agent -> master
UPGRADE = "upgrade"      # master -> agent (OTA)
RENEW = "renew"          # agent -> master (mTLS-authenticated cert renewal: CSR)
RENEWED = "renewed"      # master -> agent (signed cert + CA)


def upgrade_payload(version: str, base_url: str, files: list[str] | None = None,
                    sha256: dict | None = None) -> dict:
    return {
        "type": UPGRADE,
        "version": version,
        "base_url": base_url,
        # Files to fetch+swap. Default to the current agent files only; the legacy
        # rcpanel_agent.py is gone from /dl, so requesting it would 404 the whole
        # upgrade. Agents now run rctunnel_agent.py (post-rename reinstall).
        "files": files or ["rctunnel_agent.py", "localip.py"],
        # Trusted (mTLS-delivered) SHA-256 of each artifact; the agent verifies the
        # /dl download against this before installing.
        "sha256": sha256 or {},
    }


def tunnel_payload(t: Tunnel) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "proxy_name": f"t{t.id}",          # globally-unique frp proxy name (multi-tenant safe)
        "type": t.type.value,
        "local_ip": t.local_ip,
        "local_port": t.local_port,
        "remote_port": t.remote_port,
        "subdomain": t.subdomain,
        "custom_domains": t.custom_domains,
        "use_encryption": t.use_encryption,
        "use_compression": t.use_compression,
        "bandwidth_limit": t.bandwidth_limit,
        "health_check_type": t.health_check_type,
        "health_check_path": t.health_check_path,
        "http_user": t.http_user,
        "http_password": t.http_password,
        "host_header_rewrite": t.host_header_rewrite,
    }


def welcome_payload(agent: Agent, node: Node) -> dict:
    return {
        "type": WELCOME,
        "agent_id": agent.id,
        "node": {
            "server_addr": node.public_addr,
            "server_port": node.control_port,
            "token": node.node_token,
        },
    }


def _domainize(p: dict, subdomain_host: str, team_label: str | None) -> dict:
    """Build full-FQDN customDomains (frp has no subDomainHost here). The team's
    subdomain_label namespaces tenants: <sub>.<team_label>.<apex>."""
    if p["type"] in ("http", "https"):
        suffix = f"{team_label}.{subdomain_host}" if team_label else subdomain_host
        fqdns = []
        if p.get("subdomain"):
            fqdns.append(f'{p["subdomain"]}.{suffix}')
        if p.get("custom_domains"):
            fqdns += [d.strip() for d in p["custom_domains"].split(",") if d.strip()]
        p["subdomain"] = None
        p["custom_domains"] = ",".join(fqdns) if fqdns else None
    return p


def config_payload(agent: Agent, node: Node, tunnels: list[Tunnel],
                   team_label: str | None = None,
                   workconn_port: int = 7001, grant_secret: str = "") -> dict:
    enabled = [t for t in tunnels if t.enabled]
    out_tunnels = [_domainize(tunnel_payload(t), node.subdomain_host, team_label)
                   for t in enabled]
    # Authorization grant: scope this agent (its mTLS cert CN) to exactly the
    # ports/hosts it owns, so rctd refuses any cross-tenant registration.
    grant_token = ""
    if grant_secret:
        ports = [tp["remote_port"] for tp in out_tunnels
                 if tp["type"] in ("tcp", "udp") and tp.get("remote_port")]
        hosts: list[str] = []
        for tp in out_tunnels:
            if tp["type"] in ("http", "https") and tp.get("custom_domains"):
                hosts += [h.strip() for h in tp["custom_domains"].split(",") if h.strip()]
        grant_token = grant.sign(grant_secret, f"agent.{agent.id}", ports, hosts)
    return {
        "type": CONFIG,
        "generation": agent.generation,
        "grant": grant_token,
        "node": {
            "server_addr": node.public_addr,
            "server_port": node.control_port,
            "workconn_port": workconn_port,
            "token": node.node_token,
        },
        "tunnels": out_tunnels,
    }
