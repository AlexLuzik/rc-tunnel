"""Runtime configuration, loaded from environment / .env."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RCTUNNEL_", env_file=".env", extra="ignore")

    # --- web / api ---
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    public_domain: str = "rc-tunnel.com"          # used to build subdomain URLs
    public_base_url: str = "https://rc-tunnel.com"
    subdomain_max_depth: int = 5                   # labels before apex incl. mandatory team label (Caddy must match)

    # --- auth ---
    jwt_secret: str = "change-me"                  # override in .env (long random)
    jwt_ttl_hours: int = 24
    cookie_secure: bool = True
    allow_register: bool = False                   # public registration disabled by default

    # --- database ---
    database_url: str = "sqlite:///./rctunnel-panel.db"

    # --- control plane (mTLS, direct, NOT behind Caddy) ---
    control_host: str = "0.0.0.0"
    control_port: int = 8001

    # --- internal PKI ---
    pki_dir: str = "./pki"                          # CA + server cert live here
    agent_cert_days: int = 365                      # issued agent cert validity

    # --- tcp/udp ports ---
    tcp_port_min: int = 10000          # auto-allocation pool (when remote_port omitted)
    tcp_port_max: int = 60000
    port_allow_min: int = 1024         # manual remote_port allowed range (matches frps allowPorts)
    port_allow_max: int = 65535

    # --- OpenSearch (audit / connection / uptime logs) ---
    opensearch_url: str = "http://127.0.0.1:9200"
    logs_enabled: bool = True

    traffic_poll_secs: int = 30

    # --- data-plane engine (rctunnel-engine: rctd/rctc) ---
    rctd_workconn_port: int = 7001                   # rctd work-connection port
    rctd_control_port: int = 7000                    # rctd control port agents dial (matches rctd.yml `control`)
    rctd_vhost_port: int = 8090                      # rctd vhost http (Caddy reverse-proxies here)
    rctd_stats_url: str = "http://127.0.0.1:7401"    # rctd /api/stats (traffic poller)
    grant_secret: str = ""                           # HMAC secret shared with rctd; signs per-agent authorization grants

    # --- the single data-plane node (this host); auto-provisioned, not user-managed ---
    node_public_addr: str = ""                       # public IP/host agents dial; "" -> public_domain
    node_token: str = ""                             # data-plane token handed to agents; must match rctd.yml `token`

    # --- distribution (/dl) ---
    download_dir: str = "/var/www/rctunnel-panel-dl"

    # --- public showcase / demo deployment ---
    demo_mode: bool = False                          # landing page on /, seed read-only demo team/user/agent

    @property
    def agent_ws_url(self) -> str:
        return self.public_base_url.replace("https://", "wss://").replace("http://", "ws://") + "/agent-ws"


@lru_cache
def get_settings() -> Settings:
    return Settings()
