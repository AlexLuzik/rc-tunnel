# RC-Tunnel

Self-hosted, multi-tenant **reverse-tunnel service** — expose services running
behind NAT/firewalls at `https://<sub>.<team>.<your-domain>` (HTTP/HTTPS) or on a
public TCP/UDP port. This repo is the control panel (`rctunnel-panel`); the data
plane is the Go engine **rctunnel-engine** (`rctd` server / `rctc` client). Full
spec: [docs/SPEC.md](docs/SPEC.md).

**Highlights**
- Teams + per-team subdomain namespaces; admin / team-admin / member / demo roles.
- mTLS everywhere on an internal PKI (auto-renewing certs).
- Per-agent signed *grants* — an agent can only register the ports/hosts it owns
  (cryptographic tenant isolation).
- Automatic public TLS (Let's Encrypt) gated to real tunnels.
- Traffic accounting + quotas, audit / uptime / connection logs, OTA agent updates
  with crash-loop rollback.

> Platform: Linux. Single node. Self-hosted (no public signup/billing).

## Components

- **master** — FastAPI web/API + Jinja UI + the mTLS control plane (one process,
  `python -m rctunnel_panel`).
- **rctd / rctc** — the data plane (separate repo `rctunnel-engine`); agents run
  `rctc`, the node runs `rctd`. mTLS on the panel's own PKI; per-agent signed
  *grants* scope which ports/hosts each agent may register (tenant isolation).
- **Postgres** — primary datastore. **Caddy** — public TLS (Let's Encrypt,
  auto-renewing) + reverse proxy. **OpenSearch** — audit/uptime/connection logs.

## Run (dev)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
RCTUNNEL_JWT_SECRET=$(openssl rand -hex 32) .venv/bin/python -m rctunnel_panel
curl -s http://127.0.0.1:8000/healthz
```

Tests: `PYTHONPATH=. .venv/bin/python tests/test_phase1.py` (each `tests/test_*.py`
is a standalone script). Engine tests run in a container — see `rctunnel-engine`.

## Configuration

Environment variables with prefix `RCTUNNEL_` (or a `.env` file). Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `RCTUNNEL_PUBLIC_DOMAIN` | `rc-tunnel.com` | apex for tunnel subdomains (`<sub>.<team>.<domain>`) |
| `RCTUNNEL_PUBLIC_BASE_URL` | `https://rc-tunnel.com` | panel base URL |
| `RCTUNNEL_JWT_SECRET` | `change-me` | **must override** (long random); master refuses to start on the default |
| `RCTUNNEL_DATABASE_URL` | `sqlite:///./rctunnel-panel.db` | DB DSN; prod uses `postgresql+psycopg://…` |
| `RCTUNNEL_GRANT_SECRET` | _(unset)_ | HMAC secret shared with `rctd`; when set, grant enforcement is on |
| `RCTUNNEL_ENGINE` | `rctunnel` | data-plane engine |

## Layout

```
rctunnel_panel/
  config.py     settings (pydantic-settings, RCTUNNEL_ prefix)
  db.py         engine, sessions, init_db (+ idempotent column migrations)
  models.py     Team / User / Node / Agent / Tunnel / Visitor
  pki.py        internal CA: issues + auto-renews agent/server mTLS certs
  grant.py      signs per-agent authorization grants
  ratelimit.py  per-IP login throttle
  main.py       FastAPI app, middleware, /healthz
  __main__.py   process entrypoint (web + control plane + traffic poller)
  api/          REST routers
  control/      WSS control plane, protocol, agent manager, traffic poller
  web/          server-rendered routes (login, dashboard, on-demand-TLS gate)
  templates/    Jinja UI
agent/          rctunnel_agent.py (rctc supervisor) + localip.py
deploy/         Caddyfile, systemd units, install.sh, master.env.example
scripts/        bootstrap_admin.py, publish.py, sqlite_to_pg.py
docs/           SPEC.md, INSTALL.md
```

## Install (self-hoster)

See **[docs/INSTALL.md](docs/INSTALL.md)** for the zero-to-tunnel runbook (DNS,
bootstrap admin, publish artifacts, add node, enroll agent).
