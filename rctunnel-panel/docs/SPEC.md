# RC-Tunnel — specification

> **Status:** living spec (v1).
> **What it is:** a self-hosted, multi-tenant reverse-tunnel service — a Python
> control panel plus an own Go data-plane engine (`rctd` / `rctc`).

---

## 1. Purpose

A web panel + agent system that lets you:

1. Register **nodes** — machines with a public IP that run the data-plane server `rctd`.
2. Register **agents** — machines behind NAT that run the data-plane client `rctc`.
3. Create and manage **tunnels** that expose a local service publicly, without editing any config files by hand.
4. Distribute the agent + installer **from the panel itself** (no third-party hosting).
5. Manage agents **remotely** — the agent pulls its desired config from the master and applies it, with no SSH to each machine.
6. Isolate **tenants (teams)** cryptographically, so one team's agent can never claim another team's port or subdomain.

Self-hosted only: no public signup, email, billing, or password-reset flows.

---

## 2. Architecture

```
                       ┌─────────────────────────────────────────┐
   browser  ──HTTPS──▶ │ Caddy (80/443, automatic Let's Encrypt)  │
                       │   /            → master web/API           │
                       │   /dl/*        → agent installer/binaries │
                       │   *.domain     → rctd HTTP vhost          │
                       └───────┬───────────────────┬──────────────┘
                               │                   │
                    ┌──────────▼─────────┐   ┌─────▼───────────┐
                    │ master             │   │ rctd            │
                    │ (Python/FastAPI)   │   │ data plane (Go) │
                    │  - web UI + REST   │   │  control :7000  │
                    │  - control plane   │   │  workconn:7001  │
                    │    (WSS+mTLS) 8001 │   │  vhost   :8090  │
                    │  - traffic poller  │   └─────▲───────────┘
                    └──────────┬─────────┘         │ tunnels
                               │ WSS (control)      │
                    ┌──────────▼─────────────────┐  │
                    │ agent (Python supervisor)   │  │
                    │  - pulls desired config     │  │
                    │  - renders rctc.json        │  │
                    │  - runs rctc (engine)       ├──┘
                    │  - auto-localIP, heartbeat  │
                    └─────────────────────────────┘

   Postgres (datastore) · OpenSearch (audit/uptime/connection logs)
   — all of the above run as one Docker Compose stack.
```

**Own components:**
- **master** — control plane + web/API + traffic poller, one process (`python -m rctunnel_panel`).
- **rctd** — data-plane server, one per node (replaces external tunnel servers).
- **rctc** — data-plane client; runs as a subprocess of the agent.
- **agent** — lightweight Python supervisor that enrolls, keeps the control link, and manages `rctc`.

**Third-party (as-is):** Caddy (reverse proxy + TLS), Postgres, OpenSearch.

### 2.1 Port map

| Port | Component | Role |
|---|---|---|
| 80/443 | Caddy | public entry, TLS |
| 8000 | master | web/REST API (localhost, behind Caddy) |
| 8001 | master | control plane **mTLS** for agents (public, NOT behind Caddy; `wss://host:8001/agent-ws`) |
| 7000 | rctd | data-plane control (agents' `rctc` connect here) |
| 7001 | rctd | work connections (public) |
| 8090 | rctd | HTTP vhost (Caddy proxies `*.domain` here; localhost) |
| 7401 | rctd | stats JSON for the traffic poller (localhost) |
| 5432 | Postgres | datastore (localhost) |
| 9200 | OpenSearch | logs (localhost) |

> The agent control plane is **WSS with mutual TLS (mTLS)** on its own port 8001, terminated by the master itself (Caddy can't transparently forward client certs). Agents authenticate with a certificate issued by the panel's internal CA (§13), not a bearer token. The public web stays behind Caddy.

---

## 3. Domain model

| Entity | Description | Key fields |
|---|---|---|
| **Team** | tenant | id, name, subdomain_label, quota_bytes, suspended |
| **User** | panel account | id, email, password_hash, role (admin/team_admin/user/demo), team_id |
| **Node** | machine running `rctd` | id, name, public_addr, control_port, subdomain_host, node_token |
| **Agent** | machine running `rctc` | id, name, agent_token, node_id, team_id, status, agent_version, cert_days_left, lan_ip, os, arch |
| **Tunnel** | one exposed service | id, agent_id, name, type, local_ip, local_port, remote_port?, subdomain?, custom_domains?, enabled, traffic counters |

A tunnel's public URL is **`<subdomain>.<team-label>.<apex>`** — the team's
subdomain label namespaces tenants under the apex domain.

### 3.1 Tunnel types

| type | parameters | public access |
|---|---|---|
| `tcp` | local_ip, local_port, remote_port | `node_public_addr:remote_port` |
| `udp` | local_ip, local_port, remote_port | `node_public_addr:remote_port` (UDP) |
| `http` | local_ip, local_port, subdomain \| custom_domains | `https://<subdomain>.<team>.<apex>` via Caddy → vhost |
| `https` | local_ip, local_port, subdomain \| custom_domains | same path as http (TLS terminated by Caddy) |

`local_ip` supports the special value **`auto`** (§6.1).

---

## 4. Control plane (master ↔ agent)

Transport: **WebSocket over mTLS** (`wss://host:8001/agent-ws`). Agents
authenticate with their **client certificate** (issued by the panel CA, §13).
Messages are JSON.

### 4.0 Enrollment (once, before the first connection)

```
agent (generates an EC keypair LOCALLY) → master :  POST /api/agents/enroll {bootstrap_token, csr_pem}   # over public HTTPS
master → agent :  {agent_id, agent_cert_pem, ca_cert_pem, node, node_token}   # signed the CSR with the panel CA
```

The bootstrap token (`agent_token`) is exchanged for a certificate. The agent's
private key never leaves the host — only the CSR (public key) is sent. The same
flow is reused to **renew** the cert before expiry (§13.4).

### 4.1 Lifecycle (over the mTLS channel)

```
agent → master :  hello   {os, arch, agent_version, detected_ip}   # identity comes from the client cert CN
master → agent :  welcome {agent_id, node:{server_addr, server_port, token}}
master → agent :  config  {generation:N, grant, node, tunnels:[...]}   # desired state + signed authorization grant
agent  → master:  applied {generation:N, ok:true, rctc_pid}
agent  → master:  heartbeat {cert_days_left}                          # every ~15s
master → agent :  config  {...}                                      # pushed on any change in the panel
master → agent :  upgrade {version, base_url, files}                 # OTA, when /dl/manifest.json is newer
```

### 4.2 Principles

- **Desired-state, not commands.** The master sends the full target tunnel set with a generation number; the agent converges `rctc` to it idempotently (graceful reload, no drop of unrelated tunnels).
- **The agent is the only source of its LAN IP.** `auto` resolves on the agent.
- **Reconnect with backoff.** The master marks an agent offline on heartbeat timeout.
- **Per-agent grant.** Every `config` carries a panel-signed grant scoping which ports/hosts the agent may register; the data plane enforces it (§8, §12).

---

## 5. Data plane (rctd / rctc)

The agent renders `rctc.json` from the desired state and runs `rctc`, which
keeps one TLS/mTLS control connection to `rctd` and, per public connection,
dials back a **work connection**. Full wire protocol (control frames, the
work-connection model, and the UDP datagram framing): see the engine's
[`docs/PROTOCOL.md`](../../rctunnel-engine/docs/PROTOCOL.md).

- **tcp/http/https** — one short-lived work conn per public connection, raw bytes after a one-frame handshake.
- **udp** — one persistent work conn per proxy multiplexing all sources as framed datagrams.
- **Why NAT/CGNAT works:** the client always dials out; the public node relays. No hole-punching.

`rctc.json` (rendered by the agent) carries: `controlAddr`, `workConnAddr`,
`token`, `grant`, the TLS material paths (ca/cert/key), and the `proxies[]`
(tcp/udp/http/https only).

---

## 6. Agent features

### 6.1 `auto` localIP
The agent resolves its primary IPv4 (UDP-dial to a public address → read the
socket's local address; fall back to scanning interfaces, excluding
loopback/link-local). `auto` → detected IP; on failure → `127.0.0.1`.

### 6.2 Install from the panel (`/dl/`)
`install.sh` downloads `rctunnel_agent.py`, `localip.py`, and the `rctc` engine
binary from `https://<domain>/dl/...`, sets up a venv + systemd unit, and enrolls
with the bootstrap token. The panel shows the one-line install command.

### 6.3 OTA updates
The master tells an agent to upgrade when `/dl/manifest.json` is newer (file list
comes from the manifest). The agent downloads with retry, keeps `.bak` copies,
swaps atomically, and re-execs. A startup **crash-loop guard** restores the
previous code if the new version fails to come up.

### 6.4 English-only UI
Single-language (en); no i18n switcher.

---

## 7. Web/REST API (sketch)

```
POST   /api/auth/login            {email, password} → JWT (rate-limited)
GET    /api/nodes  · POST /api/nodes
GET    /api/agents · POST /api/agents · DELETE /api/agents/{id}
POST   /api/agents/enroll         CSR enrollment (bootstrap token)
GET    /api/agents/{id}/tunnels · POST /api/agents/{id}/tunnels
PATCH  /api/tunnels/{id} · DELETE /api/tunnels/{id}
GET    /api/teams  · POST /api/teams · members management
```

Mutations push a fresh `config` to the affected agent. Demo accounts are
read-only (every mutation blocked at the middleware).

---

## 8. Security

- Web login over real HTTPS (Caddy + Let's Encrypt); per-IP login rate-limit (real client IP via trusted proxy header).
- Passwords hashed (argon2). Sessions are JWT with expiry, `Secure` cookie; the master refuses to start with a default/empty signing secret.
- Control plane master↔agent and data plane rctc↔rctd both use **mutual TLS** on the panel CA (§13).
- **Tenant isolation via signed grants:** the panel HMAC-signs the set of ports/hosts each agent may register, bound to the agent's cert CN; `rctd` verifies the signature + CN + expiry and rejects any out-of-scope proxy. Work connections are bound to the owning identity.
- Input validation: strict subdomain charset (so a tunnel name can't inject extra grant hosts), reserved subdomain denylist, custom-domain validation (no claiming the apex or another tenant's domain).
- On-demand public TLS is gated — Caddy only issues a certificate for a host that maps to a real tunnel.
- Per-team traffic quotas (suspend on overage). Last-admin guard. Nightly backups (DB + PKI + certs).

---

## 9. Tech stack

| Layer | Choice |
|---|---|
| Web/API | FastAPI + Uvicorn |
| Models/validation | Pydantic v2 |
| ORM/DB | SQLAlchemy 2 + **Postgres** (psycopg 3) |
| Control plane | `websockets` over uvicorn mTLS (port 8001) |
| PKI | `cryptography` (X.509, EC P-256) — internal CA |
| Templates | Jinja2 (server-rendered UI) |
| Data-plane engine | Go (stdlib only), `rctd` / `rctc` |
| Agent | Python (`asyncio` + `subprocess`) |
| Logs | OpenSearch (audit / uptime / connection) |
| Reverse proxy/TLS | Caddy |

---

## 10. PKI and channel encryption

Internal CA in the master (`rctunnel_panel/pki.py`, on `cryptography`, EC P-256).

### 10.1 Hierarchy
```
RC-Tunnel Root CA  (self-signed, 10y, BasicConstraints CA:true)
├── server cert   (EKU serverAuth)  — control-plane mTLS listener (8001) and rctd
└── agent cert    (EKU clientAuth)  — one per agent, CN = agent.<id>, issued by signing a CSR
```
CA files: `${RCTUNNEL_PKI_DIR}/ca.crt`, `ca.key` (chmod 600), `server.crt/.key`.

### 10.2 Usage
- **Control plane (8001):** uvicorn terminates TLS with `CERT_REQUIRED` + `ca.crt`; the agent presents `agent.crt`; the master takes the identity from the CN. Mutual.
- **Data plane (rctc↔rctd):** the same CA in `rctc.json` / `rctd.yml` → verified mTLS.

### 10.3 Renewal
- Server cert: re-issued when within 30 days of expiry and hot-swapped into the live listener; `rctd` reloads it via a `GetCertificate` callback (no restart).
- Agent cert: the agent self-renews when within 30 days (re-runs the enrollment flow with the same token, same identity), then re-execs to load it. `cert_days_left` is reported in the heartbeat for visibility.

---

## 11. Deployment

One Docker Compose stack: `master` + `logship` + `caddy` + `rctd` + `postgres`
+ `opensearch`. The interactive installer `deploy/install-server.sh` (Ubuntu /
AlmaLinux) installs Docker, **builds the engine from source**, generates secrets,
renders all configs, and brings the stack up. See [INSTALL.md](INSTALL.md).
