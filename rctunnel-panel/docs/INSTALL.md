# RC-Tunnel — self-hoster install runbook

Zero-to-tunnel for a single Linux box. The box runs the panel (master), Postgres,
the data-plane engine (`rctd`), and Caddy — all via Docker Compose. Agents run on
the machines you want to expose.

Replace `rc-tunnel.com` with your own apex domain throughout.

## Automated installer (recommended)

On a **fresh Ubuntu or AlmaLinux** host, with both the `rctunnel-panel` and
`rctunnel-engine` repos present (side by side), run the interactive installer:

```bash
sudo bash rctunnel-panel/deploy/install-server.sh
```

It detects the distro, installs Docker, **builds the `rctd`/`rctc` engine from
source** in an ephemeral container, generates all secrets, renders every config,
brings up the full stack (**including OpenSearch** for the Activity/Fleet/audit
logs), publishes agent artifacts, creates your admin, and installs the nightly
backup timer — printing each step to the console and to
`/var/log/rctunnel-install-<ts>.log`. It also sets `vm.max_map_count` (required by
OpenSearch). The manual steps below document what it does under the hood.

> RAM: OpenSearch wants ~2× its JVM heap free (default 512m heap → ~1 GB). Budget
> at least 2 GB total for a comfortable single-node box.

## 0. Prerequisites

- A Linux host with a public IP and Docker + Docker Compose.
- A domain you control, with **two DNS records** pointing at the host's public IP:
  - `rc-tunnel.com`        → `A <host-ip>`   (the panel)
  - `*.rc-tunnel.com`      → `A <host-ip>`   (wildcard, for tunnel URLs)
- Open inbound ports: `80`, `443` (Caddy), and the data-plane work-conn port
  (`7001` by default) for tunnel traffic.

## 1. Configure the master

Create `/etc/rctunnel-panel/master.env` (see `deploy/master.env.example`):

```ini
RCTUNNEL_PUBLIC_DOMAIN=rc-tunnel.com
RCTUNNEL_PUBLIC_BASE_URL=https://rc-tunnel.com
RCTUNNEL_JWT_SECRET=<openssl rand -hex 32>          # long random; master won't start on the default
RCTUNNEL_DATABASE_URL=postgresql+psycopg://rctunnel:<db-pass>@127.0.0.1:5432/rctunnel
RCTUNNEL_GRANT_SECRET=<openssl rand -hex 32>        # also put this in rctd.yml — enables tenant isolation
```

The matching `grant_secret` must be set in the node config `rctd.yml` so the
engine enforces per-agent grants.

## 2. Bring up the stack

```bash
cd /opt/rctunnel-stack          # docker-compose.yml lives here
docker compose up -d postgres   # wait until healthy: docker compose ps
docker compose up -d            # master, logship, caddy, rctd
```

Caddy obtains Let's Encrypt certs automatically (and renews them). The internal
mTLS PKI (CA + server + agent certs) is created and auto-renewed by the master.

## 3. Create the admin

```bash
docker exec rctunnel-panel-master python -m scripts.bootstrap_admin you@example.com 'a-strong-password'
# -> "admin you@example.com created — sign in at https://rc-tunnel.com/login"
```

Re-run the same command any time to **reset** the password (this is the recovery
path — there is no email reset).

## 4. Publish agent artifacts to /dl

Agents download themselves and the `rctc` engine from the panel:

```bash
docker exec rctunnel-panel-master python -m scripts.publish --dir /var/www/rctunnel-panel-dl --skip-frpc
```

This writes `rctunnel_agent.py`, `localip.py`, `install.sh`, the `rctc-<arch>`
binary, and `manifest.json` (the version agents auto-update to via OTA).

## 5. Add a node, then a team

Sign in at `https://rc-tunnel.com/login`, then on the dashboard add a **node**:

- **Address** — the node's public IP that TCP/UDP tunnels publish to (e.g. the
  host's public IP).
- **Subdomain host** — your wildcard apex, e.g. `rc-tunnel.com`. Must match the
  `*.` DNS record. This is the suffix for tunnel URLs.

Under **Admin → Teams**, give each team a **subdomain label** — tunnel URLs are
`<subdomain>.<team-label>.<apex>` (the team label namespaces tenants).

## 6. Enroll an agent

Add an **agent** (dashboard → Add agent), open it, and copy its install command.
Run it **on the machine you want to expose**:

```bash
curl -fsSL https://rc-tunnel.com/dl/install.sh | sudo bash -s -- \
  --base-url https://rc-tunnel.com/dl --token <agent-token>
```

This installs a `rctunnel-agent` systemd service in `/opt/rctunnel-agent`, enrolls
for an mTLS cert, and connects. Re-running with the same token re-enrolls the same
agent (e.g. to migrate or repair). Future updates roll out automatically via OTA.

## 7. Create a tunnel

On the agent page, add a tunnel:

- **http/https** → reachable at `<subdomain>.<team-label>.<apex>`. Some labels are
  reserved (DNS/infra names); custom external domains can be set via *custom
  domains* (must not be under your apex, and must be globally unique).
- **tcp/udp** → a public port is auto-assigned on the node.

The public URL is shown in the agent's tunnel list. Caddy issues a cert on first
request (only for real tunnels — the on-demand gate refuses unknown hosts).

## Backups & DR

A systemd timer (`rctunnel-backup.timer`, 03:30 daily) runs
`/opt/rctunnel-stack/backup.sh`: a Postgres dump + roles, the PKI (**including
`ca.key`**), panel config, and Caddy certs → `/root/rctunnel-backups` (14-day
rotation). **Copy these off-box** for real disaster recovery — losing `ca.key`
means re-enrolling every agent.

## Demo account

`https://rc-tunnel.com/demo` is a passwordless, read-only sample tenant. Disable
it by removing the `demo@rc-tunnel.com` user if you don't want it public.
