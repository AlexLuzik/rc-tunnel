# RC-Tunnel

Self-hosted, multi-tenant **reverse-tunnel service** — expose services running
behind NAT/firewalls at `https://<sub>.<team>.<your-domain>` (HTTP/HTTPS) or on a
public TCP/UDP port. You run it on one public host; agents on your private
machines dial home and publish their local ports through it.

Think "your own ngrok", but multi-tenant, mTLS end-to-end, and fully self-hosted —
no third-party relay, no public signup, no per-tunnel pricing.

## How it works

```
 private host (agent)                 public host (this repo)              internet
 ┌───────────────────┐                ┌───────────────────────────┐
 │ rctc  ─ mTLS ────────── :7000/7001 ── rctd (data plane) ──┐    │
 │ rctunnel_agent.py ─ WSS(mTLS) ─ :8001 ─ control plane     │    │
 │ local service :8080│                │  Caddy :80/:443 ─ TLS ───────── <sub>.<team>.<domain>
 └───────────────────┘                │  panel (FastAPI/Jinja) :8000│
                                      │  Postgres · OpenSearch     │
                                      └───────────────────────────┘
```

1. An admin adds an **agent** in the panel and runs its one-line installer on a
   private host.
2. The agent **enrolls** over HTTPS (CSR → signed mTLS cert from the panel's
   internal CA), then opens a persistent **mTLS WebSocket** to the control plane.
3. The panel pushes the agent its config + a per-agent signed **grant**; the
   agent's `rctc` connects to the node's `rctd` and starts forwarding.
4. Public traffic hits **Caddy**, which terminates Let's Encrypt TLS and reverse-
   proxies HTTP tunnels by hostname, or `rctd` exposes raw TCP/UDP ports.

## Highlights

- **Multi-tenant.** Teams with per-team subdomain namespaces; `admin` /
  `team-admin` / `member` / `demo` roles.
- **mTLS everywhere** on an internal PKI with auto-renewing certs. Agents
  self-heal if their cached CA goes stale.
- **Cryptographic tenant isolation.** Per-agent signed *grants* — an agent can
  only register the ports/hosts it owns.
- **Automatic public TLS** (Let's Encrypt, on-demand) gated to real tunnels.
- **Traffic accounting + quotas**, audit / uptime / connection logs, and **OTA**
  agent updates with crash-loop rollback.
- **One-command install** on a bare Ubuntu/AlmaLinux host.

> Platform: Linux. Single node, self-hosted (no public signup/billing).

## Repository

This repo contains both components:

- **[`rctunnel-panel/`](rctunnel-panel/)** — control panel (FastAPI/Jinja),
  mTLS control plane, agent, and the full Docker stack + installer.
  See [`rctunnel-panel/README.md`](rctunnel-panel/README.md) for the deep dive.
- **[`rctunnel-engine/`](rctunnel-engine/)** — the data-plane engine in Go
  (`rctd` server / `rctc` client). Protocol: [`rctunnel-engine/docs/PROTOCOL.md`](rctunnel-engine/docs/PROTOCOL.md).

## Install (production)

On a fresh Ubuntu or AlmaLinux host, with this repo cloned:

```bash
sudo bash rctunnel-panel/deploy/install-server.sh
```

The installer is interactive and idempotent. It:

- installs Docker (handles AlmaLinux/RHEL where the convenience script doesn't),
- loads the kernel modules Docker's networking needs (and offers a reboot if the
  running kernel lacks them),
- builds the Go engine from source in an ephemeral container,
- generates secrets (reused on re-run so the DB password stays stable), renders
  all configs, and brings up the whole stack — panel, Postgres, `rctd`, Caddy,
  OpenSearch, log shipper.

Then point DNS (`<domain>` **and** `*.<domain>`) at the host, sign in, add an
agent, and run its installer on the target. Full runbook:
[`rctunnel-panel/docs/INSTALL.md`](rctunnel-panel/docs/INSTALL.md).

## Update

To update an existing install in place — preserves all data and secrets,
rebuilds from source, recreates only what changed (Postgres/OpenSearch/Caddy keep
running), runs schema migrations on boot, and republishes the agent for OTA:

```bash
cd <repo> && git pull
sudo bash rctunnel-panel/deploy/update-server.sh           # --check to preview versions, --yes to skip the prompt
```

Connected agents pick up the new agent version automatically.

## Develop

The panel is a standard Python app:

```bash
cd rctunnel-panel
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
RCTUNNEL_JWT_SECRET=$(openssl rand -hex 32) .venv/bin/python -m rctunnel_panel
curl -s http://127.0.0.1:8000/healthz
```

Tests are standalone scripts — run each in its own process:

```bash
cd rctunnel-panel
PYTHONPATH=. .venv/bin/python tests/test_phase1.py
```

Configuration is via `RCTUNNEL_`-prefixed env vars (or a `.env`); the key
settings are documented in [`rctunnel-panel/README.md`](rctunnel-panel/README.md).
The Go engine and its tests live in [`rctunnel-engine/`](rctunnel-engine/).

## Documentation

- [`rctunnel-panel/docs/INSTALL.md`](rctunnel-panel/docs/INSTALL.md) — zero-to-tunnel install runbook
- [`rctunnel-panel/docs/SPEC.md`](rctunnel-panel/docs/SPEC.md) — full system spec
- [`rctunnel-panel/docs/DESIGN.md`](rctunnel-panel/docs/DESIGN.md) — design notes
- [`rctunnel-engine/docs/PROTOCOL.md`](rctunnel-engine/docs/PROTOCOL.md) — data-plane protocol

## License

[MIT](LICENSE) © 2026 Oleksandr Luzin
