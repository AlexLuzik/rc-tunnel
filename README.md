# RC-Tunnel

Self-hosted, multi-tenant **reverse-tunnel service** — expose services running
behind NAT/firewalls at `https://<sub>.<team>.<your-domain>` (HTTP/HTTPS) or on a
public TCP/UDP port.

This repository contains both components:

- **[`rctunnel-panel/`](rctunnel-panel/)** — the control panel (FastAPI/Jinja),
  control plane, agent, and the full Docker stack + installer.
- **[`rctunnel-engine/`](rctunnel-engine/)** — the data-plane engine in Go
  (`rctd` server / `rctc` client).

## Install

On a fresh Ubuntu/AlmaLinux host (with this repo cloned):

```bash
sudo bash rctunnel-panel/deploy/install-server.sh
```

It installs Docker, builds the engine from source, generates secrets, renders all
configs, and brings up the whole stack. Details:
[`rctunnel-panel/docs/INSTALL.md`](rctunnel-panel/docs/INSTALL.md).
