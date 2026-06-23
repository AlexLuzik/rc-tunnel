#!/usr/bin/env bash
# =============================================================================
#  RC-Tunnel server installer — bare Ubuntu / AlmaLinux.
#
#  Interactive, console-based. Installs Docker, builds the data-plane engine
#  (rctd/rctc) FROM SOURCE inside an ephemeral container, generates secrets,
#  renders all configs, and brings up the full stack (panel + Postgres + rctd +
#  Caddy + log shipper). Every step is echoed to the console AND to a log file.
#
#  Run as root from inside the rctunnel-panel repo:
#      sudo bash deploy/install-server.sh
#
#  Needs the rctunnel-engine source too (for building rctd/rctc).
# =============================================================================
set -euo pipefail

# ---- logging: everything to console + a timestamped install log -------------
TS="$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/rctunnel-install-${TS}.log"
mkdir -p /var/log
exec > >(tee -a "$LOG") 2>&1

c_reset=$'\e[0m'; c_b=$'\e[1m'; c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_c=$'\e[36m'
stage() { echo; echo "${c_c}${c_b}==> [$(date +%H:%M:%S)] $*${c_reset}"; }
info()  { echo "    $*"; }
ok()    { echo "${c_g}    ✓ $*${c_reset}"; }
warn()  { echo "${c_y}    ! $*${c_reset}"; }
die()   { echo "${c_r}${c_b}ERROR: $*${c_reset}" >&2; echo "See full log: $LOG" >&2; exit 1; }
ask()   { # ask VAR "prompt" "default"  — prompt straight to the terminal
  local __v="$1" __p="$2" __d="${3:-}" __in
  if [ -n "$__d" ]; then printf '    %s [%s]: ' "$__p" "$__d" >/dev/tty
  else printf '    %s: ' "$__p" >/dev/tty; fi
  read -r __in </dev/tty || true
  [ -z "$__in" ] && __in="$__d"
  printf -v "$__v" '%s' "$__in"
}
ask_secret() { # ask_secret VAR "prompt"  (hidden; empty -> autogenerate)
  local __v="$1" __p="$2" __in
  printf '    %s (blank = auto-generate): ' "$__p" >/dev/tty
  read -rs __in </dev/tty || true; printf '\n' >/dev/tty
  printf -v "$__v" '%s' "$__in"
}
yesno() { local __p="$1" __d="${2:-y}" __in __h
  __h=$([ "$__d" = y ] && echo "Y/n" || echo "y/N")
  printf '    %s [%s]: ' "$__p" "$__h" >/dev/tty
  read -r __in </dev/tty || true; __in="${__in:-$__d}"; [[ "$__in" =~ ^[Yy] ]]; }
rand()  { openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | xxd -p | tr -d '\n'; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)."

echo "${c_b}RC-Tunnel server installer${c_reset}  —  log: $LOG"

# ---- OS detection -----------------------------------------------------------
stage "Detecting OS"
. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"
case "$OS_ID" in
  ubuntu|debian) PKG=apt ;;
  almalinux|rocky|rhel|centos|fedora) PKG=dnf ;;
  *) case "$OS_LIKE" in *debian*) PKG=apt;; *rhel*|*fedora*) PKG=dnf;; *) die "unsupported OS: $OS_ID (need Ubuntu or AlmaLinux)";; esac ;;
esac
ARCH_RAW="$(uname -m)"; case "$ARCH_RAW" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) die "unsupported arch: $ARCH_RAW";; esac
ok "$PRETTY_NAME  ($PKG, $ARCH)"

# ---- locate sources ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_DEFAULT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENGINE_DEFAULT="$(cd "$PANEL_DEFAULT/.." && pwd)/rctunnel-engine"

stage "Configuration (interactive)"
ask DOMAIN        "Public apex domain (DNS A + wildcard *.) point here" "rc-tunnel.com"
ask ACME_EMAIL    "Email for Let's Encrypt" "admin@${DOMAIN}"
ask ADMIN_EMAIL   "Panel admin login email" "admin@${DOMAIN}"
ask_secret ADMIN_PASS "Panel admin password"
ask PANEL_SRC     "rctunnel-panel source dir" "$PANEL_DEFAULT"
ask ENGINE_SRC    "rctunnel-engine source dir" "$ENGINE_DEFAULT"
ask WORKCONN_PORT "rctd work-connection port (public)" "7001"
ask CONTROL_PORT  "agent control-plane port (public, mTLS)" "8001"
ask RCTD_CTRL_PORT "rctd control port (public)" "7000"
ask OS_HEAP       "OpenSearch JVM heap (needs ~2x this in free RAM)" "512m"
OPEN_FW=n; yesno "Open firewall ports (80,443,${RCTD_CTRL_PORT},${WORKCONN_PORT},${CONTROL_PORT})?" y && OPEN_FW=y
# Demo deployment: public landing page on / + a seeded read-only demo account.
DEMO_MODE=n; yesno "Demo deployment? (public landing on / + read-only demo account)" n && DEMO_MODE=y
# Offer to reset the DB only when one already exists; default no (keep data).
WIPE_DB=n
if command -v docker >/dev/null 2>&1 && docker volume ls --format '{{.Name}}' 2>/dev/null | grep -q '_pgdata$'; then
  yesno "Existing database found — RESET it? (DESTROYS all panel data)" n && WIPE_DB=y
fi

[ -f "$PANEL_SRC/requirements.txt" ] && [ -d "$PANEL_SRC/rctunnel_panel" ] || die "not a panel repo: $PANEL_SRC"
[ -d "$ENGINE_SRC/cmd/rctd" ] && [ -d "$ENGINE_SRC/cmd/rctc" ] || die "not an engine repo: $ENGINE_SRC"
[ -n "$ADMIN_PASS" ] || { ADMIN_PASS="$(rand | cut -c1-20)"; GEN_PASS=1; }

echo
echo "${c_b}  Summary:${c_reset}"
echo "    domain=$DOMAIN  acme=$ACME_EMAIL  admin=$ADMIN_EMAIL"
echo "    panel=$PANEL_SRC"
echo "    engine=$ENGINE_SRC  (build rctd/rctc for $ARCH from source)"
echo "    ports: 80,443 + rctd $RCTD_CTRL_PORT/$WORKCONN_PORT + control $CONTROL_PORT ; firewall=$OPEN_FW ; reset-db=$WIPE_DB ; demo=$DEMO_MODE"
yesno "Proceed with installation?" y || die "aborted by user."

# ---- install prerequisites --------------------------------------------------
stage "Installing prerequisites (Docker, git, openssl, rsync)"
if [ "$PKG" = apt ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ca-certificates curl git openssl rsync xxd
else
  dnf install -y ca-certificates curl git openssl rsync vim-common
fi
if ! command -v docker >/dev/null 2>&1; then
  if [ "$PKG" = apt ]; then
    info "installing Docker via get.docker.com ..."
    curl -fsSL https://get.docker.com | sh
  else
    # get.docker.com rejects AlmaLinux/Rocky ("Unsupported distribution"), so on
    # RHEL-family hosts install straight from Docker's CE repo. AlmaLinux/Rocky are
    # binary-compatible with RHEL, so the centos repo serves the right packages.
    case "$OS_ID" in fedora) DOCKER_REPO=fedora;; *) DOCKER_REPO=centos;; esac
    info "installing Docker from Docker CE repo ($DOCKER_REPO) ..."
    dnf install -y dnf-plugins-core
    # dnf4 (Alma 8/9) uses --add-repo; dnf5 (Alma 10/Fedora 41+) uses addrepo.
    dnf config-manager --add-repo "https://download.docker.com/linux/${DOCKER_REPO}/docker-ce.repo" 2>/dev/null \
      || dnf config-manager addrepo --from-repofile="https://download.docker.com/linux/${DOCKER_REPO}/docker-ce.repo"
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
      || die "Docker CE install failed"
  fi
else ok "Docker already present"; fi

# Docker's bridge networking needs these netfilter/overlay modules. Some VPS
# images (e.g. Contabo) boot a stripped kernel without them, and dockerd dies
# with "addrtype ... missing kernel module?". Load + persist them; if they're
# absent from the running kernel, install the distro kernel and ask for a reboot.
stage "Loading kernel modules required by Docker"
cat > /etc/modules-load.d/rctunnel-docker.conf <<'EOF'
overlay
br_netfilter
xt_addrtype
EOF
NEED_REBOOT=0
for m in overlay br_netfilter xt_addrtype; do
  if modprobe "$m" 2>/dev/null; then ok "module $m loaded"
  else warn "module $m missing from running kernel $(uname -r)"; NEED_REBOOT=1; fi
done

stage "Starting Docker daemon"
systemctl enable --now docker 2>/dev/null || true
for i in 1 2 3 4 5; do docker info >/dev/null 2>&1 && break; sleep 2; done
if ! docker info >/dev/null 2>&1; then
  # daemon won't come up — almost always the missing kernel modules above.
  if [ "$NEED_REBOOT" = 1 ] && [ "$PKG" = dnf ]; then
    info "installing distro kernel + modules so a reboot provides them ..."
    dnf install -y kernel kernel-modules kernel-modules-extra || true
  fi
  RERUN="sudo bash \"$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")\""
  warn "Docker daemon did not start — the running kernel is missing modules it needs."
  echo
  echo "${c_y}${c_b}  ACTION REQUIRED — reboot, then re-run this installer to continue:${c_reset}"
  echo "      reboot"
  echo "      ${RERUN}"
  echo
  echo "  Safe to re-run: nothing has been generated yet; it resumes from this point"
  echo "  once Docker is up. Full log so far: $LOG"
  echo
  if yesno "Reboot now?" y; then
    info "rebooting — re-run the installer after the host is back up:"
    info "  ${RERUN}"
    sleep 2
    reboot
    exit 0
  fi
  warn "skipping reboot — reboot manually, then re-run: ${RERUN}"
  exit 0
fi
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"
ok "docker $(docker --version | awk '{print $3}' | tr -d ,) + compose ready"

# ---- system user + directories ----------------------------------------------
stage "Creating caddy user + directory layout"
if ! getent group caddy >/dev/null; then groupadd -r caddy; fi
if ! getent passwd caddy >/dev/null; then useradd -r -g caddy -d /var/lib/caddy -s /sbin/nologin caddy; fi
CADDY_UID="$(id -u caddy)"; CADDY_GID="$(id -g caddy)"
ok "caddy user uid:gid = ${CADDY_UID}:${CADDY_GID}"

mkdir -p /opt/rctunnel-stack/caddy-data /opt/rctunnel-panel /opt/rctunnel-engine /opt/rctunnel-node \
         /etc/rctunnel-panel /etc/caddy /var/lib/rctunnel-panel/pki /var/www/rctunnel-panel-dl /var/lib/caddy
chown -R "${CADDY_UID}:${CADDY_GID}" /var/lib/caddy /opt/rctunnel-stack/caddy-data
chmod 700 /etc/rctunnel-panel /var/lib/rctunnel-panel/pki   # CA key + serials: root-only
ok "directories created"

# OpenSearch needs a high mmap count on the host or it refuses to start.
if [ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]; then
  sysctl -w vm.max_map_count=262144 >/dev/null
  echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-rctunnel-opensearch.conf
  ok "vm.max_map_count set to 262144 (persisted)"
else ok "vm.max_map_count already sufficient"; fi

# ---- copy sources -----------------------------------------------------------
stage "Copying sources into /opt"
rsync -a --delete --exclude '.venv' --exclude '__pycache__' --exclude '*.db' --exclude '*.db-*' \
      --exclude 'pki' --exclude '.git' "$PANEL_SRC"/  /opt/rctunnel-panel/
rsync -a --delete --exclude 'bin' --exclude '.git' "$ENGINE_SRC"/ /opt/rctunnel-engine/
ok "panel + engine copied"

# ---- build engine binaries FROM SOURCE (ephemeral golang container) ---------
stage "Building rctd + rctc from source (ephemeral golang:1.23 container)"
info "go vet + static build, GOARCH=$ARCH — output streamed below:"
docker run --rm --security-opt label=disable -v /opt/rctunnel-engine:/src -w /src \
  -e GOCACHE=/tmp/gc -e GOPATH=/tmp/gp -e GOFLAGS=-mod=mod \
  golang:1.23 bash -c "
    set -e
    echo '--- go vet ---'; go vet ./...
    echo '--- building rctd ---'; CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags '-s -w' -o bin/rctd ./cmd/rctd
    echo '--- building rctc ---'; CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags '-s -w' -o bin/rctc ./cmd/rctc
    ls -la bin/" || die "engine build failed"
[ -x /opt/rctunnel-engine/bin/rctd ] && [ -x /opt/rctunnel-engine/bin/rctc ] || die "engine binaries missing after build"
# place rctd in its docker build context; publish rctc to /dl for agents
cp -f /opt/rctunnel-engine/bin/rctd /opt/rctunnel-node/rctd
cp -f /opt/rctunnel-engine/bin/rctc "/var/www/rctunnel-panel-dl/rctc-${ARCH}"
chmod +x /opt/rctunnel-node/rctd "/var/www/rctunnel-panel-dl/rctc-${ARCH}"
cat > /opt/rctunnel-node/Dockerfile.rctd <<'EOF'
FROM debian:stable-slim
COPY rctd /usr/local/bin/rctd
ENTRYPOINT ["/usr/local/bin/rctd"]
EOF
ok "built rctd ($(stat -c%s /opt/rctunnel-node/rctd) B) + rctc ($(stat -c%s /var/www/rctunnel-panel-dl/rctc-${ARCH}) B)"

# ---- secrets + configs ------------------------------------------------------
stage "Generating secrets + rendering configs"
# Reuse secrets from a previous install if present. Critical for re-runs: the
# Postgres password is baked into the pgdata volume on first init and ignored
# afterwards, so regenerating it would lock us out of the existing database.
# Reusing JWT/grant/node secrets also keeps sessions and the rctd token valid.
ENV_FILE=/etc/rctunnel-panel/master.env
getenv() { [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2- || true; }
JWT_SECRET="$(getenv RCTUNNEL_JWT_SECRET)";   [ -n "$JWT_SECRET" ]   || JWT_SECRET="$(rand)"
GRANT_SECRET="$(getenv RCTUNNEL_GRANT_SECRET)"; [ -n "$GRANT_SECRET" ] || GRANT_SECRET="$(rand)"
NODE_TOKEN="$(getenv RCTUNNEL_NODE_TOKEN)";    [ -n "$NODE_TOKEN" ]   || NODE_TOKEN="$(rand | cut -c1-32)"
PG_PASS="$(getenv RCTUNNEL_DATABASE_URL | sed -nE 's#.*rctunnel:([^@]+)@.*#\1#p')"
[ -n "$PG_PASS" ] || PG_PASS="$(rand | cut -c1-32)"
[ -f "$ENV_FILE" ] && ok "reusing existing secrets from $ENV_FILE (DB password preserved)"

cat > /etc/rctunnel-panel/master.env <<EOF
RCTUNNEL_PUBLIC_DOMAIN=${DOMAIN}
RCTUNNEL_PUBLIC_BASE_URL=https://${DOMAIN}
RCTUNNEL_JWT_SECRET=${JWT_SECRET}
RCTUNNEL_PKI_DIR=/var/lib/rctunnel-panel/pki
RCTUNNEL_DOWNLOAD_DIR=/var/www/rctunnel-panel-dl
RCTUNNEL_API_HOST=127.0.0.1
RCTUNNEL_API_PORT=8000
RCTUNNEL_CONTROL_HOST=0.0.0.0
RCTUNNEL_CONTROL_PORT=${CONTROL_PORT}
RCTUNNEL_COOKIE_SECURE=true
RCTUNNEL_DATABASE_URL=postgresql+psycopg://rctunnel:${PG_PASS}@127.0.0.1:5432/rctunnel
RCTUNNEL_GRANT_SECRET=${GRANT_SECRET}
RCTUNNEL_RCTD_WORKCONN_PORT=${WORKCONN_PORT}
RCTUNNEL_RCTD_CONTROL_PORT=${RCTD_CTRL_PORT}
RCTUNNEL_NODE_PUBLIC_ADDR=${DOMAIN}
RCTUNNEL_NODE_TOKEN=${NODE_TOKEN}
RCTUNNEL_DEMO_MODE=$([ "$DEMO_MODE" = y ] && echo true || echo false)
EOF
chmod 600 /etc/rctunnel-panel/master.env

cat > /etc/rctunnel-panel/rctd.yml <<EOF
# RC-Tunnel data-plane server (rctd).
control: ":${RCTD_CTRL_PORT}"
work:    ":${WORKCONN_PORT}"
vhost:   "127.0.0.1:8090"
stats:   "127.0.0.1:7401"
token:   "${NODE_TOKEN}"
cert:    "/var/lib/rctunnel-panel/pki/server.crt"
key:     "/var/lib/rctunnel-panel/pki/server.key"
ca:      "/var/lib/rctunnel-panel/pki/ca.crt"
grant_secret: "${GRANT_SECRET}"
revoked: "/var/lib/rctunnel-panel/pki/revoked-serials"
EOF
chmod 600 /etc/rctunnel-panel/rctd.yml

# Caddyfile (apex panel + wildcard tunnels up to 5 labels + /dl + on-demand gate)
WILDCARDS="*.${DOMAIN}, *.*.${DOMAIN}, *.*.*.${DOMAIN}, *.*.*.*.${DOMAIN}, *.*.*.*.*.${DOMAIN}"
cat > /etc/caddy/Caddyfile <<EOF
{
	email ${ACME_EMAIL}
	on_demand_tls {
		ask http://127.0.0.1:8000/_ondemand
	}
}

${DOMAIN} {
	encode zstd gzip
	handle_path /dl/* {
		root * /var/www/rctunnel-panel-dl
		file_server
	}
	handle {
		reverse_proxy 127.0.0.1:8000
	}
}

${WILDCARDS} {
	tls {
		on_demand
	}
	log {
		output file /var/lib/caddy/access.log {
			roll_size 50MiB
			roll_keep 3
		}
		format json
	}
	reverse_proxy 127.0.0.1:8090 {
		header_up Host {host}
		header_up X-Forwarded-Host {host}
		@gone status 404 502 503
		handle_response @gone {
			rewrite * /_offline
			reverse_proxy 127.0.0.1:8000 {
				header_up X-Tunnel-Host {host}
			}
		}
	}
}
EOF
ok "master.env, rctd.yml, Caddyfile written (secrets generated)"

# ---- docker-compose.yml -----------------------------------------------------
stage "Writing docker-compose.yml"
cat > /opt/rctunnel-stack/docker-compose.yml <<EOF
# RC-Tunnel stack (host networking; Postgres on a published localhost port).
services:
  master:
    build: /opt/rctunnel-panel
    image: rctunnel-app:latest
    container_name: rctunnel-panel-master
    network_mode: host
    env_file: /etc/rctunnel-panel/master.env
    volumes:
      - /var/lib/rctunnel-panel:/var/lib/rctunnel-panel
      - /var/www/rctunnel-panel-dl:/var/www/rctunnel-panel-dl
    security_opt: [label=disable]
    ulimits:
      nofile: { soft: 65536, hard: 65536 }
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

  logship:
    image: rctunnel-app:latest
    container_name: rctunnel-panel-logship
    network_mode: host
    env_file: /etc/rctunnel-panel/master.env
    environment:
      - RCTUNNEL_CADDY_ACCESS_LOG=/var/lib/caddy/access.log
    command: ["python", "-m", "rctunnel_panel.logship"]
    volumes:
      - /var/lib/rctunnel-panel:/var/lib/rctunnel-panel
      - /var/lib/caddy:/var/lib/caddy:ro
    security_opt: [label=disable]
    ulimits:
      nofile: { soft: 65536, hard: 65536 }
    depends_on: [master]
    restart: unless-stopped

  caddy:
    image: caddy:2
    container_name: rctunnel-caddy
    network_mode: host
    user: "${CADDY_UID}:${CADDY_GID}"
    environment:
      - XDG_DATA_HOME=/var/lib/caddy/.local/share
      - XDG_CONFIG_HOME=/var/lib/caddy/.config
    volumes:
      - /etc/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - /var/www/rctunnel-panel-dl:/var/www/rctunnel-panel-dl:ro
      - /opt/rctunnel-stack/caddy-data:/data
      - /var/lib/caddy:/var/lib/caddy
    security_opt: [label=disable]
    restart: unless-stopped

  rctd:
    build:
      context: /opt/rctunnel-node
      dockerfile: Dockerfile.rctd
    image: rctunnel-rctd:latest
    container_name: rctunnel-rctd
    network_mode: host
    command: ["-config", "/etc/rctunnel-panel/rctd.yml"]
    volumes:
      - /etc/rctunnel-panel/rctd.yml:/etc/rctunnel-panel/rctd.yml:ro
      - /var/lib/rctunnel-panel/pki:/var/lib/rctunnel-panel/pki:ro
    security_opt: [label=disable]
    restart: unless-stopped

  postgres:
    image: postgres:16
    container_name: rctunnel-postgres
    environment:
      - POSTGRES_USER=rctunnel
      - POSTGRES_PASSWORD=${PG_PASS}
      - POSTGRES_DB=rctunnel
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "127.0.0.1:5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U rctunnel -d rctunnel"]
      interval: 10s
      timeout: 5s
      retries: 5
    shm_size: "256mb"
    restart: unless-stopped

  # Audit / connection / uptime logs (Activity + Fleet screens). The panel
  # reaches it at 127.0.0.1:9200 and degrades gracefully if it is down.
  opensearch:
    image: opensearchproject/opensearch:2.18.0
    container_name: rctunnel-opensearch
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
      - DISABLE_INSTALL_DEMO_CONFIG=true
      - bootstrap.memory_lock=true
      - "OPENSEARCH_JAVA_OPTS=-Xms${OS_HEAP} -Xmx${OS_HEAP}"
      - cluster.name=rctunnel
      - node.name=rctunnel-os
    ulimits:
      memlock: { soft: -1, hard: -1 }
      nofile: { soft: 65536, hard: 65536 }
    volumes:
      - osdata:/usr/share/opensearch/data
    ports:
      - "127.0.0.1:9200:9200"
    restart: unless-stopped

volumes:
  pgdata:
  osdata:
EOF
chmod 600 /opt/rctunnel-stack/docker-compose.yml   # embeds POSTGRES_PASSWORD
ok "compose written (incl. OpenSearch, heap ${OS_HEAP})"

# ---- build images + start stack ---------------------------------------------
stage "Building images (master + rctd)"
docker compose -f /opt/rctunnel-stack/docker-compose.yml build || die "image build failed"

if [ "$WIPE_DB" = y ]; then
  stage "Resetting database (pgdata volume)"
  # resolve the actual data volume from the container mount before removing it,
  # so this works regardless of the compose project-name prefix.
  PG_VOL="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}' rctunnel-postgres 2>/dev/null || true)"
  docker compose -f /opt/rctunnel-stack/docker-compose.yml rm -sf postgres >/dev/null 2>&1 || true
  [ -n "$PG_VOL" ] && docker volume rm "$PG_VOL" >/dev/null 2>&1 || true
  docker volume ls --format '{{.Name}}' 2>/dev/null | grep '_pgdata$' | xargs -r docker volume rm >/dev/null 2>&1 || true
  ok "pgdata volume removed — Postgres will re-init with the current password"
fi

stage "Starting Postgres + waiting for healthy"
docker compose -f /opt/rctunnel-stack/docker-compose.yml up -d postgres
for i in $(seq 1 30); do
  h="$(docker inspect -f '{{.State.Health.Status}}' rctunnel-postgres 2>/dev/null || echo starting)"
  info "postgres: $h"; [ "$h" = healthy ] && break; sleep 2
  [ "$i" = 30 ] && die "postgres did not become healthy"
done
ok "postgres healthy"

stage "Starting the full stack"
docker compose -f /opt/rctunnel-stack/docker-compose.yml up -d
sleep 6
docker compose -f /opt/rctunnel-stack/docker-compose.yml ps

# ---- publish agent artifacts + bootstrap admin ------------------------------
stage "Publishing agent artifacts to /dl"
docker exec rctunnel-panel-master python -m scripts.publish || warn "publish failed (retry later)"
ok "manifest: $(cat /var/www/rctunnel-panel-dl/manifest.json 2>/dev/null)"

stage "Creating panel admin"
# Pipe the password via stdin (printf is a shell builtin, so it never appears in
# the host process list) rather than passing it as a docker exec argument.
printf '%s\n' "$ADMIN_PASS" | docker exec -i rctunnel-panel-master python -m scripts.bootstrap_admin "$ADMIN_EMAIL" || warn "bootstrap_admin failed (run manually)"

# ---- nightly backup timer ---------------------------------------------------
stage "Installing nightly backup timer"
if [ -f "$PANEL_SRC/deploy/backup.sh" ]; then cp -f "$PANEL_SRC/deploy/backup.sh" /opt/rctunnel-stack/backup.sh; fi
if [ -f /opt/rctunnel-stack/backup.sh ]; then
  chmod +x /opt/rctunnel-stack/backup.sh
  cat > /etc/systemd/system/rctunnel-backup.service <<'EOF'
[Unit]
Description=RC-Tunnel nightly backup
[Service]
Type=oneshot
ExecStart=/opt/rctunnel-stack/backup.sh
EOF
  cat > /etc/systemd/system/rctunnel-backup.timer <<'EOF'
[Unit]
Description=RC-Tunnel nightly backup at 03:30
[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload && systemctl enable --now rctunnel-backup.timer && ok "backup timer enabled"
else warn "deploy/backup.sh not found — skipping backup timer"; fi

# ---- firewall ---------------------------------------------------------------
if [ "$OPEN_FW" = y ]; then
  stage "Opening firewall ports"
  if command -v ufw >/dev/null 2>&1; then
    for p in 80 443 "$RCTD_CTRL_PORT" "$WORKCONN_PORT" "$CONTROL_PORT"; do ufw allow "${p}/tcp" || true; done
    ok "ufw rules added"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    systemctl enable --now firewalld || true
    for p in 80 443 "$RCTD_CTRL_PORT" "$WORKCONN_PORT" "$CONTROL_PORT"; do firewall-cmd --permanent --add-port="${p}/tcp" || true; done
    firewall-cmd --reload || true
    ok "firewalld rules added"
  else warn "no ufw/firewalld found — open 80,443,${RCTD_CTRL_PORT},${WORKCONN_PORT},${CONTROL_PORT} manually"; fi
fi

# ---- done -------------------------------------------------------------------
stage "Done"
echo "${c_g}${c_b}  RC-Tunnel is installed.${c_reset}"
echo
echo "  Panel:   https://${DOMAIN}/login"
echo "  Admin:   ${ADMIN_EMAIL}"
# Print the generated password ONLY to the terminal, bypassing the tee'd log
# file (which is world-readable) so the admin credential isn't persisted on disk.
[ "${GEN_PASS:-0}" = 1 ] && printf '  %sPassword (generated): %s%s\n' "$c_y" "$ADMIN_PASS" "$c_reset" >/dev/tty
echo
echo "  Next steps:"
echo "    1. DNS: point  ${DOMAIN}  AND  *.${DOMAIN}  (A records) at this host's public IP."
echo "    2. Ensure ports 80,443,${RCTD_CTRL_PORT},${WORKCONN_PORT},${CONTROL_PORT} are reachable from the internet."
echo "    3. Sign in (the data-plane node for this host is provisioned automatically),"
echo "       give your team a subdomain label, add an agent, copy its install command onto the target host."
echo
echo "  Secrets live in /etc/rctunnel-panel/ (mode 600). Backups: /root/rctunnel-backups (copy off-box!)."
echo "  Full install log: ${LOG}"
