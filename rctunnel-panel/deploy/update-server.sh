#!/usr/bin/env bash
# =============================================================================
#  RC-Tunnel in-place updater — safe, idempotent, non-interactive.
#
#  Updates an EXISTING install to the sources next to this script:
#    * preserves all data + secrets (never regenerates master.env / DB password);
#    * rebuilds the Go engine and the app image FROM SOURCE;
#    * recreates ONLY the services that actually changed — Postgres, OpenSearch
#      and Caddy keep running, so 80/443 stay up and the DB is untouched;
#    * DB schema migrations apply automatically when the master starts;
#    * republishes agent artifacts so connected agents OTA-upgrade themselves.
#
#  Usage (run as root from inside the rctunnel-panel repo):
#      sudo bash deploy/update-server.sh           # update (asks to confirm)
#      sudo bash deploy/update-server.sh --check    # only show deployed vs available
#      sudo bash deploy/update-server.sh --yes       # update without the prompt
# =============================================================================
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/rctunnel-update-${TS}.log"
mkdir -p /var/log
exec > >(tee -a "$LOG") 2>&1

c_reset=$'\e[0m'; c_b=$'\e[1m'; c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_c=$'\e[36m'
stage() { echo; echo "${c_c}${c_b}==> [$(date +%H:%M:%S)] $*${c_reset}"; }
info()  { echo "    $*"; }
ok()    { echo "${c_g}    ✓ $*${c_reset}"; }
warn()  { echo "${c_y}    ! $*${c_reset}"; }
die()   { echo "${c_r}${c_b}ERROR: $*${c_reset}" >&2; echo "See full log: $LOG" >&2; exit 1; }

CHECK_ONLY=0; ASSUME_YES=0
for a in "$@"; do case "$a" in
  --check) CHECK_ONLY=1 ;;
  --yes|-y) ASSUME_YES=1 ;;
  *) die "unknown option: $a (use --check or --yes)" ;;
esac; done

[ "$(id -u)" = 0 ] || die "run as root (sudo)."
command -v docker >/dev/null 2>&1 || die "docker not found — is this host installed?"

STACK=/opt/rctunnel-stack
COMPOSE="$STACK/docker-compose.yml"
ENVF=/etc/rctunnel-panel/master.env
RCTDF=/etc/rctunnel-panel/rctd.yml
DL=/var/www/rctunnel-panel-dl
[ -f "$COMPOSE" ] && [ -f "$ENVF" ] || die "no existing install ($COMPOSE / $ENVF missing) — run deploy/install-server.sh first."

dc() { docker compose -f "$COMPOSE" "$@"; }
getenv() { grep -E "^$1=" "$ENVF" | head -1 | cut -d= -f2- || true; }

# ---- locate sources ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_SRC="${PANEL_SRC:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ENGINE_SRC="${ENGINE_SRC:-$(cd "$PANEL_SRC/.." && pwd)/rctunnel-engine}"
[ -f "$PANEL_SRC/requirements.txt" ] && [ -d "$PANEL_SRC/rctunnel_panel" ] || die "not a panel repo: $PANEL_SRC"
[ -d "$ENGINE_SRC/cmd/rctd" ] && [ -d "$ENGINE_SRC/cmd/rctc" ] || die "not an engine repo: $ENGINE_SRC"

ARCH_RAW="$(uname -m)"; case "$ARCH_RAW" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) die "unsupported arch: $ARCH_RAW";; esac

# ---- versions ---------------------------------------------------------------
_ver() { grep -E "$2" "$1" 2>/dev/null | head -1 | sed -E 's/.*"([^"]+)".*/\1/'; }
NEW_PANEL="$(_ver "$PANEL_SRC/rctunnel_panel/__init__.py" '^__version__')"
NEW_AGENT="$(_ver "$PANEL_SRC/agent/rctunnel_agent.py" '^AGENT_VERSION')"
NEW_SHA="$(git -C "$PANEL_SRC" rev-parse --short HEAD 2>/dev/null || echo '?')"
CUR_PANEL="$(curl -fsS --max-time 5 http://127.0.0.1:8000/healthz 2>/dev/null | sed -nE 's/.*"version": ?"([^"]+)".*/\1/p')"
CUR_AGENT="$(sed -nE 's/.*"agent_version": ?"([^"]+)".*/\1/p' "$DL/manifest.json" 2>/dev/null)"

stage "Versions"
info "panel:  deployed ${CUR_PANEL:-unknown}  ->  available ${NEW_PANEL} (git ${NEW_SHA})"
info "agent:  deployed ${CUR_AGENT:-unknown}  ->  available ${NEW_AGENT}"
info "source: $PANEL_SRC"

if [ "$CHECK_ONLY" = 1 ]; then exit 0; fi

if [ "$ASSUME_YES" != 1 ]; then
  printf '    Apply this update? Postgres/OpenSearch/Caddy keep running; the panel and\n    rctd restart briefly (agents reconnect automatically). [y/N]: ' >/dev/tty
  read -r ans </dev/tty || true; [[ "$ans" =~ ^[Yy] ]] || die "aborted by user."
fi

# ---- sync sources into /opt -------------------------------------------------
stage "Syncing sources into /opt"
rsync -a --delete --exclude '.venv' --exclude '__pycache__' --exclude '*.db' --exclude '*.db-*' \
      --exclude 'pki' --exclude '.git' "$PANEL_SRC"/  /opt/rctunnel-panel/
rsync -a --delete --exclude 'bin' --exclude '.git' "$ENGINE_SRC"/ /opt/rctunnel-engine/
ok "panel + engine synced"

# ---- rebuild the engine; only swap if the binary actually changed -----------
stage "Building rctd + rctc from source (golang:1.23)"
docker run --rm --security-opt label=disable -v /opt/rctunnel-engine:/src -w /src \
  -e GOCACHE=/tmp/gc -e GOPATH=/tmp/gp -e GOFLAGS=-mod=mod \
  golang:1.23 bash -c "
    set -e
    go vet ./...
    CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags '-s -w' -o bin/rctd ./cmd/rctd
    CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags '-s -w' -o bin/rctc ./cmd/rctc" \
  || die "engine build failed"
[ -x /opt/rctunnel-engine/bin/rctd ] && [ -x /opt/rctunnel-engine/bin/rctc ] || die "engine binaries missing after build"

RCTD_RECREATE=0
_sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
if [ "$(_sha /opt/rctunnel-engine/bin/rctd)" != "$(_sha /opt/rctunnel-node/rctd)" ]; then
  cp -f /opt/rctunnel-engine/bin/rctd /opt/rctunnel-node/rctd; chmod +x /opt/rctunnel-node/rctd
  RCTD_RECREATE=1; ok "rctd binary changed — will recreate rctd"
else ok "rctd binary unchanged — leaving the data plane running"; fi
# always refresh the published rctc (agents verify it by hash; cheap, no restart)
cp -f /opt/rctunnel-engine/bin/rctc "$DL/rctc-${ARCH}"; chmod +x "$DL/rctc-${ARCH}"
cat > /opt/rctunnel-node/Dockerfile.rctd <<'EOF'
FROM debian:stable-slim
COPY rctd /usr/local/bin/rctd
ENTRYPOINT ["/usr/local/bin/rctd"]
EOF

# ---- re-render rctd.yml from the EXISTING secrets (adds new keys) -----------
# master.env is left untouched — new panel settings fall back to code defaults.
stage "Refreshing rctd.yml from existing config"
GRANT_SECRET="$(getenv RCTUNNEL_GRANT_SECRET)"
NODE_TOKEN="$(getenv RCTUNNEL_NODE_TOKEN)"
RCTD_CTRL_PORT="$(getenv RCTUNNEL_RCTD_CONTROL_PORT)"; RCTD_CTRL_PORT="${RCTD_CTRL_PORT:-7000}"
WORKCONN_PORT="$(getenv RCTUNNEL_RCTD_WORKCONN_PORT)"; WORKCONN_PORT="${WORKCONN_PORT:-7001}"
[ -n "$NODE_TOKEN" ] || NODE_TOKEN="$(grep -E '^token:' "$RCTDF" | sed -E 's/.*"([^"]*)".*/\1/')"
TMP_RCTD="$(mktemp)"
cat > "$TMP_RCTD" <<EOF
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
if ! cmp -s "$TMP_RCTD" "$RCTDF"; then
  cp -f "$TMP_RCTD" "$RCTDF"; chmod 600 "$RCTDF"; RCTD_RECREATE=1; ok "rctd.yml updated (will recreate rctd)"
else ok "rctd.yml unchanged"; fi
rm -f "$TMP_RCTD"

# ---- rebuild images + recreate only what changed ----------------------------
stage "Rebuilding the app image"
dc build master || die "image build failed"

stage "Applying update (recreate changed services)"
# up -d recreates master+logship when their image changed; Postgres/OpenSearch/Caddy
# are untouched (image+config unchanged) and keep serving. Migrations run as the
# master boots (init_db).
dc up -d
if [ "$RCTD_RECREATE" = 1 ]; then
  dc build rctd && dc up -d --force-recreate rctd
  ok "rctd recreated"
else
  info "data plane (rctd) left running — no engine/config change"
fi

# ---- wait for the panel to come back ----------------------------------------
stage "Waiting for the panel to be healthy"
for i in $(seq 1 30); do
  v="$(curl -fsS --max-time 3 http://127.0.0.1:8000/healthz 2>/dev/null | sed -nE 's/.*"version": ?"([^"]+)".*/\1/p' || true)"
  [ -n "$v" ] && { ok "panel up (version ${v})"; break; }
  info "waiting ... ($i/30)"; sleep 2
  [ "$i" = 30 ] && warn "panel did not report healthy in time — check: docker logs rctunnel-panel-master"
done

# ---- republish agent artifacts (OTA) ----------------------------------------
stage "Republishing agent artifacts to /dl"
docker exec rctunnel-panel-master python -m scripts.publish || warn "publish failed (run manually later)"
info "manifest: $(cat "$DL/manifest.json" 2>/dev/null)"

stage "Done"
echo "${c_g}${c_b}  RC-Tunnel updated to panel ${NEW_PANEL} / agent ${NEW_AGENT} (git ${NEW_SHA}).${c_reset}"
echo "  Connected agents pick up the new agent version automatically via OTA."
echo "  Full update log: ${LOG}"
