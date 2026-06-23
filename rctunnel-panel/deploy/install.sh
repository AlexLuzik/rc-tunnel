#!/bin/sh
# rctunnel-agent installer (Linux). Downloads the agent + engine client from the
# panel itself and installs a systemd service.
#
#   curl -fsSL https://<domain>/dl/install.sh | bash -s -- \
#       --base-url https://<domain>/dl --token <agent_token>
set -eu

BASE_URL=""
TOKEN=""
MASTER_URL=""
INSTALL_DIR="/opt/rctunnel-agent"
NO_SERVICE="0"

while [ $# -gt 0 ]; do
  case "$1" in
    --base-url)   BASE_URL="$2"; shift 2 ;;
    --token)      TOKEN="$2"; shift 2 ;;
    --master-url) MASTER_URL="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --no-service) NO_SERVICE="1"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BASE_URL" ] || { echo "error: --base-url required" >&2; exit 2; }
[ -n "$TOKEN" ]    || { echo "error: --token required" >&2; exit 2; }
# Master API URL = base URL without the trailing /dl
[ -n "$MASTER_URL" ] || MASTER_URL="$(printf '%s' "$BASE_URL" | sed 's#/dl/*$##')"

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "error: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

fetch() { # url dest — download to a temp file then atomically move into place,
          # so we can replace a binary that is currently running (avoids ETXTBSY).
  tmp="$2.dl.$$"
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$tmp"
  else wget -qO "$tmp" "$1"; fi
  mv -f "$tmp" "$2"
}

# stop a previous instance so its files aren't busy during the swap (best-effort)
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop rctunnel-agent 2>/dev/null || true
fi

echo "[rctunnel] installing agent into $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "[rctunnel] fetching agent + engine client from $BASE_URL"
fetch "$BASE_URL/rctunnel_agent.py" "$INSTALL_DIR/rctunnel_agent.py"
fetch "$BASE_URL/localip.py"       "$INSTALL_DIR/localip.py"
# rctunnel-engine client (our own data plane); agent also self-fetches if missing
fetch "$BASE_URL/rctc-$ARCH"       "$INSTALL_DIR/rctc"
chmod +x "$INSTALL_DIR/rctc"

echo "[rctunnel] setting up python venv"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet websockets cryptography

if [ "$NO_SERVICE" = "1" ] || ! command -v systemctl >/dev/null 2>&1; then
  echo "[rctunnel] no systemd (or --no-service): run manually:"
  echo "  RCTUNNEL_MASTER_URL=$MASTER_URL RCTUNNEL_AGENT_TOKEN=$TOKEN \\"
  echo "    $INSTALL_DIR/venv/bin/python $INSTALL_DIR/rctunnel_agent.py \\"
  echo "    --work-dir $INSTALL_DIR/data --rctc $INSTALL_DIR/rctc"
  exit 0
fi

echo "[rctunnel] writing systemd unit"
cat > /etc/systemd/system/rctunnel-agent.service <<UNIT
[Unit]
Description=rctunnel agent
After=network-online.target
Wants=network-online.target

[Service]
Environment=RCTUNNEL_MASTER_URL=$MASTER_URL
Environment=RCTUNNEL_AGENT_TOKEN=$TOKEN
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/rctunnel_agent.py --work-dir $INSTALL_DIR/data --rctc $INSTALL_DIR/rctc
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable rctunnel-agent
systemctl restart rctunnel-agent
echo "[rctunnel] installed and (re)started (systemctl status rctunnel-agent)"
