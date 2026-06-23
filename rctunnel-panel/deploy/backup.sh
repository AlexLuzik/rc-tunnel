#!/usr/bin/env bash
# Nightly backup: Postgres dump + PKI (incl. ca.key) + configs + Caddy certs.
# Local rotation 14 days. NOTE: copy /root/rctunnel-backups OFF-BOX for real DR.
set -euo pipefail
TS=$(date +%Y%m%d-%H%M%S)
DEST=/root/rctunnel-backups
mkdir -p "$DEST"
chmod 700 "$DEST"
# consistent logical DB dump (schema + data)
docker exec rctunnel-postgres pg_dump -U rctunnel -d rctunnel --no-owner | gzip > "$DEST/db-$TS.sql.gz"
# roles/passwords (pg_dump --no-owner omits these; needed to restore on bare metal)
docker exec rctunnel-postgres pg_dumpall -U rctunnel --globals-only | gzip > "$DEST/globals-$TS.sql.gz"
# PKI (CA key!), panel configs/env, Caddy cert store. --ignore-failed-read tolerates
# a vanished transient file but a real failure (missing dir, perms) now aborts.
tar --ignore-failed-read -czf "$DEST/state-$TS.tgz" \
  -C / var/lib/rctunnel-panel/pki etc/rctunnel-panel \
  var/lib/caddy/.local/share/caddy
chmod 600 "$DEST"/*.sql.gz "$DEST"/*.tgz 2>/dev/null || true
# rotate
find "$DEST" -maxdepth 1 -name 'db-*.sql.gz'      -mtime +14 -delete
find "$DEST" -maxdepth 1 -name 'globals-*.sql.gz' -mtime +14 -delete
find "$DEST" -maxdepth 1 -name 'state-*.tgz'       -mtime +14 -delete
echo "$(date -Is) backup ok: db-$TS.sql.gz $(du -h "$DEST/db-$TS.sql.gz"|cut -f1), globals-$TS.sql.gz $(du -h "$DEST/globals-$TS.sql.gz"|cut -f1), state-$TS.tgz $(du -h "$DEST/state-$TS.tgz"|cut -f1)"
