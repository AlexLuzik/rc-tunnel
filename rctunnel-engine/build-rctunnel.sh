#!/usr/bin/env bash
# Build the RC-Tunnel engine (rctd server + rctc client) entirely inside an
# ephemeral golang container — no Go toolchain/cache touches the host.
# Output: ./bin/rctd ./bin/rctc (linux/amd64, static, stripped).
set -euo pipefail
cd "$(dirname "$0")"
docker run --rm --security-opt label=disable -v "$PWD":/src -w /src golang:1.25-bookworm bash -c '
  set -e
  go vet ./...
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/rctd ./cmd/rctd
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/rctc ./cmd/rctc'
echo "built:"; ls -la bin/
