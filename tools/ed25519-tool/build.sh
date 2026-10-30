#!/bin/sh
# Reproducible linux/amd64 build of cdnca-ed25519. The resulting SHA-256 is
# pinned in scripts/install-control.sh and scripts/install-node.sh
# (CDNCA_ED25519_TOOL_SHA256); tests/ed25519-tool-pin.test.mjs rebuilds and
# compares. Usage: build.sh OUTPUT
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 OUTPUT" >&2; exit 64; }
[ ! -e "$1" ] && [ ! -L "$1" ] || { echo "output exists: $1" >&2; exit 1; }
output=$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")
cd "$(dirname "$0")"
env -u GOFLAGS -u GOEXPERIMENT GOTOOLCHAIN=go1.27.3 GOWORK=off GOENV=off GOFLAGS= CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -buildvcs=false -mod=readonly -ldflags='-s -w -buildid=' -o "$output" .
chmod 0555 "$output"
