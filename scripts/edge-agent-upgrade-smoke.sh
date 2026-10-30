#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
smoke_root=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-edge-upgrade.XXXXXX")
cleanup() {
	rm -rf -- "$smoke_root"
}
trap cleanup EXIT HUP INT TERM

cd "$repo_root/agents/edge-agent"
go build -trimpath -ldflags '-X main.behavior=healthy' -o "$smoke_root/agent-healthy" ./internal/updater/cmd/testbinary
go build -trimpath -ldflags '-X main.behavior=crash' -o "$smoke_root/agent-crash" ./internal/updater/cmd/testbinary
go build -trimpath -ldflags '-X main.behavior=unhealthy' -o "$smoke_root/agent-unhealthy" ./internal/updater/cmd/testbinary
go run ./internal/updater/cmd/upgrade-smoke "$smoke_root/state" "$smoke_root/agent-healthy" "$smoke_root/agent-crash" "$smoke_root/agent-unhealthy"
