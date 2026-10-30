#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
task_tmp=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-dns-check.XXXXXX")
cleanup() {
	rm -rf -- "$task_tmp"
}
trap cleanup EXIT INT TERM

cd "$repo_root/services/control-api"
TMPDIR="$task_tmp" go run ./internal/dnscheck/cmd/dnscheck-smoke
