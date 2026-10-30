#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)

require_text() {
  local needle=$1 file=$2
  grep -F -- "${needle}" "${root}/${file}" >/dev/null || {
    printf 'missing %s in %s\n' "${needle}" "${file}" >&2
    exit 1
  }
}

require_absent() {
  local needle=$1 file=$2
  if grep -Fx -- "${needle}" "${root}/${file}" >/dev/null; then
    printf 'forbidden %s in %s\n' "${needle}" "${file}" >&2
    exit 1
  fi
}

require_text 'MinimumFreeBytes' agents/edge-agent/internal/logdiskguard/guard.go
require_text 'ReasonPressureMinimumFree' agents/edge-agent/internal/logdiskguard/types.go
require_text 'unix.Openat' agents/edge-agent/internal/logdiskguard/fs_unix.go
require_text 'unix.Renameat' agents/edge-agent/internal/logdiskguard/guard.go
require_text 'unix.Unlinkat' agents/edge-agent/internal/logdiskguard/guard.go
require_text 'spool.lock' agents/edge-agent/internal/logdiskguard/guard.go
require_text 'logDiskGuard' agents/edge-agent/cmd/edge-agent/daemon.go
require_text 'minimum_free_bytes' agents/edge-agent/cmd/edge-agent/config.go
require_text 'max_round_duration' agents/edge-agent/cmd/edge-agent/config.go
require_text 'x /var/lib/cdnca-edge-agent/event-spool' agents/edge-agent/packaging/tmpfiles/cdnca-edge-agent.conf
require_text 'maxage 30' agents/edge-agent/packaging/logrotate/cdnca-edge-agent
require_text 'dateext' agents/edge-agent/packaging/logrotate/cdnca-edge-agent
require_text 'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind' agents/edge-agent/packaging/systemd/cdnca-edge-agent.service
require_absent 'ReadWritePaths=/' agents/edge-agent/packaging/systemd/cdnca-edge-agent.service
require_text 'ReasonPressureMinimumFree' docs/runbooks/edge-disk-protection.md
require_text '真实磁盘写满注入留在第 7 轮' docs/runbooks/edge-disk-protection.md

printf 'EDGE_AGENT_LOG_DISK_GUARD_STATIC PASS\n'
