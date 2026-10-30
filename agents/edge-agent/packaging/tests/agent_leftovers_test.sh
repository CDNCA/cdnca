#!/bin/sh
# KillMode=process keeps the Agent's OpenResty masters across Agent restarts;
# uninstall must still stop them. Exercises stop_cgroup_leftovers with real
# processes listed in a fake cgroup.procs file, plus the unit/uninstall wiring.
set -eu

packaging_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
workdir=$(mktemp -d)
spawned=
cleanup() {
  for pid in ${spawned}; do kill -KILL "${pid}" 2>/dev/null || true; done
  rm -rf -- "${workdir}"
}
trap cleanup EXIT

fail() {
  printf 'agent leftovers test failed: %s\n' "$*" >&2
  exit 1
}

# Double fork: the process is reparented, so an exit is reaped at once and
# kill -0 does not see a zombie of this shell.
spawn() {
  pid=$( (sh -c "$1" >/dev/null 2>&1 & echo $!) )
  spawned="${spawned} ${pid}"
  printf '%s\n' "${pid}"
}

DESTDIR=
. "${packaging_root}/scripts/lib.sh"

# Static wiring: both Agent units signal only the Agent, uninstall stops the rest.
for unit in cdnca-edge-agent.service cdnca-edge-agent-root.service; do
  grep -Fx 'KillMode=process' "${packaging_root}/systemd/${unit}" >/dev/null || fail "${unit} lacks KillMode=process"
  # ADR 0010 section 10.4: the auto defense loop thread runs at nice -5
  grep -Fx 'LimitNICE=-5' "${packaging_root}/systemd/${unit}" >/dev/null || fail "${unit} lacks LimitNICE=-5"
done
stop_line=$(grep -n '^service_action stop ' "${packaging_root}/scripts/uninstall.sh" | cut -d: -f1)
leftover_line=$(grep -n '^stop_agent_leftovers ' "${packaging_root}/scripts/uninstall.sh" | cut -d: -f1)
[ -n "${stop_line}" ] && [ -n "${leftover_line}" ] && [ "${leftover_line}" -gt "${stop_line}" ] || \
  fail "uninstall.sh must stop Agent leftovers after stopping the unit"

# Empty or missing procs file: nothing to do.
: >"${workdir}/empty.procs"
stop_cgroup_leftovers "${workdir}/empty.procs" 2 || fail "empty cgroup was not accepted"
stop_cgroup_leftovers "${workdir}/missing.procs" 2 || fail "missing cgroup was not accepted"

# A master that honours TERM stops within the grace period.
graceful=$(spawn 'exec sleep 300')
printf '%s\n' "${graceful}" >"${workdir}/graceful.procs"
started=$(date +%s)
stop_cgroup_leftovers "${workdir}/graceful.procs" 5 || fail "graceful leftover reported as still running"
kill -0 "${graceful}" 2>/dev/null && fail "TERM did not stop the leftover"
[ $(( $(date +%s) - started )) -lt 5 ] || fail "graceful leftover waited for the full timeout"

# A process ignoring TERM is killed once the grace period ends.
stubborn=$(spawn 'trap "" TERM; while :; do sleep 1; done')
printf '%s\n' "${stubborn}" >"${workdir}/stubborn.procs"
stop_cgroup_leftovers "${workdir}/stubborn.procs" 2 || fail "stubborn leftover survived KILL"
kill -0 "${stubborn}" 2>/dev/null && fail "KILL did not stop the stubborn leftover"

# Staged roots and injected service drivers never touch host processes.
sentinel=$(spawn 'exec sleep 300')
DESTDIR=${workdir}/root
stop_agent_leftovers || fail "staged uninstall leftover stop failed"
DESTDIR=
SERVICE_DRIVER=${workdir}/driver
stop_agent_leftovers || fail "driver uninstall leftover stop failed"
kill -0 "${sentinel}" 2>/dev/null || fail "staged uninstall signalled a host process"

printf 'agent leftovers test passed\n'
