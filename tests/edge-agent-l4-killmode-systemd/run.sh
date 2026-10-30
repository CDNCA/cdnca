#!/bin/sh
# Real systemd check for KillMode=process: restarting the Agent unit keeps
# the L4 OpenResty master and an established TCP session; the shipped unit
# (KillMode=process) is compared with a control-group drop-in (old default),
# and uninstall's stop_cgroup_leftovers empties the cgroup afterwards.
# Builds a throwaway image, runs one --rm container, removes both on exit.
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
base_image=${L4_KILLMODE_BASE_IMAGE:-cdnca-market-test:ubuntu24}
openresty_image=${L4_KILLMODE_OPENRESTY_IMAGE:-cdnca-native-runtime:g2-ja4}
case "$(docker info --format '{{.Architecture}}')" in
  arm64|aarch64) go_arch=arm64; musl_loader=ld-musl-aarch64.so.1 ;;
  amd64|x86_64) go_arch=amd64; musl_loader=ld-musl-x86_64.so.1 ;;
  *) echo "unsupported Docker architecture" >&2; exit 69 ;;
esac
workdir=$(mktemp -d "${TMPDIR:-/tmp}/l4-killmode.XXXXXX")
suffix=$(basename "${workdir}" | sed 's/^l4-killmode\.//' | tr 'A-Z' 'a-z')
image=cdnca-l4-killmode:${suffix}
container=cdnca-l4-killmode-${suffix}

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker image rm "${image}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'l4 killmode systemd test failed: %s\n' "$*" >&2
  docker exec "${container}" sh -c 'journalctl -u cdnca-edge-agent.service --no-pager | tail -40; cat /run/l4-probe-hold.status' >&2 || true
  exit 1
}

GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
  go -C "${repo_root}/agents/edge-agent" build -trimpath -o "${workdir}/l4-restart-probe" ./internal/l4runtime/cmd/l4-restart-probe
cp "${repo_root}/agents/edge-agent/packaging/scripts/lib.sh" "${workdir}/lib.sh"
# The shipped unit's KillMode is what is under test.
kill_mode=$(sed -n 's/^KillMode=//p' "${repo_root}/agents/edge-agent/packaging/systemd/cdnca-edge-agent-root.service")
[ "${kill_mode}" = process ] || { echo "shipped root unit KillMode=${kill_mode}" >&2; exit 1; }

cat >"${workdir}/cdnca-edge-agent.service" <<EOF
[Unit]
Description=L4 KillMode probe standing in for the edge Agent
[Service]
Type=simple
ExecStart=/usr/local/bin/l4-restart-probe -mode agent -openresty /usr/local/openresty/bin/openresty
Restart=on-failure
RestartSec=1s
TimeoutStopSec=45s
KillMode=${kill_mode}
EOF
cat >"${workdir}/l4-probe-echo.service" <<'EOF'
[Service]
ExecStart=/usr/local/bin/l4-restart-probe -mode echo
EOF
cat >"${workdir}/l4-probe-hold.service" <<'EOF'
[Service]
ExecStart=/usr/local/bin/l4-restart-probe -mode hold
EOF
cat >"${workdir}/Dockerfile" <<EOF
FROM ${openresty_image} AS openresty
RUN mkdir -p /export/lib && cp -L /lib/${musl_loader} /usr/lib/libz.so.1 /usr/lib/libgcc_s.so.1 /export/lib/
FROM ${base_image}
COPY --from=openresty /usr/local/openresty /usr/local/openresty
COPY --from=openresty /export/lib/ /usr/lib/
RUN groupadd -o -g 65534 nobody
COPY l4-restart-probe /usr/local/bin/l4-restart-probe
COPY lib.sh /usr/local/share/l4-killmode/lib.sh
COPY cdnca-edge-agent.service l4-probe-echo.service l4-probe-hold.service /etc/systemd/system/
EOF
docker build -q -t "${image}" "${workdir}" >/dev/null
docker run --detach --rm --name "${container}" --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "${image}" >/dev/null

ct() { docker exec "${container}" sh -c "$1"; }
attempt=0
until ct 'systemctl is-system-running' 2>/dev/null | grep -Eq '^(running|degraded)$'; do
  attempt=$((attempt + 1)); [ "${attempt}" -lt 120 ] || fail "systemd did not boot"; sleep 1
done
ct '/usr/local/openresty/bin/openresty -v' >/dev/null 2>&1 || fail "OpenResty does not run in the systemd image"

ready_count() { ct 'journalctl -u cdnca-edge-agent.service --no-pager -o cat | grep -c "^agent ready$" || true'; }
wait_ready() {
  want=$1; attempt=0
  while [ "$(ready_count)" -lt "${want}" ]; do
    attempt=$((attempt + 1)); [ "${attempt}" -lt 60 ] || fail "agent did not become ready (${want})"; sleep 1
  done
}
master_pid() { ct 'cat /var/lib/cdnca-l4-probe/run/nginx.pid 2>/dev/null' | tr -d '\n'; }
hold_round() { ct 'cat /run/l4-probe-hold.status' | awk '$1 == "ok" { print $2 }'; }
# Count nginx processes by /proc cmdline (pgrep -f would match this shell).
nginx_count() {
  ct "for c in /proc/[0-9]*/cmdline; do tr '\\0' ' ' <\"\$c\" 2>/dev/null; echo; done | grep -c '^nginx: $1' || true"
}
hold_status() { ct 'cat /run/l4-probe-hold.status'; }
start_hold() {
  ct 'rm -f /run/l4-probe-hold.status; systemctl start l4-probe-hold.service'
  attempt=0
  until [ -n "$(hold_round)" ]; do
    attempt=$((attempt + 1)); [ "${attempt}" -lt 30 ] || fail "hold session did not start"; sleep 1
  done
}
expect_hold_alive() {
  before=$(hold_round); sleep 2; after=$(hold_round)
  [ -n "${after}" ] && [ "${after}" -gt "${before:-0}" ] || fail "$1: session not progressing ($(hold_status))"
}

# --- shipped unit: KillMode=process ---------------------------------------
ct 'systemctl start l4-probe-echo.service cdnca-edge-agent.service'
wait_ready 1
first_master=$(master_pid)
[ -n "${first_master}" ] || fail "no L4 master pid"
start_hold
expect_hold_alive "baseline"
ct 'systemctl restart cdnca-edge-agent.service'
wait_ready 2
[ "$(master_pid)" = "${first_master}" ] || fail "restart replaced the L4 master ($(master_pid) != ${first_master})"
expect_hold_alive "after systemctl restart"
ct 'systemctl kill --signal=SIGKILL --kill-whom=main cdnca-edge-agent.service'
wait_ready 3
[ "$(master_pid)" = "${first_master}" ] || fail "agent crash replaced the L4 master"
expect_hold_alive "after agent crash + Restart=on-failure"
restart_result="kept master ${first_master}; session alive through restart and crash, last $(hold_status)"

# Master gone while the agent was down: the next agent starts it once.
ct 'systemctl stop l4-probe-hold.service cdnca-edge-agent.service'
ct "kill -TERM ${first_master}"
sleep 1
ct 'systemctl start cdnca-edge-agent.service'
wait_ready 4
second_master=$(master_pid)
[ -n "${second_master}" ] && [ "${second_master}" != "${first_master}" ] || fail "agent did not start a missing master"
[ "$(nginx_count master)" = 1 ] || fail "expected exactly one L4 master, got $(nginx_count master)"
start_hold
expect_hold_alive "after master restart by agent"

# Stop + uninstall cleanup: unit stop keeps L4, stop_cgroup_leftovers empties it.
ct 'systemctl stop l4-probe-hold.service cdnca-edge-agent.service'
ct "kill -0 ${second_master}" || fail "unit stop should leave the master to uninstall"
ct '. /usr/local/share/l4-killmode/lib.sh; DESTDIR=; stop_agent_leftovers' || fail "stop_agent_leftovers failed"
ct "kill -0 ${second_master}" 2>/dev/null && fail "uninstall cleanup left the L4 master running"
procs=$(ct 'cat /sys/fs/cgroup/system.slice/cdnca-edge-agent.service/cgroup.procs 2>/dev/null || true')
[ -z "${procs}" ] || fail "agent cgroup not empty after cleanup: ${procs}"
[ "$(nginx_count '')" = 0 ] || fail "nginx processes remain after cleanup"
cleanup_result="unit stop kept master ${second_master}; stop_agent_leftovers emptied the cgroup"

# --- control: old default KillMode=control-group drops the session --------
ct 'rm -f /run/l4-probe-hold.status; mkdir -p /etc/systemd/system/cdnca-edge-agent.service.d && printf "[Service]\nKillMode=control-group\n" >/etc/systemd/system/cdnca-edge-agent.service.d/control.conf && systemctl daemon-reload'
ct 'systemctl start cdnca-edge-agent.service'
wait_ready 5
control_master=$(master_pid)
start_hold
ct 'systemctl restart cdnca-edge-agent.service'
wait_ready 6
sleep 2
case "$(hold_status)" in broken*) ;; *) fail "control-group restart did not break the session ($(hold_status))" ;; esac
[ "$(master_pid)" != "${control_master}" ] || fail "control-group restart kept the master"
control_result="control-group restart killed master ${control_master}; session $(hold_status)"

printf 'PASS KillMode=process: %s\n' "${restart_result}"
printf 'PASS cleanup: %s\n' "${cleanup_result}"
printf 'PASS control (old default): %s\n' "${control_result}"
