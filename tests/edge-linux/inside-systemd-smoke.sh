#!/bin/sh
set -eu

distro="${1:-}"
case "${distro}" in
  debian12|ubuntu24) ;;
  *) echo "usage: $0 debian12|ubuntu24" >&2; exit 64 ;;
esac

# shellcheck source=/dev/null
. /etc/os-release
case "${distro}:${ID}:${VERSION_ID}" in
  debian12:debian:12*|ubuntu24:ubuntu:24.04) ;;
  *) echo "unexpected distro identity: ${distro}:${ID}:${VERSION_ID}" >&2; exit 1 ;;
esac
# shellcheck source=edge/openresty/runtime.env
. /workspace/edge/openresty/runtime.env

state_root=/var/lib/cdnca-edge
service=cdnca-openresty.service
package_root=/var/tmp/cdnca-edge-package-root
release_v1=1111111111111111111111111111111111111111111111111111111111111111
release_v2=2222222222222222222222222222222222222222222222222222222222222222
release_invalid=3333333333333333333333333333333333333333333333333333333333333333
release_denied=4444444444444444444444444444444444444444444444444444444444444444

fail() {
  echo "edge Linux smoke failed (${distro}): $*" >&2
  systemctl --no-pager status "${service}" >&2 || true
  journalctl --no-pager -u "${service}" -n 80 >&2 || true
  exit 1
}

wait_health() {
  expected="$1"
  attempt=0
  while [ "${attempt}" -lt 80 ]; do
    body="$(curl --silent --max-time 1 http://127.0.0.1:18080/healthz 2>/dev/null || true)"
    [ "${body}" = "ok:${expected}" ] && return 0
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "health did not become ok:${expected}"
}

require_no_health() {
  if curl --fail --silent --max-time 1 http://127.0.0.1:18080/healthz >/dev/null 2>&1; then
    fail "failed service still accepts traffic"
  fi
}

write_config() {
  release="$1"
  version="$2"
  directory="${state_root}/releases/${release}"
  install -d -o cdnca-edge -g cdnca-edge -m 0750 "${directory}"
  cat >"${directory}/nginx.conf" <<EOF
worker_processes 1;
pid ${state_root}/shared/nginx.pid;
error_log ${state_root}/shared/error.log notice;
events { worker_connections 128; }
http {
  access_log ${state_root}/shared/access.log;
  client_body_temp_path ${state_root}/shared/client-body;
  proxy_temp_path ${state_root}/shared/proxy;
  fastcgi_temp_path ${state_root}/shared/fastcgi;
  uwsgi_temp_path ${state_root}/shared/uwsgi;
  scgi_temp_path ${state_root}/shared/scgi;
  server {
    listen 0.0.0.0:18080;
    server_name _;
    location = /healthz {
      default_type text/plain;
      add_header X-CDNCA-Config-Version ${version} always;
      return 200 "ok:${version}\n";
    }
  }
}
EOF
  chown cdnca-edge:cdnca-edge "${directory}/nginx.conf"
  chmod 0440 "${directory}/nginx.conf"
  chmod 0550 "${directory}"
}

switch_current() {
  release="$1"
  next="${state_root}/.current-next"
  ln -s "releases/${release}" "${next}"
  mv -Tf "${next}" "${state_root}/current"
}

expect_start_failure() {
  stage="$1"
  systemctl reset-failed "${service}" >/dev/null 2>&1 || true
  if systemctl start "${service}" >/var/tmp/cdnca-start-error 2>&1; then
    fail "${stage} unexpectedly started"
  fi
  attempt=0
  while [ "${attempt}" -lt 30 ]; do
    if systemctl is-active --quiet "${service}"; then
      fail "${stage} became active during automatic retry"
    fi
    require_no_health
    attempt=$((attempt + 1))
    sleep 0.1
  done
  restart_count="$(systemctl show -p NRestarts --value "${service}")"
  test "${restart_count}" -ge 1 || fail "${stage} did not exercise Restart=on-failure"
  systemctl stop "${service}"
  require_no_health
  echo "fail_closed_${stage}=true retry_count=${restart_count}"
}

if ! id cdnca-edge >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin cdnca-edge
fi

rm -rf "${package_root}"
/workspace/scripts/edge-runtime-install.sh --destdir "${package_root}"
install -m 0644 "${package_root}/etc/systemd/system/cdnca-openresty.service" /etc/systemd/system/cdnca-openresty.service
install -m 0644 "${package_root}/usr/lib/tmpfiles.d/cdnca-edge.conf" /usr/lib/tmpfiles.d/cdnca-edge.conf
install -d -m 0755 /usr/share/doc/cdnca-edge
install -m 0644 "${package_root}/usr/share/doc/cdnca-edge/openresty-runtime.md" /usr/share/doc/cdnca-edge/openresty-runtime.md
systemd-tmpfiles --create /usr/lib/tmpfiles.d/cdnca-edge.conf

test "$(stat -c '%U:%G:%a' "${state_root}")" = "cdnca-edge:cdnca-edge:700"
test "$(stat -c '%U:%G:%a' "${state_root}/shared")" = "cdnca-edge:cdnca-edge:700"
install -d -o cdnca-edge -g cdnca-edge -m 0700 \
  "${state_root}/releases" "${state_root}/staging" "${state_root}/state"
cat >/etc/systemd/system/cdnca-edge-agent-write-probe.service <<EOF
[Service]
Type=oneshot
User=cdnca-edge
Group=cdnca-edge
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${state_root}
ExecStart=/usr/bin/touch ${state_root}/state/agent-write-probe
EOF
systemctl daemon-reload
systemctl start cdnca-edge-agent-write-probe.service
test "$(stat -c '%U:%G' "${state_root}/state/agent-write-probe")" = "cdnca-edge:cdnca-edge"
echo "edge_agent_unit_state_writable=true"
actual_version="$(/usr/local/openresty/bin/openresty -V 2>&1 | sed -n 's/^nginx version: openresty\///p')"
test "${actual_version}" = "${OPENRESTY_VERSION}"

write_config "${release_v1}" cfg-v1
switch_current "${release_v1}"
systemctl daemon-reload
systemctl start "${service}"
wait_health cfg-v1

test "$(systemctl show -p User --value "${service}")" = "cdnca-edge"
test "$(systemctl show -p NoNewPrivileges --value "${service}")" = "yes"
test "$(systemctl show -p ProtectSystem --value "${service}")" = "strict"
main_pid="$(systemctl show -p MainPID --value "${service}")"
test "${main_pid}" -gt 1
test "$(ps -o user= -p "${main_pid}" | tr -d ' ')" = "cdnca-edge"
test "$(awk '/^NoNewPrivs:/ {print $2}' "/proc/${main_pid}/status")" = "1"
test -s "${state_root}/shared/nginx.pid"
test -f "${state_root}/shared/error.log"
test "$(stat -c '%a' "${state_root}/releases/${release_v1}")" = "550"
test "$(stat -c '%a' "${state_root}/releases/${release_v1}/nginx.conf")" = "440"

edge_uid="$(id -u cdnca-edge)"
edge_gid="$(id -g cdnca-edge)"
if nsenter --mount="/proc/${main_pid}/ns/mnt" -- \
  setpriv --reuid="${edge_uid}" --regid="${edge_gid}" --clear-groups \
  sh -c "printf x >> '${state_root}/releases/${release_v1}/nginx.conf'" 2>/dev/null; then
  fail "release was writable inside service sandbox"
fi
if nsenter --mount="/proc/${main_pid}/ns/mnt" -- \
  setpriv --reuid="${edge_uid}" --regid="${edge_gid}" --clear-groups \
  sh -c "printf x > '${state_root}/state/openresty-write-probe'" 2>/dev/null; then
  fail "OpenResty sandbox could write Agent state"
fi
nsenter --mount="/proc/${main_pid}/ns/mnt" -- \
  setpriv --reuid="${edge_uid}" --regid="${edge_gid}" --clear-groups \
  sh -c "printf writable > '${state_root}/shared/sandbox-write'"
test "$(cat "${state_root}/shared/sandbox-write")" = "writable"
echo "sandbox_release_read_only=true"
echo "openresty_unit_state_read_only=true"
echo "sandbox_shared_writable=true"

write_config "${release_v2}" cfg-v2
switch_current "${release_v2}"
systemctl reload "${service}"
wait_health cfg-v2
test "$(systemctl show -p MainPID --value "${service}")" = "${main_pid}"
echo "reload_kept_master_pid=true"

systemctl stop "${service}"
if systemctl is-active --quiet "${service}"; then
  fail "service remained active after stop"
fi
require_no_health
systemctl start "${service}"
wait_health cfg-v2
restart_pid="$(systemctl show -p MainPID --value "${service}")"
test "${restart_pid}" -gt 1
echo "stop_start_recovered=true"

kill -KILL "${restart_pid}"
attempt=0
crash_pid=0
while [ "${attempt}" -lt 100 ]; do
  crash_pid="$(systemctl show -p MainPID --value "${service}")"
  if [ "${crash_pid}" -gt 1 ] && [ "${crash_pid}" != "${restart_pid}" ]; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
test "${crash_pid}" -gt 1 || fail "systemd did not restart killed master"
wait_health cfg-v2
echo "crash_restart_recovered=true"

systemctl stop "${service}"
unlink "${state_root}/current"
systemctl reset-failed "${service}" >/dev/null 2>&1 || true
systemctl start "${service}" >/var/tmp/cdnca-missing-current 2>&1 || true
if systemctl is-active --quiet "${service}"; then
  fail "missing current became active"
fi
require_no_health
echo "fail_closed_missing_current=true"

install -d -o cdnca-edge -g cdnca-edge -m 0550 "${state_root}/releases/${release_invalid}"
printf '%s\n' 'this_directive_does_not_exist on;' >"${state_root}/releases/${release_invalid}/nginx.conf"
chown cdnca-edge:cdnca-edge "${state_root}/releases/${release_invalid}/nginx.conf"
chmod 0440 "${state_root}/releases/${release_invalid}/nginx.conf"
switch_current "${release_invalid}"
expect_start_failure invalid_config

write_config "${release_denied}" cfg-denied
chown root:root "${state_root}/releases/${release_denied}" "${state_root}/releases/${release_denied}/nginx.conf"
chmod 0500 "${state_root}/releases/${release_denied}"
chmod 0400 "${state_root}/releases/${release_denied}/nginx.conf"
switch_current "${release_denied}"
expect_start_failure permission_error

switch_current "${release_v2}"
systemctl reset-failed "${service}" >/dev/null 2>&1 || true
systemctl start "${service}"
wait_health cfg-v2
systemctl reset-failed >/dev/null 2>&1 || true

printf 'distro=%s\ndistro_version=%s\nsystemd_version=%s\nopenresty_version=%s\nfinal_health=ok:cfg-v2\nmain_pid=%s\n' \
  "${ID}" "${VERSION_ID}" "$(systemctl --version | awk 'NR == 1 {print $2}')" "${actual_version}" \
  "$(systemctl show -p MainPID --value "${service}")"
