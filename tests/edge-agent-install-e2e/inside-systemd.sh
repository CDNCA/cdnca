#!/bin/sh
set -eu

distro=${1:-}
arch=${2:-}
phase=${3:-initial}
case "${distro}" in debian12|ubuntu2404) ;; *) printf 'usage: %s DISTRO amd64|arm64 initial|post-restart\n' "$0" >&2; exit 64 ;; esac
case "${arch}" in amd64|arm64) ;; *) printf 'usage: %s DISTRO amd64|arm64 initial|post-restart\n' "$0" >&2; exit 64 ;; esac
case "${phase}" in initial|post-restart) ;; *) printf 'usage: %s DISTRO amd64|arm64 initial|post-restart\n' "$0" >&2; exit 64 ;; esac

fail() {
  printf 'OPS-11 real systemd install failed (%s/%s): %s\n' "${distro}" "${arch}" "$*" >&2
  systemctl --no-pager status cdnca-edge-agent.service >&2 2>/dev/null || true
  journalctl --no-pager -u cdnca-edge-agent.service -n 80 >&2 2>/dev/null || true
  exit 1
}

expect() {
  "$@" || fail "command failed: $*"
}

expected_systemd=252
expected_id=debian
expected_version=12
case "${distro}" in
  ubuntu2404) expected_systemd=255; expected_id=ubuntu; expected_version=24.04 ;;
esac

# shellcheck source=/dev/null
. /etc/os-release
[ "${ID}" = "${expected_id}" ] && [ "${VERSION_ID}" = "${expected_version}" ] ||
  fail "unexpected distribution ${ID}:${VERSION_ID}"
actual_systemd=$(systemd --version | awk 'NR == 1 {print $2}')
[ "${actual_systemd}" = "${expected_systemd}" ] || fail "systemd ${actual_systemd}, expected ${expected_systemd}"
[ "$(dpkg --print-architecture)" = "${arch}" ] || fail "architecture mismatch"
[ -f /usr/share/cdnca-ops11/image-contract ] || fail 'missing fixed image contract'
grep -F "distro=${ID}" /usr/share/cdnca-ops11/image-contract >/dev/null || fail 'image distro contract mismatch'
grep -F "version=${VERSION_ID}" /usr/share/cdnca-ops11/image-contract >/dev/null || fail 'image version contract mismatch'

repository=/repository
repository_keyring=${repository}/cdnca-archive-keyring.gpg
installed_keyring=/usr/share/keyrings/cdnca-archive-keyring.gpg
provenance=${repository}/repository.provenance.json
suite=stable
component=main

sha256_file() { sha256sum -- "$1" | awk '{print $1}'; }
package_path() {
  version=$1
  jq -er --arg arch "${arch}" --arg version "${version}" \
    '.packages[] | select(.arch == $arch and .version == $version) | .path' "${provenance}"
}
package_sha() {
  version=$1
  jq -er --arg arch "${arch}" --arg version "${version}" \
    '.packages[] | select(.arch == $arch and .version == $version) | .sha256 // empty' "${provenance}"
}

verify_repository() {
  [ -f "${provenance}" ] && [ ! -L "${provenance}" ] || fail 'repository provenance is missing'
  expect gpgv --keyring "${repository_keyring}" "${repository}/dists/${suite}/InRelease"
  jq -e --arg arch "${arch}" '
    .schema == "cdnca.edge.apt-repository-provenance/v1" and
    ([.packages[] | select(.arch == $arch)] | length) == 3 and
    ([.packages[].arch] | sort | unique) == ["amd64", "arm64"]
  ' "${provenance}" >/dev/null || fail 'repository provenance does not cover the exact dual-architecture release set'
  for version in 1.0.0 1.1.0 1.2.0; do
    relative=$(package_path "${version}")
    package=${repository}/${relative}
    [ -f "${package}" ] && [ ! -L "${package}" ] || fail "missing ${version}/${arch} package"
    [ "$(sha256_file "${package}")" = "$(package_sha "${version}")" ] || fail "${version}/${arch} package digest mismatch"
    dpkg-deb -f "${package}" Package | grep -Fx cdnca-edge-agent >/dev/null || fail 'package name mismatch'
    dpkg-deb -f "${package}" Architecture | grep -Fx "${arch}" >/dev/null || fail 'package architecture metadata mismatch'
    printf 'artifact distro=%s arch=%s version=%s sha256=%s\n' "${distro}" "${arch}" "${version}" "$(sha256_file "${package}")"
  done
}

assert_current() {
  expected=$1
  [ "$(readlink /usr/lib/cdnca-edge-agent/current)" = "versions/${expected}" ] || fail "current release is not ${expected}"
  /usr/lib/cdnca-edge-agent/current/edge-agent --version |
    grep -F "\"agent_version\":\"${expected}\"" >/dev/null || fail "current binary identity is not ${expected}"
}

assert_active() {
  expected=$1
  expect systemctl is-active --quiet cdnca-edge-agent.service
  expect systemctl is-enabled --quiet cdnca-edge-agent.service
  assert_current "${expected}"
  pid=$(systemctl show -p MainPID --value cdnca-edge-agent.service)
  case "${pid}" in ''|*[!0-9]*|0|1) fail "invalid non-running main pid: ${pid}" ;; esac
  uid=$(id -u cdnca-edge)
  gid=$(id -g cdnca-edge)
  [ "$(ps -o user= -p "${pid}" | tr -d ' ')" = cdnca-edge ] || fail 'service process is not cdnca-edge'
  [ "$(awk '/^Uid:/ {print $2}' "/proc/${pid}/status")" = "${uid}" ] || fail 'service uid differs from system user'
  [ "$(awk '/^Gid:/ {print $2}' "/proc/${pid}/status")" = "${gid}" ] || fail 'service gid differs from system group'
  [ "$(awk '/^NoNewPrivs:/ {print $2}' "/proc/${pid}/status")" = 1 ] || fail 'service lacks no-new-privileges'
  [ "$(systemctl show -p User --value cdnca-edge-agent.service)" = cdnca-edge ] || fail 'unit User is not cdnca-edge'
  [ "$(systemctl show -p ProtectSystem --value cdnca-edge-agent.service)" = strict ] || fail 'unit ProtectSystem is not strict'
  [ "$(systemctl show -p NoNewPrivileges --value cdnca-edge-agent.service)" = yes ] || fail 'unit NoNewPrivileges is not enabled'
}

write_config() {
  temporary=/etc/cdnca-edge-agent/.config.ops11.$$
  printf '%s\n' '{"node_id":"ops11-node","repository_test":true}' >"${temporary}"
  chown cdnca-edge:cdnca-edge "${temporary}"
  chmod 0600 "${temporary}"
  mv -Tf "${temporary}" /etc/cdnca-edge-agent/config.json
}

write_state() {
  printf '%s\n' "$1" >/var/lib/cdnca-edge-agent-backups/active-state/state.txt
  chown cdnca-edge:cdnca-edge /var/lib/cdnca-edge-agent-backups/active-state/state.txt
  chmod 0600 /var/lib/cdnca-edge-agent-backups/active-state/state.txt
}

assert_state() {
  [ "$(sed -n '1p' /var/lib/cdnca-edge-agent-backups/active-state/state.txt)" = "$1" ] || fail "state is not $1"
}

run_upgrade() {
  bundle=$1
  timeout=$2
  stable=$3
  /usr/libexec/cdnca-edge-agent/upgrade.sh \
    --artifact "${bundle}/edge-agent" \
    --sbom "${bundle}/edge-agent.spdx.json" \
    --manifest "${bundle}/manifest" \
    --signature "${bundle}/manifest.sig" \
    --public-key "${bundle}/release-signing.pem" \
    --health-timeout "${timeout}" --health-stable "${stable}"
}

assert_failed_preserves_v2() {
  [ "$(readlink /usr/lib/cdnca-edge-agent/current)" = versions/1.1.0 ] || fail 'failed candidate changed current release'
  grep -Fx 'release_sequence=2' /var/lib/cdnca-edge-agent-packaging/accepted-manifest >/dev/null || fail 'failed candidate changed accepted sequence'
  expect systemctl is-active --quiet cdnca-edge-agent.service
  assert_state state-v2
}

wait_systemd() {
  attempt=0
  state=unknown
  while [ "${attempt}" -lt 120 ]; do
    state=$(systemctl is-system-running 2>/dev/null || true)
    case "${state}" in running|degraded) return 0 ;; esac
    attempt=$((attempt + 1))
    sleep 0.25
  done
  fail "systemd did not become ready: ${state}"
}

verify_post_restart() {
  wait_systemd
  assert_active 1.1.0
  assert_state state-v2
  grep -Fx 'release_sequence=2' /var/lib/cdnca-edge-agent-packaging/accepted-manifest >/dev/null || fail 'restart weakened accepted release floor'
  printf 'restart_recovery distro=%s arch=%s systemd=%s service=active enabled=true current=1.1.0 state=state-v2\n' "${distro}" "${arch}" "${actual_systemd}"
}

verify_repository
if [ "${phase}" = post-restart ]; then
  verify_post_restart
  exit 0
fi

wait_systemd
rm -f /etc/apt/sources.list.d/cdnca-edge.list
install -m 0644 "${repository_keyring}" "${installed_keyring}"
printf 'deb [signed-by=/usr/share/keyrings/cdnca-archive-keyring.gpg] file:%s %s %s\n' \
  "${repository}" "${suite}" "${component}" >/etc/apt/sources.list.d/cdnca-edge.list
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 -o Acquire::https::Timeout=20 \
  update -o Acquire::Languages=none -qq
apt-cache policy cdnca-edge-agent | grep -F '1.0.0-1' >/dev/null || fail 'apt did not acquire the signed repository'

DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 \
  install -y -qq cdnca-edge-agent=1.0.0-1 >/var/tmp/ops11-install-v1.log 2>&1 || {
  cat /var/tmp/ops11-install-v1.log >&2
  fail 'fresh signed package installation failed'
}
[ "$(dpkg-query -W -f='${db:Status-Status}' cdnca-edge-agent)" = installed ] || fail 'v1 package is not installed'
assert_current 1.0.0
id cdnca-edge >/dev/null 2>&1 || fail 'system user was not created'
uid=$(id -u cdnca-edge)
gid=$(id -g cdnca-edge)
[ "${uid}" -gt 0 ] && [ "${gid}" -gt 0 ] || fail 'package service account is privileged'
[ "$(systemctl is-enabled cdnca-edge-agent.service 2>/dev/null || true)" = disabled ] || fail 'fresh package was enabled before enrollment'

write_config
write_state state-v1
systemctl enable --now cdnca-edge-agent.service
assert_active 1.0.0
[ "$(stat -c '%u:%g:%a' /etc/cdnca-edge-agent/config.json)" = "${uid}:${gid}:600" ] || fail 'config uid/mode contract'
[ "$(stat -c '%u:%g:%a' /var/lib/cdnca-edge-agent-backups/active-state)" = "${uid}:${gid}:700" ] || fail 'active-state uid/mode contract'
if setpriv --reuid="${uid}" --regid="${gid}" --clear-groups --no-new-privs \
  sh -c 'printf x >>/etc/cdnca-edge-agent/package-signing.pem' >/dev/null 2>&1; then
  fail 'non-root service uid can modify package trust'
fi

CDNCA_EDGE_DEB_HEALTH_TIMEOUT=8 CDNCA_EDGE_DEB_HEALTH_STABLE=1 \
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cdnca-edge-agent=1.1.0-1 >/var/tmp/ops11-install-v2.log 2>&1 || {
  cat /var/tmp/ops11-install-v2.log >&2
  fail 'signed version upgrade failed'
}
assert_active 1.1.0
write_state state-v2
grep -Fx 'release_sequence=2' /var/lib/cdnca-edge-agent-packaging/accepted-manifest >/dev/null || fail 'v2 accepted manifest is missing'

vbad_package=${repository}/$(package_path 1.2.0)
bad_root=/var/tmp/ops11-bad-package
rm -rf "${bad_root}"
mkdir -p "${bad_root}"
dpkg-deb -x "${vbad_package}" "${bad_root}"
bad_bundle=${bad_root}/usr/lib/cdnca-edge-agent/deb-bundles/1.2.0
cp "${bad_bundle}/manifest.sig" "${bad_bundle}/manifest.sig.clean"
printf x >>"${bad_bundle}/manifest.sig"
pid_before=$(systemctl show -p MainPID --value cdnca-edge-agent.service)
if run_upgrade "${bad_bundle}" 3 0 >/var/tmp/ops11-bad-package.log 2>&1; then
  fail 'bad-package-signature unexpectedly passed'
fi
[ "$(systemctl show -p MainPID --value cdnca-edge-agent.service)" = "${pid_before}" ] || fail 'bad package changed the running service'
assert_failed_preserves_v2
printf 'bad-package-signature preserved current=1.1.0 accepted=2\n'

mv -Tf "${bad_bundle}/manifest.sig.clean" "${bad_bundle}/manifest.sig"
cp -a "${bad_root}" /var/tmp/ops11-bad-config
bad_config_bundle=/var/tmp/ops11-bad-config/usr/lib/cdnca-edge-agent/deb-bundles/1.2.0
printf 'not-json\n' >/etc/cdnca-edge-agent/config.json
chown cdnca-edge:cdnca-edge /etc/cdnca-edge-agent/config.json
chmod 0600 /etc/cdnca-edge-agent/config.json
if run_upgrade "${bad_config_bundle}" 3 0 >/var/tmp/ops11-bad-config.log 2>&1; then
  fail 'bad-configuration unexpectedly passed'
fi
write_config
assert_failed_preserves_v2
printf 'bad-configuration preserved current=1.1.0 accepted=2\n'

clean_root=/var/tmp/ops11-unhealthy-release
rm -rf "${clean_root}"
mkdir -p "${clean_root}"
dpkg-deb -x "${vbad_package}" "${clean_root}"
clean_bundle=${clean_root}/usr/lib/cdnca-edge-agent/deb-bundles/1.2.0
if run_upgrade "${clean_bundle}" 6 1 >/var/tmp/ops11-unhealthy-release.log 2>&1; then
  fail 'unhealthy-release unexpectedly passed'
fi
assert_failed_preserves_v2
printf 'unhealthy-release rolled_back current=1.1.0 accepted=2 service=active\n'

rm -rf "${bad_root}" /var/tmp/ops11-bad-config /var/tmp/ops11-unhealthy-release
printf 'OPS11_SYSTEMD_LIFECYCLE PASS distro=%s arch=%s systemd=%s uid=%s gid=%s current=1.1.0 accepted_sequence=2 rollback=3/3 restart=pending\n' \
  "${distro}" "${arch}" "${actual_systemd}" "${uid}" "${gid}"
