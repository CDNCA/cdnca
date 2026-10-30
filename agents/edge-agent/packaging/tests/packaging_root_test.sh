#!/bin/sh
# Root runtime identity (native nodes): install, preflight, upgrade, rollback,
# failure recovery and identity pinning against an isolated DESTDIR.
set -eu

packaging_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp_base=${TMPDIR:-/tmp}
workdir=$(mktemp -d "${tmp_base%/}/cdnca-edge-package-root.XXXXXX")
chmod 0711 "${workdir}"
trap 'rm -rf -- "${workdir}"' EXIT
trap 'exit 1' HUP INT TERM

fail() {
  printf 'root packaging smoke failed: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "must run as root in an isolated container"
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
assert_absent() { [ ! -e "$1" ] && [ ! -L "$1" ] || fail "path should be absent: $1"; }
policy() { stat -c '%u:%g:%a' "$1"; }

host_arch=$(uname -m)
case "${host_arch}" in
  x86_64|amd64) host_arch=amd64 ;;
  aarch64|arm64) host_arch=arm64 ;;
  *) fail "unsupported test architecture: ${host_arch}" ;;
esac

# The fixture proves the probe identities: --version must run unprivileged,
# --check-config must run as root (it reads a root-owned 0600 config). Both
# require empty supplementary groups, no_new_privs and a scrubbed environment.
make_agent() {
  path=$1
  version=$2
  source_path=${path}.c
  cat >"${source_path}" <<EOF
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static int base_identity(uid_t *uid) {
  const char *uid_text = getenv("CDNCA_PROBE_EXPECT_UID");
  const char *gid_text = getenv("CDNCA_PROBE_EXPECT_GID");
  if (uid_text == NULL || gid_text == NULL || getenv("CDNCA_ROOT_SECRET_SHOULD_NOT_LEAK") != NULL) return 90;
  *uid = (uid_t)strtoul(uid_text, NULL, 10);
  gid_t gid = (gid_t)strtoul(gid_text, NULL, 10);
  if (getuid() != *uid || geteuid() != *uid || getgid() != gid || getegid() != gid ||
      getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 91;
  return 0;
}

int main(int argc, char **argv) {
  uid_t uid;
  int status = base_identity(&uid);
  if (status != 0) return status;
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    if (uid == 0) return 92;
    puts("{\"agent_version\":\"${version}\",\"build_id\":\"smoke\"}");
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "--check-config") == 0 && strcmp(argv[2], "-config") == 0) {
    if (uid != 0) return 93;
    return access(argv[3], R_OK) == 0 ? 0 : 94;
  }
  return 2;
}
EOF
  cc -O2 -Wall -Wextra -Werror -o "${path}" "${source_path}"
  rm -f -- "${source_path}"
}

private_key=${workdir}/private.pem
public_key=${workdir}/public.pem
openssl genpkey -algorithm ED25519 -out "${private_key}"
openssl pkey -in "${private_key}" -pubout -out "${public_key}"

make_bundle() {
  bundle=$1
  version=$2
  sequence=$3
  mkdir -p "${bundle}"
  make_agent "${bundle}/edge-agent" "${version}"
  printf '{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"edge-agent-%s","documentNamespace":"https://example.invalid/spdx/edge-agent-%s","creationInfo":{"created":"2026-07-22T00:00:00Z","creators":["Tool: cdnca-packaging-root-smoke"]}}\n' \
    "${version}" "${version}" >"${bundle}/edge-agent.spdx.json"
  printf 'manifest_version=2\nrelease_sequence=%s\nversion=%s\nartifact_path=edge-agent\nartifact_sha256=%s\nartifact_size=%s\nsbom_path=edge-agent.spdx.json\nsbom_sha256=%s\nsbom_size=%s\nos=linux\narch=%s\nsource_repository=https://example.invalid/cdnca.git\nsource_commit=0123456789abcdef0123456789abcdef01234567\nbuild_time=2026-07-22T00:00:00Z\nminimum_control_protocol=1.0\nminimum_agent_protocol=1.0\n' \
    "${sequence}" "${version}" "$(sha256_file "${bundle}/edge-agent")" "$(stat -c '%s' "${bundle}/edge-agent")" \
    "$(sha256_file "${bundle}/edge-agent.spdx.json")" "$(stat -c '%s' "${bundle}/edge-agent.spdx.json")" \
    "${host_arch}" >"${bundle}/manifest"
  openssl pkeyutl -sign -inkey "${private_key}" -rawin -in "${bundle}/manifest" -out "${bundle}/manifest.sig"
}

make_bundle "${workdir}/v1" v1 1
make_bundle "${workdir}/v2" v2 2
make_bundle "${workdir}/vbad" vbad 3
make_bundle "${workdir}/v4" v4 4

root=${workdir}/root
service_driver=${workdir}/service-driver
export CDNCA_ROOT_SECRET_SHOULD_NOT_LEAK=present
cat >"${service_driver}" <<EOF
#!/bin/sh
set -eu
printf '%s\n' "\$1" >>"${workdir}/service-actions"
state_view=${root}/var/lib/cdnca-edge-agent-backups/active-state
case "\$1" in
  daemon-reload|enable|disable) ;;
  stop) rm -f "${workdir}/service-active" ;;
  restart)
    target=\$(readlink "${root}/usr/lib/cdnca-edge-agent/current")
    # A root Agent writes root-owned state and its OpenResty worker leaves
    # entries owned by another account (nginx chowns temporary paths).
    printf '%s\n' "\${target}" >"\${state_view}/started-by"
    mkdir -p "\${state_view}/certificates/shared/client_body_temp"
    chmod 0700 "\${state_view}/certificates" "\${state_view}/certificates/shared" "\${state_view}/certificates/shared/client_body_temp"
    chown 65534:65534 "\${state_view}/certificates/shared/client_body_temp"
    : >"${workdir}/service-active"
    ;;
  is-active)
    [ -f "${workdir}/service-active" ] || exit 3
    [ "\$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" != versions/vbad ] || exit 3
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "${service_driver}"

install_bundle() {
  bundle=$1
  shift
  "${packaging_root}/scripts/install.sh" \
    --artifact "${bundle}/edge-agent" --sbom "${bundle}/edge-agent.spdx.json" \
    --manifest "${bundle}/manifest" --signature "${bundle}/manifest.sig" \
    --public-key "${public_key}" --destdir "${root}" --service-driver "${service_driver}" "$@"
}

upgrade_bundle() {
  bundle=$1
  shift
  "${root}/usr/libexec/cdnca-edge-agent/upgrade.sh" \
    --artifact "${bundle}/edge-agent" --sbom "${bundle}/edge-agent.spdx.json" \
    --manifest "${bundle}/manifest" --signature "${bundle}/manifest.sig" \
    --public-key "${public_key}" --destdir "${root}" --service-driver "${service_driver}" \
    --health-timeout 2 --health-stable 0 "$@"
}

# An unknown identity is a usage error before any write.
if install_bundle "${workdir}/v1" --runtime-identity nobody >/dev/null 2>&1; then
  fail "unknown runtime identity was accepted"
fi
assert_absent "${root}"

# Fresh root install.
install_bundle "${workdir}/v1" --runtime-identity root >/dev/null
marker=${root}/var/lib/cdnca-edge-agent-packaging/runtime-identity
[ "$(stat -c '%u:%g:%a:%s' "${marker}")" = 0:0:600:4 ] && [ "$(cat "${marker}")" = root ] || fail "runtime identity marker"
unit=${root}/usr/lib/systemd/system/cdnca-edge-agent.service
cmp -s "${unit}" "${packaging_root}/systemd/cdnca-edge-agent-root.service" || fail "root unit was not installed"
# shellcheck disable=SC2016 # The unit line is matched literally.
for line in User=root Group=root \
  'ExecStart=/usr/lib/cdnca-edge-agent/current/edge-agent -config ${CDNCA_EDGE_CONFIG}' \
  'ExecStartPre=/usr/libexec/cdnca-edge-agent/preflight.sh' \
  'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind'; do
  grep -Fx -- "${line}" "${unit}" >/dev/null || fail "root unit lacks: ${line}"
done
for forbidden in User=cdnca-edge CapabilityBoundingSet= SystemCallFilter= RestrictAddressFamilies=; do
  if grep -F -- "${forbidden}" "${unit}" >/dev/null; then fail "root unit contains ${forbidden}"; fi
done
cmp -s "${root}/usr/lib/tmpfiles.d/cdnca-edge-agent.conf" "${packaging_root}/tmpfiles/cdnca-edge-agent-root.conf" || \
  fail "root tmpfiles were not installed"
for asset in systemd/cdnca-edge-agent.service systemd/cdnca-edge-agent-root.service \
  tmpfiles/cdnca-edge-agent.conf tmpfiles/cdnca-edge-agent-root.conf; do
  cmp -s "${root}/usr/libexec/cdnca-edge-agent/assets/${asset}" "${packaging_root}/${asset}" || fail "asset ${asset}"
done
grep -q '^cdnca-edge:' "${root}/etc/passwd" || fail "helper socket account was not created"
assert_absent "${root}/etc/cdnca-edge-agent/identity"
[ "$(policy "${root}/etc/cdnca-edge-agent")" = 0:0:700 ] || fail "config directory policy"
[ "$(policy "${root}/etc/cdnca-edge-agent/tls")" = 0:0:700 ] || fail "tls directory policy"
[ "$(policy "${root}/etc/cdnca-edge-agent/trust")" = 0:0:700 ] || fail "trust directory policy"
[ "$(policy "${root}/var/log/cdnca-edge-agent")" = 0:0:700 ] || fail "log directory policy"
[ "$(policy "${root}/var/lib/cdnca-edge-agent")" = 0:0:700 ] || fail "bind mountpoint policy"
[ -z "$(find "${root}/var/lib/cdnca-edge-agent" -mindepth 1 -print -quit)" ] || fail "bind mountpoint is not empty"
for state_path in active-state active-state/gateway-journal active-state/deployments; do
  [ "$(policy "${root}/var/lib/cdnca-edge-agent-backups/${state_path}")" = 0:0:700 ] || fail "root state policy: ${state_path}"
done
[ "$(stat -c '%u:%g:%a' "${root}/etc/cdnca-edge-agent/package-signing.pem")" = 0:0:444 ] || fail "pinned key policy"
cp -a /usr/lib/systemd/system/. "${root}/usr/lib/systemd/system/"
cmp -s "${unit}" "${packaging_root}/systemd/cdnca-edge-agent-root.service" || fail "unit fixture copy replaced the root unit"
if ! systemd-analyze verify --root="${root}" --recursive-errors=no /usr/lib/systemd/system/cdnca-edge-agent.service \
  >"${workdir}/systemd-verify.log" 2>&1; then
  sed -n '1,80p' "${workdir}/systemd-verify.log" >&2
  fail "root unit verification failed"
fi
# Rerunning the root tmpfiles must not touch the deployment root mode that the
# Agent's native worker access owns.
chmod 0710 "${root}/var/lib/cdnca-edge"
systemd-tmpfiles --root="${root}" --create cdnca-edge-agent.conf >/dev/null
[ "$(stat -c '%a' "${root}/var/lib/cdnca-edge")" = 710 ] || fail "tmpfiles reset the deployment root"

# The marker pins identity: a deb-mode reinstall over a root release fails.
if install_bundle "${workdir}/v1" --runtime-identity cdnca-edge >/dev/null 2>&1; then
  fail "identity change on an installed release was accepted"
fi
install_bundle "${workdir}/v1" >/dev/null
install_bundle "${workdir}/v1" --runtime-identity root >/dev/null
[ "$(cat "${marker}")" = root ] || fail "idempotent reinstall changed the marker"
if upgrade_bundle "${workdir}/v2" --runtime-identity root >/dev/null 2>&1; then
  fail "upgrade accepted a runtime identity option"
fi

# Enrollment-owned files are root-owned in root mode.
config=${root}/etc/cdnca-edge-agent/config.json
printf '%s\n' '{"smoke":true}' >"${config}"
chmod 0600 "${config}"
printf '%s\n' original-state >"${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
chmod 0600 "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
"${root}/usr/libexec/cdnca-edge-agent/preflight.sh" --destdir "${root}" >/dev/null
staged_uid=$(awk -F: '$1 == "cdnca-edge" { print $3 }' "${root}/etc/passwd")
chown "${staged_uid}" "${config}"
if "${root}/usr/libexec/cdnca-edge-agent/preflight.sh" --destdir "${root}" >/dev/null 2>&1; then
  fail "root-mode preflight accepted a cdnca-edge-owned configuration"
fi
chown 0:0 "${config}"
: >"${workdir}/service-active"

# Upgrade v1 -> v2: root probes, state backup, current switch, root unit kept.
upgrade_bundle "${workdir}/v2" >/dev/null
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "upgrade did not select v2"
cmp -s "${unit}" "${packaging_root}/systemd/cdnca-edge-agent-root.service" || fail "upgrade replaced the root unit"
cmp -s "${root}/usr/lib/tmpfiles.d/cdnca-edge-agent.conf" "${packaging_root}/tmpfiles/cdnca-edge-agent-root.conf" || \
  fail "upgrade replaced the root tmpfiles"
last_backup=$(readlink "${root}/var/lib/cdnca-edge-agent-backups/last-upgrade")
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/${last_backup}/state/state.txt")" = original-state ] || \
  fail "upgrade state backup content"
[ "$(stat -c '%u:%g' "${root}/var/lib/cdnca-edge-agent-backups/active-state/certificates/shared/client_body_temp")" = 65534:65534 ] || \
  fail "worker-owned state fixture is missing"
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/started-by")" = versions/v2 ] || fail "v2 did not start"

# A failed health gate restores v2, its state and the root unit.
if upgrade_bundle "${workdir}/vbad" >/dev/null 2>&1; then
  fail "unhealthy root-mode upgrade was accepted"
fi
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "failed upgrade did not restore v2"
cmp -s "${unit}" "${packaging_root}/systemd/cdnca-edge-agent-root.service" || fail "failed upgrade changed the root unit"
assert_absent "${root}/var/lib/cdnca-edge-agent-packaging/transaction"

# setuid state is rejected before the service is stopped.
setuid_fixture=${root}/var/lib/cdnca-edge-agent-backups/active-state/setuid
: >"${setuid_fixture}"
chmod 04700 "${setuid_fixture}"
stops_before=$(grep -c '^stop$' "${workdir}/service-actions")
if upgrade_bundle "${workdir}/v4" >/dev/null 2>&1; then
  fail "setuid state was accepted"
fi
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "setuid rejection changed current"
[ "$(grep -c '^stop$' "${workdir}/service-actions")" = "${stops_before}" ] || fail "setuid rejection stopped the service"
rm -f -- "${setuid_fixture}"

# Explicit rollback to the previous release runs root probes.
"${root}/usr/libexec/cdnca-edge-agent/rollback.sh" --version v1 --destdir "${root}" \
  --service-driver "${service_driver}" --health-timeout 2 --health-stable 0 >/dev/null
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v1 ] || fail "rollback did not select v1"

# A tampered marker fails closed before any write.
printf 'cdnf' >"${marker}"
accepted_before=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
if upgrade_bundle "${workdir}/v4" >/dev/null 2>&1; then
  fail "invalid runtime identity marker was accepted"
fi
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_before}" ] || \
  fail "invalid marker changed replay state"
printf 'root' >"${marker}"
chmod 0644 "${marker}"
if upgrade_bundle "${workdir}/v4" >/dev/null 2>&1; then
  fail "group-readable runtime identity marker was accepted"
fi
chmod 0600 "${marker}"

# Purge removes the marker with the rest of the packaging state.
"${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" --destdir "${root}" --service-driver "${service_driver}" \
  --purge --non-interactive --confirm-purge DELETE-EDGE-IDENTITY-AND-STATE >/dev/null
assert_absent "${marker}"
assert_absent "${root}/var/lib/cdnca-edge-agent-packaging"

# A default deb install in a fresh root is unchanged: no marker, deb unit.
rm -rf -- "${root}"
install_bundle "${workdir}/v1" >/dev/null
assert_absent "${marker}"
cmp -s "${unit}" "${packaging_root}/systemd/cdnca-edge-agent.service" || fail "default install did not use the deb unit"
cmp -s "${root}/usr/lib/tmpfiles.d/cdnca-edge-agent.conf" "${packaging_root}/tmpfiles/cdnca-edge-agent.conf" || \
  fail "default install did not use the deb tmpfiles"
[ "$(stat -c '%u' "${root}/var/lib/cdnca-edge-agent-backups/active-state")" = \
  "$(awk -F: '$1 == "cdnca-edge" { print $3 }' "${root}/etc/passwd")" ] || fail "deb state ownership"
if install_bundle "${workdir}/v1" --runtime-identity root >/dev/null 2>&1; then
  fail "root identity over an installed deb release was accepted"
fi
printf 'edge-agent root runtime packaging smoke passed\n'
