#!/bin/sh
set -eu

packaging_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp_base=${TMPDIR:-/tmp}
workdir=$(mktemp -d "${tmp_base%/}/cdnca-edge-package.XXXXXX")
chmod 0711 "${workdir}"
mounted_paths=
cleanup() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM
  set +e
  cleanup_failed=false
  for mounted_path in ${mounted_paths}; do
    if mountpoint -q -- "${mounted_path}" && ! umount -- "${mounted_path}"; then
      printf 'packaging smoke cleanup failed to unmount: %s\n' "${mounted_path}" >&2
      cleanup_failed=true
    fi
  done
  if [ "${cleanup_failed}" = true ]; then
    exit 1
  fi
  rm -rf -- "${workdir}"
  exit "${cleanup_status}"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

fail() {
  printf 'packaging smoke failed: %s\n' "$*" >&2
  exit 1
}

assert_file() {
  [ -f "$1" ] && [ ! -L "$1" ] || fail "missing regular file: $1"
}

assert_absent() {
  [ ! -e "$1" ] && [ ! -L "$1" ] || fail "path should be absent: $1"
}

mount_tmpfs_fixture() {
  mount_target=$1
  install -d -m 0700 "${mount_target}"
  mount -t tmpfs -o nodev,nosuid,noexec,mode=0700,size=1m \
    cdnca-ops0611-mounted-subtree "${mount_target}"
  mounted_paths="${mount_target} ${mounted_paths}"
  [ "$(stat -c '%d' "${mount_target}")" != \
    "$(stat -c '%d' "$(dirname -- "${mount_target}")")" ] || \
    fail "tmpfs fixture did not cross a filesystem boundary: ${mount_target}"
}

unmount_fixture() {
  unmount_target=$1
  umount -- "${unmount_target}" || fail "cannot unmount fixture: ${unmount_target}"
  ! mountpoint -q -- "${unmount_target}" || fail "fixture remains mounted: ${unmount_target}"
}

assert_no_restore_staging() {
  staging_path=$(find "${root}/var/lib/cdnca-edge-agent-backups" -maxdepth 1 -name '.restore-*' -print -quit)
  [ -z "${staging_path}" ] || fail "state restore staging was retained: ${staging_path}"
}

assert_package_lock_idle() {
  assert_file "${root}/var/lib/cdnca-edge-agent-packaging/transaction.lock"
  assert_absent "${root}/var/lib/cdnca-edge-agent-packaging/transaction.owner"
  assert_absent "${root}/var/lib/cdnca-edge-agent-packaging/transaction"
}

assert_no_bundle_staging() {
  [ ! -d "${root}/usr/lib/cdnca-edge-agent" ] || \
    [ -z "$(find "${root}/usr/lib/cdnca-edge-agent" -maxdepth 1 -name '.input-bundle-*' -print -quit)" ] || \
    fail "bundle staging was retained"
}

assert_no_transaction_staging() {
  [ ! -d "${root}/var/lib/cdnca-edge-agent-packaging" ] || \
    [ -z "$(find "${root}/var/lib/cdnca-edge-agent-packaging" -maxdepth 1 -name '.transaction.*' -print -quit)" ] || \
    fail "transaction staging was retained"
}

assert_no_metadata_install_staging() {
  [ ! -d "${root}" ] || \
    [ -z "$(find "${root}" -name '*.package-install-*' -print -quit)" ] || \
    fail "package metadata staging was retained"
}

assert_completed_state_layout() {
  active_state=${root}/var/lib/cdnca-edge-agent-backups/active-state
  mountpoint=${root}/var/lib/cdnca-edge-agent
  [ -d "${active_state}" ] && [ ! -L "${active_state}" ] || fail "canonical active state is unavailable"
  [ -d "${mountpoint}" ] && [ ! -L "${mountpoint}" ] || fail "state bind mountpoint is unavailable"
  [ "$(stat -c '%u:%g:%a' "${mountpoint}")" = 0:0:700 ] || fail "state bind mountpoint policy"
  [ -z "$(find "${mountpoint}" -mindepth 1 -print -quit)" ] || fail "state bind mountpoint is not empty"
  assert_absent "${root}/var/lib/cdnca-edge-agent-packaging/layout-migration"
}

package_metadata_paths() {
  printf '%s\n' \
    usr/lib/systemd/system/cdnca-edge-agent.service \
    usr/lib/sysusers.d/cdnca-edge-agent.conf \
    usr/lib/tmpfiles.d/cdnca-edge-agent.conf \
    etc/logrotate.d/cdnca-edge-agent \
    etc/cdnca-edge-agent/agent.env \
    usr/share/doc/cdnca-edge-agent/config.example.json \
    usr/share/doc/cdnca-edge-agent/README.md \
    usr/libexec/cdnca-edge-agent/install.sh \
    usr/libexec/cdnca-edge-agent/lib.sh \
    usr/libexec/cdnca-edge-agent/preflight.sh \
    usr/libexec/cdnca-edge-agent/rollback.sh \
    usr/libexec/cdnca-edge-agent/uninstall.sh \
    usr/libexec/cdnca-edge-agent/upgrade.sh \
    usr/libexec/cdnca-edge-agent/assets/systemd/cdnca-edge-agent.service \
    usr/libexec/cdnca-edge-agent/assets/sysusers/cdnca-edge-agent.conf \
    usr/libexec/cdnca-edge-agent/assets/tmpfiles/cdnca-edge-agent.conf \
    usr/libexec/cdnca-edge-agent/assets/logrotate/cdnca-edge-agent \
    usr/libexec/cdnca-edge-agent/assets/config/agent.env \
    usr/libexec/cdnca-edge-agent/assets/config/config.example.json \
    usr/libexec/cdnca-edge-agent/assets/README.md
}

snapshot_package_metadata() {
  snapshot=$1
  : >"${snapshot}"
  for relative in $(package_metadata_paths); do
    assert_file "${root}/${relative}"
    printf '%s %s %s\n' "$(sha256_file "${root}/${relative}")" \
      "$(mode_of "${root}/${relative}")" "${relative}" >>"${snapshot}"
  done
}

assert_package_metadata_snapshot() {
  snapshot=$1
  while read -r expected_digest expected_mode relative; do
    assert_file "${root}/${relative}"
    [ "$(sha256_file "${root}/${relative}")" = "${expected_digest}" ] || \
      fail "package metadata content was not restored: ${relative}"
    [ "$(mode_of "${root}/${relative}")" = "${expected_mode}" ] || \
      fail "package metadata mode was not restored: ${relative}"
  done <"${snapshot}"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

mode_of() {
  stat -c '%a' "$1"
}

make_agent() {
  path=$1
  version=$2
  source_path=${path}.c
  cat >"${source_path}" <<EOF
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static void retain_inherited_lock(void) {
  errno = 0;
  if (fcntl(9, F_GETFD) == -1 && errno == EBADF) return;
  pid_t child = fork();
  if (child == 0) {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    sleep(20);
    _exit(0);
  }
}

static int check_identity(void) {
  const char *uid_text = getenv("CDNCA_PROBE_EXPECT_UID");
  const char *gid_text = getenv("CDNCA_PROBE_EXPECT_GID");
  if (uid_text == NULL || gid_text == NULL ||
      getenv("CDNCA_ROOT_SECRET_SHOULD_NOT_LEAK") != NULL) return 90;
  uid_t uid = (uid_t)strtoul(uid_text, NULL, 10);
  gid_t gid = (gid_t)strtoul(gid_text, NULL, 10);
  if (uid == 0 || gid == 0 || getuid() != uid || geteuid() != uid ||
      getgid() != gid || getegid() != gid || getgroups(0, NULL) != 0 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 91;
  return 0;
}

int main(int argc, char **argv) {
  int identity = check_identity();
  if (identity != 0) return identity;
  retain_inherited_lock();
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    puts("{\"agent_version\":\"${version}\",\"build_id\":\"smoke\"}");
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "--check-config") == 0 &&
      strcmp(argv[2], "-config") == 0) return access(argv[3], R_OK) == 0 ? 0 : errno;
  return 2;
}
EOF
  cc -O2 -Wall -Wextra -Werror -o "${path}" "${source_path}"
  rm -f -- "${source_path}"
}

make_bundle() {
  bundle=$1
  version=$2
  sequence=$3
  minimum_control=${4:-1.0}
  minimum_agent=${5:-1.0}
  arch=${6:-${host_arch}}
  operating_system=${7:-linux}
  mkdir -p "${bundle}"
  make_agent "${bundle}/edge-agent" "${version}"
  printf '{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"edge-agent-%s","documentNamespace":"https://example.invalid/spdx/edge-agent-%s","creationInfo":{"created":"2026-07-22T00:00:00Z","creators":["Tool: cdnca-packaging-smoke"]}}\n' \
    "${version}" "${version}" >"${bundle}/edge-agent.spdx.json"
  artifact_digest=$(sha256_file "${bundle}/edge-agent")
  artifact_size=$(stat -c '%s' "${bundle}/edge-agent")
  sbom_digest=$(sha256_file "${bundle}/edge-agent.spdx.json")
  sbom_size=$(stat -c '%s' "${bundle}/edge-agent.spdx.json")
  printf 'manifest_version=2\nrelease_sequence=%s\nversion=%s\nartifact_path=edge-agent\nartifact_sha256=%s\nartifact_size=%s\nsbom_path=edge-agent.spdx.json\nsbom_sha256=%s\nsbom_size=%s\nos=%s\narch=%s\nsource_repository=https://example.invalid/cdnca.git\nsource_commit=0123456789abcdef0123456789abcdef01234567\nbuild_time=2026-07-22T00:00:00Z\nminimum_control_protocol=%s\nminimum_agent_protocol=%s\n' \
    "${sequence}" "${version}" "${artifact_digest}" "${artifact_size}" \
    "${sbom_digest}" "${sbom_size}" "${operating_system}" "${arch}" \
    "${minimum_control}" "${minimum_agent}" >"${bundle}/manifest"
  openssl pkeyutl -sign -inkey "${private_key}" -rawin -in "${bundle}/manifest" -out "${bundle}/manifest.sig"
}

resign_bundle() {
  bundle=$1
  openssl pkeyutl -sign -inkey "${private_key}" -rawin -in "${bundle}/manifest" -out "${bundle}/manifest.sig"
}

refresh_sbom_manifest() {
  bundle=$1
  sbom_digest=$(sha256_file "${bundle}/edge-agent.spdx.json")
  sbom_size=$(stat -c '%s' "${bundle}/edge-agent.spdx.json")
  sed -i "s/^sbom_sha256=.*/sbom_sha256=${sbom_digest}/;s/^sbom_size=.*/sbom_size=${sbom_size}/" "${bundle}/manifest"
  resign_bundle "${bundle}"
}

refresh_artifact_manifest() {
  bundle=$1
  artifact_digest=$(sha256_file "${bundle}/edge-agent")
  artifact_size=$(stat -c '%s' "${bundle}/edge-agent")
  sed -i "s/^artifact_sha256=.*/artifact_sha256=${artifact_digest}/;s/^artifact_size=.*/artifact_size=${artifact_size}/" "${bundle}/manifest"
  resign_bundle "${bundle}"
}

install_bundle() {
  bundle=$1
  shift
  "${packaging_root}/scripts/install.sh" \
    --artifact "${bundle}/edge-agent" \
    --sbom "${bundle}/edge-agent.spdx.json" \
    --manifest "${bundle}/manifest" \
    --signature "${bundle}/manifest.sig" \
    --public-key "${public_key}" \
    --destdir "${root}" \
    --service-driver "${service_driver}" \
    "$@"
}

upgrade_bundle() {
  bundle=$1
  shift
  "${root}/usr/libexec/cdnca-edge-agent/upgrade.sh" \
    --artifact "${bundle}/edge-agent" \
    --sbom "${bundle}/edge-agent.spdx.json" \
    --manifest "${bundle}/manifest" \
    --signature "${bundle}/manifest.sig" \
    --public-key "${public_key}" \
    --destdir "${root}" \
    --service-driver "${service_driver}" \
    --health-timeout 2 \
    --health-stable 0 \
    "$@"
}

host_arch=$(uname -m)
case "${host_arch}" in
  x86_64|amd64) host_arch=amd64; wrong_arch=arm64 ;;
  aarch64|arm64) host_arch=arm64; wrong_arch=amd64 ;;
  *) fail "unsupported test architecture: ${host_arch}" ;;
esac

regression_case=${CDNCA_REGRESSION_ONLY:-}
case "${regression_case}" in
  ''|metadata|restore-staging|rollback-interrupt|disable-failure|layout-migration|mounted-subtree) ;;
  *) fail "unknown isolated regression case: ${regression_case}" ;;
esac

private_key=${workdir}/private.pem
public_key=${workdir}/public.pem
openssl genpkey -algorithm ED25519 -out "${private_key}"
openssl pkey -in "${private_key}" -pubout -out "${public_key}"

make_bundle "${workdir}/v1" v1 1
make_bundle "${workdir}/v2" v2 2
make_bundle "${workdir}/vbad" vbad 3
make_bundle "${workdir}/vkill" vkill 3
make_bundle "${workdir}/vreleasekill" vreleasekill 3
make_bundle "${workdir}/vlegacy" vlegacy 3
make_bundle "${workdir}/vtransaction" vtransaction 3
make_bundle "${workdir}/vcurrent-fail" vcurrent-fail 3
make_bundle "${workdir}/vaccepted-fail" vaccepted-fail 3
make_bundle "${workdir}/v3layout" v3layout 3
make_bundle "${workdir}/protocol-control" protocol-control 3 2.0 1.0
make_bundle "${workdir}/protocol-agent" protocol-agent 3 1.0 2.0
make_bundle "${workdir}/same-sequence" same-sequence 2
make_bundle "${workdir}/wrong-arch" wrong-arch 3 1.0 1.0 "${wrong_arch}"
make_bundle "${workdir}/wrong-os" wrong-os 3 1.0 1.0 "${host_arch}" freebsd
make_bundle "${workdir}/toctou-source" toctou-source 1
cp "${public_key}" "${workdir}/toctou-public.pem"
alternate_private_key=${workdir}/alternate-private.pem
alternate_public_key=${workdir}/alternate-public.pem
openssl genpkey -algorithm ED25519 -out "${alternate_private_key}"
openssl pkey -in "${alternate_private_key}" -pubout -out "${alternate_public_key}"
primary_private_key=${private_key}
private_key=${alternate_private_key}
make_bundle "${workdir}/toctou-replacement" toctou-replacement 99
private_key=${primary_private_key}
cp -a "${workdir}/v1" "${workdir}/preinstall-version-mismatch"
sed -i 's/^version=v1$/version=declared-v1/' "${workdir}/preinstall-version-mismatch/manifest"
resign_bundle "${workdir}/preinstall-version-mismatch"

cp -a "${workdir}/v2" "${workdir}/artifact-tamper"
printf 'tamper\n' >>"${workdir}/artifact-tamper/edge-agent"
cp -a "${workdir}/v2" "${workdir}/sbom-tamper"
printf 'tamper\n' >>"${workdir}/sbom-tamper/edge-agent.spdx.json"
cp -a "${workdir}/v2" "${workdir}/sbom-invalid-json"
printf 'not-json\n' >"${workdir}/sbom-invalid-json/edge-agent.spdx.json"
refresh_sbom_manifest "${workdir}/sbom-invalid-json"
cp -a "${workdir}/v2" "${workdir}/sbom-missing-field"
printf '{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"missing-creation-info","documentNamespace":"https://example.invalid/spdx/missing"}\n' >"${workdir}/sbom-missing-field/edge-agent.spdx.json"
refresh_sbom_manifest "${workdir}/sbom-missing-field"
cp -a "${workdir}/v2" "${workdir}/non-elf"
printf '#!/bin/sh\nexit 0\n' >"${workdir}/non-elf/edge-agent"
chmod 0755 "${workdir}/non-elf/edge-agent"
refresh_artifact_manifest "${workdir}/non-elf"
cp -a "${workdir}/v2" "${workdir}/manifest-tamper"
sed -i 's/2026-07-22T00:00:00Z/2026-07-22T00:00:01Z/' "${workdir}/manifest-tamper/manifest"
cp -a "${workdir}/v2" "${workdir}/signature-tamper"
printf 'x' >>"${workdir}/signature-tamper/manifest.sig"
cp -a "${workdir}/v2" "${workdir}/unknown-field"
printf 'unknown_field=rejected\n' >>"${workdir}/unknown-field/manifest"
resign_bundle "${workdir}/unknown-field"
cp -a "${workdir}/v2" "${workdir}/duplicate-key"
printf 'version=v2\n' >>"${workdir}/duplicate-key/manifest"
resign_bundle "${workdir}/duplicate-key"
cp -a "${workdir}/v2" "${workdir}/path-traversal"
sed -i 's#sbom_path=edge-agent.spdx.json#sbom_path=../edge-agent.spdx.json#' "${workdir}/path-traversal/manifest"
resign_bundle "${workdir}/path-traversal"
cp -a "${workdir}/v2" "${workdir}/symlink-input"
rm "${workdir}/symlink-input/edge-agent.spdx.json"
ln -s "${workdir}/v2/edge-agent.spdx.json" "${workdir}/symlink-input/edge-agent.spdx.json"
cp -a "${workdir}/v2" "${workdir}/hardlink-input"
ln "${workdir}/hardlink-input/edge-agent" "${workdir}/hardlink-input/edge-agent.link"
cp -a "${workdir}/v2" "${workdir}/wide-mode"
chmod 0777 "${workdir}/wide-mode/edge-agent.spdx.json"
cp -a "${workdir}/v2" "${workdir}/oversized"
truncate -s 16777217 "${workdir}/oversized/edge-agent.spdx.json"
oversized_sha=$(sha256_file "${workdir}/oversized/edge-agent.spdx.json")
sed -i "s/^sbom_sha256=.*/sbom_sha256=${oversized_sha}/;s/^sbom_size=.*/sbom_size=16777217/" "${workdir}/oversized/manifest"
resign_bundle "${workdir}/oversized"
cp -a "${workdir}/v2" "${workdir}/legacy-manifest"
legacy_sha=$(sha256_file "${workdir}/legacy-manifest/edge-agent")
printf 'schema_version=1\nartifact=edge-agent\nversion=v2\nos=linux\narch=%s\nsha256=%s\n' "${host_arch}" "${legacy_sha}" >"${workdir}/legacy-manifest/manifest"
resign_bundle "${workdir}/legacy-manifest"

root=${workdir}/root
service_driver=${workdir}/service-driver
export CDNCA_ROOT_SECRET_SHOULD_NOT_LEAK=present
cat >"${service_driver}" <<EOF
#!/bin/sh
set -eu
printf '%s\n' "\$1" >>"${workdir}/service-actions"
case "\$1" in
  daemon-reload|enable) ;;
  disable)
    [ ! -f "${workdir}/service-disable-fail" ] || exit 6
    ;;
  stop)
    [ ! -f "${workdir}/service-stop-fail" ] || exit 5
    rm -f "${workdir}/service-active"
    ;;
  restart)
    target=\$(readlink "${root}/usr/lib/cdnca-edge-agent/current")
    state_view=${root}/var/lib/cdnca-edge-agent
    if grep -F 'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind' \
      "${root}/usr/lib/systemd/system/cdnca-edge-agent.service" >/dev/null 2>&1; then
      state_view=${root}/var/lib/cdnca-edge-agent-backups/active-state
    fi
    if [ "\${target}" = versions/v1 ] && [ -f "${workdir}/rollback-restart-sigkill" ]; then
      rm -f "${workdir}/rollback-restart-sigkill" "${workdir}/service-active"
      kill -KILL "\$PPID"
      exit 7
    fi
    if [ "\${target}" = versions/vbad ]; then
      ln -s /etc/passwd "\${state_view}/release-created-link"
      mkfifo "\${state_view}/release-created-fifo"
    fi
    if [ -f "${workdir}/layout-agent-write" ]; then
      printf '%s\n' agent-write-after-migration >>"\${state_view}/state.txt"
    fi
    : >"${workdir}/service-active"
    ;;
  is-active)
    [ -f "${workdir}/service-active" ] || exit 3
    target=\$(readlink "${root}/usr/lib/cdnca-edge-agent/current")
    [ "\${target}" != versions/vbad ] || exit 3
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "${service_driver}"

if [ "${regression_case}" = mounted-subtree ]; then
  [ "$(id -u)" -eq 0 ] || fail "mounted-subtree regression requires root"
  command -v mountpoint >/dev/null 2>&1 || fail "mounted-subtree regression requires mountpoint"

  installed_root=${root}
  fresh_root=${workdir}/fresh-mounted-root
  fresh_mount=${fresh_root}/var/lib/cdnca-edge-agent/external
  mount_tmpfs_fixture "${fresh_mount}"
  printf '%s\n' fresh-external-state >"${fresh_mount}/sentinel"
  root=${fresh_root}
  if install_bundle "${workdir}/v1" >"${workdir}/fresh-mounted.out" 2>&1; then
    fail "fresh install accepted mounted state content"
  fi
  root=${installed_root}
  grep -F 'fresh agent state crosses a filesystem boundary' \
    "${workdir}/fresh-mounted.out" >/dev/null || \
    fail "fresh install did not report the mounted state boundary"
  [ "$(sed -n '1p' "${fresh_mount}/sentinel")" = fresh-external-state ] || \
    fail "fresh install changed external mounted content"
  assert_absent "${fresh_root}/var/lib/cdnca-edge-agent/gateway-journal"
  assert_absent "${fresh_root}/var/lib/cdnca-edge-agent/deployments"
  assert_absent "${fresh_root}/usr/lib/cdnca-edge-agent/current"
  assert_absent "${fresh_root}/usr/lib/systemd/system/cdnca-edge-agent.service"
  assert_absent "${fresh_root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest"
  unmount_fixture "${fresh_mount}"
  rm -rf -- "${fresh_root}"
fi

# A signed binary/version disagreement is rejected before first-install writes.
if install_bundle "${workdir}/preinstall-version-mismatch" >/dev/null 2>&1; then
  fail "preinstall version mismatch was accepted"
fi
assert_absent "${root}"

# Replacing all five inputs with another valid key/bundle after the lock is
# acquired cannot change the release that was approved by the pre-lock checks.
after_lock_hook=${workdir}/after-lock-hook
cat >"${after_lock_hook}" <<EOF
#!/bin/sh
set -eu
install -m 0555 "${workdir}/toctou-replacement/edge-agent" "${workdir}/toctou-source/edge-agent"
install -m 0444 "${workdir}/toctou-replacement/edge-agent.spdx.json" "${workdir}/toctou-source/edge-agent.spdx.json"
install -m 0444 "${workdir}/toctou-replacement/manifest" "${workdir}/toctou-source/manifest"
install -m 0444 "${workdir}/toctou-replacement/manifest.sig" "${workdir}/toctou-source/manifest.sig"
install -m 0444 "${alternate_public_key}" "${workdir}/toctou-public.pem"
EOF
chmod 0755 "${after_lock_hook}"
if CDNCA_PACKAGE_TEST_AFTER_LOCK_HOOK=${after_lock_hook} \
  "${packaging_root}/scripts/install.sh" \
    --artifact "${workdir}/toctou-source/edge-agent" \
    --sbom "${workdir}/toctou-source/edge-agent.spdx.json" \
    --manifest "${workdir}/toctou-source/manifest" \
    --signature "${workdir}/toctou-source/manifest.sig" \
    --public-key "${workdir}/toctou-public.pem" \
    --destdir "${root}" --service-driver "${service_driver}" >/dev/null 2>&1; then
  fail "after-lock five-input replacement was accepted"
fi
assert_absent "${root}/etc/cdnca-edge-agent/package-signing.pem"
assert_absent "${root}/usr/lib/cdnca-edge-agent/current"
assert_absent "${root}/usr/lib/systemd/system/cdnca-edge-agent.service"
assert_absent "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest"
assert_package_lock_idle
assert_no_bundle_staging

# Fresh install lays down immutable release files and operating-system metadata.
install_bundle "${workdir}/v1" >/dev/null
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v1 ] || fail "fresh install did not select v1"
assert_completed_state_layout
for installed in \
  "${root}/usr/lib/cdnca-edge-agent/versions/v1/edge-agent" \
  "${root}/usr/lib/cdnca-edge-agent/versions/v1/edge-agent.spdx.json" \
  "${root}/usr/lib/cdnca-edge-agent/versions/v1/manifest" \
  "${root}/usr/lib/cdnca-edge-agent/versions/v1/manifest.sig" \
  "${root}/usr/lib/systemd/system/cdnca-edge-agent.service" \
  "${root}/usr/libexec/cdnca-edge-agent/install.sh" \
  "${root}/usr/libexec/cdnca-edge-agent/assets/systemd/cdnca-edge-agent.service" \
  "${root}/usr/lib/tmpfiles.d/cdnca-edge-agent.conf" \
  "${root}/usr/lib/sysusers.d/cdnca-edge-agent.conf" \
  "${root}/etc/logrotate.d/cdnca-edge-agent" \
  "${root}/etc/cdnca-edge-agent/agent.env" \
  "${root}/etc/cdnca-edge-agent/package-signing.pem" \
  "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest"; do
  assert_file "${installed}"
done
[ "$(mode_of "${root}/usr/lib/cdnca-edge-agent/versions/v1/edge-agent")" = 555 ] || fail "binary mode"
[ "$(mode_of "${root}/usr/lib/cdnca-edge-agent/versions/v1/edge-agent.spdx.json")" = 444 ] || fail "SBOM mode"
[ "$(mode_of "${root}/etc/cdnca-edge-agent/agent.env")" = 600 ] || fail "environment file mode"
[ "$(mode_of "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = 600 ] || fail "accepted manifest mode"
[ "$(mode_of "${root}/etc/cdnca-edge-agent/identity")" = 700 ] || fail "identity directory mode"
[ "$(mode_of "${root}/etc/cdnca-edge-agent/tls")" = 700 ] || fail "certificate directory mode"
[ "$(mode_of "${root}/var/lib/cdnca-edge-agent")" = 700 ] || fail "state directory mode"
[ "$(mode_of "${root}/var/lib/cdnca-edge-agent-backups")" = 700 ] || fail "state mount root mode"
[ "$(mode_of "${root}/var/lib/cdnca-edge-agent-backups/active-state")" = 700 ] || fail "active state mode"
[ "$(mode_of "${root}/usr/lib/cdnca-edge-agent/versions/v1")" = 755 ] || fail "version directory mode"
grep -F 'EnvironmentFile=/etc/cdnca-edge-agent/agent.env' "${root}/usr/lib/systemd/system/cdnca-edge-agent.service" >/dev/null || fail "unit lacks EnvironmentFile"
grep -Fx 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' "${root}/usr/lib/systemd/system/cdnca-edge-agent.service" >/dev/null || fail "unit lacks low-port precheck capability bound"
grep -Fx 'AmbientCapabilities=CAP_NET_BIND_SERVICE' "${root}/usr/lib/systemd/system/cdnca-edge-agent.service" >/dev/null || fail "unit lacks low-port precheck ambient capability"
grep -F '/usr/sbin/nologin' "${root}/usr/lib/sysusers.d/cdnca-edge-agent.conf" >/dev/null || fail "sysuser is not non-login"
grep -q '^cdnca-edge:' "${root}/etc/passwd" || fail "sysusers did not create the staged account"
staged_uid=$(awk -F: '$1 == "cdnca-edge" { print $3 }' "${root}/etc/passwd")
staged_gid=$(awk -F: '$1 == "cdnca-edge" { print $4 }' "${root}/etc/passwd")
[ "$(stat -c '%u:%g' "${root}/etc/cdnca-edge-agent/identity")" = "${staged_uid}:${staged_gid}" ] || fail "identity directory ownership"
[ "$(stat -c '%u:%g' "${root}/var/lib/cdnca-edge-agent")" = 0:0 ] || fail "state bind mountpoint ownership"
for state_path in \
  "${root}/var/lib/cdnca-edge-agent-backups/active-state" \
  "${root}/var/lib/cdnca-edge-agent-backups/active-state/gateway-journal" \
  "${root}/var/lib/cdnca-edge-agent-backups/active-state/deployments"; do
  [ "$(stat -c '%u:%g:%a' "${state_path}")" = "${staged_uid}:${staged_gid}:700" ] || \
    fail "fresh runtime state ownership or mode: ${state_path}"
done
printf '%s\n' retained-across-tmpfiles \
  >"${root}/var/lib/cdnca-edge-agent-backups/active-state/gateway-journal/tmpfiles-sentinel"
chown "${staged_uid}:${staged_gid}" \
  "${root}/var/lib/cdnca-edge-agent-backups/active-state/gateway-journal/tmpfiles-sentinel"
systemd-tmpfiles --root="${root}" --create cdnca-edge-agent.conf >/dev/null
[ "$(stat -c '%u:%g:%a' "${root}/var/lib/cdnca-edge-agent")" = 0:0:700 ] || \
  fail "repeated tmpfiles changed the state bind mountpoint"
for state_path in \
  "${root}/var/lib/cdnca-edge-agent-backups/active-state" \
  "${root}/var/lib/cdnca-edge-agent-backups/active-state/gateway-journal" \
  "${root}/var/lib/cdnca-edge-agent-backups/active-state/deployments"; do
  [ "$(stat -c '%u:%g:%a' "${state_path}")" = "${staged_uid}:${staged_gid}:700" ] || \
    fail "repeated tmpfiles changed runtime state: ${state_path}"
done
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/gateway-journal/tmpfiles-sentinel")" = \
  retained-across-tmpfiles ] || fail "repeated tmpfiles changed existing runtime state"
[ "$(stat -c '%u:%g' "${root}/usr/lib/cdnca-edge-agent/versions/v1")" = 0:0 ] || fail "version directory ownership"
cp -a /usr/lib/systemd/system/. "${root}/usr/lib/systemd/system/"
if ! systemd-analyze verify --root="${root}" --recursive-errors=no /usr/lib/systemd/system/cdnca-edge-agent.service >"${workdir}/systemd-verify.log" 2>&1; then
  sed -n '1,120p' "${workdir}/systemd-verify.log" >&2
  fail "systemd unit verification failed"
fi

# Repeating the same install is idempotent.
v1_digest_before=$(sha256_file "${root}/usr/lib/cdnca-edge-agent/versions/v1/edge-agent")
install_bundle "${workdir}/v1" >/dev/null
[ "$(sha256_file "${root}/usr/lib/cdnca-edge-agent/versions/v1/edge-agent")" = "${v1_digest_before}" ] || fail "repeat install changed v1"
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v1 ] || fail "repeat install changed current"

# Every supply-chain rejection happens before package or service state changes.
metadata_digest=$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")
accepted_digest=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
service_actions_before=$(wc -l <"${workdir}/service-actions" | tr -d ' ')
for rejected in \
  artifact-tamper \
  sbom-tamper \
  sbom-invalid-json \
  sbom-missing-field \
  non-elf \
  manifest-tamper \
  signature-tamper \
  unknown-field \
  duplicate-key \
  path-traversal \
  symlink-input \
  hardlink-input \
  wide-mode \
  oversized \
  legacy-manifest \
  wrong-arch \
  wrong-os; do
  if install_bundle "${workdir}/${rejected}" >/dev/null 2>&1; then
    fail "${rejected} was accepted"
  fi
done
[ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = "${metadata_digest}" ] || fail "trust rejection changed package metadata"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest}" ] || fail "trust rejection changed replay state"
[ "$(wc -l <"${workdir}/service-actions" | tr -d ' ')" = "${service_actions_before}" ] || fail "trust rejection touched the service"
assert_package_lock_idle
assert_no_bundle_staging

# Enrollment-owned files and mutable state exist before upgrades.
printf '%s\n' '{"smoke":true}' >"${root}/etc/cdnca-edge-agent/config.json"
chmod 0600 "${root}/etc/cdnca-edge-agent/config.json"
chown "${staged_uid}:${staged_gid}" "${root}/etc/cdnca-edge-agent/config.json"
printf '%s\n' private-identity-fixture >"${root}/etc/cdnca-edge-agent/identity/private.key"
chmod 0600 "${root}/etc/cdnca-edge-agent/identity/private.key"
chown "${staged_uid}:${staged_gid}" "${root}/etc/cdnca-edge-agent/identity/private.key"
printf '%s\n' original-state >"${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
chown "${staged_uid}:${staged_gid}" "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
"${root}/usr/libexec/cdnca-edge-agent/preflight.sh" --destdir "${root}" >/dev/null
: >"${workdir}/service-active"

# The restricted updater may only reuse an exact service identity established
# by the initial installer; it never repairs passwd or group databases.
identity_passwd=${root}/etc/passwd
identity_group=${root}/etc/group
cp -a "${identity_passwd}" "${workdir}/identity-passwd"
cp -a "${identity_group}" "${workdir}/identity-group"
identity_current=$(readlink "${root}/usr/lib/cdnca-edge-agent/current")
identity_accepted=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
for identity_case in missing-user missing-group mismatch; do
  install -m 0644 "${workdir}/identity-passwd" "${identity_passwd}"
  install -m 0644 "${workdir}/identity-group" "${identity_group}"
  case "${identity_case}" in
    missing-user)
      awk -F: '$1 != "cdnca-edge"' "${identity_passwd}" >"${workdir}/identity-passwd-edited"
      install -m 0644 "${workdir}/identity-passwd-edited" "${identity_passwd}"
      ;;
    missing-group)
      awk -F: '$1 != "cdnca-edge"' "${identity_group}" >"${workdir}/identity-group-edited"
      install -m 0644 "${workdir}/identity-group-edited" "${identity_group}"
      ;;
    mismatch)
      awk -F: 'BEGIN { OFS = FS } $1 == "cdnca-edge" { $6 = "/var/lib/wrong"; $7 = "/bin/sh" } { print }' \
        "${identity_passwd}" >"${workdir}/identity-passwd-edited"
      install -m 0644 "${workdir}/identity-passwd-edited" "${identity_passwd}"
      ;;
  esac
  passwd_digest=$(sha256_file "${identity_passwd}")
  group_digest=$(sha256_file "${identity_group}")
  if upgrade_bundle "${workdir}/v2" >/dev/null 2>&1; then
    fail "${identity_case} service identity was accepted for upgrade"
  fi
  [ "$(sha256_file "${identity_passwd}")" = "${passwd_digest}" ] || fail "${identity_case} rewrote passwd"
  [ "$(sha256_file "${identity_group}")" = "${group_digest}" ] || fail "${identity_case} rewrote group"
  [ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = "${identity_current}" ] || fail "${identity_case} changed current"
  [ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${identity_accepted}" ] || \
    fail "${identity_case} changed replay state"
done
install -m 0644 "${workdir}/identity-passwd" "${identity_passwd}"
install -m 0644 "${workdir}/identity-group" "${identity_group}"

# Upgrade backs up state, switches atomically, and commits only after health.
upgrade_bundle "${workdir}/v2" >/dev/null
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "upgrade did not select v2"
grep -Fx 'release_sequence=2' "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest" >/dev/null || fail "upgrade did not commit replay state"
last_backup=$(readlink "${root}/var/lib/cdnca-edge-agent-backups/last-upgrade")
assert_file "${root}/var/lib/cdnca-edge-agent-backups/${last_backup}/state/state.txt"
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/${last_backup}/state/state.txt")" = original-state ] || fail "upgrade state backup content"

case "${regression_case}" in
  metadata)
    metadata_snapshot=${workdir}/metadata-before-failed-upgrade
    snapshot_package_metadata "${metadata_snapshot}"
    metadata_package=${workdir}/metadata-package
    cp -a "${packaging_root}" "${metadata_package}"
    printf '\nmetadata_toolset_marker() { :; }\n' >>"${metadata_package}/scripts/lib.sh"
    # shellcheck disable=SC2016 # The fixture must match the literal source line.
    sed -i '/^\. "${script_dir}\/lib.sh"$/a metadata_toolset_marker' \
      "${metadata_package}/scripts/install.sh"
    for source in \
      systemd/cdnca-edge-agent.service \
      sysusers/cdnca-edge-agent.conf \
      tmpfiles/cdnca-edge-agent.conf \
      logrotate/cdnca-edge-agent \
      config/agent.env \
      config/config.example.json \
      README.md \
      scripts/install.sh \
      scripts/lib.sh \
      scripts/preflight.sh \
      scripts/rollback.sh \
      scripts/uninstall.sh \
      scripts/upgrade.sh; do
      printf '\n# mixed-version regression fixture\n' >>"${metadata_package}/${source}"
    done
    if CDNCA_PACKAGE_FAILPOINT=metadata-lib-before-commit \
      "${metadata_package}/scripts/upgrade.sh" \
        --artifact "${workdir}/vbad/edge-agent" \
        --sbom "${workdir}/vbad/edge-agent.spdx.json" \
        --manifest "${workdir}/vbad/manifest" \
        --signature "${workdir}/vbad/manifest.sig" \
        --public-key "${public_key}" \
        --destdir "${root}" --service-driver "${service_driver}" \
        --health-timeout 2 --health-stable 0 >/dev/null 2>&1; then
      fail "SIGKILL before installed lib metadata commit returned success"
    fi
    [ -d "${root}/var/lib/cdnca-edge-agent-packaging/transaction" ] || \
      fail "metadata SIGKILL did not retain a durable transaction"
    expected_lib_digest=$(awk '$3 == "usr/libexec/cdnca-edge-agent/lib.sh" { print $1 }' "${metadata_snapshot}")
    [ "$(sha256_file "${root}/usr/libexec/cdnca-edge-agent/lib.sh")" = "${expected_lib_digest}" ] || \
      fail "metadata SIGKILL replaced the installed recovery library"
    if upgrade_bundle "${workdir}/artifact-tamper" >/dev/null 2>&1; then
      fail "invalid bundle recovered an incomplete metadata transaction"
    fi
    [ -d "${root}/var/lib/cdnca-edge-agent-packaging/transaction" ] || \
      fail "invalid bundle changed the incomplete metadata transaction"
    trailing_status=0
    if "${root}/usr/libexec/cdnca-edge-agent/upgrade.sh" \
      --artifact "${workdir}/v2/edge-agent" \
      --sbom "${workdir}/v2/edge-agent.spdx.json" \
      --manifest "${workdir}/v2/manifest" \
      --signature "${workdir}/v2/manifest.sig" \
      --public-key "${public_key}" \
      --destdir "${root}/" --service-driver "${service_driver}" \
      --health-timeout 2 --health-stable 0 >"${workdir}/trailing-destdir.out" 2>&1; then
      fail "trailing-slash DESTDIR bypassed recovery bootstrap"
    else
      trailing_status=$?
    fi
    [ "${trailing_status}" -eq 64 ] || fail "trailing-slash DESTDIR did not return usage status"
    grep -F 'DESTDIR must be an absolute clean path' "${workdir}/trailing-destdir.out" >/dev/null || \
      fail "trailing-slash DESTDIR did not fail in the bootstrap"
    [ -d "${root}/var/lib/cdnca-edge-agent-packaging/transaction" ] || \
      fail "invalid DESTDIR changed the incomplete metadata transaction"
    stale_metadata_pid=$(sed -n 's/^pid=//p' \
      "${root}/var/lib/cdnca-edge-agent-packaging/transaction.owner")
    metadata_lib_staging=${root}/usr/libexec/cdnca-edge-agent/.lib.sh.package-install-${stale_metadata_pid}
    assert_file "${metadata_lib_staging}"
    chmod 0600 "${metadata_lib_staging}"
    upgrade_bundle "${workdir}/v2" >/dev/null
    assert_package_metadata_snapshot "${metadata_snapshot}"
    assert_no_metadata_install_staging
    if "${metadata_package}/scripts/upgrade.sh" \
      --artifact "${workdir}/vbad/edge-agent" \
      --sbom "${workdir}/vbad/edge-agent.spdx.json" \
      --manifest "${workdir}/vbad/manifest" \
      --signature "${workdir}/vbad/manifest.sig" \
      --public-key "${public_key}" \
      --destdir "${root}" --service-driver "${service_driver}" \
      --health-timeout 2 --health-stable 0 >/dev/null 2>&1; then
      fail "mixed-version unhealthy upgrade was accepted"
    fi
    assert_package_metadata_snapshot "${metadata_snapshot}"
    ;;
  restore-staging)
    if CDNCA_PACKAGE_FAILPOINT=state-restore-after-staging \
      "${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
        --version v1 --destdir "${root}" --service-driver "${service_driver}" \
        --health-timeout 2 --health-stable 0 >/dev/null 2>&1; then
      fail "SIGKILL during state restore returned success"
    fi
    [ -d "${root}/var/lib/cdnca-edge-agent-packaging/transaction" ] || \
      fail "SIGKILL rollback did not retain a durable transaction"
    [ -n "$(find "${root}/var/lib/cdnca-edge-agent-backups" -maxdepth 1 -name '.restore-*' -print -quit)" ] || \
      fail "SIGKILL restore did not retain its journal-bound staging"
    "${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
      --version v1 --destdir "${root}" --service-driver "${service_driver}" \
      --health-timeout 2 --health-stable 0 >/dev/null
    assert_no_restore_staging
    install -d -m 0700 "${root}/var/lib/cdnca-edge-agent-backups/.restore-424242"
    "${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
      --destdir "${root}" --service-driver "${service_driver}" >/dev/null
    assert_absent "${root}/var/lib/cdnca-edge-agent-backups/.restore-424242"
    install -d -m 0700 "${root}/var/lib/cdnca-edge-agent-backups/.restore-424243"
    if CDNCA_PACKAGE_FAILPOINT=transaction-before-publish install_bundle "${workdir}/v2" >/dev/null 2>&1; then
      fail "purge transaction staging fixture returned success"
    fi
    [ -n "$(find "${root}/var/lib/cdnca-edge-agent-packaging" -maxdepth 1 -name '.transaction.*' -print -quit)" ] || \
      fail "purge transaction staging fixture was not retained"
    "${packaging_root}/scripts/uninstall.sh" \
      --destdir "${root}" --service-driver "${service_driver}" \
      --purge --non-interactive \
      --confirm-purge DELETE-EDGE-IDENTITY-AND-STATE >/dev/null
    assert_absent "${root}/var/lib/cdnca-edge-agent-backups/.restore-424243"
    ;;
  rollback-interrupt)
    : >"${workdir}/rollback-restart-sigkill"
    if "${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
      --version v1 --destdir "${root}" --service-driver "${service_driver}" \
      --health-timeout 2 --health-stable 0 >/dev/null 2>&1; then
      fail "SIGKILL rollback restart returned success"
    fi
    [ -d "${root}/var/lib/cdnca-edge-agent-packaging/transaction" ] || \
      fail "interrupted rollback did not retain a durable transaction"
    assert_absent "${workdir}/service-active"
    "${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
      --version v1 --destdir "${root}" --service-driver "${service_driver}" \
      --health-timeout 2 --health-stable 0 >/dev/null
    [ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v1 ] || \
      fail "interrupted rollback retry did not select v1"
    [ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = original-state ] || \
      fail "interrupted rollback retry did not restore v1 state"
    assert_file "${workdir}/service-active"
    assert_package_lock_idle
    ;;
  disable-failure)
    unit_digest_before_uninstall=$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")
    accepted_digest_before_uninstall=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
    : >"${workdir}/service-disable-fail"
    if "${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
      --destdir "${root}" --service-driver "${service_driver}" >/dev/null 2>&1; then
      fail "uninstall continued after service disable failed"
    fi
    assert_file "${root}/usr/lib/cdnca-edge-agent/versions/v2/edge-agent"
    [ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || \
      fail "disable failure changed current"
    [ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = "${unit_digest_before_uninstall}" ] || \
      fail "disable failure changed systemd metadata"
    [ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest_before_uninstall}" ] || \
      fail "disable failure changed replay state"
    assert_file "${root}/etc/cdnca-edge-agent/config.json"
    assert_file "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
    assert_package_lock_idle
    ;;
  mounted-subtree)
    layout_base=${workdir}/mounted-layout-base
    cp -a "${root}" "${layout_base}"

    rm -rf -- "${root}"
    cp -a "${layout_base}" "${root}"
    rm -rf -- "${root}/var/lib/cdnca-edge-agent"
    mv "${root}/var/lib/cdnca-edge-agent-backups/active-state" \
      "${root}/var/lib/cdnca-edge-agent"
    sed '/^BindPaths=\/var\/lib\/cdnca-edge-agent-backups\/active-state:/d' \
      "${root}/usr/lib/systemd/system/cdnca-edge-agent.service" >"${workdir}/mounted-legacy-unit"
    install -m 0644 "${workdir}/mounted-legacy-unit" \
      "${root}/usr/lib/systemd/system/cdnca-edge-agent.service"
    : >"${workdir}/service-active"
    legacy_mount=${root}/var/lib/cdnca-edge-agent/external
    mount_tmpfs_fixture "${legacy_mount}"
    printf '%s\n' legacy-external-state >"${legacy_mount}/sentinel"
    legacy_current=$(readlink "${root}/usr/lib/cdnca-edge-agent/current")
    legacy_unit_digest=$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")
    legacy_accepted_digest=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
    service_actions_before=$(wc -l <"${workdir}/service-actions" | tr -d ' ')
    if upgrade_bundle "${workdir}/v3layout" >"${workdir}/legacy-mounted.out" 2>&1; then
      fail "legacy migration accepted mounted state content"
    fi
    grep -F 'legacy agent state crosses a filesystem boundary' \
      "${workdir}/legacy-mounted.out" >/dev/null || \
      fail "legacy migration did not report the mounted state boundary"
    [ "$(sed -n '1p' "${legacy_mount}/sentinel")" = legacy-external-state ] || \
      fail "legacy migration changed external mounted content"
    [ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = "${legacy_current}" ] || \
      fail "mounted legacy state changed current"
    [ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = \
      "${legacy_unit_digest}" ] || fail "mounted legacy state changed the unit"
    [ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = \
      "${legacy_accepted_digest}" ] || fail "mounted legacy state changed replay state"
    [ "$(wc -l <"${workdir}/service-actions" | tr -d ' ')" = "${service_actions_before}" ] || \
      fail "mounted legacy state touched the service"
    assert_absent "${root}/var/lib/cdnca-edge-agent-packaging/layout-migration"
    unmount_fixture "${legacy_mount}"

    rm -rf -- "${root}"
    cp -a "${layout_base}" "${root}"
    : >"${workdir}/service-active"
    package_mount=${root}/usr/lib/cdnca-edge-agent/external
    mount_tmpfs_fixture "${package_mount}"
    printf '%s\n' package-external-content >"${package_mount}/sentinel"
    if "${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
      --destdir "${root}" --service-driver "${service_driver}" \
      >"${workdir}/uninstall-mounted.out" 2>&1; then
      fail "uninstall accepted a mounted package subtree"
    fi
    [ "$(sed -n '1p' "${package_mount}/sentinel")" = package-external-content ] || \
      fail "uninstall deleted external mounted content"
    mountpoint -q -- "${package_mount}" || fail "uninstall detached the external mount"
    unmount_fixture "${package_mount}"
    ;;
  layout-migration)
    layout_base=${workdir}/layout-base
    cp -a "${root}" "${layout_base}"
    reset_legacy_layout() {
      rm -rf -- "${root}"
      cp -a "${layout_base}" "${root}"
      rm -rf -- "${root}/var/lib/cdnca-edge-agent"
      mv "${root}/var/lib/cdnca-edge-agent-backups/active-state" \
        "${root}/var/lib/cdnca-edge-agent"
      sed '/^BindPaths=\/var\/lib\/cdnca-edge-agent-backups\/active-state:/d' \
        "${root}/usr/lib/systemd/system/cdnca-edge-agent.service" >"${workdir}/legacy-unit"
      install -m 0644 "${workdir}/legacy-unit" \
        "${root}/usr/lib/systemd/system/cdnca-edge-agent.service"
      : >"${workdir}/service-active"
    }
    for layout_failpoint in \
      layout-after-prepared \
      layout-after-unit-installed \
      layout-after-state-move-intent \
      layout-after-state-move \
      layout-after-activated; do
      reset_legacy_layout
      if [ "${layout_failpoint}" = layout-after-activated ]; then
        : >"${workdir}/layout-agent-write"
      else
        rm -f -- "${workdir}/layout-agent-write"
      fi
      if CDNCA_PACKAGE_FAILPOINT=${layout_failpoint} \
        upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
        fail "${layout_failpoint} returned success"
      fi
      migration=${root}/var/lib/cdnca-edge-agent-packaging/layout-migration
      [ -d "${migration}" ] && [ ! -L "${migration}" ] || fail "${layout_failpoint} did not retain migration journal"
      [ "$(stat -c '%u:%g:%a' "${migration}")" = 0:0:700 ] || fail "migration journal directory policy"
      [ "$(stat -c '%u:%g:%a:%h' "${migration}/journal")" = 0:0:600:1 ] || fail "migration journal file policy"
      [ "$(stat -c '%u:%g:%a:%h' "${migration}/old-unit")" = 0:0:600:1 ] || fail "old unit snapshot policy"
      case "${layout_failpoint}" in
        layout-after-prepared) expected_phase=prepared ;;
        layout-after-unit-installed) expected_phase=unit_installed ;;
        layout-after-state-move-intent|layout-after-state-move) expected_phase=state_move_intent ;;
        layout-after-activated) expected_phase=activated ;;
      esac
      [ "$(sed -n 's/^phase=//p' "${migration}/journal")" = "${expected_phase}" ] || \
        fail "${layout_failpoint} retained the wrong phase"
      upgrade_bundle "${workdir}/v3layout" >/dev/null
      [ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v3layout ] || \
        fail "${layout_failpoint} recovery did not complete the upgrade"
      assert_completed_state_layout
      grep -F 'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind' \
        "${root}/usr/lib/systemd/system/cdnca-edge-agent.service" >/dev/null || \
        fail "${layout_failpoint} recovery did not install the bind-aware unit"
      assert_package_lock_idle
    done
    rm -f -- "${workdir}/layout-agent-write"

    reset_legacy_layout
    if CDNCA_PACKAGE_FAILPOINT=layout-after-state-move \
      upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "revert-intent migration fixture returned success"
    fi
    if CDNCA_PACKAGE_FAILPOINT=layout-after-revert-intent \
      upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "SIGKILL after revert intent returned success"
    fi
    migration=${root}/var/lib/cdnca-edge-agent-packaging/layout-migration
    [ "$(sed -n 's/^phase=//p' "${migration}/journal")" = revert_intent ] || \
      fail "revert-intent SIGKILL did not retain its phase"
    upgrade_bundle "${workdir}/v3layout" >/dev/null
    assert_completed_state_layout

    reset_legacy_layout
    if CDNCA_PACKAGE_FAILPOINT=layout-after-prepared \
      upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "double-missing migration fixture returned success"
    fi
    migration=${root}/var/lib/cdnca-edge-agent-packaging/layout-migration
    mv "${root}/var/lib/cdnca-edge-agent" "${workdir}/recorded-state"
    if upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "double-missing migration state was accepted"
    fi
    [ -d "${migration}" ] || fail "double-missing migration journal was removed"
    cp -a "${workdir}/recorded-state" "${root}/var/lib/cdnca-edge-agent"
    if upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "state inode mismatch was accepted"
    fi
    [ -d "${migration}" ] || fail "inode-mismatch migration journal was removed"
    rm -rf -- "${root}/var/lib/cdnca-edge-agent"
    mv "${workdir}/recorded-state" "${root}/var/lib/cdnca-edge-agent"
    upgrade_bundle "${workdir}/v3layout" >/dev/null
    assert_completed_state_layout

    reset_legacy_layout
    if CDNCA_PACKAGE_FAILPOINT=layout-after-state-move \
      upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "double-present migration fixture returned success"
    fi
    cp -a "${root}/var/lib/cdnca-edge-agent-backups/active-state" \
      "${root}/var/lib/cdnca-edge-agent"
    if upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "double-present migration state was accepted"
    fi
    [ -d "${migration}" ] || fail "double-present migration journal was removed"
    rm -rf -- "${root}/var/lib/cdnca-edge-agent"
    upgrade_bundle "${workdir}/v3layout" >/dev/null
    assert_completed_state_layout

    reset_legacy_layout
    if CDNCA_PACKAGE_FAILPOINT=layout-after-state-move-intent \
      upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "tree-mismatch migration fixture returned success"
    fi
    printf '%s\n' changed-after-intent >"${root}/var/lib/cdnca-edge-agent/state.txt"
    chown "${staged_uid}:${staged_gid}" "${root}/var/lib/cdnca-edge-agent/state.txt"
    if upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "state tree mismatch was accepted"
    fi
    [ -d "${migration}" ] || fail "tree-mismatch migration journal was removed"
    printf '%s\n' original-state >"${root}/var/lib/cdnca-edge-agent/state.txt"
    chown "${staged_uid}:${staged_gid}" "${root}/var/lib/cdnca-edge-agent/state.txt"
    upgrade_bundle "${workdir}/v3layout" >/dev/null
    assert_completed_state_layout

    reset_legacy_layout
    ln -s /etc/passwd "${root}/var/lib/cdnca-edge-agent/rejected-link"
    legacy_unit_digest=$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")
    service_actions_before=$(wc -l <"${workdir}/service-actions" | tr -d ' ')
    if upgrade_bundle "${workdir}/v3layout" >/dev/null 2>&1; then
      fail "unsafe legacy state tree was accepted"
    fi
    [ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = "${legacy_unit_digest}" ] || \
      fail "unsafe legacy state changed the unit"
    [ "$(wc -l <"${workdir}/service-actions" | tr -d ' ')" = "${service_actions_before}" ] || \
      fail "unsafe legacy state touched the service"
    assert_absent "${root}/var/lib/cdnca-edge-agent-packaging/layout-migration"
    if "${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
      --destdir "${root}" --service-driver "${service_driver}" >/dev/null 2>&1; then
      fail "unsafe legacy state tree was accepted by uninstall"
    fi
    assert_file "${root}/usr/lib/cdnca-edge-agent/versions/v2/edge-agent"
    rm -f -- "${root}/var/lib/cdnca-edge-agent/rejected-link"
    : >"${workdir}/service-active"
    "${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
      --destdir "${root}" --service-driver "${service_driver}" >/dev/null
    assert_absent "${root}/usr/lib/cdnca-edge-agent"
    assert_file "${root}/var/lib/cdnca-edge-agent/state.txt"
    assert_absent "${root}/var/lib/cdnca-edge-agent-backups/active-state"
    ;;
esac
if [ -n "${regression_case}" ]; then
  printf 'edge-agent packaging isolated regression passed: %s\n' "${regression_case}"
  exit 0
fi

# A kill after the transaction snapshot is durable but before it is published
# leaves only the stale PID staging. The next holder removes that exact tree.
if CDNCA_PACKAGE_FAILPOINT=transaction-before-publish upgrade_bundle "${workdir}/vtransaction" >/dev/null 2>&1; then
  fail "SIGKILL before transaction publish returned success"
fi
assert_absent "${root}/var/lib/cdnca-edge-agent-packaging/transaction"
[ -n "$(find "${root}/var/lib/cdnca-edge-agent-packaging" -maxdepth 1 -name '.transaction.*' -print -quit)" ] || \
  fail "transaction pre-publish SIGKILL did not retain staging"
upgrade_bundle "${workdir}/v2" >/dev/null
assert_no_transaction_staging
assert_package_lock_idle

# A kill after the version directory rename but before later probes leaves the
# pre-recorded cleanup intent in the journal.
if CDNCA_PACKAGE_FAILPOINT=after-release-install upgrade_bundle "${workdir}/vreleasekill" >/dev/null 2>&1; then
  fail "SIGKILL after release install returned success"
fi
assert_file "${root}/usr/lib/cdnca-edge-agent/versions/vreleasekill/edge-agent"
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "release-install SIGKILL changed current"
upgrade_bundle "${workdir}/v2" >/dev/null
assert_absent "${root}/usr/lib/cdnca-edge-agent/versions/vreleasekill"
assert_package_lock_idle
assert_no_bundle_staging

# SIGKILL after current switches leaves a durable transaction. The next
# idempotent run recovers v2 state/unit/current before proceeding.
printf '%s\n' v2-state >"${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
unit_digest_before_kill=$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")
accepted_digest_before_kill=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
if CDNCA_PACKAGE_FAILPOINT=after-current-switch upgrade_bundle "${workdir}/vkill" >/dev/null 2>&1; then
  fail "SIGKILL after current switch returned success"
fi
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/vkill ] || fail "SIGKILL fixture did not switch current"
assert_file "${root}/var/lib/cdnca-edge-agent-packaging/transaction.owner"
[ -d "${root}/var/lib/cdnca-edge-agent-packaging/transaction" ] || fail "SIGKILL did not retain transaction journal"
upgrade_bundle "${workdir}/v2" >/dev/null
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "stale transaction recovery did not restore v2"
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = v2-state ] || fail "stale transaction recovery did not restore v2 state"
[ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = "${unit_digest_before_kill}" ] || fail "stale transaction recovery did not restore the unit"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest_before_kill}" ] || fail "stale transaction recovery advanced replay state"
assert_absent "${root}/usr/lib/cdnca-edge-agent/versions/vkill"
assert_package_lock_idle
assert_no_bundle_staging

# A legacy v1 journal cannot prove recovery of the complete metadata set. New
# maintainers fail closed and retain it for an audited manual recovery.
if CDNCA_PACKAGE_FAILPOINT=after-release-install upgrade_bundle "${workdir}/vlegacy" >/dev/null 2>&1; then
  fail "legacy transaction fixture returned success"
fi
transaction_dir=${root}/var/lib/cdnca-edge-agent-packaging/transaction
cp -a "${transaction_dir}/journal" "${workdir}/v2-journal"
cp -a "${transaction_dir}/metadata" "${workdir}/v2-metadata"
cp -a "${root}/var/lib/cdnca-edge-agent-packaging/transaction.owner" "${workdir}/v2-owner"
sed -i '1s/transaction_version=2/transaction_version=1/;$d' "${transaction_dir}/journal"
rm -rf -- "${transaction_dir}/metadata"
if upgrade_bundle "${workdir}/v2" >/dev/null 2>&1; then
  fail "legacy v1 transaction was silently accepted"
fi
[ -d "${transaction_dir}" ] || fail "legacy v1 transaction was not retained"
assert_file "${root}/usr/lib/cdnca-edge-agent/versions/vlegacy/edge-agent"
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "legacy transaction rejection changed current"
install -m 0600 "${workdir}/v2-journal" "${transaction_dir}/journal"
cp -a "${workdir}/v2-metadata" "${transaction_dir}/metadata"
install -m 0600 "${workdir}/v2-owner" "${root}/var/lib/cdnca-edge-agent-packaging/transaction.owner"
upgrade_bundle "${workdir}/v2" >/dev/null
assert_absent "${root}/usr/lib/cdnca-edge-agent/versions/vlegacy"
assert_package_lock_idle
assert_no_bundle_staging

# Incompatible protocol minima and an older signed release are rejected before writes.
metadata_digest=$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")
accepted_digest=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
service_actions_before=$(wc -l <"${workdir}/service-actions" | tr -d ' ')
for rejected in protocol-control protocol-agent same-sequence v1; do
  if upgrade_bundle "${workdir}/${rejected}" >/dev/null 2>&1; then
    fail "${rejected} compatibility or replay rejection was bypassed"
  fi
done
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "compatibility or replay rejection changed current"
[ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = "${metadata_digest}" ] || fail "compatibility or replay rejection changed metadata"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest}" ] || fail "compatibility or replay rejection changed replay state"
[ "$(wc -l <"${workdir}/service-actions" | tr -d ' ')" = "${service_actions_before}" ] || fail "compatibility or replay rejection touched the service"
assert_package_lock_idle
assert_no_bundle_staging

# Failures before current or accepted-manifest commit restore every published pointer.
printf '%s\n' v2-state >"${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
accepted_digest=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
last_backup_before_failure=$(readlink "${root}/var/lib/cdnca-edge-agent-backups/last-upgrade")
if CDNCA_PACKAGE_FAILPOINT=current-commit upgrade_bundle "${workdir}/vcurrent-fail" >/dev/null 2>&1; then
  fail "current commit failpoint was accepted"
fi
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "current failpoint advanced current"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest}" ] || fail "current failpoint advanced replay state"
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = v2-state ] || fail "current failpoint changed state"
[ "$(readlink "${root}/var/lib/cdnca-edge-agent-backups/last-upgrade")" = "${last_backup_before_failure}" ] || fail "current failpoint changed recovery point"
assert_absent "${root}/usr/lib/cdnca-edge-agent/versions/vcurrent-fail"
assert_no_restore_staging

if CDNCA_PACKAGE_FAILPOINT=accepted-manifest-commit upgrade_bundle "${workdir}/vaccepted-fail" >/dev/null 2>&1; then
  fail "accepted manifest commit failpoint was accepted"
fi
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "accepted manifest failpoint advanced current"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest}" ] || fail "accepted manifest failpoint advanced replay state"
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = v2-state ] || fail "accepted manifest failpoint changed state"
[ "$(readlink "${root}/var/lib/cdnca-edge-agent-backups/last-upgrade")" = "${last_backup_before_failure}" ] || fail "accepted manifest failpoint changed recovery point"
assert_absent "${root}/usr/lib/cdnca-edge-agent/versions/vaccepted-fail"
assert_no_restore_staging

# Health failure restores both v2 and its pre-upgrade state, and removes vbad.
printf '%s\n' v2-state >"${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
accepted_digest=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
installed_unit_digest=$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")
unit_asset=${root}/usr/libexec/cdnca-edge-agent/assets/systemd/cdnca-edge-agent.service
cp "${unit_asset}" "${workdir}/unit-asset-before-failed-upgrade"
printf '%s\n' '# unhealthy upgrade metadata fixture' >>"${unit_asset}"
if upgrade_bundle "${workdir}/vbad" >/dev/null 2>&1; then
  fail "unhealthy upgrade was accepted"
fi
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "health failure did not restore v2"
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = v2-state ] || fail "health failure did not restore state"
assert_absent "${root}/var/lib/cdnca-edge-agent-backups/active-state/release-created-link"
assert_absent "${root}/var/lib/cdnca-edge-agent-backups/active-state/release-created-fifo"
[ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = "${installed_unit_digest}" ] || fail "health failure did not restore the installed unit"
install -m 0644 "${workdir}/unit-asset-before-failed-upgrade" "${unit_asset}"
assert_absent "${root}/usr/lib/cdnca-edge-agent/versions/vbad"
[ "$(readlink "${root}/var/lib/cdnca-edge-agent-backups/last-upgrade")" = "${last_backup}" ] || fail "failed upgrade replaced recovery point"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest}" ] || fail "failed upgrade advanced replay state"
assert_package_lock_idle
assert_no_bundle_staging

# Restore copy failure and interruption preserve current, accepted sequence, and state.
for restore_failpoint in state-copy state-restore-interrupt; do
  if CDNCA_PACKAGE_FAILPOINT=${restore_failpoint} \
    "${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
      --version v1 \
      --destdir "${root}" \
      --service-driver "${service_driver}" \
      --health-timeout 2 \
      --health-stable 0 >/dev/null 2>&1; then
    fail "${restore_failpoint} rollback was accepted"
  fi
  [ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "${restore_failpoint} changed current"
  [ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = v2-state ] || fail "${restore_failpoint} changed state"
  [ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest}" ] || fail "${restore_failpoint} changed replay state"
  assert_no_restore_staging
done

# Unsafe content in the selected backup is rejected before rollback mutation.
ln -s /etc/passwd "${root}/var/lib/cdnca-edge-agent-backups/${last_backup}/state/rejected-link"
if "${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
  --version v1 --destdir "${root}" --service-driver "${service_driver}" >/dev/null 2>&1; then
  fail "state backup symlink was accepted"
fi
rm -f -- "${root}/var/lib/cdnca-edge-agent-backups/${last_backup}/state/rejected-link"
mkfifo "${root}/var/lib/cdnca-edge-agent-backups/${last_backup}/state/rejected-fifo"
if "${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
  --version v1 --destdir "${root}" --service-driver "${service_driver}" >/dev/null 2>&1; then
  fail "state backup special file was accepted"
fi
rm -f -- "${root}/var/lib/cdnca-edge-agent-backups/${last_backup}/state/rejected-fifo"
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "unsafe backup changed current"
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = v2-state ] || fail "unsafe backup changed state"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest}" ] || fail "unsafe backup changed replay state"

# Explicit rollback selects v1, restores its matching state, and is idempotent.
"${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
  --version v1 \
  --destdir "${root}" \
  --service-driver "${service_driver}" \
  --health-timeout 2 \
  --health-stable 0 >/dev/null
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v1 ] || fail "explicit rollback did not select v1"
[ "$(sed -n '1p' "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = original-state ] || fail "explicit rollback did not restore v1 state"
"${root}/usr/libexec/cdnca-edge-agent/rollback.sh" \
  --version v1 --destdir "${root}" --service-driver "${service_driver}" >/dev/null

# A stop failure is fail-closed: no package metadata or retained data is
# removed before the service driver confirms the service is stopped.
unit_digest_before_uninstall=$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")
accepted_digest_before_uninstall=$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")
: >"${workdir}/service-stop-fail"
if "${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
  --destdir "${root}" --service-driver "${service_driver}" >/dev/null 2>&1; then
  fail "uninstall continued after service stop failed"
fi
assert_file "${root}/usr/lib/cdnca-edge-agent/versions/v1/edge-agent"
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v1 ] || fail "failed uninstall changed current"
[ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = "${unit_digest_before_uninstall}" ] || fail "failed uninstall changed systemd metadata"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest_before_uninstall}" ] || fail "failed uninstall changed replay state"
assert_file "${root}/etc/cdnca-edge-agent/config.json"
assert_file "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
assert_package_lock_idle
rm -f -- "${workdir}/service-stop-fail"

# A disable failure is also fail-closed, even after stop succeeded.
: >"${workdir}/service-disable-fail"
if "${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
  --destdir "${root}" --service-driver "${service_driver}" >/dev/null 2>&1; then
  fail "uninstall continued after service disable failed"
fi
assert_file "${root}/usr/lib/cdnca-edge-agent/versions/v1/edge-agent"
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v1 ] || fail "disable failure changed current"
[ "$(sha256_file "${root}/usr/lib/systemd/system/cdnca-edge-agent.service")" = "${unit_digest_before_uninstall}" ] || fail "disable failure changed systemd metadata"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest")" = "${accepted_digest_before_uninstall}" ] || fail "disable failure changed replay state"
assert_file "${root}/etc/cdnca-edge-agent/config.json"
assert_file "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
assert_package_lock_idle
rm -f -- "${workdir}/service-disable-fail"

# Default uninstall retains identity and state.
"${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" --destdir "${root}" --service-driver "${service_driver}" >/dev/null
assert_absent "${root}/usr/lib/cdnca-edge-agent"
assert_file "${root}/etc/cdnca-edge-agent/config.json"
assert_file "${root}/etc/cdnca-edge-agent/identity/private.key"
assert_file "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt"
assert_file "${root}/var/lib/cdnca-edge-agent-backups/${last_backup}/state/state.txt"
assert_file "${root}/var/lib/cdnca-edge-agent-packaging/accepted-manifest"

# Reinstalling after a default uninstall reuses the retained canonical state.
retained_state_before_reinstall=$(sha256_file "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")
install_bundle "${workdir}/v2" >/dev/null
[ "$(readlink "${root}/usr/lib/cdnca-edge-agent/current")" = versions/v2 ] || fail "reinstall after uninstall did not select v2"
[ "$(sha256_file "${root}/var/lib/cdnca-edge-agent-backups/active-state/state.txt")" = "${retained_state_before_reinstall}" ] || \
  fail "reinstall after uninstall changed retained state"
assert_completed_state_layout

# Purge requires its second, non-interactive guard and then removes retained data.
if "${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
  --destdir "${root}" --service-driver "${service_driver}" \
  --purge --non-interactive >/dev/null 2>&1; then
  fail "unguarded non-interactive purge was accepted"
fi
assert_file "${root}/etc/cdnca-edge-agent/config.json"
"${root}/usr/libexec/cdnca-edge-agent/uninstall.sh" \
  --destdir "${root}" --service-driver "${service_driver}" \
  --purge --non-interactive --confirm-purge DELETE-EDGE-IDENTITY-AND-STATE >/dev/null
assert_absent "${root}/etc/cdnca-edge-agent"
assert_absent "${root}/var/lib/cdnca-edge-agent"
assert_absent "${root}/var/lib/cdnca-edge"
assert_absent "${root}/var/lib/cdnca-edge-agent-backups"
assert_absent "${root}/var/lib/cdnca-edge-agent-packaging"

distro_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
distro_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
printf 'edge-agent packaging smoke passed on %s %s\n' "${distro_id}" "${distro_version}"
