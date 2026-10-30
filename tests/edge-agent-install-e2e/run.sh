#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
mode=${1:-all}
case "${mode}" in all|static) ;; *) printf 'usage: %s [all|static]\n' "$0" >&2; exit 64 ;; esac
packaging=${root}/agents/edge-agent/packaging
lib=${packaging}/scripts/lib.sh
install_script=${packaging}/scripts/install.sh
unit=${packaging}/systemd/cdnca-edge-agent.service
helper_unit=${packaging}/systemd/cdnca-edge-agent-helper.service

fail() {
  printf 'edge-agent install static contract failed: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  needle=$1
  file=$2
  grep -F -- "${needle}" "${file}" >/dev/null || fail "${file} lacks: ${needle}"
}

assert_reason() {
  expected=$1
  shift
  output=$(sh -c '. "$1"; shift; validate_supported_host_facts "$@"' sh "${lib}" "$@" 2>&1) &&
    fail "invalid host facts unexpectedly passed: ${expected}"
  printf '%s\n' "${output}" | grep -F "reason_code=${expected}" >/dev/null ||
    fail "host facts lacked ${expected}: ${output}"
}

# This static driver is architecture-independent. Real Debian/Ubuntu systemd
# execution remains a separate, explicit infrastructure gate.
sh -c '. "$1"; validate_supported_host_facts debian 12 6.1.0 252 unified' sh "${lib}"
sh -c '. "$1"; validate_supported_host_facts ubuntu 24.04 6.8.0 255 unified' sh "${lib}"
sh -c '. "$1"; validate_supported_host_facts ubuntu 22.04 5.15.0 249 unified' sh "${lib}"
sh -c '. "$1"; validate_supported_host_facts debian 13 6.12.0 257 unified' sh "${lib}"
sh -c '. "$1"; validate_supported_host_facts rocky 9.4 5.14.0 252 unified' sh "${lib}"
sh -c '. "$1"; validate_supported_host_facts almalinux 10.0 6.12.0 257 unified' sh "${lib}"
sh -c '. "$1"; validate_supported_host_facts rhel 9 5.14.0 252 unified' sh "${lib}"
assert_reason HOST_UNSUPPORTED_DISTRIBUTION debian 11 6.1.0 252 unified
assert_reason HOST_UNSUPPORTED_DISTRIBUTION ubuntu 20.04 5.15.0 245 unified
assert_reason HOST_UNSUPPORTED_DISTRIBUTION rocky 8.9 5.14.0 239 unified
assert_reason HOST_UNSUPPORTED_DISTRIBUTION centos 7 5.14.0 219 unified
assert_reason HOST_SYSTEMD_TOO_OLD rocky 9.4 5.14.0 251 unified
sh -c '. "$1"; validate_supported_host_facts debian 12 5.4.0 252 unified' sh "${lib}"
sh -c '. "$1"; validate_supported_host_facts ubuntu 24.04 6.8.0 255 legacy' sh "${lib}"
output=$(sh -c '. "$1"; host_pidfd_supported() { return 1; }; validate_supported_host_facts debian 12 4.19.0 252 unified' sh "${lib}" 2>&1) &&
  fail 'a kernel without pidfd unexpectedly passed'
printf '%s\n' "${output}" | grep -F 'reason_code=HOST_KERNEL_TOO_OLD' >/dev/null || fail "pidfd-less kernel lacked HOST_KERNEL_TOO_OLD: ${output}"
sh -c '. "$1"; host_pidfd_supported() { return 0; }; validate_supported_host_facts debian 12 4.18.0 252 unified' sh "${lib}" ||
  fail 'a backported pidfd kernel was rejected'
assert_reason HOST_SYSTEMD_TOO_OLD ubuntu 24.04 6.8.0 254 unified
assert_reason HOST_CGROUP_MODE_UNKNOWN ubuntu 24.04 6.8.0 255 hybrid-unknown

dependencies=$(sh -c '. "$1"; required_host_commands' sh "${lib}")
for dependency in awk cmp date env find flock getent install jq perl readlink sed setpriv sha256sum stat sync systemctl systemd-sysusers systemd-tmpfiles; do
  printf '%s\n' "${dependencies}" | grep -Fx "${dependency}" >/dev/null ||
    fail "dependency preflight omits ${dependency}"
done

preflight_line=$(grep -n '^require_supported_host$' "${install_script}" | sed -n '1s/:.*//p')
lock_line=$(grep -n '^acquire_lock$' "${install_script}" | sed -n '1s/:.*//p')
[ -n "${preflight_line}" ] && [ -n "${lock_line}" ] && [ "${preflight_line}" -lt "${lock_line}" ] ||
  fail 'host preflight must precede the packaging lock and all mutation'

assert_contains 'reason_code=COMPAT_CONTROL_PROTOCOL_TOO_OLD' "${lib}"
assert_contains 'reason_code=COMPAT_AGENT_PROTOCOL_TOO_OLD' "${lib}"
assert_contains 'reason_code=COMPAT_RELEASE_SEQUENCE_REPLAY' "${lib}"
# Native nodes verify with the pinned static Ed25519 tool; OpenSSL 3 is only
# the fallback for hosts installed without it (Debian package path).
assert_contains 'ED25519_TOOL_PATH=/usr/libexec/cdnca-ed25519' "${lib}"
assert_contains '"${ED25519_TOOL_PATH}" verify "${public_key}" "${manifest}" "${signature}"' "${lib}"
assert_contains 'openssl pkeyutl -verify' "${lib}"
assert_contains 'artifact SHA-256 verification failed' "${lib}"
assert_contains 'SBOM SHA-256 verification failed' "${lib}"
assert_contains 'rollback_package_transaction' "${lib}"
assert_contains 'publish_last_upgrade_backup' "${lib}"
assert_contains 'Default uninstall retains configuration, identity, state, backups, logs' "${packaging}/README.md"

runtime_driver=${root}/tests/edge-agent-install-e2e/inside-systemd.sh
runtime_dockerfile=${root}/tests/edge-agent-install-e2e/Dockerfile
image_lock=${root}/tests/edge-linux/images.env
[ -f "${runtime_driver}" ] && [ ! -L "${runtime_driver}" ] ||
  fail 'real distribution lifecycle driver is missing'
[ -f "${runtime_dockerfile}" ] && [ ! -L "${runtime_dockerfile}" ] ||
  fail 'real distribution systemd image is missing'
for contract in \
  'debian12:debian:12:252' \
  'ubuntu2404:ubuntu:24.04:255' \
  'linux/amd64' \
  'linux/arm64' \
  '--privileged' \
  '--cgroupns=private' \
  'apt-get install' \
  'cdnca-edge-agent=1.0.0-1' \
  'cdnca-edge-agent=1.1.0-1' \
  'cdnca-edge-agent=1.2.0-1' \
  'systemctl enable --now cdnca-edge-agent.service' \
  'systemctl is-enabled cdnca-edge-agent.service' \
  'systemctl show -p MainPID' \
  'id -u cdnca-edge' \
  'release_sequence=2' \
  'repository.provenance.json' \
  'sha256sum'; do
  grep -R -F -- "${contract}" "$0" "${runtime_driver}" "${runtime_dockerfile}" "${image_lock}" >/dev/null ||
    fail "real matrix contract is missing: ${contract}"
done
for rollback_contract in \
  'bad-package-signature' \
  'bad-configuration' \
  'unhealthy-release' \
  'docker restart'; do
  grep -R -F -- "${rollback_contract}" "$0" "${runtime_driver}" >/dev/null ||
    fail "real rollback/restart contract is missing: ${rollback_contract}"
done

for directive in \
  'User=cdnca-edge' \
  'NoNewPrivileges=yes' \
  'ProtectSystem=strict' \
  'CapabilityBoundingSet=' \
  'AmbientCapabilities=' \
  'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX' \
  'WantedBy=multi-user.target'; do
  assert_contains "${directive}" "${unit}"
done
for directive in \
  'User=root' \
  'PrivateNetwork=yes' \
  'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID' \
  'RestrictAddressFamilies=AF_UNIX'; do
  assert_contains "${directive}" "${helper_unit}"
done

if grep -R -E 'curl[^#|]*\|[[:space:]]*(ba)?sh|wget[^#|]*\|[[:space:]]*(ba)?sh' \
  "${packaging}/scripts" "${packaging}/deb" >/dev/null; then
  fail 'network pipe-to-shell installation is forbidden'
fi

printf 'EDGE_AGENT_INSTALL_E2E_STATIC PASS\n'

[ "${mode}" = all ] || exit 0

command -v docker >/dev/null 2>&1 || fail 'docker is required for the real distribution matrix'
docker info >/dev/null 2>&1 || fail 'docker daemon is unavailable'
command -v jq >/dev/null 2>&1 || fail 'jq is required for repository evidence'
command -v shellcheck >/dev/null 2>&1 || fail 'shellcheck is required for the grouped gate'

task_id=cdnca-ops11-$$
task_label=cdnca.task=${task_id}
tmp_base=${TMPDIR:-/tmp}
workdir=$(mktemp -d "${tmp_base%/}/cdnca-ops11-install.XXXXXX")
chmod 0755 "${workdir}"
owned_containers=
owned_images=

cleanup_owned() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM
  set +e
  for container in ${owned_containers}; do
    docker rm -f "${container}" >/dev/null 2>&1 || true
  done
  for image in ${owned_images}; do
    docker image rm -f "${image}" >/dev/null 2>&1 || true
  done
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-ops11-install.*) rm -rf -- "${workdir}" ;;
    *) printf 'refusing to clean unexpected OPS-11 path: %s\n' "${workdir}" >&2; cleanup_status=1 ;;
  esac
  exit "${cleanup_status}"
}
trap cleanup_owned EXIT HUP INT TERM

shellcheck -x \
  "${root}"/agents/edge-agent/packaging/scripts/*.sh \
  "${root}"/agents/edge-agent/packaging/deb/build-repository.sh \
  "${root}"/agents/edge-agent/packaging/tests/deb_repository_test.sh \
  "${root}"/scripts/package-edge-agent-deb.sh \
  "${root}"/tests/edge-agent-install-e2e/run.sh \
  "${runtime_driver}"
sh -n \
  "${root}"/agents/edge-agent/packaging/scripts/*.sh \
  "${root}"/agents/edge-agent/packaging/deb/build-repository.sh \
  "${root}"/agents/edge-agent/packaging/tests/deb_repository_test.sh \
  "${root}"/tests/edge-agent-install-e2e/run.sh \
  "${runtime_driver}"

builder=$(jq -er '.builder.image' "${packaging}/build/contract.json")
case "${builder}" in docker.io/library/golang:1.27.3-bookworm@sha256:*) ;; *) fail 'release builder is not digest pinned' ;; esac
builder_container=${task_id}-repository-builder
owned_containers="${owned_containers} ${builder_container}"
docker run --rm --name "${builder_container}" --label "${task_label}" \
  -e DEBIAN_FRONTEND=noninteractive \
  -v "${root}:/workspace:ro" -v "${workdir}:/output:rw" -w /workspace \
  "${builder}" sh -c '
    set -eu
    apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 -o Acquire::http::Timeout=20 update -qq
    apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 -o Acquire::http::Timeout=20 \
      install -y -qq gnupg gzip jq perl >/dev/null
    agents/edge-agent/packaging/tests/deb_repository_test.sh build /output/repository
  '

repository=${workdir}/repository
provenance=${repository}/repository.provenance.json
jq -e '
  .schema == "cdnca.edge.apt-repository-provenance/v1" and
  ([.packages[].arch] | sort | unique) == ["amd64", "arm64"] and
  ([.packages[].version] | sort | unique) == ["1.0.0", "1.1.0", "1.2.0"] and
  (.packages | length) == 6 and
  all(.packages[]; (.sha256 | test("^[0-9a-f]{64}$")))
' "${provenance}" >/dev/null || fail 'repository lacks the exact signed dual-architecture release set'
for relative in $(jq -er '.packages[].path' "${provenance}"); do
  expected=$(jq -er --arg path "${relative}" '.packages[] | select(.path == $path) | .sha256' "${provenance}")
  actual=$(sha256sum "${repository}/${relative}" | awk '{print $1}')
  [ "${actual}" = "${expected}" ] || fail "repository package digest mismatch: ${relative}"
done

# shellcheck source=tests/edge-linux/images.env
. "${image_lock}"
for platform in linux/amd64 linux/arm64; do
  arch=${platform#linux/}
  for specification in \
    "debian12:debian:12:252:${DEBIAN_12_IMAGE}" \
    "ubuntu2404:ubuntu:24.04:255:${UBUNTU_24_IMAGE}"; do
    distro=${specification%%:*}
    remainder=${specification#*:}
    expected_id=${remainder%%:*}
    remainder=${remainder#*:}
    expected_version=${remainder%%:*}
    remainder=${remainder#*:}
    expected_systemd=${remainder%%:*}
    distro_image=${remainder#*:}
    image=${task_id}-${distro}-${arch}:systemd
    container=${task_id}-${distro}-${arch}
    owned_images="${owned_images} ${image}"
    owned_containers="${owned_containers} ${container}"

    printf 'OPS-11 build distro=%s id=%s version=%s systemd=%s platform=%s base=%s\n' \
      "${distro}" "${expected_id}" "${expected_version}" "${expected_systemd}" "${platform}" "${distro_image}"
    docker build --pull=false --provenance=false --platform "${platform}" \
      --label "${task_label}" \
      --build-arg "DISTRO_IMAGE=${distro_image}" \
      --build-arg "APT_PACKAGES=${APT_PACKAGES}" \
      --build-arg "APT_PACKAGES_SHA256=${APT_PACKAGES_SHA256}" \
      --build-arg "APT_SNAPSHOT=${APT_SNAPSHOT}" \
      --build-arg "EXPECTED_SYSTEMD=${expected_systemd}" \
      --file "${runtime_dockerfile}" --tag "${image}" "${root}"
    image_id=$(docker image inspect "${image}" --format '{{.Id}}')
    printf '%s\n' "${image_id}" | grep -E '^sha256:[0-9a-f]{64}$' >/dev/null ||
      fail 'derived systemd image lacks a fixed local digest'

    docker run --detach --platform "${platform}" \
      --name "${container}" --label "${task_label}" \
      --privileged --cgroupns=private \
      --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
      --volume "${root}:/workspace:ro" --volume "${repository}:/repository:ro" \
      "${image}" >/dev/null

    attempt=0
    system_state=unknown
    while [ "${attempt}" -lt 120 ]; do
      system_state=$(docker exec "${container}" systemctl is-system-running 2>/dev/null || true)
      case "${system_state}" in running|degraded) break ;; esac
      attempt=$((attempt + 1))
      sleep 0.25
    done
    case "${system_state}" in running|degraded) ;; *) docker logs "${container}" >&2; fail "${distro}/${arch} systemd did not start" ;; esac

    docker exec "${container}" sh /workspace/tests/edge-agent-install-e2e/inside-systemd.sh "${distro}" "${arch}" initial
    docker restart --time 20 "${container}" >/dev/null
    docker exec "${container}" sh /workspace/tests/edge-agent-install-e2e/inside-systemd.sh "${distro}" "${arch}" post-restart
    printf 'OPS11_MATRIX PASS distro=%s arch=%s systemd=%s image=%s restart=true\n' \
      "${distro}" "${arch}" "${expected_systemd}" "${image_id}"

    docker stop --time 20 "${container}" >/dev/null
    docker rm "${container}" >/dev/null
    docker image rm "${image}" >/dev/null
  done
done

owned_containers=
owned_images=
[ -z "$(docker ps -aq --filter "label=${task_label}")" ] || fail 'task-owned containers remain'
[ -z "$(docker image ls -q --filter "label=${task_label}")" ] || fail 'task-owned images remain'
[ -z "$(docker network ls -q --filter "label=${task_label}")" ] || fail 'task-owned networks remain'
[ -z "$(docker volume ls -q --filter "label=${task_label}")" ] || fail 'task-owned volumes remain'
owned_processes=$(ps -axo ppid=,command= | CDNCA_TASK_MARKER="${task_id}" \
  awk 'index($0, ENVIRON["CDNCA_TASK_MARKER"]) {count++} END {print count+0}')
[ "${owned_processes}" -eq 0 ] || fail 'task-owned processes remain'

case "${workdir}" in "${tmp_base%/}"/cdnca-ops11-install.*) rm -rf -- "${workdir}" ;; *) fail 'unsafe final workdir' ;; esac
workdir=${tmp_base%/}/cdnca-ops11-install.cleaned
printf 'OPS11_GROUPED_GATE PASS distros=debian12,ubuntu2404 architectures=amd64,arm64 rollback=bad-package-signature,bad-configuration,unhealthy-release restart=true\n'
printf 'OPS11_RESOURCES containers=0 images=0 networks=0 volumes=0 processes=0 listeners=0 ppid1=0 temp=0\n'
trap - EXIT HUP INT TERM
