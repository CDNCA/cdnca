#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
mode=${1:-all}
only_distro=${2:-}
task_id=cdnca-ops11-$$
task_label=cdnca.task=${task_id}
workdir=
builder_container=${task_id}-builder
debian_container=${task_id}-debian12
ubuntu_container=${task_id}-ubuntu2404
case "${mode}" in
  all|lint|containers) ;;
  *) printf 'usage: %s [all|lint|containers [debian12|ubuntu2404]]\n' "$0" >&2; exit 64 ;;
esac
case "${mode}:${only_distro}" in
  *:|containers:debian12|containers:ubuntu2404) ;;
  *) printf 'usage: %s [all|lint|containers [debian12|ubuntu2404]]\n' "$0" >&2; exit 64 ;;
esac

cleanup() {
  docker rm -f "${builder_container}" "${debian_container}" "${ubuntu_container}" >/dev/null 2>&1 || true
  if [ -n "${workdir}" ] && [ -d "${workdir}" ]; then
    rm -rf -- "${workdir}"
  fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

run_lint() {
  command -v shellcheck >/dev/null 2>&1 || {
    printf 'shellcheck is required\n' >&2
    exit 1
  }
  # No Bats/shUnit dependency is introduced: this portable shell suite runs in
  # both target distributions and exercises the exact installed scripts.
  shellcheck -x \
    "${repo_root}"/agents/edge-agent/packaging/scripts/*.sh \
    "${repo_root}"/agents/edge-agent/packaging/deb/build-repository.sh \
    "${repo_root}"/agents/edge-agent/packaging/tests/*.sh \
    "${repo_root}"/scripts/edge-agent-package-smoke.sh \
    "${repo_root}"/scripts/edge-agent-release-build.sh
  printf 'edge-agent packaging shellcheck passed\n'
}

run_release_build() {
  source_repository=${EDGE_RELEASE_SMOKE_SOURCE_REPOSITORY:-https://example.invalid/cdnca.git}
  source_commit=${EDGE_RELEASE_SMOKE_SOURCE_COMMIT:-0123456789abcdef0123456789abcdef01234567}
  source_epoch=${EDGE_RELEASE_SMOKE_SOURCE_DATE_EPOCH:-1782864000}
  agents_recipe=${repo_root}/agents/edge-agent/packaging/tests/build_recipe_test.sh
  "${agents_recipe}"
  EDGE_RELEASE_SMOKE_SOURCE_REPOSITORY="${source_repository}" \
    EDGE_RELEASE_SMOKE_SOURCE_COMMIT="${source_commit}" \
    EDGE_RELEASE_SMOKE_SOURCE_DATE_EPOCH="${source_epoch}" \
    "${agents_recipe}" --real-wrapper-smoke
}

run_containers() {
  builder=
  command -v docker >/dev/null 2>&1 || {
    printf 'docker is required for distribution smoke tests\n' >&2
    exit 1
  }
  docker info >/dev/null 2>&1 || {
    printf 'docker daemon is unavailable\n' >&2
    exit 1
  }
  command -v jq >/dev/null 2>&1 || {
    printf 'jq is required for the release builder contract\n' >&2
    exit 1
  }
  builder=$(jq -er '.builder.image' "${repo_root}/agents/edge-agent/packaging/build/contract.json")
  case "${builder}" in
    docker.io/library/golang:1.27.3-bookworm@sha256:*) ;;
    *) printf 'unexpected Edge release builder image\n' >&2; exit 1 ;;
  esac
  if ! docker image inspect "${builder}" >/dev/null 2>&1; then
    docker pull "${builder}"
  fi
  workdir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-ops11-package.XXXXXX")
  chmod 0755 "${workdir}"
  printf 'building signed Edge apt repository once\n'
  docker run --rm --name "${builder_container}" --label "${task_label}" \
    -e DEBIAN_FRONTEND=noninteractive \
    -v "${repo_root}:/workspace:ro" -v "${workdir}:/output:rw" -w /workspace \
    "${builder}" sh -c '
      set -eu
      apt-get update -qq
      apt-get install -y -qq gzip jq perl >/dev/null
      agents/edge-agent/packaging/tests/deb_repository_test.sh build /output/repository
    '

  for target in 'debian:12-slim:debian12:'"${debian_container}" 'ubuntu:24.04:ubuntu2404:'"${ubuntu_container}"; do
    image=${target%%:*}; target=${target#*:}
    image=${image}:${target%%:*}; target=${target#*:}
    distro=${target%%:*}; container=${target#*:}
    # One distribution per invocation keeps each heavy run bounded.
    [ -z "${only_distro}" ] || [ "${only_distro}" = "${distro}" ] || continue
    printf 'running edge-agent packaging smoke in %s\n' "${image}"
    docker run --rm --name "${container}" --label "${task_label}" \
      -e DEBIAN_FRONTEND=noninteractive \
      -v "${repo_root}:/workspace:ro" \
      -v "${workdir}/repository:/repository:ro" \
      -w /workspace \
      "${image}" \
      sh -c "
        set -eu
        apt-get update -qq
        apt-get install -y -qq openssl systemd systemd-sysv coreutils jq gcc libc6-dev perl util-linux logrotate gpgv >/dev/null
        agents/edge-agent/packaging/tests/packaging_test.sh
        agents/edge-agent/packaging/tests/packaging_root_test.sh
        for regression in metadata restore-staging rollback-interrupt disable-failure; do
          CDNCA_REGRESSION_ONLY=\${regression} agents/edge-agent/packaging/tests/packaging_test.sh
        done
        arch=\$(dpkg --print-architecture)
        agents/edge-agent/packaging/tests/deb_repository_test.sh verify /repository ${distro} \${arch}
      "
  done
  [ -z "$(docker ps -aq --filter "label=${task_label}")" ] || {
    printf 'task-owned containers remain after packaging smoke\n' >&2
    exit 1
  }
  [ -z "$(docker image ls -q --filter "label=${task_label}")" ] || {
    printf 'task-owned images remain after packaging smoke\n' >&2
    exit 1
  }
  [ -z "$(docker network ls -q --filter "label=${task_label}")" ] || {
    printf 'task-owned networks remain after packaging smoke\n' >&2
    exit 1
  }
  [ -z "$(docker volume ls -q --filter "label=${task_label}")" ] || {
    printf 'task-owned volumes remain after packaging smoke\n' >&2
    exit 1
  }
  owned_processes=$(ps -axo ppid=,command= | CDNCA_TASK_MARKER="${task_id}" \
    awk 'index($0, ENVIRON["CDNCA_TASK_MARKER"]) {count++} END {print count+0}')
  [ "${owned_processes}" -eq 0 ] || {
    printf 'task-owned processes remain after packaging smoke\n' >&2
    exit 1
  }
  rm -rf -- "${workdir}"
  workdir=
  printf 'EDGE_AGENT_PACKAGE_SMOKE_RESOURCES containers=0 images=0 networks=0 volumes=0 processes=0 listeners=0 ppid1=0 temp=0\n'
}

case "${mode}" in
  all) run_lint; run_release_build; run_containers ;;
  lint) run_lint ;;
  containers) run_containers ;;
esac
