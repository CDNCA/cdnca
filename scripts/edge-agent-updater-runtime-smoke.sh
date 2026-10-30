#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
helper_test=${repo_root}/agents/edge-agent/packaging/tests/helper_test.sh
task_prefix=cdnca_ops0611_packaging
mode=${1:-all}
container_names=
image_names=
workdir=
verify_cleanup_on_exit=false

case "${mode}" in
  all|lint|go|containers|runtime) ;;
  *) printf 'usage: %s [all|lint|go|containers|runtime]\n' "$0" >&2; exit 64 ;;
esac

cleanup() {
  cleanup_resource_status=0
  if command -v docker >/dev/null 2>&1; then
    if ! docker info >/dev/null 2>&1; then
      printf 'docker daemon became unavailable; task-owned cleanup cannot be verified\n' >&2
      cleanup_resource_status=1
    else
      for container in ${container_names}; do
        docker container inspect "${container}" >/dev/null 2>&1 || continue
        docker rm -f -- "${container}" >/dev/null 2>&1 || true
      done
      for image in ${image_names}; do
        docker image inspect "${image}" >/dev/null 2>&1 || continue
        docker image rm --force -- "${image}" >/dev/null 2>&1 || true
      done
      for network in $(docker network ls --filter "label=com.cdnca.task=${task_prefix}" --format '{{.Name}}'); do
        docker network rm -- "${network}" >/dev/null 2>&1 || true
      done
    fi
  fi
  if [ -n "${workdir}" ]; then
    case "${workdir}" in
      "${work_base:-/tmp}"/${task_prefix}.runtime.*) rm -rf -- "${workdir}" ;;
      *) printf 'refusing to clean unexpected runtime path: %s\n' "${workdir}" >&2 ;;
    esac
  fi
  return "${cleanup_resource_status}"
}

cleanup_on_exit() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM
  set +e
  cleanup
  resource_status=$?
  if [ "${verify_cleanup_on_exit}" = true ]; then
    verify_task_cleanup
    verify_status=$?
  else
    verify_status=0
  fi
  [ "${cleanup_status}" -ne 0 ] && exit "${cleanup_status}"
  [ "${resource_status}" -ne 0 ] && exit "${resource_status}"
  exit "${verify_status}"
}
trap cleanup_on_exit EXIT HUP INT TERM

verify_task_cleanup() {
  docker info >/dev/null 2>&1 || {
    printf 'docker daemon is unavailable; task-owned cleanup is UNKNOWN\n' >&2
    return 1
  }
  container_residuals=$(docker ps -a --filter "label=com.cdnca.task=${task_prefix}" --format '{{.Names}}')
  image_residuals=$(docker image ls --filter "label=com.cdnca.task=${task_prefix}" --format '{{.Repository}}:{{.Tag}}')
  network_residuals=$(docker network ls --filter "label=com.cdnca.task=${task_prefix}" --format '{{.Name}}')
  process_snapshot=$(ps -Ao pid=,ppid=,command=)
  process_residuals=$(printf '%s\n' "${process_snapshot}" | awk -v prefix="${task_prefix}" 'index($0, prefix) { count++ } END { print count + 0 }')
  orphan_residuals=$(printf '%s\n' "${process_snapshot}" | awk -v prefix="${task_prefix}" '$2 == 1 && index($0, prefix) { count++ } END { print count + 0 }')
  tmp_residuals=$(find "${work_base}" -maxdepth 1 -name "${task_prefix}.runtime.*" -print | wc -l | tr -d ' ')
  socket_residuals=$(find "${work_base}" -maxdepth 2 -type s -name "${task_prefix}*" -print | wc -l | tr -d ' ')
  [ -z "${container_residuals}" ] || { printf 'task-owned container residuals: %s\n' "${container_residuals}" >&2; exit 1; }
  [ -z "${image_residuals}" ] || { printf 'task-owned image residuals: %s\n' "${image_residuals}" >&2; exit 1; }
  [ -z "${network_residuals}" ] || { printf 'task-owned network residuals: %s\n' "${network_residuals}" >&2; exit 1; }
  [ "${process_residuals}" -eq 0 ] || { printf 'task-owned process residuals: %s\n' "${process_residuals}" >&2; exit 1; }
  [ "${orphan_residuals}" -eq 0 ] || { printf 'task-owned PPID=1 orphan residuals: %s\n' "${orphan_residuals}" >&2; exit 1; }
  [ "${tmp_residuals}" -eq 0 ] || { printf 'task-owned tmp residuals: %s\n' "${tmp_residuals}" >&2; exit 1; }
  [ "${socket_residuals}" -eq 0 ] || { printf 'task-owned socket residuals: %s\n' "${socket_residuals}" >&2; exit 1; }
  printf 'cleanup evidence: containers=0 images=0 networks=0 processes=0 tmp=0 sockets=0 ppid1_orphans=0\n'
}

run_lint() {
  sh -n "${helper_test}" "$0"
  command -v shellcheck >/dev/null 2>&1 || {
    printf 'shellcheck is required\n' >&2
    exit 1
  }
  shellcheck "${helper_test}" "$0"
  "${helper_test}" static
  printf 'edge-agent updater/helper shell checks passed\n'
}

run_go() {
  "${helper_test}" go
}

run_containers() {
  command -v docker >/dev/null 2>&1 || {
    printf 'docker is required for distribution verification\n' >&2
    exit 1
  }
  docker info >/dev/null 2>&1 || {
    printf 'docker daemon is unavailable; it will not be started by this smoke\n' >&2
    exit 1
  }
  tmp_base=${TMPDIR:-/tmp}
  work_base=${tmp_base%/}
  verify_cleanup_on_exit=true
  run_id=$(date +%s)-$$
  for specification in 'debian:12-slim 252 debian12' 'ubuntu:24.04 255 ubuntu2404'; do
    image=${specification%% *}
    remainder=${specification#* }
    expected_systemd=${remainder%% *}
    suffix=${remainder#* }
    container=${task_prefix}_${suffix}_${run_id}
    container_names="${container_names} ${container}"
    printf 'verifying helper units in %s with systemd %s\n' "${image}" "${expected_systemd}"
    docker run --rm \
      --name "${container}" \
      --label "com.cdnca.task=${task_prefix}" \
      -e DEBIAN_FRONTEND=noninteractive \
      -e "EXPECTED_SYSTEMD=${expected_systemd}" \
      -v "${repo_root}:/workspace:ro" \
      -w /workspace \
      "${image}" \
      sh -c '
        set -eu
        apt-get -o Acquire::Retries=5 update -qq
        apt-get -o Acquire::Retries=5 install -y -qq systemd perl >/dev/null
        actual=$(systemd-analyze --version | sed -n "1s/^systemd \([0-9][0-9]*\).*/\1/p")
        [ "${actual}" = "${EXPECTED_SYSTEMD}" ] || {
          printf "expected systemd %s, got %s\n" "${EXPECTED_SYSTEMD}" "${actual}" >&2
          exit 1
        }
        agents/edge-agent/packaging/tests/helper_test.sh static
        agents/edge-agent/packaging/tests/helper_test.sh systemd-verify
      '
    container_names=$(printf '%s\n' "${container_names}" | sed "s/ ${container}//")
  done
}

run_runtime() {
  command -v docker >/dev/null 2>&1 || {
    printf 'docker is required for isolated systemd runtime\n' >&2
    exit 1
  }
  docker info >/dev/null 2>&1 || {
    printf 'docker daemon is unavailable; it will not be started by this smoke\n' >&2
    exit 1
  }
  docker_arch=$(docker info --format '{{.Architecture}}')
  case "${docker_arch}" in
    x86_64|amd64) go_arch=amd64 ;;
    aarch64|arm64) go_arch=arm64 ;;
    *) printf 'unsupported Docker architecture: %s\n' "${docker_arch}" >&2; exit 1 ;;
  esac
  tmp_base=${TMPDIR:-/tmp}
  work_base=${tmp_base%/}
  verify_cleanup_on_exit=true
  workdir=$(mktemp -d "${work_base}/${task_prefix}.runtime.XXXXXX")
  (
    cd "${repo_root}/agents/edge-agent"
    CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go build -trimpath \
      -o "${workdir}/cdnca-edge-agent-helper" \
      ./packaging/helper/cmd/cdnca-edge-agent-helper
  )
  chmod 0555 "${workdir}/cdnca-edge-agent-helper"

  run_id=$(date +%s)-$$
  for specification in 'debian:12-slim 252 debian12' 'ubuntu:24.04 255 ubuntu2404'; do
    image=${specification%% *}
    remainder=${specification#* }
    expected_systemd=${remainder%% *}
    suffix=${remainder#* }
    container=${task_prefix}_runtime_${suffix}_${run_id}
    bootstrap_container=${container}_bootstrap
    runtime_image=${task_prefix}_runtime_image_${suffix}_${run_id}
    container_names="${container_names} ${bootstrap_container} ${container}"
    image_names="${image_names} ${runtime_image}"
    printf 'running isolated helper lifecycle in %s with systemd %s\n' "${image}" "${expected_systemd}"
    docker run -d \
      --name "${bootstrap_container}" \
      --label "com.cdnca.task=${task_prefix}" \
      "${image}" \
      sh -c '
        set -eu
        apt_attempt=1
        while ! apt-get -o Acquire::Retries=5 update -qq || \
          ! DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install -y -qq systemd gcc libc6-dev openssl jq perl python3 util-linux procps >/dev/null; do
          [ "${apt_attempt}" -lt 3 ] || exit 1
          apt_attempt=$((apt_attempt + 1))
          sleep 5
        done
        apt-get clean
        touch /cdnca-runtime-ready
        exec tail -f /dev/null
      ' \
      >/dev/null
    bootstrap_ready=false
    bootstrap_attempt=0
    while [ "${bootstrap_attempt}" -lt 900 ]; do
      if ! docker container inspect "${bootstrap_container}" --format '{{.State.Running}}' 2>/dev/null | grep -F -x true >/dev/null; then
        docker logs "${bootstrap_container}" >&2 || true
        printf 'runtime bootstrap container exited early: %s\n' "${bootstrap_container}" >&2
        exit 1
      fi
      if docker exec "${bootstrap_container}" test -e /cdnca-runtime-ready; then
        bootstrap_ready=true
        break
      fi
      sleep 1
      bootstrap_attempt=$((bootstrap_attempt + 1))
    done
    [ "${bootstrap_ready}" = true ] || {
      docker logs "${bootstrap_container}" >&2 || true
      printf 'runtime bootstrap exceeded 900 seconds: %s\n' "${bootstrap_container}" >&2
      exit 1
    }
    docker commit \
      --change "LABEL com.cdnca.task=${task_prefix}" \
      --change 'STOPSIGNAL SIGRTMIN+3' \
      --change 'CMD ["/lib/systemd/systemd"]' \
      "${bootstrap_container}" "${runtime_image}" \
      >/dev/null
    docker rm -f -- "${bootstrap_container}" >/dev/null
    container_names=$(printf '%s\n' "${container_names}" | sed "s/ ${bootstrap_container}//")
    docker run -d \
      --privileged \
      --cgroupns=host \
      --name "${container}" \
      --label "com.cdnca.task=${task_prefix}" \
      --tmpfs /run \
      --tmpfs /run/lock \
      -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
      -v "${repo_root}:/workspace:ro" \
      -v "${workdir}:/task:ro" \
      "${runtime_image}" \
      >/dev/null
    ready=false
    attempt=0
    while [ "${attempt}" -lt 600 ]; do
      if ! docker container inspect "${container}" --format '{{.State.Running}}' 2>/dev/null | grep -F -x true >/dev/null; then
        docker logs "${container}" >&2 || true
        printf 'isolated systemd container exited early: %s\n' "${container}" >&2
        exit 1
      fi
      if docker exec "${container}" ps -p 1 -o comm= 2>/dev/null | tr -d ' ' | grep -F -x systemd >/dev/null && \
        docker exec "${container}" systemctl show --property=Version --value 2>/dev/null | grep . >/dev/null; then
        ready=true
        break
      fi
      sleep 1
      attempt=$((attempt + 1))
    done
    [ "${ready}" = true ] || {
      docker logs "${container}" >&2 || true
      printf 'isolated systemd did not become ready: %s\n' "${container}" >&2
      exit 1
    }
    actual=$(docker exec "${container}" systemctl --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
    [ "${actual}" = "${expected_systemd}" ] || {
      printf 'expected systemd %s, got %s\n' "${expected_systemd}" "${actual}" >&2
      exit 1
    }
    for regression in layout-migration metadata restore-staging rollback-interrupt disable-failure; do
      docker exec -e "CDNCA_REGRESSION_ONLY=${regression}" "${container}" \
        /workspace/agents/edge-agent/packaging/tests/packaging_test.sh
    done
    docker exec -e CDNCA_OPS0611_ISOLATED=1 "${container}" \
      /workspace/agents/edge-agent/packaging/tests/helper_test.sh runtime
    docker rm -f -- "${container}" >/dev/null
    container_names=$(printf '%s\n' "${container_names}" | sed "s/ ${container}//")
    docker image rm --force -- "${runtime_image}" >/dev/null
    image_names=$(printf '%s\n' "${image_names}" | sed "s/ ${runtime_image}//")
  done
}

case "${mode}" in
  lint) run_lint ;;
  go) run_go ;;
  containers) run_containers ;;
  runtime) run_runtime ;;
  all) run_lint; run_go; run_containers ;;
esac
