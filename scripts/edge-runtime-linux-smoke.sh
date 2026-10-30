#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
. "${repo_root}/edge/openresty/runtime.env"
# shellcheck source=tests/edge-linux/images.env
. "${repo_root}/tests/edge-linux/images.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-linux.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-linux\.//')"
containers=""
images=""

cleanup() {
  for container in ${containers}; do
    docker rm --force "${container}" >/dev/null 2>&1 || true
  done
  for image in ${images}; do
    docker image rm "${image}" >/dev/null 2>&1 || true
  done
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-linux.*) rm -rf -- "${workdir}" ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

run_distro() {
  distro="$1"
  distro_image="$2"
  image="cdnca/edge-linux-smoke:${distro}-${suffix}"
  container="cdnca-edge-linux-${distro}-${suffix}"
  images="${images} ${image}"
  containers="${containers} ${container}"

  docker build \
    --pull=false \
    --provenance=false \
    --build-arg "DISTRO_IMAGE=${distro_image}" \
    --build-arg "OPENRESTY_IMAGE=${OPENRESTY_IMAGE}" \
    --build-arg "OPENRESTY_VERSION=${OPENRESTY_VERSION}" \
    --build-arg "OPENRESTY_SOURCE_DIGEST=${OPENRESTY_SOURCE_DIGEST}" \
    --file "${repo_root}/tests/edge-linux/Dockerfile" \
    --tag "${image}" \
    "${repo_root}"

  test "$(docker image inspect "${image}" --format '{{index .Config.Labels "org.opencontainers.image.version"}}')" = "${OPENRESTY_VERSION}"
  test "$(docker image inspect "${image}" --format '{{index .Config.Labels "org.opencontainers.image.base.digest"}}')" = "${OPENRESTY_SOURCE_DIGEST}"

  docker run --detach \
    --name "${container}" \
    --privileged \
    --cgroupns=private \
    --tmpfs /run \
    --tmpfs /run/lock \
    --tmpfs /tmp \
    --publish 127.0.0.1::18080 \
    --volume "${repo_root}:/workspace:ro" \
    "${image}" >/dev/null

  published="$(docker port "${container}" 18080/tcp | tail -n 1)"
  case "${published}" in
    127.0.0.1:*) ;;
    *) echo "${distro} did not publish to a random loopback port: ${published}" >&2; exit 1 ;;
  esac
  host_port="${published##*:}"
  test "${host_port}" != "15173"
  test "${host_port}" != "8080"

  attempt=0
  state=unknown
  while [ "${attempt}" -lt 100 ]; do
    state="$(docker exec "${container}" systemctl is-system-running 2>/dev/null || true)"
    case "${state}" in
      running|degraded) break ;;
    esac
    attempt=$((attempt + 1))
    sleep 0.1
  done
  case "${state}" in
    running|degraded) ;;
    *) docker logs "${container}" >&2; echo "${distro} systemd did not start: ${state}" >&2; exit 1 ;;
  esac

  docker exec "${container}" /workspace/tests/edge-linux/inside-systemd-smoke.sh "${distro}"
  body="$(curl --fail --silent --show-error "http://${published}/healthz")"
  test "${body}" = "ok:cfg-v2"
  final_state="$(docker exec "${container}" systemctl is-system-running 2>/dev/null || true)"
  case "${final_state}" in
    running|degraded) ;;
    *) echo "unexpected final systemd state: ${final_state}" >&2; exit 1 ;;
  esac

  printf 'distro=%s\npublished=%s\nexternal_health=%s\nsystemd_state=%s\n' \
    "${distro}" "${published}" "${body}" "${final_state}"

  docker stop --time 10 "${container}" >/dev/null
  docker rm "${container}" >/dev/null
  docker image rm "${image}" >/dev/null
}

run_distro debian12 "${DEBIAN_12_IMAGE}"
run_distro ubuntu24 "${UBUNTU_24_IMAGE}"
