#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
alpine_image="alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"

command -v docker >/dev/null 2>&1 || {
  printf 'docker is required for the edge disk guard smoke test\n' >&2
  exit 69
}
docker info >/dev/null 2>&1 || {
  printf 'docker daemon is unavailable\n' >&2
  exit 69
}

docker_arch=$(docker info --format '{{.Architecture}}')
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *) printf 'unsupported Docker architecture: %s\n' "${docker_arch}" >&2; exit 69 ;;
esac

tmp_base=${TMPDIR:-/tmp}
workdir=$(mktemp -d "${tmp_base%/}/cdnca-edge-diskguard.XXXXXX")
suffix=$(basename "${workdir}" | sed 's/^cdnca-edge-diskguard\.//')
container="cdnca-edge-diskguard-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-diskguard.*) rm -rf -- "${workdir}" ;;
    *) printf 'refusing to remove unexpected path: %s\n' "${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -tags diskguard_smoke -trimpath \
    -o "${workdir}/edge-diskguard-smoke" ./internal/diskguard
)

output=$(docker run --rm \
  --name "${container}" \
  --pull never \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --tmpfs /smoke:rw,nosuid,nodev,size=64m,mode=0700 \
  --mount "type=bind,src=${workdir}/edge-diskguard-smoke,dst=/usr/local/bin/edge-diskguard-smoke,readonly" \
  --env EDGE_DISKGUARD_SMOKE_ROOT=/smoke/case \
  --entrypoint /usr/local/bin/edge-diskguard-smoke \
  "${alpine_image}" \
  -test.v -test.run '^TestDiskGuardSmoke$' -test.count=1)

printf '%s\n' "${output}"
case "${output}" in
  *EDGE_DISKGUARD_SMOKE_EVIDENCE=*) ;;
  *) printf 'edge disk guard smoke produced no evidence\n' >&2; exit 1 ;;
esac
