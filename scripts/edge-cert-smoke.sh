#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *)
    echo "unsupported Docker architecture: ${docker_arch}" >&2
    exit 69
    ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-cert.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-cert\.//')"
container="cdnca-edge-cert-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-cert.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/state"
chmod 0700 "${workdir}/state"
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/edge-cert-smoke" ./internal/certstore/cmd/edge-cert-smoke
)

docker run --detach \
  --name "${container}" \
  --volume "${workdir}/state:/var/lib/cdnca-edge/certificates" \
  --volume "${workdir}/edge-cert-smoke:/usr/local/bin/edge-cert-smoke:ro" \
  --entrypoint /bin/sh \
  "${OPENRESTY_IMAGE}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null

if ! docker exec "${container}" /usr/local/bin/edge-cert-smoke \
  -state-root /var/lib/cdnca-edge/certificates \
  -openresty-bin /usr/local/openresty/bin/openresty \
  -listen-port 18443 >"${workdir}/evidence.json"; then
  cat "${workdir}/evidence.json" >&2
  docker logs "${container}" >&2 || true
  if [ -f "${workdir}/state/shared/error.log" ]; then
    cat "${workdir}/state/shared/error.log" >&2
  fi
  exit 1
fi

cat "${workdir}/evidence.json"
printf 'openresty_version=%s\nimage=%s\ncontainer=%s\nisolation=task-owned-container-and-state\n' \
  "${OPENRESTY_VERSION}" "${OPENRESTY_IMAGE}" "${container}"
