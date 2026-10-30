#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
alpine_image="alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"

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
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-firewall.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-firewall\.//')"
container="cdnca-edge-firewall-${suffix}"
image="cdnca/firewall-smoke:${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker image rm "${image}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-firewall.*)
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
    -o "${workdir}/edge-firewall-smoke" ./cmd/edge-firewall-smoke
)

if ! docker build --pull=false --tag "${image}" - >"${workdir}/build.log" 2>&1 <<EOF
FROM ${alpine_image}
RUN apk add --no-cache nftables
EOF
then
  cat "${workdir}/build.log" >&2
  exit 1
fi

docker run --detach \
  --privileged \
  --name "${container}" \
  --volume "${workdir}/state:/var/lib/cdnca-edge/firewall" \
  --volume "${workdir}/edge-firewall-smoke:/usr/local/bin/edge-firewall-smoke:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null

if ! docker exec "${container}" /usr/local/bin/edge-firewall-smoke \
  -state-root /var/lib/cdnca-edge/firewall \
  -nft-binary /usr/sbin/nft \
  -isolated-namespace >"${workdir}/evidence.json"; then
  cat "${workdir}/evidence.json" >&2
  exit 1
fi

if docker exec "${container}" /usr/sbin/nft list table inet cdnca_firewall >/dev/null 2>&1; then
  echo "owned firewall table remained after smoke cleanup" >&2
  exit 1
fi
if docker exec "${container}" /usr/sbin/nft list table inet cdnca_firewall_smoke_sentinel >/dev/null 2>&1; then
  echo "sentinel table remained after smoke cleanup" >&2
  exit 1
fi

cat "${workdir}/evidence.json"
printf 'image=%s\ncontainer=%s\nprivileged_namespace=isolated\n' "${image}" "${container}"
