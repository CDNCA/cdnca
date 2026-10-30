#!/bin/sh
# Real kernel test of L4 guard kernel bans (agents/edge-agent/
# internal/l4guard, A4): an L4 guard ban becomes a real
# nftables deny in inet cdnca_firewall against real TCP connections, in a privileged
# disposable container (--rm, no network) with its own network namespace.
# Never run the test binary on a host: it creates a dummy interface and an
# nft table. Extra arguments go to the test binary (-test.run ...).
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
alpine_image="alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *) echo "unsupported Docker architecture: ${docker_arch}" >&2; exit 69 ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-l4guard.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-l4guard\.//' | tr 'A-Z' 'a-z')"
image="cdnca/l4guard-smoke:${suffix}"
cleanup() {
  docker image rm "${image}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-l4guard.*) rm -rf -- "${workdir}" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -trimpath -o "${workdir}/l4guard.test" ./internal/l4guard
)

printf 'FROM %s\nRUN apk add --no-cache nftables iproute2\n' "${alpine_image}" >"${workdir}/Dockerfile"
if ! docker build --pull=false --tag "${image}" "${workdir}" -f "${workdir}/Dockerfile" >"${workdir}/build.log" 2>&1; then
  cat "${workdir}/build.log" >&2
  exit 1
fi

docker run --rm --privileged --network none \
  --volume "${workdir}/l4guard.test:/usr/local/bin/l4guard.test:ro" \
  --env CDNCA_L4GUARD_KERNEL_TEST=1 --workdir /tmp \
  "${image}" /usr/local/bin/l4guard.test -test.v -test.count=1 "$@"
