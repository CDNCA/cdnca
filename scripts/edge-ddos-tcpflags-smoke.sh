#!/bin/sh
# Real kernel test of the node DDoS table's packet filters (TCP malformed
# flag classes, conntrack INVALID; agents/edge-agent/internal/ddos)
# with scapy-crafted packets, in a privileged disposable
# debian:12 container (--rm; nftables, iproute2 and python3-scapy installed
# at run time, no image is built). Never run the test binary on a host.
# Extra arguments go to the test binary (default -test.run Kernel).
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
image="${CDNCA_DDOS_SMOKE_IMAGE:-debian:12}"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *) echo "unsupported Docker architecture: ${docker_arch}" >&2; exit 69 ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-ddos-flags.XXXXXX")"
cleanup() {
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-ddos-flags.*) rm -rf -- "${workdir}" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -trimpath -o "${workdir}/ddos.test" ./internal/ddos
)

[ "$#" -gt 0 ] || set -- -test.run Kernel
docker run --rm --privileged \
  --volume "${workdir}/ddos.test:/usr/local/bin/ddos.test:ro" \
  --env CDNCA_DDOS_KERNEL_TEST=1 --env DEBIAN_FRONTEND=noninteractive --workdir /tmp \
  "${image}" sh -ec '
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends nftables iproute2 python3-scapy >/dev/null
    nft --version; uname -r
    exec /usr/local/bin/ddos.test -test.v -test.count=1 "$@"' sh "$@"
