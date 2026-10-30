#!/bin/sh
# Real kernel test of the node XDP filter (agents/edge-agent/internal/xdp)
# in privileged disposable debian:12 containers (--rm; nftables,
# iproute2 and python3-scapy installed at run time, no image is built).
# Never run the test binaries on a host.
#   1. generic XDP on a veth: bans, malformed flags, SYN rate, port bans, L5
#      blocks, counters, normal traffic, verify failure -> nftables; the DDoS
#      table with XDP in front (XDP drops first, fallback leaves no gap);
#      the Agent watch (cmd/edge-agent): fallback and reattach are each one
#      node security event and XDP_FILTER follows the filter (xdp-events);
#   2. a node without BPF (seccomp refuses bpf(2)): the probe reports
#      nftables, and the ge-ddos / ddos-tcpflags kernel cases all pass there.
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
image="${CDNCA_XDP_SMOKE_IMAGE:-debian:12}"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *) echo "unsupported Docker architecture: ${docker_arch}" >&2; exit 69 ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-xdp.XXXXXX")"
cleanup() {
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-xdp.*) rm -rf -- "${workdir}" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -trimpath -o "${workdir}/xdp.test" ./internal/xdp
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -trimpath -o "${workdir}/ddos.test" ./internal/ddos
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -trimpath -o "${workdir}/agent.test" ./cmd/edge-agent
)
# bpf(2) refused (ENOSYS): a kernel or runtime without BPF.
printf '%s\n' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["bpf"],"action":"SCMP_ACT_ERRNO","errnoRet":38}]}' \
  > "${workdir}/no-bpf.json"

run() {
  docker run --rm --privileged "$@" \
    --volume "${workdir}:/smoke:ro" --env DEBIAN_FRONTEND=noninteractive --workdir /tmp \
    "${image}" sh -ec '
      apt-get update -qq >/dev/null
      apt-get install -y -qq --no-install-recommends nftables iproute2 python3-scapy >/dev/null
      nft --version; uname -r
      '"${inner}"
}

echo "== generic XDP"
inner='CDNCA_XDP_KERNEL_TEST=1 /smoke/xdp.test -test.v -test.count=1 -test.run Kernel
      CDNCA_DDOS_KERNEL_TEST=1 /smoke/ddos.test -test.v -test.count=1 -test.run KernelXDPFront
      CDNCA_XDP_KERNEL_TEST=1 /smoke/agent.test -test.v -test.count=1 -test.run KernelXDPWatch'
run

echo "== no BPF: fallback to nftables, ge-ddos cases on nftables"
inner='CDNCA_XDP_KERNEL_TEST=1 CDNCA_XDP_EXPECT=nftables /smoke/xdp.test -test.v -test.count=1 -test.run Kernel
      CDNCA_DDOS_KERNEL_TEST=1 /smoke/ddos.test -test.v -test.count=1 -test.run Kernel'
run --security-opt "seccomp=${workdir}/no-bpf.json"
