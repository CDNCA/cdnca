#!/bin/sh
# Real kernel test of the level D site drop (攻击自动升级 D 级, esc-node §3:
# agents/edge-agent cmd/edge-agent site_drop*.go, internal/xdp, internal/ddos)
# in privileged disposable debian:12 containers (--rm; nftables, iptables,
# iproute2 and python3-scapy installed at run time, no image is built; the
# container never starts systemd, and systemd-binfmt is masked anyway so it
# cannot clear Docker Desktop's binfmt registrations). Never run the test
# binary on a host. Run it: scripts/edge-site-drop-smoke.sh
#   1. generic XDP on a veth: exclusive ports drop every packet (IPv4/IPv6),
#      the shared TLS port drops ClientHellos naming the D site (exact,
#      wildcard, any case) and passes the other sites' names, a run time XDP
#      fallback leaves nftables dropping the exclusive ports, lifting restores;
#   2. a node without BPF (seccomp refuses bpf(2)): nftables drops the
#      exclusive ports, the shared port passes, receipt sni_unavailable.
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
image="${CDNCA_SITE_DROP_SMOKE_IMAGE:-debian:12}"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *) echo "unsupported Docker architecture: ${docker_arch}" >&2; exit 69 ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-site-drop.XXXXXX")"
cleanup() {
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-site-drop.*) rm -rf -- "${workdir}" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
  go -C "${repo_root}/agents/edge-agent" test -c -trimpath -o "${workdir}/agent.test" ./cmd/edge-agent
printf '%s\n' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["bpf"],"action":"SCMP_ACT_ERRNO","errnoRet":38}]}' \
  > "${workdir}/no-bpf.json"

run() {
  docker run --rm --privileged "$@" \
    --volume "${workdir}:/smoke:ro" --env DEBIAN_FRONTEND=noninteractive --workdir /tmp \
    "${image}" sh -ec '
      ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service 2>/dev/null || true
      apt-get update -qq >/dev/null
      apt-get install -y -qq --no-install-recommends nftables iptables iproute2 python3-scapy >/dev/null
      nft --version; uname -r
      '"${inner}"
}

echo "== generic XDP"
inner='CDNCA_XDP_KERNEL_TEST=1 /smoke/agent.test -test.v -test.count=1 -test.run "KernelSiteDrop"'
run

echo "== no BPF: nftables"
inner='CDNCA_XDP_KERNEL_TEST=1 CDNCA_XDP_EXPECT=nftables /smoke/agent.test -test.v -test.count=1 -test.run "KernelSiteDrop"'
run --security-opt "seccomp=${workdir}/no-bpf.json"
