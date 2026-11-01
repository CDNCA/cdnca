#!/bin/sh
# Real kernel test of unban after an Agent restart (agents/edge-agent/
# internal/ddos TestKernelUnbanAfterAgentRestart, fix-nrecovery R3): two
# test processes share one state directory inside one privileged disposable
# debian:12 container (--rm; nftables, iproute2 and python3-scapy installed
# at run time, no image is built). Phase 1 bans and exits without cleanup;
# phase 2 is a new process that must adopt the table and unban only its own
# ban. Two modes: generic XDP in front, and no BPF (seccomp refuses bpf(2),
# nftables only). Needs a real Linux kernel; never run the test binary on a
# host. macOS: the test file is linux-only and skips without the env below.
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
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-ddos-restart.XXXXXX")"
cleanup() {
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-ddos-restart.*) rm -rf -- "${workdir}" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

if [ -n "${CDNCA_DDOS_TEST_BINARY:-}" ]; then
  # Prebuilt linux test binary (a host without Go).
  cp -- "${CDNCA_DDOS_TEST_BINARY}" "${workdir}/ddos.test"
else
  (
    cd "${repo_root}/agents/edge-agent"
    GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
      go test -c -trimpath -o "${workdir}/ddos.test" ./internal/ddos
  )
fi
# bpf(2) refused (ENOSYS): a kernel or runtime without BPF.
printf '%s\n' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["bpf"],"action":"SCMP_ACT_ERRNO","errnoRet":38}]}' \
  > "${workdir}/no-bpf.json"

run() {
  expect=$1; shift
  docker run --rm --privileged "$@" \
    --volume "${workdir}:/smoke:ro" --env DEBIAN_FRONTEND=noninteractive --workdir /tmp \
    --env CDNCA_DDOS_KERNEL_TEST=1 --env CDNCA_DDOS_RESTART_STATE=/tmp/restart \
    --env CDNCA_DDOS_RESTART_EXPECT="${expect}" \
    "${image}" sh -ec '
      apt-get update -qq >/dev/null
      apt-get install -y -qq --no-install-recommends nftables iproute2 python3-scapy >/dev/null
      nft --version; uname -r
      mkdir -m 700 /tmp/restart
      t="/smoke/ddos.test -test.v -test.count=1 -test.run ^TestKernelUnbanAfterAgentRestart$"
      echo "== phase 1 (Agent A bans, exits without cleanup)"
      CDNCA_DDOS_RESTART_PHASE=1 $t
      echo "== between"
      nft list set inet cdnca_ddos ban_v4
      echo "== phase 2 (Agent B adopts, unbans its own ban)"
      CDNCA_DDOS_RESTART_PHASE=2 $t
      if nft list table inet cdnca_ddos >/dev/null 2>&1; then
        echo "table left after phase 2" >&2; exit 1
      fi'
}

echo "== generic XDP in front"
run xdp
echo "== no BPF: nftables only"
run nftables --security-opt "seccomp=${workdir}/no-bpf.json"
