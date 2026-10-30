#!/bin/sh
# Node uninstall --purge then first-install gate, in one disposable privileged
# Ubuntu 24.04 systemd container (systemd-binfmt masked; no host state touched).
# Provisions a native-style node the way install-node.sh does (root packaging
# install, helper binary/units/key-init/socket, root Agent unit, compat drop-ins,
# native release tree + links + install record), runs the packaged
# uninstall.sh --purge, then runs install-node.sh's own assert_blank_host on the
# real systemd: it must pass (before the fix the helper units were left behind
# and the gate refused "existing service cdnca-edge-agent-helper.service").
#
#   agents/edge-agent/packaging/tests/purge_reinstall_e2e.sh [IMAGE]
#
# IMAGE: Ubuntu 24.04 with systemd, openssl, perl, python3 (jq is installed if missing).
set -eu

agent_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
repo_root=$(CDPATH='' cd -- "${agent_root}/../.." && pwd -P)
image=${1:-ubuntu:24.04}
name=cdnca-purge-reinstall-e2e-$$
bin=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-purge-reinstall-bin.XXXXXX")
cleanup() {
  docker rm -f "${name}" >/dev/null 2>&1 || true
  rm -rf -- "${bin}"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

arch=$(docker version --format '{{.Server.Arch}}')
case "${arch}" in amd64|arm64) ;; *) printf 'unsupported docker architecture: %s\n' "${arch}" >&2; exit 1 ;; esac
build() {
  (cd "${agent_root}" && CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go "$@")
}
build build -trimpath -o "${bin}/cdnca-edge-agent-helper" ./packaging/helper/cmd/cdnca-edge-agent-helper
build build -trimpath -o "${bin}/cdnca-edge-release-bundle" ./packaging/helper/cmd/cdnca-edge-release-bundle
build build -trimpath -ldflags "-X main.version=1.0.24" -o "${bin}/fixture-1.0.24" ./packaging/tests/roothelperfixture
chmod -R a+rX "${bin}"

docker run -d --rm --name "${name}" --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "${repo_root}:/workspace:ro" -v "${bin}:/e2e-bin:ro" \
  -v /dev/null:/etc/systemd/system/systemd-binfmt.service:ro \
  -v /dev/null:/etc/systemd/system/proc-sys-fs-binfmt_misc.automount:ro \
  -v /dev/null:/etc/systemd/system/proc-sys-fs-binfmt_misc.mount:ro \
  "${image}" /sbin/init >/dev/null
for _ in $(seq 1 30); do
  state=$(docker exec "${name}" systemctl is-system-running 2>/dev/null || true)
  case "${state}" in running|degraded) break ;; esac
  sleep 1
done
docker exec "${name}" bash /workspace/agents/edge-agent/packaging/tests/purge_reinstall_e2e_inner.sh
