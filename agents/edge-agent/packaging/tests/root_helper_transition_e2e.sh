#!/bin/sh
# Toolset transition through the production helper, in one disposable
# privileged systemd container (no host systemd, network or state is touched).
# A root node is installed with an older packaging toolset (OLD_REF, default
# the previous release commit) and its Agent state holds the four version pointer
# links the Agent writes. The old toolset refuses the upgrade while the node
# keeps serving; install.sh --refresh-toolset from the new release replaces the
# installed scripts; then the same helper path upgrades, rolls back and
# upgrades again with the links preserved. From there each upgrade refreshes
# the toolset from the bytes its signed SBOM carries: full v1 bundles exactly
# as the release build makes them (no native section).
#
#   agents/edge-agent/packaging/tests/root_helper_transition_e2e.sh [IMAGE] [OLD_REF]
#
# IMAGE: Ubuntu 24.04 with systemd, openssl, perl, python3 (jq is installed if missing).
set -eu
agent_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
repo_root=$(CDPATH='' cd -- "${agent_root}/../.." && pwd -P)
image=${1:-ubuntu:24.04}
old_ref=${2:-7c28938c}
name=cdnca-root-helper-transition-e2e-$$
bin=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-root-helper-transition-bin.XXXXXX")
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
(cd "${repo_root}/tools/ed25519-tool" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -o "${bin}/cdnca-ed25519" .)
build test -c -tags roothelpere2e -o "${bin}/updater.e2e.test" ./internal/updater
for version in 1.0.24 1.0.25 1.0.26 1.0.27 1.0.28 1.0.29; do
  build build -trimpath -ldflags "-X main.version=${version}" -o "${bin}/fixture-${version}" ./packaging/tests/roothelperfixture
done
mkdir "${bin}/old"
git -C "${repo_root}" archive "${old_ref}" agents/edge-agent/packaging | tar -x -C "${bin}/old"
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
docker exec "${name}" bash /workspace/agents/edge-agent/packaging/tests/root_helper_transition_e2e_inner.sh
