#!/bin/sh
# Packaging helper refresh through the production helper, in one disposable
# privileged systemd container (no host systemd, network or state is touched).
# A root node is installed as the previous release (OLD_REF, default 86c4d871)
# installs it: its packaging scripts and its own helper binary. Full v1
# bundles without a native section (as the release build makes them) carry
# the scripts and the helper in their signed SBOM. See
# root_helper_refresh_e2e_inner.sh for the steps.
#
#   agents/edge-agent/packaging/tests/root_helper_refresh_e2e.sh [IMAGE] [OLD_REF]
#
# IMAGE: Ubuntu 24.04 with systemd, openssl, perl, python3 (jq is installed if missing).
# Run it on an image with dbus (dnspup-systemd-test:ubuntu24) and on one
# without: the helper must be replaced through /run/systemd/private when there
# is no system bus. A no-dbus image:
#   docker run --name nodbus ubuntu:24.04 sh -c 'apt-get update && DEBIAN_FRONTEND=noninteractive
#     apt-get install -y --no-install-recommends systemd systemd-sysv openssl perl python3 jq'
#   docker commit -c 'CMD ["/sbin/init"]' nodbus cdnca-nodbus:ubuntu24 && docker rm nodbus
set -eu
agent_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
repo_root=$(CDPATH='' cd -- "${agent_root}/../.." && pwd -P)
image=${1:-ubuntu:24.04}
old_ref=${2:-86c4d871}
name=cdnca-root-helper-refresh-e2e-$$
bin=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-root-helper-refresh-bin.XXXXXX")
cleanup() {
  docker rm -f "${name}" >/dev/null 2>&1 || true
  rm -rf -- "${bin}"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

arch=$(docker version --format '{{.Server.Arch}}')
case "${arch}" in amd64|arm64) ;; *) printf 'unsupported docker architecture: %s\n' "${arch}" >&2; exit 1 ;; esac
build() {
  (cd "${agent_root}" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go "$@")
}
build build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o "${bin}/cdnca-edge-agent-helper" ./packaging/helper/cmd/cdnca-edge-agent-helper
build build -trimpath -o "${bin}/cdnca-edge-release-bundle" ./packaging/helper/cmd/cdnca-edge-release-bundle
build build -trimpath -o "${bin}/toolsetreportprobe" ./packaging/tests/toolsetreportprobe
(cd "${repo_root}/tools/ed25519-tool" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -o "${bin}/cdnca-ed25519" .)
build test -c -tags roothelpere2e -o "${bin}/updater.e2e.test" ./internal/updater
for version in 1.0.24 1.0.25 1.0.26 1.0.27; do
  build build -trimpath -ldflags "-X main.version=${version}" -o "${bin}/fixture-${version}" ./packaging/tests/roothelperfixture
done
# The previous release's packaging scripts and helper, built from its own source.
mkdir "${bin}/old" "${bin}/old-source"
git -C "${repo_root}" archive "${old_ref}" agents/edge-agent/packaging | tar -x -C "${bin}/old"
git -C "${repo_root}" archive "${old_ref}" agents/edge-agent libs proto/gen/go | tar -x -C "${bin}/old-source"
(cd "${bin}/old-source/agents/edge-agent" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
  go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o "${bin}/old-helper" ./packaging/helper/cmd/cdnca-edge-agent-helper)
rm -rf -- "${bin}/old-source"
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
docker exec "${name}" bash /workspace/agents/edge-agent/packaging/tests/root_helper_refresh_e2e_inner.sh
