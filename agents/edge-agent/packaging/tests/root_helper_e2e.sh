#!/bin/sh
# Root packaging helper end-to-end check in a disposable, privileged systemd
# container (no host systemd, network or state is touched). It proves on real
# systemd + the real helper + the real packaging scripts that a root Agent can
# upgrade itself and that a never-healthy release is rolled back.
#
#   agents/edge-agent/packaging/tests/root_helper_e2e.sh [IMAGE]
#
# IMAGE must be Ubuntu 24.04 with systemd, openssl, jq, perl, python3 and
# util-linux (default ubuntu:24.04 with packages installed on the fly).
set -eu

agent_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
repo_root=$(CDPATH='' cd -- "${agent_root}/../.." && pwd -P)
image=${1:-ubuntu:24.04}
name=cdnca-root-helper-e2e-$$
bin=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-root-helper-e2e-bin.XXXXXX")
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
build test -c -tags roothelpere2e -o "${bin}/updater.e2e.test" ./internal/updater
for version in 1.0.24 1.0.25 1.0.26; do
  exit_flag=
  [ "${version}" != 1.0.26 ] || exit_flag="-X main.daemonExit=1"
  build build -trimpath -ldflags "-X main.version=${version} ${exit_flag}" -o "${bin}/fixture-${version}" ./packaging/tests/roothelperfixture
done
chmod -R a+rX "${bin}"

docker run -d --name "${name}" --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "${repo_root}:/workspace:ro" -v "${bin}:/e2e-bin:ro" \
  "${image}" /sbin/init >/dev/null 2>&1 || {
  # Plain images lack systemd; install it once in a throwaway container.
  printf 'image %s has no /sbin/init; use an image with systemd\n' "${image}" >&2
  exit 1
}
for _ in $(seq 1 30); do
  state=$(docker exec "${name}" systemctl is-system-running 2>/dev/null || true)
  case "${state}" in running|degraded) break ;; esac
  sleep 1
done
docker exec "${name}" bash /workspace/agents/edge-agent/packaging/tests/root_helper_e2e_inner.sh
