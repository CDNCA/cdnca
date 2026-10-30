#!/bin/sh
# FX45 firewall action escalation on a real kernel under dynamic routing:
# the edge-agent runtime status mirror (cmd/edge-agent firewall_action.go)
# drives the real firewall manager and nftables (engage, restart, recover,
# site removed), in a privileged disposable container (--rm, no network) with
# its own network namespace. Never run the test binary on a host.
#   scripts/edge-firewall-action-kernel-smoke.sh
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
workdir="$(mktemp -d "${tmp_base%/}/cdnca-fw-action.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-fw-action\.//' | tr 'A-Z' 'a-z')"
image="cdnca/fw-action-smoke:${suffix}"
cleanup() {
  docker image rm "${image}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-fw-action.*) rm -rf -- "${workdir}" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
  go -C "${repo_root}/agents/edge-agent" test -c -trimpath -o "${workdir}/edge-agent.test" ./cmd/edge-agent

printf 'FROM %s\nRUN apk add --no-cache nftables\n' "${alpine_image}" >"${workdir}/Dockerfile"
if ! docker build --pull=false --tag "${image}" "${workdir}" -f "${workdir}/Dockerfile" >"${workdir}/build.log" 2>&1; then
  cat "${workdir}/build.log" >&2
  exit 1
fi

docker run --rm --privileged --network none \
  --volume "${workdir}/edge-agent.test:/usr/local/bin/edge-agent.test:ro" \
  --env CDNCA_FIREWALL_ACTION_KERNEL_TEST=1 --workdir /tmp \
  "${image}" /usr/local/bin/edge-agent.test -test.v -test.count=1 -test.run '^TestKernelFirewallActionMirrorDrivesNFTables$'
