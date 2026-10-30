#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *)
    echo "unsupported Docker architecture: ${docker_arch}" >&2
    exit 69
    ;;
esac

tmp_base="${TMPDIR:-/tmp}"
case "${tmp_base}" in
  /*) ;;
  *) echo "TMPDIR must be absolute" >&2; exit 64 ;;
esac
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-l4.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-l4\.//')"
container="cdnca-edge-l4-${suffix}"
image="cdnca/openresty-runtime:l4-smoke-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker image rm "${image}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-l4.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -m 0700 "${workdir}/state"
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/l4-smoke" ./internal/l4runtime/cmd/l4-smoke
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -trimpath -o "${workdir}/l4runtime.test" ./internal/l4runtime
)

if ! "${repo_root}/scripts/edge-runtime-build.sh" "${image}" >"${workdir}/build.log" 2>&1; then
  cat "${workdir}/build.log" >&2
  exit 1
fi

docker run --detach --init \
	  --name "${container}" \
	  --cap-add SYS_PTRACE \
	  --volume "${workdir}/state:/var/lib/cdnca-edge-l4" \
  --volume "${workdir}/l4-smoke:/usr/local/bin/cdnca-l4-smoke:ro" \
  --volume "${workdir}/l4runtime.test:/usr/local/bin/cdnca-l4runtime-test:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null

test "$(docker exec "${container}" id -u)" = "0"

docker exec "${container}" openresty -V 2>&1 | grep -F -- '--with-stream_realip_module' >/dev/null

if ! docker exec "${container}" /usr/local/bin/cdnca-l4runtime-test \
	  -test.run '^(TestLinuxPIDFDSignalsCapturedProcessNotPIDFileReplacement|TestOpenRestyReloadRetriesMixedOwnersUntilStable|TestOpenRestyReloadAcceptsStableReplacementAfterOldWorkersExit)$' \
  -test.count=1 -test.v >"${workdir}/pidfd.log"; then
  cat "${workdir}/pidfd.log" >&2
  docker logs "${container}" >&2
  exit 1
fi

if ! docker exec "${container}" /usr/local/bin/cdnca-l4-smoke \
  -state-root /var/lib/cdnca-edge-l4 >"${workdir}/evidence.json"; then
  cat "${workdir}/evidence.json" >&2
  docker logs "${container}" >&2
  exit 1
fi

for expected in \
  '"long_connections_survived_reload": true' \
  '"connection_limit_rejected": true' \
  '"syntax_precheck_rejected": true' \
	  '"strict_validation_rejected": true' \
	  '"proxy_protocol_disabled_plain": true' \
	  '"proxy_protocol_inbound_v1": true' \
	  '"proxy_protocol_inbound_v2": true' \
	  '"proxy_protocol_untrusted_spoof_rejected": true' \
	  '"udp_proxy_protocol_rejected": true' \
	  '"backend_incompatible_rejected": true' \
	  '"last_known_good_version": "l4-v2"' \
	  '"process_identity_recorded": true' \
	  '"pending_start_identity_cleared": true' \
	  '"master_owner_uid": 0' \
	  '"worker_owner_dropped": true'; do
  grep -F "${expected}" "${workdir}/evidence.json" >/dev/null
done

cat "${workdir}/pidfd.log"
cat "${workdir}/evidence.json"
printf 'openresty_version=%s\nimage=%s\ncontainer=%s\nisolation=task-owned-container-and-state\n' \
  "${OPENRESTY_VERSION}" "${image}" "${container}"
