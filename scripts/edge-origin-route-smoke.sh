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
workdir="$(mktemp -d "${tmp_base%/}/cdnca-origin-route.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-origin-route\.//')"
container="cdnca-origin-route-${suffix}"
image="cdnca/openresty-runtime:origin-route-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker image rm "${image}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-origin-route.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -trimpath \
    -o "${workdir}/originroute-smoke" ./internal/originroute
)

if ! "${repo_root}/scripts/edge-runtime-build.sh" "${image}" >"${workdir}/build.log" 2>&1; then
  cat "${workdir}/build.log" >&2
  exit 1
fi

if ! docker run --rm \
  --name "${container}" \
  --network none \
  --env CDNCA_ORIGINROUTE_SMOKE=1 \
  --env CDNCA_OPENRESTY_BIN=/usr/local/openresty/bin/openresty \
  --env CDNCA_ORIGINROUTE_LUA_ROOT=/opt/cdnca/originroute \
  --volume "${workdir}/originroute-smoke:/usr/local/bin/originroute-smoke:ro" \
  --volume "${repo_root}/edge/openresty/originroute:/opt/cdnca/originroute:ro" \
  --entrypoint /usr/local/bin/originroute-smoke \
  "${image}" \
  -test.v -test.run '^TestOriginRouteOpenRestySmoke$' -test.count=1 -test.timeout=90s >"${workdir}/smoke.log" 2>&1; then
  cat "${workdir}/smoke.log" >&2
  exit 1
fi

evidence="$(sed -n 's/^EDGE_ORIGIN_ROUTE_SMOKE_EVIDENCE=//p' "${workdir}/smoke.log")"
if [ -z "${evidence}" ]; then
  cat "${workdir}/smoke.log" >&2
  echo "origin route smoke produced no evidence" >&2
  exit 1
fi
for required in \
  '"conditional_route":true' \
  '"priority_route":true' \
  '"connect_failover":true' \
  '"read_timeout_failover":true' \
  '"get_failover":true' \
  '"head_failover":true' \
  '"post_not_replayed":true' \
  '"total_budget_bounded":true' \
  '"l2_opened":true' \
  '"l2_probe_recovered":true' \
  '"forged_hop_ignored":true' \
  '"runtime_hop_generated":true' \
  '"connect_fallback_hop_zero":true' \
  '"read_fallback_hop_zero":true' \
  '"http_502_fallback_hop_zero":true' \
  '"l2_success_hop_one":true' \
  '"initial_direct_hop_zero":true' \
  '"circuit_capacity_fail_closed":true' \
  '"circuit_state_recovered":true' \
  '"multi_version_state_expired":true' \
  '"ipv4_source_bound":true' \
  '"ipv6_source_bound":true' \
  '"concurrent_reload":true' \
  '"bad_policy_kept_version":"route-v2"' \
  '"health_rollback_version":"route-v2"' \
  '"initial_failure_stopped":true' \
  '"current_matches_lkg":true'
do
  case "${evidence}" in
    *"${required}"*) ;;
    *)
      echo "origin route evidence is missing ${required}" >&2
      echo "${evidence}" >&2
      exit 1
      ;;
  esac
done

printf 'openresty_version=%s\nimage=%s\nEDGE_ORIGIN_ROUTE_SMOKE_EVIDENCE=%s\n' \
  "${OPENRESTY_VERSION}" "${image}" "${evidence}"
