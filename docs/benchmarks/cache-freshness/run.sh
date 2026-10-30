#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

rounds=8
concurrency=32
origin_delay_ms=200
prepare_wait=1300ms

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *) echo "unsupported Docker architecture: ${docker_arch}" >&2; exit 69 ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-cache-freshness-benchmark.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-cache-freshness-benchmark\.//')"
network="cdnca-cache-freshness-benchmark-${suffix}"
origin_container="cdnca-cache-freshness-benchmark-origin-${suffix}"
baseline_container="cdnca-cache-freshness-benchmark-baseline-${suffix}"
enhancement_container="cdnca-cache-freshness-benchmark-enhancement-${suffix}"
sampler_pid=""

cleanup() {
  cleanup_status=$?
  if [ "${sampler_pid}" != "" ]; then
    kill "${sampler_pid}" >/dev/null 2>&1 || true
    wait "${sampler_pid}" 2>/dev/null || true
  fi
  if [ "${cleanup_status}" -ne 0 ]; then
    test ! -f "${workdir}/baseline-state/error.log" || tail -n 100 "${workdir}/baseline-state/error.log" >&2
    test ! -f "${workdir}/enhancement-state/error.log" || tail -n 100 "${workdir}/enhancement-state/error.log" >&2
    docker logs "${baseline_container}" >&2 2>/dev/null || true
    docker logs "${enhancement_container}" >&2 2>/dev/null || true
    docker logs "${origin_container}" >&2 2>/dev/null || true
  fi
  docker rm -f "${baseline_container}" "${enhancement_container}" "${origin_container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-cache-freshness-benchmark.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
  return "${cleanup_status}"
}
trap cleanup EXIT HUP INT TERM

mkdir -p \
  "${workdir}/bin" \
  "${workdir}/baseline-policy" "${workdir}/baseline-state/cache" "${workdir}/baseline-state/proxy_temp" \
  "${workdir}/enhancement-policy" "${workdir}/enhancement-state/cache" "${workdir}/enhancement-state/proxy_temp"
chmod -R 0700 "${workdir}"

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go build -trimpath -o "${workdir}/bin/policy" ./internal/cachefreshness/cmd/cache-freshness-policy
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/bin/origin" ./internal/cachefreshness/cmd/cache-freshness-origin
)
(
  cd "${repo_root}"
  GOWORK=off go build -trimpath -o "${workdir}/bin/loadgen" ./docs/benchmarks/cache-freshness/loadgen.go
)

"${workdir}/bin/policy" -state-root /state -lua-root /opt/cache-freshness >"${workdir}/baseline-policy/nginx.conf" <<'JSON'
{"schema_version":"cdnca.edge.cache-freshness/v1","policy_version":1,"configuration_version":101,"tenant_id":"benchmark-tenant","site_id":"benchmark-baseline","mode":"baseline","listen_address":"0.0.0.0","listen_port":18086,"hosts":["cache.example.test"],"origin_host":"cache-origin","origin_port":18090,"cache_max_bytes":134217728,"cache_inactive_seconds":60,"fresh_seconds":1,"cacheable_statuses":[200],"enhancement":{"enabled":false}}
JSON
"${workdir}/bin/policy" -state-root /state -lua-root /opt/cache-freshness >"${workdir}/enhancement-policy/nginx.conf" <<'JSON'
{"schema_version":"cdnca.edge.cache-freshness/v1","policy_version":1,"configuration_version":102,"tenant_id":"benchmark-tenant","site_id":"benchmark-enhancement","mode":"enhancement","listen_address":"0.0.0.0","listen_port":18087,"hosts":["cache.example.test"],"origin_host":"cache-origin","origin_port":18090,"cache_max_bytes":134217728,"cache_inactive_seconds":60,"fresh_seconds":1,"cacheable_statuses":[200],"enhancement":{"enabled":true,"stale_window_seconds":5,"expert":{"lock_timeout_milliseconds":1000,"lock_age_milliseconds":5000,"background_update":true,"revalidation":true,"failure_classes":["updating","error","timeout","http_500","http_502","http_503","http_504"]}}}
JSON

docker network create "${network}" >/dev/null
for mode in baseline enhancement; do
  docker run --rm \
    --network "${network}" \
    --network-alias cache-origin \
    --volume "${workdir}/${mode}-policy:/policy:ro" \
    --volume "${workdir}/${mode}-state:/state" \
    --volume "${repo_root}/edge/openresty/cachefreshness:/opt/cache-freshness:ro" \
    --entrypoint /usr/local/openresty/bin/openresty \
    "${OPENRESTY_IMAGE}" -t -c /policy/nginx.conf >/dev/null
done

docker run --detach \
  --name "${origin_container}" \
  --network "${network}" \
  --network-alias cache-origin \
  --publish 127.0.0.1::18090 \
  --volume "${workdir}/bin/origin:/usr/local/bin/cache-freshness-origin:ro" \
  --entrypoint /usr/local/bin/cache-freshness-origin \
  "${OPENRESTY_IMAGE}" >/dev/null
docker run --detach \
  --name "${baseline_container}" \
  --network "${network}" \
  --publish 127.0.0.1::18086 \
  --volume "${workdir}/baseline-policy:/policy:ro" \
  --volume "${workdir}/baseline-state:/state" \
  --volume "${repo_root}/edge/openresty/cachefreshness:/opt/cache-freshness:ro" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" -c /policy/nginx.conf -g 'daemon off;' >/dev/null
docker run --detach \
  --name "${enhancement_container}" \
  --network "${network}" \
  --publish 127.0.0.1::18087 \
  --volume "${workdir}/enhancement-policy:/policy:ro" \
  --volume "${workdir}/enhancement-state:/state" \
  --volume "${repo_root}/edge/openresty/cachefreshness:/opt/cache-freshness:ro" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" -c /policy/nginx.conf -g 'daemon off;' >/dev/null

origin_published="$(docker port "${origin_container}" 18090/tcp | tail -n 1)"
baseline_published="$(docker port "${baseline_container}" 18086/tcp | tail -n 1)"
enhancement_published="$(docker port "${enhancement_container}" 18087/tcp | tail -n 1)"
origin_url="http://${origin_published}"
baseline_url="http://${baseline_published}"
enhancement_url="http://${enhancement_published}"

wait_healthy() {
  edge_url=$1
  attempt=0
  while [ "${attempt}" -lt 100 ]; do
    if [ "$(curl --silent --show-error -H 'Host: cache.example.test' "${edge_url}/_cdnca/cache-freshness-healthz" 2>/dev/null || true)" = 'ok:1' ]; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.05
  done
  return 1
}

wait_healthy "${baseline_url}"
wait_healthy "${enhancement_url}"
curl --fail --silent --show-error --get \
  --data-urlencode "delay_ms=${origin_delay_ms}" --data-urlencode 'status=200' --data-urlencode 'body=benchmark' \
  "${origin_url}/control" >/dev/null

origin_count() {
  count_path=$1
  count_json="$(curl --fail --silent --show-error "${origin_url}/counts")"
  count_value="$(printf '%s\n' "${count_json}" | sed -n "s|.*\"${count_path}\":\([0-9][0-9]*\).*|\1|p")"
  printf '%s\n' "${count_value:-0}"
}

sample_stats() {
  container=$1
  output=$2
  stop_file=$3
  while [ ! -f "${stop_file}" ]; do
    docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}' "${container}" >>"${output}" 2>/dev/null || true
    sleep 0.1
  done
}

summarize_stats() {
  awk -F '|' '
    function to_mib(raw, value) {
      value = raw
      gsub(/[[:alpha:]]+$/, "", value)
      if (raw ~ /GiB$/) return value * 1024
      if (raw ~ /MiB$/) return value
      if (raw ~ /KiB$/) return value / 1024
      if (raw ~ /GB$/) return value * 1000000000 / 1048576
      if (raw ~ /MB$/) return value * 1000000 / 1048576
      if (raw ~ /kB$/) return value * 1000 / 1048576
      if (raw ~ /B$/) return value / 1048576
      return 0
    }
    {
      cpu = $1
      gsub(/%/, "", cpu)
      split($2, memory, " ")
      mib = to_mib(memory[1])
      if (cpu + 0 > peak_cpu) peak_cpu = cpu + 0
      if (mib > peak_memory) peak_memory = mib
      samples++
    }
    END { printf "%d|%.3f|%.3f\n", samples, peak_cpu, peak_memory }
  ' "$1"
}

run_mode() {
  mode=$1
  edge_url=$2
  container=$3
  path="/benchmark-${mode}"
  stats_file="${workdir}/${mode}.stats"
  stop_file="${workdir}/${mode}.stats.stop"
  sample_stats "${container}" "${stats_file}" "${stop_file}" &
  sampler_pid=$!

  before="$(origin_count "${path}")"
  "${workdir}/bin/loadgen" -url "${edge_url}${path}" -mode "${mode}" -phase cold \
    -rounds "${rounds}" -concurrency "${concurrency}" >"${workdir}/${mode}-cold.json"
  after="$(origin_count "${path}")"
  cold_origin=$((after - before))

  before="${after}"
  "${workdir}/bin/loadgen" -url "${edge_url}${path}" -mode "${mode}" -phase stale \
    -rounds "${rounds}" -concurrency "${concurrency}" -prepare-wait "${prepare_wait}" >"${workdir}/${mode}-stale.json"
  after="$(origin_count "${path}")"
  stale_origin=$((after - before))

  : >"${stop_file}"
  wait "${sampler_pid}"
  sampler_pid=""
  stats="$(summarize_stats "${stats_file}")"
  IFS='|' read -r stats_samples peak_cpu peak_memory <<EOF
${stats}
EOF

  printf 'CACHE_FRESHNESS_BENCHMARK_LOAD='
  cat "${workdir}/${mode}-cold.json"
  printf 'CACHE_FRESHNESS_BENCHMARK_LOAD='
  cat "${workdir}/${mode}-stale.json"
  printf 'CACHE_FRESHNESS_BENCHMARK_MODE={"mode":"%s","cold_origin_requests":%d,"stale_origin_requests_including_prepare":%d,"stats_samples":%d,"peak_cpu_percent":%s,"peak_memory_mib":%s}\n' \
    "${mode}" "${cold_origin}" "${stale_origin}" "${stats_samples}" "${peak_cpu}" "${peak_memory}"

  case "${mode}" in
    baseline)
      baseline_cold_origin=${cold_origin}
      baseline_stale_origin=${stale_origin}
      ;;
    enhancement)
      enhancement_cold_origin=${cold_origin}
      enhancement_stale_origin=${stale_origin}
      ;;
  esac
}

run_mode baseline "${baseline_url}" "${baseline_container}"
run_mode enhancement "${enhancement_url}" "${enhancement_container}"

baseline_floor=$((rounds * concurrency * 3 / 4))
stale_baseline_floor=$((rounds + baseline_floor))
enhancement_ceiling=$((rounds * 2))
stale_enhancement_ceiling=$((rounds * 3))
test "${baseline_cold_origin}" -ge "${baseline_floor}"
test "${baseline_stale_origin}" -ge "${stale_baseline_floor}"
test "${enhancement_cold_origin}" -le "${enhancement_ceiling}"
test "${enhancement_stale_origin}" -le "${stale_enhancement_ceiling}"
test "${enhancement_cold_origin}" -lt "${baseline_cold_origin}"
test "${enhancement_stale_origin}" -lt "${baseline_stale_origin}"

printf 'CACHE_FRESHNESS_BENCHMARK_COMPARE={"openresty_version":"%s","image_digest":"%s","rounds":%d,"concurrency":%d,"origin_delay_ms":%d,"baseline_cold_origin_requests":%d,"enhancement_cold_origin_requests":%d,"baseline_stale_origin_requests_including_prepare":%d,"enhancement_stale_origin_requests_including_prepare":%d}\n' \
  "${OPENRESTY_VERSION}" "${OPENRESTY_SOURCE_DIGEST}" "${rounds}" "${concurrency}" "${origin_delay_ms}" \
  "${baseline_cold_origin}" "${enhancement_cold_origin}" "${baseline_stale_origin}" "${enhancement_stale_origin}"
