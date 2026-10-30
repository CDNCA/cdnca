#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
image=clickhouse/clickhouse-server:25.3.6.56-alpine
suffix="${PPID}-$$-$(date +%s)"
container="cdnca-obs-query-benchmark-${suffix}"
network="cdnca-obs-query-benchmark-${suffix}"
database="obs_query_benchmark_${PPID}_$$_$(date +%s)"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-obs-query-benchmark.XXXXXX")
client_user=obs_benchmark
client_password=obs_benchmark_local_only
capacity_rows=100000
samples_per_cell=8
raw_wall="${tmp_dir}/wall.tsv"
query_id_prefix="obsbench${PPID}x$$x$(date +%s)"

cleanup() {
  docker rm -f -v "${container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -rf "${tmp_dir}"
}

fail() {
  printf 'FAIL production-query-benchmark: %s\n' "$1" >&2
  exit 1
}

exec_ch() {
  docker exec "${container}" clickhouse-client \
    --user "${client_user}" --password "${client_password}" \
    --connect_timeout 30 --send_timeout 120 --receive_timeout 120 "$@"
}

production_query() {
  local query_name=$1
  local source="${repo_root}/services/control-api/internal/analyticslog/client.go"
  local query

  query=$(sed -n "/^const ${query_name} = /,/FORMAT JSONEachRow/p" "${source}" | \
    sed '1s/^[^=]*= .//' | sed '$s/.$//')
  [[ ${query} == *$'\nFORMAT JSONEachRow' ]] || fail "cannot extract ${query_name}"
  printf '%s' "${query%$'\nFORMAT JSONEachRow'}"
}

candidate_query() {
  local production=$1
  local candidate

  candidate=$(printf '%s' "${production}" | perl -0777 -ne \
    'if (/candidate_event_ids\s+AS\s*\(\s*(SELECT\s+event_id.*?GROUP\s+BY\s+event_id)\s*\)\s*SELECT/s) { print $1 }')
  [[ -n ${candidate} ]] || fail 'cannot extract access candidate query'
  printf "WITH fromUnixTimestamp64Milli({snapshot_ms:Int64}, 'UTC') AS snapshot_at\n%s" "${candidate}"
}

percentile() {
  local field=$1
  local threads=$2
  local concurrency=$3
  local percentile_value=$4

  awk -F '\t' -v field="${field}" -v threads="${threads}" -v concurrency="${concurrency}" \
    '$1 == threads && $2 == concurrency { print $field }' "${raw_wall}" | LC_ALL=C sort -n | \
    awk -v percentile_value="${percentile_value}" '
      { values[NR]=$1 }
      END {
        rank=int(NR*percentile_value)
        if (rank < NR*percentile_value) rank++
        if (rank < 1) rank=1
        printf "%.6f", values[rank]
      }'
}

trap cleanup EXIT HUP INT TERM

for dependency in docker perl awk sed sort; do
  command -v "${dependency}" >/dev/null 2>&1 || fail "${dependency} is unavailable"
done
docker info >/dev/null 2>&1 || fail 'Docker daemon is unavailable'
if ! docker image inspect "${image}" >/dev/null 2>&1 && ! docker pull "${image}" >/dev/null; then
  fail "fixed image ${image} is unavailable"
fi

docker network create "${network}" >/dev/null
docker run -d --name "${container}" --network "${network}" --ulimit nofile=262144:262144 \
  -e CLICKHOUSE_DB=default -e CLICKHOUSE_USER="${client_user}" -e CLICKHOUSE_PASSWORD="${client_password}" \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 "${image}" >/dev/null

ready_streak=0
for _ in {1..300}; do
  if exec_ch --query 'SELECT 1' >/dev/null 2>&1; then
    ready_streak=$((ready_streak + 1))
    [[ ${ready_streak} -ge 3 ]] && break
  else
    ready_streak=0
  fi
  sleep 0.2
done
[[ ${ready_streak} -ge 3 ]] || fail 'ClickHouse did not become ready'
[[ $(exec_ch --format TSVRaw --query 'SELECT version()') == 25.3.6.56 ]] || fail 'ClickHouse version drifted'
exec_ch --query "CREATE DATABASE ${database}" >/dev/null

while IFS= read -r migration; do
  docker exec -i "${container}" clickhouse-client --user "${client_user}" --password "${client_password}" \
    --database "${database}" --multiquery <"${migration}" >/dev/null
done < <(find "${repo_root}/infra/clickhouse/migrations" -maxdepth 1 -type f \
  -name '[0-9][0-9][0-9]_*.up.sql' -print | LC_ALL=C sort)

tenant=10000000-0000-4000-8000-000000000099
security_tenant=10000000-0000-4000-8000-000000000098
site=20000000-0000-4000-8000-000000000099
node=30000000-0000-4000-8000-000000000099
exec_ch --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,country_code,carrier,
   method,protocol,cache_status,upstream_result,status_code,request_bytes,response_bytes,duration_us)
  SELECT 1,concat('capacity-',toString(number)),now64(3,'UTC')-toIntervalMillisecond(number%3600000),
   now64(3,'UTC')-INTERVAL 5 SECOND,toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),
   'capacity.example.test',concat('/capacity/',toString(number)),toIPv6('2001:db8::99'),'CN','capacity-carrier',
   'GET','HTTP/2',if(number%4=0,'MISS','HIT'),'ok',if(number%20=0,503,200),100,512+number%4096,
   1000+number%10000 FROM numbers(${capacity_rows})" >/dev/null
exec_ch --database "${database}" --query "INSERT INTO security_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,country_code,carrier,
   event_type,action,severity,rule_id,status_code,request_bytes,response_bytes)
  SELECT 1,concat('security-capacity-',toString(number)),now64(3,'UTC')-toIntervalMillisecond(number%3600000),
   now64(3,'UTC')-INTERVAL 5 SECOND,toUUID('${security_tenant}'),toUUID('${site}'),toUUID('${node}'),
   'capacity.example.test',concat('/capacity/',toString(number)),toIPv6('2001:db8::98'),'CN','capacity-carrier',
   'waf','block','high','capacity-rule',if(number%20=0,429,403),100,512+number%4096
  FROM numbers(${capacity_rows})" >/dev/null
exec_ch --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,
   cache_status,upstream_result,status_code,request_bytes,response_bytes,duration_us)
  VALUES (1,'partition-decoy',now64(3,'UTC')+INTERVAL 40 DAY,now64(3,'UTC')-INTERVAL 5 SECOND,
   toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),'decoy.example.test','/decoy',toIPv6('2001:db8::99'),
   'GET','HTTP/2','MISS','ok',200,1,1,1)" >/dev/null

from_ms=$(exec_ch --database "${database}" --format TSVRaw --query \
  "SELECT toUnixTimestamp64Milli(now64(3,'UTC')-INTERVAL 2 HOUR)")
to_ms=$(exec_ch --database "${database}" --format TSVRaw --query \
  "SELECT toUnixTimestamp64Milli(now64(3,'UTC')+INTERVAL 1 MINUTE)")
snapshot_ms=$(exec_ch --database "${database}" --format TSVRaw --query \
  "SELECT toUnixTimestamp64Milli(now64(3,'UTC'))")
query=$(production_query accessPageSQL)
candidate=$(candidate_query "${query}")

query_params=(
  --param_has_snapshot 0 --param_snapshot_ms "${snapshot_ms}"
  --param_tenant_id "${tenant}" --param_from_ms "${from_ms}" --param_to_ms "${to_ms}"
  --param_has_site 0 --param_site_id 00000000-0000-0000-0000-000000000000
  --param_has_node 0 --param_node_id 00000000-0000-0000-0000-000000000000
  --param_has_ip 0 --param_client_ip :: --param_has_uri_path 0 --param_uri_path /
  --param_has_status 0 --param_status_code 0 --param_has_method 0 --param_method GET
  --param_has_protocol 0 --param_protocol HTTP/2 --param_has_cache 0 --param_cache_status HIT
  --param_has_upstream_result 0 --param_upstream_result success
  --param_has_content_type 0 --param_content_type application/json
  --param_has_user_agent 0 --param_user_agent cdnca-observability-benchmark
  --param_has_request_bytes_min 0 --param_request_bytes_min 0
  --param_has_request_bytes_max 0 --param_request_bytes_max 0
  --param_has_response_bytes_min 0 --param_response_bytes_min 0
  --param_has_response_bytes_max 0 --param_response_bytes_max 0
  --param_has_country 0 --param_country_code CN --param_has_carrier 0 --param_carrier capacity-carrier
  --param_has_ja4 0 --param_ja4 '' --param_has_origin_connect_min 0 --param_origin_connect_us_min 0
  --param_has_origin_connect_max 0 --param_origin_connect_us_max 0
  --param_has_origin_first_byte_min 0 --param_origin_first_byte_us_min 0
  --param_has_origin_first_byte_max 0 --param_origin_first_byte_us_max 0
  --param_has_origin_total_min 0 --param_origin_total_us_min 0
  --param_has_origin_total_max 0 --param_origin_total_us_max 0
  --param_has_cursor 0 --param_cursor_occurred_at_ms 0 --param_cursor_event_id '' --param_row_limit 101
)

printf '%s\n' 'SELECT1_CLIENT_BASELINE_SECONDS'
for sample in {1..8}; do
  started=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
  exec_ch --query 'SELECT 1' >/dev/null
  finished=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
  awk -v start="${started}" -v finish="${finished}" 'BEGIN {printf "%.6f\n", finish-start}'
done

printf '%s\n' 'ACCESS_CANDIDATE_EXPLAIN'
exec_ch --database "${database}" --format TSVRaw \
  --param_snapshot_ms "${snapshot_ms}" --param_tenant_id "${tenant}" \
  --param_from_ms "${from_ms}" --param_to_ms "${to_ms}" \
  --query "EXPLAIN indexes=1 ${candidate}"

: >"${raw_wall}"
for max_threads in 1 2 4; do
  benchmark_query=${query/SETTINGS max_threads = 2/SETTINGS max_threads = ${max_threads}}
  [[ ${benchmark_query} == *"SETTINGS max_threads = ${max_threads}"* ]] || fail 'max_threads replacement failed'
  for concurrency in 1 2 4 8; do
    sample=0
    while [[ ${sample} -lt ${samples_per_cell} ]]; do
      pids=()
      launched=0
      while [[ ${launched} -lt ${concurrency} && ${sample} -lt ${samples_per_cell} ]]; do
        sample=$((sample + 1))
        launched=$((launched + 1))
        query_id="${query_id_prefix}_t${max_threads}_c${concurrency}_s${sample}"
        (
          started=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
          exec_ch --database "${database}" --format Null --query_id "${query_id}" \
            "${query_params[@]}" --query "${benchmark_query}" >/dev/null
          finished=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
          wall=$(awk -v start="${started}" -v finish="${finished}" 'BEGIN {printf "%.6f", finish-start}')
          printf '%d\t%d\t%d\t%s\n' "${max_threads}" "${concurrency}" "${sample}" "${wall}" >>"${raw_wall}"
        ) &
        pids+=("$!")
      done
      for pid in "${pids[@]}"; do
        wait "${pid}" || fail "query failed max_threads=${max_threads} concurrency=${concurrency}"
      done
    done
  done
done

exec_ch --query 'SYSTEM FLUSH LOGS' >/dev/null
printf '%s\n' 'ACCESS_BENCHMARK_WALL_SECONDS'
printf '%s\n' $'max_threads\tconcurrency\tsamples\tp50\tp95'
for max_threads in 1 2 4; do
  for concurrency in 1 2 4 8; do
    p50=$(percentile 4 "${max_threads}" "${concurrency}" .50)
    p95=$(percentile 4 "${max_threads}" "${concurrency}" .95)
    printf '%d\t%d\t%d\t%s\t%s\n' "${max_threads}" "${concurrency}" "${samples_per_cell}" "${p50}" "${p95}"
  done
done

printf '%s\n' 'ACCESS_BENCHMARK_QUERY_LOG'
exec_ch --format TSVWithNames --query "SELECT
  toUInt8(substring(splitByChar('_',query_id)[2],2)) AS max_threads,
  toUInt8(substring(splitByChar('_',query_id)[3],2)) AS concurrency,
  count() AS samples,
  round(quantileExact(0.50)(query_duration_ms)/1000,6) AS p50_seconds,
  round(quantileExact(0.95)(query_duration_ms)/1000,6) AS p95_seconds,
  round(avg(read_rows),0) AS avg_read_rows,
  round(avg(read_bytes),0) AS avg_read_bytes,
  max(memory_usage) AS max_memory_bytes
FROM system.query_log
WHERE type='QueryFinish' AND startsWith(query_id,'${query_id_prefix}_')
GROUP BY max_threads,concurrency
ORDER BY max_threads,concurrency"

exec_ch --query "DROP DATABASE ${database} SYNC" >/dev/null
docker rm -f -v "${container}" >/dev/null
docker network rm "${network}" >/dev/null
rm -rf "${tmp_dir}"
trap - EXIT HUP INT TERM
