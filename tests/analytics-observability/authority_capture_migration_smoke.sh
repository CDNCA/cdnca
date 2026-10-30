#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
image=clickhouse/clickhouse-server:25.3.6.56-alpine
up_migration="${repo_root}/infra/clickhouse/migrations/002_analytics_authority_capture.up.sql"
down_migration="${repo_root}/infra/clickhouse/migrations/002_analytics_authority_capture.down.sql"
suffix="${PPID}-$$-$(date +%s)"
container="cdnca-obs-capture-ch-${suffix}"
network="cdnca-obs-capture-${suffix}"
database="obs_capture_${PPID}_$$_$(date +%s)"
client_user=obs_capture
client_password=obs_capture_local_only

obs_capture_cleanup() {
  docker rm -f -v "${container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
}

obs_capture_fail() {
  printf 'FAIL authority-capture-migration: %s\n' "$1" >&2
  if docker inspect "${container}" >/dev/null 2>&1; then
    docker logs --tail 120 "${container}" 2>&1 >&2 || true
  fi
  exit 1
}

obs_capture_ch() {
  docker exec -i "${container}" clickhouse-client \
    --user "${client_user}" --password "${client_password}" "$@"
}

trap obs_capture_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

sha001=$(shasum -a 256 "${repo_root}/infra/clickhouse/migrations/001_analytics.up.sql" | awk '{print $1}')
[[ ${sha001} == 1213c9da79aefb7332eb24f0c789b145e6e63c2cbacdca53eff736cc38bee8a3 ]] || \
  obs_capture_fail "001 SHA drifted: ${sha001}"
[[ -r ${up_migration} ]] || obs_capture_fail 'missing 002_analytics_authority_capture.up.sql'
[[ -r ${down_migration} ]] || obs_capture_fail 'missing 002_analytics_authority_capture.down.sql'

for dependency in docker rg shasum awk; do
  command -v "${dependency}" >/dev/null 2>&1 || {
    printf 'SKIP authority-capture-migration: %s is unavailable\n' "${dependency}" >&2
    exit 77
  }
done
docker info >/dev/null 2>&1 || {
  printf '%s\n' 'SKIP authority-capture-migration: Docker daemon is unavailable' >&2
  exit 77
}
if ! docker image inspect "${image}" >/dev/null 2>&1 && ! docker pull "${image}" >/dev/null; then
  printf 'SKIP authority-capture-migration: fixed image %s is unavailable\n' "${image}" >&2
  exit 77
fi

docker network create "${network}" >/dev/null
docker run -d --name "${container}" --network "${network}" \
  --ulimit nofile=262144:262144 \
  -e CLICKHOUSE_DB=default -e CLICKHOUSE_USER="${client_user}" \
  -e CLICKHOUSE_PASSWORD="${client_password}" -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  "${image}" >/dev/null
ready_streak=0
for _ in {1..300}; do
  if obs_capture_ch --query 'SELECT 1' >/dev/null 2>&1; then
    ready_streak=$((ready_streak + 1))
    [[ ${ready_streak} -ge 3 ]] && break
  else
    ready_streak=0
  fi
  sleep 0.2
done
[[ ${ready_streak} -ge 3 ]] || obs_capture_fail 'ClickHouse did not become stably ready'
version=$(obs_capture_ch --format TSVRaw --query 'SELECT version()')
[[ ${version} == 25.3.6.56 ]] || obs_capture_fail "version=${version}, want 25.3.6.56"

obs_capture_ch --query "CREATE DATABASE ${database}" >/dev/null
obs_capture_ch --database "${database}" --multiquery \
  <"${repo_root}/infra/clickhouse/migrations/001_analytics.up.sql" >/dev/null

tenant=10000000-0000-4000-8000-000000000001
site=20000000-0000-4000-8000-000000000001
node=30000000-0000-4000-8000-000000000001
obs_capture_ch --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,cache_status,
   status_code,request_bytes,response_bytes,duration_us)
  VALUES (1,'legacy-access',now64(3,'UTC'),toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),
   'legacy.example.test','/legacy',toIPv6('2001:db8::1'),'GET','HTTP/2','HIT',200,1,2,3)" >/dev/null
obs_capture_ch --database "${database}" --query "INSERT INTO security_events
  (metric_version,event_id,occurred_at,tenant_id,site_id,node_id,host,path,client_ip,event_type,action,severity,
   status_code,request_bytes,response_bytes)
  VALUES (1,'legacy-security',now64(3,'UTC'),toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),
   'legacy.example.test','/legacy',toIPv6('2001:db8::2'),'waf','block','high',403,1,2)" >/dev/null

obs_capture_ch --database "${database}" --multiquery <"${up_migration}" >/dev/null

columns=$(obs_capture_ch --format TSVRaw --query "SELECT table,name,type FROM system.columns
  WHERE database='${database}' AND table IN ('access_events','security_events')
    AND name IN ('task_id','installation_id','request_headers','response_headers','request_body','response_body',
      'ja4','origin_connect_us','origin_first_byte_us','origin_total_us') ORDER BY table,name")
expected_column_count=0
for table in access_events security_events; do
  for spec in \
    $'installation_id\tString' \
    $'ja4\tNullable(String)' \
    $'origin_connect_us\tNullable(UInt64)' \
    $'origin_first_byte_us\tNullable(UInt64)' \
    $'origin_total_us\tNullable(UInt64)' \
    $'request_body\tNullable(String)' \
    $'request_headers\tMap(String, String)' \
    $'response_body\tNullable(String)' \
    $'response_headers\tMap(String, String)' \
    $'task_id\tNullable(String)'; do
    rg -Fqx "${table}"$'\t'"${spec}" <<<"${columns}" || obs_capture_fail "column contract missing: ${table} ${spec}"
    expected_column_count=$((expected_column_count + 1))
  done
done
[[ $(wc -l <<<"${columns}" | tr -d ' ') -eq ${expected_column_count} ]] || \
  obs_capture_fail 'unexpected authority/capture column count'

expected_defaults=$'1\t1\t1\t1\t1\t1\t1\t1\t1\t1'
for table_event in 'access_events legacy-access' 'security_events legacy-security'; do
  table=${table_event% *}
  event=${table_event#* }
  defaults=$(obs_capture_ch --database "${database}" --format TSVRaw --query "SELECT
    isNull(task_id),installation_id='',empty(request_headers),empty(response_headers),isNull(request_body),
    isNull(response_body),isNull(ja4),isNull(origin_connect_us),isNull(origin_first_byte_us),isNull(origin_total_us)
    FROM ${table} FINAL WHERE event_id='${event}'")
  [[ ${defaults} == "${expected_defaults}" ]] || obs_capture_fail "legacy defaults ${table}=${defaults}"
done

for suffix_id in a b; do
  obs_capture_ch --database "${database}" --query "INSERT INTO access_events
    (metric_version,event_id,occurred_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,cache_status,
     status_code,request_bytes,response_bytes,duration_us,request_headers,response_headers,request_body,response_body)
    VALUES (1,'capture-${suffix_id}',toDateTime64(toStartOfMinute(now()),3,'UTC'),toUUID('${tenant}'),toUUID('${site}'),
     toUUID('${node}'),'capture.example.test','/capture',toIPv6('2001:db8::3'),'POST','HTTP/2','MISS',200,10,20,30,
     map('x-request-id','safe-${suffix_id}'),map('content-type','application/json'),'{}','{}')" >/dev/null
done
capture_semantics=$(obs_capture_ch --database "${database}" --format TSVRaw --query "SELECT count() FROM access_events FINAL
  WHERE startsWith(event_id,'capture-') AND installation_id='' AND task_id IS NULL AND ja4 IS NULL
    AND origin_connect_us IS NULL AND origin_first_byte_us IS NULL AND origin_total_us IS NULL
    AND mapContains(request_headers,'x-request-id') AND mapContains(response_headers,'content-type')
    AND request_body='{}' AND response_body='{}' AND isValidJSON(request_body) AND isValidJSON(response_body)")
[[ ${capture_semantics} -eq 2 ]] || obs_capture_fail "capture JSON/NULL semantics rows=${capture_semantics}"

snapshot_ms=$(obs_capture_ch --database "${database}" --format TSVRaw --query 'SELECT toUnixTimestamp64Milli(now64(3))')
first=$(obs_capture_ch --database "${database}" --format TSVRaw --param_snapshot_ms "${snapshot_ms}" --query \
  "SELECT toUnixTimestamp64Milli(occurred_at),event_id FROM access_events FINAL
   WHERE startsWith(event_id,'capture-') AND toUnixTimestamp64Milli(ingested_at)<={snapshot_ms:Int64}
     AND task_id IS NULL AND ja4 IS NULL AND origin_total_us IS NULL
   ORDER BY occurred_at DESC,event_id DESC LIMIT 1")
cursor_ms=${first%%$'\t'*}
cursor_event=${first#*$'\t'}
second=$(obs_capture_ch --database "${database}" --format TSVRaw --param_cursor_ms "${cursor_ms}" \
  --param_cursor_event "${cursor_event}" --query "SELECT event_id FROM access_events FINAL
   WHERE startsWith(event_id,'capture-') AND (toUnixTimestamp64Milli(occurred_at)<{cursor_ms:Int64}
     OR (toUnixTimestamp64Milli(occurred_at)={cursor_ms:Int64} AND event_id<{cursor_event:String}))
   ORDER BY occurred_at DESC,event_id DESC LIMIT 1")
[[ ${cursor_event} == capture-b && ${second} == capture-a ]] || \
  obs_capture_fail "keyset order first=${cursor_event} second=${second}"

obs_capture_ch --database "${database}" --multiquery <"${down_migration}" >/dev/null
remaining_columns=$(obs_capture_ch --format TSVRaw --query "SELECT count() FROM system.columns
  WHERE database='${database}' AND table IN ('access_events','security_events')
    AND name IN ('task_id','installation_id','request_headers','response_headers','request_body','response_body',
      'ja4','origin_connect_us','origin_first_byte_us','origin_total_us')")
[[ ${remaining_columns} -eq 0 ]] || obs_capture_fail "down migration left ${remaining_columns} columns"
remaining_rows=$(obs_capture_ch --database "${database}" --format TSVRaw --query \
  "SELECT (SELECT count() FROM access_events FINAL),(SELECT count() FROM security_events FINAL)")
[[ ${remaining_rows} == $'3\t1' ]] || obs_capture_fail "down migration changed raw rows: ${remaining_rows}"

obs_capture_ch --database "${database}" --multiquery <"${up_migration}" >/dev/null
readded_columns=$(obs_capture_ch --format TSVRaw --query "SELECT count() FROM system.columns
  WHERE database='${database}' AND table IN ('access_events','security_events')
    AND name IN ('task_id','installation_id','request_headers','response_headers','request_body','response_body',
      'ja4','origin_connect_us','origin_first_byte_us','origin_total_us')")
[[ ${readded_columns} -eq 20 ]] || obs_capture_fail "second up columns=${readded_columns}, want 20"
table_contract=$(obs_capture_ch --format TSVRaw --query "SELECT name,engine,partition_key,sorting_key,create_table_query
  FROM system.tables WHERE database='${database}' AND name IN ('access_events','security_events') ORDER BY name")
rg -q $'access_events\tReplacingMergeTree\ttoYYYYMM\(occurred_at\)' <<<"${table_contract}" || \
  obs_capture_fail 'access engine/partition changed'
rg -q $'security_events\tReplacingMergeTree\ttoYYYYMM\(occurred_at\)' <<<"${table_contract}" || \
  obs_capture_fail 'security engine/partition changed'
rg -q '(INTERVAL 30 DAY|toIntervalDay\(30\))' <<<"${table_contract}" || obs_capture_fail 'access TTL changed'
rg -q '(INTERVAL 90 DAY|toIntervalDay\(90\))' <<<"${table_contract}" || obs_capture_fail 'security TTL changed'

printf 'authority-capture-migration passed: version=%s sha001=%s columns=%d lifecycle=up/down/up legacy_defaults=preserved capture_json=canonical task_ja4_timing=NULL installation=authority_default keyset=%s,%s rows_after_down=%s\n' \
  "${version}" "${sha001}" "${readded_columns}" "${cursor_event}" "${second}" "${remaining_rows//$'\t'/,}"

obs_capture_ch --query "DROP DATABASE ${database} SYNC" >/dev/null
docker rm -f -v "${container}" >/dev/null
docker network rm "${network}" >/dev/null
if docker ps -a --format '{{.Names}}' | rg -q "^${container}$" || docker network ls --format '{{.Name}}' | rg -q "^${network}$"; then
  obs_capture_fail 'task container or network remained after cleanup'
fi
trap - EXIT HUP INT TERM

