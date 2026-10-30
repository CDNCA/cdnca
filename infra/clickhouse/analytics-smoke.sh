#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
env_file=${ENV_FILE:-$repo_root/infra/env/development.env}
capacity_rows=${ANALYTICS_SMOKE_ROWS:-100000}
capacity_max_seconds=${ANALYTICS_SMOKE_MAX_SECONDS:-20}
clickhouse_container=${ANALYTICS_CLICKHOUSE_CONTAINER:-}

case "$capacity_rows:$capacity_max_seconds" in
    *[!0-9:]* | 0:* | *:0)
        printf '%s\n' 'ANALYTICS_SMOKE_ROWS and ANALYTICS_SMOKE_MAX_SECONDS must be positive integers' >&2
        exit 2
        ;;
esac

task_database="cdnca_analytics_smoke_$(date +%Y%m%d%H%M%S)_$$"

clickhouse() {
	if [ -n "$clickhouse_container" ]; then
		docker exec -i "$clickhouse_container" clickhouse-client "$@"
		return
	fi
    docker compose --env-file "$env_file" -f "$repo_root/compose.yaml" exec -T clickhouse \
        sh -c 'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' \
        analytics-smoke "$@"
}

cleanup() {
    clickhouse --param_database "$task_database" \
        --query 'DROP DATABASE IF EXISTS {database:Identifier} SYNC' >/dev/null 2>&1 || :
}

fail() {
    printf 'analytics smoke failed: %s\n' "$1" >&2
    exit 1
}

assert_equal() {
    expected=$1
    actual=$2
    label=$3
    [ "$actual" = "$expected" ] || fail "$label expected=$expected actual=$actual"
}

trap cleanup EXIT HUP INT TERM

clickhouse --param_database "$task_database" \
    --query 'CREATE DATABASE {database:Identifier}' >/dev/null

clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/001_analytics.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/002_analytics_authority_capture.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/003_analytics_hourly_rollup.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/004_analytics_version_evidence.up.sql" >/dev/null
schema_count=$(clickhouse --param_database "$task_database" --format TSVRaw \
    --query 'SELECT count() FROM system.tables WHERE database = {database:String}')
assert_equal 12 "$schema_count" 'first up object count'
first_schema=$(clickhouse --param_database "$task_database" --format TSVRaw --query \
    'SELECT create_table_query FROM system.tables WHERE database = {database:String} ORDER BY name')

clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/004_analytics_version_evidence.down.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/003_analytics_hourly_rollup.down.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/002_analytics_authority_capture.down.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/001_analytics.down.sql" >/dev/null
schema_count=$(clickhouse --param_database "$task_database" --format TSVRaw \
    --query 'SELECT count() FROM system.tables WHERE database = {database:String}')
assert_equal 0 "$schema_count" 'down object count'

clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/001_analytics.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/002_analytics_authority_capture.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/003_analytics_hourly_rollup.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/004_analytics_version_evidence.up.sql" >/dev/null
schema_count=$(clickhouse --param_database "$task_database" --format TSVRaw \
    --query 'SELECT count() FROM system.tables WHERE database = {database:String}')
assert_equal 12 "$schema_count" 'second up object count'
second_schema=$(clickhouse --param_database "$task_database" --format TSVRaw --query \
    'SELECT create_table_query FROM system.tables WHERE database = {database:String} ORDER BY name')
assert_equal "$first_schema" "$second_schema" 'up/down/up deterministic DDL'

insert_fixed_access() {
    clickhouse --database "$task_database" --insert_deduplication_token analytics-smoke-access-v1 \
        --date_time_input_format best_effort --query 'INSERT INTO access_events FORMAT JSONEachRow' <<'JSON'
{"metric_version":1,"event_id":"fixed-access-1","occurred_at":"2099-01-01T00:05:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"one.example.test","path":"/a","client_ip":"2001:db8::1","method":"GET","protocol":"HTTP/2","cache_status":"HIT","status_code":200,"request_bytes":100,"response_bytes":1000,"duration_us":1000}
{"metric_version":1,"event_id":"fixed-access-2","occurred_at":"2099-01-01T00:15:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"one.example.test","path":"/missing","client_ip":"2001:db8::2","method":"GET","protocol":"HTTP/2","cache_status":"MISS","status_code":404,"request_bytes":50,"response_bytes":200,"duration_us":2000}
{"metric_version":1,"event_id":"fixed-access-3","occurred_at":"2099-01-01T00:25:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000002","node_id":"30000000-0000-0000-0000-000000000002","host":"two.example.test","path":"/failure","client_ip":"2001:db8::3","method":"POST","protocol":"HTTP/1.1","cache_status":"BYPASS","status_code":503,"request_bytes":25,"response_bytes":300,"duration_us":3000}
JSON
}

insert_fixed_security() {
    clickhouse --database "$task_database" --insert_deduplication_token analytics-smoke-security-v1 \
        --date_time_input_format best_effort --query 'INSERT INTO security_events FORMAT JSONEachRow' <<'JSON'
{"metric_version":1,"event_id":"fixed-security-1","occurred_at":"2099-01-01T00:10:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"one.example.test","path":"/login","client_ip":"2001:db8::4","event_type":"waf","action":"block","severity":"high","rule_id":"rule-1","status_code":403,"request_bytes":80,"response_bytes":120}
{"metric_version":1,"event_id":"fixed-security-2","occurred_at":"2099-01-01T00:20:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000002","node_id":"30000000-0000-0000-0000-000000000002","host":"two.example.test","path":"/api","client_ip":"2001:db8::5","event_type":"cc","action":"challenge","severity":"medium","status_code":429,"request_bytes":90,"response_bytes":130}
JSON
}

insert_fixed_access >/dev/null
insert_fixed_access >/dev/null
insert_fixed_security >/dev/null
insert_fixed_security >/dev/null

clickhouse --database "$task_database" --insert_deduplication_token analytics-smoke-cross-batch-v1 \
    --date_time_input_format best_effort --query 'INSERT INTO access_events FORMAT JSONEachRow' >/dev/null <<'JSON'
{"metric_version":1,"event_id":"fixed-access-1","occurred_at":"2099-01-01T00:05:00Z","ingested_at":"2099-01-01T01:00:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"one.example.test","path":"/a","client_ip":"2001:db8::1","method":"GET","protocol":"HTTP/2","cache_status":"HIT","status_code":200,"request_bytes":100,"response_bytes":1000,"duration_us":1000}
JSON

physical_access=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT count() FROM access_events WHERE startsWith(event_id, 'fixed-access-')")
logical_access=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT count() FROM access_events FINAL WHERE startsWith(event_id, 'fixed-access-')")
logical_security=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT count() FROM security_events FINAL WHERE startsWith(event_id, 'fixed-security-')")
hourly_access=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT sum(request_count), sum(response_bytes), sumIf(request_count, status_code >= 500) FROM access_hourly_v1 WHERE tenant_id = toUUID('10000000-0000-0000-0000-000000000001')")
hourly_security=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT sum(event_count) FROM security_hourly_v1 WHERE tenant_id = toUUID('10000000-0000-0000-0000-000000000001')")

assert_equal 4 "$physical_access" 'physical retry rows'
assert_equal 3 "$logical_access" 'event id logical deduplication'
assert_equal 2 "$logical_security" 'security retry deduplication'
expected_hourly_access=$(printf '3\t1500\t1')
assert_equal "$expected_hourly_access" "$hourly_access" 'hourly access reconciliation'
assert_equal 2 "$hourly_security" 'hourly security reconciliation'

clickhouse --database "$task_database" --date_time_input_format best_effort \
    --query 'INSERT INTO access_events FORMAT JSONEachRow' >/dev/null <<'JSON'
{"metric_version":1,"event_id":"late-access-1","occurred_at":"2099-01-01T00:01:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"one.example.test","path":"/late","client_ip":"2001:db8::6","method":"GET","protocol":"HTTP/2","cache_status":"MISS","status_code":200,"request_bytes":10,"response_bytes":20,"duration_us":100}
JSON
late_count=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id = 'late-access-1'")
assert_equal 1 "$late_count" 'late arrival materialization'

ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
ANALYTICS_REBUILD_DATABASE="$task_database" \
ANALYTICS_REBUILD_RUN_ID=analytics_smoke \
ANALYTICS_REBUILD_OWNER=analytics_smoke \
    sh "$script_dir/analytics-rebuild-hourly-v1.sh" >/dev/null
rebuilt_access=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT count() FROM access_hourly_facts_v1 FINAL WHERE tenant_id = toUUID('10000000-0000-0000-0000-000000000001')")
assert_equal 4 "$rebuilt_access" 'hourly rebuild fallback'

if clickhouse --database "$task_database" --date_time_input_format best_effort \
    --query 'INSERT INTO access_events FORMAT JSONEachRow' >/dev/null 2>&1 <<'JSON'
{"metric_version":1,"event_id":"negative-byte","occurred_at":"2099-01-01T00:00:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"one.example.test","path":"/","client_ip":"2001:db8::1","method":"GET","protocol":"HTTP/2","cache_status":"MISS","status_code":200,"request_bytes":0,"response_bytes":-1,"duration_us":1}
JSON
then
    fail 'negative response bytes were accepted'
fi

clickhouse --database "$task_database" --query "INSERT INTO access_events
    (metric_version, event_id, occurred_at, tenant_id, site_id, node_id, host, path, client_ip,
     method, protocol, cache_status, status_code, request_bytes, response_bytes, duration_us)
    VALUES (1, 'expired-access', toDateTime64('2000-01-01 00:00:00', 3, 'UTC'),
     toUUID('10000000-0000-0000-0000-000000000001'), toUUID('20000000-0000-0000-0000-000000000001'),
     toUUID('30000000-0000-0000-0000-000000000001'), 'one.example.test', '/', toIPv6('2001:db8::1'),
     'GET', 'HTTP/2', 'MISS', 200, 0, 1, 1)" >/dev/null
clickhouse --database "$task_database" --query 'OPTIMIZE TABLE access_events FINAL' >/dev/null
expired_count=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT count() FROM access_events FINAL WHERE event_id = 'expired-access'")
assert_equal 0 "$expired_count" 'access TTL merge'

capacity_started=$(date +%s)
clickhouse --database "$task_database" --query "INSERT INTO access_events
    (metric_version, event_id, occurred_at, tenant_id, site_id, node_id, host, path, client_ip,
     country_code, carrier, method, protocol, cache_status, status_code, request_bytes, response_bytes, duration_us)
    SELECT
        1,
        concat('capacity-', toString(number)),
        toDateTime64('2099-01-02 00:00:00', 3, 'UTC') + toIntervalMillisecond(number % 3600000),
        toUUID('10000000-0000-0000-0000-000000000099'),
        toUUID('20000000-0000-0000-0000-000000000099'),
        toUUID('30000000-0000-0000-0000-000000000099'),
        'capacity.example.test',
        concat('/object/', toString(number)),
        toIPv6('2001:db8::99'),
        'CN', 'smoke-carrier', 'GET', 'HTTP/2', if(number % 4 = 0, 'MISS', 'HIT'),
        if(number % 20 = 0, 503, 200), 100, 512 + number % 4096, 1000 + number % 10000
    FROM numbers($capacity_rows)" >/dev/null
capacity_count=$(clickhouse --database "$task_database" --format TSVRaw \
    --query "SELECT sum(request_count) FROM access_hourly_v1 WHERE tenant_id = toUUID('10000000-0000-0000-0000-000000000099')")
capacity_elapsed=$(($(date +%s) - capacity_started))
assert_equal "$capacity_rows" "$capacity_count" 'capacity aggregate count'
[ "$capacity_elapsed" -le "$capacity_max_seconds" ] || \
    fail "capacity query exceeded ${capacity_max_seconds}s (actual=${capacity_elapsed}s)"

compressed_bytes=$(clickhouse --param_database "$task_database" --format TSVRaw --query \
    "SELECT sum(bytes_on_disk) FROM system.parts WHERE active AND database = {database:String}")
case "$compressed_bytes" in
    '' | *[!0-9]*) fail 'capacity storage measurement was not numeric' ;;
esac
[ "$compressed_bytes" -gt 0 ] || fail 'capacity storage measurement was zero'

clickhouse --param_database "$task_database" \
    --query 'DROP DATABASE {database:Identifier} SYNC' >/dev/null
remaining=$(clickhouse --param_database "$task_database" --format TSVRaw \
    --query 'SELECT count() FROM system.databases WHERE name = {database:String}')
assert_equal 0 "$remaining" 'task database cleanup'
trap - EXIT HUP INT TERM

printf 'analytics smoke passed: logical_access=%s logical_security=%s capacity_rows=%s query_seconds=%s compressed_bytes=%s\n' \
    "$logical_access" "$logical_security" "$capacity_rows" "$capacity_elapsed" "$compressed_bytes"
