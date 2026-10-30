#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
env_file=${ENV_FILE:-$repo_root/infra/env/development.env}
clickhouse_container=${ANALYTICS_CLICKHOUSE_CONTAINER:-}
task_database="cdnca_rebuild_smoke_$(date +%Y%m%d%H%M%S)_$$"

clickhouse() {
    if [ -n "$clickhouse_container" ]; then
        docker exec -i "$clickhouse_container" clickhouse-client "$@"
        return
    fi
    docker compose --env-file "$env_file" -f "$repo_root/compose.yaml" exec -T clickhouse \
        sh -c 'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' \
        analytics-rebuild-smoke "$@"
}

run_rebuild() {
    run_id=$1
    ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
    ANALYTICS_REBUILD_DATABASE="$task_database" \
    ANALYTICS_REBUILD_RUN_ID="$run_id" \
    ANALYTICS_REBUILD_OWNER="atomic_smoke_$$" \
        sh "$script_dir/analytics-rebuild-hourly-v1.sh"
}

cleanup() {
    clickhouse --param_database "$task_database" \
        --query 'DROP DATABASE IF EXISTS {database:Identifier} SYNC' >/dev/null 2>&1 || :
}

fail() {
    printf 'analytics rebuild smoke failed: %s\n' "$1" >&2
    exit 1
}

assert_equal() {
    expected=$1
    actual=$2
    label=$3
    [ "$actual" = "$expected" ] || fail "$label expected=$expected actual=$actual"
}

trap cleanup EXIT HUP INT TERM
clickhouse --param_database "$task_database" --query 'CREATE DATABASE {database:Identifier}' >/dev/null
for migration in 001_analytics.up.sql 002_analytics_authority_capture.up.sql 003_analytics_hourly_rollup.up.sql 004_analytics_version_evidence.up.sql 025_security_event_count.up.sql; do
    clickhouse --database "$task_database" --multiquery < "$script_dir/migrations/$migration" >/dev/null
done

clickhouse --database "$task_database" --query "INSERT INTO access_hourly_facts_v1
    (metric_version, tenant_id, event_id, occurred_at, hour, site_id, node_id, status_code,
     request_bytes, response_bytes, ingested_at)
    VALUES (1, toUUID('10000000-0000-0000-0000-000000000001'), 'older-than-raw-ttl',
     now64(3, 'UTC') - INTERVAL 120 DAY, toStartOfHour(now64(3, 'UTC') - INTERVAL 120 DAY, 'UTC'),
     toUUID('20000000-0000-0000-0000-000000000001'), toUUID('30000000-0000-0000-0000-000000000001'),
     200, 10, 20, now64(3, 'UTC') - INTERVAL 120 DAY)" >/dev/null
clickhouse --database "$task_database" --query "INSERT INTO access_events
    (metric_version, event_id, occurred_at, tenant_id, site_id, node_id, host, path, client_ip,
     method, protocol, cache_status, status_code, request_bytes, response_bytes, duration_us)
    VALUES (1, 'within-raw-ttl', now64(3, 'UTC') - INTERVAL 1 DAY,
     toUUID('10000000-0000-0000-0000-000000000001'), toUUID('20000000-0000-0000-0000-000000000001'),
     toUUID('30000000-0000-0000-0000-000000000001'), 'rebuild.example.test', '/', toIPv6('2001:db8::1'),
     'GET', 'HTTP/2', 'MISS', 200, 11, 22, 100)" >/dev/null
clickhouse --database "$task_database" --query "INSERT INTO security_hourly_facts_v1
    (metric_version, tenant_id, event_id, occurred_at, hour, site_id, node_id, event_type, action,
     request_bytes, response_bytes, ingested_at)
    VALUES (1, toUUID('10000000-0000-0000-0000-000000000001'), 'security-older-than-raw-ttl',
     now64(3, 'UTC') - INTERVAL 120 DAY, toStartOfHour(now64(3, 'UTC') - INTERVAL 120 DAY, 'UTC'),
     toUUID('20000000-0000-0000-0000-000000000001'), toUUID('30000000-0000-0000-0000-000000000001'),
     'waf', 'block', 10, 20, now64(3, 'UTC') - INTERVAL 120 DAY)" >/dev/null
clickhouse --database "$task_database" --query "INSERT INTO security_events
    (metric_version, event_id, occurred_at, tenant_id, site_id, node_id, host, path, client_ip,
     event_type, action, severity, status_code, request_bytes, response_bytes)
    VALUES (1, 'security-within-raw-ttl', now64(3, 'UTC') - INTERVAL 1 DAY,
     toUUID('10000000-0000-0000-0000-000000000001'), toUUID('20000000-0000-0000-0000-000000000001'),
     toUUID('30000000-0000-0000-0000-000000000001'), 'rebuild.example.test', '/', toIPv6('2001:db8::1'),
     'waf', 'block', 'high', 403, 11, 22)" >/dev/null
before=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id IN ('older-than-raw-ttl','within-raw-ttl')")
assert_equal 2 "$before" 'rebuild fixture'
security_before=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM security_hourly_facts_v1 FINAL WHERE event_id IN ('security-older-than-raw-ttl','security-within-raw-ttl')")
assert_equal 2 "$security_before" 'security rebuild fixture'

if clickhouse --database "$task_database" --multiquery >/dev/null 2>&1 <<'SQL'
CREATE TABLE access_hourly_facts_v1_rebuild_failure AS access_hourly_facts_v1;
INSERT INTO access_hourly_facts_v1_rebuild_failure SELECT * FROM access_hourly_facts_v1 FINAL;
SELECT throwIf(1, 'task-owned rebuild failure before swap');
EXCHANGE TABLES access_hourly_facts_v1 AND access_hourly_facts_v1_rebuild_failure;
SQL
then
    fail 'injected pre-swap rebuild failure unexpectedly succeeded'
fi
after_failure=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id IN ('older-than-raw-ttl','within-raw-ttl')")
assert_equal 2 "$after_failure" 'mid-rebuild failure preserved production facts'
clickhouse --database "$task_database" --query 'DROP TABLE IF EXISTS access_hourly_facts_v1_rebuild_failure SYNC' >/dev/null

run_rebuild first >/dev/null
after_rebuild=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id IN ('older-than-raw-ttl','within-raw-ttl')")
assert_equal 2 "$after_rebuild" 'atomic rebuild retained old history and reconstructed raw horizon'
security_after_rebuild=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM security_hourly_facts_v1 FINAL WHERE event_id IN ('security-older-than-raw-ttl','security-within-raw-ttl')")
assert_equal 2 "$security_after_rebuild" 'security rebuild retained history outside 90-day raw TTL'
run_rebuild retry >/dev/null
after_retry=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id IN ('older-than-raw-ttl','within-raw-ttl')")
assert_equal 2 "$after_retry" 'idempotent rebuild retry'

clickhouse --database "$task_database" --query "INSERT INTO access_events
    (metric_version, event_id, occurred_at, tenant_id, site_id, node_id, host, path, client_ip,
     method, protocol, cache_status, status_code, request_bytes, response_bytes, duration_us)
    VALUES (1, 'post-rebuild-access', now64(3, 'UTC'),
     toUUID('10000000-0000-0000-0000-000000000001'), toUUID('20000000-0000-0000-0000-000000000001'),
     toUUID('30000000-0000-0000-0000-000000000001'), 'rebuild.example.test', '/', toIPv6('2001:db8::1'),
     'GET', 'HTTP/2', 'MISS', 200, 1, 2, 10)" >/dev/null
clickhouse --database "$task_database" --query "INSERT INTO security_events
    (metric_version, event_id, occurred_at, tenant_id, site_id, node_id, host, path, client_ip,
     event_type, action, severity, status_code, request_bytes, response_bytes)
    VALUES (1, 'post-rebuild-security', now64(3, 'UTC'),
     toUUID('10000000-0000-0000-0000-000000000001'), toUUID('20000000-0000-0000-0000-000000000001'),
     toUUID('30000000-0000-0000-0000-000000000001'), 'rebuild.example.test', '/', toIPv6('2001:db8::1'),
     'waf', 'block', 'high', 403, 1, 2)" >/dev/null
post_rebuild=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT
       (SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id='post-rebuild-access'),
       (SELECT count() FROM security_hourly_facts_v1 FINAL WHERE event_id='post-rebuild-security')")
assert_equal "$(printf '1\t1')" "$post_rebuild" 'materialized views remained bound after table exchange'

cleanup
trap - EXIT HUP INT TERM
printf '%s\n' 'analytics rebuild smoke passed: dual-TTL history, failure atomicity, raw reconstruction, MV continuity, retry'
