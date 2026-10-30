#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
env_file=${ENV_FILE:-$repo_root/infra/env/development.env}
clickhouse_container=${ANALYTICS_CLICKHOUSE_CONTAINER:-}
task_database="cdnca_reviewer_round2_$(date +%Y%m%d%H%M%S)_$$"
task_root=${TMPDIR:-/tmp}/cdnca_obs_a_round2_$$
same_owner_waiter_pid=

clickhouse() {
    if [ -n "$clickhouse_container" ]; then
        docker exec -i "$clickhouse_container" clickhouse-client "$@"
        return
    fi
    docker compose --env-file "$env_file" -f "$repo_root/compose.yaml" exec -T clickhouse \
        sh -c 'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' \
        analytics-reviewer-round2 "$@"
}

cleanup() {
	if [ -n "$same_owner_waiter_pid" ]; then
		kill "$same_owner_waiter_pid" >/dev/null 2>&1 || :
		wait "$same_owner_waiter_pid" >/dev/null 2>&1 || :
	fi
	clickhouse --param_database "$task_database" \
        --query 'DROP DATABASE IF EXISTS {database:Identifier} SYNC' >/dev/null 2>&1 || :
    rm -rf "$task_root"
}

fail() {
    printf 'analytics reviewer round2 smoke failed: %s\n' "$1" >&2
    exit 1
}

assert_equal() {
    expected=$1
    actual=$2
    label=$3
    [ "$actual" = "$expected" ] || fail "$label expected=$expected actual=$actual"
}

run_rebuild() {
	run_id=$1
	owner=$2
	lock_token=$3
	ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
	ANALYTICS_REBUILD_DATABASE="$task_database" \
	ANALYTICS_REBUILD_RUN_ID="$run_id" \
	ANALYTICS_REBUILD_OWNER="$owner" \
	ANALYTICS_REBUILD_LOCK_TOKEN="$lock_token" \
		sh "$script_dir/analytics-rebuild-hourly-v1.sh"
}

trap cleanup EXIT HUP INT TERM
mkdir -m 700 "$task_root"
clickhouse --param_database "$task_database" --query 'CREATE DATABASE {database:Identifier}' >/dev/null
for migration in 001_analytics.up.sql 002_analytics_authority_capture.up.sql; do
    clickhouse --database "$task_database" --multiquery < "$script_dir/migrations/$migration" >/dev/null
done

clickhouse --database "$task_database" --query "INSERT INTO access_events
    (metric_version,event_id,occurred_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,cache_status,status_code,request_bytes,response_bytes,duration_us)
    VALUES (1,'old-reader',now64(3,'UTC')-INTERVAL 1 DAY,
      toUUID('10000000-0000-0000-0000-000000000001'),toUUID('20000000-0000-0000-0000-000000000001'),
      toUUID('30000000-0000-0000-0000-000000000001'),'cutover.example.test','/',toIPv6('2001:db8::1'),
      'GET','HTTP/2','HIT',200,1,2,10)" >/dev/null
clickhouse --database "$task_database" --query "INSERT INTO security_events
    (metric_version,event_id,occurred_at,tenant_id,site_id,node_id,host,path,client_ip,event_type,action,severity,status_code,request_bytes,response_bytes)
    VALUES (1,'split-security-reader',now64(3,'UTC')-INTERVAL 1 DAY,
      toUUID('10000000-0000-0000-0000-000000000001'),toUUID('20000000-0000-0000-0000-000000000001'),
      toUUID('30000000-0000-0000-0000-000000000001'),'cutover.example.test','/',toIPv6('2001:db8::1'),
      'waf','block','high',403,1,2)" >/dev/null
old_count=$(clickhouse --database "$task_database" --format TSVRaw --query 'SELECT sum(request_count) FROM access_hourly_v1')
assert_equal 1 "$old_count" 'old raw reader baseline'

awk '/CREATE OR REPLACE VIEW access_hourly_v1/{exit} {print}' \
    "$script_dir/migrations/003_analytics_hourly_rollup.up.sql" | \
    clickhouse --database "$task_database" --multiquery >/dev/null
if clickhouse --database "$task_database" --query "SELECT throwIf(1,'injected backfill failure before cutover')" >/dev/null 2>&1; then
    fail 'injected migration failure unexpectedly succeeded'
fi
after_failure=$(clickhouse --database "$task_database" --format TSVRaw --query 'SELECT sum(request_count) FROM access_hourly_v1')
assert_equal 1 "$after_failure" 'old reader continuity after failed backfill'
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/003_analytics_hourly_rollup.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/004_analytics_version_evidence.up.sql" >/dev/null
after_cutover=$(clickhouse --database "$task_database" --format TSVRaw --query 'SELECT sum(request_count) FROM access_hourly_v1')
assert_equal 1 "$after_cutover" 'exact standalone final cutover'

run_rebuild concurrent_a owner_a concurrent_a_token >"$task_root/a.log" 2>&1 &
first_pid=$!
run_rebuild concurrent_b owner_b concurrent_b_token >"$task_root/b.log" 2>&1 &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
concurrent_count=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id='old-reader'")
assert_equal 1 "$concurrent_count" 'two concurrent rebuilds'

if ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
	ANALYTICS_REBUILD_DATABASE="$task_database" \
	ANALYTICS_REBUILD_RUN_ID=same_owner_active \
	ANALYTICS_REBUILD_OWNER=shared_owner \
	ANALYTICS_REBUILD_LOCK_TOKEN=same_owner_active_token \
	ANALYTICS_REBUILD_FAIL_AFTER_BACKFILL=1 \
		sh "$script_dir/analytics-rebuild-hourly-v1.sh" >/dev/null 2>&1; then
	fail 'same-owner crash fixture unexpectedly succeeded'
fi
run_rebuild same_owner_waiter shared_owner same_owner_waiter_token >"$task_root/same-owner-waiter.log" 2>&1 &
same_owner_waiter_pid=$!
sleep 1
if ! kill -0 "$same_owner_waiter_pid" >/dev/null 2>&1; then
	fail 'same-owner waiter bypassed the active invocation token'
fi
if ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
	ANALYTICS_REBUILD_DATABASE="$task_database" \
	ANALYTICS_REBUILD_RUN_ID=same_owner_active \
	ANALYTICS_REBUILD_OWNER=shared_owner \
	ANALYTICS_REBUILD_LOCK_TOKEN=same_owner_waiter_token \
		sh "$script_dir/analytics-rebuild-hourly-cleanup-v1.sh" >/dev/null 2>&1; then
	fail 'same owner with a different token cleaned an active invocation'
fi
same_owner_marker=$(clickhouse --database "$task_database" --format TSVRaw --query \
	"SELECT concat(any(owner), char(9), any(lock_token)) FROM analytics_rebuild_same_owner_active_marker")
assert_equal "$(printf 'shared_owner\tsame_owner_active_token')" "$same_owner_marker" 'same-owner marker ownership'
ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
	ANALYTICS_REBUILD_DATABASE="$task_database" \
	ANALYTICS_REBUILD_RUN_ID=same_owner_active \
	ANALYTICS_REBUILD_OWNER=shared_owner \
	ANALYTICS_REBUILD_LOCK_TOKEN=same_owner_active_token \
		sh "$script_dir/analytics-rebuild-hourly-cleanup-v1.sh" >/dev/null
wait "$same_owner_waiter_pid"
same_owner_waiter_pid=

if ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
    ANALYTICS_REBUILD_DATABASE="$task_database" \
	ANALYTICS_REBUILD_RUN_ID=crashed_run \
	ANALYTICS_REBUILD_OWNER=crashed_owner \
	ANALYTICS_REBUILD_LOCK_TOKEN=crashed_token \
    ANALYTICS_REBUILD_FAIL_AFTER_BACKFILL=1 \
        sh "$script_dir/analytics-rebuild-hourly-v1.sh" >/dev/null 2>&1; then
    fail 'mid-phase rebuild fault unexpectedly succeeded'
fi
if ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
    ANALYTICS_REBUILD_DATABASE="$task_database" \
	ANALYTICS_REBUILD_RUN_ID=crashed_run \
	ANALYTICS_REBUILD_OWNER=wrong_owner \
	ANALYTICS_REBUILD_LOCK_TOKEN=wrong_token \
        sh "$script_dir/analytics-rebuild-hourly-cleanup-v1.sh" >/dev/null 2>&1; then
    fail 'wrong owner cleaned stale rebuild objects'
fi
ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
ANALYTICS_REBUILD_DATABASE="$task_database" \
ANALYTICS_REBUILD_RUN_ID=crashed_run \
ANALYTICS_REBUILD_OWNER=crashed_owner \
	ANALYTICS_REBUILD_LOCK_TOKEN=crashed_token \
	sh "$script_dir/analytics-rebuild-hourly-cleanup-v1.sh" >/dev/null
run_rebuild retry_after_cleanup retry_owner retry_token >/dev/null

if ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
    ANALYTICS_REBUILD_DATABASE="$task_database" \
	ANALYTICS_REBUILD_RUN_ID=split_exchange_run \
	ANALYTICS_REBUILD_OWNER=split_exchange_owner \
	ANALYTICS_REBUILD_LOCK_TOKEN=split_exchange_crash_token \
    ANALYTICS_REBUILD_FAIL_AFTER_ACCESS_EXCHANGE=1 \
        sh "$script_dir/analytics-rebuild-hourly-v1.sh" >/dev/null 2>&1; then
    fail 'split-exchange rebuild fault unexpectedly succeeded'
fi
split_failure_state=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT
       (SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id='old-reader'),
       (SELECT count() FROM security_hourly_facts_v1 FINAL WHERE event_id='split-security-reader')")
assert_equal "$(printf '1\t1')" "$split_failure_state" 'split-exchange failure reader continuity'
ANALYTICS_CLICKHOUSE_CONTAINER="$clickhouse_container" \
	ANALYTICS_REBUILD_DATABASE="$task_database" \
	ANALYTICS_REBUILD_RUN_ID=split_exchange_run \
	ANALYTICS_REBUILD_OWNER=split_exchange_owner \
	ANALYTICS_REBUILD_LOCK_TOKEN=split_exchange_crash_token \
		sh "$script_dir/analytics-rebuild-hourly-cleanup-v1.sh" >/dev/null
run_rebuild split_exchange_run split_exchange_owner split_exchange_retry_token >/dev/null
split_recovered_state=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT
       (SELECT count() FROM access_hourly_facts_v1 FINAL WHERE event_id='old-reader'),
       (SELECT count() FROM security_hourly_facts_v1 FINAL WHERE event_id='split-security-reader')")
assert_equal "$(printf '1\t1')" "$split_recovered_state" 'split-exchange restart exact final state'

remaining=$(clickhouse --database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM system.tables WHERE database=currentDatabase() AND
       (name LIKE 'analytics_rebuild_%' OR name LIKE '%_rebuild_%')")
assert_equal 0 "$remaining" 'stale run cleanup'

cleanup
trap - EXIT HUP INT TERM
printf '%s\n' 'analytics reviewer round2 smoke passed: migration continuity, concurrent rebuild, crash ownership, split-exchange restart, cleanup, retry'
