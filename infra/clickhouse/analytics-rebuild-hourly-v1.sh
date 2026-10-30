#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
env_file=${ENV_FILE:-$repo_root/infra/env/development.env}
clickhouse_container=${ANALYTICS_CLICKHOUSE_CONTAINER:-}
database=${ANALYTICS_REBUILD_DATABASE:-}
run_id=${ANALYTICS_REBUILD_RUN_ID:-}
owner=${ANALYTICS_REBUILD_OWNER:-}
lock_token=${ANALYTICS_REBUILD_LOCK_TOKEN:-}
fail_after_backfill=${ANALYTICS_REBUILD_FAIL_AFTER_BACKFILL:-0}
fail_after_access_exchange=${ANALYTICS_REBUILD_FAIL_AFTER_ACCESS_EXCHANGE:-0}
lock_table=analytics_rebuild_hourly_v1_lock

fail() {
    printf 'analytics hourly rebuild failed: %s\n' "$1" >&2
    exit 1
}

case "$database" in
    ''|[0-9]*|*[!A-Za-z0-9_]*) fail 'ANALYTICS_REBUILD_DATABASE must be a ClickHouse identifier' ;;
esac
case "$run_id" in
    ''|*[!A-Za-z0-9_]*) fail 'ANALYTICS_REBUILD_RUN_ID must contain only letters, digits, and underscores' ;;
esac
[ "${#run_id}" -le 40 ] || fail 'ANALYTICS_REBUILD_RUN_ID is too long'
case "$owner" in
    ''|*[!A-Za-z0-9._:-]*) fail 'ANALYTICS_REBUILD_OWNER contains unsupported characters' ;;
esac
[ "${#owner}" -le 128 ] || fail 'ANALYTICS_REBUILD_OWNER is too long'
if [ -z "$lock_token" ]; then
    random_token=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
    [ "${#random_token}" = 24 ] || fail 'could not generate rebuild lock token'
    lock_token="auto_$$_${random_token}"
fi
case "$lock_token" in
    *[!A-Za-z0-9_]*) fail 'ANALYTICS_REBUILD_LOCK_TOKEN must contain only letters, digits, and underscores' ;;
esac
[ "${#lock_token}" -le 128 ] || fail 'ANALYTICS_REBUILD_LOCK_TOKEN is too long'
case "$fail_after_backfill" in
    0|1) ;;
    *) fail 'ANALYTICS_REBUILD_FAIL_AFTER_BACKFILL must be 0 or 1' ;;
esac
case "$fail_after_access_exchange" in
    0|1) ;;
    *) fail 'ANALYTICS_REBUILD_FAIL_AFTER_ACCESS_EXCHANGE must be 0 or 1' ;;
esac

run_marker="analytics_rebuild_${run_id}_marker"
access_shadow="access_hourly_facts_${run_id}_shadow"
security_shadow="security_hourly_facts_${run_id}_shadow"
access_catchup="access_hourly_${run_id}_catchup"
security_catchup="security_hourly_${run_id}_catchup"

clickhouse() {
    if [ -n "$clickhouse_container" ]; then
        docker exec -i "$clickhouse_container" clickhouse-client "$@"
        return
    fi
    docker compose --env-file "$env_file" -f "$repo_root/compose.yaml" exec -T clickhouse \
        sh -c 'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' \
        analytics-hourly-rebuild "$@"
}

release_lock() {
	clickhouse --database "$database" --param_lock_token "$lock_token" --multiquery <<SQL >/dev/null
SELECT throwIf(
    (SELECT comment FROM system.tables WHERE database = currentDatabase() AND name = '$lock_table') != {lock_token:String},
    'analytics rebuild lock token does not match'
);
DROP TABLE $lock_table SYNC;
SQL
}

attempt=0
while :; do
	clickhouse --database "$database" --query \
		"CREATE TABLE IF NOT EXISTS $lock_table (token UInt8) ENGINE = TinyLog COMMENT '$lock_token'" >/dev/null
	lock_owner=$(clickhouse --database "$database" --format TSVRaw --query \
		"SELECT comment FROM system.tables WHERE database = currentDatabase() AND name = '$lock_table'")
	[ "$lock_owner" = "$lock_token" ] && break
    attempt=$((attempt + 1))
    [ "$attempt" -lt 240 ] || fail "rebuild lock is owned by $lock_owner"
    sleep 0.25
done

marker_exists=$(clickhouse --database "$database" --param_name "$run_marker" --format TSVRaw --query \
    'SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = {name:String}')
if [ "$marker_exists" = 1 ]; then
	marker_state=$(clickhouse --database "$database" --param_run_marker "$run_marker" --format TSVRaw --query \
		'SELECT concat(toString(uniqExact(tuple(owner, lock_token))), char(9), any(owner), char(9), any(lock_token)) FROM {run_marker:Identifier}')
	if [ "$marker_state" != "$(printf '1\t%s\t%s' "$owner" "$lock_token")" ]; then
		release_lock || :
		fail 'existing run marker owner or token does not match'
	fi
	clickhouse --database "$database" \
		--param_owner "$owner" \
		--param_lock_token "$lock_token" \
        --param_run_marker "$run_marker" \
        --param_access_shadow "$access_shadow" \
        --param_security_shadow "$security_shadow" \
        --param_access_catchup "$access_catchup" \
        --param_security_catchup "$security_catchup" \
        --multiquery < "$script_dir/rebuild-hourly-cleanup-v1.sql" >/dev/null
fi

sed \
    -e "s/TO {access_shadow:Identifier}/TO $access_shadow/" \
    -e "s/TO {security_shadow:Identifier}/TO $security_shadow/" \
    "$script_dir/rebuild-hourly-v1.sql" | clickhouse --database "$database" \
	--param_owner "$owner" \
	--param_lock_token "$lock_token" \
    --param_run_marker "$run_marker" \
    --param_access_shadow "$access_shadow" \
    --param_security_shadow "$security_shadow" \
    --param_access_catchup "$access_catchup" \
    --param_security_catchup "$security_catchup" \
    --param_fail_after_backfill "$fail_after_backfill" \
    --param_fail_after_access_exchange "$fail_after_access_exchange" \
    --multiquery >/dev/null

release_lock
