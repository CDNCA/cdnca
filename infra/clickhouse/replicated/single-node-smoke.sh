#!/bin/sh
# Execute the ON CLUSTER mirror for real on one ClickHouse server with embedded Keeper:
#   1. migrations/*.up.sql into database `single`, replicated/*.up.sql into `repl` (once each, in order);
#   2. every MergeTree in `repl` is Replicated and writable, and both databases end with the same
#      tables/views (create query with the Replicated prefix and Keeper arguments removed) and columns;
#   3. a counted security event reaches security_hourly_v1.security_requests (head 025);
#   4. replicated/*.down.sql in reverse order empties `repl`, and up again gives the same schema.
# Reuses the local clickhouse/clickhouse-server image; one container, removed on exit.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
single_dir="$here/../migrations"
image=${CDNCA_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:25.3.6.56-alpine}
container="cdnca-ch-replicated-$$"

cleanup() { docker rm -fv "$container" >/dev/null 2>&1 || :; }
fail() { printf 'replicated single-node smoke failed: %s\n' "$1" >&2; exit 1; }
trap cleanup EXIT HUP INT TERM

docker image inspect "$image" >/dev/null 2>&1 || fail "image $image not present locally (not pulling)"
ch() { docker exec -i "$container" clickhouse-client "$@"; }

docker run -d --rm --name "$container" -e CLICKHOUSE_SKIP_USER_SETUP=1 \
    -v "$here/testdata/single-node.xml:/etc/clickhouse-server/config.d/single-node.xml:ro" "$image" >/dev/null
attempts=0
until ch --query "SELECT count() FROM system.zookeeper WHERE path = '/'" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 120 ] || { docker logs "$container" >&2 || :; fail 'server or embedded Keeper not ready'; }
    sleep 1
done

ch --query 'CREATE DATABASE single'
ch --query 'CREATE DATABASE repl ON CLUSTER cdnca_analytics' >/dev/null

apply() {
    database=$1
    shift
    for file in "$@"; do
        ch --database "$database" --multiquery <"$file" >/dev/null || fail "$database: $(basename "$file")"
    done
}
up_files() { find "$1" -maxdepth 1 -name '*.up.sql' | sort; }
down_files() { find "$1" -maxdepth 1 -name '*.down.sql' | sort -r; }

# shellcheck disable=SC2046
apply single $(up_files "$single_dir")
# shellcheck disable=SC2046
apply repl $(up_files "$here")

fingerprint() {
    ch --param_db "$1" --format TSVRaw --multiquery --query "
        SELECT name, engine_family, normalized FROM (
            SELECT name,
                   replaceRegexpOne(engine, '^Replicated', '') AS engine_family,
                   replaceRegexpAll(
                       replaceRegexpOne(
                           replaceRegexpOne(create_table_query,
                               'Replicated(\\\\w*)MergeTree\\\\(''/clickhouse/tables/\\\\{shard\\\\}/[^/'']+/[^'']+'', ''\\\\{replica\\\\}''(, )?',
                               '\\\\1MergeTree('),
                           'MergeTree\\\\(\\\\)', 'MergeTree'),
                       concat('\\\\b', {db:String}, '\\\\.'), 'DB.') AS normalized
            FROM system.tables WHERE database = {db:String})
        ORDER BY name;
        SELECT table, type, concat(toString(position), ' ', name, ' ', default_kind, ' ', default_expression, ' ', compression_codec)
        FROM system.columns WHERE database = {db:String}
        ORDER BY 1, 3"
}

single_schema=$(fingerprint single)
repl_schema=$(fingerprint repl)
[ -n "$single_schema" ] || fail 'empty single-node schema'
if [ "$single_schema" != "$repl_schema" ]; then
    printf '%s\n' "$single_schema" >"${TMPDIR:-/tmp}/ch-replicated-single.$$"
    printf '%s\n' "$repl_schema" >"${TMPDIR:-/tmp}/ch-replicated-repl.$$"
    diff "${TMPDIR:-/tmp}/ch-replicated-single.$$" "${TMPDIR:-/tmp}/ch-replicated-repl.$$" | head -40 >&2 || :
    rm -f "${TMPDIR:-/tmp}/ch-replicated-single.$$" "${TMPDIR:-/tmp}/ch-replicated-repl.$$"
    fail 'single-node and replicated schemas differ'
fi
tables=$(ch --query "SELECT count() FROM system.tables WHERE database = 'repl'")

non_replicated=$(ch --query "SELECT count() FROM system.tables WHERE database = 'repl' AND engine LIKE '%MergeTree' AND engine NOT LIKE 'Replicated%'")
[ "$non_replicated" = 0 ] || fail "$non_replicated non-replicated MergeTree tables"
merge_tree=$(ch --query "SELECT count() FROM system.tables WHERE database = 'repl' AND engine LIKE 'Replicated%MergeTree'")
healthy=$(ch --query "SELECT count() FROM system.replicas WHERE database = 'repl' AND NOT is_readonly AND zookeeper_path LIKE '/clickhouse/tables/01/repl/%'")
[ "$merge_tree" = "$healthy" ] && [ "$merge_tree" -gt 0 ] || fail "replicas healthy=$healthy of $merge_tree"

ch --database repl --date_time_input_format best_effort --query 'INSERT INTO security_events FORMAT JSONEachRow' >/dev/null <<'JSON'
{"metric_version":1,"event_id":"replicated-cc-1","occurred_at":"2099-01-01T00:05:00Z","ingested_at":"2099-01-01T00:06:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"replicated.example.test","path":"/","client_ip":"2001:db8::1","event_type":"cc","action":"challenge","severity":"medium","status_code":0,"request_bytes":0,"response_bytes":0,"event_count":5}
JSON
counted=$(ch --database repl --format TSVRaw --query "SELECT event_count, security_requests FROM security_hourly_v1 WHERE event_type = 'cc'")
[ "$counted" = "$(printf '1\t5')" ] || fail "security_hourly_v1 counted=$counted"
state=$(ch --database repl --query "SELECT argMaxMerge(latest_count_state) FROM security_event_count_state_v1 WHERE event_id = 'replicated-cc-1'")
[ "$state" = 5 ] || fail "security_event_count_state_v1=$state"

# shellcheck disable=SC2046
apply repl $(down_files "$here")
remaining=$(ch --query "SELECT count() FROM system.tables WHERE database = 'repl'")
[ "$remaining" = 0 ] || fail "$remaining objects left after replicated down chain"
# shellcheck disable=SC2046
apply repl $(up_files "$here")
[ "$(fingerprint repl)" = "$single_schema" ] || fail 'replicated up/down/up schema drift'

ch --query 'DROP DATABASE repl ON CLUSTER cdnca_analytics SYNC' >/dev/null
printf 'replicated single-node smoke passed: %s migrations, %s objects (%s Replicated*MergeTree) identical to single node, 025 counting, down/up\n' \
    "$(up_files "$here" | wc -l | tr -d ' ')" "$tables" "$merge_tree"
