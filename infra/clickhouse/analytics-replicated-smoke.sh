#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
task_suffix="$(date +%Y%m%d%H%M%S)_$$"
task_network="cdnca-obs-a-net-$task_suffix"
keeper_container="cdnca-obs-a-keeper-$task_suffix"
replica_one_container="cdnca-obs-a-ch1-$task_suffix"
replica_two_container="cdnca-obs-a-ch2-$task_suffix"
clickhouse_image=${CDNCA_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:25.3.6.56-alpine}
task_database="cdnca_obs_a_$task_suffix"

cleanup() {
    docker rm -fv "$replica_one_container" "$replica_two_container" "$keeper_container" >/dev/null 2>&1 || :
    docker network rm "$task_network" >/dev/null 2>&1 || :
}

fail() {
    printf 'replicated analytics smoke failed: %s\n' "$1" >&2
    exit 1
}

assert_equal() {
    expected=$1
    actual=$2
    label=$3
    [ "$actual" = "$expected" ] || fail "$label expected=$expected actual=$actual"
}

clickhouse() {
    container=$1
    shift
    docker exec -i "$container" clickhouse-client "$@"
}

wait_clickhouse() {
    container=$1
    attempts=0
    until clickhouse "$container" --query 'SELECT 1' >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 120 ] || {
            docker logs "$container" >&2 || :
            fail "$container did not become ready"
        }
        sleep 1
    done
}

wait_keeper() {
    attempts=0
    until docker exec "$keeper_container" clickhouse-keeper-client --host 127.0.0.1 --port 9181 \
        --query 'ruok' 2>/dev/null | grep -q imok; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 120 ] || {
            docker logs "$keeper_container" >&2 || :
            fail 'Keeper did not become ready'
        }
        sleep 1
    done
}

wait_replicas() {
    for container in "$replica_one_container" "$replica_two_container"; do
        clickhouse "$container" --database "$task_database" --multiquery <<'SQL' >/dev/null
SYSTEM SYNC REPLICA access_events;
SYSTEM SYNC REPLICA security_events;
SYSTEM SYNC REPLICA access_hourly_facts_v1;
SYSTEM SYNC REPLICA security_hourly_facts_v1;
SQL
    done
}

wait_evidence_replicas() {
    for container in "$replica_one_container" "$replica_two_container"; do
        clickhouse "$container" --database "$task_database" --multiquery <<'SQL' >/dev/null
SYSTEM SYNC REPLICA access_version_evidence_v1;
SYSTEM SYNC REPLICA security_version_evidence_v1;
SQL
    done
}

wait_raw_replicas() {
    for container in "$replica_one_container" "$replica_two_container"; do
        clickhouse "$container" --database "$task_database" --multiquery <<'SQL' >/dev/null
SYSTEM SYNC REPLICA access_events;
SYSTEM SYNC REPLICA security_events;
SQL
    done
}

schema_fingerprint() {
    clickhouse "$1" --param_database "$task_database" --format TSVRaw --query \
        "SELECT arrayStringConcat(groupArray(concat(name, ':', normalized)), '\n')
         FROM (
             SELECT name, normalizeQuery(create_table_query) AS normalized
             FROM system.tables WHERE database = {database:String} ORDER BY name
         )"
}

replicated_up() {
    for file in $(find "$script_dir/replicated" -maxdepth 1 -name '*.up.sql' | sort); do cat "$file"; printf '\n'; done
}

replicated_down() {
    for file in $(find "$script_dir/replicated" -maxdepth 1 -name '*.down.sql' | sort -r); do cat "$file"; printf '\n'; done
}

trap cleanup EXIT HUP INT TERM
cleanup

docker network create "$task_network" >/dev/null
docker run -d --name "$keeper_container" --hostname cdnca-obs-a-keeper \
    --network "$task_network" --network-alias cdnca-obs-a-keeper \
    -v "$script_dir/replicated/testdata/keeper.xml:/etc/clickhouse-keeper/keeper.xml:ro" \
    "$clickhouse_image" clickhouse keeper --config-file=/etc/clickhouse-keeper/keeper.xml >/dev/null
wait_keeper

docker run -d --name "$replica_one_container" --hostname cdnca-obs-a-ch-replica-1 \
    --network "$task_network" --network-alias cdnca-obs-a-ch-replica-1 \
    -e CLICKHOUSE_SKIP_USER_SETUP=1 \
    -v "$script_dir/replicated/testdata/replica-1.xml:/etc/clickhouse-server/config.d/replica.xml:ro" \
    "$clickhouse_image" >/dev/null
docker run -d --name "$replica_two_container" --hostname cdnca-obs-a-ch-replica-2 \
    --network "$task_network" --network-alias cdnca-obs-a-ch-replica-2 \
    -e CLICKHOUSE_SKIP_USER_SETUP=1 \
    -v "$script_dir/replicated/testdata/replica-2.xml:/etc/clickhouse-server/config.d/replica.xml:ro" \
    "$clickhouse_image" >/dev/null
wait_clickhouse "$replica_one_container"
wait_clickhouse "$replica_two_container"

clickhouse "$replica_one_container" --query \
    "CREATE DATABASE $task_database ON CLUSTER cdnca_analytics" >/dev/null
replicated_up 2>/dev/null | awk '/CREATE TABLE IF NOT EXISTS access_hourly_facts_v1 ON CLUSTER/{exit} {print}' | \
    clickhouse "$replica_one_container" --database "$task_database" --multiquery >/dev/null

clickhouse "$replica_one_container" --database "$task_database" --date_time_input_format best_effort \
    --query 'INSERT INTO access_events FORMAT JSONEachRow' >/dev/null <<'JSON'
{"metric_version":1,"event_id":"replicated-old-reader","occurred_at":"2099-01-01T00:01:00Z","ingested_at":"2099-01-01T00:02:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"replicated.example.test","path":"/continuity","client_ip":"2001:db8::1","method":"GET","protocol":"HTTP/2","cache_status":"HIT","status_code":200,"request_bytes":1,"response_bytes":2,"duration_us":10}
JSON
wait_raw_replicas
for container in "$replica_one_container" "$replica_two_container"; do
    old_reader=$(clickhouse "$container" --database "$task_database" --format TSVRaw --query \
        "SELECT sum(request_count) FROM access_hourly_v1 WHERE tenant_id=toUUID('10000000-0000-0000-0000-000000000001')")
    assert_equal 1 "$old_reader" 'replicated raw reader baseline'
done

replicated_up 2>/dev/null | awk '/CREATE OR REPLACE VIEW access_hourly_v1 ON CLUSTER/{exit} {print}' | \
    clickhouse "$replica_one_container" --database "$task_database" --multiquery >/dev/null
if clickhouse "$replica_one_container" --database "$task_database" \
    --query "SELECT throwIf(1,'injected replicated backfill failure before cutover')" >/dev/null 2>&1; then
    fail 'injected replicated migration failure unexpectedly succeeded'
fi
wait_replicas
for container in "$replica_one_container" "$replica_two_container"; do
    after_failure=$(clickhouse "$container" --database "$task_database" --format TSVRaw --query \
        "SELECT sum(request_count) FROM access_hourly_v1 WHERE tenant_id=toUUID('10000000-0000-0000-0000-000000000001')")
    assert_equal 1 "$after_failure" 'replicated old-reader continuity after failed backfill'
done

replicated_up | clickhouse "$replica_one_container" --database "$task_database" --multiquery >/dev/null
wait_replicas
wait_evidence_replicas
for container in "$replica_one_container" "$replica_two_container"; do
    after_cutover=$(clickhouse "$container" --database "$task_database" --format TSVRaw --query \
        "SELECT sum(request_count) FROM access_hourly_v1 WHERE tenant_id=toUUID('10000000-0000-0000-0000-000000000001') AND hour=toDateTime('2099-01-01 00:00:00','UTC')")
    assert_equal 1 "$after_cutover" 'replicated exact final cutover'
    evidence=$(clickhouse "$container" --database "$task_database" --format TSVRaw --query \
        "SELECT count(), uniqExact(payload_digest) FROM access_version_evidence_v1 FINAL WHERE tenant_id=toUUID('10000000-0000-0000-0000-000000000001') AND event_id='replicated-old-reader'")
    assert_equal "$(printf '1\t1')" "$evidence" 'replicated evidence backfill convergence'
done

first_schema=$(schema_fingerprint "$replica_one_container")
second_schema=$(schema_fingerprint "$replica_two_container")
assert_equal "$first_schema" "$second_schema" 'initial two-replica DDL convergence'

clickhouse "$replica_one_container" --database "$task_database" --date_time_input_format best_effort \
    --query 'INSERT INTO access_events FORMAT JSONEachRow' >/dev/null <<'JSON'
{"metric_version":1,"event_id":"replicated-dedup-1","occurred_at":"2099-01-01T00:05:00Z","ingested_at":"2099-01-01T01:00:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"replicated.example.test","path":"/one","client_ip":"2001:db8::1","method":"GET","protocol":"HTTP/2","cache_status":"HIT","status_code":200,"request_bytes":10,"response_bytes":11,"duration_us":100}
JSON
wait_replicas
replica_two_first=$(clickhouse "$replica_two_container" --database "$task_database" --format TSVRaw \
    --query "SELECT count(), sum(response_bytes) FROM access_events FINAL WHERE tenant_id=toUUID('10000000-0000-0000-0000-000000000001') AND event_id='replicated-dedup-1'")
assert_equal "$(printf '1\t11')" "$replica_two_first" 'replica-one insert convergence'

clickhouse "$replica_two_container" --database "$task_database" --date_time_input_format best_effort \
    --query 'INSERT INTO access_events FORMAT JSONEachRow' >/dev/null <<'JSON'
{"metric_version":1,"event_id":"replicated-dedup-1","occurred_at":"2099-01-01T00:05:00Z","ingested_at":"2099-01-01T02:00:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","host":"replicated.example.test","path":"/one","client_ip":"2001:db8::1","method":"GET","protocol":"HTTP/2","cache_status":"HIT","status_code":200,"request_bytes":10,"response_bytes":22,"duration_us":100}
JSON
wait_replicas
for container in "$replica_one_container" "$replica_two_container"; do
    deduplicated=$(clickhouse "$container" --database "$task_database" --format TSVRaw \
        --query "SELECT count(), sum(response_bytes) FROM access_events FINAL WHERE tenant_id=toUUID('10000000-0000-0000-0000-000000000001') AND event_id='replicated-dedup-1'")
    assert_equal "$(printf '1\t22')" "$deduplicated" 'cross-replica identity deduplication'
    queue=$(clickhouse "$container" --database "$task_database" --format TSVRaw --query \
        "SELECT sum(queue_size), min(active_replicas) FROM system.replicas WHERE database='$task_database'")
    assert_equal "$(printf '0\t2')" "$queue" 'replica queue convergence'
done

clickhouse "$replica_two_container" --database "$task_database" \
    --query 'DROP VIEW security_hourly_v1' >/dev/null
partial_count=$(clickhouse "$replica_two_container" --param_database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM system.tables WHERE database={database:String} AND name='security_hourly_v1'")
assert_equal 0 "$partial_count" 'partial DDL fault injection'
clickhouse "$replica_one_container" --database "$task_database" --multiquery \
    < "$script_dir/replicated/025_security_event_count.up.sql" >/dev/null
recovered_count=$(clickhouse "$replica_two_container" --param_database "$task_database" --format TSVRaw --query \
    "SELECT count() FROM system.tables WHERE database={database:String} AND name='security_hourly_v1'")
assert_equal 1 "$recovered_count" 'partial DDL recovery'

replicated_down | clickhouse "$replica_one_container" --database "$task_database" --multiquery >/dev/null
for container in "$replica_one_container" "$replica_two_container"; do
    remaining=$(clickhouse "$container" --param_database "$task_database" --format TSVRaw --query \
        'SELECT count() FROM system.tables WHERE database={database:String}')
    assert_equal 0 "$remaining" 'replicated down convergence'
done
replicated_up | clickhouse "$replica_one_container" --database "$task_database" --multiquery >/dev/null
wait_replicas
wait_evidence_replicas
assert_equal "$first_schema" "$(schema_fingerprint "$replica_one_container")" 'replicated up/down/up determinism replica one'
assert_equal "$first_schema" "$(schema_fingerprint "$replica_two_container")" 'replicated up/down/up determinism replica two'
for container in "$replica_one_container" "$replica_two_container"; do
    evidence=$(clickhouse "$container" --database "$task_database" --format TSVRaw --query \
        "SELECT count(), uniqExact(payload_digest) FROM access_version_evidence_v1 FINAL WHERE tenant_id=toUUID('10000000-0000-0000-0000-000000000001') AND event_id='replicated-old-reader'")
    # The down chain dropped access_events with its rows; up starts empty.
    assert_equal "$(printf '0\t0')" "$evidence" 'replicated down/up starts without evidence'
done

clickhouse "$replica_one_container" --query \
    "DROP DATABASE $task_database ON CLUSTER cdnca_analytics SYNC" >/dev/null
cleanup
trap - EXIT HUP INT TERM

survivors=$(docker ps -a --format '{{.Names}}' | grep -Ec "^($keeper_container|$replica_one_container|$replica_two_container)$" || :)
assert_equal 0 "$survivors" 'task container cleanup'
if docker network inspect "$task_network" >/dev/null 2>&1; then
    fail 'task network survived cleanup'
fi

printf '%s\n' 'replicated analytics smoke passed: keeper, two replicas, convergence, cross-replica dedup, partial DDL recovery, up/down/up'
