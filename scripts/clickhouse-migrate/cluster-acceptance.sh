#!/bin/sh
# Real two-shard ClickHouse (one Keeper) acceptance for ON CLUSTER mode:
# 001 -> head with Replicated engines on both shards, shared ledger, rerun idempotent.
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
data="$repo/scripts/clickhouse-migrate/testdata"
image=${CDNCA_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:25.3.6.56-alpine}
migrator=cdnca/clickhouse-migrate:f11-cluster-acceptance
network="cdnca-f11-net-$$"
log=${TMPDIR:-/tmp}/cdnca-f11-cluster-acceptance.$$
admin=cdnca_admin user=cdnca_migrator password=acceptance-only-password database=cdnca_analytics cluster=cdnca_analytics
mkdir -p "$log"

cleanup() {
  docker rm -fv cdnca-f11-ch1 cdnca-f11-ch2 cdnca-f11-keeper >/dev/null 2>&1 || :
  docker network rm "$network" >/dev/null 2>&1 || :
  docker rmi "$migrator" >/dev/null 2>&1 || :
}
fail() { printf 'cluster acceptance failed: %s (logs in %s)\n' "$1" "$log" >&2; exit 1; }
trap cleanup EXIT HUP INT TERM
cleanup

sql() { printf '%s\n' "$2" | docker exec -i "$1" clickhouse-client --user "$admin" --password "$password" --multiquery; }
wait_ready() {
  attempts=0
  until sql "$1" 'SELECT 1' >/dev/null 2>&1; do
    attempts=$((attempts + 1)); [ "$attempts" -lt 120 ] || fail "$1 not ready"; sleep 1
  done
}
migrate() {
  docker run --rm --network "$network" -e CLICKHOUSE_MIGRATE_URL=http://cdnca-f11-ch1:8123 \
    -e CLICKHOUSE_MIGRATE_USER="$user" -e CLICKHOUSE_MIGRATE_PASSWORD="$password" \
    -e CLICKHOUSE_MIGRATE_DATABASE="$database" -e CLICKHOUSE_MIGRATE_CLUSTER="$cluster" "$migrator" "$@"
}

docker build -q -f "$repo/deploy/clickhouse-migrate/Dockerfile" -t "$migrator" "$repo" >"$log/build.log" 2>&1 || fail 'image build'
docker network create "$network" >/dev/null
docker run -d --rm --name cdnca-f11-keeper --network "$network" -v "$data/keeper.xml:/etc/clickhouse-keeper/keeper.xml:ro" \
  "$image" clickhouse keeper --config-file=/etc/clickhouse-keeper/keeper.xml >/dev/null
for n in 1 2; do
  docker run -d --rm --name "cdnca-f11-ch$n" --network "$network" -e CLICKHOUSE_USER="$admin" -e CLICKHOUSE_PASSWORD="$password" \
    -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 -v "$data/shard-$n.xml:/etc/clickhouse-server/config.d/cluster.xml:ro" "$image" >/dev/null
done
wait_ready cdnca-f11-ch1
wait_ready cdnca-f11-ch2
# The migration identity gets exactly the privileges the runbook lists for an
# external cluster; ON CLUSTER DDL runs under the same name on every node.
for n in 1 2; do
  sql "cdnca-f11-ch$n" "CREATE USER $user IDENTIFIED BY '$password';
GRANT CREATE DATABASE, CREATE TABLE, CREATE VIEW, ALTER, DROP TABLE, DROP VIEW, SELECT, INSERT ON $database.* TO $user;
GRANT SELECT ON system.clusters TO $user;
GRANT CLUSTER ON *.* TO $user;" || fail "grant migration identity on shard $n"
done

migrate dry-run >"$log/dry.sql" 2>"$log/dry.err" || fail 'dry-run'
grep -q "ON CLUSTER $cluster" "$log/dry.sql" || fail 'dry-run lacks ON CLUSTER'
migrate migrate >"$log/first.json" 2>&1 || fail 'first migrate'
head_count=$(find "$repo/infra/clickhouse/migrations" -name '*.up.sql' | wc -l | tr -d ' ')
for n in 1 2; do
  [ "$(sql "cdnca-f11-ch$n" "SELECT count() FROM $database.schema_migrations FINAL WHERE applied = 1")" = "$head_count" ] ||
    fail "ledger on shard $n"
  [ "$(sql "cdnca-f11-ch$n" "SELECT countIf(engine LIKE '%MergeTree' AND engine NOT LIKE 'Replicated%') FROM system.tables WHERE database = '$database'")" = 0 ] ||
    fail "non-replicated table on shard $n"
  [ "$(sql "cdnca-f11-ch$n" "SELECT count() FROM system.tables WHERE database = '$database' AND name = 'access_metering_facts_mv_v1'")" = 1 ] ||
    fail "head objects missing on shard $n"
done
migrate migrate >"$log/second.json" 2>&1 || fail 'rerun'
grep -q '"applied": \[\]' "$log/second.json" || fail 'rerun applied migrations again'

# Reading the ledger from the other shard gives the same history.
docker run --rm --network "$network" -e CLICKHOUSE_MIGRATE_URL=http://cdnca-f11-ch2:8123 -e CLICKHOUSE_MIGRATE_USER="$user" \
  -e CLICKHOUSE_MIGRATE_PASSWORD="$password" -e CLICKHOUSE_MIGRATE_DATABASE="$database" -e CLICKHOUSE_MIGRATE_CLUSTER="$cluster" \
  "$migrator" check >"$log/check.json" 2>&1 || fail 'check from shard 2'
grep -q '"pending": \[\]' "$log/check.json" || fail 'shard 2 reports pending migrations'

printf 'cluster acceptance passed: %s migrations ON CLUSTER %s across 2 shards, rerun idempotent\n' "$head_count" "$cluster"
