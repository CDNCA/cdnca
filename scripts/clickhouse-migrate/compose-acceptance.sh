#!/bin/sh
# Real ClickHouse acceptance for the compose migration job: 001 -> head, rerun
# is a no-op with an unchanged schema, check/dry-run, grants, tamper refusal.
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
project="cdnca-f11-chmig-$$"
log=${TMPDIR:-/tmp}/cdnca-f11-compose-acceptance.$$
mkdir -p "$log"

export CLICKHOUSE_DB=cdnca_analytics CLICKHOUSE_USER=cdnca_migrator CLICKHOUSE_PASSWORD=acceptance-only-password
export CLICKHOUSE_HTTP_PORT=0 CLICKHOUSE_NATIVE_PORT=0
# compose.yaml interpolates every service; only clickhouse is started here.
for name in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD REDIS_PASSWORD NATS_CONTROL_CONSUMER_USERNAME \
    NATS_CONTROL_CONSUMER_PASSWORD NATS_GATEWAY_PUBLISHER_USERNAME NATS_GATEWAY_PUBLISHER_PASSWORD \
    NATS_PREPROVISION_USERNAME NATS_PREPROVISION_PASSWORD; do
  export "$name=unused"
done

compose() {
  docker compose --project-name "$project" --project-directory "$repo" \
    -f "$repo/compose.yaml" -f "$repo/deploy/compose/clickhouse-migrate.yaml" "$@"
}
cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || :
  docker rmi cdnca/clickhouse-migrate:local >/dev/null 2>&1 || :
}
fail() { printf 'compose acceptance failed: %s (logs in %s)\n' "$1" "$log" >&2; exit 1; }
trap cleanup EXIT HUP INT TERM

# $1 is the action; an assignment prefix on a shell function would persist in sh.
migrate() {
  action=$1; shift
  CLICKHOUSE_MIGRATE_ACTION=$action docker compose --project-name "$project" --project-directory "$repo" \
    -f "$repo/compose.yaml" -f "$repo/deploy/compose/clickhouse-migrate.yaml" run --rm --no-deps "$@" clickhouse-migrate
}
# SQL goes over stdin: with -T the client reads stdin, and INSERT ... VALUES via --query waits on it.
sql() { printf '%s\n' "$1" | compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD"; }
fingerprint() {
  sql "SELECT name, normalizeQuery(create_table_query) FROM system.tables WHERE database = '$CLICKHOUSE_DB' AND name != 'schema_migrations' ORDER BY name FORMAT TSVRaw" | shasum -a 256
}
head_count=$(find "$repo/infra/clickhouse/migrations" -name '*.up.sql' | wc -l | tr -d ' ')

compose build clickhouse-migrate >"$log/build.log" 2>&1 || fail 'image build'
compose up -d --wait clickhouse >"$log/up.log" 2>&1 || fail 'clickhouse start'

migrate dry-run >"$log/dry-empty.sql" 2>"$log/dry-empty.err" || fail 'dry-run on empty server'
# The server image pre-creates the empty CLICKHOUSE_DB; dry-run must leave it empty.
[ "$(sql "SELECT count() FROM system.tables WHERE database = '$CLICKHOUSE_DB'")" = 0 ] || fail 'dry-run changed the database'
grep -q 'CREATE TABLE IF NOT EXISTS access_events' "$log/dry-empty.sql" || fail 'dry-run did not print 001'

sql "CREATE USER IF NOT EXISTS q IDENTIFIED BY 'q-pass'"
sql "CREATE USER IF NOT EXISTS i IDENTIFIED BY 'i-pass'"
sql "CREATE USER IF NOT EXISTS r NOT IDENTIFIED HOST NONE"
grants="-e CLICKHOUSE_MIGRATE_GRANT_QUERY_USER=q -e CLICKHOUSE_MIGRATE_GRANT_INGEST_USER=i -e CLICKHOUSE_MIGRATE_GRANT_ROLLUP_USER=r"

# shellcheck disable=SC2086
migrate migrate $grants >"$log/first.json" 2>&1 || fail 'first migrate'
python3 -c 'import json,sys; r=json.loads(open(sys.argv[1]).read().splitlines()[-1]); assert r["status"]=="migrations_applied" and len(r["applied"])==int(sys.argv[2]), r' \
  "$log/first.json" "$head_count" || fail 'first migrate did not apply 001..head'
[ "$(sql "SELECT count() FROM $CLICKHOUSE_DB.schema_migrations FINAL WHERE applied = 1")" = "$head_count" ] || fail 'ledger rows'
[ "$(sql "SELECT max(version) FROM $CLICKHOUSE_DB.schema_migrations")" = "$head_count" ] || fail 'ledger head'
before=$(fingerprint)

# shellcheck disable=SC2086
migrate migrate $grants >"$log/second.json" 2>&1 || fail 'rerun'
grep -q '"applied": \[\]' "$log/second.json" || fail 'rerun applied migrations again'
[ "$(fingerprint)" = "$before" ] || fail 'rerun changed the schema'
migrate check >"$log/check.json" 2>&1 || fail 'check'
grep -q '"pending": \[\]' "$log/check.json" || fail 'check reports pending migrations'
migrate dry-run >"$log/dry-head.sql" 2>"$log/dry-head.err" || fail 'dry-run at head'
! grep -qv '^--\|^$' "$log/dry-head.sql" || fail 'dry-run at head printed SQL'

[ "$(sql "SELECT count() FROM system.grants WHERE user_name = 'i' AND access_type = 'INSERT'")" -ge 5 ] || fail 'ingest grants'
[ "$(sql "SELECT count() FROM system.grants WHERE user_name = 'q' AND access_type = 'SELECT'")" -ge 1 ] || fail 'query grants'
printf 'SELECT count() FROM %s.access_events\n' "$CLICKHOUSE_DB" | compose exec -T clickhouse clickhouse-client --user q --password q-pass >/dev/null || fail 'query identity cannot read'

# A ledger that disagrees with the shipped files must fail the job.
sql "INSERT INTO $CLICKHOUSE_DB.schema_migrations (version, name, checksum, applied) VALUES (1, '001_analytics', '$(printf 0%.0s $(seq 64))', 1)"
if migrate migrate >"$log/tamper.json" 2>&1; then fail 'tampered ledger was accepted'; fi
grep -q 'checksum_mismatch' "$log/tamper.json" || fail 'tamper reason'

printf 'compose acceptance passed: %s migrations, rerun idempotent, check/dry-run/grants/tamper ok\n' "$head_count"
