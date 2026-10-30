#!/bin/bash
# Auto defense three process ingest e2e: native PostgreSQL
# (template at MIGRATION_HEAD) + ClickHouse and NATS in --rm containers; runs
# cmd/control-api TestAutoDefenseRuntimeIngestsGatewayReportsEndToEnd
# (agent-gateway bus -> control-api runtime -> ClickHouse -> tenant API).
#   PG_NATIVE      pg-native-test.sh path (required: start|stop <name> <port>)
#   PG_BIN         psql directory (default /opt/homebrew/opt/postgresql@17/bin)
#   MIGRATION_HEAD control-api migration head of the template (default: highest)
# Usage: PG_NATIVE=... tests/autodefense-ingest-e2e/run.sh
set -u
W="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"; S=$W/services/control-api; P=${PG_PORT:-56133}
PGT=${PG_NATIVE:?PG_NATIVE is required}
PSQL=${PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}/psql
HEAD=${MIGRATION_HEAD:-$(ls "$S/migrations" | sed -n 's/^\([0-9]\{3\}\)_.*\.up\.sql$/\1/p' | sort -n | tail -1)}
CH=cdnca-ad-e2e-ch; NA=cdnca-ad-e2e-nats
cleanup() { docker rm -f $CH $NA >/dev/null 2>&1; $PGT stop ad-e2e >/dev/null 2>&1; }
trap cleanup EXIT
URL=$($PGT start ad-e2e $P | grep -o 'postgres://[^ ]*' | head -1); echo "PG $URL"
base=${URL%/*}
"$PSQL" "$base/postgres" -qc 'DROP DATABASE IF EXISTS ad_e2e_tpl' -c 'CREATE DATABASE ad_e2e_tpl' >/dev/null || exit 1
"$PSQL" "$base/ad_e2e_tpl" -qc 'CREATE SCHEMA migrated' || exit 1
CDNCA_BUILD_MIGRATION_TEMPLATE=$((10#$HEAD)) TEST_DATABASE_URL="$base/ad_e2e_tpl?sslmode=disable&search_path=migrated" \
  go -C $S test -count=1 -tags integration -run '^TestBuildMigrationTemplate$' ./migrations/ > "${TMPDIR:-/tmp}/ad-e2e-tpl.log" 2>&1 || { tail -20 "${TMPDIR:-/tmp}/ad-e2e-tpl.log"; exit 1; }
docker run -d --rm --name $CH -p 127.0.0.1:18933:8123 -e CLICKHOUSE_SKIP_USER_SETUP=1 -v "$W/infra"/clickhouse/migrations:/m:ro clickhouse/clickhouse-server:25.3.6.56-alpine >/dev/null || exit 1
docker run -d --rm --name $NA -p 127.0.0.1:14333:4222 nats:2-alpine -js >/dev/null || exit 1
for i in $(seq 60); do curl -sf http://127.0.0.1:18933/ping >/dev/null && break; sleep 1; done
for f in $(ls $W/infra/clickhouse/migrations/*.up.sql | sort); do
  docker exec $CH clickhouse-client --multiquery --queries-file /m/$(basename $f) || { echo "CH migration $f failed"; exit 1; }
done
# -p 1: the NATS tests of several packages recreate the same AUTODEFENSE_REPORTS stream.
TEST_DATABASE_TEMPLATE=ad_e2e_tpl TEST_DATABASE_URL="$URL" CDNCA_TEST_CLICKHOUSE_URL=http://127.0.0.1:18933 CDNCA_TEST_NATS_URL=nats://127.0.0.1:14333 \
  go -C $S test -race -count=1 -p 1 -tags integration -run "${RUN:-TestAutoDefenseRuntimeIngestsGatewayReportsEndToEnd}" ${PKGS:-./cmd/control-api} 2>&1
