#!/usr/bin/env bash
# Run precompiled Linux test binaries against task-owned fixtures, never the
# application database or the production ClickHouse container.
set -euo pipefail
test_root=${1:?test binary directory required}
test_name="cdnca_usage_search_$(date +%s)_$$"
test_container="${test_name//_/-}"
pg_created=false
ch_created=false
cleanup() {
  if [[ "$ch_created" == true ]]; then docker stop --time 5 "$test_container" >/dev/null; fi
  if [[ "$pg_created" == true ]]; then runuser -u postgres -- dropdb --if-exists "$test_name"; fi
}
trap cleanup EXIT
[[ -x "$test_root/analytics.test" && -x "$test_root/usage.test" ]]
if ss -ltn '( sport = :18129 )' | tail -n +2 | read -r _; then
  echo 'Test port 18129 is occupied; refusing to reuse it.' >&2
  exit 1
fi
test_image=$(docker inspect --format '{{.Image}}' cdnca-management-clickhouse)
docker run --rm --detach --name "$test_container" --memory 1g --cpus 2 \
  --publish 127.0.0.1:18129:8123 \
  --env CLICKHOUSE_USER=usage_test --env CLICKHOUSE_PASSWORD=usage_test_fixture \
  --env CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 "$test_image" >/dev/null
ch_created=true
for attempt in {1..20}; do
  if curl -fsS --max-time 1 http://127.0.0.1:18129/ping >/dev/null 2>&1; then break; fi
  sleep 1
done
USAGE_SEARCH_TEST_CH_URL=http://127.0.0.1:18129 "$test_root/analytics.test" -test.run '^TestUsageSearchClickHouseFiltersAndAggregation$' -test.v -test.timeout 60s
runuser -u postgres -- createdb "$test_name"
pg_created=true
runuser -u postgres -- env TEST_DATABASE_URL="postgres:///$test_name?host=/var/run/postgresql" \
  "$test_root/usage.test" -test.run '^TestUsageSearchPostgresTargetIsolation$' -test.v -test.timeout 60s
echo 'USAGE_SEARCH_REAL_DATABASE_TESTS=PASS'
