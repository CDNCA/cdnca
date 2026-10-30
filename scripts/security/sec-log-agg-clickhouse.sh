#!/bin/sh
# sec-log-agg: the analytics log ClickHouse integration (migration 025
# event_count; block event count, attack summary sum) on a throwaway
# ClickHouse (--rm, loopback only).
#   scripts/security/sec-log-agg-clickhouse.sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
port=${SEC_LOG_AGG_CH_PORT:-18931}
name="sec-log-agg-ch-$$"
docker run -d --rm --name "${name}" -p "127.0.0.1:${port}:8123" -e CLICKHOUSE_SKIP_USER_SETUP=1 \
	clickhouse/clickhouse-server:25.3.6.56-alpine >/dev/null
trap 'docker rm -f "${name}" >/dev/null 2>&1 || true' EXIT INT TERM
for _ in $(seq 1 60); do
	curl -fsS "http://127.0.0.1:${port}/ping" >/dev/null 2>&1 && break
	sleep 1
done
status=0
TEST_CLICKHOUSE_URL="http://127.0.0.1:${port}" TEST_CLICKHOUSE_REQUIRED=1 go -C "${repo_root}/services/control-api" test -v -tags integration \
	-count=1 -p 1 -run '^TestClickHouse' ./internal/analyticslog/ || status=1
TEST_CLICKHOUSE_URL="http://127.0.0.1:${port}" TEST_CLICKHOUSE_DATABASE=sec_log_agg_test go -C "${repo_root}/services/control-api" test -v \
	-tags integration -count=1 -p 1 -run '^(TestCheckIngestMatchesMigratedClickHouseSchema|TestWriteSecurityEventsStoresEventCount)$' ./internal/analytics/ || status=1
exit ${status}
