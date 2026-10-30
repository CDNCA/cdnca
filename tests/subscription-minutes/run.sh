#!/bin/bash
# ML-07 S3 e2e: market per subscription minute statistics from a real
# OpenResty node to ClickHouse (ADR 0012 §6.2). Three legs, one heavy slot:
#   1. tests/dynroute-filters ONLY=market (node runtime image): cdnca_limits
#      counts, the agent's dyntelemetry source takes /subscription-minutes
#      into a real event spool, the telemetry publisher's wire records are
#      written out (records.jsonl) with the node-side maxima (expect.json);
#   2. agent-gateway TestSubscriptionMinuteGatewayLeg: validate + bind each
#      record against the node's site authorization (bound.jsonl);
#   3. control-api TestSubscriptionMinuteControlLeg: the ingest processor
#      writes them (each delivered twice) into a --rm ClickHouse with every
#      migration (024 subscription_minutes_v1); rows and maxima are compared.
# Usage: bash tests/subscription-minutes/run.sh > log
set -u
W="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
out=$(mktemp -d /tmp/cdnca-ml07-minutes.XXXXXX); chmod 0777 "$out"
CH=cdnca-ml07-ch-$$; port=$((18960 + RANDOM % 30))
cleanup() { docker rm -f "$CH" >/dev/null 2>&1; rm -rf "$out"; }
trap cleanup EXIT
echo "== leg 1: real OpenResty + agent spool"
MINUTE_RECORDS="$out" ONLY=market bash "$W/tests/dynroute-filters/run.sh" || { echo "RESULT leg1 failed"; exit 1; }
[ -s "$out/records.jsonl" ] || { echo "RESULT no wire records"; exit 1; }
echo "records: $(wc -l < "$out/records.jsonl")"
echo "== leg 2: gateway validate + bind"
CDNCA_MINUTE_RECORDS="$out/records.jsonl" CDNCA_MINUTE_BOUND="$out/bound.jsonl" \
	go -C "$W/services/agent-gateway" test -tags integration -count=1 -v -run '^TestSubscriptionMinuteGatewayLeg$' . 2>&1 | tail -5
[ -s "$out/bound.jsonl" ] || { echo "RESULT leg2 failed"; exit 1; }
echo "== leg 3: control-api ingest -> ClickHouse"
docker run -d --rm --name "$CH" -p 127.0.0.1:$port:8123 -e CLICKHOUSE_SKIP_USER_SETUP=1 \
	clickhouse/clickhouse-server:25.3.6.56-alpine >/dev/null || { echo "BLOCKED: clickhouse"; exit 69; }
for _ in $(seq 60); do curl -sf "http://127.0.0.1:$port/ping" >/dev/null && break; sleep 1; done
CDNCA_MINUTE_BOUND="$out/bound.jsonl" CDNCA_MINUTE_EXPECT="$(cat "$out/expect.json")" \
	TEST_CLICKHOUSE_URL="http://127.0.0.1:$port" TEST_CLICKHOUSE_DATABASE=ml07_minutes_test \
	go -C "$W/services/control-api" test -tags integration -count=1 -v -run '^TestSubscriptionMinuteControlLeg$' ./internal/analytics/ 2>&1 | tail -8
status=${PIPESTATUS[0]}
[ "$status" = 0 ] && echo "RESULT failures=0" || echo "RESULT leg3 failed"
exit "$status"
