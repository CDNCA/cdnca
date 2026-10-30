#!/bin/sh
# dnspup-probe PG integration: dnspupprobe (settings, key rotation,
# capability test, degrade + alert, runtime against the dnspup fake),
# originfailover (runner with the dnspup source), migrations 427 contract and
# up/down. Native PG through CDNCA_PG_NATIVE (start <name> <port> prints the URL).
# Usage: itest.sh <log>
set -u
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
log=${1:-/tmp/dnspup-probe-pg.log}
port=${PG_PORT:-55963}
pg=${CDNCA_PG_NATIVE:?set CDNCA_PG_NATIVE to a pg-native-test.sh compatible script}
url=$("$pg" start dpp "$port" | tail -1)
trap '"$pg" stop dpp >/dev/null' EXIT
TEST_DATABASE_URL=$url go -C "$repo/services/control-api" test -tags integration -p 1 -count=1 -timeout 40m -v \
	./internal/dnspupprobe/ ./internal/originfailover/ >"$log" 2>&1
echo "RESULT dnspupprobe+originfailover=$?" >>"$log"
TEST_DATABASE_URL=$url go -C "$repo/services/control-api" test -tags integration -p 1 -count=1 -timeout 40m \
	-run 'DNSPupProbe427|Migration.*(Up|Down|Round)' ./migrations/ >>"$log" 2>&1
echo "RESULT migrations=$?" >>"$log"
