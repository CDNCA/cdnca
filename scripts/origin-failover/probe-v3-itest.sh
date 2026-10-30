#!/bin/sh
# probe-v3 PG integration: originfailover (store/service/runner with
# MARKET_PROBE v3 node votes). Native PG through CDNCA_PG_NATIVE
# (start <name> <port> prints the URL). Usage: probe-v3-itest.sh <log>
set -u
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
log=${1:-/tmp/probe-v3-pg.log}
port=${PG_PORT:-55947}
pg=${CDNCA_PG_NATIVE:?set CDNCA_PG_NATIVE to a pg-native-test.sh compatible script}
url=$("$pg" start pv3 "$port" | tail -1)
trap '"$pg" stop pv3 >/dev/null' EXIT
TEST_DATABASE_URL=$url go -C "$repo/services/control-api" test -tags integration -p 1 -count=1 -timeout 40m -v \
	./internal/originfailover/ >"$log" 2>&1
echo "RESULT originfailover=$?" >>"$log"
