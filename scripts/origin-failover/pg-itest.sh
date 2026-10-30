#!/bin/sh
# origin-failover PG integration: originfailover store/service, migration
# 417 up/down, the site origin HTTP flow. Native PG through CDNCA_PG_NATIVE
# (start <name> <port> prints the URL). Usage: pg-itest.sh <log>
set -u
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
log=${1:-/tmp/of2-pg.log}
port=${PG_PORT:-55931}
pg=${CDNCA_PG_NATIVE:?set CDNCA_PG_NATIVE to a pg-native-test.sh compatible script}
url=$("$pg" start of2 "$port" | tail -1)
trap '"$pg" stop of2 >/dev/null' EXIT
cd "$repo/services/control-api" || exit 1
TEST_DATABASE_URL=$url go test -tags integration -p 1 -count=1 -timeout 40m \
	./internal/originfailover/ >"$log" 2>&1
s1=$?
TEST_DATABASE_URL=$url go test -tags integration -p 1 -count=1 -timeout 40m -run 'TestOriginFailover417' \
	./migrations/ >>"$log" 2>&1
s2=$?
TEST_DATABASE_URL=$url go test -tags integration -p 1 -count=1 -timeout 40m -run 'TestSiteOriginHTTPFlow' \
	./internal/httpapi/ >>"$log" 2>&1
s3=$?
echo "RESULT originfailover=$s1 migrations=$s2 httpapi=$s3" >>"$log"
