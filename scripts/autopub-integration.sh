#!/usr/bin/env bash
# autopub PG 集成验收：本机原生 PG17，模板库建到迁移头后各用例克隆（TEST_DATABASE_TEMPLATE）。
# 用法：scripts/autopub-integration.sh [端口]；结果 /tmp/autopub-int-*.log，-v 输出，要求 SKIP=0。
# CDNCA_PG_NATIVE：原生 PG 管理脚本（start <名> <端口> 打印连接串 / stop <名>），必填。
set -uo pipefail
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH" GOTOOLCHAIN=go1.27.3 GOPROXY=https://goproxy.cn,direct
ROOT=$(cd "$(dirname "$0")/.." && pwd)
API="$ROOT/services/control-api"
P=${1:-55981}
while lsof -nP -iTCP:$P -sTCP:LISTEN >/dev/null 2>&1; do P=$((P-1)); done
: "${CDNCA_PG_NATIVE:?set CDNCA_PG_NATIVE to a pg-native-test.sh compatible script}"
HEAD=$(ls "$API/migrations" | grep -oE '^[0-9]+' | sort -n | tail -1 | sed 's/^0*//')
url=$("$CDNCA_PG_NATIVE" start autopub "$P" | tail -1) || exit 2
trap '"$CDNCA_PG_NATIVE" stop autopub >/dev/null' EXIT
base=${url%/cdnca_integration*}
psql -X -q "$base/postgres" -c "CREATE DATABASE int_tpl OWNER cdnca TEMPLATE template0" -c "REVOKE CREATE ON DATABASE int_tpl FROM PUBLIC"
psql -X -q "$base/int_tpl" -c "CREATE SCHEMA migrated"
CDNCA_BUILD_MIGRATION_TEMPLATE=$HEAD TEST_DATABASE_URL="$base/int_tpl?sslmode=disable&search_path=migrated" \
  go -C "$API" test -count=1 -tags integration -timeout 60m -run '^TestBuildMigrationTemplate$' -v ./migrations/ > /tmp/autopub-int-tpl.log 2>&1 || { echo 模板失败; exit 1; }
export TEST_DATABASE_URL="$base/cdnca_integration?sslmode=disable" TEST_DATABASE_TEMPLATE=int_tpl
rc=0
go -C "$API" test -count=1 -tags integration -timeout 30m -v -run 'TestPackageAutomaticPublication457' ./migrations/ > /tmp/autopub-int-mig.log 2>&1 || rc=1
go -C "$API" test -count=1 -tags integration -timeout 30m -v \
  -run 'TestPackageOpenPublishesAutomaticallyToPackageLineGroup|TestAutomaticPublicationExcludesIncapableNodesAndCatchesUpAfterUpgrade' \
  ./internal/edgepublish > /tmp/autopub-int-edgepublish.log 2>&1 || rc=1
go -C "$API" test -count=1 -tags integration -timeout 30m -v -p 1 ./internal/packagesubscription ./internal/edgeautopublish \
  > /tmp/autopub-int-pkgs.log 2>&1 || rc=1
for f in tpl mig edgepublish pkgs; do
  echo "== $f PASS=$(grep -c -- '--- PASS' /tmp/autopub-int-$f.log) FAIL=$(grep -c -- '--- FAIL' /tmp/autopub-int-$f.log) SKIP=$(grep -c -- '--- SKIP' /tmp/autopub-int-$f.log)"
  grep -E -- '^(ok|FAIL)\s|--- FAIL|--- SKIP' /tmp/autopub-int-$f.log | head -20
done
exit $rc
