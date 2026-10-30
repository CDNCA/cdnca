#!/bin/bash
# esc-core PG 集成：一个原生 PG，建到当前迁移头的模板，跑 460 迁移用例与给定包（-v，统计 PASS/SKIP）。
# 用法: esc-core-pg.sh <端口> '<migrations -run 正则>' '<包列表>' [包 -run 正则]
# CDNCA_HEAVY：可选的排队包装脚本（设了脚本自身会经它重入一次）；CDNCA_PG_NATIVE：原生 PG 管理脚本，必填。
# CDNCA_LOG_DIR：日志目录，默认 ${TMPDIR:-/tmp}/esc-core。
[ -n "${CDNCA_HEAVY:-}" ] && [ -z "${CDNCA_HEAVY_HELD:-}" ] && exec env CDNCA_HEAVY_HELD=1 "$CDNCA_HEAVY" "$0" "$@"
: "${CDNCA_PG_NATIVE:?set CDNCA_PG_NATIVE to a pg-native-test.sh compatible script}"
set -u
export PATH=/opt/homebrew/opt/postgresql@17/bin:$PATH GOTOOLCHAIN=go1.27.3 GOPROXY=https://goproxy.cn,direct
W=$(cd "$(dirname "$0")/../.." && pwd)
P=$1 RUN=$2 PKGS=$3 PRUN=${4:-.}
while lsof -nP -iTCP:$P -sTCP:LISTEN >/dev/null 2>&1; do P=$((P-1)); done
L=${CDNCA_LOG_DIR:-${TMPDIR:-/tmp}/esc-core}; mkdir -p $L
HEAD=$(ls "$W/services/control-api/migrations" | grep -oE '^[0-9]+' | sort -n | tail -1 | sed 's/^0*//')
url=$("$CDNCA_PG_NATIVE" start esccore$$ $P | tail -1)
base=${url%/cdnca_integration*}
psql -X -q "$base/postgres" -c "CREATE DATABASE esc_tpl OWNER cdnca TEMPLATE template0" -c "REVOKE CREATE ON DATABASE esc_tpl FROM PUBLIC"
psql -X -q "$base/esc_tpl" -c "CREATE SCHEMA migrated"
CDNCA_BUILD_MIGRATION_TEMPLATE=$HEAD TEST_DATABASE_URL="$base/esc_tpl?sslmode=disable&search_path=migrated" \
  go -C "$W/services/control-api" test -count=1 -tags integration -timeout 60m -run '^TestBuildMigrationTemplate$' ./migrations/ > $L/esc-core-tpl.log 2>&1 || echo "模板失败"
export TEST_DATABASE_URL="$base/cdnca_integration?sslmode=disable" TEST_DATABASE_TEMPLATE=esc_tpl
go -C "$W/services/control-api" test -count=1 -v -tags integration -timeout 20m -run "$RUN" ./migrations/ > $L/esc-core-mig.log 2>&1
go -C "$W/services/control-api" test -count=1 -v -p 1 -tags integration -timeout 30m -run "$PRUN" $PKGS > $L/esc-core-pkgs.log 2>&1
"$CDNCA_PG_NATIVE" stop esccore$$ $P > /dev/null
echo "head=$HEAD"
for f in tpl mig pkgs; do
  echo "== $f PASS=$(grep -c -- '--- PASS' $L/esc-core-$f.log) SKIP=$(grep -c -- '--- SKIP' $L/esc-core-$f.log)"
  grep -E -- '^(ok|FAIL)\s|--- FAIL|_test.go:[0-9]+:|panic' $L/esc-core-$f.log | head -30
done
