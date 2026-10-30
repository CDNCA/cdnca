#!/usr/bin/env bash
# 规则情报上报联调（ADR 0011 §4.3，RI-08）：license-service <-> control-api，两个进程。
#
#   RULE_INTEL_E2E_DATABASE_URL=postgres://... RULE_INTEL_E2E_CONTROL_DATABASE_URL=postgres://... run.sh
#       复用已有 PG（每次运行各自隔离 schema）；control 库需有 control-api 角色基线
#       （scripts/install-control.sh setup_postgres 的基线）。
#   不设时起一次性 postgres:17.5 容器（--rm）。
#
# 进程 1（license-service internal/httpapi TestRuleIntelReportLicenseFixture）：生产 license API（业务监听器签发
#   安装客户端证书）+ 生产安装 mTLS 监听器（真实 POST /installation/v1/rule-intel-reports handler），真实 PG。
# 进程 2（control-api cmd/control-api TestRuleIntelReportControlAgainstLicenseProcess）：生产接线 newRuleIntelReporter
#   （插件运行时 mTLS 环境、证书签发、Ed25519 签名），迁移到头号的 PG 上的自动防御签名 + 注入片段；
#   上报一次、未到期不重发、关闭开关后记 disabled。进程 1 再核对授权端库：收据数、候选/证据/片段语料已写、
#   全部情报行里没有站点 ID、域名、IP、原始路径、UA 哈希与安装 ID。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/rule-intel-e2e.XXXXXX")" && pwd -P)"
chmod 700 "$WORK"
CONTAINER=""
LICENSE_PID=""

cleanup() {
  [ -n "$LICENSE_PID" ] && kill "$LICENSE_PID" 2>/dev/null || true
  [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "${RULE_INTEL_E2E_KEEP:-}" = 1 ]; then echo "[rule-intel-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

if [ -z "${RULE_INTEL_E2E_DATABASE_URL:-}" ]; then
  PORT="${RULE_INTEL_E2E_PG_PORT:-55688}"
  CONTAINER="rule-intel-e2e-pg-$$"
  docker run -d --rm --name "$CONTAINER" -e POSTGRES_PASSWORD=pw -p "127.0.0.1:${PORT}:5432" \
    postgres:17.5-bookworm -c max_locks_per_transaction=4096 -c max_connections=300 >/dev/null
  for _ in $(seq 1 60); do
    docker exec "$CONTAINER" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 &&
      (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && break
    sleep 1
  done
  sleep 2
  RULE_INTEL_E2E_DATABASE_URL="postgres://postgres:pw@127.0.0.1:${PORT}/postgres?sslmode=disable"
  docker exec -i "$CONTAINER" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
CREATE ROLE cdnca_control_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_control_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE rule_intel_e2e_control TEMPLATE template0;
REVOKE CREATE ON DATABASE rule_intel_e2e_control FROM PUBLIC;
REVOKE ALL ON DATABASE rule_intel_e2e_control FROM cdnca_control_app, cdnca_plugin_webhook_runtime;
\connect rule_intel_e2e_control
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
  RULE_INTEL_E2E_CONTROL_DATABASE_URL="postgres://postgres:pw@127.0.0.1:${PORT}/rule_intel_e2e_control?sslmode=disable"
fi
RULE_INTEL_E2E_CONTROL_DATABASE_URL="${RULE_INTEL_E2E_CONTROL_DATABASE_URL:-$RULE_INTEL_E2E_DATABASE_URL}"

echo "[rule-intel-e2e] building test binaries"
mkdir -p "$WORK/bin"
GOWORK=off go test -C "$ROOT/services/license-service" -c -o "$WORK/bin/license.test" ./internal/httpapi
go test -C "$ROOT/services/control-api" -c -o "$WORK/bin/control.test" ./cmd/control-api

echo "[rule-intel-e2e] license process"
(cd "$ROOT/services/license-service/internal/httpapi" && RULE_INTEL_E2E_DIR="$WORK" \
  LICENSE_TEST_DATABASE_URL="$RULE_INTEL_E2E_DATABASE_URL" LICENSE_TEST_MIGRATION_TIMEOUT=5m "$WORK/bin/license.test" \
  -test.run '^TestRuleIntelReportLicenseFixture$' -test.count=1 -test.v -test.timeout 30m) >"$WORK/license.log" 2>&1 &
LICENSE_PID=$!
for _ in $(seq 1 600); do
  [ -f "$WORK/rule-intel-license.json" ] && break
  kill -0 "$LICENSE_PID" 2>/dev/null || break
  sleep 1
done
if [ ! -f "$WORK/rule-intel-license.json" ]; then
  grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/license.log" | sed 's/^/[license] /' >&2
  echo "[rule-intel-e2e] license process did not become ready" >&2
  exit 1
fi

echo "[rule-intel-e2e] control-api process"
set +e
(cd "$ROOT/services/control-api/cmd/control-api" && RULE_INTEL_E2E_DIR="$WORK" \
  TEST_DATABASE_URL="$RULE_INTEL_E2E_CONTROL_DATABASE_URL" "$WORK/bin/control.test" \
  -test.run '^TestRuleIntelReportControlAgainstLicenseProcess$' -test.count=1 -test.v -test.timeout 30m) \
  >"$WORK/control.log" 2>&1
control=$?
[ "$control" -ne 0 ] && kill "$LICENSE_PID" 2>/dev/null
wait "$LICENSE_PID"
license=$?
LICENSE_PID=""
set -e
grep -E '^(--- |PASS|FAIL|ok)|_test.go:[0-9]+' "$WORK/control.log" | sed 's/^/[control] /'
grep -E '^(--- |PASS|FAIL|ok)|_test.go:[0-9]+|runtime .* status=' "$WORK/license.log" | sed 's/^/[license] /'
if [ "$control" -ne 0 ] || [ "$license" -ne 0 ]; then
  echo "[rule-intel-e2e] FAILED control=$control license=$license" >&2
  exit 1
fi
echo "[rule-intel-e2e] PASS"
