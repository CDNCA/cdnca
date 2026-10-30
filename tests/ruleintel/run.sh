#!/usr/bin/env bash
# ADR 0011 RI-15 场景矩阵一键验收。整条脚本经全机队列跑一次、只占 1 槽，内部各段串行：
#   bash tests/ruleintel/run.sh
# 段（PARTS=逗号分隔，默认全部）：
#   unit     质量门 G1/G2 静态（ruleintelgate：never_relax、冲突、递增、单档改强弱）+ 合并构建 + 聚类/防投毒库
#   license  授权端 PG 回放：投毒 P1–P4、灰度每阶段 1 小时与回滚（TestRuleIntelReplay*），以及既有
#            上报/日任务/草稿/门/发布/误判暂停/回执暂停/下线恢复（TestRuleIntel*）
#   control  主控 PG：自动排除全生命周期（建议→影子→生效→续期/过期、采纳、人工锁、驳回冷却、暂停、攻击冻结）、
#            灰区挑战证据、Cookie 名集合（TestWAFAdapt*）、情报上报（ruleintelreport）
#   node     真实 OpenResty 1.31.1.1 + ModSecurity + CRS 4.30（tests/dynroute-waf/run.sh）：
#            adaptive（灰区挑战 GET/POST/API/伪造/强分不放行）、tuning（官方调优按档位/u= 逐站关闭）、
#            wafadapt（快照→agent→节点：排除生效、暂停、离站）、buckets（同档 129 站：128 站共享一个桶 location、
#            第 129 站进第二桶；撤销一站只影响该站）
#   e2e      三进程 control-api → NATS → agent-gateway → edge-agent（tests/artifact-set-e2e/run.sh，含官方情报包无挂载下发、
#            节点 applied、pack_receipts 汇总）
#   g3       G3 真实容器语料回归（ruleintelgate TestG3Container RI11_G3_CASES=same,weaker，约 2 分钟；默认不跑：
#            PARTS=...,g3 显式加入）
# PG：每段用 CDNCA_PG_NATIVE（原生 PG 管理脚本，必填）起一个原生实例，段结束即 stop。RI15_PG_PORT 起始端口（默认 56151）。
# 日志：RI15_LOG_DIR（默认 /tmp/ri15），每段 <段>.log；最后打印 MATRIX 汇总，任一段失败退出码 1。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PG="${CDNCA_PG_NATIVE:?set CDNCA_PG_NATIVE to a pg-native-test.sh compatible script}"
LOG="${RI15_LOG_DIR:-/tmp/ri15}"
PORT="${RI15_PG_PORT:-56151}"
PARTS=",${PARTS:-unit,license,control,node,e2e},"
export PATH="/opt/homebrew/opt/postgresql@17/bin:${PATH}" GOWORK=off
mkdir -p "${LOG}"
declare -a RESULTS=()
failed=0
started_all=$(date +%s)

record() { # 段 退出码 起始秒
  local status=PASS
  [ "$2" -ne 0 ] && status=FAIL && failed=1
  RESULTS+=("$1 ${status} $(( $(date +%s) - $3 ))s")
  echo "[ruleintel] $1 ${status} (log ${LOG}/$1.log)"
}

want() { case "${PARTS}" in *",$1,"*) return 0 ;; esac; return 1; }

summary() { # 只保留结论与失败原因行
  grep -E -- '^(ok|FAIL|PASS|RESULT)\b|--- FAIL|_test.go:[0-9]+:|^FAIL |\[artifact-set-e2e\]|^FAIL' "$1" | grep -v '^=== ' | head -40
}

with_pg() { # 名称 端口 命令...：起 PG、导出 URL、跑、停
  local name=$1 port=$2
  shift 2
  local url
  url=$("${PG}" start "${name}" "${port}" | tail -1) || return 70
  RI15_DB_URL="${url}" "$@"
  local rc=$?
  "${PG}" stop "${name}" >/dev/null
  return ${rc}
}

if want unit; then
  t=$(date +%s)
  {
    go -C "${ROOT}/services/license-service" test -count=1 ./internal/ruleintelgate/ &&
      go -C "${ROOT}/services/license-service" test -count=1 -run 'TestBuild|TestPublishedPack|TestRuleDormant|TestOfficialPack|TestNormalizeRuleIntel|TestReportRuleIntel' ./internal/licensing/ &&
      go -C "${ROOT}/libs/entitlement" test -count=1 ./ruleintel/...
  } >"${LOG}/unit.log" 2>&1
  rc=$?; summary "${LOG}/unit.log"; record unit ${rc} "${t}"
fi

license_run() {
  LICENSE_TEST_DATABASE_URL="${RI15_DB_URL}" LICENSE_TEST_MIGRATION_TIMEOUT=5m go -C "${ROOT}/services/license-service" test -tags integration \
    -p 1 -count=1 -timeout 30m -v -run 'TestRuleIntel' ./internal/licensing/
}
if want license; then
  t=$(date +%s)
  with_pg ri15lic "${PORT}" license_run >"${LOG}/license.log" 2>&1
  rc=$?; summary "${LOG}/license.log"; record license ${rc} "${t}"
fi

control_run() {
  TEST_DATABASE_URL="${RI15_DB_URL}" go -C "${ROOT}/services/control-api" test -tags integration -p 1 -count=1 -timeout 30m \
    ./internal/wafadapt/ ./internal/ruleintelreport/
}
if want control; then
  t=$(date +%s)
  with_pg ri15ctl "$((PORT + 1))" control_run >"${LOG}/control.log" 2>&1
  rc=$?; summary "${LOG}/control.log"; record control ${rc} "${t}"
fi

if want node; then
  t=$(date +%s)
  ONLY=adaptive,tuning,wafadapt,buckets sh "${ROOT}/tests/dynroute-waf/run.sh" >"${LOG}/node.log" 2>&1
  rc=$?; grep -E '^(FAIL|RESULT)' "${LOG}/node.log" | head -40; record node ${rc} "${t}"
fi

e2e_run() {
  TMPDIR=/tmp ARTIFACT_SET_E2E_DATABASE_URL="${RI15_DB_URL}" bash "${ROOT}/tests/artifact-set-e2e/run.sh"
}
if want e2e; then
  t=$(date +%s)
  with_pg ri15e2e "$((PORT + 2))" e2e_run >"${LOG}/e2e.log" 2>&1
  rc=$?; summary "${LOG}/e2e.log"; record e2e ${rc} "${t}"
fi

if want g3; then
  t=$(date +%s)
  RI11_G3_CASES="${RI11_G3_CASES:-same,weaker}" go -C "${ROOT}/services/license-service" test -tags g3container -count=1 -timeout 60m \
    -run TestG3Container -v ./internal/ruleintelgate/ >"${LOG}/g3.log" 2>&1
  rc=$?; summary "${LOG}/g3.log"; record g3 ${rc} "${t}"
fi

echo "MATRIX total=$(( $(date +%s) - started_all ))s"
for line in "${RESULTS[@]}"; do echo "MATRIX ${line}"; done
exit ${failed}
