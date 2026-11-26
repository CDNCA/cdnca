#!/usr/bin/env bash
# commercial-leak-check.sh 自测：基线缺失、搜索命令出错都必须 FAIL（不得被当成无命中而 PASS）。
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
gate=$here/commercial-leak-check.sh
cd "$here/../.." || exit 1  # 网关按当前目录定位仓库
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
failures=0
expect_fail() {
  local name=$1 want=$2; shift 2
  local rc=0
  env "$@" bash "$gate" >"$tmp/out" 2>&1 || rc=$?
  if [ "$rc" = 0 ] || grep -q 'commercial-leak-check: PASS' "$tmp/out" || ! grep -qF -- "$want" "$tmp/out"; then
    echo "not ok - $name（退出码 $rc）"; sed 's/^/    /' "$tmp/out"; failures=$((failures + 1))
  else
    echo "ok - $name"
  fi
}
printf 'example\\.invalid\n' >"$tmp/patterns"
expect_fail "不存在的基线提交" "缺基线 0000000000000000000000000000000000000000" \
  CE_GATE_BASE=0000000000000000000000000000000000000000 CE_GATE_PRIVATE_PATTERNS="$tmp/patterns"
printf '(\n' >"$tmp/bad-patterns"
expect_fail "git grep 出错（非法正则）" "命令失败" CE_GATE_PRIVATE_PATTERNS="$tmp/bad-patterns"
[ "$failures" = 0 ] && { echo "commercial-leak-check.test: PASS"; exit 0; }
echo "commercial-leak-check.test: FAIL（$failures 项）" >&2; exit 1
