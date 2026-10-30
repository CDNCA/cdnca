#!/bin/sh
# 编译并冲突检查 rulepacks/ 下的规则包草稿与已知良性爬虫清单（rulepackcheck/main.go）。
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH='' cd -- "${here}/../../.." && pwd)
work=$(mktemp -d /tmp/rulepackcheck.XXXXXX)
trap 'rm -rf "${work}"' EXIT
cp "${here}/rulepackcheck/main.go" "${work}/"
sed "s|../../../../libs|${repo}/libs|" "${here}/rulepackcheck/check.mod" >"${work}/go.mod"
cp "${here}/rulepackcheck/check.sum" "${work}/go.sum"
# 第 2 个参数（可选）：写出授权端官方规则包迁移的 VALUES 行（规范字节）。
GOWORK=off GOFLAGS=-mod=readonly go -C "${work}" run . "${1:-${here}/rulepacks}" ${2:+"$2"}
