#!/bin/sh
# G8-a 规模基准。用法：
#   tests/scale/run.sh control  [站点数,...]   主控编译/签名（本机，无数据库）
# （节点 compile/node 模式随 v7 渲染器删除，D13-c③c；节点规模见 tests/dynroute-agent 与 dynroute 规模测）
# 结果追加到 tests/scale/results/<模式>-<时间>.jsonl。
# 环境变量：CDNCA_SCALE_IMAGE（默认 cdnca-native-runtime:wafdual）、
#   CDNCA_SCALE_MEMORY（容器内存上限，默认 6g）、CDNCA_SCALE_WORKERS（默认 2）、
#   CDNCA_SCALE_CC_PERMILLE（CC 站点比例，默认 100 即 10%）、CDNCA_SCALE_NODES（control 模式节点数）、
#   CDNCA_SCALE_LAZY_CERTS（1 = site runtime v7 懒加载证书，G8-b）。
set -eu

mode=${1:?usage: run.sh control [sites,...]}
sites=${2:-1000,5000,10000}
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
results="$repo_root/tests/scale/results"
mkdir -p "$results"
out="$results/$mode-$(date +%Y%m%d-%H%M%S).jsonl"
# node 模式默认关 CC，与 G8-a 基准数据保持可比（注册表 4096 字节缺陷已修，可用 CDNCA_SCALE_CC_PERMILLE 打开）。
if [ "$mode" = node ]; then export CDNCA_SCALE_CC_PERMILLE="${CDNCA_SCALE_CC_PERMILLE:-0}"; else export CDNCA_SCALE_CC_PERMILLE="${CDNCA_SCALE_CC_PERMILLE:-100}"; fi
export CDNCA_SCALE_HTTPS_PERMILLE="${CDNCA_SCALE_HTTPS_PERMILLE:-1000}"

case "$mode" in
control)
	CDNCA_SCALE_SITES="$sites" CDNCA_SCALE_OUT="$out" go -C "$repo_root/services/control-api" test -tags scale -p 1 -count=1 \
		-timeout 60m -run '^TestScaleControlCompile$' ./internal/edgepublish
	CDNCA_SCALE_OUT="$out.ceiling" go -C "$repo_root/services/control-api" test -tags scale -p 1 -count=1 \
		-timeout 60m -run '^TestScaleControlCeiling$' ./internal/edgepublish
	cat "$out.ceiling" >>"$out" && rm -f "$out.ceiling"
	;;
*)
	printf 'unknown mode %s\n' "$mode" >&2
	exit 64
	;;
esac
printf 'results: %s\n' "$out"
