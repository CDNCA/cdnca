#!/bin/sh
# 检测器正反例（真实 OpenResty，detscan.sh）。每类 attack.tsv 全部命中、benign.tsv 0 命中。
#   用法：scripts/security/datasets/detcases/run.sh [检测器名，默认 cmd]
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
names=${1:-cmd,format,redirect}
out=$(sh "${here}/../detscan.sh" "${here}" benign:benign.tsv,attack:attack.tsv "${names}")
printf '%s\n' "${out}" | grep -E '^(SCAN|FP|ERROR)'
fail=0
for name in $(printf '%s' "${names}" | tr ',' ' '); do
	a_total=$(grep -c "^${name}	" "${here}/attack.tsv" || true)
	b_total=$(grep -c "^${name}	" "${here}/benign.tsv" || true)
	printf '%s\n' "${out}" | grep -q "^SCAN attack class=${name} total=${a_total} .*${name}=${a_total}\( \|$\)" || { echo "FAIL ${name} attack: want ${a_total}/${a_total}"; fail=1; }
	printf '%s\n' "${out}" | grep -q "^SCAN benign class=${name} total=${b_total} .*${name}=0\( \|$\)" || { echo "FAIL ${name} benign: want 0/${b_total}"; fail=1; }
done
printf '%s\n' "${out}" | grep -q '^ERROR' && fail=1
[ "${fail}" = 0 ] && echo "RESULT failures=0" || { echo "RESULT failures=1"; exit 1; }
