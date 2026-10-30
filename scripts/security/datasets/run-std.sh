#!/bin/sh
# Run -corpus-set std in batches (each one job, optionally queued through HEAVY, under 10 minutes:
# measured ~80 requests/s x 4 tiers, so <= 40k requests a batch) and sum the STD lines: scripts/security/datasets/run-std.sh <log dir>
#   FAST=1 (default) waf-comparison --fast subset; FAST=0 all 1,040,242 benign (about 3.6 h)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../../.." && pwd)
logs=${1:?log dir}
mkdir -p "${logs}"
heavy=${HEAVY:-env}
fast=${FAST:-1}
# dataset:shards (fast legit 155k, mal 74k, leipzig 200k requests)
if [ "${fast}" = 1 ]; then legit=4; else legit=27; fi
for spec in gotestwaf:1 wafcomp-mal:2 wafcomp-legit:${legit} leipzig:5; do
	set_name=${spec%%:*} shards=${spec#*:} shard=0
	while [ "${shard}" -lt "${shards}" ]; do
		log="${logs}/${set_name}-${shard}of${shards}.log"
		if ! grep -q '^RESULT' "${log}" 2>/dev/null; then
			"${heavy}" env ONLY=eval CORPUS_SET=std STD_SETS="${set_name}" STD_SHARD="${shard}/${shards}" STD_FAST="${fast}" \
				WORKERS="${WORKERS:-4}" sh "${repo_root}/tests/dynroute-waf/run.sh" >"${log}" 2>&1 || echo "batch ${log} exit $?"
		fi
		shard=$((shard + 1))
	done
done
# sum: dataset tier counted blocked excluded
grep -h '^STD dataset=' "${logs}"/*.log | awk '{
	for (i = 2; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] }
	key = v["dataset"] " " v["tier"]; if (!(key in c)) order[n++] = key
	c[key] += v["counted"]; b[key] += v["blocked"]; e[key] += v["excluded"]
} END { for (i = 0; i < n; i++) printf "SUM %s counted=%d blocked=%d excluded=%d\n", order[i], c[order[i]], b[order[i]], e[order[i]] }'
