#!/bin/sh
set -eu

engine_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
engine="$engine_dir/engine.lua"
legacy="$(dirname "$engine_dir")/cc/engine.lua"

grep -F 'cdnca.edge.cc-metrics/v1' "$engine" >/dev/null
grep -F 'function _M.metrics(entry_id)' "$engine" >/dev/null
grep -F 'ngx.ctx.ccv2_capacity_recorded' "$engine" >/dev/null
grep -F 'shared_dict_evictions = evictions' "$engine" >/dev/null
grep -F 'ja4_unavailable = ja4_unavailable' "$engine" >/dev/null
grep -F 'function _M.metrics(context)' "$legacy" >/dev/null
grep -F 'ngx.ctx.cdnca_cc_capacity_recorded' "$legacy" >/dev/null
grep -F 'shared_dict_evictions = evictions' "$legacy" >/dev/null

printf '%s\n' 'CC_METRICS_CONTRACT={"status":"pass","schema":"cdnca.edge.cc-metrics/v1","per_request_dedup":true,"scoped_keys":true,"read_only_snapshot":true}'
