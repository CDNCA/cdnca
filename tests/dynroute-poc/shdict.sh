#!/bin/sh
# ADR 0009 §8.5 item 1: lua_shared_dict as the site index — memory per key,
# lookup cost, cold rebuild from the on-disk index file, reload/resize and
# eviction semantics. Measures 10k/50k/100k keys and extrapolates to 1M:
#   memory:  used(100k) + slope(10k→100k) × 900k   (slab is per-key; slope = marginal bytes/key)
#   rebuild: us_per_record(100k) × 1M, and × log2(1e6)/log2(1e5) = 1.2 for the rbtree depth
. "$(dirname -- "$0")/lib.sh"
command -v jq >/dev/null || { echo "BLOCKED: jq required on the host" >&2; exit 69; }
build_probe
cp -R "${poc_dir}/shdict" "${work}/shdict"
sed 's/__INDEX_SIZE__/256m/' "${poc_dir}/shdict/nginx.conf" >"${work}/shdict/nginx.conf"
start_container
get() { in_c "wget -q -O - 'http://127.0.0.1:8080$1'"; }
restart() {
  in_c 'openresty -p /poc/shdict/ -c nginx.conf -s stop 2>/dev/null; sleep 0.5' || true
  nginx_start shdict
  for _ in 1 2 3 4 5 6 7 8 9 10; do get /stats >/dev/null 2>&1 && return 0; sleep 0.2; done
  return 1
}
results="${work}/fill.jsonl"
: >"${results}"
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'

echo "== memory and set cost (fresh 256m zone per run, 1 worker)"
for enc in json binary md5 single compact; do
  for n in 10000 50000 100000; do
    restart
    line="$(get "/fill?n=${n}&enc=${enc}")"
    printf '%s\n' "${line}" >>"${results}"
    printf '%s\n' "${line}" | jq -c '{enc,n,key_len,value_len,bytes_per_key,rss_bytes_per_key,set_us_per_key,keys}'
    if [ "${n}" = 100000 ]; then
      get "/bench?n=${n}&enc=${enc}" | jq -c '{enc,n,hit_us,miss4_us,found,iterations}'
    fi
  done
done
echo "== extrapolation to 1,000,000 keys"
jq -s -c 'group_by(.enc)[] | (map(select(.n==10000))[0]) as $a | (map(select(.n==100000))[0]) as $b |
  ((($b.used_after-$b.used_before)-($a.used_after-$a.used_before))/90000) as $slope |
  {enc:$b.enc, bytes_per_key_100k:$b.bytes_per_key, marginal_bytes_per_key:$slope,
   est_1m_MiB:((($b.used_after-$b.used_before)+$slope*900000)/1048576),
   rss_per_key_100k:$b.rss_bytes_per_key}' "${results}"
check SAFE-SET-FILL 15 "$(jq -s '[.[]|select(.error==null and .keys==.n)]|length' "${results}")" "15 次填充全部写入，无 no memory"

echo "== cold rebuild from the index file (compact encoding, 100k records)"
restart
get "/dump?n=100000&enc=compact&path=/poc/idx.bin" >/dev/null
in_c 'ls -l /poc/idx.bin' | awk '{print "index file bytes:", $5}'
for mode in "yield=1&slice=1000" "yield=1&slice=5000" "yield=0"; do
  restart
  get "/fill?n=100000&enc=compact" >/dev/null
  # latency probe on the same (single) worker while the rebuild runs
  # ~2 s of back-to-back requests; the rebuild (~0.1 s) starts 0.5 s in
  docker exec "${container}" /poc/probe get -url http://127.0.0.1:8080/lookup -n 20000 -summary >"${work}/lat.json" &
  probe_pid=$!
  sleep 0.5
  get "/rebuild?path=/poc/idx.bin&${mode}" >/dev/null
  for _ in $(seq 1 100); do
    state="$(get /status)"
    case "${state}" in *'"done"'*|failed*|locked) break ;; esac
    sleep 0.1
  done
  wait "${probe_pid}" || true
  printf '%s\n' "${state}" | jq -c "{mode:\"${mode}\",records,total_ms,us_per_record,max_slice_ms,slices}"
  printf 'latency during rebuild (%s): %s\n' "${mode}" "$(cat "${work}/lat.json")"
  if [ "${mode}" = "yield=1&slice=1000" ]; then
    us="$(printf '%s' "${state}" | jq '.us_per_record')"
    echo "rebuild 1M estimate: linear $(echo "${us} * 1000000 / 1000000" | bc -l | cut -c1-6) s, with rbtree depth factor $(echo "${us} * 1.2" | bc -l | cut -c1-6) s"
    check REBUILD-COUNT 100000 "$(get /stats | jq '.keys')" "重建后键数"
  fi
done

echo "== reload keeps the zone; resizing it drops the contents"
restart
get "/marker?set=gen-42" >/dev/null
nginx_reload shdict
check RELOAD-SAME-SIZE gen-42 "$(get /marker)" "同名同尺寸 reload 后索引保留"
sed 's/__INDEX_SIZE__/128m/' "${poc_dir}/shdict/nginx.conf" >"${work}/shdict/nginx.conf"
nginx_reload shdict
check RELOAD-RESIZED absent "$(get /marker)" "改尺寸 reload 后索引清空，需要重建"

echo "== eviction: safe_set fails, set evicts silently"
ev="$(get /evict)"
echo "${ev}"
check SAFE-SET-NOMEM '"no memory"' "$(printf '%s' "${ev}" | jq '.safe_set_err')" "满了 safe_set 返回 no memory"
check SET-EVICTS true "$(printf '%s' "${ev}" | jq '.set_forcible')" "set 强制淘汰（索引绝不能用 set）"
finish
