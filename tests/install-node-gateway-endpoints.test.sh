#!/usr/bin/env bash
# install-node.sh node-install-defaults 的 gateway_endpoints 字符集校验（ih-control 报：旧写法在 bash 5 上放行 ';' 等）。
set -euo pipefail
script=${1:-$(dirname "$0")/../scripts/install-node.sh}
line=$(grep -E "^\s+gateway_endpoints\) " "$script")
re=$(printf '%s' "$line" | sed -nE "s/.*endpoints_re='([^']*)'.*/\1/p")
[ -n "$re" ] || { echo "FAIL: gateway_endpoints 校验没有用变量形式的字符集"; exit 1; }
ok=0
for v in 'a.example:443|a.example|grpc' '[::1]:443|x|ws a.example:29402|a.example|grpc'; do
  [[ "$v" =~ $re ]] || { echo "FAIL: 合法值被拒：$v"; ok=1; }
done
grep -A2 -E "^\s+gateway_endpoints\) " "$script" | grep -qF '${#value}" -le 2048' || { echo "FAIL: gateway_endpoints 缺长度上限"; ok=1; }
for v in 'a:1;rm -rf /' 'a:1$(id)' 'a:1`id`' 'a:1&b'; do
  if [[ "$v" =~ $re ]]; then echo "FAIL: 非法值被放行：$v"; ok=1; fi
done
[ "$ok" = 0 ] && echo "PASS install-node gateway_endpoints charset"
exit "$ok"
