#!/bin/sh
# Real-OpenResty smoke of the native JA4 module (edge/openresty/native/ja4).
# A uTLS client (scripts/security/ja4probe) sends fixed and browser-like
# ClientHellos; the server echoes $cdnca_ja4. Checks:
#   - module JA4 == the probe's own JA4 from the bytes it sent == Wireshark's
#     independent tls.handshake.ja4 (when tshark is installed) == FoxIO vector
#   - GREASE + reversed extension order, and Chrome's per-connection extension
#     shuffling, give one JA4; no SNI gives 'i'
#   - the edgeconfig-rendered WAF condition blocks exactly the listed JA4
#   - the rendered telemetry $cdnca_ja4_log carries the fingerprint
#   - plain HTTP and HTTP/3 leave the variable empty
#   JA4_IMAGE  native runtime image (docker build -f edge/openresty/native/Dockerfile --target runtime)
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
image="${JA4_IMAGE:-cdnca-native-runtime:g2-ja4}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-ja4-smoke.XXXXXX")"
container="cdnca-ja4-smoke-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM
failures=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 expected=$2 actual=$3 $4"; else echo "FAIL $1 expected=$2 actual=$3 $4"; failures=$((failures + 1)); fi; }

fox=t13d1516h2_8daaf6152771_e5627efa2ab1
mkdir -p "${work}/probe" "${work}/run/logs"
cp "${repo_root}/scripts/security/ja4probe/main.go" "${work}/probe/main.go"
cp "${repo_root}/scripts/security/ja4probe/probe.mod" "${work}/probe/go.mod"
cp "${repo_root}/scripts/security/ja4probe/probe.sum" "${work}/probe/go.sum"
GOWORK=off GOFLAGS=-mod=readonly go -C "${work}/probe" build -trimpath -o "${work}/ja4probe" .
arch="$(docker image inspect "${image}" --format '{{.Architecture}}')"
mkdir -p "${work}/h3"
cp "${repo_root}/edge/openresty/http3/client/main.go" "${work}/h3/main.go"
cp "${repo_root}/edge/openresty/http3/client/client.mod" "${work}/h3/go.mod"
cp "${repo_root}/edge/openresty/http3/client/client.sum" "${work}/h3/go.sum"
GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
  go -C "${work}/h3" build -trimpath -o "${work}/run/h3client" .
check PROBE-SELFTEST "selftest ok ${fox}" "$("${work}/ja4probe" -selftest)" "探针本地 JA4 实现对 FoxIO 示例向量"

# The WAF condition exactly as edgeconfig renders it for a ja4block rule.
waf_block="$(go -C "${repo_root}/libs/edgeconfig" run ./cmd/ja4-condition "${fox}")"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ja4.example.test \
  -keyout "${work}/run/tls.key" -out "${work}/run/tls.crt" >/dev/null 2>&1
cat >"${work}/run/nginx.conf" <<EOF
worker_processes 1; pid /run/ja4/nginx.pid; error_log /run/ja4/error.log notice;
events { worker_connections 256; }
http {
  map \$host \$cdnca_ja4_log { default ""; }
  log_format ja4 escape=json '{"ja4":"\$cdnca_ja4_log","protocol":"\$server_protocol"}';
  server {
    listen 8443 ssl; listen 8443 quic reuseport; http3 on;
    server_name ja4.example.test;
    ssl_certificate /run/ja4/tls.crt; ssl_certificate_key /run/ja4/tls.key;
    set_by_lua_block \$cdnca_ja4_log { return ngx.var.cdnca_ja4 or "" }
    access_log /run/ja4/logs/access.jsonl ja4;
    location = /ja4 { add_header Alt-Svc 'h3=":8443"'; return 200 "\$cdnca_ja4\n"; }
    location = /blocked {
      # Same phase as the rendered security state machine (rewrite).
      rewrite_by_lua_block { if ${waf_block} then return ngx.exit(403) end }
      content_by_lua_block { ngx.say("allowed") }
    }
  }
  server { listen 8080; location = /ja4 { return 200 "[\$cdnca_ja4]\n"; } }
}
EOF
chmod -R a+rwX "${work}/run"
docker run -d --rm --name "${container}" -p 127.0.0.1::8443 -p 127.0.0.1::8080 -v "${work}/run:/run/ja4" \
  --entrypoint sh "${image}" -c 'sleep 600' >/dev/null
docker exec "${container}" openresty -p /run/ja4/ -c nginx.conf ||
  { echo "openresty failed to start" >&2; cat "${work}/run/error.log" >&2 2>/dev/null; exit 1; }
tls_port="$(docker port "${container}" 8443/tcp | head -1 | sed 's/.*://')"
http_port="$(docker port "${container}" 8080/tcp | head -1 | sed 's/.*://')"
check MODULE-IN-V 1 "$(docker exec "${container}" sh -c 'openresty -V 2>&1 | grep -c -- "--add-module=[^ ]*/cdnca-ja4"')" "openresty -V 列出 JA4 模块"
for _ in $(seq 1 50); do "${work}/ja4probe" -addr "127.0.0.1:${tls_port}" -profile fixed >/dev/null 2>&1 && break; sleep 0.2; done

probe() { "${work}/ja4probe" -addr "127.0.0.1:${tls_port}" "$@"; }
field() { sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p"; }
for profile in fixed fixed-grease-shuffled fixed-no-sni safari edge firefox chrome; do
  probe -profile "${profile}" -count 4 -pcap "${work}/${profile}.pcap" >"${work}/${profile}.jsonl"
  local_ja4="$(field local_ja4 <"${work}/${profile}.jsonl" | sort -u | tr '\n' ' ' | sed 's/ $//')"
  server_ja4="$(field server_ja4 <"${work}/${profile}.jsonl" | sort -u | tr '\n' ' ' | sed 's/ $//')"
  check "${profile}-MODULE" "${local_ja4}" "${server_ja4}" "4 次握手，模块 JA4 与探针按所发字节计算的 JA4 一致且唯一"
  if command -v tshark >/dev/null 2>&1; then
    wireshark="$(tshark -r "${work}/${profile}.pcap" -T fields -e tls.handshake.ja4 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')"
    check "${profile}-WIRESHARK" "${wireshark}" "${server_ja4}" "Wireshark tls.handshake.ja4（独立实现）"
  fi
done
check FIXED-FOXIO "${fox}" "$(field server_ja4 <"${work}/fixed.jsonl" | sort -u)" "FoxIO JA4.md 示例套件/扩展/签名算法"
check GREASE-SHUFFLE "${fox}" "$(field server_ja4 <"${work}/fixed-grease-shuffled.jsonl" | sort -u)" "加 GREASE 且扩展倒序，JA4 不变"
check NO-SNI "t13i1515h2_8daaf6152771_e5627efa2ab1" "$(field server_ja4 <"${work}/fixed-no-sni.jsonl" | sort -u)" "无 SNI：i 且扩展数 15"
orders="$(field extension_order <"${work}/chrome.jsonl" | sort -u | wc -l | tr -d ' ')"
[ "${orders}" -gt 1 ] && shuffled=yes || shuffled=no
check CHROME-SHUFFLED yes "${shuffled}" "Chrome 配置每次扩展顺序不同（${orders} 种）而 JA4 唯一（见 chrome-MODULE）"

check WAF-BLOCK 403 "$(probe -profile fixed -path /blocked | sed -n 's/.*"status":\([0-9]*\).*/\1/p')" "edgeconfig 渲染的 JA4 条件拦截命中指纹"
check WAF-OTHER 200 "$(probe -profile safari -path /blocked | sed -n 's/.*"status":\([0-9]*\).*/\1/p')" "其它指纹放行"
check PLAIN-HTTP "[]" "$(curl -s --max-time 5 "http://127.0.0.1:${http_port}/ja4")" "明文 HTTP 无指纹"
logged="$(grep -c "\"ja4\":\"${fox}\",\"protocol\":\"HTTP/1.1\"" "${work}/run/logs/access.jsonl" || true)"
[ "${logged}" -ge 4 ] && logged=ok
check LOG-JA4 ok "${logged}" "访问日志 \$cdnca_ja4_log 写入真实 JA4"
h3="$(docker exec "${container}" /run/ja4/h3client request -url https://127.0.0.1:8443/ja4 -server-name ja4.example.test 2>/dev/null)"
h3body="$(printf '%s' "${h3}" | tr -d ' \n' | sed -n 's/.*"protocol":"HTTP\/3.0","status":200,"body":"\([^"]*\)".*/[\1]/p')"
echo "INFO h3client: $(printf '%s' "${h3}" | tr -d '\n' | cut -c1-200)"
check H3-EMPTY '[]' "${h3body}" "HTTP/3(QUIC) 不采集：200 且 \$cdnca_ja4 为空（h3client 去掉末尾换行）"
h3log="$(grep -c '"ja4":"","protocol":"HTTP/3.0"' "${work}/run/logs/access.jsonl" || true)"
check H3-LOG-EMPTY 1 "${h3log}" "HTTP/3 访问日志 ja4 为空（Agent 记为 null）"
docker exec "${container}" sh -c 'grep -E "\[(alert|emerg|crit)\]" /run/ja4/error.log | tail -5' || true
echo "image=${image} failures=${failures}"
[ "${failures}" -eq 0 ]
