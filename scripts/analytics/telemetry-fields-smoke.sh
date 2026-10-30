#!/bin/sh
# ge-analytics: runs the node's http{} telemetry (libs/edgeconfig
# RenderTelemetryHTTP: $request_time -> duration_us, User-Agent -> browser/OS
# family maps, the access log_format) in the pinned OpenResty and checks the
# access log fields with real User-Agents and a rate-limited 2 MB download.
# Prints PASS/FAIL per check; exit 1 on any failure.
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-telemetry-fields.XXXXXX")"
container="cdnca-telemetry-fields-$(basename "${work}" | tr -dc 'a-zA-Z0-9')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM

CDNCA_TELEMETRY_SMOKE_OUT="${work}" go -C "${repo_root}/libs/edgeconfig" test . -run '^TestWriteTelemetryHTTPForSmoke$' -count=1 >/dev/null
mkdir -p "${work}/logs" "${work}/html"
head -c 2097152 /dev/zero >"${work}/html/big.bin"
cat >"${work}/nginx.conf" <<'CONF'
worker_processes 1; pid /work/nginx.pid; error_log /work/logs/error.log;
events { worker_connections 64; }
http {
  include /work/telemetry-http.conf;
  server {
    listen 127.0.0.1:8080;
    include /work/telemetry-server.conf;
    location = /big.bin { root /work/html; limit_rate 1m; limit_rate_after 0; }
    location / { default_type text/plain; return 200 "ok\n"; }
  }
}
CONF
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none -v "${work}:/work" --entrypoint sh "${OPENRESTY_IMAGE}" \
  -c 'exec openresty -g "daemon off;" -p /work/ -c nginx.conf' >/dev/null
sleep 0.5
docker exec "${container}" true 2>/dev/null || { cat "${work}/logs/error.log" >&2; exit 1; }
for _ in $(seq 1 50); do docker exec "${container}" sh -c 'curl -fsS -o /dev/null http://127.0.0.1:8080/ready' 2>/dev/null && break; sleep 0.2; done

ua() { docker exec "${container}" curl -fsS -o /dev/null -A "$1" "http://127.0.0.1:8080/$2"; }
ua 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36' chrome-windows
ua 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0' edge-windows
ua 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1' safari-ios
ua 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36 MicroMessenger/8.0.50' wechat-android
ua 'Mozilla/5.0 (Phone; OpenHarmony 4.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 ArkWeb/4.1.6.1 Mobile HuaweiBrowser/5.0.4.300' chrome-harmonyos
ua 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:130.0) Gecko/20100101 Firefox/130.0' firefox-macos
ua 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' bot-other
ua 'curl/8.9.1' bot-curl
docker exec "${container}" curl -fsS -o /dev/null -A 'x' "http://127.0.0.1:8080/big.bin"
sleep 0.5
log="${work}/logs/access.json"

failed=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: got '$2' want '$3'"; failed=1; fi; }
field() { python3 -c 'import json,sys
for line in open(sys.argv[1]):
    e=json.loads(line)
    if e["path"]==sys.argv[2]: print(e[sys.argv[3]])' "${log}" "$1" "$2"; }
for case in chrome-windows:chrome:windows edge-windows:edge:windows safari-ios:safari:ios wechat-android:wechat:android \
  chrome-harmonyos:chrome:harmonyos firefox-macos:firefox:macos bot-other:bot:other bot-curl:bot:other; do
  path="${case%%:*}"; rest="${case#*:}"
  check "${path} browser" "$(field "/${path}" client_browser)" "${rest%%:*}"
  check "${path} os" "$(field "/${path}" client_os)" "${rest#*:}"
done
duration="$(field /big.bin duration_us)"
# 2 MB at 1 MB/s: at least 1.5 s of transfer time is recorded.
if [ "${duration}" -ge 1500000 ] 2>/dev/null; then echo "PASS big.bin duration_us=${duration}"; else echo "FAIL big.bin duration_us=${duration}"; failed=1; fi
check "small response duration is a number" "$(field /chrome-windows duration_us | tr -dc '0-9' | head -c1 | wc -c | tr -d ' ')" "1"
python3 -c 'import json,sys
[json.loads(l) for l in open(sys.argv[1])]' "${log}" && echo "PASS every access line is valid JSON" || { echo "FAIL invalid JSON line"; failed=1; }
exit "${failed}"
