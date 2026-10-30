#!/bin/sh
# ge-analytics: a package's bandwidth limit on the node (libs/edgeconfig
# PackageBandwidthDirective) in the pinned OpenResty: one subscription capped
# at 16 Mbit/s (2 MB/s). One 4 MB download takes ~2 s; two concurrent ones
# share the budget (~4 s each); after both finish the in-flight count is back
# to 0, so the next single download is ~2 s again. Prints PASS/FAIL.
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-package-bandwidth.XXXXXX")"
container="cdnca-package-bandwidth-$(basename "${work}" | tr -dc 'a-zA-Z0-9')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM

CDNCA_PACKAGE_BANDWIDTH_SMOKE_OUT="${work}" go -C "${repo_root}/libs/edgeconfig" test . -run '^TestWritePackageBandwidthForSmoke$' -count=1 >/dev/null
mkdir -p "${work}/logs" "${work}/html"
head -c 4194304 /dev/zero >"${work}/html/big.bin"
cat >"${work}/nginx.conf" <<'CONF'
worker_processes 1; pid /work/nginx.pid; error_log /work/logs/error.log;
events { worker_connections 64; }
http {
  access_log off;
  include /work/package-http.conf;
  server {
    listen 127.0.0.1:8080;
    include /work/package-server.conf;
    location = /active { content_by_lua_block { ngx.say(ngx.shared.cdnca_package_bandwidth:get("22222222-2222-4222-8222-222222222222") or 0) } }
    location / { root /work/html; }
  }
}
CONF
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none -v "${work}:/work" --entrypoint sh "${OPENRESTY_IMAGE}" \
  -c 'exec openresty -g "daemon off;" -p /work/ -c nginx.conf' >/dev/null
sleep 0.5
docker exec "${container}" true 2>/dev/null || { cat "${work}/logs/error.log" >&2; exit 1; }

failed=0
timed() { docker exec "${container}" sh -c "$1"; }
between() { awk -v v="$2" -v lo="$3" -v hi="$4" -v n="$1" 'BEGIN { if (v >= lo && v <= hi) { print "PASS " n " = " v "s"; exit 0 } print "FAIL " n " = " v "s (want " lo ".." hi ")"; exit 1 }' || failed=1; }

single="$(timed "curl -s -o /dev/null -w '%{time_total}' http://127.0.0.1:8080/big.bin")"
between "single download (4 MB at 2 MB/s)" "${single}" 1.6 2.8
pair="$(timed "curl -s -o /dev/null -w '%{time_total}\n' http://127.0.0.1:8080/big.bin & sleep 0.05; curl -s -o /dev/null -w '%{time_total}\n' http://127.0.0.1:8080/big.bin; wait" | sort -n | tail -1)"
between "second of two concurrent downloads (shared budget)" "${pair}" 3.2 5.2
# /active is a request of the subscription too: it counts itself.
active="$(timed "curl -s http://127.0.0.1:8080/active")"
if [ "${active}" = "1" ]; then echo "PASS in-flight count released (only the probe itself: ${active})"; else echo "FAIL in-flight count = ${active}, want 1"; failed=1; fi
again="$(timed "curl -s -o /dev/null -w '%{time_total}' http://127.0.0.1:8080/big.bin")"
between "single download after release" "${again}" 1.6 2.8
exit "${failed}"
