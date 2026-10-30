#!/bin/sh
# Real-OpenResty smoke of Brotli/WebP: ngx_brotli (native step 25), the
# compression levels with variables (step 26), the per-site compression gate
# of cdnca_dynroute (br / gzip / plain by site settings and Accept-Encoding)
# and cdnca_webp (JPEG/PNG to WebP in the worker thread pool, Vary: Accept,
# fallback to the original, large images skipped). The servers carry the
# skeleton's directives (edgeskeleton siteGzipServer + siteBrotliServer); a
# local origin serves the fixtures. Bodies are decompressed on the host
# (brotli, gzip) and compared byte for byte.
#   BROTLI_WEBP_IMAGE  runtime image (edge/openresty/native/Dockerfile --target
#                      runtime); one --rm --network none container.
# Prints PASS|FAIL <id> expected=<..> actual=<..> <note>; exits non-zero on failures.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
image="${BROTLI_WEBP_IMAGE:-cdnca-native-runtime:edge-golden}"
command -v brotli >/dev/null || { echo "BLOCKED: host brotli (decoder) missing" >&2; exit 69; }
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-brotli-webp.XXXXXX")"
container="cdnca-brotli-webp-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; [ -n "${KEEP:-}" ] || rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM
run=/run/bw
mkdir -p "${work}/run/origin" "${work}/run/lua"
cp "${repo_root}/edge/openresty/dynroute/cdnca_dynroute.lua" "${repo_root}/edge/openresty/dynroute/cdnca_webp.lua" \
  "${repo_root}/edge/openresty/dynroute/cdnca_webp_codec.lua" "${work}/run/lua/"
# text fixture: ~200 KiB of varied CSS-like text (levels make a difference)
python3 - "${work}/run/origin/a.css" <<'PY'
import random, sys
random.seed(7)
words = ['margin', 'padding', 'color', 'border', 'font', 'display', 'flex', 'grid', 'width', 'height', 'top', 'left']
with open(sys.argv[1], 'w') as out:
    for i in range(6000):
        out.write('.c%d { %s: %dpx; %s: #%06x; }\n' % (random.randint(0, 99999), random.choice(words), random.randint(0, 999),
                                                   random.choice(words), random.randint(0, 0xffffff)))
PY
head -c 10 "${work}/run/origin/a.css" >"${work}/run/origin/tiny.css"

cat >"${work}/run/nginx.conf" <<EOF
worker_processes 2; pid ${run}/nginx.pid; error_log ${run}/error.log info;
thread_pool cdnca_webp threads=2 max_queue=64;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path ${run}/body; proxy_temp_path ${run}/proxy;
  fastcgi_temp_path ${run}/fastcgi; uwsgi_temp_path ${run}/uwsgi; scgi_temp_path ${run}/scgi;
  lua_package_path "${run}/lua/?.lua;;";
  lua_shared_dict cdnca_webp 64m;
  types { text/css css; text/plain txt; image/jpeg jpg; image/png png; }
  gzip_comp_level 1;
  init_by_lua_block {
    -- cdnca_dynroute needs the node modules; only its gate is exercised here
    package.loaded["cdnca_site"] = {} package.loaded["cdnca_tls"] = {} package.loaded["cdnca_origin"] = {}
    package.loaded["cdnca_security"] = {} package.loaded["cdnca_filters"] = {} package.loaded["cdnca_limits"] = {}
    package.loaded["cdnca_telemetry"] = {} package.loaded["cdnca_managed_waf"] = {} package.loaded["siteaccess.engine"] = {}
    SITES = {
      br = { site_id = "br", access = { compression = { enabled = true, types = { "text/css" }, min_length_bytes = 100,
             encodings = { "br", "gzip" }, gzip_level = 9, brotli_level = 11 } } },
      gz = { site_id = "gz", access = { compression = { enabled = true, types = { "text/css" }, min_length_bytes = 100 } } },
      bronly = { site_id = "bronly", access = { compression = { enabled = true, types = { "text/css" }, min_length_bytes = 100, encodings = { "br" } } } },
      off = { site_id = "off", access = { compression = { enabled = false, types = {} } } },
      webp = { site_id = "webp", access = { webp = { enabled = true } } },
    }
    DYN = require "cdnca_dynroute"
    WEBP = require "cdnca_webp"
  }
  server {
    listen 127.0.0.1:8081;
    location / { root ${run}/origin; etag on; }
    location /noetag/ { root ${run}/origin; etag off; more_clear_headers Last-Modified; rewrite ^/noetag(/.*)$ \$1 break; }
  }
  server {
    listen 127.0.0.1:8080;
    # edgeskeleton siteGzipServer + siteBrotliServer
    gzip on; gzip_types *; gzip_min_length 0; gzip_proxied any; gzip_vary off;
    brotli on; brotli_types *; brotli_min_length 0;
    gzip_comp_level \$cdnca_compress_gzip_level; brotli_comp_level \$cdnca_compress_brotli_level;
    set \$cdnca_compress_gzip_level ""; set \$cdnca_compress_brotli_level "";
    location ~ ^/(?<site>[a-z]+)(?<path>/.*)\$ {
      proxy_http_version 1.1;
      proxy_set_header Accept-Encoding "";
      proxy_pass http://127.0.0.1:8081\$path;
      header_filter_by_lua_block {
        local site = SITES[ngx.var.site]
        WEBP.header_filter(site)
        DYN.compression_gate(site, { site_gzip = { disabled = true, vary = false, min_length = 20, types = {} }, site_brotli = true })
      }
      body_filter_by_lua_block { WEBP.body_filter() }
    }
  }
}
EOF
# WebP fixtures and the large-image case are written by the runtime's own libgd
cat >"${work}/run/fixtures.lua" <<'EOF'
local ffi = require "ffi"
ffi.cdef "typedef struct gdImageStruct gdImage; gdImage *gdImageCreateTrueColor(int,int); void *gdImageJpegPtr(gdImage*,int*,int); void *gdImagePngPtr(gdImage*,int*); void gdFree(void*); void gdImageFilledRectangle(gdImage*,int,int,int,int,int); void gdImageDestroy(gdImage*);"
local gd = ffi.load("libgd.so.3")
local function image(w, h, path, png)
  local im = gd.gdImageCreateTrueColor(w, h)
  -- photo-like content: smooth gradients with noise (a flat PNG would
  -- already be smaller than its WebP and stay the original by design)
  math.randomseed(3)
  for y = 0, h - 1, 2 do for x = 0, w - 1, 2 do
    local n = math.random(0, 24)
    gd.gdImageFilledRectangle(im, x, y, x + 1, y + 1, ((x + n) % 256) * 65536 + ((y + n) % 256) * 256 + ((x + y + n) % 256))
  end end
  local n = ffi.new("int[1]")
  local p = png and gd.gdImagePngPtr(im, n) or gd.gdImageJpegPtr(im, n, 92)
  local f = assert(io.open(path, "wb")); f:write(ffi.string(p, n[0])); f:close()
  gd.gdFree(p); gd.gdImageDestroy(im)
end
local root = arg[1]
image(400, 300, root .. "/a.jpg") image(256, 256, root .. "/a.png", true)
image(4000, 2500, root .. "/big.jpg")
-- a damaged JPEG: valid header, truncated scan
local f = assert(io.open(root .. "/a.jpg", "rb")); local data = f:read("*a"); f:close()
f = assert(io.open(root .. "/broken.jpg", "wb")); f:write(data:sub(1, 600)); f:close()
EOF
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none -v "${work}/run:${run}" --entrypoint sh "${image}" -c 'sleep 900' >/dev/null
docker exec "${container}" /usr/local/openresty/luajit/bin/luajit "${run}/fixtures.lua" "${run}/origin"
docker exec "${container}" openresty -p "${run}/" -c "${run}/nginx.conf" ||
  { echo "openresty failed to start" >&2; cat "${work}/run/error.log" >&2 2>/dev/null; exit 1; }
sleep 1

# fetch NAME PATH [HEADER...]: body to run/NAME, response headers to run/NAME.h
fetch() {
  name=$1 path=$2; shift 2
  set -- "$@"
  args=""
  for header in "$@"; do args="${args} --header '${header}'"; done
  docker exec "${container}" sh -c "wget -q -S -O ${run}/${name} ${args} http://127.0.0.1:8080${path} 2>${run}/${name}.h" || true
}
header() { value=$(grep -i "^  $2:" "${work}/run/$1.h" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'); echo "${value:-none}"; }
failures=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 expected=$2 actual=$3 $4"; else echo "FAIL $1 expected=$2 actual=$3 $4"; failures=$((failures + 1)); fi; }
same() { cmp -s "$1" "$2" && echo same || echo differs; }
css="${work}/run/origin/a.css"

# Brotli: encoded, decodes to the original; preferred when both are accepted
fetch br1 /br/a.css 'Accept-Encoding: gzip, deflate, br'
check BR-ENCODING br "$(header br1 Content-Encoding)" "客户端同时支持时用 Brotli"
brotli -d -c "${work}/run/br1" >"${work}/run/br1.out" 2>/dev/null || :
check BR-DECODES same "$(same "${work}/run/br1.out" "${css}")" "Brotli 解压与原文一致"
check BR-VARY Accept-Encoding "$(header br1 Vary)" "Brotli 响应带 Vary: Accept-Encoding"
# level variable (11 vs default 6) changes the size
fetch br6 /bronly/a.css 'Accept-Encoding: br'
s11=$(wc -c <"${work}/run/br1"); s6=$(wc -c <"${work}/run/br6")
check BR-LEVEL smaller "$([ "${s11}" -lt "${s6}" ] && echo smaller || echo "${s11}>=${s6}")" "站点 Brotli 级别 11 比默认 6 更小（补丁 26 变量生效）"
# gzip fallback with the site level
fetch gz9 /br/a.css 'Accept-Encoding: gzip'
check GZIP-ENCODING gzip "$(header gz9 Content-Encoding)" "只接受 gzip 时回落 gzip"
gzip -d -c <"${work}/run/gz9" >"${work}/run/gz9.out" 2>/dev/null || :
check GZIP-DECODES same "$(same "${work}/run/gz9.out" "${css}")" "gzip 解压与原文一致"
fetch gz1 /gz/a.css 'Accept-Encoding: gzip, br'
check GZIP-ONLY-SITE gzip "$(header gz1 Content-Encoding)" "只开 gzip 的站点不发 Brotli"
g9=$(wc -c <"${work}/run/gz9"); g1=$(wc -c <"${work}/run/gz1")
check GZIP-LEVEL smaller "$([ "${g9}" -lt "${g1}" ] && echo smaller || echo "${g9}>=${g1}")" "站点 gzip 级别 9 比 http 级 1 更小"
fetch bo /bronly/a.css 'Accept-Encoding: gzip'
check BR-ONLY-NO-GZIP none "$(header bo Content-Encoding)" "只开 Brotli 的站点对 gzip 客户端不压缩"
# off / q=0 / too small / other type
fetch off /off/a.css 'Accept-Encoding: gzip, br'
check OFF-PLAIN none "$(header off Content-Encoding)" "关闭压缩时不压"
check OFF-BODY same "$(same "${work}/run/off" "${css}")" "关闭时原文返回"
fetch q0 /br/a.css 'Accept-Encoding: br;q=0, gzip'
check BR-Q0 gzip "$(header q0 Content-Encoding)" "br;q=0 不用 Brotli"
fetch tiny /br/tiny.css 'Accept-Encoding: br'
check MIN-LENGTH none "$(header tiny Content-Encoding)" "小于最小长度不压"
fetch img /br/a.jpg 'Accept-Encoding: br'
check TYPE-NOT-LISTED none "$(header img Content-Encoding)" "不在类型列表的不压"

# WebP: first request original + Vary: Accept, then the WebP variant
fetch w1 /webp/a.jpg 'Accept: image/webp,*/*'
check WEBP-FIRST-ORIGINAL image/jpeg "$(header w1 Content-Type)" "第一次返回原图（后台转换）"
check WEBP-VARY Accept "$(header w1 Vary)" "可转换图片带 Vary: Accept"
sleep 2
fetch w2 /webp/a.jpg 'Accept: image/webp,*/*'
check WEBP-CONVERTED image/webp "$(header w2 Content-Type)" "转换完成后返回 WebP"
check WEBP-MAGIC WEBP "$(dd if="${work}/run/w2" bs=1 skip=8 count=4 2>/dev/null)" "WebP 文件头"
check WEBP-LENGTH "$(wc -c <"${work}/run/w2" | tr -d ' ')" "$(header w2 Content-Length)" "Content-Length 为变体长度"
check WEBP-SMALLER smaller "$([ "$(wc -c <"${work}/run/w2")" -lt "$(wc -c <"${work}/run/origin/a.jpg")" ] && echo smaller || echo larger)" "变体比原图小"
check WEBP-ETAG weak "$(header w2 ETag | grep -q '^W/' && echo weak || echo other)" "变体使用自己的弱 ETag"
fetch w3 /webp/a.jpg 'Accept: image/jpeg,*/*'
check WEBP-NOT-ACCEPTED image/jpeg "$(header w3 Content-Type)" "不接受 WebP 的客户端拿原图"
check WEBP-ORIGINAL-BODY same "$(same "${work}/run/w3" "${work}/run/origin/a.jpg")" "原图字节不变"
fetch p1 /webp/a.png 'Accept: image/webp'
sleep 2
fetch p2 /webp/a.png 'Accept: image/webp'
check WEBP-PNG image/webp "$(header p2 Content-Type)" "PNG 转 WebP"
# fallback: a damaged image stays the original
fetch b1 /webp/broken.jpg 'Accept: image/webp'
sleep 2
fetch b2 /webp/broken.jpg 'Accept: image/webp'
check WEBP-BROKEN-FALLBACK image/jpeg "$(header b2 Content-Type)" "损坏图片转换失败回落原图"
check WEBP-BROKEN-BODY same "$(same "${work}/run/b2" "${work}/run/origin/broken.jpg")" "回落时原图字节不变"
# large image (over 5 MiB or 8 megapixels) is skipped
fetch g1 /webp/big.jpg 'Accept: image/webp'
sleep 2
fetch g2 /webp/big.jpg 'Accept: image/webp'
check WEBP-LARGE-SKIPPED image/jpeg "$(header g2 Content-Type)" "超出像素上限的大图不转"
# no validator: never converted
fetch n1 /webp/noetag/a.png 'Accept: image/webp'
sleep 2
fetch n2 /webp/noetag/a.png 'Accept: image/webp'
check WEBP-NO-VALIDATOR image/png "$(header n2 Content-Type)" "无 ETag/Last-Modified 不转"
check WEBP-NO-VALIDATOR-VARY none "$(header n2 Vary)" "不转时不加 Vary"
# site without WebP
fetch o1 /gz/a.jpg 'Accept: image/webp'
sleep 1
fetch o2 /gz/a.jpg 'Accept: image/webp'
check WEBP-SITE-OFF image/jpeg "$(header o2 Content-Type)" "未开 WebP 的站点不转"

grep -E "\[(error|crit|alert|emerg)\]" "${work}/run/error.log" | grep -v "using uninitialized" | tail -5 || true
grep -c "gd-jpeg" "${work}/run/error.log" >/dev/null 2>&1 || true
echo "runtime=${image} failures=${failures}"
[ "${failures}" -eq 0 ]
