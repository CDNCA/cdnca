#!/bin/sh
# Real-OpenResty test of WAF inspect clauses (libs/edgeconfig WAFInspect,
# edge/openresty/lua/cdnca_waf.lua inspect): named values (args / query /
# form / JSON key path / cookie), multipart upload file names and extensions,
# header names, number targets (request length, header length, argument
# count) and the length filter, negated / contains_all / prefix / suffix /
# equals operators, decoding filters (base64, unicode, HTML) and the body
# overflow choice (inspect the first 64 KiB only, or match).
#   WAF_INSPECT_IMAGE  OpenResty image (default the pinned node release, runtime.env)
# Prints PASS|FAIL <case>; exits non-zero on any failure.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
. "${repo_root}/edge/openresty/runtime.env"
image="${WAF_INSPECT_IMAGE:-${OPENRESTY_IMAGE}}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-waf-inspect.XXXXXX")"
container="cdnca-ge-waf-inspect-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM
mkdir -p "${work}/lua/resty" "${work}/logs"
cp "${repo_root}/edge/openresty/lua/cdnca_waf.lua" "${work}/lua/cdnca_waf.lua"
# ip_list conditions use the vendored lua-resty-ipmatcher, as the node image installs it.
cp "${repo_root}/edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua" "${work}/lua/resty/ipmatcher.lua"
cp "${repo_root}/scripts/security/waf-inspect-cases.lua" "${work}/cases.lua"
cat >"${work}/nginx.conf" <<'EOF'
worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 256; }
http {
  access_log off;
  lua_package_path "$prefix/lua/?.lua;;";
  client_body_buffer_size 16k;
  client_max_body_size 32m;
  client_body_temp_path /tmp/inspect-body;
  server {
    listen 127.0.0.1:18090;
    # X-Spec is an IP list condition spec (cdnca_waf.ip_list).
    location = /iplist {
      content_by_lua_block {
        ngx.say(require("cdnca_waf").ip_list(ngx.decode_base64(ngx.var.http_x_spec)) and "match" or "nomatch")
      }
    }
    location / {
      content_by_lua_block {
        local spec = ngx.var.http_x_spec
        local matched = require("cdnca_waf").inspect(ngx.decode_base64(spec))
        local last = require("cdnca_waf").last_match()
        ngx.header["X-Fragment"] = last and last.fragment or ""
        ngx.header["X-Detector"] = last and last.detector or ""
        ngx.say(matched and "match" or "nomatch")
      }
    }
  }
}
EOF
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none -v "${work}:/w" --entrypoint sh "${image}" -c 'sleep 600' >/dev/null
docker exec "${container}" openresty -p /w/ -c nginx.conf
docker exec "${container}" sh -c 'cd /w && resty cases.lua'
if grep -E '\[(error|crit|alert|emerg)\]' "${work}/logs/error.log"; then
  echo "FAIL error log"
  exit 1
fi
