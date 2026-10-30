#!/bin/sh
# fix-mktsiteconf4: site basic auth with per-user salted SHA-256 on a real
# OpenResty (node runtime image, one --rm --network none container):
#   ok        alice:s3cret (salt 000102..0f) passes, the origin sees no
#             Authorization header;
#   wrong     a wrong password, an unknown user, a missing header: 401 with
#             WWW-Authenticate;
#             (engine.access takes no site ID: the hash is site independent);
#   exclude   an excluded prefix passes without credentials.
#   edge/openresty/siteaccess/basic_auth_test.sh
#   CDNCA_SITEACCESS_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../../.." && pwd)
image=${CDNCA_SITEACCESS_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
work=$(mktemp -d /tmp/cdnca-siteaccess.XXXXXX)
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/lua/siteaccess" "${work}/out"
cp "${repo_root}/edge/openresty/siteaccess/engine.lua" "${work}/lua/siteaccess/engine.lua"

# SHA-256(bytes 00..0f || "s3cret")
hash=$(printf '000102030405060708090a0b0c0d0e0f' | xxd -r -p | { cat; printf 's3cret'; } | sha256sum | cut -d' ' -f1)

cat >"${work}/nginx.conf" <<EOF
worker_processes 1;
error_log /sa/out/error.log notice;
pid /tmp/sa-nginx.pid;
events { worker_connections 64; }
http {
  access_log off;
  lua_package_path "/sa/lua/?.lua;;";
  init_by_lua_block {
    local function unhex(v) return (v:gsub("..", function(p) return string.char(tonumber(p, 16)) end)) end
    SA_SETTINGS = { basic_auth = { realm = "staff", exclude = { "/public/" },
      users = { alice = { salt = unhex("000102030405060708090a0b0c0d0e0f"), sha256 = "${hash}" } } } }
  }
  server {
    listen 127.0.0.1:8080;
    location / {
      access_by_lua_block { require("siteaccess.engine").access(SA_SETTINGS) }
      content_by_lua_block { ngx.say("origin auth=", ngx.var.http_authorization or "none") }
    }
  }
}
EOF

docker run --rm --network none -v "${work}:/sa" "${image}" sh -c '
set -eu
openresty -p /sa -c /sa/nginx.conf
sleep 0.5
code() { curl -s -o /sa/out/body -w "%{http_code}" "$@"; }
fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: got $2 want $3"; fail=1; fi; }
check ok "$(code -u alice:s3cret http://127.0.0.1:8080/)" 200
grep -q "origin auth=none" /sa/out/body && echo "PASS ok-no-credential" || { echo "FAIL ok-no-credential"; fail=1; }
check wrong "$(code -u alice:wrong http://127.0.0.1:8080/)" 401
check unknown "$(code -u bob:s3cret http://127.0.0.1:8080/)" 401
check missing "$(code http://127.0.0.1:8080/)" 401
curl -s -D - -o /dev/null http://127.0.0.1:8080/ | grep -qi "WWW-Authenticate: Basic realm=\"staff\"" && echo "PASS challenge" || { echo "FAIL challenge"; fail=1; }
check exclude "$(code http://127.0.0.1:8080/public/x)" 200
openresty -p /sa -c /sa/nginx.conf -s stop
exit $fail
'
