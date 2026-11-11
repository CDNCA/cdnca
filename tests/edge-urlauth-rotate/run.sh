#!/bin/sh
# 真实 OpenResty：URL 鉴权 preload + access_site 的轮换回退、产物未装 503、错签 403（t4）。
# 用法: tests/edge-urlauth-rotate/run.sh [镜像，默认 cdnca-native-runtime:edge-golden]
set -eu
R=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd); IMG=${1:-cdnca-native-runtime:edge-golden}
W=$(mktemp -d /tmp/ua.XXXXXX); chmod 0755 "$W"
T=11111111-1111-4111-8111-111111111111; S=33333333-3333-4333-8333-333333333333
P=55555555-5555-4555-8555-555555555555; KID=rot-key; SECRET=SENSITIVE_CREDENTIAL_0123456789abcdef
mkdir -p "$W/state/policies/$P/versions" "$W/state/keys" "$W/prefix/logs"
printf '%s' "$SECRET" > "$W/state/keys/$KID.key"; chmod 0644 "$W/state/keys/$KID.key"
KSHA=$(printf '%s' "$SECRET" | shasum -a 256 | awk '{print $1}')
# 只装 revision 1（修订 2 的产物"还在路上"）
printf '{"schema_version":"cdnca.edge.urlauth/v1","policy_version":1,"tenant_id":"%s","site_id":"%s","algorithm":"hmac-sha256","signature_parameter":"sig","expiration_parameter":"expires","key_id_parameter":"key","bind_client_ip":false,"max_clock_skew_seconds":5,"max_validity_seconds":600,"max_signature_uses":0,"excluded_query_parameters":[],"trusted_proxies":[{"family":4,"network":[127,0,0,0],"prefix_length":8}],"current_key":{"key_id":"%s","key_file":"/state/keys/%s.key","key_sha256":"%s"}}' \
  "$T" "$S" "$KID" "$KID" "$KSHA" > "$W/state/policies/$P/versions/$(printf '%020d' 1).json"
chmod -R a+rX "$W"; chmod -R a+rwX "$W/prefix"; chmod 0600 "$W/state/keys/$KID.key"
cat > "$W/nginx.conf" <<EOF
daemon off; master_process off; pid /prefix/nginx.pid; error_log stderr notice;
events { worker_connections 64; }
http {
  access_log off;
  lua_package_path "/ua/?.lua;;";
  lua_shared_dict cdnca_url_auth_state 16m;
  init_by_lua_block {
    local ua = require("url_auth")
    ua.preload({ state_dict = "cdnca_url_auth_state", root = "/state", policies = { { id = "$P", revision = 1 } } })
  }
  server {
    listen 18080;
    set \$cdnca_tenant_id "$T"; set \$cdnca_site_id "$S"; set \$cdnca_node_id ""; set \$cdnca_config_version_id "c";
    set \$cdnca_urlauth_emit 0; set \$cdnca_urlauth_trace_id ""; set \$cdnca_urlauth_action ""; set \$cdnca_urlauth_reason "";
    set \$cdnca_urlauth_status 0; set \$cdnca_urlauth_policy_version 0; set \$cdnca_urlauth_policy_event "";
    # 站点引用修订 R，回退楼层 F
    location /r1   { access_by_lua_block { return require("url_auth").access_site({ tenant_id="$T", site_id="$S", security={ url_auth={ id="$P", revision=1 } } }) } content_by_lua_block { ngx.exit(204) } }
    location /r2f1 { access_by_lua_block { return require("url_auth").access_site({ tenant_id="$T", site_id="$S", security={ url_auth={ id="$P", revision=2 }, url_auth_fallback_floor=1 } }) } content_by_lua_block { ngx.exit(204) } }
    location /r2f0 { access_by_lua_block { return require("url_auth").access_site({ tenant_id="$T", site_id="$S", security={ url_auth={ id="$P", revision=2 } } }) } content_by_lua_block { ngx.exit(204) } }
    location /r100f1 { access_by_lua_block { return require("url_auth").access_site({ tenant_id="$T", site_id="$S", security={ url_auth={ id="$P", revision=100 }, url_auth_fallback_floor=1 } }) } content_by_lua_block { ngx.exit(204) } }
    location /r3f2 { access_by_lua_block { return require("url_auth").access_site({ tenant_id="$T", site_id="$S", security={ url_auth={ id="$P", revision=3 }, url_auth_fallback_floor=2 } }) } content_by_lua_block { ngx.exit(204) } }
  }
}
EOF
NAME=ua-$$
docker run -d --rm --name "$NAME" --network none --user 0 -v "$W/state:/state:ro" -v "$W/prefix:/prefix" -v "$W/nginx.conf:/nginx.conf:ro" \
  -v "$R/edge/openresty/urlauth/engine.lua:/ua/url_auth.lua:ro" --entrypoint /usr/local/openresty/nginx/sbin/nginx "$IMG" -p /prefix -c /nginx.conf >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$W"' EXIT
sleep 3
# 容器没有网络；用容器内 resty 的 curl 不可得，改用容器内 lua socket 之外的方式：busybox wget
EXP=$(( $(date +%s) + 300 ))
sign() { # location -> 签名（path 为 <location>/dl）
  pth=$(printf '%s/dl' "$1" | sed 's#/#%2F#g')
  can="CDNCA-URL-AUTH/1
tenant_id=$T
site_id=$S
method=GET
path=$pth
query=
expires=$EXP
key_id=$KID
client_ip=
"
  printf '%s' "$can" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}'
}
fail=0
check() { # 名称 location 期望状态 签名
  code=$(docker exec "$NAME" sh -c "wget -S -O /dev/null -q 'http://127.0.0.1:18080$2/dl?sig=$4&expires=$EXP&key=$KID' 2>&1 | grep -o 'HTTP/[0-9.]* [0-9]*' | tail -1 | cut -d' ' -f2")
  [ -n "$code" ] || code=none
  if [ "$code" = "$3" ]; then echo "PASS $1 -> $code"; else echo "FAIL $1 -> $code (期望 $3)"; fail=$((fail+1)); fi
}
BAD=0000000000000000000000000000000000000000000000000000000000000000
check "r1 正确签名放行" /r1 204 "$(sign /r1)"
check "r1 错误签名拒绝"            /r1   403 "$BAD"
check "r2 楼层1 轮换回退放行" /r2f1 204 "$(sign /r2f1)"
check "r2 楼层1 回退后错签拒绝"    /r2f1 403 "$BAD"
check "r2 楼层0 无回退 产物未装503" /r2f0 503 "$(sign /r2f0)"
check "r100 楼层1 超出64步回退范围503" /r100f1 503 "$(sign /r100f1)"
check "r3 楼层2 低于楼层不回退503" /r3f2 503 "$(sign /r3f2)"
docker logs "$NAME" 2>&1 | grep -iE "url auth|emerg|error" | cut -c1-260 | head -5
echo "RESULT failures=$fail"
[ "$fail" = 0 ]
