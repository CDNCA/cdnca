#!/bin/sh
# Runs the detector corpora (SQL注入 / XSS, then SSTI / Java / PHP 反序列化, then
# waf-gap4 crlf / redirect / format / nosql / ldap / upload, waf-gap5 proto / path) and
# their microbenchmarks inside nginx of the node runtime image (an init_worker
# timer: the image has no perl for the resty CLI). Exit 1 on any failure.
#   WAF_DETECTOR_IMAGE (default cdnca-native-runtime:edge-golden)
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
image="${WAF_DETECTOR_IMAGE:-cdnca-native-runtime:edge-golden}"
docker run --rm --network none -v "${repo_root}/scripts/security:/s:ro" -v "${repo_root}/edge/openresty/lua:/l:ro" \
  --entrypoint sh "${image}" -c '
mkdir -p /tmp/c/logs
cat >/tmp/c/nginx.conf <<CONF
daemon off; master_process off; error_log /dev/stderr notice; pid /tmp/c/nginx.pid;
events {}
http {
  lua_package_path "/l/?.lua;;";
  init_worker_by_lua_block {
    print = function(...) ngx.log(ngx.NOTICE, table.concat({...}, " ")) end
    local real_exit, status = os.exit, 0
    os.exit = function(code) if code ~= 0 then status = 1 end end
    ngx.timer.at(0, function()
      for _, file in ipairs({ "/s/waf-detector-corpus.lua", "/s/waf-detector-corpus-ext.lua", "/s/waf-detector-corpus-gap4.lua", "/s/waf-detector-corpus-gap5.lua" }) do
        local ok, err = pcall(dofile, file)
        if not ok then status = 1 ngx.log(ngx.ERR, file, ": ", err) end
      end
      real_exit(status)
    end)
  }
}
CONF
timeout 300 /usr/local/openresty/bin/openresty -p /tmp/c -c /tmp/c/nginx.conf >/tmp/c/out 2>&1
code=$?
grep -E "\[(error|emerg|alert)\]" /tmp/c/out
sed -n "s/^.*\[lua\][^)]*): *//p; s/^.*\[notice\].*\*[0-9]* \(.*\), context.*/\1/p" /tmp/c/out | sed "s/, context: .*//; s/^[0-9]*: print(): //"
exit $code'
