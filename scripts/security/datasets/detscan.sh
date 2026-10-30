#!/bin/sh
# waf-gap4 离线检测器扫描（detscan.lua）在节点运行时镜像的 nginx 里跑。
#   用法：detscan.sh <数据目录> benign:<文件名>[,attack:<文件名>]  [检测器名,逗号分隔]
#   数据目录挂到 /data（只读）；文件名相对数据目录。
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
image="${WAF_DETECTOR_IMAGE:-cdnca-native-runtime:edge-golden}"
data=$1
files=$(printf '%s' "$2" | sed 's#:#:/data/#g')
names=${3:-crlf,redirect,format,nosql,ldap}
docker run --rm --network none -e DETSCAN_FILES="${files}" -e DETSCAN_NAMES="${names}" \
  -v "${repo_root}/scripts/security/datasets:/s:ro" -v "${repo_root}/edge/openresty/lua:/l:ro" -v "${data}:/data:ro" \
  --entrypoint sh "${image}" -c '
mkdir -p /tmp/c/logs
cat >/tmp/c/nginx.conf <<CONF
daemon off; master_process off; error_log /dev/stderr notice; pid /tmp/c/nginx.pid;
env DETSCAN_FILES; env DETSCAN_NAMES;
events {}
http {
  lua_package_path "/l/?.lua;;";
  init_worker_by_lua_block {
    print = function(...) io.stdout:write(table.concat({...}, " "), "\n") io.stdout:flush() end
    ngx.timer.at(0, function()
      local ok, err = pcall(dofile, "/s/detscan.lua")
      if not ok then io.stdout:write("ERROR ", tostring(err), "\n") end
      os.exit(ok and 0 or 1)
    end)
  }
}
CONF
timeout 1800 /usr/local/openresty/bin/openresty -p /tmp/c -c /tmp/c/nginx.conf 2>/tmp/c/err
code=$?
grep -E "\[(error|emerg|alert)\]" /tmp/c/err | head -20
exit $code'
