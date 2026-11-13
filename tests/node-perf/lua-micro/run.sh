#!/bin/sh
# 节点 Lua 微基准：在节点运行时镜像里起真 nginx，content_by_lua 里跑指定脚本，
# 脚本用 print 输出（进 error log），本脚本只回显 [bench] 行。
#   tests/node-perf/lua-micro/run.sh <脚本.lua> [迭代次数]
# LUA_ROOT 默认本工作树 edge/openresty；IMAGE 默认 cdnca-native-runtime:edge-golden（arm64）。
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH='' cd -- "${here}/../../.." && pwd)
script=$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd)/$(basename "$1")
iters=${2:-1000000}
image=${IMAGE:-cdnca-native-runtime:edge-golden}
root=${LUA_ROOT:-${repo}/edge/openresty}
work=$(mktemp -d /tmp/np-micro.XXXXXX); trap 'rm -rf "${work}"' EXIT
cat > "${work}/nginx.conf" <<CONF
daemon off; worker_processes 1; error_log /tmp/err.log notice; pid /tmp/np.pid;
env NP_ITERS;
events { worker_connections 64; }
http {
  lua_package_path "/lua/dynroute/?.lua;/lua/lua/?.lua;/lua/?.lua;;";
  uninitialized_variable_warn off;
  access_log off;
  server {
    listen 127.0.0.1:8080;
    set \$cdnca_security_emit "0"; set \$cdnca_security_type ""; set \$cdnca_security_action ""; set \$cdnca_security_severity ""; set \$cdnca_security_rule_id ""; set \$cdnca_security_block_page "0"; set \$cdnca_security_path "";
    ${NP_SERVER_EXTRA:-}
    location / { content_by_lua_block { dofile("/mb/$(basename "${script}")"); ngx.say("done") } }
  }
}
CONF
chmod -R a+rX "${work}"
docker run --rm --network none --cpus 1 ${NP_DOCKER_ARGS:-} -e NP_ITERS="${iters}" \
  -v "${root}:/lua:ro" ${EXTRA_MOUNT:+-v "${EXTRA_MOUNT}"} -v "$(dirname "${script}"):/mb:ro" -v "${work}:/w:ro" \
  --entrypoint sh "${image}" -c '
    /usr/local/openresty/bin/openresty -p /tmp -c /w/nginx.conf >/tmp/ng.out 2>&1 &
    i=0; until wget -qO- http://127.0.0.1:8080/ >/dev/null 2>&1 || [ $i -ge 600 ]; do sleep 0.2; i=$((i+1)); done
    grep -E "\[bench\]|\[error\]|\[emerg\]" /tmp/err.log /tmp/ng.out | sed -E "s/^[^:]*:[0-9 \/:]+ \[[a-z]+\] [0-9#: ]*//; s/, client:.*//"
  '
