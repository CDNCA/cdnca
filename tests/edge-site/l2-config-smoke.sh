#!/bin/sh
# A19-a L2 配置在真实节点运行时（OpenResty 1.31.1.1）上的选择：L2 池按成员
# 权重轮询、按成员排序、URL哈希同一 URL 固定一个 L2 节点（lua/l2_config.lua）。
# A19-b（L2_ROUTING 能力 59）：模式=缓存只有缓存规则命中的 URL 走 L2、其余直连；
# L2 条件按 host/uri/request_uri/protocol 匹配（规则为且，正则 RE2 同 L2-REGEX-01），
# node_ids 只在列出的 L1 生效，多个条件命中取成员并集，无默认候选时直连。
# L2_ROUTING v2：本节点是该站点 L2 池端点时直连源站；带 X-Cdnca-L2-Hop
# 标记的请求只直连（防环）；passthrough 时 L1 按访客进来的协议与端口连 L2（HTTPS 带访客
# SNI、校验 L2 出示本站该端口证书）。
# 带跳标记且对端在平台节点网段的请求是 L1 跳——跳过 CC/规则/托管 WAF/限速/自动防御计数、
# 用 L1 传来的访客 IP（XFF 访客在首位）、访问日志标 l2:true（agent 跳过不计费）；非受信对端带该头被剥掉按普通访客走 CC。
# 待出包前全量跑（子任务不跑真实 OpenResty / docker run）。
#   CDNCA_D5A_IMAGE  节点运行时镜像（默认 cdnca-native-runtime:edge-golden）
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D5A_IMAGE:-cdnca-native-runtime:edge-golden}
work=$(mktemp -d /tmp/cdnca-l2cfg.XXXXXX)
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/logs"
cat >"${work}/nginx.conf" <<'CONF'
daemon off; master_process off; error_log stderr warn; pid /tmp/l2cfg.pid;
events {}
http {
  lua_package_path "/t/dynroute/?.lua;;";
  init_worker_by_lua_block {
    ngx.timer.at(0, function()
      local ok, err = pcall(dofile, "/x/l2_config.lua")
      if not ok then ngx.log(ngx.WARN, "RESULT failures=error ", err) end
      os.exit(0)
    end)
  }
  server { listen 127.0.0.1:1; }
}
CONF
cp "${here}/lua/l2_config.lua" "${work}/"
chmod -R a+rX "${work}"
docker run --rm --network none -v "${repo_root}/edge/openresty:/t:ro" -v "${work}:/x" \
	--entrypoint /usr/local/openresty/bin/openresty "${image}" -p /x/ -c nginx.conf 2>&1 |
	grep -Eo "(PASS|FAIL|RESULT) .*" | sed "s/, context: .*//" | tee "${work}/out"
grep -q '^RESULT failures=0$' "${work}/out"
