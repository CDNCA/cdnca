#!/bin/sh
# 两个提交的 cdnca_waf.lua 检测器逐值差分与耗时（节点运行时镜像里的 LuaJIT，--network none）
#   用法：detdiff.sh <改前提交> <改后提交|WORKTREE> <数据目录> <文件,逗号分隔> [检测器,逗号分隔]
#   输出 DIFF 行（判定不同的值）与 RESULT checks= diffs= base_ms= new_ms=
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../../../.." && pwd)
image="${WAF_DETECTOR_IMAGE:-cdnca-native-runtime:edge-golden}"
work=$(mktemp -d /tmp/cdnca-detdiff.XXXXXX)
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/base" "${work}/new"
git -C "${repo_root}" show "$1:edge/openresty/lua/cdnca_waf.lua" > "${work}/base/cdnca_waf.lua"
if [ "$2" = WORKTREE ]; then cp "${repo_root}/edge/openresty/lua/cdnca_waf.lua" "${work}/new/"; else git -C "${repo_root}" show "$2:edge/openresty/lua/cdnca_waf.lua" > "${work}/new/cdnca_waf.lua"; fi
chmod -R a+rX "${work}"
docker run --rm --network none -e DETDIFF_FILES="$4" -e DETDIFF_NAMES="${5:-cmd}" \
  -v "${here}:/s:ro" -v "${repo_root}/edge/openresty/lua:/l:ro" -v "${work}/base:/base:ro" -v "${work}/new:/new:ro" -v "$3:/data:ro" \
  --entrypoint /usr/local/openresty/luajit/bin/luajit "${image}" /s/detdiff.lua
