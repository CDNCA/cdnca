#!/usr/bin/env bash
# Go/Lua parity of the content rewrite engine: the Go cases
# (libs/edgeconfig/contentrewrite TestWriteLuaVectors) run through
# cdnca_rewrite.lua in OpenResty at chunk sizes 1, 2, 3, 7, 64, 4096 and
# whole; every output must equal Go's byte for byte.
# usage: scripts/edge/content-rewrite-parity.sh [openresty image]
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
image=${1:-openresty/openresty:1.27.1.2-alpine-fat}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
CONTENTREWRITE_VECTORS="$work/vectors.json" go -C "$repo_root/libs/edgeconfig" test -count=1 -run TestWriteLuaVectors ./contentrewrite >/dev/null
cat > "$work/parity.lua" <<'LUA'
local cjson = require "cjson.safe"
local rewrite = require "cdnca_rewrite"
local file = assert(io.open("/work/vectors.json"))
local vectors = assert(cjson.decode(file:read("*a")))
file:close()
local failed = 0
for _, v in ipairs(vectors) do
    for _, size in ipairs({ 0, 1, 2, 3, 7, 64, 4096 }) do
        local state = rewrite.new_stream(v.node, v.path, v.type)
        local got
        if not state then
            got = v.body
        elseif size == 0 then
            got = rewrite.stream_write(state, v.body, true)
        else
            local out = {}
            for start = 1, #v.body, size do
                out[#out + 1] = rewrite.stream_write(state, v.body:sub(start, start + size - 1), false)
            end
            out[#out + 1] = rewrite.stream_write(state, "", true)
            got = table.concat(out)
        end
        if (state ~= nil) ~= v.matched or got ~= v.want then
            failed = failed + 1
            print(("FAIL %s chunk %d (%d vs %d bytes)"):format(v.name, size, #got, #v.want))
        end
    end
end
print(failed == 0 and ("ok " .. #vectors .. " vectors") or ("FAIL " .. failed))
os.exit(failed == 0 and 0 or 1)
LUA
docker run --rm --network none -v "$repo_root/edge/openresty/dynroute":/lua:ro -v "$work":/work:ro \
    "$image" resty -I /lua /work/parity.lua
