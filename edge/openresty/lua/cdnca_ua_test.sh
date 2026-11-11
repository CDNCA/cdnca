#!/bin/sh
# cdnca_ua.parse must give what Go
# edgeconfig.ParseUserAgent gives for every case of
# libs/edgeconfig/testdata/user_agents.json (TestParseUserAgentTable checks
# the Go side against the same file). LuaJIT of the pinned OpenResty
# (edge/openresty/runtime.env), one --rm --network none container.
# Usage: edge/openresty/lua/cdnca_ua_test.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
. "${repo_root}/edge/openresty/runtime.env"
image="${CDNCA_UA_TEST_IMAGE:-${OPENRESTY_IMAGE}}"
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }

docker run --rm --network none \
  -v "${repo_root}/edge/openresty/lua:/lua:ro" \
  -v "${repo_root}/libs/edgeconfig/testdata:/data:ro" \
  --entrypoint /usr/local/openresty/luajit/bin/luajit "${image}" -e '
package.path = "/lua/?.lua;/usr/local/openresty/lualib/?.lua;" .. package.path
package.cpath = "/usr/local/openresty/lualib/?.so;" .. package.cpath
local cjson = require "cjson.safe"
local ua = require "cdnca_ua"
local table_ = assert(cjson.decode(assert(io.open("/data/user_agents.json")):read("*a")))
local scale, failed = ua.VERSION_SCALE, 0
for _, case in ipairs(table_.cases) do
  local browser, version, device = ua.parse(case.ua)
  local want
  if type(case.version) == "table" then
    want = (case.version[1] * scale + case.version[2]) * scale + case.version[3]
  end
  if browser ~= case.browser or device ~= case.device or version ~= want then
    failed = failed + 1
    print(string.format("FAIL %s: got %s %s %s, want %s %s %s", case.note, browser, tostring(version), device,
      case.browser, tostring(want), case.device))
  end
end
print(string.format("%d cases, %d failed", #table_.cases, failed))
os.exit(failed == 0 and 0 or 1)
'
