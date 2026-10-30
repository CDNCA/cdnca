#!/bin/sh
# fix-telemetry TF-E03: cdnca_telemetry's aggregate flush on the pinned
# OpenResty with resty (real shared dictionary, a scripted socket in place of
# the flush server's unix socket). 204 removes the key; a refused connect,
# a 500, a lost or cut response keep the frozen line, count and queue entry
# and the next run sends the same bytes; 400 (the server never takes the
# line) drops it.
# Usage: edge/openresty/dynroute/aggregate_flush_retry_test.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
container="cdnca-aggregate-flush-$$"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true' EXIT HUP INT TERM

docker run --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 32 \
  -v "${repo_root}/edge/openresty/dynroute:/lua:ro" "${OPENRESTY_IMAGE}" \
  resty --shdict "cdnca_agg 1m" -I /lua -e '
package.loaded["cdnca_site"] = { current = function() return nil end }
local t = require("cdnca_telemetry")
t.configure_aggregate({ dict = "cdnca_agg", socket = "/run/none.sock" })
local dict = ngx.shared.cdnca_agg
local failed = 0
local function eq(name, got, want)
  if got ~= want then failed = failed + 1; print("FAIL " .. name .. " got " .. tostring(got) .. " want " .. tostring(want))
  else print("ok   " .. name) end
end
local sent, mode = {}, nil
local real_tcp = ngx.socket.tcp
ngx.socket.tcp = function()
  local lines = {}
  return {
    settimeouts = function() end,
    connect = function() if mode == "refuse" then return nil, "connection refused" end return true end,
    send = function(_, parts) local line = parts[#parts]; sent[#sent + 1] = line
      if mode == "204" then lines = { "HTTP/1.1 204 No Content", "" }
      elseif mode == "500" then lines = { "HTTP/1.1 500 Internal Server Error", "" }
      elseif mode == "400" then lines = { "HTTP/1.1 400 Bad Request", "" }
      elseif mode == "cut" then lines = { "HTTP/1.1 204 No Content" }
      else lines = {} end
      return #line end,
    receive = function() return table.remove(lines, 1) end,
    close = function() end, setkeepalive = function() end,
  }
end
local function seed(key, count)
  dict:flush_all()
  local past = (math.floor(ngx.time() / 60) - 2) .. "|" .. key
  dict:set("n|" .. past, count, 600); dict:set("l|" .. past, "{\"schema_version\":1}\0\"cdnca\":{}", 600)
  dict:lpush("queue", past)
  return past
end
for _, case in ipairs({ { "refuse", true }, { "500", true }, { "none", true }, { "cut", true }, { "204", false }, { "400", false } }) do
  local key = seed(case[1], 5)
  sent, mode = {}, case[1]
  t._flush(false)
  eq(case[1] .. " keeps count", dict:get("n|" .. key) ~= nil, case[2])
  eq(case[1] .. " keeps queue", dict:llen("queue") == 1, case[2])
  if case[2] then
    local first = sent[1]
    mode = "204"; sent = {}
    t._flush(false)
    eq(case[1] .. " retried once with count 5", sent[1] ~= nil and sent[1]:find("\"count\":5", 1, true) ~= nil, true)
    if first then eq(case[1] .. " retry sends the same bytes", sent[1], first) end
    eq(case[1] .. " removed after 204", dict:get("n|" .. key), nil)
  end
end
ngx.socket.tcp = real_tcp
if failed > 0 then print(failed .. " failed"); os.exit(1) end
print("all passed")
'
