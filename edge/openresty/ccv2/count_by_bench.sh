#!/bin/sh
# Cost of a count_by key (engine.lua count_key): per-request CPU of building
# the key (network mask + SHA-256 over the joined values) against the plain
# client-IP key, and shared-dict bytes per fixed-window counter, measured in
# the pinned OpenResty with resty. Prints one JSON line.
#
# Usage: edge/openresty/ccv2/count_by_bench.sh [iterations]
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
iterations="${1:-200000}"
container="cdnca-g1-ccdim-bench-$$"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true' EXIT HUP INT TERM

docker run --rm --name "${container}" --network none --cpus 1 --memory 256m --pids-limit 32 \
  -e ITERATIONS="${iterations}" "${OPENRESTY_IMAGE}" \
  resty --shdict 'cdnca_cc_v2_state 32m' -e '
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")
local bit = require("bit")
local n = tonumber(os.getenv("ITERATIONS"))
local function sha256(value)
  local digest = resty_sha256:new()
  digest:update(value)
  return resty_string.to_hex(digest:final())
end
local function masked(bytes, prefix)
  local parts = {}
  for index, byte in ipairs(bytes) do
    local keep = prefix - (index - 1) * 8
    if keep >= 8 then parts[index] = byte
    elseif keep <= 0 then parts[index] = 0
    else parts[index] = bit.band(byte, bit.band(0xff, bit.lshift(0xff, 8 - keep))) end
  end
  return "4:" .. table.concat(parts, ".") .. "/" .. prefix
end
local base = "018f1000-0000-7000-8000-000000000030:1:018f1000-0000-7000-8000-000000000021"
local uri = "/api/v1/items?page=12&sort=desc"
local function plain(i) return base .. ":198.51.100." .. (i % 256) end
local function counted(i)
  local values = { "client_cidr=" .. masked({ 198, 51, 100, i % 256 }, 24), "uri=" .. uri }
  return base .. ":k:" .. sha256(table.concat(values, "\0")):sub(1, 32)
end
local sink = 0
local function time(fn)
  ngx.update_time()
  local started = ngx.now()
  for i = 1, n do sink = sink + #fn(i) end
  ngx.update_time()
  return (ngx.now() - started) * 1e9 / n
end
time(counted)
local plain_ns, counted_ns = time(plain), time(counted)
local dict = ngx.shared.cdnca_cc_v2_state
dict:flush_all(); dict:flush_expired()
local before = dict:free_space()
local keys = 20000
for i = 1, keys do
  local key = "fixed:" .. base .. ":k:" .. sha256(tostring(i)):sub(1, 32) .. ":" .. 1234567
  dict:incr(key, 1, 0, 61)
end
local used = before - dict:free_space()
print(string.format("{\"iterations\":%d,\"plain_key_ns\":%.0f,\"count_by_key_ns\":%.0f,\"extra_ns_per_rule\":%.0f,\"dict_bytes_per_counter\":%.0f,\"counters_per_32m\":%d}",
  n, plain_ns, counted_ns, counted_ns - plain_ns, used / keys, math.floor(32 * 1024 * 1024 / (used / keys))))
'
