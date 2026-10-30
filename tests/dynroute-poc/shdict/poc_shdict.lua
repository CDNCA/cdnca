-- ADR 0009 §8.5 item 1: lua_shared_dict as the site index.
-- Endpoints (see nginx.conf): /fill /stats /bench /dump /rebuild /status /lookup /evict
local ffi = require "ffi"
local cjson = require "cjson.safe"
local lock = require "resty.lock"
local C = ffi.C
pcall(ffi.cdef, [[
typedef struct { long tv_sec; long tv_nsec; } dynpoc_timespec;
int clock_gettime(int clk_id, dynpoc_timespec *tp);
]])
local ts = ffi.new("dynpoc_timespec")
local function now_us()
  C.clock_gettime(1, ts) -- CLOCK_MONOTONIC
  return tonumber(ts.tv_sec) * 1e6 + tonumber(ts.tv_nsec) / 1e3
end

local _M = {}
local index = ngx.shared.cdnca_site_index

-- Deterministic synthetic data: domain i on port 443, two 32-byte digests.
local function domain(i) return string.format("site%07d-shop.example-cdn.com", i) end
local function digest32(seed)
  return ngx.sha1_bin(seed) .. ngx.md5_bin(seed):sub(1, 12)
end
local function tohex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

-- Encodings measured (key, value); all hold the current and the previous
-- generation's site object digest except "single".
--   json    "<port>\0<host>" -> {"gen_a":"<hex64>","gen_b":"<hex64>"}   (ADR §8.2 as written)
--   binary  "<port>\0<host>" -> 32-byte digest a .. 32-byte digest b
--   md5     md5("<port>\0<host>") (16 bytes) -> 64-byte binary value
--   single  md5 key (16 bytes) -> 32-byte digest of the current generation only
--   compact md5 key (16 bytes) -> 16-byte truncated digest a .. 16-byte b
local encoders = {
  json = function(i)
    local a, b = digest32("a" .. i), digest32("b" .. i)
    return "443\0" .. domain(i), cjson.encode({ gen_a = tohex(a), gen_b = tohex(b) })
  end,
  binary = function(i)
    return "443\0" .. domain(i), digest32("a" .. i) .. digest32("b" .. i)
  end,
  md5 = function(i)
    return ngx.md5_bin("443\0" .. domain(i)), digest32("a" .. i) .. digest32("b" .. i)
  end,
  -- single: md5 key + only the current generation's full 32-byte digest
  -- (rollback re-reads the previous generation's index file instead)
  single = function(i)
    return ngx.md5_bin("443\0" .. domain(i)), digest32("a" .. i)
  end,
  compact = function(i)
    return ngx.md5_bin("443\0" .. domain(i)), digest32("a" .. i):sub(1, 16) .. digest32("b" .. i):sub(1, 16)
  end,
}

local function zone_smaps()
  -- The zone is a MAP_SHARED anonymous mapping ("/dev/zero (deleted)") of the
  -- configured size; report its resident size in this worker.
  local f = io.open("/proc/self/smaps")
  if not f then return nil end
  local want = math.floor(index:capacity() / 1024)
  local result, current = {}, nil
  for line in f:lines() do
    if line:find("^%x+%-%x+ ") then
      current = line:find("/dev/zero", 1, true) and {} or nil
    elseif current then
      local k, v = line:match("^(%w+):%s+(%d+) kB")
      if k then current[k] = tonumber(v) end
      if k == "Size" and current.Size and math.abs(current.Size - want) < 64 then
        result = current
      end
    end
  end
  f:close()
  return result
end

local function stats()
  local cap, free = index:capacity(), index:free_space()
  local smaps = zone_smaps() or {}
  return { capacity = cap, free_space = free, used = cap - free,
           keys = #index:get_keys(0), zone_rss_kb = smaps.Rss, zone_pss_kb = smaps.Pss }
end

function _M.fill()
  local args = ngx.req.get_uri_args()
  local n, enc = tonumber(args.n), args.enc
  local encode = encoders[enc]
  if not n or not encode then return ngx.exit(400) end
  local before = stats()
  -- Pre-generate so the timing is the shared dict cost, not sha1/json.
  local keys, values = {}, {}
  for i = 1, n do keys[i], values[i] = encode(i) end
  ngx.update_time()
  local t0 = now_us()
  for i = 1, n do
    local ok, err = index:safe_set(keys[i], values[i])
    if not ok then
      ngx.say(cjson.encode({ error = err, at = i }))
      return
    end
  end
  local elapsed = now_us() - t0
  local after = stats()
  ngx.say(cjson.encode({ enc = enc, n = n, key_len = #keys[1], value_len = #values[1],
    set_total_ms = elapsed / 1000, set_us_per_key = elapsed / n,
    used_before = before.used, used_after = after.used,
    bytes_per_key = (after.used - before.used) / n,
    rss_kb_before = before.zone_rss_kb, rss_kb_after = after.zone_rss_kb,
    rss_bytes_per_key = after.zone_rss_kb and before.zone_rss_kb and
      (after.zone_rss_kb - before.zone_rss_kb) * 1024 / n or cjson.null,
    capacity = after.capacity, keys = after.keys }))
end

function _M.stats() ngx.say(cjson.encode(stats())) end

-- Lookup cost as a request would pay it: exact key + the wildcard probes of a
-- miss (3 extra gets for a 4-label host), plus value decoding.
function _M.bench()
  local args = ngx.req.get_uri_args()
  local n, enc, iterations = tonumber(args.n), args.enc, tonumber(args.iter) or 200000
  local encode = encoders[enc]
  local keys = {}
  for i = 1, 1000 do keys[i] = (encode(math.random(n))) end
  ngx.update_time()
  local t0 = now_us()
  local found = 0
  for i = 1, iterations do
    local v = index:get(keys[(i % 1000) + 1])
    if v then
      found = found + 1
      if enc == "json" then
        local d = cjson.decode(v); v = d and d.gen_a
      else
        v = v:sub(1, enc == "compact" and 16 or 32)
      end
    end
  end
  local hit_us = (now_us() - t0) / iterations
  t0 = now_us()
  for i = 1, iterations do
    -- miss path: exact + three wildcard probes, all absent
    local base = keys[(i % 1000) + 1]
    for p = 1, 4 do local _ = index:get(base .. "#" .. p) end
  end
  local miss_us = (now_us() - t0) / iterations
  ngx.say(cjson.encode({ enc = enc, n = n, iterations = iterations, found = found,
    hit_us = hit_us, miss4_us = miss_us }))
end

-- Writes the "whole-generation index file" the agent would keep on disk:
-- records of u16 key length, u16 value length, key, value.
function _M.dump()
  local args = ngx.req.get_uri_args()
  local n, enc, path = tonumber(args.n), args.enc, args.path
  local encode = encoders[enc]
  local f = assert(io.open(path, "wb"))
  local parts, count = {}, 0
  for i = 1, n do
    local k, v = encode(i)
    count = count + 1
    parts[count] = string.char(math.floor(#k / 256), #k % 256, math.floor(#v / 256), #v % 256) .. k .. v
    if count == 4096 then f:write(table.concat(parts)); parts, count = {}, 0 end
  end
  f:write(table.concat(parts, "", 1, count))
  f:close()
  ngx.say(cjson.encode({ path = path, n = n }))
end

local function rebuild(premature, path, slice, yield)
  if premature then return end
  local status = ngx.shared.cdnca_site_generation
  local l = lock:new("cdnca_index_lock", { timeout = 0, exptime = 600 })
  if not l:lock("rebuild") then status:set("rebuild", "locked"); return end
  status:set("rebuild", "running")
  index:flush_all()
  index:flush_expired(0)
  ngx.update_time()
  local t0, slice_t0 = now_us(), now_us()
  local max_slice_us, slices, records = 0, 0, 0
  local f = assert(io.open(path, "rb"))
  local buf, pos = "", 1
  while true do
    -- records here are < 200 bytes: refill when less than 1 KiB is left
    if #buf - pos + 1 < 1024 then
      local chunk = f:read(1048576)
      if chunk then buf = buf:sub(pos) .. chunk; pos = 1 end
    end
    if #buf - pos + 1 < 4 then break end
    local b1, b2, b3, b4 = buf:byte(pos, pos + 3)
    local kl, vl = b1 * 256 + b2, b3 * 256 + b4
    local k = buf:sub(pos + 4, pos + 3 + kl)
    local v = buf:sub(pos + 4 + kl, pos + 3 + kl + vl)
    pos = pos + 4 + kl + vl
    local ok, err = index:safe_set(k, v)
    if not ok then status:set("rebuild", "failed: " .. err); f:close(); l:unlock(); return end
    records = records + 1
    if yield and records % slice == 0 then
      local spent = now_us() - slice_t0
      if spent > max_slice_us then max_slice_us = spent end
      slices = slices + 1
      ngx.sleep(0)
      slice_t0 = now_us()
    end
  end
  f:close()
  local total = now_us() - t0
  status:set("rebuild", cjson.encode({ state = "done", records = records, total_ms = total / 1000,
    us_per_record = total / records, slices = slices, slice = slice, yield = yield,
    max_slice_ms = max_slice_us / 1000 }))
  l:unlock()
end

function _M.rebuild()
  local args = ngx.req.get_uri_args()
  ngx.shared.cdnca_site_generation:set("rebuild", "scheduled")
  local ok, err = ngx.timer.at(0, rebuild, args.path, tonumber(args.slice) or 1000, args.yield ~= "0")
  ngx.say(cjson.encode({ scheduled = ok, err = err }))
end

function _M.status() ngx.say(ngx.shared.cdnca_site_generation:get("rebuild") or "none") end

-- A request-path lookup used as the latency probe during a rebuild.
function _M.lookup()
  local k = encoders.compact(math.random(1000))
  local _ = index:get(k)
  ngx.say("ok")
end

-- Eviction semantics on a small dict: safe_set fails, set silently evicts.
function _M.evict()
  local small = ngx.shared.cdnca_small
  small:flush_all(); small:flush_expired(0)
  local i, err = 0, nil
  repeat
    i = i + 1
    local ok
    ok, err = small:safe_set("k" .. i, string.rep("v", 64))
  until not ok
  local stored = i - 1
  local _, _, forcible = small:set("extra-1", string.rep("v", 64))
  local first_survives = small:get("k1") ~= nil
  ngx.say(cjson.encode({ safe_set_stored = stored, safe_set_err = err,
    set_forcible = forcible, first_key_survives_after_set = first_survives }))
end

return _M
