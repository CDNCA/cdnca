-- ADR 0017 PoC option ②b: in-process restricted Lua sandbox (not product
-- code). setfenv with a whitelist environment (no io/os/ffi/require/debug/
-- load*), JIT off for the untrusted chunk and an instruction-count hook.
-- The PoC measures what this can and cannot bound inside an nginx worker.
local M = {}

local SAFE = {
  string = { find = string.find, sub = string.sub, len = string.len, lower = string.lower,
             upper = string.upper, rep = string.rep, match = string.match, gsub = string.gsub,
             byte = string.byte, char = string.char },
  table = { concat = table.concat, insert = table.insert },
  math = { floor = math.floor, max = math.max, min = math.min },
  pairs = pairs, ipairs = ipairs, tostring = tostring, tonumber = tonumber, type = type,
  pcall = pcall, error = error,
}

local LIMIT = 1000000 -- VM instructions per call

function M.run(source, request)
  local chunk, err = loadstring(source, "=plugin")
  if not chunk then
    return nil, "compile: " .. err
  end
  local env = setmetatable({}, { __index = SAFE })
  setfenv(chunk, env)
  local ok, handler = pcall(chunk)
  if not ok or type(handler) ~= "function" then
    return nil, "init: " .. tostring(handler)
  end
  jit.off(handler, true)
  local co = coroutine.create(handler)
  local steps = 0
  debug.sethook(co, function()
    steps = steps + 1000
    if steps > LIMIT then
      error("instruction budget exceeded", 2)
    end
  end, "", 1000)
  local started = ngx.now()
  ngx.update_time()
  started = ngx.now()
  local okc, result = coroutine.resume(co, request)
  ngx.update_time()
  local elapsed_ms = (ngx.now() - started) * 1000
  return okc and result or ("error " .. tostring(result)), nil, elapsed_ms
end

return M
