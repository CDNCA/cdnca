-- ADR 0017 PoC: access phase call into cdnca-plugin-host (not product code).
-- Keepalive unix-socket cosocket; any failure (no host, timeout, host
-- error) falls back to the site's policy (here: fail open, header marks it).
local M = {}

local SOCKET = "unix:/run/cdnca/plugin.sock"
local TIMEOUT_MS = 30 -- connect/send/read; above the host's per-call deadline

local function frame(payload)
  local n = #payload
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256) .. payload
end

local function call(payload)
  local sock = ngx.socket.tcp()
  sock:settimeouts(TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS)
  local ok, err = sock:connect(SOCKET)
  if not ok then
    return nil, "connect: " .. tostring(err)
  end
  ok, err = sock:send(frame(payload))
  if not ok then
    sock:close()
    return nil, "send: " .. tostring(err)
  end
  local header, rerr = sock:receive(4)
  if not header then
    sock:close()
    return nil, "receive: " .. tostring(rerr)
  end
  local b1, b2, b3, b4 = header:byte(1, 4)
  local body = ""
  local size = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
  if size > 0 then
    body, rerr = sock:receive(size)
    if not body then
      sock:close()
      return nil, "receive: " .. tostring(rerr)
    end
  end
  sock:setkeepalive(60000, 64)
  return body
end
M.call = call

function M.access()
  local parts = { ngx.req.get_method() .. " " .. ngx.var.request_uri }
  local headers = ngx.req.get_headers(32)
  for name, value in pairs(headers) do
    if type(value) == "table" then value = value[1] end
    parts[#parts + 1] = name .. ": " .. value
  end
  local decision, err = call(table.concat(parts, "\n"))
  if not decision then
    ngx.header["x-plugin"] = "unavailable"
    ngx.log(ngx.WARN, "plugin host: ", err)
    return
  end
  if decision:sub(1, 6) == "error " or decision == "none" then
    ngx.header["x-plugin"] = decision
    return
  end
  local status = decision:match("^deny (%d%d%d)$")
  if status then
    return ngx.exit(tonumber(status))
  end
  local name, value = decision:match("^header ([%w-]+) (.+)$")
  if name then
    ngx.header[name] = value
    ngx.header["x-plugin"] = "ok"
  end
end

return M
