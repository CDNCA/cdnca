local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

local MAX_RAW_QUERY_BYTES = 8192
local MAX_QUERY_PAIRS = 256
local MAX_HEADER_VALUE_BYTES = 4096
local MAX_HEADER_TOTAL_BYTES = 16384

local M = {}

local function add_frame(frames, tag, value)
  frames[#frames + 1] = tag .. ":" .. #value .. ":" .. value .. ";"
end

local function digest_frames(frames)
  local digest = resty_sha256:new()
  for _, frame in ipairs(frames) do
    digest:update(frame)
  end
  return resty_string.to_hex(digest:final())
end

local function valid_percent(value)
  local index = 1
  while index <= #value do
    if string.byte(value, index) == 37 then
      if index + 2 > #value or not string.match(string.sub(value, index + 1, index + 2), "^[0-9A-Fa-f][0-9A-Fa-f]$") then
        return false
      end
      index = index + 3
    else
      index = index + 1
    end
  end
  return true
end

local function decode_name(value)
  local output = {}
  local index = 1
  while index <= #value do
    if string.byte(value, index) == 37 then
      output[#output + 1] = string.char(tonumber(string.sub(value, index + 1, index + 2), 16))
      index = index + 3
    else
      output[#output + 1] = string.sub(value, index, index)
      index = index + 1
    end
  end
  return table.concat(output)
end

local function query_presence()
  local request_uri = ngx.var.request_uri or ""
  local marker = string.find(request_uri, "?", 1, true)
  if not marker then
    return false, ""
  end
  return true, string.sub(request_uri, marker + 1)
end

local function query_digest(mode, names)
  local present, raw = query_presence()
  if #raw > MAX_RAW_QUERY_BYTES or not valid_percent(raw) then
    return nil
  end
  local frames = {}
  add_frame(frames, "schema", "cdnca-cache-query-v1")
  add_frame(frames, "mode", mode)
  if mode == "ignore" then
    add_frame(frames, "state", "ignored")
    return digest_frames(frames)
  end
  if mode == "preserve" then
    add_frame(frames, "state", present and (#raw == 0 and "empty" or "present") or "absent")
    if present and #raw > 0 then
      add_frame(frames, "raw", raw)
    end
    return digest_frames(frames)
  end

  add_frame(frames, "state", present and (#raw == 0 and "empty" or "present") or "absent")
  if not present or #raw == 0 then
    return digest_frames(frames)
  end
  local selected = {}
  for _, name in ipairs(names) do
    selected[name] = true
  end
  local start = 1
  local pairs = 0
  while start <= #raw + 1 do
    pairs = pairs + 1
    if pairs > MAX_QUERY_PAIRS then
      return nil
    end
    local boundary = string.find(raw, "&", start, true)
    local pair
    if boundary then
      pair = string.sub(raw, start, boundary - 1)
      start = boundary + 1
    else
      pair = string.sub(raw, start)
      start = #raw + 2
    end
    local equals = string.find(pair, "=", 1, true)
    local raw_name = equals and string.sub(pair, 1, equals - 1) or pair
    local name = decode_name(raw_name)
    local keep = selected[name] == true
    if mode == "exclude" then
      keep = not keep
    end
    if keep then
      add_frame(frames, "pair", pair)
    end
  end
  return digest_frames(frames)
end

local function header_digest(names)
  local frames = {}
  add_frame(frames, "schema", "cdnca-cache-vary-v1")
  if #names == 0 then
    return digest_frames(frames)
  end
  local raw, header_error = ngx.req.get_headers(100, true)
  if header_error == "truncated" then
    return nil
  end
  local indexed = {}
  local repeated = {}
  for name, value in pairs(raw) do
    local normalized = string.lower(name)
    if indexed[normalized] ~= nil or type(value) == "table" then
      repeated[normalized] = true
    end
    indexed[normalized] = value
  end
  local total = 0
  for _, name in ipairs(names) do
    if repeated[name] then
      return nil
    end
    local value = indexed[name]
    add_frame(frames, "name", name)
    if value == nil then
      add_frame(frames, "state", "absent")
    elseif type(value) ~= "string" or #value > MAX_HEADER_VALUE_BYTES or total > MAX_HEADER_TOTAL_BYTES - #value then
      return nil
    else
      total = total + #value
      add_frame(frames, "state", #value == 0 and "empty" or "value")
      add_frame(frames, "value", value)
    end
  end
  return digest_frames(frames)
end

local function request_extension(uri)
  local name = string.match(uri, "([^/]*)$") or ""
  local extension = string.match(name, "(%.[^.]*)$")
  return extension and string.lower(extension) or ""
end

local function matching_candidates(rules, uri)
  local extension = request_extension(uri)
  local matches = {}
  for index, rule in ipairs(rules) do
    local path_match = rule.path_prefix == "" or string.sub(uri, 1, #rule.path_prefix) == rule.path_prefix
    local extension_match = #rule.extensions == 0
    if not extension_match then
      for _, candidate in ipairs(rule.extensions) do
        if candidate == extension then
          extension_match = true
          break
        end
      end
    end
    if path_match and extension_match then
      matches[#matches + 1] = tostring(index)
    end
  end
  return table.concat(matches, ",")
end

local function select_route(options)
  local uri = ngx.var.uri or ""
  if string.sub(uri, 1, 1) ~= "/" then
    return nil
  end
  local signature = matching_candidates(options.rules, uri)
  local route = options.routes[signature]
  if not route then
    return nil
  end
  if options.legacy then
    ngx.var.cdnca_cache_policy_key = options.key_prefix .. uri .. (ngx.var.is_args or "") .. (ngx.var.args or "")
  else
    local query = query_digest(options.query_mode, options.query_names)
    local vary = header_digest(options.vary_headers)
    if not query or not vary then
      return nil
    end
    ngx.var.cdnca_cache_policy_key = options.key_prefix .. uri .. "?~q=" .. query .. "&~v=" .. vary
  end
  ngx.var.cdnca_cache_policy_bypass = "0"
  return route
end

function M.dispatch(options)
  ngx.var.cdnca_cache_policy_bypass = "1"
  local ok, route = pcall(select_route, options)
  ngx.var.cdnca_cache_policy_routed = "1"
  if not ok or not route then
    return ngx.exec(options.bypass)
  end
  return ngx.exec(route)
end

return M
