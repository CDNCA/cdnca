local function safe_status(raw)
  local status = tonumber(raw)
  if status == nil or status ~= math.floor(status) or status < 400 or status > 599 then
    return 500
  end
  return status
end

local function fallback(status)
  if status >= 500 then
    return "text/plain", "Service temporarily unavailable.\n"
  end
  return "text/plain", "Request could not be completed.\n"
end

local function lookup(policy, site_key, category, status)
  if type(policy) ~= "table" or type(policy.bindings) ~= "table" or type(policy.resources) ~= "table" then
    return nil
  end
  local suffix = "|" .. category .. "|" .. tostring(status)
  local resource_key
  if site_key ~= "" then
    resource_key = policy.bindings[site_key .. suffix]
  end
  if resource_key == nil then
    resource_key = policy.bindings[suffix]
  end
  if type(resource_key) ~= "string" then
    return nil
  end
  local resource = policy.resources[resource_key]
  if type(resource) ~= "table" or type(resource.body) ~= "string" or
      type(resource.mime) ~= "string" or type(resource.size) ~= "number" or
      #resource.body ~= resource.size then
    return nil
  end
  if resource.mime ~= "text/html" and resource.mime ~= "text/plain" and resource.mime ~= "application/json" then
    return nil
  end
  return resource
end

-- The policy file the site runtime copied into its release; loaded once per
-- worker (a new policy is a new release and a reload).
local function load_policy(path)
  if path == nil or path == "" then
    return rawget(_G, "cdnca_error_policy")
  end
  local cache = package.loaded["cdnca.errorpage.policies"]
  if cache == nil then
    cache = {}
    package.loaded["cdnca.errorpage.policies"] = cache
  end
  local policy = cache[path]
  if policy == nil then
    local ok, loaded = pcall(dofile, path)
    if ok and type(loaded) == "table" then
      policy = loaded
    else
      ngx.log(ngx.ERR, "error page policy is unavailable: ", path)
      policy = false
    end
    cache[path] = policy
  end
  return policy or nil
end

-- origin_response: the origin answered with this status; edge_connect: the
-- edge could not get a response from the origin (502/503/504 it generated);
-- edge_route: the edge answered without the origin (ACL, WAF, routing).
local function classify(status)
  local configured = ngx.var.cdnca_error_category
  if configured ~= nil and configured ~= "" then
    return configured
  end
  local upstream = ngx.var.upstream_status
  if upstream == nil or upstream == "" or upstream == "-" then
    return "edge_route"
  end
  local last = upstream:match("([^,%s:]+)%s*$")
  local headers = ngx.var.upstream_header_time or ""
  local last_header = headers:match("([^,%s:]+)%s*$")
  if tonumber(last) == status and last_header ~= nil and last_header ~= "-" then
    return "origin_response"
  end
  return "edge_connect"
end

local status = safe_status(ngx.var.cdnca_error_status)
local category = classify(status)
local site_key = ngx.var.cdnca_error_site or ""
local resource

if ngx.ctx.cdnca_errorpage_handled ~= true then
  ngx.ctx.cdnca_errorpage_handled = true
  resource = lookup(load_policy(ngx.var.cdnca_error_policy), site_key, category, status)
end

local mime_type
local body
local style_hash
if resource == nil then
  mime_type, body = fallback(status)
else
  mime_type, body = resource.mime, resource.body
  -- ADR 0007 §7.2: a theme page's single <style>, pinned by the hash the
  -- agent computed after validating it against the canonical grammar.
  if mime_type == "text/html" and type(resource.style_hash) == "string" and
      resource.style_hash:match("^sha256%-[A-Za-z0-9+/]+=*$") then
    style_hash = resource.style_hash
  end
end

for _, header in ipairs({
  "Content-Encoding", "Content-Range", "ETag", "Expires", "Last-Modified",
  "Location", "Set-Cookie", "Vary", "Via", "WWW-Authenticate", "X-Powered-By"
}) do
  ngx.header[header] = nil
end

if mime_type == "text/html" or mime_type == "text/plain" then
  ngx.header["Content-Type"] = mime_type .. "; charset=utf-8"
else
  ngx.header["Content-Type"] = mime_type
end
ngx.header["Content-Length"] = tostring(#body)
ngx.header["Cache-Control"] = "no-store, max-age=0"
ngx.header["Pragma"] = "no-cache"
ngx.header["Expires"] = "0"
local csp = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox"
if style_hash ~= nil then
  csp = csp .. "; style-src '" .. style_hash .. "'"
end
ngx.header["Content-Security-Policy"] = csp
ngx.header["Referrer-Policy"] = "no-referrer"
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.status = status

if ngx.req.get_method() ~= "HEAD" then
  ngx.print(body)
end
return ngx.exit(ngx.OK)
