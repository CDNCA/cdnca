-- ri-03d: automatic exclusions without per-site locations. The test passes
-- the site in X-Poc-Site (cleared before ModSecurity reads the headers);
-- production takes it from the site object. Every site enters the tier
-- location; A: the node rules' hook tree picks the site's exclusions from
-- s= in the transaction ID. B: Lua removes the excluded argument first.
local _M = {}
-- plan C: site ID -> bucket location (empty in plan A)
local buckets = {}

function _M.load(path)
  local file = io.open(path, "r")
  if not file then return end
  for line in file:lines() do
    local site, location = line:match("^(%S+) (%S+)$")
    buckets[site] = location
  end
  file:close()
end

local function txid(site)
  return "s=" .. site .. "|" .. string.format("%08x%08x", math.random(0, 0x7fffffff), math.random(0, 0x7fffffff))
end

function _M.rewrite()
  local site = ngx.var.http_x_poc_site or ""
  ngx.req.clear_header("X-Poc-Site")
  ngx.var.cdnca_waf_txid = txid(site)
  return ngx.exec(buckets[site] or "@cdnca_waf_tier")
end

-- B: drop the argument from the request's arguments (ngx.req.set_uri_args)
-- and then enter the tier location
function _M.rewrite_drop(name)
  local site = ngx.var.http_x_poc_site or ""
  ngx.req.clear_header("X-Poc-Site")
  local args = ngx.req.get_uri_args()
  args[name] = nil
  ngx.req.set_uri_args(args)
  ngx.var.cdnca_waf_txid = txid(site)
  return ngx.exec("@cdnca_waf_tier")
end

return _M
