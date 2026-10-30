-- ADR 0011 RI-03: per-site automatic exclusions. The test
-- passes the site in X-Poc-Site (cleared before ModSecurity reads the
-- headers); production takes it from the site object. A site with an
-- exclusion block enters its own named location (one table lookup, one
-- ngx.exec); every other site its tier location.
local _M = {}
local sites = {}

function _M.load(path)
  local file = io.open(path, "r")
  if not file then return end
  for id in file:lines() do sites[id] = "@cdnca_waf_s" .. id end
  file:close()
end

function _M.rewrite()
  local site = ngx.var.http_x_poc_site or ""
  ngx.req.clear_header("X-Poc-Site")
  ngx.var.cdnca_waf_txid = "s=" .. site .. "|" .. string.format("%08x%08x", math.random(0, 0x7fffffff), math.random(0, 0x7fffffff))
  return ngx.exec(sites[site] or "@cdnca_waf_tier")
end

return _M
