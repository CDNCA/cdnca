-- The node's Lua writes the managed WAF context into the transaction ID
-- before ModSecurity's rewrite handler (ADR 0009 PoC 5). Here the test
-- passes the t= part in X-Poc-Ctx (cleared before ModSecurity reads the
-- headers); production builds it from the site object.
local _M = {}
function _M.server_rewrite()
  local ctx = ngx.var.http_x_poc_ctx
  ngx.req.clear_header("X-Poc-Ctx")
  if not ctx or not ctx:match("^t=,[0-9A-Za-z_.:,-]*$") then ctx = "t=," end
  ngx.var.cdnca_waf_txid = ctx .. "|" .. string.format("%08x%08x", math.random(0, 0x7fffffff), math.random(0, 0x7fffffff))
end
return _M
