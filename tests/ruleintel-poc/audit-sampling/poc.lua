-- Transaction ID = "<context>|<request id>": the request id is nginx's
-- $request_id (32 random hex digits), so its last hex digit is a uniform
-- 1/16 sample key (ADR 0011 §3.1).
local _M = {}
function _M.server_rewrite()
  ngx.var.cdnca_waf_txid = "c3;|" .. ngx.var.request_id
end
return _M
