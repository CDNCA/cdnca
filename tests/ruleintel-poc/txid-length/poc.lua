-- Writes a c3-shaped context of exactly X-Poc-Len bytes into the
-- transaction ID: "c3;s=<uuid>;t=" + ",<rule>:<param>" pairs padded to
-- length + ";|" + $request_id (32 hex). X-Poc-Len absent: a short context.
local _M = {}
function _M.server_rewrite()
  local want = tonumber(ngx.var.http_x_poc_len or "") or 0
  ngx.req.clear_header("X-Poc-Len")
  local head = "c3;s=00000000-0000-4000-8000-000000000001;t="
  local tail = ";|" .. ngx.var.request_id
  local fill = want - #head - #tail
  local parts, n = {}, 0
  local size = 0
  while fill > 0 and size + 13 <= fill do
    n = n + 1
    parts[#parts + 1] = string.format(",942%03d:p%04d", n % 1000, n % 10000)
    size = size + 13
  end
  local body = table.concat(parts) .. string.rep(",", math.max(fill - size, 0))
  ngx.var.cdnca_waf_txid = head .. body .. tail
end
return _M
