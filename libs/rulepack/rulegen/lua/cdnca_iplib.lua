-- Stand-in for edge/openresty/iplib/cdnca_iplib.lua in the rule plan
-- differential test: match(spec) is a deterministic function of the spec and
-- the client address (so both modes see the same answer and either value
-- occurs), and every call is counted so the two modes can be compared on how
-- often the condition was evaluated.
local _M = {}

function _M.match(spec)
    ngx.ctx.iplib_calls = (ngx.ctx.iplib_calls or 0) + 1
    local key = ngx.crc32_short(spec .. "|" .. (ngx.var.binary_remote_addr or ""))
    return key % 3 == 0
end

return _M
