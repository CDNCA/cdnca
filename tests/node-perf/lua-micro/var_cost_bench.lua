-- ngx.var 读写与 SERVER_DEFAULTS 循环的每请求成本（log 阶段）。需 run.sh 声明变量。
local ngx_var = ngx.var
local N = tonumber(os.getenv("NP_ITERS")) or 1000000
local D = { cdnca_security_emit = "0", cdnca_security_type = "", cdnca_security_action = "",
    cdnca_security_severity = "", cdnca_security_rule_id = "", cdnca_security_block_page = "0" }
local function t(name, f)
    for _ = 1, 20000 do f() end
    local c = os.clock(); for _ = 1, N do f() end
    print(string.format("[bench] %-34s %7.0f ns", name, (os.clock() - c) / N * 1e9))
end
t("pairs(DEFAULTS) 6次读(已有值)", function() for name, d in pairs(D) do if ngx_var[name] == nil then ngx_var[name] = d end end end)
t("1次 ngx.var 读", function() return ngx_var.cdnca_security_emit end)
t("1次 ngx.var 写", function() ngx_var.cdnca_security_path = "/x" end)
t("1次 ngx.var 读(内置 uri)", function() return ngx_var.uri end)
