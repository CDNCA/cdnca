-- capture log() 改前(/old)与改后(/lua)差分。每个用例在两棵树各跑一次 log()，比较两个 JSON 变量。
-- emit=0 时只比 access（security 变量改后固定为占位，且不会被写入日志）；emit=1 时 access 与 security 都必须相同。
local function strip(s)
    return (s:gsub('"request_id":"%x+"', ""):gsub('"connection":"%d+"', ""))
end

local function run(root, case)
    for k in pairs(package.loaded) do
        if k:match("^cdnca_") then package.loaded[k] = nil end
    end
    local saved = package.path
    package.path = root .. "/dynroute/?.lua;" .. root .. "/?.lua;" .. saved
    local site = { telemetry = { capture = case.capture } }
    package.loaded["cdnca_site"] = { current = function() return site end }
    local t = require "cdnca_telemetry"
    ngx.var.cdnca_security_emit = case.emit
    ngx.var.cdnca_security_user_agent = case.ua or ""
    ngx.var.cdnca_security_matched = case.matched or ""
    ngx.var.cdnca_site_generation, ngx.var.cdnca_site_scope, ngx.var.cdnca_site_digest = "1", "s", "d"
    t.log()
    package.path = saved
    return ngx.var.cdnca_access_telemetry_json, ngx.var.cdnca_security_telemetry_json
end

local big = string.rep("x", 3000)
local cases = {
    { name = "emit0 默认", emit = "0", capture = { enabled = true } },
    { name = "emit1 默认", emit = "1", capture = { enabled = true }, ua = "curl/8", matched = "rule" },
    { name = "emit1 头白名单", emit = "1", capture = { enabled = true, request_header_allowlist = { "Host" } } },
    { name = "emit0 max_event=300", emit = "0", capture = { enabled = true, max_event_bytes = 300 } },
    { name = "emit1 max_event=300", emit = "1", capture = { enabled = true, max_event_bytes = 300 } },
    { name = "emit1 仅 security 超限", emit = "1", capture = { enabled = true, max_event_bytes = 1200 }, ua = big, matched = big },
    { name = "emit0 max_event=50", emit = "0", capture = { enabled = true, max_event_bytes = 50 } },
    { name = "emit1 max_event=50", emit = "1", capture = { enabled = true, max_event_bytes = 50 } },
}

local bad = 0
for _, c in ipairs(cases) do
    local oa, os_ = run("/old", c)
    local na, ns = run("/lua", c)
    local same_a = strip(oa) == strip(na)
    local same_s = c.emit ~= "1" or strip(os_) == strip(ns)
    if not (same_a and same_s) then bad = bad + 1 end
    print(string.format("[bench] %-24s access=%s security=%s (access %d/%d, security %d/%d)", c.name,
        same_a and "同" or "不同", c.emit == "1" and (same_s and "同" or "不同") or "略", #oa, #na, #os_, #ns))
end
print("[bench] 不同用例数 " .. bad)
