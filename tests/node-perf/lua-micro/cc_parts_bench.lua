-- ccv2 run() 每请求每规则的固定开销拆解（表达式与 ccv2/engine.lua 一致，内联复现）。
local N = tonumber(os.getenv("NP_ITERS")) or 1000000
local config = { tenant_scope_id = "01a1ceda-7a86-7ec2-bcdb-6fd857778340", site_id = "01a192ca-1111-7222-8333-444455556666",
    policy_id = "01a192ca-aaaa-7bbb-8ccc-ddddeeeeffff", policy_version = 7, binding_id = "01a192ca-9999-7888-8777-666655554444",
    binding_revision = 3 }
local rule_id = "01a192ca-5555-7444-8333-222211110000"
local peer_text = "203.0.113.57"
local rows = {}
local function t(name, f)
    for _ = 1, 20000 do f() end
    local c = os.clock(); for _ = 1, N do f() end
    print(string.format("[bench] %-44s %7.0f ns", name, (os.clock() - c) / N * 1e9))
end
t("stat(): ngx.now+floor+concat6+查表(命中)", function()
    local minute = math.floor(ngx.now() / 60) * 60
    local key = table.concat({ config.tenant_scope_id, config.site_id, config.policy_id, tostring(config.policy_version),
        rule_id, tostring(minute) }, "|")
    local row = rows[key]; if not row then row = { matched = 0 }; rows[key] = row end
    row.matched = row.matched + 1
end)
local cached_minute, cached_row = -1, { matched = 0 }
t("stat() 缓存方案: ngx.now+floor+比较", function()
    local minute = math.floor(ngx.now() / 60) * 60
    if minute ~= cached_minute then cached_minute = minute end
    cached_row.matched = cached_row.matched + 1
end)
t("规则 key: scoped+concat4(binding,rev,rule,ip)", function()
    local k = "t:" .. config.tenant_scope_id .. ":" .. table.concat({ config.binding_id, tostring(config.binding_revision), rule_id, peer_text }, ":")
    return k
end)
t("规则 key 缓存前缀 .. ip", function()
    local k = "t:01a1ceda-7a86-7ec2-bcdb-6fd857778340:01a192ca-9999-7888-8777-666655554444:3:01a192ca-5555-7444-8333-222211110000:" .. peer_text
    return k
end)
local function parse_ipv4(value)
    if type(value) ~= "string" or #value == 0 or #value > 15 then return nil end
    local bytes = {}
    for part in (value .. "."):gmatch("(.-)%.") do
        if part == "" or part:find("[^0-9]") or (#part > 1 and part:sub(1, 1) == "0") then return nil end
        local byte = tonumber(part)
        if not byte or byte > 255 then return nil end
        bytes[#bytes + 1] = byte
    end
    if #bytes ~= 4 then return nil end
    return { family = 4, bytes = bytes, text = value }
end
t("parse_ipv4 (每请求一次)", function() return parse_ipv4(peer_text) end)
