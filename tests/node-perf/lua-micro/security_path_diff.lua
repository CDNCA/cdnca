-- 差分：NEW 为 /lua（改后），OLD 为 /old（改前），随机查询串输出必须逐字节相同。
package.loaded["cdnca_site"] = {}
local function load(root)
    local saved = package.loaded["cdnca_telemetry"]; package.loaded["cdnca_telemetry"] = nil
    local f = assert(loadfile(root .. "/dynroute/cdnca_telemetry.lua"))
    local m = f(); package.loaded["cdnca_telemetry"] = saved; return m
end
local new, old = load("/lua"), load("/old")
math.randomseed(7)
local names = { "q", "token", "Token", "api_key", "apiKey", "client_secret", "a+b", "pass%77ord", "id", "utm_source", "", "x y", "refreshSecret", "code", "%E4%BD%A0" }
local vals = { "", "1", "hello", "%2F", "a b", "\1\2", "\200\201", string.rep("v", 300) }
local bad = 0
for i = 1, 20000 do
    local parts = {}
    for _ = 1, math.random(0, 8) do
        local n, v = names[math.random(#names)], vals[math.random(#vals)]
        parts[#parts + 1] = math.random(5) == 1 and n or (n .. "=" .. v)
        if math.random(10) == 1 then parts[#parts + 1] = "" end
    end
    local q = table.concat(parts, "&")
    local uri = math.random(20) == 1 and string.rep("/p", math.random(1, 2100)) or "/x"
    if new.security_path(uri, q) ~= old.security_path(uri, q) then
        bad = bad + 1; if bad < 4 then print("[bench] DIFF", q) end
    end
end
print("[bench] 差分 20000 例, 不一致 " .. bad)
