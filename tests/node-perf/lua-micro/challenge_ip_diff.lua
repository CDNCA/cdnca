-- 差分：challenge/ip.lua 的 parse_ipv4，改前(/old)与改后(/lua)逐例比较 family/bytes/display/canonical。
resty_string = require("resty.string") -- 改前版本的上值，抽出函数文本后按全局解析
local function extract(path)
    local f = assert(io.open(path, "rb")); local s = f:read("*a"); f:close()
    local from = assert(s:find("local function parse_ipv4", 1, true))
    local to = assert(s:find("\nend\n", from, true))
    return assert(loadstring("return " .. s:sub(from, to + 3):gsub("^local function parse_ipv4", "function")))()
end
local new, old = extract("/lua/challenge/ip.lua"), extract("/old/challenge/ip.lua")
local function same(v)
    local a, b = new(v), old(v)
    if (a == nil) ~= (b == nil) then return false end
    if a == nil then return true end
    if a.family ~= b.family or a.display ~= b.display or a.canonical ~= b.canonical or #a.bytes ~= #b.bytes then return false end
    for i = 1, #a.bytes do if a.bytes[i] ~= b.bytes[i] then return false end end
    return true
end
local fixed = { "0.0.0.0", "255.255.255.255", "256.1.1.1", "01.2.3.4", "1.2.3", "1.2.3.4.5", "1..2.3", ".1.2.3", "1.2.3.", "a.b.c.d",
    "1.2.3.4 ", " 1.2.3.4", "1.2.3.04", "001.2.3.4", "1.2.3.-4", "1.2.3.4a", "", "::1", "999.999.999.999", "00.0.0.0", "12345.1.1.1", "1.2.3.4\n", "203.0.113.57", 7, nil }
local bad, total = 0, 0
for _, v in ipairs(fixed) do total = total + 1; if not same(v) then bad = bad + 1; print("[bench] DIFF", tostring(v)) end end
total = total + 1; if not same(nil) then bad = bad + 1 end
math.randomseed(13)
local pool = { "0", "1", "9", "10", "99", "100", "199", "200", "249", "255", "256", "300", "00", "01", "007", "1000", "", "a", "-1", "1 " }
for _ = 1, 200000 do
    local t = {}
    for i = 1, math.random(3, 5) do t[i] = pool[math.random(#pool)] end
    local v = table.concat(t, ".")
    total = total + 1; if not same(v) then bad = bad + 1; if bad < 6 then print("[bench] DIFF", v) end end
end
print(string.format("[bench] challenge parse_ipv4 差分 %d 例, 不一致 %d", total, bad))
local N = tonumber(os.getenv("NP_ITERS")) or 1000000
for _, c in ipairs({ { "改前", old }, { "改后", new } }) do
    for _ = 1, 20000 do c[2]("203.0.113.57") end
    local t0 = os.clock(); for _ = 1, N do c[2]("203.0.113.57") end
    print(string.format("[bench] challenge parse_ipv4 %s %6.0f ns", c[1], (os.clock() - t0) / N * 1e9))
end
