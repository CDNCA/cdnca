-- 差分：ccv2/engine.lua 的 parse_ipv4，改前(/old)与改后(/lua)逐例比较。
local function extract(path)
    local f = assert(io.open(path, "rb")); local s = f:read("*a"); f:close()
    local from = assert(s:find("local function parse_ipv4", 1, true))
    local to = assert(s:find("\nend\n", from, true))
    return assert(loadstring("return " .. s:sub(from, to + 3):gsub("^local function parse_ipv4", "function")))()
end
local new, old = extract("/lua/ccv2/engine.lua"), extract("/old/ccv2/engine.lua")
local function same(v)
    local a, b = new(v), old(v)
    if (a == nil) ~= (b == nil) then return false end
    if a == nil then return true end
    if a.family ~= b.family or a.text ~= b.text or #a.bytes ~= #b.bytes then return false end
    for i = 1, #a.bytes do if a.bytes[i] ~= b.bytes[i] then return false end end
    return true
end
local fixed = { "0.0.0.0", "255.255.255.255", "256.1.1.1", "01.2.3.4", "1.2.3", "1.2.3.4.5", "1..2.3", ".1.2.3", "1.2.3.", "a.b.c.d",
    "1.2.3.4 ", " 1.2.3.4", "1.2.3.04", "001.2.3.4", "1.2.3.-4", "1.2.3.4a", "", "::1", "999.999.999.999", "00.0.0.0", "0.00.0.0", "12345.1.1.1", "1.2.3.4\n" }
local bad, total = 0, 0
for _, v in ipairs(fixed) do total = total + 1; if not same(v) then bad = bad + 1; print("[bench] DIFF", v) end end
math.randomseed(11)
local pool = { "0", "1", "9", "10", "99", "100", "199", "200", "249", "255", "256", "300", "00", "01", "007", "1000", "", "a", "-1", "1 " }
for _ = 1, 200000 do
    local n = math.random(3, 5); local t = {}
    for i = 1, n do t[i] = pool[math.random(#pool)] end
    local v = table.concat(t, ".")
    total = total + 1; if not same(v) then bad = bad + 1; if bad < 6 then print("[bench] DIFF", v) end end
end
print(string.format("[bench] parse_ipv4 差分 %d 例, 不一致 %d", total, bad))
