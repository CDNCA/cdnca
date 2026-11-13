-- ccv2 parse_ipv4（每请求解析 remote_addr）改前后耗时。需挂 /old 与 /lua。
local function extract(path)
    local f = assert(io.open(path, "rb")); local s = f:read("*a"); f:close()
    local from = assert(s:find("local function parse_ipv4", 1, true))
    local to = assert(s:find("\nend\n", from, true))
    return assert(loadstring("return " .. s:sub(from, to + 3):gsub("^local function parse_ipv4", "function")))()
end
local N = tonumber(os.getenv("NP_ITERS")) or 1000000
for _, c in ipairs({ { "改前", "/old" }, { "改后", "/lua" } }) do
    local fn = extract(c[2] .. "/ccv2/engine.lua")
    for _ = 1, 20000 do fn("203.0.113.57") end
    local t0 = os.clock(); for _ = 1, N do fn("203.0.113.57") end
    print(string.format("[bench] parse_ipv4 %s %6.0f ns", c[1], (os.clock() - t0) / N * 1e9))
end
