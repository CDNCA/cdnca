-- HTTP 策略精确来源 CORS：每个响应合并 Vary: Origin 的开销。
-- 每次迭代发一个子请求（新响应、新头部列表；同一请求里反复改头会让 nginx 头部列表越积越长，不能那样测），
-- 子请求的 header_filter 连续跑 50 次 httppolicy.header_filter（每次先清掉它写的头，摊薄子请求开销；头部列表略增长，结果偏高、作为上限）：开 CORS（精确来源列表）且无 Origin、开 CORS 且来源允许、
-- 未开 CORS 三种，各减去不跑过滤器的子请求；几种交替跑多轮取中位数。
-- NP_SERVER_EXTRA="$(cat tests/node-perf/lua-micro/http_policy_cors_vary_server.conf)" \
-- tests/node-perf/lua-micro/run.sh tests/node-perf/lua-micro/http_policy_cors_vary_bench.lua 4000
-- 实测（arm64，中位数 ns/响应，旧→新）：未开 CORS 178→187、来源允许 519→553（同为噪声内），
-- 开 CORS 无 Origin 181→384（多一次 Vary 合并，只发生在精确来源 CORS 站点）。
-- 与改动前比较：LUA_ROOT=<旧提交的 edge/openresty> 再跑一次。
local ngx = ngx
local N = tonumber(os.getenv("NP_ITERS")) or 20000
local ROUNDS = 9
local capture = ngx.location.capture

local function run(mode)
    local args = { args = { mode = mode } }
    local c = os.clock()
    for _ = 1, N do capture("/np-cors", args) end
    return os.clock() - c
end

local modes = { "cors_no_origin", "cors_allowed_origin", "no_cors" }
run("none"); for _, mode in ipairs(modes) do run(mode) end -- warm up
local samples = {}
for _ = 1, ROUNDS do
    local base = run("none")
    for _, mode in ipairs(modes) do
        samples[mode] = samples[mode] or {}
        table.insert(samples[mode], (run(mode) - base) / (N * 50) * 1e9)
    end
end
for _, mode in ipairs(modes) do
    local s = samples[mode]
    table.sort(s)
    ngx.log(ngx.NOTICE, string.format("[bench] %-20s median %7.1f ns/response (min %7.1f max %7.1f)",
        mode, s[(#s + 1) / 2], s[1], s[#s]))
end
