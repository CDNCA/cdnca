-- Differential harness of the rule plan interpreter (rule_plan_diff_integration_test.go).
-- One server runs every generated rule set two ways, chosen by the request
-- header X-Cdnca-Case "<compiled|interp>:<index>":
--   compiled  require("rules.r<index>").run(trace)  -- renderWAF output (oracle)
--   interp    cdnca_rule_interp.enforce(plan, trace) -- plans/<index>.json
-- header_filter reports status-independent observations in X-Cdnca-Result:
-- the security telemetry variables, the per-segment trace and how often the
-- side-effecting conditions (cdnca_iplib.match, cdnca_waf.inspect) ran.
local interp = require("cdnca_rule_interp")
local waf = require("cdnca_waf")

local inspect = waf.inspect
waf.inspect = function(raw)
    ngx.ctx.inspect_calls = (ngx.ctx.inspect_calls or 0) + 1
    return inspect(raw)
end

local _M = {}
local programs = {}
local root = ngx.config.prefix()

local function program(index)
    local cached = programs[index]
    if cached then return cached end
    local file = assert(io.open(root .. "plans/" .. index .. ".json", "rb"))
    local raw = file:read("*a")
    file:close()
    cached = assert(interp.compile_json(raw))
    programs[index] = cached
    return cached
end

function _M.rewrite()
    local case = ngx.var.http_x_cdnca_case
    if not case then return end
    local mode, index, pair = case:match("^(%a+):(%d+):?(%d*)$")
    if pair and pair ~= "" then ngx.ctx.cdnca_waf_scope_suffix = ":" .. mode .. ":" .. pair end
    local trace = {}
    ngx.ctx.trace = trace
    if mode == "compiled" then
        return require("rules.r" .. index).run(trace)
    end
    return interp.enforce(program(index), trace)
end

function _M.header_filter()
    local var, ctx = ngx.var, ngx.ctx
    ngx.header["X-Cdnca-Result"] = table.concat({
        var.cdnca_security_emit, var.cdnca_security_type, var.cdnca_security_action, var.cdnca_security_block_page,
        var.cdnca_security_severity, var.cdnca_security_rule_id, table.concat(ctx.trace or {}, ","),
        tostring(ctx.iplib_calls or 0), tostring(ctx.inspect_calls or 0),
        var.cdnca_security_policy_id, var.cdnca_security_detector, ngx.encode_base64(var.cdnca_security_matched or ""),
    }, "|")
end

-- Benchmark: run one rule set many times in the current request, alternating
-- modes in blocks, and report per-run latency percentiles (nanoseconds).
local ffi = require("ffi")
ffi.cdef [[
typedef struct { long tv_sec; long tv_nsec; } cdnca_bench_timespec;
int clock_gettime(int clk_id, cdnca_bench_timespec *tp);
]]
local now_buffer = ffi.new("cdnca_bench_timespec")
local function now_ns()
    ffi.C.clock_gettime(1, now_buffer) -- CLOCK_MONOTONIC
    return tonumber(now_buffer.tv_sec) * 1e9 + tonumber(now_buffer.tv_nsec)
end

local function stats(samples)
    table.sort(samples)
    local sum = 0
    for _, value in ipairs(samples) do sum = sum + value end
    local function at(fraction) return samples[math.max(1, math.ceil(#samples * fraction))] end
    return { p50 = at(0.5), p90 = at(0.9), p99 = at(0.99), mean = sum / #samples, n = #samples }
end

function _M.bench()
    local index = ngx.var.http_x_cdnca_bench
    local rounds = tonumber(ngx.var.http_x_cdnca_rounds) or 20
    local block = tonumber(ngx.var.http_x_cdnca_block) or 1000
    local compiled = require("rules.r" .. index)
    local plan = program(index)
    local runs = {
        compiled = function() compiled.run(nil) end,
        interp = function() interp.enforce(plan, nil) end,
    }
    local samples = { compiled = {}, interp = {} }
    for _ = 1, rounds do
        for _, mode in ipairs({ "compiled", "interp" }) do
            local run, list = runs[mode], samples[mode]
            for _ = 1, block do
                ngx.ctx.cdnca_inspect_values, ngx.ctx.cdnca_inspect_body = nil, nil
                local started = now_ns()
                run()
                list[#list + 1] = now_ns() - started
            end
        end
    end
    -- Plan load cost: JSON decode + compile, and the program's Lua heap.
    local file = assert(io.open(root .. "plans/" .. index .. ".json", "rb"))
    local raw = file:read("*a")
    file:close()
    local loads = {}
    for _ = 1, 30 do
        local started = now_ns()
        assert(interp.compile_json(raw))
        loads[#loads + 1] = now_ns() - started
    end
    collectgarbage("collect")
    collectgarbage("stop")
    local before = collectgarbage("count")
    local kept = assert(interp.compile_json(raw))
    local heap_kb = collectgarbage("count") - before
    collectgarbage("restart")
    local verdict, kind, rule = interp.evaluate(kept)
    ngx.say(require("cjson").encode({
        compiled = stats(samples.compiled), interp = stats(samples.interp), load = stats(loads),
        plan_bytes = #raw, program_heap_kb = heap_kb, verdict = verdict, kind = kind, rule = rule,
    }))
end

return _M
