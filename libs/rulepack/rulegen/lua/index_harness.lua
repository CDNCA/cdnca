-- Harness of matchindex_integration_test.go. Every plan is loaded twice from
-- plans/<i>.json: "linear" (the D6 interpreter path, index dropped) and
-- "index" (the match index). X-Cdnca-Case "<mode>:<i>" picks one; the
-- X-Cdnca-Result header reports the decision and its observable side effects.
-- X-Cdnca-Time: cold | warm records the evaluation time instead (GET /__stats).
local interp = require("cdnca_rule_interp")
local cjson = require("cjson")
local ffi = require("ffi")
ffi.cdef [[
typedef struct { long tv_sec; long tv_nsec; } cdnca_index_timespec;
int clock_gettime(int clk_id, cdnca_index_timespec *tp);
]]
local now_buffer = ffi.new("cdnca_index_timespec")
local function now_ns()
    ffi.C.clock_gettime(1, now_buffer)
    return tonumber(now_buffer.tv_sec) * 1e9 + tonumber(now_buffer.tv_nsec)
end

local _M = {}
local programs, heap_kb, samples, rss_kb = {}, {}, {}, {}
local root = ngx.config.prefix()

local function rss()
    local file = io.open("/proc/self/status", "r")
    local status = file:read("*a")
    file:close()
    return tonumber(status:match("VmRSS:%s*(%d+)"))
end

local function program(mode, index)
    local key = mode .. ":" .. index
    local cached = programs[key]
    if cached then return cached end
    local file = assert(io.open(root .. "plans/" .. index .. ".json", "rb"))
    local raw = file:read("*a")
    file:close()
    collectgarbage("collect")
    local before = collectgarbage("count")
    if mode == "linear" then
        local plan = cjson.decode(raw)
        plan.index = nil
        cached = assert(interp.compile(plan))
    else
        -- The production path (cdnca_security mount_program).
        cached = assert(interp.compile_json(raw))
    end
    raw = nil
    collectgarbage("collect")
    heap_kb[key] = collectgarbage("count") - before
    programs[key] = cached
    return cached
end

-- preload: the indexed programs first, so rss_kb splits the worker's RSS
-- into the process base, the indexed programs and the linear programs.
function _M.preload(count)
    collectgarbage("collect")
    rss_kb.base = rss()
    for index = 0, count - 1 do program("index", index) end
    collectgarbage("collect")
    rss_kb.index = rss()
    for index = 0, count - 1 do program("linear", index) end
    collectgarbage("collect")
    rss_kb.linear = rss()
end

function _M.content()
    local mode, index = (ngx.var.http_x_cdnca_case or ""):match("^(%a+):(%d+)$")
    if not mode then return ngx.exit(400) end
    local compiled = program(mode, index)
    local trace = {}
    local timing = ngx.var.http_x_cdnca_time
    if timing then
        -- "warm": the request's inspect values are extracted first (with
        -- the index groups' specs, which both modes read through the same
        -- per-request cache), so only matching is timed; "cold" times all.
        if timing == "warm" then
            ngx.req.read_body()
            local waf = require("cdnca_waf")
            for _, group in ipairs(program("index", index).index.groups) do waf.text_values(group.spec) end
        end
        local started = now_ns()
        interp.evaluate(compiled, nil)
        local elapsed = now_ns() - started
        local key = mode .. ":" .. timing .. (ngx.var.http_x_cdnca_class and ":" .. ngx.var.http_x_cdnca_class or "")
        samples[key] = samples[key] or {}
        local list = samples[key]
        list[#list + 1] = elapsed
        return ngx.say("t")
    end
    local verdict, kind, rule, policy = interp.evaluate(compiled, trace)
    local last = ngx.ctx.cdnca_inspect_last or {}
    ngx.header["X-Cdnca-Result"] = table.concat({ verdict or "", kind or "", rule or "", policy or "", table.concat(trace, ","),
        ngx.ctx.cdnca_inspect_body ~= nil and "body" or "nobody", last.target or "", last.key or "",
        ngx.encode_base64(last.fragment or ""), last.detector or "" }, "|")
    ngx.say("ok")
end

local function stats(list)
    table.sort(list)
    local function at(fraction) return list[math.max(1, math.ceil(#list * fraction))] end
    local sum = 0
    for _, value in ipairs(list) do sum = sum + value end
    return { p50 = at(0.5), p99 = at(0.99), mean = sum / #list, n = #list }
end

-- stats: the worker RSS at the end and by source (rss_kb: base, after the
-- indexed programs, after the linear programs; samples: RSS before and
-- after dropping the timing samples; heap_kb.end: Lua heap now).
function _M.stats()
    local result = { rss_kb = rss(), heap_kb = heap_kb, timing = {}, rss_split_kb = rss_kb }
    for key, list in pairs(samples) do result.timing[key] = stats(list) end
    collectgarbage("collect")
    heap_kb["end"] = collectgarbage("count")
    local count = 0
    for _, list in pairs(samples) do count = count + #list end
    result.samples = count
    ngx.say(cjson.encode(result))
end

return _M
