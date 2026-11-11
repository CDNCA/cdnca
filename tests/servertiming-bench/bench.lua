-- Server-Timing micro benchmark: each case runs N
-- times inside one real header_filter (the response of /bypass or /hit),
-- ns per call = CPU time / N minus the empty loop. "old" is aea807acc's
-- server_timing copied verbatim; "new" is cdnca_filters' current one.
local ngx = ngx
local ngx_var, ngx_header = ngx.var, ngx.header
local ngx_resp = require "ngx.resp"
local N = 200000
-- a header written and cleared stays in headers_out (nginx only zeroes its
-- hash), so each later write scans one more entry: few rounds for those
local NH = 50
local ffi = require "ffi"
ffi.cdef[[ typedef struct { long tv_sec; long tv_nsec; } cdnca_st_ts; int clock_gettime(int, cdnca_st_ts *); ]]
local ts = ffi.new("cdnca_st_ts")
local function now()
    ffi.C.clock_gettime(1, ts)
    return tonumber(ts.tv_sec) * 1e9 + tonumber(ts.tv_nsec)
end

local _M = {}

-- aea807acc cdnca_filters.lua server_timing (verbatim, minus the L2 branch)
local HIT_LAYER_EDGE = { HIT = true, STALE = true, UPDATING = true, REVALIDATED = true }
local HIT_LAYER_MISS = { MISS = true, EXPIRED = true }
local function old_last_ms(value)
    if not value then
        return nil
    end
    local seconds = tonumber(value:match("([%d%.]+)%s*$"))
    if not seconds then
        return nil
    end
    return string.format("%d", math.floor(seconds * 1000 + 0.5))
end
local function old_server_timing()
    if ngx_var.cdnca_l2_trusted == "1" then
        return
    end
    local entries = {}
    local status = ngx_var.cdnca_cache_status
    if status and status ~= "" then
        entries[1] = "cdn-cache;desc=" .. status
        if HIT_LAYER_EDGE[status] then
            entries[#entries + 1] = "cdn-hit-layer;desc=edge"
        elseif HIT_LAYER_MISS[status] and ngx_var.cdnca_origin_l2_hop == "1" and
            HIT_LAYER_EDGE[ngx_var.upstream_http_x_cdnca_l2_cache or ""] then
            entries[#entries + 1] = "cdn-hit-layer;desc=l2"
        end
    end
    local connect = old_last_ms(ngx_var.upstream_connect_time)
    if connect then
        entries[#entries + 1] = "cdn-connect;dur=" .. connect
    end
    local ttfb = old_last_ms(ngx_var.upstream_header_time)
    if ttfb then
        entries[#entries + 1] = "cdn-ttfb;dur=" .. ttfb
    end
    if #entries == 0 then
        return
    end
    local value = table.concat(entries, ", ")
    local current = ngx_header["Server-Timing"]
    if current == nil then
        ngx_header["Server-Timing"] = value
    elseif type(current) == "table" then
        current[#current + 1] = value
        ngx_header["Server-Timing"] = current
    else
        ngx_header["Server-Timing"] = { current, value }
    end
end

local filters = require "cdnca_filters"
local new_server_timing, new_last_ms = filters._server_timing, filters._last_ms

local sink
local cases = {
    { "empty loop", function() end },
    { "var cdnca_cache_status (volatile map)", function() sink = ngx_var.cdnca_cache_status end },
    { "var upstream_cache_status (builtin)", function() sink = ngx_var.upstream_cache_status end },
    { "var cdnca_l2_trusted (set)", function() sink = ngx_var.cdnca_l2_trusted end },
    { "var upstream_connect_time", function() sink = ngx_var.upstream_connect_time end },
    { "var upstream_header_time", function() sink = ngx_var.upstream_header_time end },
    { "old last_ms(\"0.001\")", function() sink = old_last_ms("0.001") end },
    { "new last_ms(\"0.001\")", function() sink = new_last_ms("0.001") end },
    { "concat 3 entries", function() sink = table.concat({ "cdn-cache;desc=BYPASS", "cdn-connect;dur=0", "cdn-ttfb;dur=1" }, ", ") end },
    { "header get Server-Timing", function() sink = ngx_header["Server-Timing"] end },
    { "header set+clear Server-Timing", function() ngx_header["Server-Timing"] = "x"; ngx_header["Server-Timing"] = nil end, NH },
    { "add_header+clear Server-Timing", function() ngx_resp.add_header("Server-Timing", "x"); ngx_header["Server-Timing"] = nil end, NH },
    { "header clear only", function() ngx_header["Server-Timing"] = nil end, NH },
    { "old server_timing()+clear", function() old_server_timing(); ngx_header["Server-Timing"] = nil end, NH },
    { "new server_timing()+clear", function() new_server_timing(); ngx_header["Server-Timing"] = nil end, NH },
}

function _M.run(kind)
    local result = {}
    old_server_timing()
    result.old = ngx_header["Server-Timing"]
    ngx_header["Server-Timing"] = nil
    new_server_timing()
    result.new = ngx_header["Server-Timing"]
    ngx_header["Server-Timing"] = nil
    local base
    for _, case in ipairs(cases) do
        local fn, n = case[2], case[3] or N
        if n == N then
            for _ = 1, 1000 do fn() end -- warm the trace
        end
        local started = now()
        for _ = 1, n do fn() end
        local ns = (now() - started) / n
        if not base then
            base = ns
        end
        ngx.log(ngx.NOTICE, string.format("ST %s status=%s %-40s %8.1f ns", kind, tostring(ngx_var.cdnca_cache_status), case[1], ns - base))
    end
    ngx.log(ngx.NOTICE, "ST ", kind, " value old=", tostring(result.old), " new=", tostring(result.new),
        " same=", tostring(result.old == result.new))
end

-- e2e: one call per request like a node's header_filter (traces form across
-- requests); some header work around it stands for the other slots
local modes = { off = false, old = old_server_timing, new = new_server_timing }
function _M.e2e(mode)
    local _ = ngx_var.cdnca_cache_zone, ngx_var.cdnca_cache_prewarm, ngx_var.https, ngx_var.cdnca_site_digest
    ngx_header["X-Bench"] = "1"
    local fn = modes[mode]
    if fn then
        fn()
    end
end

local function keepalive_get(sock, path)
    sock:send("GET " .. path .. " HTTP/1.1\r\nHost: st.test\r\n\r\n")
    local length
    while true do
        local line = assert(sock:receive("*l"))
        if line == "" then
            break
        end
        local value = line:match("^[Cc]ontent%-[Ll]ength:%s*(%d+)")
        if value then
            length = tonumber(value)
        end
    end
    return assert(sock:receive(length))
end

local function e2e_round(mode, requests)
    local sock = ngx.socket.tcp()
    assert(sock:connect("127.0.0.1", 18300))
    keepalive_get(sock, "/e2e/" .. mode)
    local started = now()
    for _ = 1, requests do
        keepalive_get(sock, "/e2e/" .. mode)
    end
    local ns = (now() - started) / requests
    sock:close()
    return ns
end

local function get(path)
    local sock = ngx.socket.tcp()
    assert(sock:connect("127.0.0.1", 18300))
    sock:send("GET " .. path .. " HTTP/1.0\r\nHost: st.test\r\n\r\n")
    local response = sock:receive("*a")
    sock:close()
    return response
end

function _M.driver()
    require("jit.v").on("/tmp/st-jit.log")
    ngx.timer.at(0.2, function()
        local ok, err = pcall(_M.drive)
        if not ok then
            ngx.log(ngx.ERR, "ST FAILED ", err)
        end
        os.exit(ok and 0 or 1)
    end)
end

function _M.drive()
    do
        get("/bypass")
        get("/hit") -- MISS, stored
        get("/hit") -- HIT
        local results = { off = {}, old = {}, new = {} }
        local orders = { { "off", "old", "new" }, { "new", "old", "off" }, { "old", "off", "new" }, { "new", "off", "old" },
            { "off", "new", "old" }, { "old", "new", "off" } }
        for round = 1, #orders do
            for _, mode in ipairs(orders[round]) do
                table.insert(results[mode], e2e_round(mode, 20000))
            end
        end
        for _, mode in ipairs({ "off", "old", "new" }) do
            local list = results[mode]
            table.sort(list)
            ngx.log(ngx.NOTICE, string.format("ST e2e %-3s median %.0f ns/request (min %.0f max %.0f)", mode,
                (list[3] + list[4]) / 2, list[1], list[#list]))
        end
        local file, lines = io.open("/tmp/st-jit.log"), 0
        for line in file:lines() do
            lines = lines + 1
            if line:find("abort", 1, true) or line:find("NYI", 1, true) or line:find("blacklist", 1, true) or line:find("stitch", 1, true) then
                ngx.log(ngx.NOTICE, "ST jit ", line)
            end
        end
        file:close()
        ngx.log(ngx.NOTICE, "ST jit log lines ", lines)
        ngx.log(ngx.NOTICE, "ST DONE")
    end
end

return _M
