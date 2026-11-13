-- cdnca_site.current() 单价 与 请求内缓存(ngx.ctx)后的单价。
-- current() = 读 $cdnca_site_state、读 $cdnca_site_digest、lrucache get、取 entry.site（与 cdnca_site.lua 一致）。
local lrucache = require "resty.lrucache"
local sites = lrucache.new(1024)
local hex = string.rep("ab", 32)
sites:set(hex, { site = { site_id = "x" }, hex = hex })
local ngx_var, ngx_ctx = ngx.var, ngx.ctx
local N = tonumber(os.getenv("NP_ITERS")) or 2000000
local function current()
    if ngx_var.cdnca_site_state ~= "ok" then return nil end
    local entry = sites:get(ngx_var.cdnca_site_digest)
    return entry and entry.site
end
local function current_cached()
    local ctx = ngx.ctx
    local s = ctx.cdnca_site_cur
    if s ~= nil then return s or nil end
    s = current() or false
    ctx.cdnca_site_cur = s
    return s or nil
end
local function bench(name, fn)
    for _ = 1, 50000 do fn() end
    local t0 = os.clock()
    for _ = 1, N do fn() end
    print(string.format("[bench] %-34s %6.0f ns/次", name, (os.clock() - t0) / N * 1e9))
end
bench("current()（现状）", current)
bench("current_cached()（命中 ngx.ctx）", current_cached)
bench("仅 ngx.ctx.x 读", function() return ngx.ctx.cdnca_site_cur end)
