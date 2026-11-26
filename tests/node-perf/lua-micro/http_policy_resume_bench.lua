-- HTTP 策略在 ngx.exec 后的内部那一趟恢复响应头状态
-- 给每个缓存/跟随/不缓冲请求增加的开销：cdnca_dynroute.access 的 elseif 分支调用
-- cdnca_security.resume → httppolicy.resume_object（worker 缓存命中）。
-- 无策略站点 / 有策略站点，每次的纳秒数（减去只清 ngx.ctx 的空循环）。
--   tests/node-perf/lua-micro/run.sh tests/node-perf/lua-micro/http_policy_resume_bench.lua
local ngx = ngx
local N = tonumber(os.getenv("NP_ITERS")) or 1000000
local cjson = require "cjson.safe"
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local httppolicy = require "httppolicy.engine"

local site_id = "0a1b2009-0000-4000-8000-000000000101"
local raw = cjson.encode({
    site_id = site_id, max_upload_bytes = 104857600, request_headers = {},
    response_headers = { { kind = "set", name = "x-edge", values = { "yes" } } },
    rewrites = {}, redirect_allowed_hosts = {}, redirects = {},
})
local hash = resty_sha256:new(); hash:update(raw)
local digest = str.to_hex(hash:final())
local function read(value) if value == digest then return raw end return nil, "missing" end

local with_policy = { site_id = site_id, http_policy = { sha256 = digest, revision = 3 } }
local without_policy = { site_id = site_id }
-- the same shape as cdnca_security.resume
local function resume(site)
    local policy = site.http_policy
    if type(policy) == "table" then
        return httppolicy.resume_object(policy, read, site.site_id)
    end
end

local ctx = ngx.ctx
local function t(name, site)
    local f = function() ctx.cdnca_http_policy_site = nil; resume(site) end
    local empty = function() ctx.cdnca_http_policy_site = nil; return site end
    for _ = 1, 20000 do f(); empty() end
    local c = os.clock(); for _ = 1, N do empty() end
    local base = os.clock() - c
    c = os.clock(); for _ = 1, N do f() end
    print(string.format("[bench] %-24s %7.1f ns/请求", name, (os.clock() - c - base) / N * 1e9))
end

t("无 HTTP 策略站点", without_policy)
t("有 HTTP 策略站点", with_policy)
ctx.cdnca_http_policy_site = nil
resume(with_policy)
print(string.format("[bench] restored=%s (须为 true)", tostring(ctx.cdnca_http_policy_site ~= nil)))
