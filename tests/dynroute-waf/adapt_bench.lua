-- RI-03 per request cost of the c3 context's adaptive parts (shape typing,
-- browser class, t= fit), resty CLI in the node runtime image:
--   resty -I <dynroute dir> -I <lua dir> adapt_bench.lua
-- The request API is stubbed (no ngx.req in the CLI timer context); what is
-- measured is the Lua the context adds over c2 for a site with 32 typed
-- parameters, 8 query arguments and a cookie.
local crc = ngx.crc32_long
local typed = {}
for index = 1, 32 do
    local key = string.format("%08x%08x", crc("/item/{n}"), crc("args:p" .. index))
    typed[crc("args:p" .. index)] = { [crc("/item/{n}")] = { key = key, type = index % 2 == 0 and "number" or "ident",
        max_len_bucket = 5, charset = 0 } }
end
local state = { typed = typed, targets = {} }
for index = 1, 32 do
    state.targets[index] = { text = string.format("94%04d:a:param_%02d", index, index), since = 0, ["until"] = 2 ^ 40 }
end
local args = {}
for index = 1, 8 do args["p" .. index] = index % 2 == 0 and tostring(index * 1000) or "value-" .. index end
ngx.var = setmetatable({ uri = "/item/42", http_cookie = "session=abcdef0123456789; p3=xyz", http_accept = "text/html",
    content_type = "" }, { __index = function() return nil end })
ngx.req = { get_uri_args = function() return args end, get_method = function() return "GET" end }
package.loaded.cdnca_managed_waf = nil
local adapt = require("cdnca_managed_waf")._adapt

local function run(n)
    local start = ngx.now()
    for _ = 1, n do
        adapt.shape(state)
        adapt.browser()
        adapt.targets(state, 1)
    end
    ngx.update_time()
    return (ngx.now() - start) / n * 1e6
end
run(2000)
local samples = {}
for round = 1, 21 do
    ngx.update_time()
    samples[round] = run(5000)
end
table.sort(samples)
ngx.log(ngx.WARN, string.format("ADAPT_BENCH us_per_request p50=%.2f p95=%.2f max=%.2f", samples[11], samples[20], samples[21]))
