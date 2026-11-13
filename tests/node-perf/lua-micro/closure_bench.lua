-- run_capture 里 9 个局部闭包每请求创建的开销上限（只建闭包，不调用）。
local N = tonumber(os.getenv("NP_ITERS")) or 1000000
local null, redacted = {}, "[REDACTED]"
local function make(max_value, max_body, capture_methods, capture_uri_prefixes)
    local function capture_matches(method, uri) return #capture_methods + #capture_uri_prefixes + #method + #uri end
    local function sensitive(name) return #name end
    local function cleanse(value, depth, state) return null, max_value, redacted, sensitive, cleanse end
    local function capture_headers(source, source_error, names) return max_value, redacted, sensitive end
    local function is_json_content_type(value) return #value end
    local function header_value(source, name) return source, name end
    local function capture_body(raw, content_type, names) return max_body, null, cleanse, is_json_content_type, sensitive end
    local function timing(raw) return raw end
    return capture_matches, sensitive, cleanse, capture_headers, is_json_content_type, header_value, capture_body, timing
end
local m, b, mm, p = 8192, 65536, {}, {}
for _ = 1, 20000 do make(m, b, mm, p) end
local t0 = os.clock()
for _ = 1, N do make(m, b, mm, p) end
print(string.format("[bench] 8 个闭包创建 %8.0f ns/次", (os.clock() - t0) / N * 1e9))
