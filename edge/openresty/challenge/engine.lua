local bit = require("bit")
local cjson = require("cjson.safe")
local crypto = require("crypto")
local ffi = require("ffi")
local ip = require("ip")

-- Every site (v7) or policy (dynamic routing) loads its own engine instance
-- into one LuaJIT state; a second cdef of these structs would fail.
if not pcall(ffi.typeof, "struct cdnca_challenge_statx") then ffi.cdef([[
int open(const char *pathname, int flags, ...);
long read(int fd, void *buf, unsigned long count);
int close(int fd);
int statx(int dirfd, const char *pathname, int flags, unsigned int mask, void *statxbuf);
struct cdnca_challenge_statx_timestamp {
    long long tv_sec;
    unsigned int tv_nsec;
    int reserved;
};
struct cdnca_challenge_statx {
    unsigned int stx_mask;
    unsigned int stx_blksize;
    unsigned long long stx_attributes;
    unsigned int stx_nlink;
    unsigned int stx_uid;
    unsigned int stx_gid;
    unsigned short stx_mode;
    unsigned short spare0;
    unsigned long long stx_ino;
    unsigned long long stx_size;
    unsigned long long stx_blocks;
    unsigned long long stx_attributes_mask;
    struct cdnca_challenge_statx_timestamp stx_atime;
    struct cdnca_challenge_statx_timestamp stx_btime;
    struct cdnca_challenge_statx_timestamp stx_ctime;
    struct cdnca_challenge_statx_timestamp stx_mtime;
    unsigned int stx_rdev_major;
    unsigned int stx_rdev_minor;
    unsigned int stx_dev_major;
    unsigned int stx_dev_minor;
    unsigned long long spare2[14];
};
]]) end

local _M = {}

local SCHEMA_VERSION = "cdnca.edge.challenge/v1"
local ALGORITHM = "hmac-sha256"
local VERIFY_ENDPOINT = "/.cdnca/challenge/verify"
local MAX_POLICY_BYTES = 1024 * 1024
local MAX_POLICY_VERSION = 9007199254740991
local MAX_RULES = 64
local MAX_IDENTIFIER_BYTES = 128
local MAX_HOST_BYTES = 253
local MAX_COOKIE_NAME_BYTES = 64
local MAX_PROXY_CIDRS = 64
local MAX_BYPASS_ROUTES = 32
local MAX_BYPASS_PATH_BYTES = 512
local MIN_KEY_BYTES = 32
local MAX_KEY_BYTES = 128
local MAX_KEY_PATH_BYTES = 4096
local MAX_DELAY_SECONDS = 10
local MAX_CHALLENGE_TTL_SECONDS = 300
local MAX_PASS_TTL_SECONDS = 3600
local MAX_CLOCK_SKEW_SECONDS = 30
local MAX_FAILURE_WINDOW_SECONDS = 3600
local MAX_FAILURES = 20
local MAX_TARGET_BYTES = 4096
local MAX_QUERY_BYTES = 2048
local MAX_USER_AGENT_BYTES = 512
local MAX_COOKIE_HEADER_BYTES = 4096
local MAX_COOKIE_VALUE_BYTES = 1024
local MAX_FORM_BYTES = 6144
local MAX_RESPONSE_BYTES = 256
local MAX_EXTERNAL_PROOF_BYTES = 4096
local MIN_INTERACTION_SECONDS = 0.2
local DUMMY_KEY = string.rep("\165", 32)
local O_RDONLY = 0
local O_CLOEXEC = 0x80000
local O_NOFOLLOW = 0x20000
local AT_FDCWD = -100
local AT_EMPTY_PATH = 0x1000
local AT_SYMLINK_NOFOLLOW = 0x100
local STATX_BASIC_STATS = 0x7ff
local MODE_TYPE_MASK = 0xf000
local MODE_REGULAR = 0x8000
local MODE_DIRECTORY = 0x4000
local MODE_PERMISSIONS = 0x1ff

local current_policy
local current_digest
local policy_path
local state_dict_name
local reload_interval = 1
local next_reload_at = 0
local policy_state = "unavailable"
local policy_fallback_reason = "-"

local function record_decision(decision, reason, status, policy, rule)
    if ngx.ctx.cdnca_challenge_decision ~= nil then
        error("challenge decision already recorded")
    end
    if (decision ~= "allow" and decision ~= "challenge" and decision ~= "block" and decision ~= "error")
        or type(reason) ~= "string" or #reason < 1 or #reason > 64
        or reason:match("^[a-z][a-z0-9_]*$") == nil
        or (status ~= 0 and status ~= ngx.HTTP_OK and status ~= 303 and status ~= ngx.HTTP_FORBIDDEN
            and status ~= ngx.HTTP_NOT_ALLOWED and status ~= ngx.HTTP_TOO_MANY_REQUESTS
            and status ~= ngx.HTTP_SERVICE_UNAVAILABLE) then
        error("invalid challenge decision")
    end
    local audit_state = policy and policy_state or "unavailable"
    ngx.ctx.cdnca_challenge_decision = {
        decision = decision,
        reason = reason,
        status = status,
        policy_version = policy and policy.policy_version or 0,
        rule_id = rule and rule.rule_id or "-",
        policy_state = audit_state,
        fallback_reason = audit_state == "lkg" and policy_fallback_reason or "-",
    }
end

local function integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum
end

local function identifier(value, maximum)
    return type(value) == "string" and #value >= 1 and #value <= maximum
        and value:match("^[A-Za-z0-9._:-]+$") ~= nil
end

local function bounded_string(value, maximum)
    return type(value) == "string" and #value >= 1 and #value <= maximum and value:find("[%c]") == nil
end

local function has_only(value, allowed)
    if type(value) ~= "table" then
        return false
    end
    for key in pairs(value) do
        if not allowed[key] then
            return false
        end
    end
    return true
end

local function array_length(value, maximum)
    if type(value) ~= "table" then
        return nil
    end
    local length = #value
    if length > maximum then
        return nil
    end
    for key in pairs(value) do
        if type(key) ~= "number" or key < 1 or key > length or key ~= math.floor(key) then
            return nil
        end
    end
    return length
end

local cidr_fields = { family = true, network = true, prefix_length = true }

local function validate_cidr(cidr)
    if not has_only(cidr, cidr_fields) or (cidr.family ~= 4 and cidr.family ~= 6) then
        return false
    end
    local byte_count = cidr.family == 4 and 4 or 16
    if array_length(cidr.network, byte_count) ~= byte_count then
        return false
    end
    for _, value in ipairs(cidr.network) do
        if not integer(value, 0, 255) then
            return false
        end
    end
    if not integer(cidr.prefix_length, 0, cidr.family == 4 and 32 or 128) then
        return false
    end
    local full_bytes = math.floor(cidr.prefix_length / 8)
    local remaining = cidr.prefix_length % 8
    if remaining > 0
        and bit.band(cidr.network[full_bytes + 1], bit.lshift(1, 8 - remaining) - 1) ~= 0 then
        return false
    end
    local first_host_byte = full_bytes + (remaining > 0 and 2 or 1)
    for index = first_host_byte, #cidr.network do
        if cidr.network[index] ~= 0 then
            return false
        end
    end
    return true
end

local function validate_cidrs(value)
    local length = array_length(value, MAX_PROXY_CIDRS)
    if not length then
        return false
    end
    local seen = {}
    for index = 1, length do
        local cidr = value[index]
        if not validate_cidr(cidr) then
            return false
        end
        local key = cidr.family .. ":" .. cidr.prefix_length .. ":" .. table.concat(cidr.network, ".")
        if seen[key] then
            return false
        end
        seen[key] = true
    end
    return true
end

local key_fields = { key_id = true, key_file = true, key_sha256 = true }

local function validate_key(value)
    if not has_only(value, key_fields) or not identifier(value.key_id, 64)
        or not bounded_string(value.key_file, MAX_KEY_PATH_BYTES) or value.key_file:sub(1, 1) ~= "/"
        or value.key_file:find("//", 1, true) ~= nil
        or type(value.key_sha256) ~= "string" or #value.key_sha256 ~= 64
        or value.key_sha256:match("^[0-9a-f]+$") == nil then
        return false
    end
    for segment in value.key_file:gmatch("[^/]+") do
        if segment == "." or segment == ".." then
            return false
        end
    end
    return true
end

local rule_fields = {
    rule_id = true, priority = true, tenant_id = true, site_id = true, host = true, mode = true,
    min_delay_seconds = true, challenge_ttl_seconds = true, pass_ttl_seconds = true,
    clock_skew_seconds = true, attempts_per_nonce = true, failure_window_seconds = true,
	max_failures_per_window = true, ip_binding = true, bind_user_agent = true,
	external_provider = true,
}

local external_provider_fields = { provider = true, app_id = true }

local bypass_fields = { kind = true, path = true }

local function validate_bypass_route(value)
    if not has_only(value, bypass_fields) or (value.kind ~= "exact" and value.kind ~= "prefix")
        or not bounded_string(value.path, MAX_BYPASS_PATH_BYTES) or value.path:sub(1, 1) ~= "/"
        or value.path:sub(1, 2) == "//" or value.path:find("[\\?#%%]")
        or value.path:find("//", 1, true) or value.path:find("/./", 1, true)
        or value.path:find("/../", 1, true) or value.path:sub(-2) == "/."
        or value.path:sub(-3) == "/.." then
        return false
    end
    if value.kind == "prefix" and (value.path == "/" or value.path:sub(-1) ~= "/") then
        return false
    end
    return true
end

local function validate_bypass_routes(value)
    local length = array_length(value, MAX_BYPASS_ROUTES)
    if not length then
        return false
    end
    local seen = {}
    local previous
    for index = 1, length do
        local route = value[index]
        if not validate_bypass_route(route) or seen[route.path]
            or (previous and (route.path < previous.path
                or (route.path == previous.path and route.kind <= previous.kind))) then
            return false
        end
        seen[route.path] = true
        previous = route
    end
    return true
end

local function valid_host(value)
    if not bounded_string(value, MAX_HOST_BYTES) or value ~= string.lower(value)
        or value:find("[:/\\%%]") or value:match("^[a-z0-9.-]+$") == nil
        or value:sub(1, 1) == "." or value:sub(-1) == "." or value:find("..", 1, true) then
        return false
    end
    for label in value:gmatch("[^.]+") do
        if #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" then
            return false
        end
    end
    return true
end

local function validate_rule(value)
    if not has_only(value, rule_fields) or not identifier(value.rule_id, MAX_IDENTIFIER_BYTES)
        or not integer(value.priority, 0, 4294967295) or not identifier(value.tenant_id, MAX_IDENTIFIER_BYTES)
        or not identifier(value.site_id, MAX_IDENTIFIER_BYTES) or not valid_host(value.host)
		or (value.mode ~= "delay" and value.mode ~= "click"
			and value.mode ~= "slider" and value.mode ~= "captcha" and value.mode ~= "external") then
		return false
	end
	if value.mode == "external" then
		if not has_only(value.external_provider, external_provider_fields)
			or (value.external_provider.provider ~= "tencent" and value.external_provider.provider ~= "geetest-v4")
			or not identifier(value.external_provider.app_id, MAX_IDENTIFIER_BYTES) then
			return false
		end
	elseif value.external_provider ~= nil then
		return false
	end
    if value.mode == "delay" then
        if not integer(value.min_delay_seconds, 5, MAX_DELAY_SECONDS) then
            return false
        end
    elseif value.min_delay_seconds ~= 0 then
        return false
    end
    if not integer(value.clock_skew_seconds, 0, MAX_CLOCK_SKEW_SECONDS)
        or not integer(value.challenge_ttl_seconds, 10, MAX_CHALLENGE_TTL_SECONDS)
        or value.challenge_ttl_seconds <= value.min_delay_seconds + value.clock_skew_seconds then
        return false
    end
    return integer(value.pass_ttl_seconds, 1, MAX_PASS_TTL_SECONDS)
        and value.attempts_per_nonce == 1
        and integer(value.failure_window_seconds, 1, MAX_FAILURE_WINDOW_SECONDS)
        and integer(value.max_failures_per_window, 1, MAX_FAILURES)
        and (value.ip_binding == "none" or value.ip_binding == "exact")
        and type(value.bind_user_agent) == "boolean"
end

local policy_fields = {
    schema_version = true, policy_version = true, algorithm = true, cookie_name = true,
    trusted_proxies = true, bypass_routes = true, current_key = true, previous_key = true, rules = true,
}

local function validate_cookie_name(value)
    return type(value) == "string" and #value > #"__Host-" and #value <= MAX_COOKIE_NAME_BYTES
        and value:sub(1, #"__Host-") == "__Host-" and value:find("[%c%s()<>@,;:\\/%[%]?={}]") == nil
end

local function validate_policy(value)
    if not has_only(value, policy_fields) or value.schema_version ~= SCHEMA_VERSION
        or not integer(value.policy_version, 1, MAX_POLICY_VERSION) or value.algorithm ~= ALGORITHM
        or not validate_cookie_name(value.cookie_name) or not validate_cidrs(value.trusted_proxies)
        or not validate_bypass_routes(value.bypass_routes)
        or not validate_key(value.current_key) or (value.previous_key ~= nil and not validate_key(value.previous_key)) then
        return nil, "policy_envelope_invalid"
    end
    if value.previous_key and (value.previous_key.key_id == value.current_key.key_id
        or value.previous_key.key_file == value.current_key.key_file
        or value.previous_key.key_sha256 == value.current_key.key_sha256) then
        return nil, "key_rotation_invalid"
    end
    local length = array_length(value.rules, MAX_RULES)
    if not length or length == 0 then
        return nil, "rules_invalid"
    end
    local ids = {}
    local scopes = {}
    local previous
    for index = 1, length do
        local rule = value.rules[index]
        if not validate_rule(rule) then
            return nil, "rule_invalid"
        end
        local scope = rule.tenant_id .. "\0" .. rule.site_id .. "\0" .. rule.host
        if ids[rule.rule_id] or scopes[scope] then
            return nil, "rule_duplicate"
        end
        if previous and (rule.priority < previous.priority
            or (rule.priority == previous.priority and rule.rule_id <= previous.rule_id)) then
            return nil, "rule_order_invalid"
        end
        ids[rule.rule_id] = true
        scopes[scope] = true
        previous = rule
    end
    return value
end

local function secure_read_key(path)
    local parent = path:match("^(.*)/[^/]+$")
    if not parent or parent == "" then
        parent = "/"
    end
    local parent_info = ffi.new("struct cdnca_challenge_statx[1]")
    local parent_valid = ffi.C.statx(
        AT_FDCWD, parent, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, parent_info
    ) == 0
        and bit.band(tonumber(parent_info[0].stx_mode), MODE_TYPE_MASK) == MODE_DIRECTORY
        and bit.band(tonumber(parent_info[0].stx_mode), MODE_PERMISSIONS) == 448
    if not parent_valid then
        return nil, "key_parent_metadata_invalid"
    end
    local fd = ffi.C.open(path, bit.bor(O_RDONLY, O_CLOEXEC, O_NOFOLLOW))
    if fd < 0 then
        return nil, "key_open_failed"
    end
    local info = ffi.new("struct cdnca_challenge_statx[1]")
    if ffi.C.statx(fd, "", bit.bor(AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW), STATX_BASIC_STATS, info) ~= 0
        or bit.band(tonumber(info[0].stx_mode), MODE_TYPE_MASK) ~= MODE_REGULAR
        or bit.band(tonumber(info[0].stx_mode), MODE_PERMISSIONS) ~= 384
        or tonumber(info[0].stx_nlink) ~= 1
        or tonumber(info[0].stx_size) < MIN_KEY_BYTES
        or tonumber(info[0].stx_size) > MAX_KEY_BYTES then
        ffi.C.close(fd)
        return nil, "key_metadata_invalid"
    end
    local buffer = ffi.new("unsigned char[?]", MAX_KEY_BYTES + 1)
    local chunks = {}
    local length = 0
    while length <= MAX_KEY_BYTES do
        local read_length = ffi.C.read(fd, buffer, MAX_KEY_BYTES + 1 - length)
        if read_length < 0 then
            ffi.C.close(fd)
            return nil, "key_read_failed"
        end
        if read_length == 0 then
            break
        end
        chunks[#chunks + 1] = ffi.string(buffer, read_length)
        length = length + read_length
    end
    ffi.C.close(fd)
    if length ~= tonumber(info[0].stx_size) or length < MIN_KEY_BYTES or length > MAX_KEY_BYTES then
        return nil, "key_read_failed"
    end
    return table.concat(chunks)
end

local function read_key(key)
    local secret, read_error = secure_read_key(key.key_file)
    if not secret then
        return nil, read_error
    end
    local digest = crypto.sha256_hex(secret)
    if not digest or not crypto.constant_time_equal(digest, key.key_sha256) then
        return nil, "key_digest_invalid"
    end
    return secret
end

local function read_candidate()
    local file = io.open(policy_path, "rb")
    if not file then
        return nil, "policy_open_failed"
    end
    local raw = file:read(MAX_POLICY_BYTES + 1)
    file:close()
    if not raw or #raw == 0 or #raw > MAX_POLICY_BYTES then
        return nil, "policy_size_invalid"
    end
    local decoded = cjson.decode(raw)
    if not decoded then
        return nil, "policy_decode_invalid"
    end
    local candidate, validation_error = validate_policy(decoded)
    if not candidate then
        return nil, validation_error
    end
    local current_secret, current_error = read_key(candidate.current_key)
    if not current_secret then
        return nil, current_error
    end
    candidate.current_key.secret = current_secret
    candidate.key_by_id = { [candidate.current_key.key_id] = candidate.current_key }
    if candidate.previous_key then
        local previous_secret, previous_error = read_key(candidate.previous_key)
        if not previous_secret then
            return nil, previous_error
        end
        candidate.previous_key.secret = previous_secret
        candidate.key_by_id[candidate.previous_key.key_id] = candidate.previous_key
    end
    return candidate, nil, crypto.sha256_hex(raw)
end

local function reload(force)
    local now = ngx.now()
    if not force and now < next_reload_at then
        return true
    end
    next_reload_at = now + reload_interval
    local candidate, candidate_error, candidate_digest = read_candidate()
    if not candidate then
        ngx.log(ngx.ERR, "challenge policy reload rejected; retaining LKG code=", candidate_error)
        if current_policy then
            policy_state = "lkg"
            policy_fallback_reason = candidate_error
        else
            policy_state = "unavailable"
            policy_fallback_reason = "-"
        end
        return false, candidate_error
    end
    if current_policy and candidate.policy_version < current_policy.policy_version then
        ngx.log(ngx.ERR, "challenge policy reload rejected; retaining newer LKG")
        policy_state = "lkg"
        policy_fallback_reason = "policy_version_older"
        return false, "policy_version_older"
    end
    if current_policy and candidate.policy_version == current_policy.policy_version and candidate_digest ~= current_digest then
        ngx.log(ngx.ERR, "challenge policy reload rejected; retaining same-version LKG")
        policy_state = "lkg"
        policy_fallback_reason = "policy_same_version_changed"
        return false, "policy_same_version_changed"
    end
    if not current_policy or candidate.policy_version > current_policy.policy_version then
        current_policy = candidate
        current_digest = candidate_digest
        ngx.log(ngx.NOTICE, "challenge policy activated version=", candidate.policy_version)
    end
    policy_state = "active"
    policy_fallback_reason = "-"
    return true
end

local function response_headers(csp_nonce, scripted, external_provider)
	local script_source = scripted and "'nonce-" .. csp_nonce .. "'" or "'none'"
	local connect_source = "'none'"
	if external_provider == "tencent" then
		script_source = script_source .. " https://turing.captcha.qcloud.com"
		connect_source = "https://*.captcha.qq.com https://turing.captcha.qcloud.com"
	elseif external_provider == "geetest-v4" then
		script_source = script_source .. " https://static.geetest.com"
		connect_source = "https://*.geetest.com"
	end
	ngx.header["Content-Security-Policy"] = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
		.. "form-action 'self'; style-src 'nonce-" .. csp_nonce .. "'; script-src " .. script_source
		.. "; connect-src " .. connect_source
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["Expires"] = "0"
    ngx.header["Referrer-Policy"] = "no-referrer"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["X-Frame-Options"] = "DENY"
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
end

local function page_style(nonce)
    return [[<style nonce="]] .. nonce .. [[">
*{box-sizing:border-box}html,body{min-height:100%;margin:0}body{display:grid;place-items:center;padding:24px;background:#f4f6f8;color:#17202a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;letter-spacing:0}main{width:min(100%,560px);padding:34px 0;border-top:4px solid #c7352c}h1{margin:0 0 14px;font-size:28px;line-height:1.3;font-weight:650}p{margin:0 0 18px;font-size:16px;line-height:1.75;color:#475467}.status{display:flex;align-items:center;gap:10px;margin:24px 0;color:#17202a;font-weight:600}.mark{width:14px;height:14px;background:#16865c;border-radius:50%;flex:0 0 auto}form{display:grid;gap:16px}label{display:grid;gap:8px;font-weight:600}input[type=text]{width:100%;min-height:48px;padding:0 12px;border:1px solid #98a2b3;border-radius:4px;background:#fff;color:#17202a;font:inherit;font-size:18px;text-transform:uppercase}input[type=range]{width:100%;min-height:44px;accent-color:#16865c}.captcha{display:inline-flex;align-items:center;justify-content:center;min-height:58px;padding:8px 18px;border:1px solid #98a2b3;background:#fff;font:700 24px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:0}output{font-variant-numeric:tabular-nums}button,.link{display:inline-flex;align-items:center;justify-content:center;min-height:48px;padding:0 22px;border:0;border-radius:4px;background:#17202a;color:#fff;font:inherit;font-weight:650;text-decoration:none;cursor:pointer}button:hover,.link:hover{background:#294052}button:focus-visible,.link:focus-visible,input:focus-visible{outline:3px solid #f2b84b;outline-offset:3px}button:disabled{background:#98a2b3;cursor:wait}.detail{font-size:14px;color:#667085}.error{padding:12px 14px;border-left:3px solid #c7352c;background:#fff1f0;color:#8a1c16}@media(max-width:480px){body{padding:20px}main{padding-top:26px}h1{font-size:24px}p{font-size:15px}button,.link{width:100%}}
</style>]]
end

local function render_error(status, title, message, retry_after, policy, rule, reason)
    local nonce = crypto.random_token(18)
    if not nonce then
        record_decision("error", "response_nonce_unavailable", ngx.HTTP_SERVICE_UNAVAILABLE, policy, rule)
        return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    record_decision(status == ngx.HTTP_SERVICE_UNAVAILABLE and "error" or "block", reason, status, policy, rule)
    response_headers(nonce, false)
    if retry_after then
        ngx.header["Retry-After"] = tostring(retry_after)
    end
    ngx.status = status
    ngx.print("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>", title, "</title>", page_style(nonce), "</head><body><main><h1>", title, "</h1><p class=\"error\">", message, "</p><a class=\"link\" href=\"/\">重新访问</a></main></body></html>")
    return ngx.exit(status)
end

local function safe_target()
    local path = ngx.var.uri
    if type(path) ~= "string" or #path == 0 or #path > MAX_TARGET_BYTES or path:sub(1, 1) ~= "/"
        or path:sub(1, 2) == "//" or path == VERIFY_ENDPOINT or path:find("[%c\\]") then
        return nil
    end
    local query = ngx.var.args
    if query == nil or query == "" then
        return path
    end
    if #path + #query + 1 > MAX_TARGET_BYTES or #query > MAX_QUERY_BYTES or query:find("[%c#]") then
        return nil
    end
    local index = 1
    while index <= #query do
        if query:sub(index, index) == "%" then
            local encoded = query:sub(index + 1, index + 2)
            if #encoded ~= 2 or not encoded:match("^[0-9A-Fa-f][0-9A-Fa-f]$") then
                return nil
            end
            local byte = tonumber(encoded, 16)
            if byte < 0x20 or byte == 0x7f then
                return nil
            end
            index = index + 3
        else
            index = index + 1
        end
    end
    return path .. "?" .. query
end

local function bypass_route(policy, request_path)
    for _, route in ipairs(policy.bypass_routes) do
        if route.kind == "exact" and request_path == route.path
            or route.kind == "prefix" and request_path:sub(1, #route.path) == route.path then
            return true
        end
    end
    return false
end

local function browser_document_request()
    if ngx.req.get_method() ~= "GET" then
        return false, "method"
    end
    if ngx.var.http_upgrade and ngx.var.http_upgrade ~= "" then
        return false, "upgrade"
    end
    if ngx.var.http_authorization and ngx.var.http_authorization ~= "" then
        return false, "authorization"
    end
    local content_type = string.lower(ngx.var.http_content_type or "")
    if content_type:find("application/json", 1, true) or content_type:find("application/grpc", 1, true)
        or content_type:find("application/protobuf", 1, true) then
        return false, "content_type"
    end
    local destination = string.lower(ngx.var.http_sec_fetch_dest or "")
    if destination ~= "" then
        if destination == "document" or destination == "iframe" then
            return true
        end
        return false, "fetch_destination"
    end
    local accept = string.lower(ngx.var.http_accept or "")
    if #accept > 2048 then
        return true
    end
    if accept:find("text/event-stream", 1, true) then
        return false, "event_stream"
    end
    if accept:find("application/json", 1, true) or accept:find("application/grpc", 1, true)
        or accept:find("application/protobuf", 1, true) then
        return false, "machine_accept"
    end
    if accept:find("text/html", 1, true) or accept:find("application/xhtml+xml", 1, true) then
        return true
    end
    return false, "non_document_accept"
end

-- nginx already routed the request to this site by server_name (every
-- domain, alias and wildcard of the site; other hosts hit the 421 default
-- server), and each site runs its own engine instance. A rule naming the
-- request host wins; otherwise the site's only rule covers every host the
-- site serves (a wildcard site's policy names one host under the wildcard,
-- a multi-domain site's names the primary domain). Several rules for the
-- site and none for this host stay unavailable instead of guessing.
local function find_rule(policy, context, host)
    local site_rule
    local site_rules = 0
    for _, rule in ipairs(policy.rules) do
        if rule.tenant_id == context.tenant_id and rule.site_id == context.site_id then
            if rule.host == host then
                return rule
            end
            site_rule = rule
            site_rules = site_rules + 1
        end
    end
    if site_rules == 1 then
        return site_rule
    end
    return nil
end

local function binding(rule, address, user_agent)
    local ip_digest = rule.ip_binding == "exact" and crypto.sha256_hex(address.canonical) or "-"
    local ua_digest = rule.bind_user_agent and crypto.sha256_hex(user_agent) or "-"
    return ip_digest, ua_digest
end

local function scope_digest(rule)
    return crypto.sha256_hex(table.concat({
        rule.tenant_id, rule.site_id, rule.host, rule.mode,
    }, "\0"))
end

local function failure_key(policy, rule, address)
    return "challenge:v" .. policy.policy_version .. ":t:" .. rule.tenant_id .. ":s:" .. rule.site_id
        .. ":h:" .. rule.host .. ":m:" .. rule.mode .. ":r:" .. rule.rule_id
        .. ":fail:" .. crypto.sha256_hex(address.canonical)
end

local function record_failure(policy, rule, address)
    local dict = ngx.shared[state_dict_name]
    local count, increment_error, forcible = dict:incr(failure_key(policy, rule, address), 1, 0, rule.failure_window_seconds)
    if not count or increment_error or forcible then
        return nil
    end
    return count
end

local function reject_attempt(policy, rule, address, code)
    ngx.log(ngx.WARN, "challenge verification rejected code=", code, " rule_id=", rule.rule_id)
    local failures = record_failure(policy, rule, address)
    if not failures then
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "验证状态容量不足，请稍后重试。", 1,
            policy, rule, "failure_state_unavailable")
    end
    if failures >= rule.max_failures_per_window then
        return render_error(ngx.HTTP_TOO_MANY_REQUESTS, "尝试次数过多", "验证失败次数已达到上限，请稍后重试。",
            rule.failure_window_seconds, policy, rule, "failure_threshold")
    end
    return render_error(ngx.HTTP_FORBIDDEN, "验证未通过", "本次验证已失效，请重新访问原页面后再试。", nil,
        policy, rule, code)
end

local function pending_key(policy, rule, nonce_digest)
    return "challenge:v" .. policy.policy_version .. ":t:" .. rule.tenant_id .. ":s:" .. rule.site_id
        .. ":h:" .. rule.host .. ":m:" .. rule.mode .. ":r:" .. rule.rule_id .. ":pending:" .. nonce_digest
end

local function consumed_key(policy, rule, nonce_digest)
    return "challenge:v" .. policy.policy_version .. ":t:" .. rule.tenant_id .. ":s:" .. rule.site_id
        .. ":h:" .. rule.host .. ":m:" .. rule.mode .. ":r:" .. rule.rule_id .. ":used:" .. nonce_digest
end

local function response_material(mode)
	if mode == "delay" or mode == "external" then
		return mode, nil
    end
    local random = crypto.random_token(18)
    if not random then
        return nil
    end
    if mode == "click" then
        return random, random
    end
    local digest = crypto.sha256_hex(random)
    if mode == "slider" then
        local target = tostring(70 + (tonumber(digest:sub(1, 2), 16) % 26))
        return target, target
    end
    local code = string.upper(digest:sub(1, 6))
    return code, code
end

local function issue_pending(policy, rule, address, user_agent, target)
    local dict = ngx.shared[state_dict_name]
    local ip_digest, ua_digest = binding(rule, address, user_agent)
    local now = ngx.now()
    for _ = 1, 3 do
        local nonce = crypto.random_token(24)
        local response, presentation = response_material(rule.mode)
        if not nonce or not response then
            return nil, "random_unavailable"
        end
        local nonce_digest = crypto.sha256_hex(nonce)
        local state = cjson.encode({
            policy_version = policy.policy_version, rule_id = rule.rule_id, mode = rule.mode,
            issued_at = now, expires_at = now + rule.challenge_ttl_seconds, target = target,
            not_before = now + (rule.mode == "delay" and rule.min_delay_seconds or MIN_INTERACTION_SECONDS),
            response_digest = crypto.sha256_hex(response), ip_digest = ip_digest, ua_digest = ua_digest,
        })
        if not state then
            return nil, "state_encode_failed"
        end
        local added, add_error, forcible = dict:add(pending_key(policy, rule, nonce_digest), state, rule.challenge_ttl_seconds)
        if added and not forcible then
            return nonce, presentation
        end
        if added then
            dict:delete(pending_key(policy, rule, nonce_digest))
        end
        if add_error ~= "exists" then
            return nil, "state_capacity_unavailable"
        end
    end
    return nil, "nonce_collision"
end

local function render_challenge(policy, rule, nonce, presentation, reason)
    local csp_nonce = crypto.random_token(18)
    if not csp_nonce then
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "无法建立安全验证，请稍后重试。", 1,
            policy, rule, "response_nonce_unavailable")
    end
    record_decision("challenge", reason, ngx.HTTP_OK, policy, rule)
	local delay = rule.mode == "delay"
	local slider = rule.mode == "slider"
	local external = rule.mode == "external"
	response_headers(csp_nonce, delay or slider or external,
		external and rule.external_provider.provider or nil)
    ngx.status = ngx.HTTP_OK
	local titles = { delay = "正在进行五秒安全检查", click = "请确认您正在访问此网站", slider = "请完成滑动验证", captcha = "请输入文本验证码", external = "请完成安全验证" }
	local messages = { delay = "浏览器将在等待期结束后自动提交一次性证明。", click = "点击下方按钮提交一次性确认。", slider = "将滑块移动到标记的目标位置，键盘方向键同样可用。", captcha = "输入下方显示的六位文本，不区分大小写。", external = "验证结果将由受控服务端适配器核验，密钥不会发送到浏览器。" }
    local title = titles[rule.mode]
    ngx.print("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>", title, "</title>", page_style(csp_nonce), "</head><body><main><h1>", title, "</h1><p>", messages[rule.mode], "</p><div class=\"status\" aria-live=\"polite\"><span class=\"mark\" aria-hidden=\"true\"></span><span id=\"status\">等待完成验证</span></div><form id=\"challenge-form\" method=\"post\" action=\"", VERIFY_ENDPOINT, "\"><input type=\"hidden\" name=\"nonce\" value=\"", nonce, "\">")
    if delay then
        ngx.print("<input type=\"hidden\" name=\"response\" value=\"delay\"><button id=\"continue\" type=\"submit\" disabled>等待 ", rule.min_delay_seconds, " 秒</button>")
    elseif rule.mode == "click" then
        ngx.print("<button name=\"response\" value=\"", presentation, "\" type=\"submit\">确认并继续</button>")
    elseif slider then
        ngx.print("<label for=\"slider-response\">目标位置：", presentation, "%<input id=\"slider-response\" name=\"response\" type=\"range\" min=\"0\" max=\"100\" value=\"0\" step=\"1\" aria-describedby=\"slider-value\"></label><output id=\"slider-value\" for=\"slider-response\">当前 0%</output><button id=\"continue\" type=\"submit\" disabled>移动滑块后继续</button>")
	elseif rule.mode == "captcha" then
		ngx.print("<div class=\"captcha\" role=\"img\" aria-label=\"验证码 ", presentation, "\">", presentation, "</div><label for=\"captcha-response\">验证码<input id=\"captcha-response\" name=\"response\" type=\"text\" minlength=\"6\" maxlength=\"6\" pattern=\"[0-9A-Fa-f]{6}\" inputmode=\"text\" autocomplete=\"off\" autocapitalize=\"characters\" required></label><button type=\"submit\">验证并继续</button>")
	else
		ngx.print("<input id=\"external-proof\" name=\"response\" type=\"hidden\"><div id=\"external-widget\"></div><button id=\"external-start\" type=\"button\">开始验证</button><noscript><p class=\"error\">此验证方式需要 JavaScript；请联系站点管理员改用无脚本验证方式。</p></noscript>")
    end
    ngx.print("</form>")
    if delay then
        ngx.print("<noscript><button id=\"manual-continue\" type=\"submit\" form=\"challenge-form\">等待完成后手动继续</button></noscript><script nonce=\"", csp_nonce, "\">(()=>{const seconds=", rule.min_delay_seconds, ";const started=performance.now();const status=document.getElementById('status');const button=document.getElementById('continue');const form=document.getElementById('challenge-form');const tick=()=>{const elapsed=(performance.now()-started)/1000;const left=Math.max(0,Math.ceil(seconds-elapsed));if(left===0){status.textContent='等待完成，正在提交证明';button.disabled=false;button.textContent='继续访问';form.requestSubmit(button);return;}status.textContent=`还需等待 ${left} 秒`;button.textContent=`等待 ${left} 秒`;setTimeout(tick,200)};tick()})();</script>")
	elseif slider then
        ngx.print("<noscript><button id=\"manual-continue\" type=\"submit\" form=\"challenge-form\">移动到目标位置后手动继续</button></noscript><script nonce=\"", csp_nonce, "\">(()=>{const target=", presentation, ";const input=document.getElementById('slider-response');const output=document.getElementById('slider-value');const button=document.getElementById('continue');const status=document.getElementById('status');const update=()=>{const value=Number(input.value);output.textContent=`当前 ${value}%`;const done=value===target;button.disabled=!done;button.textContent=done?'验证并继续':'移动滑块后继续';status.textContent=done?'已到达目标位置':'等待完成验证'};input.addEventListener('input',update);update()})();</script>")
	elseif external and rule.external_provider.provider == "tencent" then
		ngx.print("<script src=\"https://turing.captcha.qcloud.com/TCaptcha.js\"></script><script nonce=\"", csp_nonce, "\">(()=>{const button=document.getElementById('external-start');const status=document.getElementById('status');button.addEventListener('click',()=>{if(typeof TencentCaptcha!=='function'){status.textContent='验证组件不可用';return}button.disabled=true;new TencentCaptcha('", rule.external_provider.app_id, "',result=>{if(!result||result.ret!==0||typeof result.ticket!=='string'||typeof result.randstr!=='string'){status.textContent='验证未通过';button.disabled=false;return}document.getElementById('external-proof').value=JSON.stringify({ticket:result.ticket,randstr:result.randstr});status.textContent='验证完成，正在核验';document.getElementById('challenge-form').requestSubmit()}).show()})})();</script>")
	elseif external then
		ngx.print("<script src=\"https://static.geetest.com/v4/gt4.js\"></script><script nonce=\"", csp_nonce, "\">(()=>{const button=document.getElementById('external-start');const status=document.getElementById('status');button.addEventListener('click',()=>{if(typeof initGeetest4!=='function'){status.textContent='验证组件不可用';return}button.disabled=true;initGeetest4({captchaId:'", rule.external_provider.app_id, "',product:'bind'},captcha=>{captcha.appendTo('#external-widget');captcha.onSuccess(()=>{const result=captcha.getValidate();if(!result){status.textContent='验证未通过';button.disabled=false;return}document.getElementById('external-proof').value=JSON.stringify(result);status.textContent='验证完成，正在核验';document.getElementById('challenge-form').requestSubmit()});captcha.onError(()=>{status.textContent='验证组件不可用';button.disabled=false})})})})();</script>")
	end
    ngx.print("<p class=\"detail\">安全检查不会读取或记录您的请求正文。</p></main></body></html>")
    return ngx.exit(ngx.HTTP_OK)
end

local function cookie_value(policy, rule, address, user_agent)
    local issued = ngx.time()
    local expires = issued + rule.pass_ttl_seconds
    local ip_digest, ua_digest = binding(rule, address, user_agent)
    local payload = table.concat({
        "v1", policy.current_key.key_id, tostring(issued), tostring(expires),
        scope_digest(rule), ip_digest, ua_digest,
    }, "|")
    local encoded = crypto.base64url_encode(payload)
    local signature = crypto.hmac_sha256_hex(policy.current_key.secret, payload)
    if not signature then
        return nil
    end
    return encoded .. "." .. signature, expires
end

local function set_pass_cookie(policy, rule, address, user_agent)
    local value, expires = cookie_value(policy, rule, address, user_agent)
    if not value then
        return false
    end
    ngx.header["Set-Cookie"] = policy.cookie_name .. "=" .. value .. "; Path=/; Max-Age="
        .. rule.pass_ttl_seconds .. "; Expires=" .. ngx.cookie_time(expires) .. "; Secure; HttpOnly; SameSite=Lax"
    return true
end

local function clear_pass_cookie(policy)
    ngx.header["Set-Cookie"] = policy.cookie_name .. "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax"
end

local function request_cookie(name)
    local header = ngx.var.http_cookie
    if not header then
        return nil, "missing"
    end
    if #header > MAX_COOKIE_HEADER_BYTES or header:find("[%c]") then
        return nil, "invalid"
    end
    local found
    for part in (header .. ";"):gmatch("(.-);") do
        local key, value = part:match("^[ ]*([^=; ]+)=([^;]*)[ ]*$")
        if key == name then
            if found or #value == 0 or #value > MAX_COOKIE_VALUE_BYTES then
                return nil, "invalid"
            end
            found = value
        end
    end
    return found, found and nil or "missing"
end

local function split_payload(payload)
    local fields = {}
    for field in (payload .. "|"):gmatch("(.-)|") do
        fields[#fields + 1] = field
    end
    if #fields ~= 7 then
        return nil
    end
    return fields
end

local function valid_pass_cookie(policy, rule, address, user_agent)
    local cookie, cookie_error = request_cookie(policy.cookie_name)
    if not cookie then
        return false, cookie_error
    end
    local encoded, signature = cookie:match("^([A-Za-z0-9_-]+)%.([0-9a-f]+)$")
    if not encoded or #signature ~= 64 then
        return false, "invalid"
    end
    local payload = crypto.base64url_decode(encoded)
    if not payload or #payload > 768 then
        return false, "invalid"
    end
    local fields = split_payload(payload)
    if not fields then
        return false, "invalid"
    end
    local key = policy.key_by_id[fields[2]]
    local expected = crypto.hmac_sha256_hex(key and key.secret or DUMMY_KEY, payload)
    local signature_valid = expected and crypto.constant_time_equal(signature, expected)
    local issued = fields[3]:match("^[1-9][0-9]*$") and tonumber(fields[3]) or nil
    local expires = fields[4]:match("^[1-9][0-9]*$") and tonumber(fields[4]) or nil
    local now = ngx.time()
    local ip_digest, ua_digest = binding(rule, address, user_agent)
    local fields_valid = fields[1] == "v1" and key ~= nil and fields[5] == scope_digest(rule)
        and integer(issued, 1, MAX_POLICY_VERSION) and integer(expires, 1, MAX_POLICY_VERSION)
        and expires - issued == rule.pass_ttl_seconds and issued <= now + rule.clock_skew_seconds and now < expires
        and fields[6] == ip_digest and fields[7] == ua_digest
    return fields_valid and signature_valid, "invalid"
end

local function form_values()
    local content_length = tonumber(ngx.var.http_content_length or "0")
    local content_type = string.lower(ngx.var.http_content_type or "")
    if not content_length or content_length < 1 or content_length > MAX_FORM_BYTES
        or (content_type ~= "application/x-www-form-urlencoded"
            and content_type:match("^application/x%-www%-form%-urlencoded[ ]*;") == nil) then
        return nil
    end
    ngx.req.read_body()
    if not ngx.req.get_body_data() then
        return nil
    end
    local values, parse_error = ngx.req.get_post_args(3)
    if not values or parse_error == "truncated" then
        return nil
    end
    for key, value in pairs(values) do
        if key ~= "nonce" and key ~= "response" or type(value) ~= "string" then
            return nil
        end
    end
    if type(values.nonce) ~= "string" or #values.nonce ~= 32 or values.nonce:find("[^A-Za-z0-9_-]")
		or type(values.response) ~= "string" or #values.response < 1 or #values.response > MAX_EXTERNAL_PROOF_BYTES
        or values.response:find("[%c]") then
        return nil
    end
    return values
end

local function external_verify(policy, rule, address, proof)
	if #proof > MAX_EXTERNAL_PROOF_BYTES then
		return false
	end
	local payload = cjson.encode({
		policy_id = rule.rule_id, policy_version = policy.policy_version,
		tenant_id = rule.tenant_id, site_id = rule.site_id,
		provider = rule.external_provider.provider, app_id = rule.external_provider.app_id,
		proof = proof, client_ip = address.canonical,
	})
	if not payload or #payload > 8192 then
		return false
	end
	local socket = ngx.socket.tcp()
	if not socket then
		return false
	end
	socket:settimeouts(250, 3500, 500)
	local connected = socket:connect("127.0.0.1", 19178)
	if not connected then
		socket:close()
		return false
	end
	local request = "POST /v1/challenge/external/verify HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
		.. #payload .. "\r\n\r\n" .. payload
	local sent = socket:send(request)
	if sent ~= #request then
		socket:close()
		return false
	end
	local status = socket:receive("*l")
	if status ~= "HTTP/1.1 204 No Content" then
		socket:close()
		return false
	end
	for _ = 1, 32 do
		local line = socket:receive("*l")
		if line == "" then
			socket:close()
			return true
		end
		if not line or #line > 4096 or line:find("[%c]") then
			socket:close()
			return false
		end
	end
	socket:close()
	return false
end

local function verify_submission(policy, rule, address, user_agent)
    local values = form_values()
    if not values then
        return reject_attempt(policy, rule, address, "form_invalid")
    end
    local nonce_digest = crypto.sha256_hex(values.nonce)
    local dict = ngx.shared[state_dict_name]
    local pending = dict:get(pending_key(policy, rule, nonce_digest))
    if not pending then
        return reject_attempt(policy, rule, address, "nonce_missing_or_replayed")
    end
    local state = cjson.decode(pending)
    if type(state) ~= "table" then
        dict:delete(pending_key(policy, rule, nonce_digest))
        return reject_attempt(policy, rule, address, "nonce_state_invalid")
    end
    local now = ngx.now()
    local consumed_ttl = math.max(1, math.ceil((tonumber(state.expires_at) or now) - now + 1))
    local consumed, consume_error, forcible = dict:add(consumed_key(policy, rule, nonce_digest), true, consumed_ttl)
    if not consumed then
        if consume_error == "exists" then
            return reject_attempt(policy, rule, address, "nonce_replayed")
        end
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "验证状态容量不足，请稍后重试。", 1,
            policy, rule, "replay_state_unavailable")
    end
    if forcible then
        dict:delete(consumed_key(policy, rule, nonce_digest))
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "验证状态容量不足，请稍后重试。", 1,
            policy, rule, "replay_state_unavailable")
    end
    dict:delete(pending_key(policy, rule, nonce_digest))
    local ip_digest, ua_digest = binding(rule, address, user_agent)
    local response = values.response
    if rule.mode == "captcha" then
        response = string.upper(response:match("^%s*(.-)%s*$"))
    end
	local response_digest = crypto.sha256_hex(response)
	local external_valid = rule.mode ~= "external" or external_verify(policy, rule, address, response)
    local state_valid = state.policy_version == policy.policy_version and state.rule_id == rule.rule_id
        and state.mode == rule.mode and type(state.issued_at) == "number" and type(state.expires_at) == "number"
        and type(state.not_before) == "number" and now <= state.expires_at and now >= state.not_before
        and state.ip_digest == ip_digest and state.ua_digest == ua_digest
        and type(state.response_digest) == "string" and #state.response_digest == 64
		and response_digest and (rule.mode == "external" and external_valid
			or crypto.constant_time_equal(response_digest, state.response_digest))
        and type(state.target) == "string" and #state.target <= MAX_TARGET_BYTES
        and state.target:sub(1, 1) == "/" and state.target:sub(1, 2) ~= "//" and state.target:find("[%c\\]") == nil
    if not state_valid then
        return reject_attempt(policy, rule, address, "proof_invalid_or_too_early")
    end
    if not set_pass_cookie(policy, rule, address, user_agent) then
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "无法签发安全通行凭据，请稍后重试。", 1,
            policy, rule, "pass_cookie_unavailable")
    end
    dict:delete(failure_key(policy, rule, address))
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Location"] = state.target
    record_decision("allow", "proof_valid", 303, policy, rule)
    return ngx.exit(303)
end

function _M.init(options)
    if type(options) ~= "table" or type(options.policy_path) ~= "string" or options.policy_path:sub(1, 1) ~= "/"
        or type(options.state_dict) ~= "string" or not ngx.shared[options.state_dict] then
        error("invalid challenge engine options")
    end
    if options.reload_interval ~= nil and (type(options.reload_interval) ~= "number"
        or options.reload_interval < 0.05 or options.reload_interval > 60) then
        error("invalid challenge reload interval")
    end
    policy_path = options.policy_path
    state_dict_name = options.state_dict
    reload_interval = options.reload_interval or 1
    next_reload_at = 0
    local ok, load_error = reload(true)
    if not ok and not current_policy then
        error("no valid challenge policy code=" .. tostring(load_error))
    end
    return current_policy.policy_version
end

function _M.policy_version()
    reload(false)
    return current_policy and current_policy.policy_version or 0
end

function _M.resolve_client_ip()
    reload(false)
    local address = current_policy and ip.client_address(current_policy.trusted_proxies)
    return address and address.display or nil
end

function _M.access(context)
    reload(false)
    local policy = current_policy
    if not policy then
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "站点验证策略不可用，请稍后重试。", 1,
            nil, nil, "policy_unavailable")
    end
    if type(context) ~= "table" or not identifier(context.tenant_id, MAX_IDENTIFIER_BYTES)
        or not identifier(context.site_id, MAX_IDENTIFIER_BYTES) then
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "站点验证上下文不可用，请稍后重试。", 1,
            policy, nil, "context_invalid")
    end
    local host = string.lower(ngx.var.host or "")
    local rule = find_rule(policy, context, host)
    if not rule then
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "当前站点没有可用的验证策略。", 1,
            policy, nil, "rule_unavailable")
    end
    if ngx.var.uri ~= VERIFY_ENDPOINT then
        if bypass_route(policy, ngx.var.uri) then
            ngx.ctx.cdnca_challenge_bypass_reason = "route"
            record_decision("allow", "bypass_route", 0, policy, rule)
            return
        end
        local browser_document, reason = browser_document_request()
        if not browser_document then
            ngx.ctx.cdnca_challenge_bypass_reason = reason
            record_decision("allow", "bypass_" .. reason, 0, policy, rule)
            return
        end
    end
    local address = ip.client_address(policy.trusted_proxies)
    local user_agent = ngx.var.http_user_agent or ""
    if not address or #user_agent > MAX_USER_AGENT_BYTES or user_agent:find("[%c]") then
        return render_error(ngx.HTTP_FORBIDDEN, "请求无法验证", "客户端上下文不符合安全验证要求。", nil,
            policy, rule, "client_context_invalid")
    end
    if ngx.var.uri == VERIFY_ENDPOINT then
        if ngx.req.get_method() ~= "POST" then
            ngx.header["Allow"] = "POST"
            return render_error(ngx.HTTP_NOT_ALLOWED, "请求方法不受支持", "验证提交只接受 POST 请求。", nil,
                policy, rule, "verify_method_invalid")
        end
        return verify_submission(policy, rule, address, user_agent)
    end
    local passed, cookie_error = valid_pass_cookie(policy, rule, address, user_agent)
    if passed then
        ngx.ctx.cdnca_challenge_policy_version = policy.policy_version
        ngx.ctx.cdnca_challenge_rule_id = rule.rule_id
        record_decision("allow", "pass_cookie_valid", 0, policy, rule)
        return
    end
    if cookie_error ~= "missing" then
        clear_pass_cookie(policy)
    end
    if ngx.req.get_method() ~= "GET" then
        return render_error(ngx.HTTP_FORBIDDEN, "需要浏览器验证", "当前切片只允许通过 GET 页面完成挑战，非幂等请求不会自动重放。", nil,
            policy, rule, "challenge_non_idempotent")
    end
    local failures = ngx.shared[state_dict_name]:get(failure_key(policy, rule, address)) or 0
    if failures >= rule.max_failures_per_window then
        return render_error(ngx.HTTP_TOO_MANY_REQUESTS, "尝试次数过多", "验证失败次数已达到上限，请稍后重试。",
            rule.failure_window_seconds, policy, rule, "failure_threshold")
    end
    local target = safe_target()
    if not target then
        return render_error(ngx.HTTP_FORBIDDEN, "请求地址无效", "请求路径或查询参数无法安全恢复。", nil,
            policy, rule, "target_invalid")
    end
    local nonce, presentation_or_error = issue_pending(policy, rule, address, user_agent, target)
    if not nonce then
        ngx.log(ngx.ERR, "challenge nonce issue failed code=", presentation_or_error, " rule_id=", rule.rule_id)
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "无法分配一次性验证状态，请稍后重试。", 1,
            policy, rule, presentation_or_error)
    end
    return render_challenge(policy, rule, nonce, presentation_or_error,
        cookie_error == "missing" and "pass_cookie_missing" or "pass_cookie_invalid")
end

return _M
