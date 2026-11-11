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
-- Same-origin assets of the built-in pages: the page script (one long-cached
-- file) and each puzzle's picture (drawn on request from its pending state),
-- so a challenge page stays about as small as before.
local SOLVER_ENDPOINT = "/.cdnca/challenge/solver.js"
local PICTURE_ENDPOINT = "/.cdnca/challenge/picture"
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
-- Built-in modes carry a bounded proof of work: the page must find x in
-- [0, 2^difficulty) with sha256(salt || ASCII(x)) = target (the license
-- portal's powfast search). 18 bits is at most 262144 hashes, about 0.3 s
-- on a slow phone; the node checks it with one string compare.
local MIN_POW_DIFFICULTY = 12
local MAX_POW_DIFFICULTY = 24
local DEFAULT_POW_DIFFICULTY = 18
-- Slider and captcha also accept response=wait (the screen-reader path):
-- no picture, but this much server-timed waiting plus the proof of work.
local ALTERNATIVE_WAIT_SECONDS = 5
local SLIDER_TOLERANCE = 3
local CAPTCHA_LENGTH = 6
local CAPTCHA_ALPHABET = "23456789ABCDEFGHJKMNPQRTUVWXY"
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
	external_provider = true, pow_difficulty = true,
}

local external_provider_fields = { provider = true, app_id = true, score_threshold = true, unavailable = true }

-- CHALLENGE_EXTERNAL v1: reCAPTCHA site keys may carry '_'.
local EXTERNAL_PROVIDERS = { tencent = true, ["geetest-v4"] = true, turnstile = true, ["recaptcha-v3"] = true }

local function external_app_id(value)
	return type(value) == "string" and #value >= 1 and #value <= MAX_IDENTIFIER_BYTES
		and value:match("^[A-Za-z0-9][A-Za-z0-9._:_-]*$") ~= nil
end

local function valid_external_provider(value)
	if not has_only(value, external_provider_fields) or not EXTERNAL_PROVIDERS[value.provider]
		or not external_app_id(value.app_id) then
		return false
	end
	local score = value.score_threshold
	if score ~= nil and (value.provider ~= "recaptcha-v3" or type(score) ~= "number"
		or score < 0.1 - 1e-9 or score > 0.9 + 1e-9 or math.abs(score * 10 - math.floor(score * 10 + 0.5)) > 1e-6) then
		return false
	end
	return value.unavailable == nil or value.unavailable == "builtin" or value.unavailable == "closed"
end

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
		if not valid_external_provider(value.external_provider) then
			return false
		end
		if value.pow_difficulty ~= nil then
			return false
		end
	elseif value.external_provider ~= nil
		or (value.pow_difficulty ~= nil
			and not integer(value.pow_difficulty, MIN_POW_DIFFICULTY, MAX_POW_DIFFICULTY)) then
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

local function response_headers(csp_nonce, scripted, external_provider, builtin)
	local script_source = scripted and "'nonce-" .. csp_nonce .. "'" or "'none'"
	local connect_source = "'none'"
	local frame_source
	local extra = ""
	if builtin then
		-- The proof of work runs in blob: Workers; puzzle pictures are same-origin.
		extra = "; worker-src blob:; img-src 'self'"
	end
	if external_provider == "tencent" then
		script_source = script_source .. " https://turing.captcha.qcloud.com"
		connect_source = "https://*.captcha.qq.com https://turing.captcha.qcloud.com"
	elseif external_provider == "geetest-v4" then
		script_source = script_source .. " https://static.geetest.com"
		connect_source = "https://*.geetest.com"
	elseif external_provider == "turnstile" then
		-- Cloudflare Turnstile CSP reference: script-src and frame-src.
		script_source = script_source .. " https://challenges.cloudflare.com"
		frame_source = "https://challenges.cloudflare.com"
	elseif external_provider == "recaptcha-v3" then
		-- From earlier reCAPTCHA docs (developers.google.com unreachable
		-- when written); 合并后实测：check the browser CSP report.
		script_source = script_source .. " https://www.recaptcha.net https://www.gstatic.com"
		frame_source = "https://www.recaptcha.net"
		connect_source = "https://www.recaptcha.net"
	end
	ngx.header["Content-Security-Policy"] = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
		.. "form-action 'self'; style-src 'nonce-" .. csp_nonce .. "'; script-src " .. script_source
		.. "; connect-src " .. connect_source .. (frame_source and ("; frame-src " .. frame_source) or "") .. extra
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
*{box-sizing:border-box}html,body{min-height:100%;margin:0}body{display:grid;place-items:center;padding:24px;background:#f4f6f8;color:#17202a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;letter-spacing:0}main{width:min(100%,560px);padding:34px 0;border-top:4px solid #c7352c}h1{margin:0 0 14px;font-size:28px;line-height:1.3;font-weight:650}p{margin:0 0 18px;font-size:16px;line-height:1.75;color:#475467}.status{display:flex;align-items:center;gap:10px;margin:24px 0;color:#17202a;font-weight:600}.mark{width:14px;height:14px;background:#16865c;border-radius:50%;flex:0 0 auto}form{display:grid;gap:16px}label{display:grid;gap:8px;font-weight:600}input[type=text]{width:100%;min-height:48px;padding:0 12px;border:1px solid #98a2b3;border-radius:4px;background:#fff;color:#17202a;font:inherit;font-size:18px;text-transform:uppercase}input[type=range]{width:100%;min-height:44px;accent-color:#16865c}.captcha{display:inline-flex;align-items:center;justify-content:center;min-height:58px;padding:8px 18px;border:1px solid #98a2b3;background:#fff;font:700 24px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:0}output{font-variant-numeric:tabular-nums}button,.link{display:inline-flex;align-items:center;justify-content:center;min-height:48px;padding:0 22px;border:0;border-radius:4px;background:#17202a;color:#fff;font:inherit;font-weight:650;text-decoration:none;cursor:pointer}button:hover,.link:hover{background:#294052}button:focus-visible,.link:focus-visible,input:focus-visible{outline:3px solid #f2b84b;outline-offset:3px}button:disabled{background:#98a2b3;cursor:wait}.detail{font-size:14px;color:#667085}.error{padding:12px 14px;border-left:3px solid #c7352c;background:#fff1f0;color:#8a1c16}.puzzle{position:relative;width:100%;max-width:240px}.puzzle img,.captcha-image{display:block;width:100%;max-width:240px;height:auto;image-rendering:pixelated;border:1px solid #98a2b3}.captcha-image{max-width:180px}.piece{position:absolute;top:16.67%;left:0;width:16.67%;height:66.67%;border:2px solid #16865c;background:rgba(22,134,92,.35)}.alt{background:#475467}@media(max-width:480px){body{padding:20px}main{padding-top:26px}h1{font-size:24px}p{font-size:15px}button,.link{width:100%}}
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
        or path:sub(1, 2) == "//" or path:sub(1, #"/.cdnca/challenge/") == "/.cdnca/challenge/"
        or path:find("[%c\\]") then
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

-- Puzzle pictures are 1-bit palette PNGs (one stored deflate block) drawn
-- here, so neither the captcha text nor the slider gap is page text.
local GLYPHS = {
    ["2"] = { "01110", "10001", "00001", "00110", "01000", "10000", "11111" },
    ["3"] = { "11110", "00001", "00001", "01110", "00001", "00001", "11110" },
    ["4"] = { "00010", "00110", "01010", "10010", "11111", "00010", "00010" },
    ["5"] = { "11111", "10000", "11110", "00001", "00001", "10001", "01110" },
    ["6"] = { "00110", "01000", "10000", "11110", "10001", "10001", "01110" },
    ["7"] = { "11111", "00001", "00010", "00100", "01000", "01000", "01000" },
    ["8"] = { "01110", "10001", "10001", "01110", "10001", "10001", "01110" },
    ["9"] = { "01110", "10001", "10001", "01111", "00001", "00010", "01100" },
    A = { "01110", "10001", "10001", "11111", "10001", "10001", "10001" },
    B = { "11110", "10001", "10001", "11110", "10001", "10001", "11110" },
    C = { "01111", "10000", "10000", "10000", "10000", "10000", "01111" },
    D = { "11110", "10001", "10001", "10001", "10001", "10001", "11110" },
    E = { "11111", "10000", "10000", "11110", "10000", "10000", "11111" },
    F = { "11111", "10000", "10000", "11110", "10000", "10000", "10000" },
    G = { "01111", "10000", "10000", "10011", "10001", "10001", "01111" },
    H = { "10001", "10001", "10001", "11111", "10001", "10001", "10001" },
    J = { "00111", "00010", "00010", "00010", "00010", "10010", "01100" },
    K = { "10001", "10010", "10100", "11000", "10100", "10010", "10001" },
    M = { "10001", "11011", "10101", "10101", "10001", "10001", "10001" },
    N = { "10001", "11001", "10101", "10011", "10001", "10001", "10001" },
    P = { "11110", "10001", "10001", "11110", "10000", "10000", "10000" },
    Q = { "01110", "10001", "10001", "10001", "10101", "10010", "01101" },
    R = { "11110", "10001", "10001", "11110", "10100", "10010", "10001" },
    T = { "11111", "00100", "00100", "00100", "00100", "00100", "00100" },
    U = { "10001", "10001", "10001", "10001", "10001", "10001", "01110" },
    V = { "10001", "10001", "10001", "10001", "10001", "01010", "00100" },
    W = { "10001", "10001", "10001", "10101", "10101", "11011", "10001" },
    X = { "10001", "10001", "01010", "00100", "01010", "10001", "10001" },
    Y = { "10001", "10001", "01010", "00100", "00100", "00100", "00100" },
}
local CAPTCHA_WIDTH, CAPTCHA_HEIGHT, CAPTCHA_SCALE = 180, 48, 4
local SLIDER_WIDTH, SLIDER_HEIGHT, SLIDER_PIECE, SLIDER_MIN, SLIDER_MAX = 240, 60, 40, 30, 200
local CAPTCHA_PALETTE = "\244\246\248\23\32\42"
local SLIDER_PALETTE = "\228\231\236\71\84\103"

-- One buffer per worker, reused (pictures are drawn and encoded without
-- yielding): "IDAT" + zlib/stored-block header (11 bytes), the pixel rows
-- (each starts with its PNG filter byte 0), then the adler32. The IDAT
-- chunk body is one copy out of it.
local CAPTCHA_STRIDE, SLIDER_STRIDE = math.ceil(CAPTCHA_WIDTH / 8) + 1, math.ceil(SLIDER_WIDTH / 8) + 1
local PICTURE_BYTES = math.max(CAPTCHA_STRIDE * CAPTCHA_HEIGHT, SLIDER_STRIDE * SLIDER_HEIGHT)
local picture_buffer = ffi.new("uint8_t[?]", 11 + PICTURE_BYTES + 4)
local pixels = picture_buffer + 11
ffi.copy(picture_buffer, "IDAT\120\1\1", 7)

local function flip(stride, width, height, x, y)
    if x >= 0 and y >= 0 and x < width and y < height then
        local index = y * stride + 1 + bit.rshift(x, 3)
        pixels[index] = bit.bxor(pixels[index], bit.rshift(0x80, bit.band(x, 7)))
    end
end

-- ORs bytes (a row drawn at x = 0, five bytes) into row y at x, shifting
-- across byte boundaries.
local function blit(stride, y, x, bytes)
    local index = y * stride + 1 + bit.rshift(x, 3)
    local shift = bit.band(x, 7)
    local carry = 0
    for offset = 1, #bytes do
        local value = bytes[offset]
        pixels[index] = bit.bor(pixels[index], carry, bit.rshift(value, shift))
        carry = bit.band(bit.lshift(value, 8 - shift), 255)
        index = index + 1
    end
    if carry ~= 0 then
        pixels[index] = bit.bor(pixels[index], carry)
    end
end

local function be32(value)
    return string.char(bit.band(bit.rshift(value, 24), 255), bit.band(bit.rshift(value, 16), 255),
        bit.band(bit.rshift(value, 8), 255), bit.band(value, 255))
end

-- zlib's crc32/adler32 (nginx links libz; about 9x ngx.crc32_long on a
-- picture), with the nginx/Lua versions when the symbols are not there.
if not pcall(function() return ffi.C.crc32 end) then
    pcall(ffi.cdef, [[
unsigned long crc32(unsigned long crc, const unsigned char *buf, unsigned int len);
unsigned long adler32(unsigned long adler, const unsigned char *buf, unsigned int len);
]])
end
local zlib = pcall(function() return ffi.C.crc32, ffi.C.adler32 end) and ffi.C or nil

local function crc32(data)
    return zlib and tonumber(zlib.crc32(0, data, #data)) or ngx.crc32_long(data)
end

local function png_chunk(kind, data)
    return be32(#data) .. kind .. data .. be32(crc32(kind .. data))
end

local png_ends = {}

local function encode_png(width, height, stride, palette)
    local length = stride * height
    local a, b
    if zlib then
        local adler = tonumber(zlib.adler32(1, pixels, length))
        a, b = adler % 65536, math.floor(adler / 65536)
    else
        a, b = 1, 0
        for index = 0, length - 1 do
            a = a + pixels[index]
            b = b + a
        end
        a, b = a % 65521, b % 65521
    end
    picture_buffer[7], picture_buffer[8] = bit.band(length, 255), bit.rshift(length, 8)
    picture_buffer[9], picture_buffer[10] = bit.band(bit.bnot(length), 255), bit.band(bit.rshift(bit.bnot(length), 8), 255)
    pixels[length], pixels[length + 1] = bit.rshift(b, 8), bit.band(b, 255)
    pixels[length + 2], pixels[length + 3] = bit.rshift(a, 8), bit.band(a, 255)
    local body = ffi.string(picture_buffer, 11 + length + 4)
    local ends = png_ends[palette]
    if not ends then
        ends = { "\137PNG\r\n\26\n" .. png_chunk("IHDR", be32(width) .. be32(height) .. "\1\3\0\0\0")
            .. png_chunk("PLTE", palette), png_chunk("IEND", "") }
        png_ends[palette] = ends
    end
    return ends[1] .. be32(#body - 4) .. body .. be32(crc32(body)) .. ends[2]
end

-- Each glyph row as the bytes of its 4x-wide stroke drawn at x = 0.
local GLYPH_ROWS = {}
for character, rows in pairs(GLYPHS) do
    local scaled = {}
    for row = 1, 7 do
        local bytes = { 0, 0, 0 }
        for column = 1, 5 do
            if rows[row]:byte(column) == 49 then
                for dx = 0, CAPTCHA_SCALE - 1 do
                    local x = (column - 1) * CAPTCHA_SCALE + dx
                    local slot = bit.rshift(x, 3) + 1
                    bytes[slot] = bit.bor(bytes[slot], bit.rshift(0x80, bit.band(x, 7)))
                end
            end
        end
        scaled[row] = bytes
    end
    GLYPH_ROWS[character] = scaled
end

-- Six glyphs scaled 4x with per-glyph offset and slant, two thin strokes
-- across the text (drawn over, never through, the glyphs) and scattered
-- flipped pixels; byte() is the noise source.
-- Every stroke stays inside the canvas: x = left + slant shift is 1..159, so
-- x + 19 <= 178, and y = top + 27 <= 44.
local function captcha_picture(code, byte)
    ffi.fill(pixels, CAPTCHA_STRIDE * CAPTCHA_HEIGHT)
    for index = 1, #code do
        local rows = GLYPH_ROWS[code:sub(index, index)]
        local left = (index - 1) * 30 + 3 + byte() % 5
        local top = 4 + byte() % 14
        local slant = byte() % 3 - 1
        for row = 1, 7 do
            local x = left + math.floor((4 - row) * slant / 2)
            local y = top + (row - 1) * CAPTCHA_SCALE
            local bytes = rows[row]
            for dy = 0, CAPTCHA_SCALE - 1 do
                blit(CAPTCHA_STRIDE, y + dy, x, bytes)
            end
        end
    end
    for _ = 1, 2 do
        local y1, y2 = byte() % CAPTCHA_HEIGHT, byte() % CAPTCHA_HEIGHT
        for x = 0, CAPTCHA_WIDTH - 1 do
            local y = y1 + math.floor((y2 - y1) * x / (CAPTCHA_WIDTH - 1))
            local index = y * CAPTCHA_STRIDE + 1 + bit.rshift(x, 3)
            pixels[index] = bit.bor(pixels[index], bit.rshift(0x80, bit.band(x, 7)))
        end
    end
    for _ = 1, 140 do
        flip(CAPTCHA_STRIDE, CAPTCHA_WIDTH, CAPTCHA_HEIGHT,
            (byte() * 256 + byte()) % CAPTCHA_WIDTH, byte() % CAPTCHA_HEIGHT)
    end
    return encode_png(CAPTCHA_WIDTH, CAPTCHA_HEIGHT, CAPTCHA_STRIDE, CAPTCHA_PALETTE)
end

-- The gap drawn at x = 0: outline plus a checker interior, one row of
-- bytes per gap row (the checker phase follows the gap, not the canvas).
local GAP_ROWS = {}
for row = 0, SLIDER_PIECE - 1 do
    local bytes = { 0, 0, 0, 0, 0 }
    for x = 0, SLIDER_PIECE - 1 do
        local edge = row == 0 or row == SLIDER_PIECE - 1 or x == 0 or x == SLIDER_PIECE - 1
        if edge or (x >= 2 and x <= SLIDER_PIECE - 3 and (x + row) % 2 == 0) then
            local slot = bit.rshift(x, 3) + 1
            bytes[slot] = bit.bor(bytes[slot], bit.rshift(0x80, bit.band(x, 7)))
        end
    end
    GAP_ROWS[row + 1] = bytes
end

-- A dotted track with the gap at x = target (30..200); byte() is the noise source.
local function slider_picture(target, byte)
    ffi.fill(pixels, SLIDER_STRIDE * SLIDER_HEIGHT)
    for row = 1, SLIDER_PIECE do
        blit(SLIDER_STRIDE, 9 + row, target, GAP_ROWS[row])
    end
    for _ = 1, 220 do
        flip(SLIDER_STRIDE, SLIDER_WIDTH, SLIDER_HEIGHT, (byte() * 256 + byte()) % SLIDER_WIDTH, byte() % SLIDER_HEIGHT)
    end
    return encode_png(SLIDER_WIDTH, SLIDER_HEIGHT, SLIDER_STRIDE, SLIDER_PALETTE)
end

-- The page gets salt and target = sha256(salt || ASCII(answer)); the answer
-- (uniform in [0, 2^difficulty)) stays in the pending state. random is 64
-- strong bytes: 1-32 salt, 33-36 counter, the rest for the puzzle.
local function pow_material(rule, random)
    local difficulty = rule.pow_difficulty or DEFAULT_POW_DIFFICULTY
    local salt = random:sub(1, 32)
    local counter = 0
    for index = 33, 36 do
        counter = counter * 256 + random:byte(index)
    end
    local answer = string.format("%d", counter % 2 ^ difficulty)
    local target = crypto.sha256_hex(salt .. answer)
    if not target then
        return nil
    end
    return answer, { salt = crypto.to_hex(salt), target = target, difficulty = difficulty }
end

-- Puzzle noise: xorshift32 from the seed kept in the pending state, so the
-- picture endpoint redraws the same picture for a nonce (reloads match). The
-- answer is not derived from the seed.
local function noise_source(seed)
    local state = seed
    return function()
        state = bit.bxor(state, bit.lshift(state, 13))
        state = bit.bxor(state, bit.rshift(state, 17))
        state = bit.bxor(state, bit.lshift(state, 5))
        return bit.band(state, 255)
    end
end

-- Bytes 37-40 seed the noise, 41-42 pick the slider gap, 43-64 the captcha
-- characters (rejection sampled; 22 bytes give 6 with overwhelming odds).
local function puzzle_material(mode, random)
    local seed = 0
    for index = 37, 40 do
        seed = seed * 256 + random:byte(index)
    end
    seed = seed ~= 0 and seed or 1
    if mode == "slider" then
        return SLIDER_MIN + (random:byte(41) * 256 + random:byte(42)) % (SLIDER_MAX - SLIDER_MIN + 1), seed
    end
    local code = {}
    for index = 43, 64 do
        local value = random:byte(index)
        if value < 232 then
            local offset = value % #CAPTCHA_ALPHABET + 1
            code[#code + 1] = CAPTCHA_ALPHABET:sub(offset, offset)
            if #code == CAPTCHA_LENGTH then
                return table.concat(code), seed
            end
        end
    end
    return nil
end

-- Returns the pending answer, the PoW answer, what the page shows and the
-- picture seed (slider/captcha).
local function challenge_material(rule)
    if rule.mode == "external" then
        return "external", "", {}
    end
    local random = crypto.random_bytes(64, true)
    if not random then
        return nil
    end
    local pow_answer, presentation = pow_material(rule, random)
    if not pow_answer then
        return nil
    end
    if rule.mode == "delay" or rule.mode == "click" then
        return rule.mode, pow_answer, presentation
    end
    local answer, seed = puzzle_material(rule.mode, random)
    if not answer then
        return nil
    end
    return answer, pow_answer, presentation, seed
end

local function issue_pending(policy, rule, address, user_agent, target)
    local dict = ngx.shared[state_dict_name]
    local ip_digest, ua_digest = binding(rule, address, user_agent)
    local now = ngx.now()
    local answer, pow_answer, presentation, seed = challenge_material(rule)
    if not answer then
        return nil, "random_unavailable"
    end
    local state = cjson.encode({
        policy_version = policy.policy_version, rule_id = rule.rule_id, mode = rule.mode,
        issued_at = now, expires_at = now + rule.challenge_ttl_seconds, target = target,
        not_before = now + (rule.mode == "delay" and rule.min_delay_seconds or MIN_INTERACTION_SECONDS),
        answer = answer, pow = pow_answer, seed = seed, ip_digest = ip_digest, ua_digest = ua_digest,
        fallback = rule.fallback or nil,
    })
    if not state then
        return nil, "state_encode_failed"
    end
    for _ = 1, 3 do
        local nonce = crypto.random_token(24)
        if not nonce then
            return nil, "random_unavailable"
        end
        local nonce_digest = crypto.sha256_hex(nonce)
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

-- Built-in page script. scan() is the license portal's bounded powfast search
-- (apps/license-portal/src/auth/powCore.ts): salt rounds 0-7 once, then one
-- block per counter; it also runs inside blob: Workers via toString().
local BUILTIN_SCRIPT = [==[(()=>{const form=document.getElementById('challenge-form'),d=form.dataset,status=document.getElementById('status'),button=document.getElementById('continue'),pow=document.getElementById('pow'),slider=document.getElementById('slider-response'),piece=document.getElementById('piece'),code=document.getElementById('captcha-response'),altButton=document.getElementById('alt-start');const started=performance.now(),space=2**Number(d.powDifficulty);let solved=null,sent=false,alt=false,timer=0;
function scan(saltHex,targetHex,from,to){const K=Int32Array.from([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]),H=Int32Array.from([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);const w=new Int32Array(64),mid=new Int32Array(8),r=new Int32Array(8),t=new Int32Array(8),dg=new Uint8Array(16);
const expand=()=>{for(let i=16;i<64;i++){const x=w[i-15],y=w[i-2];w[i]=(((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3))+w[i-7]+(((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10))+w[i-16]}};
const rounds=(first,last)=>{let a=r[0],b=r[1],c=r[2],e3=r[3],e=r[4],f=r[5],g=r[6],h=r[7];for(let i=first;i<last;i++){const t1=(h+(((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)))+((e&f)^(~e&g))+K[i]+w[i])|0;const t2=((((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)))+((a&b)^(a&c)^(b&c)))|0;h=g;g=f;f=e;e=(e3+t1)|0;e3=c;c=b;b=a;a=(t1+t2)|0}r[0]=a;r[1]=b;r[2]=c;r[3]=e3;r[4]=e;r[5]=f;r[6]=g;r[7]=h};
for(let i=0;i<8;i++){w[i]=parseInt(saltHex.slice(i*8,i*8+8),16)|0;t[i]=parseInt(targetHex.slice(i*8,i*8+8),16)|0}r.set(H);rounds(0,8);mid.set(r);let n=0;for(const ch of String(from))dg[n++]=ch.charCodeAt(0);
for(let counter=from;counter<to;counter++){dg[n]=0x80;dg[n+1]=0;dg[n+2]=0;dg[n+3]=0;w[8]=(dg[0]<<24)|(dg[1]<<16)|(dg[2]<<8)|dg[3];w[9]=(dg[4]<<24)|(dg[5]<<16)|(dg[6]<<8)|dg[7];w[10]=(dg[8]<<24)|(dg[9]<<16)|(dg[10]<<8)|dg[11];w[11]=0;w[12]=0;w[13]=0;w[14]=0;w[15]=(32+n)*8;expand();r.set(mid);rounds(8,64);
if(((H[0]+r[0])|0)===t[0]){let same=true;for(let i=1;i<8;i++)if(((H[i]+r[i])|0)!==t[i])same=false;if(same)return counter}let i=n-1;while(i>=0&&dg[i]===57)dg[i--]=48;if(i>=0)dg[i]+=1;else{dg.copyWithin(1,0,n);dg[0]=49;n++}}return -1}
function update(){if(sent)return;const ready=solved!==null;if(alt||d.mode==='delay'){const left=Math.max(0,Math.ceil((alt?Number(d.wait):Number(d.delay))-(performance.now()-started)/1000));if(left>0||!ready){status.textContent=left>0?`还需等待 ${left} 秒`:'正在完成浏览器校验';button.textContent=left>0?`等待 ${left} 秒`:'正在校验';if(!timer)timer=setTimeout(()=>{timer=0;update()},200);return}sent=true;status.textContent='校验完成，正在提交';button.disabled=false;button.textContent='继续访问';form.requestSubmit(button);return}
let done=d.mode==='click';if(slider){piece.style.left=(Number(slider.value)/2.4)+'%';done=slider.dataset.moved==='1'}if(code)done=code.value.trim().length===6;button.disabled=!(ready&&done);status.textContent=!ready?'正在完成浏览器校验':done?'可以继续':'等待完成验证'}
const finish=x=>{if(solved!==null)return;solved=String(x);pow.value=solved;update()};const fail=()=>{status.textContent='浏览器校验失败，请刷新页面重试'};const single=()=>{let from=0;const step=()=>{const to=Math.min(space,from+32768),x=scan(d.powSalt,d.powTarget,from,to);if(x>=0)return finish(x);from=to;from<space?setTimeout(step,0):fail()};setTimeout(step,0)};const workers=[];const stop=()=>workers.forEach(worker=>worker.terminate());
try{const url=URL.createObjectURL(new Blob(['onmessage=e=>postMessage(('+scan.toString()+')(e.data[0],e.data[1],e.data[2],e.data[3]))'],{type:'text/javascript'}));const count=Math.min(4,Math.max(1,navigator.hardwareConcurrency||1)),share=Math.ceil(space/count);let left=count,fallen=false;const fallback=()=>{if(fallen||solved!==null)return;fallen=true;stop();single()};
for(let i=0;i<count;i++){const worker=new Worker(url);workers.push(worker);worker.onerror=fallback;worker.onmessage=e=>{if(e.data>=0){stop();finish(e.data)}else if(--left===0&&solved===null)fail()};worker.postMessage([d.powSalt,d.powTarget,i*share,Math.min(space,(i+1)*share)])}}catch(_){stop();single()}
if(slider)slider.addEventListener('input',()=>{slider.dataset.moved='1';update()});if(code)code.addEventListener('input',update);if(altButton)altButton.addEventListener('click',()=>{alt=true;const field=slider||code;field.removeAttribute('name');field.required=false;field.disabled=true;document.getElementById('alt-response').name='response';altButton.disabled=true;update()});update()})();]==]
local SOLVER_URL = SOLVER_ENDPOINT .. "?v=" .. crypto.sha256_hex(BUILTIN_SCRIPT):sub(1, 16)

local TITLES = { delay = "正在进行五秒安全检查", click = "请确认您正在访问此网站", slider = "请完成滑动验证", captcha = "请输入图形验证码", external = "请完成安全验证" }
local MESSAGES = {
    delay = "浏览器会在本机完成一段校验计算，等待期结束后自动继续。",
    click = "浏览器在本机完成校验计算后，点击下方按钮继续。",
    slider = "拖动滑块，把方块移到图中缺口处；键盘方向键同样可用。",
    captcha = "输入图中显示的 6 个字符，不区分大小写。",
    external = "验证结果将由受控服务端适配器核验，密钥不会发送到浏览器。",
}
-- Turnstile / reCAPTCHA v3 run without a start button. Without a
-- token within 8 seconds the page submits widget_unavailable and the engine
-- falls back to the built-in check or answers 503 (unavailable policy).
local WIDGET_LOADING = { turnstile = "正在加载验证组件", ["recaptcha-v3"] = "正在验证" }
local WIDGET_TIMEOUT_SCRIPT = "(()=>{const form=document.getElementById('challenge-form'),proof=document.getElementById('external-proof'),status=document.getElementById('status');let done=false;const send=v=>{if(done)return;done=true;proof.value=v;form.requestSubmit()};window.cdncaExternalDone=t=>{if(typeof t!=='string'||t.length<1||t.length>4096){window.cdncaExternalFail();return}status.textContent='验证完成，正在核验';send(t)};window.cdncaExternalFail=()=>{if(done)return;status.textContent='验证组件加载失败';send('widget_unavailable')};setTimeout(()=>window.cdncaExternalFail(),8000)})();"
local ALTERNATIVE = "<input id=\"alt-response\" type=\"hidden\" value=\"wait\"><button id=\"alt-start\" class=\"alt\" type=\"button\">改用等待验证（约 5 秒，适合读屏或无法查看图片）</button>"

local function render_challenge(policy, rule, nonce, presentation, reason)
    local csp_nonce = crypto.random_token(18)
    if not csp_nonce then
        return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "无法建立安全验证，请稍后重试。", 1,
            policy, rule, "response_nonce_unavailable")
    end
    record_decision("challenge", reason, ngx.HTTP_OK, policy, rule)
    -- The page goes out in one write with a Content-Length: separate prints
    -- became separate writev calls (and a chunked trailer), which cost more
    -- per issued page than everything the engine computes for it.
    local parts = {}
    local function emit(...)
        for index = 1, select("#", ...) do
            parts[#parts + 1] = select(index, ...)
        end
    end
	local external = rule.mode == "external"
	response_headers(csp_nonce, true, external and rule.external_provider.provider or nil, not external)
    ngx.status = ngx.HTTP_OK
    local title = TITLES[rule.mode]
    emit("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>", title, "</title>", page_style(csp_nonce), "</head><body><main><h1>", title, "</h1><p>", MESSAGES[rule.mode], "</p><div class=\"status\" aria-live=\"polite\"><span class=\"mark\" aria-hidden=\"true\"></span><span id=\"status\">", external and (WIDGET_LOADING[rule.external_provider.provider] or "等待完成验证") or (rule.fallback and "验证组件加载失败，已改用站内验证" or "正在完成浏览器校验"), "</span></div>")
	if external then
		emit("<form id=\"challenge-form\" method=\"post\" action=\"", VERIFY_ENDPOINT, "\"><input type=\"hidden\" name=\"nonce\" value=\"", nonce, "\">")
		local widget_only = WIDGET_LOADING[rule.external_provider.provider] ~= nil
		emit("<input id=\"external-proof\" name=\"response\" type=\"hidden\"><div id=\"external-widget\"></div>", widget_only and "" or "<button id=\"external-start\" type=\"button\">开始验证</button>", "<noscript><p class=\"error\">此验证方式需要 JavaScript；请联系站点管理员改用无脚本验证方式。</p></noscript></form>")
		if rule.external_provider.provider == "tencent" then
			emit("<script src=\"https://turing.captcha.qcloud.com/TCaptcha.js\"></script><script nonce=\"", csp_nonce, "\">(()=>{const button=document.getElementById('external-start');const status=document.getElementById('status');button.addEventListener('click',()=>{if(typeof TencentCaptcha!=='function'){status.textContent='验证组件不可用';return}button.disabled=true;new TencentCaptcha('", rule.external_provider.app_id, "',result=>{if(!result||result.ret!==0||typeof result.ticket!=='string'||typeof result.randstr!=='string'){status.textContent='验证未通过';button.disabled=false;return}document.getElementById('external-proof').value=JSON.stringify({ticket:result.ticket,randstr:result.randstr});status.textContent='验证完成，正在核验';document.getElementById('challenge-form').requestSubmit()}).show()})})();</script>")
		elseif rule.external_provider.provider == "turnstile" then
			emit("<script nonce=\"", csp_nonce, "\">", WIDGET_TIMEOUT_SCRIPT, "window.cdncaTurnstileReady=()=>{try{turnstile.render('#external-widget',{sitekey:'", rule.external_provider.app_id, "',action:'cdnca_challenge',callback:token=>window.cdncaExternalDone(token),'error-callback':()=>window.cdncaExternalFail()})}catch(_){window.cdncaExternalFail()}};</script><script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&amp;onload=cdncaTurnstileReady\" async defer nonce=\"", csp_nonce, "\"></script>")
		elseif rule.external_provider.provider == "recaptcha-v3" then
			emit("<script nonce=\"", csp_nonce, "\">", WIDGET_TIMEOUT_SCRIPT, "window.cdncaRecaptchaReady=()=>{try{grecaptcha.ready(()=>{grecaptcha.execute('", rule.external_provider.app_id, "',{action:'cdnca_challenge'}).then(token=>window.cdncaExternalDone(token),()=>window.cdncaExternalFail())})}catch(_){window.cdncaExternalFail()}};</script><script src=\"https://www.recaptcha.net/recaptcha/api.js?render=", rule.external_provider.app_id, "&amp;onload=cdncaRecaptchaReady\" async defer nonce=\"", csp_nonce, "\"></script>")
		else
			emit("<script src=\"https://static.geetest.com/v4/gt4.js\"></script><script nonce=\"", csp_nonce, "\">(()=>{const button=document.getElementById('external-start');const status=document.getElementById('status');button.addEventListener('click',()=>{if(typeof initGeetest4!=='function'){status.textContent='验证组件不可用';return}button.disabled=true;initGeetest4({captchaId:'", rule.external_provider.app_id, "',product:'bind'},captcha=>{captcha.appendTo('#external-widget');captcha.onSuccess(()=>{const result=captcha.getValidate();if(!result){status.textContent='验证未通过';button.disabled=false;return}document.getElementById('external-proof').value=JSON.stringify(result);status.textContent='验证完成，正在核验';document.getElementById('challenge-form').requestSubmit()});captcha.onError(()=>{status.textContent='验证组件不可用';button.disabled=false})})})})();</script>")
		end
	else
		-- No-JS clients cannot pass: every submit starts disabled and the
		-- server requires the proof of work.
		emit("<noscript><p class=\"error\">此安全检查需要启用 JavaScript：浏览器要在本机完成一段校验计算才能继续。请开启 JavaScript 后刷新页面。</p></noscript><form id=\"challenge-form\" method=\"post\" action=\"", VERIFY_ENDPOINT, "\" data-mode=\"", rule.mode, "\" data-pow-salt=\"", presentation.salt, "\" data-pow-target=\"", presentation.target, "\" data-pow-difficulty=\"", presentation.difficulty, "\" data-delay=\"", rule.min_delay_seconds, "\" data-wait=\"", ALTERNATIVE_WAIT_SECONDS, "\"><input type=\"hidden\" name=\"nonce\" value=\"", nonce, "\"><input id=\"pow\" type=\"hidden\" name=\"pow\" value=\"\">")
		if rule.mode == "delay" then
			emit("<input type=\"hidden\" name=\"response\" value=\"delay\"><button id=\"continue\" type=\"submit\" disabled>等待 ", rule.min_delay_seconds, " 秒</button>")
		elseif rule.mode == "click" then
			emit("<input type=\"hidden\" name=\"response\" value=\"click\"><button id=\"continue\" type=\"submit\" disabled>确认并继续</button>")
		elseif rule.mode == "slider" then
			emit("<div class=\"puzzle\"><img src=\"", PICTURE_ENDPOINT, "?nonce=", nonce, "\" width=\"240\" height=\"60\" alt=\"滑动拼图：把方块移到图中缺口处。无法查看图片请使用下方“改用等待验证”。\"><div id=\"piece\" class=\"piece\" aria-hidden=\"true\"></div></div><label for=\"slider-response\">拖动滑块对准缺口<input id=\"slider-response\" name=\"response\" type=\"range\" min=\"0\" max=\"", SLIDER_WIDTH - SLIDER_PIECE, "\" value=\"0\" step=\"1\"></label><button id=\"continue\" type=\"submit\" disabled>验证并继续</button>", ALTERNATIVE)
		else
			emit("<img class=\"captcha-image\" src=\"", PICTURE_ENDPOINT, "?nonce=", nonce, "\" width=\"180\" height=\"48\" alt=\"图形验证码：无法查看图片请使用下方“改用等待验证”。\"><label for=\"captcha-response\">图中的 6 个字符<input id=\"captcha-response\" name=\"response\" type=\"text\" minlength=\"6\" maxlength=\"6\" pattern=\"[0-9A-Za-z]{6}\" inputmode=\"text\" autocomplete=\"off\" autocapitalize=\"characters\" spellcheck=\"false\" required></label><button id=\"continue\" type=\"submit\" disabled>验证并继续</button>", ALTERNATIVE)
		end
		emit("</form><script nonce=\"", csp_nonce, "\" src=\"", SOLVER_URL, "\"></script>")
	end
    emit("<p class=\"detail\">安全检查不会读取或记录您的请求正文。</p></main></body></html>")
    local page = table.concat(parts)
    ngx.header["Content-Length"] = #page
    ngx.print(page)
    return ngx.exit(ngx.HTTP_OK)
end

-- The picture of a pending slider/captcha nonce, for the client it was issued
-- to. Fetching does not consume the nonce; nothing is drawn for clients that
-- never load the picture.
local function serve_picture(policy, rule, address, user_agent)
    local nonce = ngx.var.arg_nonce
    local state = type(nonce) == "string" and #nonce == 32 and not nonce:find("[^A-Za-z0-9_-]")
        and ngx.shared[state_dict_name]:get(pending_key(policy, rule, crypto.sha256_hex(nonce)))
    state = state and cjson.decode(state)
    local ip_digest, ua_digest = binding(rule, address, user_agent)
    if type(state) ~= "table" or state.mode ~= rule.mode or type(state.seed) ~= "number"
        or state.ip_digest ~= ip_digest or state.ua_digest ~= ua_digest
        or type(state.expires_at) ~= "number" or ngx.now() > state.expires_at then
        record_decision("block", "picture_unavailable", ngx.HTTP_FORBIDDEN, policy, rule)
        ngx.header["Cache-Control"] = "no-store"
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    local byte = noise_source(state.seed)
    local image
    if rule.mode == "slider" and type(state.answer) == "number" then
        image = slider_picture(state.answer, byte)
    elseif rule.mode == "captcha" and type(state.answer) == "string" then
        image = captcha_picture(state.answer, byte)
    end
    if not image then
        record_decision("block", "picture_unavailable", ngx.HTTP_FORBIDDEN, policy, rule)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    record_decision("challenge", "challenge_picture", ngx.HTTP_OK, policy, rule)
    ngx.header["Content-Type"] = "image/png"
    ngx.header["Cache-Control"] = "no-store, private, max-age=0"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["Content-Length"] = #image
    ngx.status = ngx.HTTP_OK
    ngx.print(image)
    return ngx.exit(ngx.HTTP_OK)
end

local function serve_solver(policy, rule)
    record_decision("challenge", "challenge_script", ngx.HTTP_OK, policy, rule)
    ngx.header["Content-Type"] = "text/javascript; charset=utf-8"
    ngx.header["Cache-Control"] = "public, max-age=31536000, immutable"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["Content-Length"] = #BUILTIN_SCRIPT
    ngx.status = ngx.HTTP_OK
    ngx.print(BUILTIN_SCRIPT)
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
    local values, parse_error = ngx.req.get_post_args(4)
    if not values or parse_error == "truncated" then
        return nil
    end
    for key, value in pairs(values) do
        if key ~= "nonce" and key ~= "response" and key ~= "pow" or type(value) ~= "string" then
            return nil
        end
    end
    if values.pow ~= nil and values.pow:match("^[0-9][0-9]?[0-9]?[0-9]?[0-9]?[0-9]?[0-9]?[0-9]?$") == nil then
        return nil
    end
    if type(values.nonce) ~= "string" or #values.nonce ~= 32 or values.nonce:find("[^A-Za-z0-9_-]")
		or type(values.response) ~= "string" or #values.response < 1 or #values.response > MAX_EXTERNAL_PROOF_BYTES
        or values.response:find("[%c]") then
        return nil
    end
    return values
end

-- Returns "ok" (agent 204), "rejected" (403: the provider refused the
-- token) or "unavailable" (503, any other answer or no answer; §4.3).
-- Only "rejected" counts as a failed attempt.
local function external_verify(policy, rule, address, proof)
	if #proof > MAX_EXTERNAL_PROOF_BYTES then
		return "rejected"
	end
	local provider = rule.external_provider
	local payload = cjson.encode({
		policy_id = rule.rule_id, policy_version = policy.policy_version,
		tenant_id = rule.tenant_id, site_id = rule.site_id,
		provider = provider.provider, app_id = provider.app_id,
		proof = proof, client_ip = address.canonical,
		host = WIDGET_LOADING[provider.provider] and rule.host or nil,
		score_threshold = provider.score_threshold,
	})
	if not payload or #payload > 8192 then
		return "rejected"
	end
	local socket = ngx.socket.tcp()
	if not socket then
		return "unavailable"
	end
	socket:settimeouts(250, 3500, 500)
	local connected = socket:connect("127.0.0.1", 19178)
	if not connected then
		socket:close()
		return "unavailable"
	end
	local request = "POST /v1/challenge/external/verify HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
		.. #payload .. "\r\n\r\n" .. payload
	local sent = socket:send(request)
	if sent ~= #request then
		socket:close()
		return "unavailable"
	end
	local status = socket:receive("*l")
	if status == "HTTP/1.1 403 Forbidden" then
		socket:close()
		return "rejected"
	end
	if status ~= "HTTP/1.1 204 No Content" then
		socket:close()
		return "unavailable"
	end
	for _ = 1, 32 do
		local line = socket:receive("*l")
		if line == "" then
			socket:close()
			return "ok"
		end
		if not line or #line > 4096 or line:find("[%c]") then
			socket:close()
			return "unavailable"
		end
	end
	socket:close()
	return "unavailable"
end

-- The built-in check an external rule falls back to (unavailable =
-- builtin): click + proof of work at the engine default difficulty, same
-- rule identity, so pending/failure keys and the pass cookie are unchanged.
local function fallback_rule(rule)
	local copy = {}
	for key, value in pairs(rule) do
		copy[key] = value
	end
	copy.mode = "click"
	copy.external_provider = nil
	copy.pow_difficulty = nil
	copy.fallback = true
	return copy
end

local function verify_submission(policy, rule, address, user_agent)
    local values = form_values()
    if not values then
        return reject_attempt(policy, rule, address, "form_invalid")
    end
    local nonce_digest = crypto.sha256_hex(values.nonce)
    local dict = ngx.shared[state_dict_name]
    -- a pending state issued by the built-in fallback of an external rule is
    -- keyed by the fallback's mode (click), not the rule's
    local pending_rule = rule
    local pending = dict:get(pending_key(policy, pending_rule, nonce_digest))
    if not pending and rule.mode == "external" then
        pending_rule = fallback_rule(rule)
        pending = dict:get(pending_key(policy, pending_rule, nonce_digest))
    end
    if not pending then
        return reject_attempt(policy, rule, address, "nonce_missing_or_replayed")
    end
    local state = cjson.decode(pending)
    if type(state) ~= "table" then
        dict:delete(pending_key(policy, pending_rule, nonce_digest))
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
    dict:delete(pending_key(policy, pending_rule, nonce_digest))
    local ip_digest, ua_digest = binding(rule, address, user_agent)
    local response = values.response
    -- A pending state issued by the built-in fallback of an external rule is
    -- checked as that click + proof of work rule and never calls the agent.
    local original = rule
    if rule.mode == "external" and state.fallback == true then
        rule = fallback_rule(rule)
    end
    local state_ok = state.policy_version == policy.policy_version and state.rule_id == rule.rule_id
        and state.mode == rule.mode and type(state.issued_at) == "number" and type(state.expires_at) == "number"
        and type(state.not_before) == "number" and now <= state.expires_at and now >= state.not_before
        and state.ip_digest == ip_digest and state.ua_digest == ua_digest
        and type(state.target) == "string" and #state.target <= MAX_TARGET_BYTES
        and state.target:sub(1, 1) == "/" and state.target:sub(1, 2) ~= "//" and state.target:find("[%c\\]") == nil
    local answer_valid
    if rule.mode == "external" then
        if not state_ok or values.pow ~= nil then
            return reject_attempt(policy, rule, address, "proof_invalid_or_too_early")
        end
        local outcome = response == "widget_unavailable" and "unavailable"
            or external_verify(policy, rule, address, response)
        if outcome == "rejected" then
            return reject_attempt(policy, rule, address, "external_rejected")
        end
        if outcome == "unavailable" then
            -- Not a failed attempt.
            if rule.external_provider.unavailable == "closed" then
                return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "验证服务暂不可用，请稍后重试。", 30,
                    policy, rule, "external_unavailable")
            end
            local fallback = fallback_rule(rule)
            local nonce, presentation_or_error = issue_pending(policy, fallback, address, user_agent, state.target)
            if not nonce then
                return render_error(ngx.HTTP_SERVICE_UNAVAILABLE, "验证服务暂不可用", "无法分配一次性验证状态，请稍后重试。", 1,
                    policy, rule, presentation_or_error)
            end
            return render_challenge(policy, fallback, nonce, presentation_or_error, "external_unavailable_fallback")
        end
        answer_valid = outcome == "ok"
    elseif response == "wait" and (rule.mode == "slider" or rule.mode == "captcha") then
        answer_valid = type(state.issued_at) == "number" and now >= state.issued_at + ALTERNATIVE_WAIT_SECONDS
    elseif rule.mode == "slider" then
        local position = response:match("^[0-9][0-9]?[0-9]?$") and tonumber(response)
        answer_valid = position ~= nil and type(state.answer) == "number"
            and math.abs(position - state.answer) <= SLIDER_TOLERANCE
    elseif rule.mode == "captcha" then
        answer_valid = type(state.answer) == "string"
            and crypto.constant_time_equal(string.upper(response:match("^%s*(.-)%s*$")), state.answer)
    else
        answer_valid = response == rule.mode and state.answer == rule.mode
    end
    local pow_valid = rule.mode == "external" or (type(state.pow) == "string" and values.pow ~= nil
        and crypto.constant_time_equal(values.pow, state.pow))
    local state_valid = state_ok and answer_valid and pow_valid
    rule = original
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
    local uri = ngx.var.uri
    local asset = uri == SOLVER_ENDPOINT or uri == PICTURE_ENDPOINT
    if asset and ngx.req.get_method() ~= "GET" and ngx.req.get_method() ~= "HEAD" then
        ngx.header["Allow"] = "GET, HEAD"
        return render_error(ngx.HTTP_NOT_ALLOWED, "请求方法不受支持", "验证资源只接受 GET 请求。", nil,
            policy, rule, "asset_method_invalid")
    end
    if uri == SOLVER_ENDPOINT then
        return serve_solver(policy, rule)
    end
    if uri ~= VERIFY_ENDPOINT and not asset then
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
    if uri == PICTURE_ENDPOINT then
        return serve_picture(policy, rule, address, user_agent)
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
