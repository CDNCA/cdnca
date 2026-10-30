local bit = require("bit")
local cjson = require("cjson.safe")
-- "originauth.crypto" from the node Lua root (dynamic routing), "crypto" when
-- originauth/ itself is on the path (v7 renders it first, the smoke script).
local crypto_ok, crypto = pcall(require, "originauth.crypto")
if not crypto_ok then crypto = require("crypto") end
local ffi = require("ffi")

ffi.cdef([[
int open(const char *pathname, int flags, ...);
long read(int fd, void *buf, unsigned long count);
int close(int fd);
unsigned int geteuid(void);
int statx(int dirfd, const char *pathname, int flags, unsigned int mask, void *statxbuf);
struct cdnca_originauth_statx_timestamp {
    long long tv_sec;
    unsigned int tv_nsec;
    int reserved;
};
struct cdnca_originauth_statx {
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
    struct cdnca_originauth_statx_timestamp stx_atime;
    struct cdnca_originauth_statx_timestamp stx_btime;
    struct cdnca_originauth_statx_timestamp stx_ctime;
    struct cdnca_originauth_statx_timestamp stx_mtime;
    unsigned int stx_rdev_major;
    unsigned int stx_rdev_minor;
    unsigned int stx_dev_major;
    unsigned int stx_dev_minor;
    unsigned long long spare2[14];
};
]])

local _M = {}

local SCHEMA_VERSION = "cdnca.edge.originauth/v1"
local CREDENTIAL_VERSION = "cdnca.edge.originauth.credential/v1"
local MAX_POLICY_BYTES = 1024 * 1024
local MAX_CREDENTIAL_BYTES = 16 * 1024
local MAX_POLICY_VERSION = 9007199254740991
local MAX_RULES = 128
local MAX_PATH_BYTES = 4096
local MAX_QUERY_BYTES = 8192
local MAX_QUERY_PARAMETERS = 128
local EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
local OFFICIAL_REGIONS = {
    oss = {
        ["cn-hangzhou"] = true, ["cn-shanghai"] = true, ["cn-nanjing"] = true, ["cn-fuzhou"] = true,
        ["cn-wuhan-lr"] = true, ["cn-qingdao"] = true, ["cn-beijing"] = true, ["cn-zhangjiakou"] = true,
        ["cn-huhehaote"] = true, ["cn-wulanchabu"] = true, ["cn-shenzhen"] = true, ["cn-heyuan"] = true,
        ["cn-guangzhou"] = true, ["cn-chengdu"] = true, ["cn-hongkong"] = true, ["cn-zhongwei"] = true,
        ["cn-beijing-finance-1"] = true, ["cn-hangzhou-finance"] = true, ["cn-shanghai-finance-1"] = true,
        ["cn-shenzhen-finance-1"] = true, ["cn-north-2-gov-1"] = true, ["us-west-1"] = true,
        ["us-east-1"] = true, ["ap-northeast-1"] = true, ["ap-northeast-2"] = true,
        ["ap-southeast-1"] = true, ["ap-southeast-3"] = true, ["ap-southeast-5"] = true,
        ["ap-southeast-6"] = true, ["ap-southeast-7"] = true, ["ap-southeast-8"] = true,
        ["eu-central-1"] = true, ["eu-west-1"] = true, ["eu-west-2"] = true, ["me-east-1"] = true,
    },
    cos = {
        ["ap-beijing-1"] = true, ["ap-beijing"] = true, ["ap-nanjing"] = true, ["ap-shanghai"] = true,
        ["ap-guangzhou"] = true, ["ap-chengdu"] = true, ["ap-chongqing"] = true,
        ["ap-shenzhen-fsi"] = true, ["ap-shanghai-fsi"] = true, ["ap-beijing-fsi"] = true,
        ["ap-hongkong"] = true, ["ap-singapore"] = true, ["ap-mumbai"] = true, ["ap-jakarta"] = true,
        ["ap-seoul"] = true, ["ap-bangkok"] = true, ["ap-tokyo"] = true, ["na-siliconvalley"] = true,
        ["na-ashburn"] = true, ["na-toronto"] = true, ["eu-frankfurt"] = true, ["eu-moscow"] = true,
        ["sa-saopaulo"] = true,
    },
}

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
local fallback_path
local reload_interval = 1
local next_reload_at = 0

local function integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum
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
        if type(key) ~= "number" or key ~= math.floor(key) or key < 1 or key > length then
            return nil
        end
    end
    return length
end

local function contains_control(value)
    return type(value) ~= "string" or value:find("[%z\1-\31\127]") ~= nil
end

local function identifier(value, maximum)
    return type(value) == "string" and #value >= 1 and #value <= maximum
        and value:match("^[A-Za-z0-9._:-]+$") ~= nil
end

local function scope_name(value)
    return type(value) == "string" and #value >= 1 and #value <= 64
        and value:match("^[a-z0-9][a-z0-9-]*$") ~= nil and value:sub(-1) ~= "-"
end

local function valid_domain(value)
    if type(value) ~= "string" or #value == 0 or #value > 253 or value:sub(-1) == "."
        or value:sub(1, 1) == "." or value:find("..", 1, true)
        or value ~= string.lower(value) or value == "localhost" or value:sub(-6) == ".local"
        or value:match("^%d+%.%d+%.%d+%.%d+$") then
        return false
    end
    for label in value:gmatch("[^.]+") do
        if #label == 0 or #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-"
            or label:find("[^a-z0-9-]") then
            return false
        end
    end
    return true
end

local function safe_absolute_path(value)
    if type(value) ~= "string" or #value < 2 or #value > 4096 or value:sub(1, 1) ~= "/"
        or contains_control(value) or value:find("//", 1, true) then
        return false
    end
    for segment in value:gmatch("[^/]+") do
        if segment == "." or segment == ".." then
            return false
        end
    end
    return true
end

local function utf8_valid(value)
    local index = 1
    while index <= #value do
        local first = value:byte(index)
        if first <= 0x7f then
            index = index + 1
        elseif first >= 0xc2 and first <= 0xdf then
            local second = value:byte(index + 1)
            if not second or second < 0x80 or second > 0xbf then return false end
            index = index + 2
        elseif first >= 0xe0 and first <= 0xef then
            local second, third = value:byte(index + 1), value:byte(index + 2)
            if not second or not third or third < 0x80 or third > 0xbf
                or first == 0xe0 and (second < 0xa0 or second > 0xbf)
                or first == 0xed and (second < 0x80 or second > 0x9f)
                or first ~= 0xe0 and first ~= 0xed and (second < 0x80 or second > 0xbf) then
                return false
            end
            index = index + 3
        elseif first >= 0xf0 and first <= 0xf4 then
            local second, third, fourth = value:byte(index + 1), value:byte(index + 2), value:byte(index + 3)
            if not second or not third or not fourth or third < 0x80 or third > 0xbf or fourth < 0x80 or fourth > 0xbf
                or first == 0xf0 and (second < 0x90 or second > 0xbf)
                or first == 0xf4 and (second < 0x80 or second > 0x8f)
                or first ~= 0xf0 and first ~= 0xf4 and (second < 0x80 or second > 0xbf) then
                return false
            end
            index = index + 4
        else
            return false
        end
    end
    return true
end

local function percent_decode(value)
    local output = {}
    local index = 1
    while index <= #value do
        if value:sub(index, index) == "%" then
            local encoded = value:sub(index + 1, index + 2)
            if #encoded ~= 2 or not encoded:match("^[0-9A-Fa-f][0-9A-Fa-f]$") then
                return nil
            end
            output[#output + 1] = string.char(tonumber(encoded, 16))
            index = index + 3
        else
            output[#output + 1] = value:sub(index, index)
            index = index + 1
        end
    end
    return table.concat(output)
end

local function percent_encode(value, preserve_slash)
    local output = {}
    for index = 1, #value do
        local byte = value:byte(index)
        if (byte >= 65 and byte <= 90) or (byte >= 97 and byte <= 122) or (byte >= 48 and byte <= 57)
            or byte == 45 or byte == 46 or byte == 95 or byte == 126 or preserve_slash and byte == 47 then
            output[#output + 1] = string.char(byte)
        else
            output[#output + 1] = string.format("%%%02X", byte)
        end
    end
    return table.concat(output)
end

local function canonical_path(raw)
    if type(raw) ~= "string" or #raw == 0 or #raw > MAX_PATH_BYTES or raw:sub(1, 1) ~= "/"
        or raw:find("\\", 1, true) or string.lower(raw):find("%%2f") or string.lower(raw):find("%%5c") then
        return nil
    end
    local decoded = percent_decode(raw)
    if not decoded or not utf8_valid(decoded) or contains_control(decoded) or decoded:find("\\", 1, true) then
        return nil
    end
    if decoded:find("//", 1, true) then return nil end
    for segment in decoded:gmatch("[^/]+") do
        if segment == "." or segment == ".." then return nil end
    end
    return percent_encode(decoded, true), decoded
end

local function credential_query_name(name)
    local value = string.lower(name)
    return value:sub(1, 6) == "x-amz-" or value:sub(1, 6) == "x-oss-"
        or value:sub(1, 7) == "q-sign-" or value:sub(1, 6) == "q-key-"
        or value == "authorization" or value == "signature" or value == "ossaccesskeyid"
        or value == "security-token" or value == "x-cos-security-token" or value == "q-ak"
        or value == "q-header-list" or value == "q-url-param-list"
end

local function parse_query(raw)
    if not raw or raw == "" then
        return {}
    end
    if #raw > MAX_QUERY_BYTES or raw:find("[;+#]") then
        return nil
    end
    local result = {}
    local seen = {}
    for part in (raw .. "&"):gmatch("(.-)&") do
        if part == "" or #result >= MAX_QUERY_PARAMETERS then
            return nil
        end
        local equals = part:find("=", 1, true)
        local raw_name = equals and part:sub(1, equals - 1) or part
        local raw_value = equals and part:sub(equals + 1) or ""
        local name = percent_decode(raw_name)
        local value = percent_decode(raw_value)
        if not name or name == "" or not value or not utf8_valid(name) or not utf8_valid(value)
            or contains_control(name) or contains_control(value) or seen[name] or credential_query_name(name) then
            return nil
        end
        seen[name] = true
        result[#result + 1] = { name = name, value = value }
    end
    return result
end

local key_fields = { key_id = true, secret_file = true, sha256 = true }
local endpoint_fields = { scheme = true, host = true, port = true }
local rule_fields = {
    rule_id = true, provider = true, algorithm = true, endpoint = true, bucket = true,
    path_prefix = true, region = true, service = true, signature_ttl_seconds = true,
    current_key = true, previous_key = true, activate_current_at_unix = true,
}
local policy_fields = { schema_version = true, policy_version = true, rules = true }
local credential_fields = {
    schema_version = true, provider = true, access_key_id = true, secret_access_key = true,
    session_token = true, not_before_unix = true, expires_at_unix = true,
}

local function validate_key(value)
    return has_only(value, key_fields) and identifier(value.key_id, 64) and safe_absolute_path(value.secret_file)
        and type(value.sha256) == "string" and #value.sha256 == 64 and value.sha256:match("^[0-9a-f]+$") ~= nil
end

local function validate_endpoint(value)
    return has_only(value, endpoint_fields) and value.scheme == "https" and value.port == 443 and valid_domain(value.host)
end

local function validate_rule(value, key_valid, fields)
    key_valid = key_valid or validate_key
    if not has_only(value, fields or rule_fields) or not identifier(value.rule_id, 128) or not validate_endpoint(value.endpoint)
        or not scope_name(value.region) or not scope_name(value.service)
        or not integer(value.signature_ttl_seconds, 1, 3600) or not key_valid(value.current_key)
        or not integer(value.activate_current_at_unix, 0, MAX_POLICY_VERSION) then
        return false
    end
    local path = canonical_path(value.path_prefix)
    if path ~= value.path_prefix or value.path_prefix:sub(-1) ~= "/" then
        return false
    end
    if value.provider == "s3" then
        if value.algorithm ~= "aws4-hmac-sha256" or value.bucket ~= "" then return false end
    elseif value.provider == "oss" then
        if value.algorithm ~= "oss4-hmac-sha256" or value.service ~= "oss" or not OFFICIAL_REGIONS.oss[value.region]
            or not valid_domain(value.bucket)
            or value.endpoint.host ~= value.bucket .. ".oss-" .. value.region .. ".aliyuncs.com" then return false end
    elseif value.provider == "cos" then
        if value.algorithm ~= "cos-hmac-sha1" or value.service ~= "cos" or not OFFICIAL_REGIONS.cos[value.region]
            or value.bucket ~= ""
            or value.endpoint.host:sub(-#(".cos." .. value.region .. ".myqcloud.com")) ~= ".cos." .. value.region .. ".myqcloud.com" then return false end
    else
        return false
    end
    if value.previous_key ~= nil then
        if not key_valid(value.previous_key) or value.activate_current_at_unix == 0
            or value.previous_key.key_id == value.current_key.key_id
            or value.previous_key.secret_file ~= nil and value.previous_key.secret_file == value.current_key.secret_file
            or value.previous_key.sha256 ~= nil and value.previous_key.sha256 == value.current_key.sha256 then return false end
    elseif value.activate_current_at_unix ~= 0 then
        return false
    end
    return true
end

local function validate_policy(value)
    local length = value and array_length(value.rules, MAX_RULES)
    if not has_only(value, policy_fields) or value.schema_version ~= SCHEMA_VERSION
        or not integer(value.policy_version, 1, MAX_POLICY_VERSION) or not length or length == 0 then
        return nil, "policy_invalid"
    end
    local previous_id
    value.rule_by_id = {}
    for index = 1, length do
        local rule = value.rules[index]
        if not validate_rule(rule) or previous_id and rule.rule_id <= previous_id then
            return nil, "rule_invalid"
        end
        previous_id = rule.rule_id
        value.rule_by_id[rule.rule_id] = rule
    end
    return value
end

local function stat_path(path)
    local info = ffi.new("struct cdnca_originauth_statx[1]")
    if ffi.C.statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, info) ~= 0 then
        return nil
    end
    return info[0]
end

local function stat_fd(fd)
    local info = ffi.new("struct cdnca_originauth_statx[1]")
    if ffi.C.statx(fd, "", bit.bor(AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW), STATX_BASIC_STATS, info) ~= 0 then
        return nil
    end
    return info[0]
end

local function secure_read(path, maximum)
    if not safe_absolute_path(path) then return nil, "file_path_invalid" end
    local parent = path:match("^(.*)/[^/]+$")
    if not parent or parent == "" then parent = "/" end
    local owner = tonumber(ffi.C.geteuid())
    local parent_info = stat_path(parent)
    if not parent_info or bit.band(tonumber(parent_info.stx_mode), MODE_TYPE_MASK) ~= MODE_DIRECTORY
        or bit.band(tonumber(parent_info.stx_mode), MODE_PERMISSIONS) ~= 448
        or tonumber(parent_info.stx_uid) ~= owner then return nil, "directory_metadata_invalid" end
    local fd = ffi.C.open(path, bit.bor(O_RDONLY, O_CLOEXEC, O_NOFOLLOW))
    if fd < 0 then return nil, "file_open_failed" end
    local info = stat_fd(fd)
    if not info or bit.band(tonumber(info.stx_mode), MODE_TYPE_MASK) ~= MODE_REGULAR
        or bit.band(tonumber(info.stx_mode), MODE_PERMISSIONS) ~= 384 or tonumber(info.stx_nlink) ~= 1
        or tonumber(info.stx_uid) ~= owner or tonumber(info.stx_size) < 1 or tonumber(info.stx_size) > maximum then
        ffi.C.close(fd)
        return nil, "file_metadata_invalid"
    end
    local buffer = ffi.new("unsigned char[?]", maximum + 1)
    local chunks = {}
    local length = 0
    while length <= maximum do
        local count = ffi.C.read(fd, buffer, maximum + 1 - length)
        if count < 0 then ffi.C.close(fd); return nil, "file_read_failed" end
        if count == 0 then break end
        chunks[#chunks + 1] = ffi.string(buffer, count)
        length = length + count
    end
    ffi.C.close(fd)
    if length < 1 or length > maximum or length ~= tonumber(info.stx_size) then return nil, "file_read_failed" end
    return table.concat(chunks)
end

local function secret_field(value, maximum)
    return type(value) == "string" and #value >= 1 and #value <= maximum and not contains_control(value)
        and not value:match("^%s") and not value:match("%s$")
end

local function valid_credential(provider, value)
    return has_only(value, credential_fields) and value.schema_version == CREDENTIAL_VERSION and value.provider == provider
        and secret_field(value.access_key_id, 256) and secret_field(value.secret_access_key, 512)
        and type(value.session_token) == "string" and (value.session_token == "" or secret_field(value.session_token, 4096))
        and integer(value.not_before_unix, 0, MAX_POLICY_VERSION)
        and integer(value.expires_at_unix, 1, MAX_POLICY_VERSION) and value.expires_at_unix > value.not_before_unix
end

local function read_credential(provider, key)
    local raw, read_error = secure_read(key.secret_file, MAX_CREDENTIAL_BYTES)
    if not raw then return nil, read_error end
    local digest = crypto.sha256_hex(raw)
    if not digest or not crypto.constant_time_equal(digest, key.sha256) then return nil, "credential_binding_mismatch" end
    local value = cjson.decode(raw)
    if not valid_credential(provider, value) then
        return nil, "credential_invalid"
    end
    return value
end

local function read_candidate(path)
    local raw, read_error = secure_read(path, MAX_POLICY_BYTES)
    if not raw then return nil, read_error end
    local candidate, validation_error = validate_policy(cjson.decode(raw))
    if not candidate then return nil, validation_error end
    for _, rule in ipairs(candidate.rules) do
        local current, current_error = read_credential(rule.provider, rule.current_key)
        if not current then return nil, current_error end
        rule.current_key.credential = current
        if rule.previous_key then
            local previous, previous_error = read_credential(rule.provider, rule.previous_key)
            if not previous then return nil, previous_error end
            rule.previous_key.credential = previous
        end
    end
    return candidate, nil, crypto.sha256_hex(raw)
end

local function reload(force)
    local now = ngx.now()
    if not force and now < next_reload_at then return true end
    next_reload_at = now + reload_interval
    local candidate, candidate_error, candidate_digest = read_candidate(policy_path)
    if not candidate and not current_policy then
        candidate, candidate_error, candidate_digest = read_candidate(fallback_path)
    end
    if not candidate then
        if force then ngx.log(ngx.ERR, "origin auth policy load rejected code=", candidate_error) end
        return false, candidate_error
    end
    if current_policy and candidate.policy_version < current_policy.policy_version then return false, "policy_version_regressed" end
    if current_policy and candidate.policy_version == current_policy.policy_version and candidate_digest ~= current_digest then
        return false, "same_version_changed"
    end
    if not current_policy or candidate.policy_version > current_policy.policy_version then
        current_policy = candidate
        current_digest = candidate_digest
        if force then ngx.log(ngx.NOTICE, "origin auth policy activated version=", candidate.policy_version) end
    end
    return true
end

local function normalized_header(value)
    if type(value) ~= "string" or #value == 0 or #value > 4096 or contains_control(value) then return nil end
    return (value:gsub("^%s+", ""):gsub("%s+$", ""):gsub("%s+", " "))
end

local function canonical_headers(headers)
    local names = {}
    for name in pairs(headers) do names[#names + 1] = string.lower(name) end
    table.sort(names)
    local output = {}
    for _, name in ipairs(names) do
        local value = normalized_header(headers[name])
        if not value then return nil end
        output[#output + 1] = name .. ":" .. value .. "\n"
    end
    return table.concat(output), table.concat(names, ";"), names
end

local function canonical_query(query_pairs, omit_empty)
    local values = {}
    for _, pair in ipairs(query_pairs) do
        local value = percent_encode(pair.name, false)
        if not omit_empty or pair.value ~= "" then value = value .. "=" .. percent_encode(pair.value, false) end
        values[#values + 1] = value
    end
    table.sort(values)
    return table.concat(values, "&")
end

local function cos_query(query_pairs)
    local values = {}
    for _, pair in ipairs(query_pairs) do
        values[#values + 1] = { name = string.lower(percent_encode(pair.name, false)), value = percent_encode(pair.value, false) }
    end
    table.sort(values, function(left, right)
        return left.name < right.name or left.name == right.name and left.value < right.value
    end)
    local encoded = {}
    local names = {}
    for _, value in ipairs(values) do
        encoded[#encoded + 1] = value.name .. "=" .. value.value
        names[#names + 1] = value.name
    end
    return table.concat(encoded, "&"), table.concat(names, ";")
end

local function sign_s3(rule, method, encoded_path, query_pairs, range_value, credential, now)
    local datetime = os.date("!%Y%m%dT%H%M%SZ", now)
    local date = os.date("!%Y%m%d", now)
    local headers = { host = rule.endpoint.host, ["x-amz-content-sha256"] = EMPTY_SHA256, ["x-amz-date"] = datetime }
    if range_value then headers.range = range_value end
    if credential.session_token ~= "" then headers["x-amz-security-token"] = credential.session_token end
    local canonical, names = canonical_headers(headers)
    if not canonical then return nil end
    local request = method .. "\n" .. encoded_path .. "\n" .. canonical_query(query_pairs, false)
        .. "\n" .. canonical .. "\n" .. names .. "\n" .. EMPTY_SHA256
    local scope = date .. "/" .. rule.region .. "/" .. rule.service .. "/aws4_request"
    local string_to_sign = "AWS4-HMAC-SHA256\n" .. datetime .. "\n" .. scope .. "\n" .. crypto.sha256_hex(request)
    local key = crypto.hmac_sha256_binary("AWS4" .. credential.secret_access_key, date)
    key = key and crypto.hmac_sha256_binary(key, rule.region)
    key = key and crypto.hmac_sha256_binary(key, rule.service)
    key = key and crypto.hmac_sha256_binary(key, "aws4_request")
    local signature = key and crypto.hmac_sha256_hex(key, string_to_sign)
    if not signature then return nil end
    headers.authorization = "AWS4-HMAC-SHA256 Credential=" .. credential.access_key_id .. "/" .. scope
        .. ", SignedHeaders=" .. names .. ", Signature=" .. signature
    return headers
end

local function sign_oss(rule, method, encoded_path, query_pairs, range_value, credential, now)
    local datetime = os.date("!%Y%m%dT%H%M%SZ", now)
    local date = os.date("!%Y%m%d", now)
    local headers = { host = rule.endpoint.host, ["x-oss-content-sha256"] = "UNSIGNED-PAYLOAD", ["x-oss-date"] = datetime }
    local additional = { "host" }
    if range_value then headers.range = range_value; additional[#additional + 1] = "range" end
    if credential.session_token ~= "" then headers["x-oss-security-token"] = credential.session_token end
    local canonical = canonical_headers(headers)
    if not canonical then return nil end
    local additional_names = table.concat(additional, ";")
    local request = method .. "\n/" .. rule.bucket .. encoded_path .. "\n" .. canonical_query(query_pairs, true)
        .. "\n" .. canonical .. "\n" .. additional_names .. "\nUNSIGNED-PAYLOAD"
    local scope = date .. "/" .. rule.region .. "/" .. rule.service .. "/aliyun_v4_request"
    local string_to_sign = "OSS4-HMAC-SHA256\n" .. datetime .. "\n" .. scope .. "\n" .. crypto.sha256_hex(request)
    local key = crypto.hmac_sha256_binary("aliyun_v4" .. credential.secret_access_key, date)
    key = key and crypto.hmac_sha256_binary(key, rule.region)
    key = key and crypto.hmac_sha256_binary(key, rule.service)
    key = key and crypto.hmac_sha256_binary(key, "aliyun_v4_request")
    local signature = key and crypto.hmac_sha256_hex(key, string_to_sign)
    if not signature then return nil end
    headers.authorization = "OSS4-HMAC-SHA256 Credential=" .. credential.access_key_id .. "/" .. scope
        .. ",AdditionalHeaders=" .. additional_names .. ",Signature=" .. signature
    return headers
end

local function sign_cos(rule, method, decoded_path, query_pairs, range_value, credential, now)
    local key_time = now .. ";" .. now + rule.signature_ttl_seconds
    local headers = { host = rule.endpoint.host }
    if range_value then headers.range = range_value end
    if credential.session_token ~= "" then headers["x-cos-security-token"] = credential.session_token end
    local names = {}
    for name in pairs(headers) do names[#names + 1] = name end
    table.sort(names)
    local formatted = {}
    for _, name in ipairs(names) do
        local value = normalized_header(headers[name])
        if not value then return nil end
        formatted[#formatted + 1] = string.lower(percent_encode(name, false)) .. "=" .. percent_encode(value, false)
    end
    local query, query_names = cos_query(query_pairs)
    local format_string = string.lower(method) .. "\n" .. decoded_path .. "\n" .. query .. "\n" .. table.concat(formatted, "&") .. "\n"
    local string_to_sign = "sha1\n" .. key_time .. "\n" .. crypto.sha1_hex(format_string) .. "\n"
    local sign_key = crypto.hmac_sha1_hex(credential.secret_access_key, key_time)
    local signature = sign_key and crypto.hmac_sha1_hex(sign_key, string_to_sign)
    if not signature then return nil end
    headers.authorization = "q-sign-algorithm=sha1&q-ak=" .. credential.access_key_id
        .. "&q-sign-time=" .. key_time .. "&q-key-time=" .. key_time .. "&q-header-list=" .. table.concat(names, ";")
        .. "&q-url-param-list=" .. query_names .. "&q-signature=" .. signature
    return headers
end

-- request_parts is the origin request target. strip_prefix is the loopback
-- prewarm location's internal prefix, which its rewrite (^prefix(.*)$ -> /$1)
-- removes before proxying; the client's raw target must carry it literally.
local function request_parts(strip_prefix)
    local request_uri = ngx.var.request_uri
    if type(request_uri) ~= "string" or #request_uri == 0 or #request_uri > MAX_PATH_BYTES + MAX_QUERY_BYTES + 1
        or contains_control(request_uri) or request_uri:find("#", 1, true) then return nil end
    if strip_prefix then
        if request_uri:sub(1, #strip_prefix) ~= strip_prefix then return nil end
        request_uri = "/" .. request_uri:sub(#strip_prefix + 1)
    end
    local question = request_uri:find("?", 1, true)
    local raw_path = question and request_uri:sub(1, question - 1) or request_uri
    local raw_query = question and request_uri:sub(question + 1) or nil
    local encoded_path, decoded_path = canonical_path(raw_path)
    if not encoded_path or decoded_path ~= ngx.var.uri then return nil end
    local query_pairs = parse_query(raw_query)
    if not query_pairs then return nil end
    return encoded_path, decoded_path, query_pairs
end

local function range_header(value)
    if value == nil then return nil, true end
    if type(value) ~= "string" or #value > 128
        or not value:match("^bytes=%d+%-%d*$") and not value:match("^bytes=%-%d+$") then return nil, false end
    return value, true
end

local function reject_request(status, code)
    ngx.ctx.cdnca_origin_auth_reject_code = code
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.status = status
    ngx.say(status == ngx.HTTP_FORBIDDEN and "Forbidden" or "Service Unavailable")
    return ngx.exit(status)
end

function _M.init(options)
    if type(options) ~= "table" or not safe_absolute_path(options.policy_path) then
        error("invalid origin auth engine options")
    end
    if options.reload_interval ~= nil and (type(options.reload_interval) ~= "number"
        or options.reload_interval < 0.05 or options.reload_interval > 60) then
        error("invalid origin auth reload interval")
    end
    policy_path = options.policy_path
    fallback_path = policy_path:match("^(.*)/[^/]+$") .. "/fallback.json"
    reload_interval = options.reload_interval or 1
    next_reload_at = 0
    local ok, load_error = reload(true)
    if not ok and not current_policy then error("no valid origin auth policy code=" .. tostring(load_error)) end
    return current_policy.policy_version
end

-- ensure keeps a worker usable when the master could not load the policy at
-- start: it binds the path so access reloads (and refuses until it loads).
function _M.ensure(path)
    if policy_path == nil and safe_absolute_path(path) then
        policy_path = path
        fallback_path = path:match("^(.*)/[^/]+$") .. "/fallback.json"
        reload_interval = reload_interval or 1
        next_reload_at = 0
    end
end

function _M.policy_version()
    reload(false)
    return current_policy and current_policy.policy_version or 0
end

function _M.access(context)
    reload(false)
    local policy = current_policy
    if not policy then return reject_request(ngx.HTTP_SERVICE_UNAVAILABLE, "policy_unavailable") end
    if not has_only(context, { rule_id = true, endpoint = true, strip_prefix = true }) or not identifier(context.rule_id, 128)
        or context.strip_prefix ~= nil and (type(context.strip_prefix) ~= "string"
            or not context.strip_prefix:match("^/%.cdnca%-internal/cache%-task/v2/%x+/$")) then
        return reject_request(ngx.HTTP_FORBIDDEN, "context_invalid")
    end
    local ok = _M.sign(policy.rule_by_id[context.rule_id], context.endpoint, context.strip_prefix)
    ngx.ctx.cdnca_origin_auth_policy_version = policy.policy_version
    return ok, context.endpoint
end

-- sign(rule, endpoint, strip_prefix): sign the current request for a
-- validated rule whose keys carry their credential (.credential); refuses
-- (403/503, request ended) whatever cannot be signed. Shared by access()
-- (v7 policy files) and dynroute/cdnca_originauth (secret objects).
function _M.sign(rule, endpoint, strip_prefix)
    if not rule or endpoint ~= "https://" .. rule.endpoint.host then
        return reject_request(ngx.HTTP_FORBIDDEN, "endpoint_mismatch")
    end
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then return reject_request(ngx.HTTP_FORBIDDEN, "method_not_allowed") end
    local request_headers, header_error = ngx.req.get_headers(128, true)
    if header_error == "truncated" then return reject_request(ngx.HTTP_FORBIDDEN, "headers_invalid") end
    local range_value
    local content_length
    local transfer_encoding
    for name, value in pairs(request_headers) do
        local lower = string.lower(name)
        if lower == "authorization" or lower:sub(1, 6) == "x-amz-" or lower:sub(1, 6) == "x-oss-" or lower:sub(1, 6) == "x-cos-" then
            return reject_request(ngx.HTTP_FORBIDDEN, "auth_header_conflict")
        end
        if lower == "range" then range_value = value end
        if lower == "content-length" then content_length = value end
        if lower == "transfer-encoding" then transfer_encoding = value end
    end
    if transfer_encoding or content_length and content_length ~= "0" then
        return reject_request(ngx.HTTP_FORBIDDEN, "body_not_allowed")
    end
    local range_ok
    range_value, range_ok = range_header(range_value)
    if not range_ok then return reject_request(ngx.HTTP_FORBIDDEN, "range_invalid") end
    local encoded_path, decoded_path, query_pairs = request_parts(strip_prefix)
    if not encoded_path then return reject_request(ngx.HTTP_FORBIDDEN, "request_target_invalid") end
    if rule.path_prefix ~= "/" and encoded_path:sub(1, #rule.path_prefix) ~= rule.path_prefix then
        return reject_request(ngx.HTTP_FORBIDDEN, "path_not_allowed")
    end
    local now = ngx.time()
    local key = rule.current_key
    if rule.previous_key and now < rule.activate_current_at_unix then key = rule.previous_key end
    local credential = key.credential
    if now < credential.not_before_unix or now >= credential.expires_at_unix
        or credential.expires_at_unix <= now + rule.signature_ttl_seconds then
        return reject_request(ngx.HTTP_SERVICE_UNAVAILABLE, "credential_unavailable")
    end
    local signed
    if rule.provider == "s3" then
        signed = sign_s3(rule, method, encoded_path, query_pairs, range_value, credential, now)
    elseif rule.provider == "oss" then
        signed = sign_oss(rule, method, encoded_path, query_pairs, range_value, credential, now)
    else
        signed = sign_cos(rule, method, decoded_path, query_pairs, range_value, credential, now)
    end
    if not signed then return reject_request(ngx.HTTP_SERVICE_UNAVAILABLE, "signing_failed") end
    for name, value in pairs(signed) do ngx.req.set_header(name, value) end
    ngx.ctx.cdnca_origin_auth_rule_id = rule.rule_id
    return true
end

-- Validators for the dynamic routing secret object (same rule semantics as
-- the policy file; keys hold the credential inline instead of a file).
_M.validate_rule = validate_rule
_M.valid_credential = valid_credential
_M.identifier = identifier
_M.has_only = has_only
_M.rule_fields = rule_fields

return _M
