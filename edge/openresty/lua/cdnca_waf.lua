local cjson = require "cjson.safe"
local resty_lock = require "resty.lock"
local resty_sha256 = require "resty.sha256"
local resty_string = require "resty.string"

-- The public port. A composed node dispatches plaintext and TLS that share one
-- port through internal unix sockets, where $server_port is empty; those
-- listeners alone accept PROXY protocol, which carries the public port.
local function public_server_port()
    return ngx.var.proxy_protocol_server_port or ngx.var.server_port
end

local _M = {}

local SCHEMA_VERSION_V1 = "cdnca.edge.waf/v1"
local SCHEMA_VERSION_V2 = "cdnca.edge.waf/v2"
local MAX_POLICY_BYTES = 1048576
local MAX_POLICY_VERSION = 9007199254740991
local MAX_RULES = 512
local MAX_RULE_ID_BYTES = 128
local MAX_HOST_BYTES = 253
local MAX_METHOD_BYTES = 32
local MAX_PATH_BYTES = 1024
local MAX_NAME_BYTES = 128
local MAX_VALUE_BYTES = 1024
local MAX_USER_AGENT_BYTES = 512
local MAX_COMMENT_BYTES = 256
local MAX_JSON_DEPTH = 32
local MAX_REQUEST_FIELDS = 100
local MAX_GEO_RANGES = 4096
local MAX_TRUSTED_PROXIES = 64
local MAX_TRUSTED_CRAWLERS = 64
local MAX_CRAWLER_NETWORKS = 64
local MAX_CRAWLER_USER_AGENTS = 64
local MAX_PROXY_HOPS = 16
local MAX_REQUEST_PATH_BYTES = 4096
local MAX_REQUEST_VALUE_BYTES = 4096
local BLOCK_STATUS = 403
local RELOAD_INTERVAL_SECONDS = 0.25
local CLOCK_DICT = "cdnca_waf_clock"
local LOCK_DICT = "cdnca_waf_locks"
local CLOCK_LOCK_TIMEOUT_SECONDS = 0.05
local CLOCK_LOCK_EXPTIME_SECONDS = 0.5
local MIN_SHARED_DICT_BYTES = 1048576

local states = {}

local function is_integer(value)
    return type(value) == "number" and value >= 0 and value == math.floor(value)
end

local function valid_utf8(value)
    local index = 1
    while index <= #value do
        local first = string.byte(value, index)
        if first < 128 then
            index = index + 1
        else
            local length
            local minimum_second = 128
            local maximum_second = 191
            if first >= 194 and first <= 223 then
                length = 2
            elseif first >= 224 and first <= 239 then
                length = 3
                if first == 224 then
                    minimum_second = 160
                elseif first == 237 then
                    maximum_second = 159
                end
            elseif first >= 240 and first <= 244 then
                length = 4
                if first == 240 then
                    minimum_second = 144
                elseif first == 244 then
                    maximum_second = 143
                end
            else
                return false
            end
            if index + length - 1 > #value then
                return false
            end
            local second = string.byte(value, index + 1)
            if second < minimum_second or second > maximum_second then
                return false
            end
            for offset = 2, length - 1 do
                local byte = string.byte(value, index + offset)
                if byte < 128 or byte > 191 then
                    return false
                end
            end
            index = index + length
        end
    end
    return true
end

local function utf8_codepoint(value, index)
    local first = string.byte(value, index)
    if first < 128 then
        return first, index + 1
    end
    local second = string.byte(value, index + 1)
    if first < 224 then
        return (first - 192) * 64 + second - 128, index + 2
    end
    local third = string.byte(value, index + 2)
    if first < 240 then
        return (first - 224) * 4096 + (second - 128) * 64 + third - 128, index + 3
    end
    local fourth = string.byte(value, index + 3)
    return (first - 240) * 262144 + (second - 128) * 4096 + (third - 128) * 64 + fourth - 128, index + 4
end

local function is_unicode_whitespace(codepoint)
    return (codepoint >= 9 and codepoint <= 13) or codepoint == 32 or codepoint == 133 or
        codepoint == 160 or codepoint == 5760 or (codepoint >= 8192 and codepoint <= 8202) or
        codepoint == 8232 or codepoint == 8233 or codepoint == 8239 or codepoint == 8287 or codepoint == 12288
end

local function has_non_whitespace(value)
    local index = 1
    while index <= #value do
        local codepoint
        codepoint, index = utf8_codepoint(value, index)
        if not is_unicode_whitespace(codepoint) then
            return true
        end
    end
    return false
end

local function has_control(value)
    for index = 1, #value do
        local byte = string.byte(value, index)
        if byte < 32 or byte == 127 then
            return true
        end
        if byte == 194 and index < #value then
            local following = string.byte(value, index + 1)
            if following >= 128 and following <= 159 then
                return true
            end
        end
    end
    return false
end

local function bounded_string(value, maximum, allow_empty)
    return type(value) == "string" and (allow_empty or #value > 0) and #value <= maximum and
        valid_utf8(value) and not has_control(value)
end

local function only_keys(value, allowed)
    if type(value) ~= "table" then
        return false
    end
    for key, _ in pairs(value) do
        if type(key) ~= "string" or not allowed[key] then
            return false
        end
    end
    return true
end

local function array_length(value)
    if type(value) ~= "table" then
        return nil
    end
    local count = 0
    local maximum = 0
    for key, _ in pairs(value) do
        if not is_integer(key) or key < 1 then
            return nil
        end
        count = count + 1
        if key > maximum then
            maximum = key
        end
    end
    if count ~= maximum then
        return nil
    end
    return count
end

local function skip_json_space(raw, index)
    while index <= #raw do
        local byte = string.byte(raw, index)
        if byte ~= 9 and byte ~= 10 and byte ~= 13 and byte ~= 32 then
            break
        end
        index = index + 1
    end
    return index
end

local function scan_json_string(raw, index)
    if string.byte(raw, index) ~= 34 then
        return nil
    end
    local finish = index + 1
    while finish <= #raw do
        local byte = string.byte(raw, finish)
        if byte == 34 then
            local value, err = cjson.decode(string.sub(raw, index, finish))
            if err or type(value) ~= "string" then
                return nil
            end
            return finish + 1, value
        end
        if byte == 92 then
            finish = finish + 1
            if finish > #raw then
                return nil
            end
        elseif byte < 32 then
            return nil
        end
        finish = finish + 1
    end
    return nil
end

local scan_json_value

local function scan_json_object(raw, index, depth)
    local keys = {}
    index = skip_json_space(raw, index + 1)
    if string.byte(raw, index) == 125 then
        return index + 1
    end
    while index <= #raw do
        local key_end, key = scan_json_string(raw, index)
        if not key_end or keys[key] then
            return nil
        end
        keys[key] = true
        index = skip_json_space(raw, key_end)
        if string.byte(raw, index) ~= 58 then
            return nil
        end
        index = skip_json_space(raw, index + 1)
        if depth == 1 and key == "rules" and string.byte(raw, index) ~= 91 then
            return nil
        end
        index = scan_json_value(raw, index, depth)
        if not index then
            return nil
        end
        index = skip_json_space(raw, index)
        local byte = string.byte(raw, index)
        if byte == 125 then
            return index + 1
        end
        if byte ~= 44 then
            return nil
        end
        index = skip_json_space(raw, index + 1)
    end
    return nil
end

local function scan_json_array(raw, index, depth)
    index = skip_json_space(raw, index + 1)
    if string.byte(raw, index) == 93 then
        return index + 1
    end
    while index <= #raw do
        index = scan_json_value(raw, index, depth)
        if not index then
            return nil
        end
        index = skip_json_space(raw, index)
        local byte = string.byte(raw, index)
        if byte == 93 then
            return index + 1
        end
        if byte ~= 44 then
            return nil
        end
        index = skip_json_space(raw, index + 1)
    end
    return nil
end

scan_json_value = function(raw, index, depth)
    if depth > MAX_JSON_DEPTH then
        return nil
    end
    index = skip_json_space(raw, index)
    local byte = string.byte(raw, index)
    if byte == 123 then
        return scan_json_object(raw, index, depth + 1)
    end
    if byte == 91 then
        return scan_json_array(raw, index, depth + 1)
    end
    if byte == 34 then
        return scan_json_string(raw, index)
    end
    local finish = index
    while finish <= #raw do
        byte = string.byte(raw, finish)
        if byte == 9 or byte == 10 or byte == 13 or byte == 32 or byte == 44 or byte == 93 or byte == 125 then
            break
        end
        finish = finish + 1
    end
    if finish == index then
        return nil
    end
    local _, err = cjson.decode(string.sub(raw, index, finish - 1))
    if err then
        return nil
    end
    return finish
end

local function valid_json_keys(raw)
    local finish = scan_json_value(raw, 1, 0)
    return finish ~= nil and skip_json_space(raw, finish) == #raw + 1
end

local function valid_rule_id(value)
    if not bounded_string(value, MAX_RULE_ID_BYTES, false) then
        return false
    end
    for index = 1, #value do
        local byte = string.byte(value, index)
        local valid = (byte >= 48 and byte <= 57) or (byte >= 65 and byte <= 90) or
            (byte >= 97 and byte <= 122) or byte == 45 or byte == 46 or byte == 58 or byte == 95
        if not valid then
            return false
        end
    end
    return true
end

local token_separators = {
    [32] = true, [34] = true, [40] = true, [41] = true, [44] = true, [47] = true,
    [58] = true, [59] = true, [60] = true, [61] = true, [62] = true, [63] = true,
    [64] = true, [91] = true, [92] = true, [93] = true, [123] = true, [125] = true,
}

local function valid_token(value, maximum)
    if not bounded_string(value, maximum, false) then
        return false
    end
    for index = 1, #value do
        local byte = string.byte(value, index)
        if byte < 33 or byte > 126 or token_separators[byte] then
            return false
        end
    end
    return true
end

local function valid_path(value)
    if not bounded_string(value, MAX_PATH_BYTES, false) or string.sub(value, 1, 1) ~= "/" then
        return false
    end
    if string.find(value, "\\", 1, true) or string.find(value, "%", 1, true) or
        string.find(value, "?", 1, true) or string.find(value, "#", 1, true) or
        string.find(value, "//", 1, true) then
        return false
    end
    local segments = {}
    local start = 2
    while start <= #value + 1 do
        local finish = string.find(value, "/", start, true)
        local segment
        if finish then
            segment = string.sub(value, start, finish - 1)
            start = finish + 1
        else
            segment = string.sub(value, start)
            start = #value + 2
        end
        if segment == "." or segment == ".." then
            return false
        end
        segments[#segments + 1] = segment
    end
    return true
end

local function validate_value_match(value, header)
    if not only_keys(value, {name = true, operator = true, value = true}) then
        return false
    end
    if not bounded_string(value.name, MAX_NAME_BYTES, false) then
        return false
    end
    if header and (value.name ~= string.lower(value.name) or not valid_token(value.name, MAX_NAME_BYTES)) then
        return false
    end
    if value.operator == "exists" then
        return value.value == nil
    end
    return value.operator == "exact" and bounded_string(value.value, MAX_VALUE_BYTES, true)
end

local function validate_user_agent_match(value)
    if not only_keys(value, {operator = true, value = true}) then return false end
    if value.operator == "exists" then return value.value == nil end
    return value.operator == "exact" and bounded_string(value.value, MAX_USER_AGENT_BYTES, false)
end

local function validate_cidr(value)
    if not only_keys(value, {family = true, network = true, prefix_length = true}) then
        return false
    end
    if value.family ~= 4 and value.family ~= 6 then
        return false
    end
    local expected = value.family == 4 and 4 or 16
    if array_length(value.network) ~= expected or not is_integer(value.prefix_length) or
        value.prefix_length > expected * 8 then
        return false
    end
    for index = 1, expected do
        if not is_integer(value.network[index]) or value.network[index] > 255 then
            return false
        end
    end
    local full_bytes = math.floor(value.prefix_length / 8)
    local remaining = value.prefix_length % 8
    if remaining > 0 then
        local divisor = 2 ^ (8 - remaining)
        if value.network[full_bytes + 1] % divisor ~= 0 then
            return false
        end
        full_bytes = full_bytes + 1
    end
    for index = full_bytes + 1, expected do
        if value.network[index] ~= 0 then
            return false
        end
    end
    if value.family == 6 then
        local mapped = true
        for index = 1, 10 do
            if value.network[index] ~= 0 then
                mapped = false
                break
            end
        end
        if mapped and value.network[11] == 255 and value.network[12] == 255 then
            return false
        end
    end
    return true
end

local function validate_trusted_cidr(value)
    if not validate_cidr(value) or value.prefix_length == 0 then return false end
    local network = value.network
    if value.family == 4 then
        local unspecified = network[1] == 0 and network[2] == 0 and network[3] == 0 and network[4] == 0
        return not unspecified and network[1] ~= 127 and not (network[1] >= 224 and network[1] <= 239) and
            not (network[1] == 169 and network[2] == 254)
    end
    local unspecified = true
    for index = 1, 16 do
        if network[index] ~= 0 then unspecified = false; break end
    end
    local loopback = true
    for index = 1, 15 do
        if network[index] ~= 0 then loopback = false; break end
    end
    loopback = loopback and network[16] == 1
    return not unspecified and not loopback and network[1] ~= 255 and
        not (network[1] == 254 and network[2] >= 128 and network[2] <= 191)
end

local function validate_match(value)
    if not only_keys(value, {
        host = true, port = true, method = true, path = true,
        query = true, header = true, user_agent = true, source_cidr = true, country = true,
    }) then
        return false
    end
    local conditions = 0
    if value.host ~= nil then
        if not bounded_string(value.host, MAX_HOST_BYTES, false) or value.host ~= string.lower(value.host) then
            return false
        end
        conditions = conditions + 1
    end
    if value.port ~= nil then
        if not is_integer(value.port) or value.port < 1 or value.port > 65535 then
            return false
        end
        conditions = conditions + 1
    end
    if value.method ~= nil then
        if not valid_token(value.method, MAX_METHOD_BYTES) or value.method ~= string.upper(value.method) then
            return false
        end
        conditions = conditions + 1
    end
    if value.path ~= nil then
        if not only_keys(value.path, {kind = true, value = true}) or
            (value.path.kind ~= "exact" and value.path.kind ~= "prefix" and value.path.kind ~= "raw_prefix") or
            not valid_path(value.path.value) then
            return false
        end
        conditions = conditions + 1
    end
    if value.query ~= nil then
        if not validate_value_match(value.query, false) then
            return false
        end
        conditions = conditions + 1
    end
    if value.header ~= nil then
        if not validate_value_match(value.header, true) then
            return false
        end
        conditions = conditions + 1
    end
    if value.user_agent ~= nil then
        if not validate_user_agent_match(value.user_agent) then return false end
        conditions = conditions + 1
    end
    if value.source_cidr ~= nil then
        if not validate_cidr(value.source_cidr) then
            return false
        end
        conditions = conditions + 1
    end
    if value.country ~= nil then
        if not only_keys(value.country, {operator = true, values = true}) or
            (value.country.operator ~= "in" and value.country.operator ~= "not_in") then
            return false
        end
        local length = array_length(value.country.values)
        if not length or length < 1 or length > 64 then return false end
        local previous = ""
        for index = 1, length do
            local country = value.country.values[index]
            if type(country) ~= "string" or not country:match("^[A-Z][A-Z]$") or country <= previous then return false end
            previous = country
        end
        conditions = conditions + 1
    end
    return conditions > 0
end

local function validate_policy(policy)
    if not only_keys(policy, {
        schema_version = true, policy_version = true, client_source = true,
        trusted_crawlers = true, geo = true, unknown_geo_action = true, rules = true,
    }) or (policy.schema_version ~= SCHEMA_VERSION_V1 and policy.schema_version ~= SCHEMA_VERSION_V2) or
        not is_integer(policy.policy_version) or
        policy.policy_version < 1 or policy.policy_version > MAX_POLICY_VERSION then
        return false
    end
    if policy.schema_version == SCHEMA_VERSION_V1 and
        (policy.client_source ~= nil or policy.trusted_crawlers ~= nil or policy.unknown_geo_action ~= nil) then return false end
    if policy.client_source ~= nil then
        local source = policy.client_source
        if policy.schema_version ~= SCHEMA_VERSION_V2 or not only_keys(source, {
            header = true, max_hops = true, trusted_proxy_cidrs = true,
        }) or source.header ~= "x-forwarded-for" or not is_integer(source.max_hops) or
            source.max_hops < 1 or source.max_hops > MAX_PROXY_HOPS then return false end
        local proxies = array_length(source.trusted_proxy_cidrs)
        if not proxies or proxies < 1 or proxies > MAX_TRUSTED_PROXIES then return false end
        for index = 1, proxies do
            local cidr = source.trusted_proxy_cidrs[index]
            if not validate_trusted_cidr(cidr) then return false end
        end
    end
    local crawler_count = policy.trusted_crawlers == nil and 0 or array_length(policy.trusted_crawlers)
    if crawler_count == nil or crawler_count > MAX_TRUSTED_CRAWLERS or
        crawler_count > 0 and policy.schema_version ~= SCHEMA_VERSION_V2 then return false end
    for index = 1, crawler_count do
        local crawler = policy.trusted_crawlers[index]
        if not only_keys(crawler, {networks = true, user_agent_prefixes = true}) then return false end
        local networks = array_length(crawler.networks)
        local prefixes = array_length(crawler.user_agent_prefixes)
        if not networks or networks < 1 or networks > MAX_CRAWLER_NETWORKS or
            not prefixes or prefixes < 1 or prefixes > MAX_CRAWLER_USER_AGENTS then return false end
        for network = 1, networks do
            local cidr = crawler.networks[network]
            if not validate_trusted_cidr(cidr) then return false end
        end
        local previous = ""
        for prefix = 1, prefixes do
            local value = crawler.user_agent_prefixes[prefix]
            if not bounded_string(value, MAX_VALUE_BYTES, false) or value <= previous then return false end
            previous = value
        end
    end
    local count = array_length(policy.rules)
    if count == nil or count > MAX_RULES then
        return false
    end
    local geo_count = policy.geo == nil and 0 or array_length(policy.geo)
    if geo_count == nil or geo_count > MAX_GEO_RANGES then return false end
    for index = 1, geo_count do
        local item = policy.geo[index]
        if not only_keys(item, {cidr = true, country = true}) or not validate_cidr(item.cidr) or
            type(item.country) ~= "string" or not item.country:match("^[A-Z][A-Z]$") then return false end
    end
    local ids = {}
    local previous_priority = -1
    local previous_id = ""
    local has_country_rule = false
    for index = 1, count do
        local rule = policy.rules[index]
        if not only_keys(rule, {
            rule_id = true, priority = true, action = true, flow = true, match = true,
            comment = true, expires_at_unix = true,
        }) or
            not valid_rule_id(rule.rule_id) or ids[rule.rule_id] or
            not is_integer(rule.priority) or rule.priority > 4294967295 or
            (rule.action ~= "allow" and rule.action ~= "block" and rule.action ~= "log") or
            (rule.flow ~= "continue" and rule.flow ~= "stop") or not validate_match(rule.match) then
            return false
        end
        if rule.match.country ~= nil then
            if geo_count == 0 then return false end
            has_country_rule = true
        end
        if rule.comment ~= nil then
            if not bounded_string(rule.comment, MAX_COMMENT_BYTES, false) or not has_non_whitespace(rule.comment) then
                return false
            end
        end
        if rule.expires_at_unix ~= nil and (not is_integer(rule.expires_at_unix) or
            rule.expires_at_unix < 1 or rule.expires_at_unix > MAX_POLICY_VERSION) then
            return false
        end
        if (rule.comment ~= nil or rule.expires_at_unix ~= nil) and rule.match.source_cidr == nil then
            return false
        end
        if rule.priority < previous_priority or (rule.priority == previous_priority and rule.rule_id <= previous_id) then
            return false
        end
        ids[rule.rule_id] = true
        previous_priority = rule.priority
        previous_id = rule.rule_id
    end
    if policy.schema_version == SCHEMA_VERSION_V2 then
        if has_country_rule and policy.unknown_geo_action ~= "allow" and policy.unknown_geo_action ~= "block" then
            return false
        end
        if not has_country_rule and policy.unknown_geo_action ~= nil then return false end
    end
    return true
end

local function read_policy(path)
    local file = io.open(path, "rb")
    if not file then
        return nil
    end
    local raw = file:read(MAX_POLICY_BYTES + 1)
    file:close()
    if not raw or #raw == 0 or #raw > MAX_POLICY_BYTES then
        return nil
    end
    return raw
end

local function decode_policy(raw)
    if not raw or not valid_json_keys(raw) then
        return nil
    end
    local candidate = cjson.decode(raw)
    if not candidate or not validate_policy(candidate) then
        return nil
    end
    return candidate
end

local function read_sealed_fallback(path)
    local directory = path:match("^(.*)/[^/]+$")
    if not directory then
        return nil
    end
    local fallback_raw = read_policy(directory .. "/fallback.json")
    local candidate = decode_policy(fallback_raw)
    if not candidate then
        return nil
    end
    local version_path = directory .. "/versions/" .. string.format("%020.0f", candidate.policy_version) .. ".json"
    if read_policy(version_path) ~= fallback_raw then
        return nil
    end
    return fallback_raw, candidate
end

local function emit(reason, rule_id, version)
    ngx.log(ngx.NOTICE, "cdnca_waf reason=", reason, " rule_id=", rule_id or "-", " policy_version=", version or 0)
end

local function emit_decision(action, reason, rule_id, version)
    ngx.log(ngx.NOTICE, "cdnca_waf decision action=", action, " reason=", reason,
        " rule_id=", rule_id or "-", " policy_version=", version)
end

local function export_telemetry(enabled, action, rule_id, version, should_emit)
    if not enabled then
        return
    end
    local safe_rule_id = rule_id and valid_rule_id(rule_id) and rule_id or "-"
    local severity = action == "block" and "high" or "info"
    local ok = pcall(function()
        ngx.var.cdnca_security_emit = "0"
        ngx.var.cdnca_security_type = "waf"
        ngx.var.cdnca_security_action = action
        ngx.var.cdnca_security_severity = severity
        ngx.var.cdnca_security_rule_id = safe_rule_id
        if should_emit then
            ngx.var.cdnca_security_emit = "1"
        end
    end)
    if not ok then
        emit("telemetry_unavailable", safe_rule_id, version)
    end
    if action == "block" then
        -- FX60: the 403 is a node-answered block page (not billed traffic).
        -- Servers rendered before the variable existed simply do not tag.
        pcall(function() ngx.var.cdnca_security_block_page = "1" end)
    end
end

local function load_policy(path)
    local state = states[path]
    if not state then
        state = {}
        states[path] = state
    end
    local now = ngx.now()
    if state.next_check and now < state.next_check then
        return state.policy, state
    end
    state.next_check = now + RELOAD_INTERVAL_SECONDS
    local current_raw = read_policy(path)
    if current_raw and current_raw == state.good_raw then
        return state.policy, state
    end
    if current_raw and current_raw == state.bad_raw and state.policy then
        return state.policy, state
    end
    local raw = current_raw
    local candidate = decode_policy(raw)
    if not candidate and not state.policy then
        raw, candidate = read_sealed_fallback(path)
    end
    if not candidate or (state.policy and candidate.policy_version <= state.policy.policy_version) then
        local rejected_raw = current_raw or false
        if state.bad_raw ~= rejected_raw then
            emit("policy_rejected", nil, state.policy and state.policy.policy_version)
        end
        state.bad_raw = rejected_raw
        return state.policy, state
    end
    state.policy = candidate
    state.good_raw = raw
    state.bad_raw = nil
    emit("policy_loaded", nil, candidate.policy_version)
    return candidate, state
end

local function clock_key(path)
    local digest = resty_sha256:new()
    if not digest or digest:update(path) ~= true then
        return nil
    end
    local binary = digest:final()
    if type(binary) ~= "string" or #binary ~= 32 then
        return nil
    end
    local hex = resty_string.to_hex(binary)
    if type(hex) ~= "string" or #hex ~= 64 or string.find(hex, "[^0-9a-f]") then
        return nil
    end
    return hex
end

local function valid_shared_time(value)
    return value == nil or (is_integer(value) and value >= 1 and value <= MAX_POLICY_VERSION)
end

local function has_required_capacity(dictionary)
    if not dictionary then
        return false
    end
    local ok, capacity = pcall(function()
        return dictionary:capacity()
    end)
    return ok and is_integer(capacity) and capacity >= MIN_SHARED_DICT_BYTES and capacity <= MAX_POLICY_VERSION
end

local function effective_time(path)
    local clock = ngx.shared[CLOCK_DICT]
    local locks = ngx.shared[LOCK_DICT]
    local now = ngx.time()
    local digest = clock_key(path)
    if not has_required_capacity(clock) or not has_required_capacity(locks) or
        not digest or not is_integer(now) or now < 1 or now > MAX_POLICY_VERSION then
        return nil
    end
    local key = "clock:" .. digest
    local current = clock:get(key)
    if not valid_shared_time(current) then
        return nil
    end
    if current and now <= current then
        return current
    end
    local lock, err = resty_lock:new(LOCK_DICT, {
        timeout = CLOCK_LOCK_TIMEOUT_SECONDS,
        exptime = CLOCK_LOCK_EXPTIME_SECONDS,
    })
    if not lock then
        return nil
    end
    local elapsed
    elapsed, err = lock:lock("clock-lock:" .. digest)
    if type(elapsed) ~= "number" or elapsed < 0 or elapsed > CLOCK_LOCK_TIMEOUT_SECONDS then
        return nil
    end
    current = clock:get(key)
    local result = current
    local ok = valid_shared_time(current)
    if ok and (not current or now > current) then
        result = now
        ok = clock:safe_set(key, result) == true
    end
    local unlocked = lock:unlock()
    if not ok or unlocked ~= 1 then
        return nil
    end
    return result
end

local function split_plain(value, separator)
    local result = {}
    local start = 1
    while true do
        local finish = string.find(value, separator, start, true)
        if not finish then
            result[#result + 1] = string.sub(value, start)
            return result
        end
        result[#result + 1] = string.sub(value, start, finish - 1)
        start = finish + #separator
    end
end

local function parse_ipv4(value)
    local parts = split_plain(value, ".")
    if #parts ~= 4 then
        return nil
    end
    local bytes = {}
    for index = 1, 4 do
        if parts[index] == "" or #parts[index] > 3 then
            return nil
        end
        for character = 1, #parts[index] do
            local byte = string.byte(parts[index], character)
            if byte < 48 or byte > 57 then
                return nil
            end
        end
        local number = tonumber(parts[index], 10)
        if not number or number > 255 then
            return nil
        end
        bytes[index] = number
    end
    return bytes
end

local function parse_hex_groups(value)
    if value == "" then
        return {}
    end
    local groups = split_plain(value, ":")
    for index = 1, #groups do
        if groups[index] == "" or #groups[index] > 4 then
            return nil
        end
        local number = tonumber(groups[index], 16)
        if not number or number > 65535 then
            return nil
        end
        groups[index] = number
    end
    return groups
end

local function parse_ipv6(value)
    if string.find(value, "%", 1, true) then
        return nil
    end
    if string.find(value, ".", 1, true) then
        local last_colon = nil
        local search = 1
        while true do
            local found = string.find(value, ":", search, true)
            if not found then
                break
            end
            last_colon = found
            search = found + 1
        end
        if not last_colon then
            return nil
        end
        local ipv4 = parse_ipv4(string.sub(value, last_colon + 1))
        if not ipv4 then
            return nil
        end
        value = string.sub(value, 1, last_colon) .. string.format("%x:%x", ipv4[1] * 256 + ipv4[2], ipv4[3] * 256 + ipv4[4])
    end

    local double = string.find(value, "::", 1, true)
    if double and string.find(value, "::", double + 2, true) then
        return nil
    end
    local groups = {}
    if double then
        local left = parse_hex_groups(string.sub(value, 1, double - 1))
        local right = parse_hex_groups(string.sub(value, double + 2))
        if not left or not right or #left + #right >= 8 then
            return nil
        end
        for index = 1, #left do
            groups[#groups + 1] = left[index]
        end
        for _ = 1, 8 - #left - #right do
            groups[#groups + 1] = 0
        end
        for index = 1, #right do
            groups[#groups + 1] = right[index]
        end
    else
        groups = parse_hex_groups(value)
        if not groups or #groups ~= 8 then
            return nil
        end
    end

    local bytes = {}
    for index = 1, 8 do
        bytes[#bytes + 1] = math.floor(groups[index] / 256)
        bytes[#bytes + 1] = groups[index] % 256
    end
    local mapped = true
    for index = 1, 10 do
        if bytes[index] ~= 0 then
            mapped = false
            break
        end
    end
    mapped = mapped and bytes[11] == 255 and bytes[12] == 255
    if mapped then
        return nil
    end
    return bytes
end

local function parse_address(value)
    if type(value) ~= "string" or #value == 0 or #value > 64 then
        return nil, nil
    end
    if string.find(value, ":", 1, true) then
        return 6, parse_ipv6(value)
    end
    return 4, parse_ipv4(value)
end

local function prefix_matches(cidr, family, address)
    if cidr.family ~= family or not address then
        return false
    end
    local full_bytes = math.floor(cidr.prefix_length / 8)
    for index = 1, full_bytes do
        if cidr.network[index] ~= address[index] then
            return false
        end
    end
    local remaining = cidr.prefix_length % 8
    if remaining == 0 then
        return true
    end
    local divisor = 2 ^ (8 - remaining)
    return math.floor(cidr.network[full_bytes + 1] / divisor) == math.floor(address[full_bytes + 1] / divisor)
end

local function validate_request_values(values)
    local count = 0
    for key, value in pairs(values) do
        count = count + 1
        if count > MAX_REQUEST_FIELDS or type(key) ~= "string" or #key > MAX_NAME_BYTES or has_control(key) then
            return false
        end
        if type(value) == "table" then
            if #value > MAX_REQUEST_FIELDS then
                return false
            end
            for index = 1, #value do
                if type(value[index]) ~= "string" or #value[index] > MAX_REQUEST_VALUE_BYTES or has_control(value[index]) then
                    return false
                end
            end
        elseif type(value) == "string" then
            if #value > MAX_REQUEST_VALUE_BYTES or has_control(value) then
                return false
            end
        elseif value ~= true then
            return false
        end
    end
    return true
end

local function request_context()
    local headers, header_error = ngx.req.get_headers(MAX_REQUEST_FIELDS)
    local query, query_error = ngx.req.get_uri_args(MAX_REQUEST_FIELDS)
    local family, address = parse_address(ngx.var.remote_addr)
    local host = ngx.var.host
    local method = ngx.req.get_method()
    local request_path = ngx.var.uri
    local port = tonumber(public_server_port())
    if header_error == "truncated" or query_error == "truncated" or not family or not address or
        not bounded_string(host, MAX_HOST_BYTES, false) or not valid_token(method, MAX_METHOD_BYTES) or
        not bounded_string(request_path, MAX_REQUEST_PATH_BYTES, false) or not is_integer(port) or
        port < 1 or port > 65535 or not validate_request_values(headers) or not validate_request_values(query) then
        return nil
    end
    return {
        headers = headers,
        query = query,
        family = family,
        address = address,
        host = string.lower(host),
        method = method,
        path = request_path,
        port = port,
    }
end

local function find_values(values, name, fold_name)
    local found = nil
    for key, value in pairs(values) do
        if key == name or (fold_name and string.lower(key) == name) then
            if found ~= nil then
                return false
            end
            found = value
        end
    end
    return found
end

local function address_is_safe(family, address)
    if not address then return false end
    if family == 4 then
        local unspecified = address[1] == 0 and address[2] == 0 and address[3] == 0 and address[4] == 0
        return not unspecified and address[1] ~= 127 and not (address[1] >= 224 and address[1] <= 239) and
            not (address[1] == 169 and address[2] == 254)
    end
    local unspecified = true
    for index = 1, 16 do
        if address[index] ~= 0 then unspecified = false; break end
    end
    local loopback = true
    for index = 1, 15 do
        if address[index] ~= 0 then loopback = false; break end
    end
    loopback = loopback and address[16] == 1
    return not unspecified and not loopback and address[1] ~= 255 and
        not (address[1] == 254 and address[2] >= 128 and address[2] <= 191)
end

local function cidr_list_matches(cidrs, family, address)
    if cidrs then
        for index = 1, #cidrs do
            if prefix_matches(cidrs[index], family, address) then return true end
        end
    end
    return false
end

local function trim_forwarded_ows(value)
    return string.gsub(string.gsub(value, "^[ \t]+", ""), "[ \t]+$", "")
end

local function resolve_client_source(policy, request)
    local source = policy.client_source
    if not source then return request end
    if not address_is_safe(request.family, request.address) then return nil end
    local forwarded = find_values(request.headers, source.header, true)
    local peer_trusted = cidr_list_matches(source.trusted_proxy_cidrs, request.family, request.address)
    if not peer_trusted then
        if forwarded ~= nil then return nil end
        return request
    end
    if type(forwarded) ~= "string" or forwarded == "" then return nil end
    local chain = split_plain(forwarded, ",")
    if #chain < 1 or #chain > source.max_hops then return nil end
    for index = 1, #chain do
        local value = trim_forwarded_ows(chain[index])
        local family, address = parse_address(value)
        if not family or not address_is_safe(family, address) then return nil end
        chain[index] = {family = family, address = address}
    end
    for index = #chain, 1, -1 do
        local hop = chain[index]
        if not cidr_list_matches(source.trusted_proxy_cidrs, hop.family, hop.address) then
            request.family = hop.family
            request.address = hop.address
            return request
        end
    end
    return nil
end

local function trusted_crawler(policy, request)
    if not policy.trusted_crawlers then return false end
    local user_agent = find_values(request.headers, "user-agent", true)
    if type(user_agent) ~= "string" then return false end
    for index = 1, #policy.trusted_crawlers do
        local crawler = policy.trusted_crawlers[index]
        if cidr_list_matches(crawler.networks, request.family, request.address) then
            for prefix = 1, #crawler.user_agent_prefixes do
                local value = crawler.user_agent_prefixes[prefix]
                if string.sub(user_agent, 1, #value) == value then return true end
            end
        end
    end
    return false
end

local function value_matches(matcher, values, fold_name)
    local found = find_values(values, matcher.name, fold_name)
    if found == nil or found == false then
        return false
    end
    if matcher.operator == "exists" then
        return true
    end
    return type(found) == "string" and found == matcher.value
end

local function path_matches(matcher, request_path)
    if matcher.kind == "exact" then
        return request_path == matcher.value
    end
    if matcher.kind == "raw_prefix" then
        return string.sub(request_path, 1, #matcher.value) == matcher.value
    end
    if matcher.value == "/" or request_path == matcher.value then
        return true
    end
    return string.sub(request_path, 1, #matcher.value + 1) == matcher.value .. "/"
end

local function country_for(geo, request)
    if geo then
        for index = 1, #geo do
            if prefix_matches(geo[index].cidr, request.family, request.address) then return geo[index].country end
        end
    end
    return nil
end

local function country_matches(matcher, country)
    if not country then return false end
    local found = false
    for index = 1, #matcher.values do
        if matcher.values[index] == country then found = true; break end
    end
    return matcher.operator == "in" and found or matcher.operator == "not_in" and not found
end

local function matches(matcher, request, country, skip_country)
    if matcher.host and matcher.host ~= request.host then
        return false
    end
    if matcher.port and matcher.port ~= request.port then
        return false
    end
    if matcher.method and matcher.method ~= request.method then
        return false
    end
    if matcher.path and not path_matches(matcher.path, request.path) then
        return false
    end
    if matcher.query and not value_matches(matcher.query, request.query, false) then
        return false
    end
    if matcher.header and not value_matches(matcher.header, request.headers, true) then
        return false
    end
    if matcher.user_agent and not value_matches({
        name = "user-agent", operator = matcher.user_agent.operator, value = matcher.user_agent.value,
    }, request.headers, true) then
        return false
    end
    if matcher.source_cidr and not prefix_matches(matcher.source_cidr, request.family, request.address) then
        return false
    end
    if matcher.country and not skip_country and not country_matches(matcher.country, country) then return false end
    return true
end

local function matched_and_active(rule, request, country, now, policy_version)
    if not matches(rule.match, request, country, false) then
        return false
    end
    if rule.expires_at_unix and now >= rule.expires_at_unix then
        emit("rule_expired", rule.rule_id, policy_version)
        return false
    end
    return true
end

local function evaluate(policy, request, now)
    local action = "allow"
    local reason = "no_match"
    local rule_id = nil
    local country = country_for(policy.geo, request)
    local crawler = trusted_crawler(policy, request)
    if not country and policy.unknown_geo_action then
        if crawler then
            emit("crawler_geo_bypass", nil, policy.policy_version)
        elseif policy.unknown_geo_action == "block" then
            emit("unknown_geo_block", nil, policy.policy_version)
            return "block", "unknown_geo_block", nil
        else
            reason = "unknown_geo_allow"
            emit("unknown_geo_allow", nil, policy.policy_version)
        end
    end
    for _, rule in ipairs(policy.rules) do
        if rule.match.country and crawler and country_matches(rule.match.country, country) and
            matches(rule.match, request, country, true) then
            if rule.expires_at_unix and now >= rule.expires_at_unix then
                emit("rule_expired", rule.rule_id, policy.policy_version)
            else
                emit("crawler_geo_bypass", rule.rule_id, policy.policy_version)
            end
        elseif matched_and_active(rule, request, country, now, policy.policy_version) then
            action = rule.action
            rule_id = rule.rule_id
            if rule.action == "allow" then
                reason = rule.flow == "stop" and "allowlist_stop" or "allowlist_continue"
            elseif rule.action == "block" then
                reason = "rule_block"
            else
                reason = "rule_log"
            end
            emit(reason, rule.rule_id, policy.policy_version)
            if rule.flow == "stop" then
                break
            end
        end
    end
    return action, reason, rule_id
end

local function block_response()
    ngx.status = BLOCK_STATUS
    ngx.header["Content-Type"] = "text/plain"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say("Request blocked")
    return ngx.exit(BLOCK_STATUS)
end

function _M.access(options)
    if type(options) ~= "table" or type(options.policy_path) ~= "string" or options.policy_path == "" or
        (options.telemetry ~= nil and type(options.telemetry) ~= "boolean") then
        emit("policy_unavailable", nil, nil)
        emit_decision("block", "policy_unavailable", nil, 0)
        return block_response()
    end
    local policy = load_policy(options.policy_path)
    if not policy then
        emit("policy_unavailable", nil, nil)
        emit_decision("block", "policy_unavailable", nil, 0)
        export_telemetry(options.telemetry, "block", nil, 0, true)
        return block_response()
    end
    local request = request_context()
    if not request then
        emit("request_limit", nil, policy.policy_version)
        emit_decision("block", "request_limit", nil, policy.policy_version)
        export_telemetry(options.telemetry, "block", nil, policy.policy_version, true)
        return block_response()
    end
    request = resolve_client_source(policy, request)
    if not request then
        emit("client_source_invalid", nil, policy.policy_version)
        emit_decision("block", "client_source_invalid", nil, policy.policy_version)
        export_telemetry(options.telemetry, "block", nil, policy.policy_version, true)
        return block_response()
    end
    local now = effective_time(options.policy_path)
    if not now then
        emit("policy_unavailable", nil, policy.policy_version)
        emit_decision("block", "policy_unavailable", nil, policy.policy_version)
        export_telemetry(options.telemetry, "block", nil, policy.policy_version, true)
        return block_response()
    end
    local action, reason, rule_id = evaluate(policy, request, now)
    emit_decision(action, reason, rule_id, policy.policy_version)
    export_telemetry(options.telemetry, action, rule_id, policy.policy_version, reason ~= "no_match")
    if action == "block" then
        return block_response()
    end
end

-- ---------------------------------------------------------------------------
-- Request-content inspection for security-policy WAF rules (edgeconfig
-- WAFInspect). Called from the rendered state machine as
--   require("cdnca_waf").inspect([[{"target":..,"operator":..,"values":[..]}]])
-- Values are URL-decoded up to three times (double encoding), bodies are read
-- up to INSPECT_BODY_LIMIT bytes (form fields, JSON string leaves, else raw in
-- overlapping chunks); multipart file names are scanned up to
-- INSPECT_UPLOAD_SCAN_LIMIT bytes. A clause may select one named value (key),
-- transform values (filters) and compare with text or number operators.
-- Detectors are original code following the ideas of libinjection (SQL token
-- context, BSD-3) and OWASP CRS (XSS vectors, Apache-2.0); no code is copied.
-- ---------------------------------------------------------------------------
local INSPECT_BODY_LIMIT = 65536
local INSPECT_UPLOAD_SCAN_LIMIT = 16777216
local INSPECT_UPLOAD_CHUNK = 65536
local INSPECT_MAX_VALUES = 256
local INSPECT_MAX_VALUE_BYTES = 8192
local INSPECT_CHUNK_OVERLAP = 1024
local INSPECT_MAX_HEADERS = 100
local INSPECT_FRAGMENT_BYTES = 128
local inspect_specs = {}
local inspect_spec_count = 0

local function url_decode_all(value)
    for _ = 1, 3 do
        if not value:find("%", 1, true) and not value:find("+", 1, true) then break end
        local decoded = ngx.unescape_uri(value)
        if decoded == value then break end
        value = decoded
    end
    return value
end

local function push_value(list, value)
    if type(value) ~= "string" or #list >= INSPECT_MAX_VALUES then return end
    if #value > INSPECT_MAX_VALUE_BYTES then value = value:sub(1, INSPECT_MAX_VALUE_BYTES) end
    list[#list + 1] = url_decode_all(value)
end

-- A long raw value is pushed as overlapping chunks, so content past the
-- first INSPECT_MAX_VALUE_BYTES is inspected too.
local function push_chunks(list, value)
    if type(value) ~= "string" then return end
    if #value <= INSPECT_MAX_VALUE_BYTES then return push_value(list, value) end
    local step = INSPECT_MAX_VALUE_BYTES - INSPECT_CHUNK_OVERLAP
    local start = 1
    while start <= #value and #list < INSPECT_MAX_VALUES do
        push_value(list, value:sub(start, start + INSPECT_MAX_VALUE_BYTES - 1))
        start = start + step
    end
end

-- push_pairs adds names and values of a&b=c / a; b=c lists; with key only the
-- values whose (decoded) name is key.
local function push_pairs(list, raw, separator, key)
    if type(raw) ~= "string" or raw == "" then return end
    for pair in raw:gmatch(separator or "[^&]+") do
        if separator then pair = pair:gsub("^%s+", "") end
        local equals = pair:find("=", 1, true)
        local name, value = pair, nil
        if equals then name, value = pair:sub(1, equals - 1), pair:sub(equals + 1) end
        if key then
            if url_decode_all(name) == key then push_value(list, value or "") end
        else
            push_value(list, name)
            if value then push_value(list, value) end
        end
    end
end

local function push_json_leaves(list, value, depth)
    if depth > 16 or #list >= INSPECT_MAX_VALUES then return end
    if type(value) == "string" then
        push_value(list, value)
    elseif type(value) == "table" then
        for name, child in pairs(value) do
            if type(name) == "string" then push_value(list, name) end
            push_json_leaves(list, child, depth + 1)
        end
    end
end

-- JSON key path a.b.0: object members by name, array elements by 0-based index.
local function push_json_path(list, value, key)
    for segment in key:gmatch("[^.]+") do
        if type(value) ~= "table" then return end
        local index = segment:match("^%d+$") and tonumber(segment)
        if index and value[index + 1] ~= nil then
            value = value[index + 1]
        else
            value = value[segment]
        end
    end
    if type(value) == "string" then
        push_value(list, value)
    elseif type(value) == "number" or type(value) == "boolean" then
        push_value(list, tostring(value))
    elseif type(value) == "table" then
        push_json_leaves(list, value, 1)
    end
end

-- Always let nginx read the body: HTTP/2 and HTTP/3 may stream one without
-- Content-Length (END_STREAM ends it), and any method may carry one that is
-- proxied upstream. Deciding from request headers would skip inspection of
-- exactly those bodies. Without a body read_body() returns immediately.
-- Returns the first INSPECT_BODY_LIMIT bytes and whether the body is longer.
local function request_body()
    local ctx = ngx.ctx
    local cached = ctx.cdnca_inspect_body
    if cached ~= nil then return cached, ctx.cdnca_inspect_body_truncated end
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local truncated = false
    if not body then
        local path = ngx.req.get_body_file()
        local file = path and io.open(path, "rb")
        body = file and file:read(INSPECT_BODY_LIMIT + 1) or ""
        if file then file:close() end
    end
    body = body or ""
    if #body > INSPECT_BODY_LIMIT then body, truncated = body:sub(1, INSPECT_BODY_LIMIT), true end
    ctx.cdnca_inspect_body, ctx.cdnca_inspect_body_truncated = body, truncated
    return body, truncated
end

-- The body length: the whole body nginx read (memory or temporary file).
local function body_length()
    local ctx = ngx.ctx
    if ctx.cdnca_inspect_body_length then return ctx.cdnca_inspect_body_length end
    request_body()
    local length = #(ngx.req.get_body_data() or "")
    local path = ngx.req.get_body_file()
    if path then
        local file = io.open(path, "rb")
        if file then
            length = file:seek("end") or 0
            file:close()
        end
    end
    ctx.cdnca_inspect_body_length = length
    return length
end

local function content_type()
    return string.lower(ngx.var.http_content_type or "")
end

local function decoded_json_body()
    local ctx = ngx.ctx
    if ctx.cdnca_inspect_json ~= nil then return ctx.cdnca_inspect_json or nil end
    local decoded = cjson.decode((request_body()))
    ctx.cdnca_inspect_json = decoded == nil and false or decoded
    return decoded
end

local function body_values(list, key)
    local body = request_body()
    if body == "" then return end
    local kind = content_type()
    if kind:find("application/x-www-form-urlencoded", 1, true) then
        push_pairs(list, body, nil, key)
    elseif kind:find("json", 1, true) then
        local decoded = decoded_json_body()
        if decoded == nil then
            if not key then push_chunks(list, body) end
        elseif key then
            push_json_path(list, decoded, key)
        else
            push_json_leaves(list, decoded, 0)
        end
    elseif not key then
        push_chunks(list, body)
    end
end

-- Multipart file names: every filename= / filename*= of a Content-Disposition
-- part header in the first INSPECT_UPLOAD_SCAN_LIMIT body bytes. Returns the
-- names and whether the body is longer than the scan.
--
-- The same pass keeps ngx.ctx.cdnca_inspect_multipart
-- for the multipart_* targets: fields, every name= / name*= of a
-- Content-Disposition header (distinct, as sent, at most 4096); parts, the
-- parts the Content-Type boundary delimits; field_max, the longest part body
-- without filename= in bytes; truncated, more names than kept. Boundary and
-- part syntax follow PHP's multipart parser (main/rfc1867.c): "boundary"
-- found case-insensitively up to its "=", quoted or up to "," / ";";
-- delimiter lines and the blank line after a part's headers end in LF or
-- CRLF. A part header block over 16 KiB is no field (not measured).
local function upload_names()
    local ctx = ngx.ctx
    if ctx.cdnca_inspect_uploads then return ctx.cdnca_inspect_uploads, ctx.cdnca_inspect_upload_truncated end
    local names, seen, truncated = {}, {}, false
    local multipart = { fields = {}, parts = 0, field_max = 0, truncated = false }
    if content_type():find("multipart/", 1, true) then
        ngx.req.read_body()
        local field_seen = {}
        local raw_type = ngx.var.http_content_type or ""
        local at = string.lower(raw_type):find("boundary", 1, true)
        local equals = at and raw_type:find("=", at, true)
        local boundary = equals and (raw_type:match('^"([^"]*)"', equals + 1) or raw_type:match("^([^,;]*)", equals + 1))
        local delimiter = boundary and boundary ~= "" and #boundary <= 256 and "\n--" .. boundary
        -- state: "pre" before the first delimiter, "head" in a part's
        -- headers, "body" in its body, "end" after the close delimiter.
        -- pending is the unprocessed tail; pending byte k is body byte base + k.
        -- prev is the byte before pending (a CR before the delimiter's LF
        -- belongs to the line break, not the field).
        local state, pending, base, body_start, is_file, prev = "pre", "\n", -1, 0, false, ""
        local function measure(last)
            if state == "body" and not is_file and last - body_start > multipart.field_max then
                multipart.field_max = last - body_start
            end
        end
        local function parts(chunk)
            if not delimiter or state == "end" then return end
            local buffer = pending .. chunk
            local position = 1
            while true do
                if state == "head" then
                    local _, stop = buffer:find("\n\r?\n", position)
                    if stop then
                        is_file = string.lower(buffer:sub(position, stop)):find("filename%*?%s*=") ~= nil
                        body_start, position, state = base + stop + 1, stop + 1, "body"
                    elseif #buffer - position >= 16384 then
                        is_file, state = true, "body"
                    else
                        break
                    end
                else
                    local found = buffer:find(delimiter, position, true)
                    if not found then
                        position = math.max(position, #buffer - #delimiter + 2)
                        break
                    end
                    local cr = (found > 1 and buffer:sub(found - 1, found - 1) or prev) == "\r"
                    measure(base + found - (cr and 1 or 0))
                    local after = found + #delimiter
                    if #buffer - after < 1 then -- the 2 bytes after the delimiter decide
                        position = found
                        break
                    end
                    if buffer:sub(after, after + 1) == "--" then
                        state = "end"
                        break
                    end
                    multipart.parts = multipart.parts + 1
                    state, position = "head", after
                end
            end
            if position > 1 then prev = buffer:sub(position - 1, position - 1) end
            pending = buffer:sub(position)
            base = base + position - 1
        end
        local function scan(text)
            for line in text:gmatch("[Cc][Oo][Nn][Tt][Ee][Nn][Tt]%-[Dd][Ii][Ss][Pp][Oo][Ss][Ii][Tt][Ii][Oo][Nn]:[^\r\n]*") do
                local lowered = string.lower(line)
                local position = 1
                while true do
                    local start, stop = lowered:find("[;%s]name%*?%s*=%s*", position)
                    if not start then break end
                    local rest = line:sub(stop + 1)
                    local name = rest:match('^"([^"]*)"') or rest:match("^'([^']*)'") or rest:match("^([^;%s]*)")
                    if lowered:sub(start, stop):find("*", 1, true) then
                        name = ngx.unescape_uri((name:gsub("^[^']*'[^']*'", "")))
                    end
                    if name ~= "" and not field_seen[name] then
                        if #multipart.fields >= 4096 then
                            multipart.truncated = true
                            break
                        end
                        field_seen[name] = true
                        multipart.fields[#multipart.fields + 1] = name
                    end
                    position = stop + 1
                end
                position = 1
                while #names < INSPECT_MAX_VALUES do
                    local start, stop = lowered:find("filename%*?%s*=%s*", position)
                    if not start then break end
                    local rest = line:sub(stop + 1)
                    local name = rest:match('^"([^"]*)"') or rest:match("^([^;%s]*)")
                    if lowered:sub(start, stop):find("*", 1, true) then
                        name = (name or ""):gsub("^[^']*'[^']*'", "")
                        name = ngx.unescape_uri(name)
                    end
                    if name and name ~= "" and not seen[name] then
                        seen[name] = true
                        names[#names + 1] = name
                    end
                    position = stop + 1
                end
            end
        end
        local data = ngx.req.get_body_data()
        if data then
            if #data > INSPECT_UPLOAD_SCAN_LIMIT then data, truncated = data:sub(1, INSPECT_UPLOAD_SCAN_LIMIT), true end
            scan(data)
            for start = 1, #data, INSPECT_UPLOAD_CHUNK do parts(data:sub(start, start + INSPECT_UPLOAD_CHUNK - 1)) end
        else
            local path = ngx.req.get_body_file()
            local file = path and io.open(path, "rb")
            if file then
                local read, carry = 0, ""
                while read < INSPECT_UPLOAD_SCAN_LIMIT do
                    local chunk = file:read(math.min(INSPECT_UPLOAD_CHUNK, INSPECT_UPLOAD_SCAN_LIMIT - read))
                    if not chunk then break end
                    read = read + #chunk
                    scan(carry .. chunk)
                    parts(chunk)
                    carry = chunk:sub(-INSPECT_CHUNK_OVERLAP)
                end
                truncated = file:read(1) ~= nil
                file:close()
            end
        end
        -- a part the scan ends in (unclosed body, or the scan limit)
        measure(base + #pending + 1)
    end
    ctx.cdnca_inspect_uploads, ctx.cdnca_inspect_upload_truncated = names, truncated
    ctx.cdnca_inspect_multipart = multipart
    return names, truncated
end

local function request_headers()
    local ctx = ngx.ctx
    if ctx.cdnca_inspect_headers then return ctx.cdnca_inspect_headers end
    local headers = ngx.req.get_headers(0, true)
    ctx.cdnca_inspect_headers = headers
    return headers
end

local function inspect_values(target, key)
    local cache = ngx.ctx.cdnca_inspect_values
    if not cache then
        cache = {}
        ngx.ctx.cdnca_inspect_values = cache
    end
    local cache_key = target .. "\0" .. (key or "")
    if cache[cache_key] then return cache[cache_key] end
    local list = {}
    if target == "args" then
        push_pairs(list, ngx.var.args, nil, key)
        body_values(list, key)
    elseif target == "query" then
        push_pairs(list, ngx.var.args, nil, key)
    elseif target == "body" then
        body_values(list, key)
    elseif target == "request_uri" then
        push_value(list, ngx.var.request_uri)
    elseif target == "path" then
        push_value(list, ngx.var.uri)
    elseif target == "header" then
        local value = ngx.req.get_headers(INSPECT_MAX_HEADERS)[key]
        if type(value) == "table" then
            for _, item in ipairs(value) do push_value(list, item) end
        else
            push_value(list, value)
        end
    elseif target == "header_names" then
        for name in pairs(request_headers()) do push_value(list, string.lower(name)) end
        table.sort(list)
    elseif target == "cookie" then
        push_pairs(list, ngx.var.http_cookie, "[^;]+", key)
    elseif target == "user_agent" then
        -- A request without the header has an empty User-Agent / Referer
        -- (the empty-UA rule must hold for both).
        push_value(list, ngx.var.http_user_agent or "")
    elseif target == "referer" then
        push_value(list, ngx.var.http_referer or "")
    elseif target == "content_type" then
        -- "" without the header (like user_agent).
        push_value(list, ngx.var.http_content_type or "")
    elseif target == "http_version" then
        -- 1.0 / 1.1 / 2 / 3 (edgeconfig wafInspectHTTPVersions).
        local version = ngx.req.http_version()
        push_value(list, version == 1.0 and "1.0" or version == 1.1 and "1.1" or version == 2.0 and "2" or
            version == 3.0 and "3" or tostring(version))
    elseif target == "upload_filename" or target == "upload_extension" then
        for _, name in ipairs((upload_names())) do
            if target == "upload_filename" then
                push_value(list, name)
            else
                local base = name:match("([^/\\]*)$") or name
                local extension = base:match("%.([^.]+)$")
                if extension then push_value(list, string.lower(extension)) end
            end
        end
    elseif target == "multipart_field_names" then
        -- Every part's name= (upload_names); kept as
        -- sent (no URL decoding: PHP takes the name literally).
        upload_names()
        for _, name in ipairs(ngx.ctx.cdnca_inspect_multipart.fields) do
            if #list >= INSPECT_MAX_VALUES * 16 then break end
            list[#list + 1] = #name > INSPECT_MAX_VALUE_BYTES and name:sub(1, INSPECT_MAX_VALUE_BYTES) or name
        end
    end
    cache[cache_key] = list
    return list
end

-- Number targets (one value each).
local function inspect_number(target)
    if target == "body_length" then return body_length() end
    if target == "uri_length" then return #(ngx.var.request_uri or "") end
    if target == "multipart_part_count" or target == "multipart_field_max_length" then
        upload_names()
        local multipart = ngx.ctx.cdnca_inspect_multipart
        return target == "multipart_part_count" and multipart.parts or multipart.field_max
    end
    if target == "header_count" or target == "header_max_length" then
        local count, longest = 0, 0
        for name, value in pairs(request_headers()) do
            local values = type(value) == "table" and value or { value }
            for _, item in ipairs(values) do
                count = count + 1
                local length = #name + #tostring(item)
                if length > longest then longest = length end
            end
        end
        return target == "header_count" and count or longest
    end
    if target == "arg_count" then
        local count = 0
        for _ in (ngx.var.args or ""):gmatch("[^&]+") do count = count + 1 end
        if content_type():find("application/x-www-form-urlencoded", 1, true) then
            for _ in (request_body()):gmatch("[^&]+") do count = count + 1 end
        end
        return count
    end
    return nil
end

-- Whether the clause's body input was cut at the inspection limit.
local function body_truncated(target)
    if target == "upload_filename" or target == "upload_extension" or target:find("^multipart_") then
        local _, truncated = upload_names()
        return truncated or target == "multipart_field_names" and ngx.ctx.cdnca_inspect_multipart.truncated
    end
    local _, truncated = request_body()
    return truncated
end

-- Value filters ----------------------------------------------------------
local function utf8_char(codepoint)
    if codepoint < 0 or codepoint > 0x10FFFF or codepoint >= 0xD800 and codepoint <= 0xDFFF then return "" end
    if codepoint < 0x80 then return string.char(codepoint) end
    if codepoint < 0x800 then
        return string.char(0xC0 + math.floor(codepoint / 0x40), 0x80 + codepoint % 0x40)
    end
    if codepoint < 0x10000 then
        return string.char(0xE0 + math.floor(codepoint / 0x1000), 0x80 + math.floor(codepoint / 0x40) % 0x40, 0x80 + codepoint % 0x40)
    end
    return string.char(0xF0 + math.floor(codepoint / 0x40000), 0x80 + math.floor(codepoint / 0x1000) % 0x40,
        0x80 + math.floor(codepoint / 0x40) % 0x40, 0x80 + codepoint % 0x40)
end

local HTML_NAMED = { lt = "<", gt = ">", quot = '"', apos = "'", amp = "&", colon = ":", lpar = "(", rpar = ")",
    sol = "/", tab = "\t", newline = "\n", nbsp = "\194\160", semi = ";", comma = ",", period = ".", equals = "=",
    num = "#", excl = "!", quest = "?", grave = "`", lsqb = "[", rsqb = "]", lcub = "{", rcub = "}", bsol = "\\" }

local FILTERS = {
    lowercase = string.lower,
    base64_decode = function(value)
        local stripped = value:gsub("%s", "")
        local padded = stripped:gsub("-", "+"):gsub("_", "/")
        padded = padded .. string.rep("=", (4 - #padded % 4) % 4)
        return ngx.decode_base64(padded) or value
    end,
    unicode_decode = function(value)
        value = value:gsub("[\\%%][uU](%x%x%x%x)", function(hex) return utf8_char(tonumber(hex, 16)) end)
        return (value:gsub("\\[xX](%x%x)", function(hex) return string.char(tonumber(hex, 16)) end))
    end,
    html_unescape = function(value)
        value = value:gsub("&#[xX](%x+);?", function(hex) return utf8_char(tonumber(hex, 16) or -1) end)
        value = value:gsub("&#(%d+);?", function(dec) return utf8_char(tonumber(dec) or -1) end)
        return (value:gsub("&(%a+);", function(name) return HTML_NAMED[string.lower(name)] end))
    end,
}

-- The values after the clause's filters; "length" (always last) turns each
-- into its byte length.
local function filtered_values(spec)
    local values = inspect_values(spec.target, spec.key)
    local filters = spec.filters
    if not filters or #filters == 0 then return values end
    local cache = ngx.ctx.cdnca_inspect_filtered
    if not cache then
        cache = {}
        ngx.ctx.cdnca_inspect_filtered = cache
    end
    local cache_key = spec.target .. "\0" .. (spec.key or "") .. "\0" .. table.concat(filters, ",")
    if cache[cache_key] then return cache[cache_key] end
    local result = {}
    for index, value in ipairs(values) do
        for _, name in ipairs(filters) do
            if name == "length" then
                value = #value
            else
                value = FILTERS[name](value)
            end
        end
        result[index] = value
    end
    cache[cache_key] = result
    return result
end

local NUMBER_COMPARE = {
    gt = function(a, b) return a > b end, gte = function(a, b) return a >= b end,
    lt = function(a, b) return a < b end, lte = function(a, b) return a <= b end,
    eq = function(a, b) return a == b end, neq = function(a, b) return a ~= b end,
}
local NEGATED = { not_contains = "contains", not_regex = "regex", not_equals = "equals" }

local SQL_LOGIC = { ["or"] = true, ["and"] = true, ["xor"] = true, ["||"] = true, ["&&"] = true }
local SQL_COMPARE = { ["="] = true, ["<"] = true, [">"] = true, ["<="] = true, [">="] = true, ["<>"] = true,
    ["!="] = true, ["like"] = true, ["rlike"] = true, ["regexp"] = true, ["is"] = true, ["in"] = true, ["between"] = true }
local SQL_STACKED = { drop = true, insert = true, update = true, delete = true, exec = true, execute = true,
    declare = true, shutdown = true, truncate = true, alter = true, create = true, select = true }
local SQL_DELAY = { sleep = true, benchmark = true, pg_sleep = true, waitfor = true, dbms_pipe = true }

-- Tokens: { t = "s" string | "n" number | "w" word | "o" operator | "c" comment | "(" | ")" | ";" | "," , v = text }.
local function sql_tokens(text, start)
    local tokens, index, length = {}, start or 1, #text
    while index <= length and #tokens < 64 do
        local char = text:sub(index, index)
        if char:find("^%s") then
            index = index + 1
        elseif char == "'" or char == '"' or char == "`" then
            local close = text:find(char, index + 1, true)
            tokens[#tokens + 1] = { t = "s", v = text:sub(index + 1, (close or length + 1) - 1) }
            index = (close or length) + 1
        elseif text:sub(index, index + 1) == "/*" then
            local close = text:find("*/", index + 2, true)
            if not close then tokens[#tokens + 1] = { t = "c" } break end
            index = close + 2 -- inline comments separate tokens (UN/**/ION is not merged)
        elseif text:sub(index, index + 1) == "--" or char == "#" then
            tokens[#tokens + 1] = { t = "c" }
            break
        elseif char:find("^%d") then
            local finish = select(2, text:find("^[%w%.]+", index))
            tokens[#tokens + 1] = { t = "n", v = text:sub(index, finish) }
            index = finish + 1
        elseif char:find("^[%a_@$]") then
            local finish = select(2, text:find("^[%w_@$%.]+", index))
            tokens[#tokens + 1] = { t = "w", v = text:sub(index, finish) }
            index = finish + 1
        elseif char == "(" or char == ")" or char == ";" or char == "," then
            tokens[#tokens + 1] = { t = char }
            index = index + 1
        else
            local finish = select(2, text:find("^[=<>!|&%+%-%*/%%^~]+", index)) or index
            tokens[#tokens + 1] = { t = "o", v = text:sub(index, finish) }
            index = finish + 1
        end
    end
    return tokens
end

local function sql_operand(token)
    return token and (token.t == "s" or token.t == "n" or token.t == "w" or token.t == "(")
end

-- Attack shapes valid anywhere in a value.
local function sql_anywhere(tokens)
    for index, token in ipairs(tokens) do
        local nxt, after = tokens[index + 1], tokens[index + 2]
        if token.t == "w" and token.v == "union" then
            for offset = 1, 3 do
                local candidate = tokens[index + offset]
                if candidate and candidate.t == "w" and candidate.v == "select" then return true end
            end
        end
        if token.t == "w" and SQL_DELAY[token.v] and nxt and (nxt.t == "(" or token.v == "waitfor") then return true end
        if token.t == ";" and nxt and nxt.t == "w" and SQL_STACKED[nxt.v] and after and after.t ~= "c" then return true end
    end
    return false
end

-- Shapes of an injected fragment: tokens right after leaving a string or a
-- numeric literal context.
local function sql_fragment(tokens)
    local first, second = tokens[1], tokens[2]
    if not first then return false end
    if first.t == "c" or first.t == ")" and second and second.t == "c" or first.t == ";" and second and second.t == "c" then
        return true
    end
    for index = 1, math.min(#tokens, 3) do
        local token = tokens[index]
        if (token.t == "w" and SQL_LOGIC[token.v] or token.t == "o" and SQL_LOGIC[token.v]) then
            local skip = index + 1
            while tokens[skip] and tokens[skip].t == "(" and tokens[skip + 1] and tokens[skip + 1].t ~= "w" do skip = skip + 1 end
            local left, compare, right = tokens[skip], tokens[skip + 1], tokens[skip + 2]
            if sql_operand(left) and (compare and (compare.t == "o" and SQL_COMPARE[compare.v] or compare.t == "w"
                and SQL_COMPARE[compare.v])) and sql_operand(right) then
                return true
            end
            local open, keyword = tokens[index + 1], tokens[index + 2]
            if open and open.t == "(" and keyword and keyword.t == "w" and keyword.v == "select" then return true end
            if left and left.t == "n" and (compare == nil or compare.t == "c") then return true end
        end
    end
    return false
end

local function detect_sqli(value)
    local text = string.lower(value)
    -- prose without SQL punctuation, a leading number or SQL-only keywords cannot form an attack
    if not text:find("[';\"`#/]") and not text:find("^%s*%-?%d") and not text:find("%-%-")
        and not text:find("union") and not text:find("sleep") and not text:find("benchmark") and not text:find("waitfor") then
        return false
    end
    if sql_anywhere(sql_tokens(text)) then return true end
    local quote = text:find("['\"`]")
    if quote then
        local tokens = sql_tokens(text, quote + 1)
        if sql_fragment(tokens) or sql_anywhere(tokens) then return true end
    end
    local numeric = text:match("^%s*%-?%d+[%s%)]*()")
    return numeric ~= nil and numeric <= #text and sql_fragment(sql_tokens(text, numeric))
end

local HTML_ENTITIES = { lt = "<", gt = ">", quot = '"', apos = "'", amp = "&", colon = ":", lpar = "(", rpar = ")",
    sol = "/", tab = "\t", newline = "\n" }

local function html_decode(text)
    text = text:gsub("&#[xX](%x+);?", function(hex) local n = tonumber(hex, 16) return n and n < 128 and string.char(n) or "" end)
    text = text:gsub("&#(%d+);?", function(dec) local n = tonumber(dec) return n and n < 128 and string.char(n) or "" end)
    return (text:gsub("&(%a+);", function(name) return HTML_ENTITIES[string.lower(name)] end))
end

local XSS_TAGS = { script = true, iframe = true, frame = true, object = true, embed = true, svg = true, math = true,
    base = true, link = true, meta = true, applet = true, form = true, img = true, video = true, audio = true,
    body = true, style = true, isindex = true, marquee = true, details = true, input = true, textarea = true }

local function detect_xss(value)
    if not value:find("[<:=(&]") then return false end
    local text = string.lower(html_decode(value)):gsub("[%z\1-\8\11\12\14-\31]", "")
    if not text:find("[<:=(]") then return false end
    for tag in text:gmatch("<%s*/?%s*([%a][%w]*)") do
        if XSS_TAGS[tag] then return true end
    end
    if text:find("<[^>]-[%s/\"']on%a+%s*=") or text:find("^%s*[\"']?%s*on%a+%s*=")
        or text:find("[\"'][^\"']-%s+on%a+%s*=") then
        return true
    end
    local scheme = text:gsub("[%s%z]", "")
    if scheme:find("^[\"'=]*javascript:") or scheme:find("[\"'=(]javascript:") or scheme:find("^[\"'=]*vbscript:")
        or scheme:find("^[\"'=]*data:text/html") then
        return true
    end
    return text:find("expression%s*%(") ~= nil or text:find("srcdoc%s*=") ~= nil or text:find("%-moz%-binding") ~= nil
end

-- SSTI: a template delimiter whose expression evaluates something. Plain
-- placeholders ({{name}}, {{user.name}}, {{ name | upper }}, ${HOME}) are
-- what templates and form text legitimately carry; an attack needs
-- arithmetic between operands (the {{7*7}} probe), a call, a dunder or
-- reflective attribute, subscripts with strings, or a reflective/global
-- object (request, config, self, class, Runtime ...) reached by attribute.
local SSTI_REFLECT = { class = true, getclass = true, forname = true, constructor = true, prototype = true,
    runtime = true, processbuilder = true, getruntime = true, exec = true, popen = true, system = true,
    environment = true, request = true, self = true, config = true, lipsum = true, cycler = true, joiner = true,
    namespace = true, application = true, getengine = true, eval = true, ["require"] = true, process = true }

local function ssti_expression(expr)
    expr = expr:gsub("%s+", " ")
    if expr:find("__%a+__") then return true end
    -- arithmetic between two operands: 7*7, 7*'7', a+1 (not "a-b" slugs or dates)
    if expr:find("[%w'\"%)]%s*[%*%%/]%s*[%w'\"%(]") or expr:find("%d%s*%+%s*%d")
        or expr:find("%d%s+%-%s+%d") then
        return true
    end
    -- a call: name( ... ), T(java.lang.Runtime), filter|attr("x")
    if expr:find("[%a_][%w_]*%s*%(") then return true end
    if expr:find("%[%s*['\"]") then return true end
    local chain = 0
    for link in expr:gmatch("%.%s*([%a_][%w_]*)") do
        chain = chain + 1
        if SSTI_REFLECT[string.lower(link)] then return true end
    end
    local head = expr:match("^%s*([%a_][%w_]*)")
    return head ~= nil and SSTI_REFLECT[string.lower(head)] == true and chain >= 1
end

local SSTI_DELIMITERS = { { "{{", "}}" }, { "${", "}" }, { "#{", "}" }, { "*{", "}" }, { "{%", "%}" },
    { "<%=", "%>" }, { "<%", "%>" }, { "@{", "}" } }

local function detect_ssti(value)
    if not value:find("[{%%#]") then return false end
    for _, pair in ipairs(SSTI_DELIMITERS) do
        local start = 1
        for _ = 1, 32 do
            local open = value:find(pair[1], start, true)
            if not open then break end
            local close = value:find(pair[2], open + #pair[1], true)
            if not close then break end
            local expr = value:sub(open + #pair[1], close - 1)
            if #expr > 0 and #expr <= 512 and ssti_expression(expr) then return true end
            start = open + 1
        end
    end
    local lowered = string.lower(value)
    -- FreeMarker built-ins and Velocity directives that instantiate or reflect
    if lowered:find("<#assign[^>]-%?new%s*%(") or lowered:find("%?api%.") or lowered:find("freemarker%.template%.utility")
        or lowered:find("#set%s*%(%s*%$[%w_]+%s*=[^)]*%.") then
        return true
    end
    return false
end

-- Java deserialization: an ObjectOutputStream (magic AC ED, version 00 05)
-- in raw, Base64 or hexadecimal form whose next bytes are a valid stream
-- element: a new object with a class descriptor whose declared name length
-- matches a Java class name, or any element when a known gadget class is
-- named in the stream. Text formats (fastjson @type, Jackson polymorphic
-- arrays, XStream) count only when they name a known gadget class.
local JAVA_GADGETS = { "org.apache.commons.collections", "org.apache.commons.beanutils", "invokertransformer",
    "chainedtransformer", "constanttransformer", "instantiatetransformer", "lazymap", "templatesimpl",
    "com.sun.rowset.jdbcrowsetimpl", "com.sun.org.apache.xalan", "java.beans.eventhandler", "javax.management",
    "org.springframework.beans.factory", "org.codehaus.groovy.runtime", "bsh.interpreter", "com.mchange.v2.c3p0",
    "org.hibernate.engine", "rome.feed", "com.sun.syndication", "ysoserial", "java.lang.runtime", "java.lang.processbuilder",
    "org.apache.xbean", "org.apache.tomcat.dbcp", "com.alibaba.fastjson", "java.net.url", "java.net.inet4address",
    "javax.naming.initialcontext", "sun.rmi.server", "java.rmi.registry", "java.util.priorityqueue", "jdk.nashorn" }
local JAVA_STREAM_ELEMENTS = { [0x70] = true, [0x71] = true, [0x72] = true, [0x73] = true, [0x74] = true, [0x75] = true,
    [0x76] = true, [0x77] = true, [0x79] = true, [0x7a] = true, [0x7b] = true, [0x7c] = true, [0x7d] = true, [0x7e] = true }

local function java_gadget(text)
    local lowered = string.lower(text)
    for _, name in ipairs(JAVA_GADGETS) do
        if lowered:find(name, 1, true) then return true end
    end
    return false
end

local function java_stream(bytes)
    if #bytes < 6 or bytes:sub(1, 4) ~= "\172\237\0\5" or not JAVA_STREAM_ELEMENTS[bytes:byte(5)] then return false end
    if bytes:byte(5) == 0x73 and bytes:byte(6) == 0x72 and #bytes >= 8 then
        local length = bytes:byte(7) * 256 + bytes:byte(8)
        local name = bytes:sub(9, 8 + length)
        if length > 0 and #name == length and name:find("^[%a_$%[][%w_$%.;%[]*$") then return true end
    end
    return java_gadget(bytes)
end

local function hex_bytes(hex)
    return (hex:gsub("%x%x", function(pair) return string.char(tonumber(pair, 16)) end))
end

local function detect_java_deser(value)
    local raw = value:find("\172\237\0\5", 1, true)
    if raw and java_stream(value:sub(raw, raw + 4095)) then return true end
    -- Base64 of the stream: "rO0AB" when the magic starts a 3-byte group, "?ztAA" / "??s7QA"
    -- when one or two bytes of something else precede it in the same encoded token.
    for _, marker in ipairs({ { "rO0AB", 0 }, { "ztAA", 2 }, { "s7QA", 3 } }) do
        local start = 1
        for _ = 1, 8 do
            local found = value:find(marker[1], start, true)
            if not found then break end
            -- the 4-char group holding the magic (and the 1 or 2 bytes before it) starts marker[2] characters earlier
            local group = found - marker[2]
            if group >= 1 then
                -- a query string may have turned Base64 "+" into a space
                local token = value:match("^[%w%+/_%- ]+", group)
                token = token and token:sub(1, 5464):gsub("[ %-]", "+"):gsub("_", "/") or ""
                token = token:sub(1, #token - #token % 4)
                local decoded = #token >= 8 and ngx.decode_base64(token)
                if decoded then
                    local at = decoded:find("\172\237\0\5", 1, true)
                    if at and at <= 3 and java_stream(decoded:sub(at)) then return true end
                end
            end
            start = found + 1
        end
    end
    local lowered = string.lower(value)
    local hex = lowered:find("aced0005", 1, true)
    if hex then
        local digits = lowered:match("^%x+", hex):sub(1, 8192)
        if java_stream(hex_bytes(digits:sub(1, #digits - #digits % 2))) then return true end
    end
    -- fastjson / Jackson / XStream polymorphic payloads naming a gadget
    if (lowered:find("@type", 1, true) or lowered:find("^%s*%[%s*\"[%a_][%w_]*%.") or lowered:find("<[%a_][%w_%-]*%.[%w_.%-]+[%s>/]")
        or lowered:find("<dynamic%-proxy") or lowered:find("<sorted%-set")) and java_gadget(lowered) then
        return true
    end
    return false
end

-- PHP deserialization: an unserialize() object O:<len>:"Class":<n>:{ (or a
-- Serializable C:<len>:"Class":<n>:{) whose declared length equals the
-- class name's (PHP rejects anything else, so prose never satisfies it),
-- also inside a Base64 token (Tzo / Qzo), and phar:// stream wrappers that
-- deserialize archive metadata.
local function php_object(text)
    -- "+" before a number is legal PHP; URL decoding may have turned it into a space
    for _, length, name in text:gmatch('([OC]):[+ ]?(%d+):"([^"]*)":[+ ]?%d+:{') do
        if tonumber(length) == #name and name:find("^[%a_\\\128-\255][%w_\\\128-\255]*$") then return true end
    end
    return false
end

local function detect_php_deser(value)
    if string.lower(value):find("phar://", 1, true) then return true end
    if value:find(':"', 1, true) and php_object(value) then return true end
    for token in value:gmatch("[TQ]zo[%w%+/=_%-]+") do
        if #token >= 16 then
            token = token:gsub("%-", "+"):gsub("_", "/")
            local decoded = ngx.decode_base64(token .. string.rep("=", (4 - #token % 4) % 4))
            if decoded and php_object(decoded) then return true end
        end
    end
    return false
end

-- SSRF: the whole value is a URL whose scheme is a dangerous wrapper, whose
-- host is internal (loopback, private, link-local, reserved, cloud metadata,
-- localhost / *.internal), or whose authority is obfuscated (several "@",
-- "@" with "#"/"&", spaces, backslashes, full-width characters, hex / octal /
-- integer / shortened IPv4). Port of scripts/security/wsa-proto/det.py ssrf.
-- NFKC is not available here: only full-width ASCII (U+FF01-FF5E) and the
-- ideographic full stop (U+3002) count as Unicode obfuscation.
-- IPv6 literals are judged for ::1, ::, fe80::/10, fc00::/7 and
-- ::ffff:<internal IPv4>.
local SSRF = {} -- one main-chunk local (LuaJIT caps a chunk at 200 locals)
SSRF.meta = { ["metadata.google.internal"] = true, ["metadata.packet.net"] = true, metadata = true,
    ["instance-data"] = true, ["metadata.azure.com"] = true, ["100.100.100.200"] = true }
SSRF.schemes = { jar = true, file = true, ftp = true, gopher = true, dict = true, ldap = true, ldaps = true,
    local_file = true, netdoc = true, tftp = true, php = true, expect = true, data = true, phar = true, sftp = true }

-- one IPv4 component (0x.. hex, 0.. octal, decimal) or nil
function SSRF.ipv4_part(p)
    local hex = p:match("^0[xX](%x+)$")
    if hex then return tonumber(hex, 16) end
    if p:match("^0[0-7]+$") then return tonumber(p, 8) end
    if p:match("^%d+$") then return tonumber(p) end
    return nil
end

-- host as a 32-bit IPv4 number (inet_aton forms: a, a.b, a.b.c, a.b.c.d) or nil
function SSRF.ipv4_value(host)
    local parts = {}
    for part in (host .. "."):gmatch("([^.]*)%.") do parts[#parts + 1] = part end
    if #parts < 1 or #parts > 4 then return nil end
    local nums = {}
    for i, part in ipairs(parts) do
        local n = SSRF.ipv4_part(part)
        if not n then return nil end
        nums[i] = n
    end
    if #nums == 1 then return nums[1] % 4294967296 end
    local value = 0
    for i = 1, #nums - 1 do
        if nums[i] > 255 then return nil end
        value = value * 256 + nums[i]
    end
    local tail_bytes = 5 - #nums
    if nums[#nums] >= 256 ^ tail_bytes then return nil end
    return value * 256 ^ tail_bytes + nums[#nums]
end

function SSRF.ipv4_internal(v)
    local a, b = math.floor(v / 16777216), math.floor(v / 65536) % 256
    return a == 0 or a == 10 or a == 127 or (a == 100 and b >= 64 and b <= 127) or (a == 169 and b == 254)
        or (a == 172 and b >= 16 and b <= 31) or (a == 192 and b == 168) or (a == 192 and b == 0)
        or (a == 198 and (b == 18 or b == 19)) or a >= 224
end

function SSRF.ipv6_internal(h)
    if h == "::1" or h == "::" then return true end
    if h:match("^fe[89ab]%x:") or h:match("^f[cd]%x%x:") then return true end
    local mapped = h:match("^::ffff:([%d.]+)$")
    if mapped then
        local v = SSRF.ipv4_value(mapped)
        return v ~= nil and SSRF.ipv4_internal(v)
    end
    return false
end

function SSRF.detect(value)
    local s = value:match("^%s*(.-)%s*$")
    -- waf-gap4: a name=URL pair sent as one value (a header or cookie
    -- carrying url=tftp://...): judge the URL
    local inner = s:match("^[%a_][%w_.%-]*=(.+)$")
    if inner and inner:find("^[%a][%w+.%-_]*:/") then s = inner end
    local scheme, slashes, rest = s:match("^([%a][%w+.%-_]+):(/*)(.*)$")
    if not scheme or #scheme > 16 then return false end
    scheme = string.lower(scheme)
    if scheme == "url" then return SSRF.detect(s:sub(5)) end
    -- a wrapper scheme counts with "//" or when it wraps another URL (jar:http://...)
    if SSRF.schemes[scheme] then return slashes ~= "" or rest:find("://", 1, true) ~= nil end
    if (scheme ~= "http" and scheme ~= "https") or slashes == "" then return false end
    local authority = rest:match("^[^/?#]*")
    local raw = authority
    local _, ats = raw:gsub("@", "")
    -- userinfo confusion: several "@", "@" with "#"/"&", encoded or escaped characters before "@"
    if raw:find(" ", 1, true) or raw:find("\\", 1, true) or ats > 1
        or (ats == 1 and (rest:find("#", 1, true) or raw:find("&", 1, true) or raw:match("^[^@]*%%"))) then
        return true
    end
    if ats == 1 then authority = authority:match("@(.*)$") end
    local host = authority:gsub(":%d*$", "")
    if host:find("\\", 1, true) or host:find("\239\188[\129-\191]") or host:find("\239\189[\128-\158]")
        or host:find("\227\128\130", 1, true) then
        return true
    end
    host = string.lower(host)
    if SSRF.meta[host] or host == "localhost" or host:match("%.localhost$") or host:match("%.internal$") then
        return true
    end
    local v6 = host:match("^%[(.*)%]$")
    if v6 then return SSRF.ipv6_internal(v6) end
    local v = SSRF.ipv4_value(host)
    if not v then return false end
    -- anything but plain dotted decimal without leading zeros is an evasion
    if not host:match("^%d+%.%d+%.%d+%.%d+$") or host:match("^0%d") or host:match("%.0%d") then return true end
    return SSRF.ipv4_internal(v)
end

-- Command injection: shell structure, not keywords. A known command word
-- right after a shell separator (; | || & && ` $( ), a command word whose
-- spelling was split by shell no-ops ('' "" \ $x ${x} ``) or written as a
-- glob (/bin/c?t, w[h]oami), a glob that matches a sensitive path
-- (/e?c/p*sswd), brace expansion {cat,/etc/passwd} and the fork bomb.
-- Ambiguous English words (cat, find, host, ...) after a separator need a
-- shell-like argument. Port of scripts/security/wsa-proto/det.py cmd.
local CMDI = { words = {}, ambiguous = {}, english = {} } -- one main-chunk local
for word in ([[cat tac head tail less more nl ls dir id whoami uname hostname ifconfig ip netstat ps env printenv
    wget curl nc ncat netcat telnet ssh scp bash sh zsh dash ksh csh tcsh python python2 python3 perl ruby php lua
    node ping nslookup dig host traceroute chmod chown chgrp rm mv cp touch mkdir rmdir kill pkill killall sleep
    base64 xxd od dd find grep awk sed xargs crontab at nohup sudo su useradd adduser usermod passwd socat tftp ftp
    lwp-download fetch powershell cmd certutil bitsadmin systeminfo net reg]]):gmatch("%S+") do
    CMDI.words[word] = true
end
for word in ([[at id host find more head tail touch less net fetch ip kill sleep dir cat env nl od su sh ps rm mv cp
    dd ftp ping]]):gmatch("%S+") do CMDI.ambiguous[word] = true end
for word in ([[cat at more head tail touch less net fetch find kill sleep host dir]]):gmatch("%S+") do
    CMDI.english[word] = true
end
CMDI.sensitive = { "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts", "/etc/issue", "/etc/sudoers",
    "/proc/self/environ", "/proc/self/cmdline", "/proc/version", "/bin/sh", "/bin/bash", "/bin/cat", "/bin/nc",
    "/usr/bin/id", "/usr/bin/whoami", "/bin/ls" }

-- remove shell no-ops an attacker inserts inside a word
function CMDI.unevade(w)
    if not w:find("[%$`'\"\\]") then return w end
    -- quotes in the middle of a word only split it for the shell: c'a't is cat
    return (w:gsub("%${[^}]*}", ""):gsub("%$[@*#?%d]", ""):gsub("%$[%a_][%w_]*", ""):gsub("``", "")
        :gsub("%$%(%)", ""):gsub("(%w)['\"]+(%w)", "%1%2"):gsub("(%w)['\"]+(%w)", "%1%2"):gsub("''", "")
        :gsub('""', ""):gsub("\\", ""))
end

-- shell glob (* ? [..]) against a literal, anchored
function CMDI.glob(pattern, text)
    local lua = pattern:gsub("[%^%$%(%)%%%.%+%-]", "%%%0"):gsub("%*", ".*"):gsub("%?", ".")
    -- an unbalanced [ (e.g. "[Host:") is no shell class: not a match
    -- (it made string.match raise "malformed pattern", a 500)
    local ok, matched = pcall(string.match, text, "^" .. lua .. "$")
    return ok and matched ~= nil
end

-- is the word a command; second result: was it disguised
function CMDI.word(raw)
    local w = string.lower(CMDI.unevade(raw)):gsub("^['\"]+", ""):gsub("['\"]+$", "")
    local base = w:match("([^/]*)$")
    if CMDI.words[base] then return true, raw ~= w and CMDI.unevade(raw) ~= raw end
    if #base >= 2 and #base <= 24 and base:find("[?*%[]") and base:find("%a") then
        local fixed = not base:find("*", 1, true)
        for command in pairs(CMDI.words) do
            if (not fixed or #command == #base) and CMDI.glob(base, command) then return true, true end
        end
    end
    return false, false
end

function CMDI.sensitive_glob(token)
    local t = string.lower(CMDI.unevade(token))
    if not t:find("[?*%[]") or t:sub(1, 1) ~= "/" then return false end
    local _, slashes = t:gsub("/", "")
    local _, letters = t:gsub("%a", "")
    if slashes < 2 or letters < 2 then return false end
    for _, path in ipairs(CMDI.sensitive) do
        if CMDI.glob(t, path) then return true end
    end
    return false
end

-- a shell-like argument after an ambiguous word: option, number, path, variable, IP, script file
function CMDI.argument(rest)
    return rest:match("^%s+%-%-?%a") or rest:match("^%s+%d+%s*$") or rest:match("^%s+[/~.%$]")
        or rest:match("^%s+%d+%.%d+%.") or rest:match("^%s+['\"]?/")
        or rest:match("^%s+[%w._-]+%.[%a]+") and (rest:match("^%s+[%w._-]+%.(%a+)") or ""):match("^[ps][hylo]")
end

function CMDI.after_separator(s, finish, word, separator)
    local ok, disguised = CMDI.word(word)
    if not ok then return false end
    local w = string.lower(CMDI.unevade(word)):gsub("^['\"]+", ""):gsub("['\"]+$", ""):match("([^/]*)$")
    if not CMDI.ambiguous[w] or disguised or word:find("/", 1, true) then return true end
    local rest = s:sub(finish + 1)
    if CMDI.argument(rest) then return true end
    if not CMDI.english[w] and rest:match("^%s*$") then return true end
    return (separator == "`" or separator == "$(") and rest:match("^%s*[`)]") ~= nil
end

function CMDI.detect(value)
    if not value:find("[;|&`$(){}/*?%[\\'\"]") then return false end
    local s = value:gsub("```", "")
    -- waf-gap4: shell-only syntax that probes use (commix): arithmetic
    -- expansion $((n+n)) and $IFS / ${IFS} as a space
    if s:find("$((", 1, true) and s:find("%$%(%(%s*%d+%s*[%+%-%*/%%]%s*%d+%s*%)%)") then return true end
    if s:find("%${?IFS[}%$%w]") then return true end
    -- fork bomb f(){ f|f& };f — the backreference pattern is slow, so only when "()" and "|" are there
    if s:find("()", 1, true) and s:find("|", 1, true)
        and s:match("([%w_:]+)%s*%(%)%s*{%s*%1%s*|%s*%1%s*&%s*}%s*;%s*%1") then return true end
    if s:find("{", 1, true) and s:find(",", 1, true) then for inner in s:gmatch("{([^{}]*,[^{}]*)}") do
        local first = inner:match("^([^,]+)")
        if first and CMDI.word((first:gsub("^[%$'\"]+", ""):gsub("['\"]+$", ""))) then return true end
    end end
    if s:find("/", 1, true) and s:find("[?*%[]") then
        for token in s:gmatch("[^%s;|&`()<>]+") do
            if CMDI.sensitive_glob(token) then return true end
        end
    end
    local position = s:find("[;|&`]") or s:find("$(", 1, true) or #s + 1
    while position <= #s do
        local start, finish, separator = s:find("([;|&`]+)", position)
        local dollar = s:find("$(", position, true)
        if dollar and (not start or dollar < start) then start, finish, separator = dollar, dollar + 1, "$(" end
        if not start then break end
        if separator ~= "$(" then
            separator = separator:sub(1, 1) == "`" and "`" or separator:match("^([;|&][|&]?)")
        end
        local after = s:sub(finish + 1)
        local skip = after:match("^%s*") .. (after:match("^%s*(%$[%a_][%w_]*%s+)") or "")
        local word_start = finish + #skip + 1
        local word = s:match("^([^%s;|&`()<>]+)", word_start)
        -- the word ends at whitespace or a separator; quotes and $vars inside belong to it
        if word then word = word:gsub("^(.-)[%s].*$", "%1") end
        if word and CMDI.after_separator(s, word_start + #word - 1, word, separator) then return true end
        position = finish + 1
    end
    local leading = s:match("^%s*([^%s;|&()<>]+)")
    -- a leading word only counts when disguised (shell no-ops or a glob inside it)
    if leading and leading:find("[%$`'\"\\?*%[]") then
        local ok, disguised = CMDI.word(leading)
        if ok and disguised then return true end
    end
    return false
end

local DETECTORS = { sqli = detect_sqli, xss = detect_xss, ssti = detect_ssti, java_deser = detect_java_deser,
    php_deser = detect_php_deser, ssrf = SSRF.detect, cmd = CMDI.detect }
-- words(set, text): set[word] = true for each word (a function: a main
-- chunk for loop's hidden locals would pass Lua's 200)
DETECTORS.words = function(set, text) for word in text:gmatch("%S+") do set[word] = true end return set end

-- waf-gap4 detectors (strong signals only; values as inspect sees them, URL
-- decoded). Fields of DETECTORS: the main chunk is at Lua's 200 local limit.
--
-- crlf: a line break (CR/LF, the literal \r \n escapes, or the U+010A/U+010D
-- and U+560A/U+560D forms some servers truncate to a byte, %u000a, \u000a,
-- 0x0A) followed by a response header or status line. Any header name
-- counts when the break is at the value's start (splitting injects right
-- there); the splitting-only ones (Set-Cookie, HTTP/1.x, Content-Length,
-- ...) anywhere. A break at the start followed by another
-- break and markup is body injection.
DETECTORS.CRLF_STRONG = { ["set-cookie"] = true, ["set-cookie2"] = true, ["content-length"] = true,
    ["transfer-encoding"] = true, ["x-xss-protection"] = true, ["content-security-policy"] = true,
    ["www-authenticate"] = true, ["access-control-allow-origin"] = true, ["access-control-allow-credentials"] = true,
    ["x-forwarded-for"] = true, ["x-forwarded-host"] = true, ["x-real-ip"] = true, refresh = true }
function DETECTORS.crlf(value)
    if not value:find("[\r\n\\\196\229]") and not value:find("0[xX]0") and not value:find("%%[uU]000") then return false end
    local text = value:gsub("\\[rn]", "\n"):gsub("\\t", "\t"):gsub("[%%\\][uU]000[aAdD]", "\n"):gsub("0[xX]0[aAdD]", "\n")
        :gsub("\196[\138\141]", "\n"):gsub("\229\152[\138\141]", "\n")
    -- binary (other control bytes) is not a header line
    if not text:find("[\r\n]") or text:find("[%z\1-\8\11\12\14-\31\127]") then return false end
    -- a dump of header lines (session replay, logs: three or more
    -- "name: value" lines) is data about HTTP, not an injection
    local _, lines = text:gsub("[\r\n]+%s*[%a][%w%-]*%s*:", "")
    if lines >= 3 and not text:find("^[^%w\r\n]?[^%w\r\n]?[^%w\r\n]?[\r\n]") then return false end
    for start, name in text:gmatch("()[\r\n]+%s*([%a][%w%-]*)%s*:") do
        -- at the value's start (after at most a path like ../ or a few
        -- bytes) any header name: that is where splitting injects
        if start <= 4 and not text:sub(1, start - 1):find("[%w]") or DETECTORS.CRLF_STRONG[string.lower(name)] then return true end
    end
    if text:find("[\r\n]+%s*[Hh][Tt][Tt][Pp]/%d[%.%d]*%s+%d%d%d") then return true end
    return text:find("^[^\r\n]?[^\r\n]?[^\r\n]?[\r\n]+[\r\n]+%s*<") ~= nil
end

-- redirect (open redirect): a target whose authority is disguised. Plain
-- //host/path and https://host are what return URLs legitimately carry; an
-- attack hides the host from a naive "starts with /" or "contains my
-- domain" check: a backslash, tab or encoded whitespace among the leading
-- slashes, three or more slashes, a scheme without slashes before an
-- obfuscated IP (http:0330.072.0326.0316, http:3627734734),
-- userinfo that looks like a domain (trusted.tld@evil.com). A host must
-- follow (a domain or an IP literal), so escaped JSON or binary starting
-- with a backslash does not count.
DETECTORS.HOST = "^[%w%-]+%.[%w%-%.]*[%w]"
function DETECTORS.redirect(value)
    local s = value:match("^%s*(.-)%s*$")
    local lead, after = s:match("^([/\\][/\\%s%c]*)(.*)$")
    if lead and (lead:find("[\\%c%s]") and lead:find("[/\\].*[/\\%c%s]") or #lead >= 3 and not lead:find("[^/]")) then
        return after:find(DETECTORS.HOST) ~= nil or after:find("^%[") ~= nil
    end
    local scheme, rest = s:match("^([%a][%w+.%-]*):(.*)$")
    if scheme then
        scheme = string.lower(scheme)
        if scheme ~= "http" and scheme ~= "https" then return false end
        -- https:host without slashes also comes from analytics that lost
        -- "//" (dl=https:account.booking.com): only an IP in disguise counts
        if rest:find("^[%w%[]") then
            local host = rest:match("^[^/?#]*")
            local userinfo = host:match("^([^@]*)@")
            if userinfo and userinfo:find("[%w%-]%.[%a][%w%-]*") then return true end
            host = host:gsub("^.*@", ""):gsub(":%d*$", "")
            return host:find("^%d+$") ~= nil or host:find("^0[xX]%x") ~= nil or host:find("^%d+%.0%d") ~= nil
                or host:find("^0%d+%.") ~= nil
        end
        if rest:find("^/?[\\%c]") then return true end
        rest = rest:gsub("^/+", "")
    elseif s:find("^//") then
        rest = s:sub(3)
    else
        return false
    end
    local userinfo = rest:match("^([^/?#@]*)@")
    return userinfo ~= nil and userinfo:find("[%w%-]%.[%a][%w%-]*") ~= nil
end

-- format: printf directives a C/native formatter would act on, written
-- next to each other (stack walking %x%x%x%x, %s%p%x%d, %p.%p.%p): three
-- adjacent with %n or %p, four otherwise, or a positional %N$x. Isolated
-- %s / %d (i18n strings, "50% off", random tokens) never count; nor
-- values over 1 KiB (telemetry blobs: an attack probe is short).
function DETECTORS.format(value)
    if #value > 1024 or not value:find("%", 1, true) then return false end
    if value:find("%%%d+%$[hlLqjzt]*[nspxXdiouc]") then return true end
    local run, pointer = 0, false
    local index = 1
    while true do
        local start, finish, conversion = value:find("^%%[-+ #0]*%d*%.?%d*[hlLqjzt]*([pxXnsduoeEfgGic])", index)
        if start then
            run, index = run + 1, finish + 1
            pointer = pointer or conversion == "n" or conversion == "p"
            if run >= 4 or run >= 3 and pointer then return true end
            local gap = value:match("^[%s.,:|_%-]?", index)
            index = index + #gap
        else
            local nxt = value:find("%", index + 1, true)
            if not nxt then return false end
            run, pointer, index = 0, false, nxt
        end
    end
end

-- nosql: MongoDB query operators where a credential or lookup value was
-- expected: a parameter name like user[$ne] / password[$regex] (form and
-- query brackets; detect_args adds key[$op] for a JSON object under such a
-- key), {"$ne": ...} inside a value, server-side JavaScript ($where with
-- code, this.<field>.match(, db.<coll>.<op>(, '; sleep(). Plain operator
-- keys elsewhere (Strapi / Hasura style filters) and GraphQL $where
-- variables do not count.
DETECTORS.NOSQL_OPS = DETECTORS.words({}, "ne nin gt gte lt lte regex where exists expr elemmatch function accumulator eq or")
DETECTORS.NOSQL_KEYS = DETECTORS.words({}, [[user username login pass password passwd pwd email mail token auth
    secret account name uid userid user_id session code otp pin]])
function DETECTORS.nosql(value)
    local lowered = string.lower(value)
    if lowered:find("$", 1, true) then
        for key, op in lowered:gmatch("([%w_]+)%[%s*%$([%a]+)%s*%]") do
            if DETECTORS.NOSQL_OPS[op] and DETECTORS.NOSQL_KEYS[key] then return true end
        end
        for key, op in lowered:gmatch("[\"']*([%w_]+)[\"']*%s*:%s*{%s*[\"']%$([%a]+)[\"']%s*:") do
            if DETECTORS.NOSQL_OPS[op] and DETECTORS.NOSQL_KEYS[key] then return true end
        end
        if lowered:find("%$where%s*[\"']?%s*:%s*[\"']?%s*[%w%s]*[=!<>]=") or lowered:find("%$where%s*[\"']?%s*:%s*function")
            or lowered:find("[\"']%s*[,}%]]+%s*%]?%s*,?%s*%$[%a]+%s*:") and lowered:find("^%s*[\"']") then
            return true
        end
    end
    if lowered:find("this.", 1, true) and lowered:find("this%.[%a_][%w_]*%.match%s*%(") then return true end
    if lowered:find("db.", 1, true) and lowered:find("^%s*db%.[%a_][%w_]*%.[%a]+%s*%(") then return true end
    return lowered:find("^%s*['\"]%s*[;&|]+%s*sleep%s*%(%s*%d") ~= nil or lowered:find("['\"]%s*&&%s*this%.") ~= nil
        or lowered:find("^%s*['\"]%s*;%s*return%s") ~= nil
end

-- ldap: filter injection: a complete filter term (attr=value) next to a
-- break out of the application's filter (*)( , )(|( , )(&( , )(attr=*)
-- or a value that is itself a boolean term list (|(a=..)(b=..)).
function DETECTORS.ldap(value)
    if #value > 1024 or not value:find("=", 1, true) or not value:find(")", 1, true) then return false end
    local s = value:gsub("%s+", "")
    if not s:find("%([|&!]?%(?[%a][%w%-]+[~<>]?=[^()]*%)") then return false end
    if s:find("%)%(+[|&!]%(") or s:find("%*%)%(") or s:find("%)%([%a][%w%-]+[~<>]?=%*") then return true end
    return s:find("^[%w*]*%(?%([|&!]%([%a][%w%-]+[~<>]?=") ~= nil
end

-- xxe: XML that makes the parser fetch or expand something: an external
-- entity or DTD (<!ENTITY [%] name SYSTEM|PUBLIC "...">, <!DOCTYPE x SYSTEM
-- "...">), a parameter entity, XInclude, an XSLT extension namespace
-- (php: / java: / exslt) or a billion-laughs style entity referring to
-- entities. An internal text entity alone (<!ENTITY a "text">) does not.
function DETECTORS.xxe(value)
    if not value:find("<", 1, true) then return false end
    local lowered = string.lower(value)
    if lowered:find("<!entity%s+%%") or lowered:find("<!entity%s+[%w_.:%-]+%s+system%s*[\"']")
        or lowered:find("<!entity%s+[%w_.:%-]+%s+public%s*[\"']") or lowered:find("<!doctype%s+[%w_.:%-]+%s+system%s*[\"']")
        or lowered:find("<!doctype%s+[%w_.:%-]+%s+public%s*[\"']") then
        return true
    end
    if lowered:find("<xi:include", 1, true) or lowered:find("xmlns:xi%s*=%s*[\"']http://www%.w3%.org/2001/xinclude") then return true end
    if lowered:find("<xsl:", 1, true) and (lowered:find("xmlns:php", 1, true) or lowered:find("xmlns:java", 1, true)
        or lowered:find("xalan", 1, true) or lowered:find("document%s*%(") or lowered:find("unparsed%-text")) then
        return true
    end
    return lowered:find("<!entity%s+[%w_.:%-]+%s+[\"'][^\"']*&[%w_.:%-]+;") ~= nil
end

-- upload (multipart file names, not argument values; detect_args feeds it
-- upload_names): a server-side executable extension anywhere in the name
-- (double extension shell.php.jpg, shell.jpg.php, case and digit variants),
-- a name that ends the extension early (NUL, ::$DATA, ";", trailing dots or
-- spaces) or a server configuration file (.htaccess, web.config, .user.ini).
DETECTORS.UPLOAD_EXEC = {}
DETECTORS.words(DETECTORS.UPLOAD_EXEC, [[php php2 php3 php4 php5 php6 php7 php8 pht phtm phtml phar pgif inc asp aspx asa cer cdx ashx asmx
    axd jsp jspx jsw jsv jspf shtml shtm stm cgi pl py rb sh war]])
function DETECTORS.upload(name)
    local base = string.lower(name:match("([^/\\]*)$") or name)
    if base == ".htaccess" or base == "web.config" or base == ".user.ini" then return true end
    if base:find("%z") or base:find("%%00") or base:find("::$data", 1, true) or base:find("[;:]") then return true end
    for part in base:gmatch("%.([^.]*)") do
        if DETECTORS.UPLOAD_EXEC[(part:gsub("[%s]+$", ""))] then return true end
    end
    return base:find("[%s.]+$") ~= nil and base:find("%.") ~= nil
end

-- Additional injection detectors.
--
-- proto: JavaScript prototype pollution: __proto__ (any case, as a name, a
-- path segment or a JSON key), constructor followed by prototype as the next
-- path segment (constructor.prototype, constructor[prototype], a JSON
-- {"constructor":{"prototype":...}}), a write to Object.prototype, and the
-- legacy accessor definers (__defineGetter__ ...). "prototype" or
-- "constructor" alone, or in prose ("Array.prototype.map"), does not count.
DETECTORS.PROTO_DEFINERS = { "__definegetter__", "__definesetter__", "__lookupgetter__", "__lookupsetter__" }
function DETECTORS.proto(value)
    if #value > 4096 then value = value:sub(1, 4096) end
    local s = string.lower(value)
    if s:find("__proto__", 1, true) then return true end
    for _, name in ipairs(DETECTORS.PROTO_DEFINERS) do
        if s:find(name, 1, true) then return true end
    end
    -- segments: a.b, a[b], a['b'], {"a":{"b" (JSON key followed by an object)
    if s:find("constructor%s*[%.%[]%s*['\"]?prototype") or s:find("[\"']constructor[\"']%s*:%s*{%s*[\"']prototype[\"']") then
        return true
    end
    return s:find("^%s*object%.prototype%.[%a_$][%w_$]*") ~= nil
end

-- path: traversal out of the web root and its encodings: "../" or "..\"
-- (three levels, two from the start or below a path, or one into a system
-- directory or file), the doubled / dotted variants ("....//", "..././",
-- ".%2e/"), overlong UTF-8, %uXXXX, fullwidth and nested / double URL
-- encodings that survive one decode, "..;/" (Tomcat path parameter), a NUL
-- right after a path, and well-known system files and directories
-- (/etc/passwd, win.ini, WEB-INF/web.xml, /proc/...) as the whole value. A
-- single "../" to an asset (relative links), ordinary file paths and dotted
-- prose do not count.
DETECTORS.PATH_FILES = { "etc/passwd", "etc/shadow", "etc/hosts", "etc/group", "etc/issue", "proc/self/", "boot.ini",
    "win.ini", "system.ini", "windows/system32", "windows\\system32", "web-inf/web.xml", "web-inf\\web.xml",
    "system32/drivers/etc", "system32\\drivers\\etc", ".htpasswd", ".ssh/id_rsa", ".ssh/authorized_keys" }
DETECTORS.PATH_DOT = { "%%c0%%ae", "%%c0%%2e", "%%e0%%80%%ae", "%%f0%%80%%80%%ae", "%%f8%%80%%80%%80%%ae",
    "%%fc%%80%%80%%80%%80%%ae", "%%uff0e", "%%u002e", "0x2e", "%%c0%%6e", "\192\174", "\224\128\174", "\239\188\142" }
DETECTORS.PATH_SEP = { "%%c0%%af", "%%c0%%2f", "%%e0%%80%%af", "%%f0%%80%%80%%af", "%%f8%%80%%80%%80%%af",
    "%%fc%%80%%80%%80%%80%%af", "%%c1%%9c", "%%c1%%1c", "%%c1%%pc", "%%c0%%5c", "%%c0%%9v", "%%c0%%qf", "%%c1%%8s",
    "%%bg%%qf", "%%u2215", "%%u2216", "%%uefc8", "%%uf025", "%%ef%%bc%%8f", "%%ef%%bc%%bc", "0x5c", "0x2f",
    "\192\175", "\193\156", "\226\136\149", "\226\136\150", "\239\188\143", "\239\188\188" }
function DETECTORS.path(value)
    -- a value over 1 KiB is no path (telemetry and encoded blobs; as format/ldap)
    if #value > 1024 then return false end
    local s = string.lower(value)
    if not s:find("[./\\%%?]") and not s:find("0x[25]") then return false end
    if s:find("%%[%x%%u]") or s:find("[\192-\239]") or s:find("0x[25]") then
        -- decode what one URL decode left (double / nested encoding:
        -- %252e, %%32%%65 = "%" "2" "e"), then fold the non-ASCII and
        -- invalid dot / separator spellings (overlong UTF-8, %u, fullwidth,
        -- 0x2e, dotdotpwn's %c1%pc)
        for _ = 1, 3 do
            local before = s
            s = s:gsub("%%%%", "%%"):gsub("%%25", "%%"):gsub("%%3(%x)", "%1")
            s = s:gsub("%%%%", "%%"):gsub("%%2e", "."):gsub("%%2f", "/"):gsub("%%5c", "\\")
            if s == before then break end
        end
        if s:find("%%[%x%%u]") or s:find("[\192-\239]") or s:find("0x[25]") then
            for _, form in ipairs(DETECTORS.PATH_DOT) do s = s:gsub(form, ".") end
            for _, form in ipairs(DETECTORS.PATH_SEP) do s = s:gsub(form, "/") end
            s = s:gsub("%%00", "\0"):gsub("%%01", ""):gsub("%%c0%%5e", ".")
        end
    end
    s = s:gsub("\\", "/")
    -- a NUL right after a path (extension truncation)
    if s:find("[%w/]%z") and s:find("/", 1, true) then return true end
    -- dot runs that collapse to ".." after a strip pass ("....//", "..././",
    -- ".?./", ".%00./"), "..;/" (Tomcat path parameter) in text
    if s:find("%.%.%.%.//") or s:find("%.%.%./%./") then return true end
    if s:find("%.[%z?]%./") then return true end
    if s:find("%.%.;/") and not value:find("[%z\1-\8\14-\31\127]") then return true end
    local _, ups = s:gsub("%.%./", "")
    local _, downs = s:gsub("/%.%.", "")
    local whole = s:match("^%s*(.-)%s*$")
    -- an absolute path (or a drive) of no prose: a file name, not a sentence
    local absolute = not whole:find("%s[^%s]*%s") and (whole:find("^/") or whole:find("^%a:/"))
    for _, file in ipairs(DETECTORS.PATH_FILES) do
        local at = s:find((file:gsub("\\", "/")), 1, true)
        if at and (ups + downs > 0 or absolute) then return true end
    end
    -- an absolute path into the system directories (LFI word lists), or a
    -- traversal into one ("../var/log/x")
    local into = whole:match("^/?(.*)$")
    if ups > 0 then into = whole:match("^[./]*/(.*)$") or into end
    if (absolute or ups > 0) and (into:find("^etc/[%w_]") or into:find("^proc/[%w_]") or into:find("^sys/[%w_]")
        or into:find("^var/log/") or into:find("^var/adm/") or into:find("^root/") or into:find("^%a:/windows/")
        or into:find("^windows/") or into:find("^%a:/winnt/") or into:find("^%a:/inetpub/") or into:find("^usr/local/")
        or into:find("^volumes/") or into:find("^private/etc/") or into:find("^%a:/boot%.ini")) then
        return true
    end
    -- climbing levels in a row: three or more "../" anywhere, or two from
    -- the value's start or right below a path ("/var/www/../../x"), except
    -- a relative asset link (../../assets/logo.svg)
    if s:find("%.%./%.%./%.%./") or s:find("%.%./%.%./%.%.$") then return true end
    if s:find("%.%./%.%./") and not s:find("^%.%./%.%./[%w_%-]+[%w_%-./]*%.[%a]+$") then
        return s:find("^%s*/?%.%./%.%./") ~= nil or s:find("^[%w_%-.:]*/[%w_%-./]*/%.%./%.%./") ~= nil
    end
    -- a traversal to a placeholder or template file name ({FILE})
    return ups > 0 and s:find("%.%./{[%w_]+}") ~= nil
end

-- base64_text(value): the text a parameter value of at least 16 base64
-- characters decodes to (standard or URL alphabet, padding optional), nil for
-- anything else or when it decodes to bytes that are not text (a serialized
-- object, an image, a hash).
function DETECTORS.base64_text(value)
    if #value < 16 or #value > 8192 or not value:find("^[%w+/_%-]+=?=?$") then return nil end
    local padded = value:gsub("=+$", ""):gsub("-", "+"):gsub("_", "/")
    if #padded % 4 == 1 then return nil end
    local decoded = ngx.decode_base64(padded .. string.rep("=", (4 - #padded % 4) % 4))
    if not decoded or #decoded == 0 or decoded:find("[%z\1-\8\14-\31\127]") then return nil end
    -- printable ASCII or valid UTF-8 text only
    if decoded:find("[\128-\255]") and not ngx.re.find(decoded, [[^(?:[\x09-\x0d\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|]] ..
        [[[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3})*$]], "jo") then
        return nil
    end
    return decoded
end



local function fragment_of(value, from, to)
    if type(value) ~= "string" then return nil end
    from, to = from or 1, to or #value
    local start = math.max(1, from - 32)
    return value:sub(start, math.min(#value, to + 32, start + INSPECT_FRAGMENT_BYTES - 1))
end

-- positive_match: the first target value matching the (non-negated) operator,
-- returned as fragment, detector.
local function positive_match(spec, operator, values)
    if operator == "contains" or operator == "contains_all" then
        for _, value in ipairs(values) do
            local lowered = string.lower(value)
            if operator == "contains" then
                for _, needle in ipairs(spec.needles) do
                    local from, to = lowered:find(needle, 1, true)
                    if from then return fragment_of(value, from, to) end
                end
            else
                local first, last
                for _, needle in ipairs(spec.needles) do
                    local from, to = lowered:find(needle, 1, true)
                    if not from then first = nil break end
                    first, last = first and math.min(first, from) or from, last and math.max(last, to) or to
                end
                if first then return fragment_of(value, first, last) end
            end
        end
    elseif operator == "regex" then
        for _, value in ipairs(values) do
            for _, pattern in ipairs(spec.values) do
                local from, to = ngx.re.find(value, pattern, "jo")
                if from then return fragment_of(value, from, to) end
            end
        end
    elseif operator == "prefix" or operator == "suffix" or operator == "equals" then
        for _, value in ipairs(values) do
            for _, entry in ipairs(spec.values) do
                if operator == "equals" and value == entry or
                    operator == "prefix" and value:sub(1, #entry) == entry or
                    operator == "suffix" and #value >= #entry and value:sub(-#entry) == entry then
                    return fragment_of(value)
                end
            end
        end
    elseif operator == "detect" then
        for _, value in ipairs(values) do
            for _, name in ipairs(spec.values) do
                local detector = DETECTORS[name]
                if type(detector) == "function" and detector(value) then return fragment_of(value), name end
            end
        end
    end
    return nil
end

local function decode_spec(raw)
    local spec = cjson.decode(raw)
    if type(spec) ~= "table" or type(spec.values) ~= "table" then return false end
    spec.number = NUMBER_COMPARE[spec.operator] ~= nil
    if spec.number then
        spec.limit = tonumber(spec.values[1])
        if not spec.limit then return false end
    end
    spec.positive = NEGATED[spec.operator] or spec.operator
    spec.negated = NEGATED[spec.operator] ~= nil
    if spec.positive == "contains" or spec.positive == "contains_all" then
        spec.needles = {}
        for index, needle in ipairs(spec.values) do spec.needles[index] = string.lower(needle) end
    end
    spec.overflow_match = spec.body_overflow == "match"
    return spec
end

-- record_match keeps the evidence of the last clause that held: what the
-- security log reports (target, key, detector, matched fragment).
local function record_match(spec, fragment, detector)
    local ctx = ngx.ctx
    ctx.cdnca_inspect_last = { target = spec.target, key = spec.key, operator = spec.operator,
        detector = detector, fragment = fragment }
    if detector then ctx.cdnca_inspect_detector = detector end
end

function _M.inspect(raw)
    local spec = inspect_specs[raw]
    if spec == nil then
        spec = decode_spec(raw)
        if inspect_spec_count >= 4096 then inspect_specs, inspect_spec_count = {}, 0 end
        inspect_specs[raw], inspect_spec_count = spec, inspect_spec_count + 1
    end
    if not spec then return false end
    if spec.overflow_match and body_truncated(spec.target) then
        record_match(spec, nil, nil)
        ngx.ctx.cdnca_inspect_last.overflow = true
        return true
    end
    if spec.number then
        local compare = NUMBER_COMPARE[spec.operator]
        local number = inspect_number(spec.target)
        if number ~= nil then
            if compare(number, spec.limit) then
                record_match(spec, tostring(number), nil)
                return true
            end
            return false
        end
        for _, value in ipairs(filtered_values(spec)) do
            if type(value) == "number" and compare(value, spec.limit) then
                record_match(spec, tostring(value), nil)
                return true
            end
        end
        return false
    end
    local values = filtered_values(spec)
    local fragment, detector = positive_match(spec, spec.positive, values)
    local matched = fragment ~= nil
    if spec.negated then matched = not matched end
    if matched then record_match(spec, not spec.negated and fragment or nil, detector) end
    return matched
end

-- ip_list(raw): an IP list condition (edgeconfig
-- WAFIPList / IPListConditionSpec JSON {id, revision, negate, cidrs}) holds
-- when the client address is (negate: is not) in one of the CIDRs. The
-- address is looked up like nginx geo does: an IPv4-mapped IPv6 address as
-- IPv4. Matchers (lua-resty-ipmatcher) are cached per worker by the spec text.
_M.ip_lists = { count = 0, matchers = {} }
function _M.ip_list(raw)
    local cache = _M.ip_lists
    local entry = cache.matchers[raw]
    if entry == nil then
        local spec = cjson.decode(raw)
        entry = false
        if type(spec) == "table" and type(spec.cidrs) == "table" and #spec.cidrs > 0 then
            local matcher = require("resty.ipmatcher").new(spec.cidrs)
            if matcher then entry = { matcher = matcher, negate = spec.negate == true } end
        end
        if cache.count >= 1024 then cache.matchers, cache.count = {}, 0 end
        cache.matchers[raw], cache.count = entry, cache.count + 1
    end
    if not entry then return false end
    local address = ngx.var.remote_addr or ""
    local mapped = address:match("^::[fF][fF][fF][fF]:(%d+%.%d+%.%d+%.%d+)$")
    local inside = entry.matcher:match(mapped or address) and true or false
    if entry.negate then return not inside end
    return inside
end

-- text_values: the filtered values cdnca_waf.inspect reads for a clause of
-- spec {target, key, filters} (the rule interpreter's match index scans them
-- once per request; same cache, same body read).
_M.text_values = filtered_values

-- last_match is the evidence of the last inspect clause that held in this
-- request (nil when none did).
function _M.last_match()
    return ngx.ctx.cdnca_inspect_last
end

-- ---------------------------------------------------------------------------
-- WAF actions (edgeconfig waf_action.go, CAPABILITY_NAME_WAF v2): a segment
-- of a policy with challenge / ban rules, auto block or observe mode ends in
--   require("cdnca_waf").act(spec, action, rule_id)
-- instead of the plain block / log code, and starts with
--   if require("cdnca_waf").gate(spec) then return end
-- spec is the JSON of wafActionSpec: scope (the site), kind, policy_id, mode,
-- auto_block, telemetry and per rule action parameters (rules[rule_id]).
-- State (bans, auto block counters, challenge nonces, the pass secret) lives
-- in lua_shared_dict cdnca_waf_state, keyed by scope so sites never share it.
-- ---------------------------------------------------------------------------
local resty_random = require "resty.random"
local bit = require "bit"
local WAF_STATE_DICT = "cdnca_waf_state"
local WAF_VERIFY_PATH = "/.cdnca/waf/verify"
local WAF_PASS_COOKIE = "__cdnca_waf_pass"
local WAF_PROBE_COOKIE = "__cdnca_waf_probe"
local WAF_CHALLENGE_SECONDS = 300
local WAF_MAX_TARGET_BYTES = 2048
local WAF_SECRET_KEY = "wafs:secret"
local action_specs = {}
local action_spec_count = 0

local function waf_state()
    return ngx.shared[WAF_STATE_DICT]
end

-- The differential harness (libs/edgeconfig rule_plan_diff_integration_test)
-- gives every request its own state with ngx.ctx.cdnca_waf_scope_suffix.
local function scoped(spec)
    local suffix = ngx.ctx.cdnca_waf_scope_suffix
    if suffix then
        local copy = setmetatable({ scope = spec.scope .. suffix }, { __index = spec })
        return copy
    end
    return spec
end

local function action_spec(raw)
    local spec = action_specs[raw]
    if spec == nil then
        spec = cjson.decode(raw) or false
        if spec and type(spec.rules) ~= "table" then spec.rules = {} end
        if action_spec_count >= 4096 then action_specs, action_spec_count = {}, 0 end
        action_specs[raw], action_spec_count = spec, action_spec_count + 1
    end
    return spec
end

local function client_ip()
    return ngx.var.remote_addr or ""
end

-- The client network a pass is bound to: /24 for IPv4, /64 for IPv6.
local function client_network(address)
    local a, b, c = address:match("^(%d+)%.(%d+)%.(%d+)%.%d+$")
    if a then return a .. "." .. b .. "." .. c .. ".0/24" end
    local groups = {}
    for group in (address .. ":"):gmatch("([^:]*):") do groups[#groups + 1] = group end
    return table.concat(groups, ":", 1, math.min(4, #groups)) .. "::/64"
end

local function sha256_hex(value)
    local digest = resty_sha256:new()
    digest:update(value)
    return resty_string.to_hex(digest:final())
end

local function waf_secret(dict)
    local secret = dict:get(WAF_SECRET_KEY)
    if secret then return secret end
    local bytes = resty_random.bytes(32, true)
    if not bytes then return nil end
    dict:add(WAF_SECRET_KEY, resty_string.to_hex(bytes))
    return dict:get(WAF_SECRET_KEY)
end

local function random_token()
    local bytes = resty_random.bytes(16, true) or resty_random.bytes(16)
    return bytes and resty_string.to_hex(bytes) or nil
end

local function user_agent_digest()
    return sha256_hex(ngx.var.http_user_agent or ""):sub(1, 16)
end

local function constant_equal(left, right)
    if type(left) ~= "string" or type(right) ~= "string" or #left ~= #right then return false end
    local diff = 0
    for index = 1, #left do diff = bit.bor(diff, bit.bxor(left:byte(index), right:byte(index))) end
    return diff == 0
end

-- The request target a passed challenge returns to: the request URI when it
-- is a plain origin-form path, else "/".
local function waf_target()
    local target = ngx.var.request_uri or "/"
    if target:sub(1, 1) ~= "/" or target:sub(1, 2) == "//" or #target > WAF_MAX_TARGET_BYTES or
        target:find("[%c\\]") or target:sub(1, #WAF_VERIFY_PATH) == WAF_VERIFY_PATH then
        return "/"
    end
    return target
end

local function ban_key(spec, address) return "wafs:ban:" .. spec.scope .. ":" .. address end

-- Telemetry variables of the WAF v2 decisions (gate / act): $cdnca_security_*,
-- the names every runtime declares (configure{variables} may rename them).
local telemetry_vars = {
    emit = "cdnca_security_emit", type = "cdnca_security_type", action = "cdnca_security_action",
    severity = "cdnca_security_severity", rule_id = "cdnca_security_rule_id", block_page = "cdnca_security_block_page",
}

-- configure (init_by_lua): opts.variables maps emit, type, action, severity,
-- rule_id and block_page to variable names.
function _M.configure(opts)
    local variables = opts and opts.variables
    if variables == nil then return end
    if type(variables) ~= "table" then error("invalid WAF variables") end
    for key in pairs(telemetry_vars) do
        local name = variables[key]
        if type(name) ~= "string" or not name:match("^[a-z][a-z0-9_]*$") then error("invalid WAF variables") end
        telemetry_vars[key] = name
    end
end

-- telemetry_variables: the configured names (cdnca_rule_interp shares them).
function _M.telemetry_variables() return telemetry_vars end

local function set_block_page()
    pcall(function() ngx.var[telemetry_vars.block_page] = "1" end)
end

local function set_telemetry(spec, action, severity, rule_id, block_page)
    if not spec.telemetry then return end
    _M.evidence(spec.policy_id)
    local var = ngx.var
    var[telemetry_vars.emit] = "1"
    var[telemetry_vars.type] = spec.kind
    var[telemetry_vars.action] = action
    if block_page then var[telemetry_vars.block_page] = "1" end
    var[telemetry_vars.severity] = severity
    var[telemetry_vars.rule_id] = rule_id
end

local function send_page(status, title, body, script, headers)
    local nonce = random_token() or "0"
    ngx.status = status
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["Content-Security-Policy"] = "default-src 'none'; style-src 'nonce-" .. nonce .. "'; script-src 'nonce-" ..
        nonce .. "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    for name, value in pairs(headers or {}) do ngx.header[name] = value end
    ngx.print('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>',
        title, '</title><style nonce="', nonce, '">body{font-family:system-ui,sans-serif;background:#f5f6f8;color:#1f2329;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}main{background:#fff;padding:32px;border-radius:8px;max-width:420px;width:90%;box-shadow:0 2px 12px rgba(0,0,0,.08)}h1{font-size:20px;margin:0 0 16px}</style></head><body><main><h1>',
        title, "</h1>", body, "</main>")
    if script then ngx.print('<script nonce="', nonce, '">', script, "</script>") end
    ngx.print("</body></html>")
    return ngx.exit(status)
end

local function send_ban(dict, spec, address)
    local retry = math.max(1, math.ceil(tonumber((dict:ttl(ban_key(spec, address)))) or 1))
    set_block_page()
    return send_page(403, "访问已被临时限制", "<p>请求触发了安全策略，请 " .. retry .. " 秒后再试。</p>", nil,
        { ["Retry-After"] = tostring(retry), ["X-Cdnca-WAF"] = "banned" })
end

-- ban records a temporary ban of address for seconds (telemetry
-- temporary_ban, which the control plane aggregates into the ban list).
local function ban(dict, spec, address, seconds, rule_id)
    dict:set(ban_key(spec, address), rule_id, seconds)
    set_telemetry(spec, "temporary_ban", "high", rule_id, true)
    ngx.ctx.cdnca_waf_ban = { seconds = seconds, rule_id = rule_id }
    -- Raised to the kernel firewall like a CC ban
    -- (cdnca_banlist kernel queue; nothing when the dictionary is absent).
    local site = spec.scope:match("^site:(.+)$")
    if site and not ngx.ctx.cdnca_waf_scope_suffix then
        local ok, banlist = pcall(require, "cdnca_banlist")
        if ok and banlist then banlist.queue_kernel_ban(site, address, seconds) end
    end
end

-- Auto defense module overlay (ADR 0010 §7A.3): the WAF values
-- in force the agent wrote into the auto defense gate for the site (a
-- person's locked value, or the automatic one while the WAF module runs
-- "智能自动"). They only tighten a policy, never relax it:
--   waf.tier >= strict (2)  an observe mode policy enforces its decisions;
--   waf.auto_block = 1      a policy without auto block bans a client after
--                           overlay.auto_block.hit_threshold block / challenge
--                           decisions within window_seconds.
-- Cached per request (false: no overlay); absent off dynamic routing.
-- One table (the main chunk is at Lua's 200 local limit).
local overlay = { tier_enforce = 2, auto_block = { window_seconds = 60, hit_threshold = 20, block_seconds = 600 } }

function overlay.of(spec)
    local ctx = ngx.ctx
    local cached = ctx.cdnca_waf_overlay
    if cached ~= nil then return cached end
    local value = false
    local site = ngx.shared.cdnca_autodefense and spec.scope:match("^site:(.+)$")
    if site then
        local ok, autodefense = pcall(require, "cdnca_autodefense")
        if ok and autodefense then value = autodefense.overlay(site) or false end
    end
    ctx.cdnca_waf_overlay = value
    return value
end

function overlay.observing(spec)
    if spec.mode ~= "observe" then return false end
    local values = overlay.of(spec)
    local tier = values and values["waf.tier"]
    return not (type(tier) == "number" and tier >= overlay.tier_enforce)
end

function overlay.auto_block_config(spec)
    if type(spec.auto_block) == "table" then return spec.auto_block end
    local values = overlay.of(spec)
    if values and values["waf.auto_block"] == 1 then return overlay.auto_block end
    return nil
end

-- auto_block counts one block / challenge decision of the policy; returns
-- true when it banned the client.
local function auto_block(dict, spec, address, rule_id)
    local config = overlay.auto_block_config(spec)
    if type(config) ~= "table" then return false end
    local key = "wafs:hit:" .. spec.scope .. ":" .. spec.policy_id .. ":" .. address
    local count = dict:incr(key, 1, 0, config.window_seconds)
    if not count or count < config.hit_threshold then return false end
    dict:delete(key)
    ban(dict, spec, address, config.block_seconds, rule_id)
    return true
end

local function pass_material(spec, address, expires)
    return table.concat({ "waf-pass/v1", spec.scope, spec.policy_id, client_network(address), user_agent_digest(),
        tostring(expires) }, "|")
end

local function valid_pass(dict, spec, address)
    local raw = ngx.var["cookie_" .. (spec.pass_cookie or WAF_PASS_COOKIE)]
    if type(raw) ~= "string" or #raw > 128 then return false end
    local expires, signature = raw:match("^(%d+)%.(%x+)$")
    expires = tonumber(expires)
    if not expires or expires < ngx.time() then return false end
    local secret = waf_secret(dict)
    return secret ~= nil and constant_equal(signature, sha256_hex(secret .. "|" .. pass_material(spec, address, expires)))
end

local function issue_pass(dict, spec, address, seconds)
    local secret = waf_secret(dict)
    if not secret then return false end
    local expires = ngx.time() + seconds
    local value = expires .. "." .. sha256_hex(secret .. "|" .. pass_material(spec, address, expires))
    local secure = ngx.var.scheme == "https" and "; Secure" or ""
    ngx.header["Set-Cookie"] = (spec.pass_cookie or WAF_PASS_COOKIE) .. "=" .. value .. "; Path=/; Max-Age=" .. seconds .. "; HttpOnly; SameSite=Lax" .. secure
    return true
end

local function leading_zero_bits(digest)
    local bits = 0
    for index = 1, #digest do
        local value = digest:byte(index)
        if value == 0 then
            bits = bits + 8
        else
            while bit.band(value, 0x80) == 0 do bits, value = bits + 1, bit.lshift(value, 1) end
            return bits
        end
    end
    return bits
end

local function pow_ok(salt, bits, counter)
    if type(counter) ~= "string" or #counter == 0 or #counter > 12 or counter:find("[^0-9]") then return false end
    local digest = resty_sha256:new()
    digest:update(salt .. ":" .. counter)
    return leading_zero_bits(digest:final()) >= bits
end

-- Compact SHA-256 + chunked proof-of-work search (the CC engine's solver).
local WAF_POW_SCRIPT = "const K=[];for(let i=0,n=2;i<64;n++){let p=1;for(let d=2;d*d<=n;d++)if(n%d==0){p=0;break}" ..
    "if(p)K[i++]=(Math.pow(n,1/3)%1)*4294967296|0}" ..
    "function H(m){const b=new TextEncoder().encode(m),l=b.length,w=new Uint32Array(64),n=((l+9+63)>>6)<<4,x=new Uint32Array(n);" ..
    "for(let i=0;i<l;i++)x[i>>2]|=b[i]<<(24-(i%4)*8);x[l>>2]|=0x80<<(24-(l%4)*8);x[n-1]=l*8;" ..
    "let h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];" ..
    "for(let o=0;o<n;o+=16){let [a,c,d,e,f,g,k,j]=h;for(let t=0;t<64;t++){if(t<16)w[t]=x[o+t];else{const s0=w[t-15],s1=w[t-2];" ..
    "w[t]=(((s0>>>7|s0<<25)^(s0>>>18|s0<<14)^(s0>>>3))+w[t-7]+((s1>>>17|s1<<15)^(s1>>>19|s1<<13)^(s1>>>10))+w[t-16])|0}" ..
    "const t1=(j+((f>>>6|f<<26)^(f>>>11|f<<21)^(f>>>25|f<<7))+((f&g)^(~f&k))+K[t]+w[t])|0," ..
    "t2=(((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+((a&c)^(a&d)^(c&d)))|0;j=k;k=g;g=f;f=(e+t1)|0;e=d;d=c;c=a;a=(t1+t2)|0}" ..
    "h=[h[0]+a|0,h[1]+c|0,h[2]+d|0,h[3]+e|0,h[4]+f|0,h[5]+g|0,h[6]+k|0,h[7]+j|0]}return h}" ..
    "function Z(h){let z=0;for(const v of h){if(v===0){z+=32;continue}return z+Math.clz32(v)}return z}" ..
    "function solve(salt,bits,done){let n=0;(function step(){const end=n+20000;for(;n<end;n++){if(Z(H(salt+':'+n))>=bits){done(String(n));return}}setTimeout(step,0)})()}" ..
    "const F=document.getElementById('f'),P=document.getElementById('p').dataset;" ..
    "solve(P.salt,Number(P.bits),(n)=>{document.getElementById('pow').value=n;F.submit()});"

local function is_idempotent(method)
    return method == "GET" or method == "HEAD"
end

-- challenge answers a request without a valid pass: a proof-of-work page for
-- GET / HEAD; for any other method a 307 to the same URL with a probe cookie,
-- so the browser repeats the request with its method and body (without
-- CC redirect's "/" fallback that lost both).
local function challenge(dict, spec, address, rule_id, config)
    local method = ngx.req.get_method()
    local target = waf_target()
    if not is_idempotent(method) then
        local probe = ngx.var["cookie_" .. WAF_PROBE_COOKIE]
        local probe_key = type(probe) == "string" and #probe == 32 and probe:match("^%x+$") and
            ("wafs:probe:" .. spec.scope .. ":" .. probe)
        local raw = probe_key and dict:get(probe_key)
        local state = raw and cjson.decode(raw)
        if raw then dict:delete(probe_key) end
        if type(state) == "table" and state.policy_id == spec.policy_id and state.ip == address and state.ua == user_agent_digest() then
            if not issue_pass(dict, spec, address, config.pass_seconds) then return ngx.exit(503) end
            ngx.header["Cache-Control"] = "no-store"
            ngx.header["Location"] = target
            return ngx.exit(307)
        end
    end
    set_telemetry(spec, "challenge", "medium", rule_id, true)
    if auto_block(dict, spec, address, rule_id) then return send_ban(dict, spec, address) end
    local token = random_token()
    if not token then return ngx.exit(503) end
    if not is_idempotent(method) then
        if not dict:set("wafs:probe:" .. spec.scope .. ":" .. token, cjson.encode({ policy_id = spec.policy_id, ip = address,
            ua = user_agent_digest() }), WAF_CHALLENGE_SECONDS) then
            return ngx.exit(503)
        end
        ngx.header["Set-Cookie"] = WAF_PROBE_COOKIE .. "=" .. token .. "; Path=/; Max-Age=" .. WAF_CHALLENGE_SECONDS .. "; HttpOnly; SameSite=Lax"
        ngx.header["Cache-Control"] = "no-store"
        ngx.header["Location"] = target
        ngx.header["X-Cdnca-WAF"] = "challenge"
        return ngx.exit(307)
    end
    local salt = random_token()
    if not salt or not dict:set("wafs:nonce:" .. token, cjson.encode({ scope = spec.scope, policy_id = spec.policy_id,
        ip = address, ua = user_agent_digest(), target = target, salt = salt, bits = config.pow_bits,
        pass = config.pass_seconds }), WAF_CHALLENGE_SECONDS) then
        return ngx.exit(503)
    end
    local body = '<p>正在进行安全验证，请稍候……</p><form id="f" method="post" action="' .. WAF_VERIFY_PATH ..
        '"><input type="hidden" name="token" value="' .. token .. '"><input type="hidden" id="pow" name="pow" value=""></form>' ..
        '<div id="p" data-salt="' .. salt .. '" data-bits="' .. config.pow_bits .. '" hidden></div>'
    return send_page(503, "安全验证", body, WAF_POW_SCRIPT, { ["X-Cdnca-WAF"] = "challenge", ["Retry-After"] = "1" })
end

local function verify(dict, spec, address)
    if ngx.req.get_method() ~= "POST" then
        ngx.header["Allow"] = "POST"
        return ngx.exit(ngx.HTTP_NOT_ALLOWED)
    end
    ngx.req.read_body()
    local args = ngx.req.get_post_args(4) or {}
    local token = type(args.token) == "string" and args.token or ""
    local key = "wafs:nonce:" .. token
    local raw = #token == 32 and token:match("^%x+$") and dict:get(key)
    local state = raw and cjson.decode(raw)
    -- Every action segment's gate sees the
    -- verification POST; a nonce of another policy (an earlier ACL / bound
    -- policy segment, a later rule pack segment) is left for that segment's
    -- gate instead of being consumed and refused 403 here.
    if type(state) == "table" and (state.scope ~= spec.scope or state.policy_id ~= spec.policy_id) then return end
    if raw then dict:delete(key) end
    if type(state) ~= "table" then
        return send_page(403, "验证已失效", '<p>验证信息已过期，请<a href="/">返回首页</a>重新访问。</p>', nil,
            { ["X-Cdnca-WAF"] = "expired" })
    end
    if state.ip ~= address or state.ua ~= user_agent_digest() or not pow_ok(state.salt, state.bits, args.pow) then
        return send_page(403, "验证未通过", '<p>验证未通过，请返回重试。</p>', nil, { ["X-Cdnca-WAF"] = "failed" })
    end
    if not issue_pass(dict, spec, address, state.pass) then return ngx.exit(503) end
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Location"] = state.target
    return ngx.exit(303)
end

-- gate runs before a policy segment's rules: the challenge verification
-- endpoint, then the client's ban. Returns nothing when the request goes on
-- (a terminating answer exits the request).
function _M.gate(raw)
    local spec = action_spec(raw)
    if not spec then return ngx.exit(503) end
    spec = scoped(spec)
    if overlay.observing(spec) then return end
    local dict = waf_state()
    if not dict then return end
    local address = client_ip()
    if ngx.var.uri == WAF_VERIFY_PATH then return verify(dict, spec, address) end
    if dict:get(ban_key(spec, address)) then return send_ban(dict, spec, address) end
    -- A ban of the ban list library (another node's
    -- automatic ban of the client on this site, or a manual one).
    local site = spec.scope:match("^site:(.+)$")
    if site then
        local ok, banlist = pcall(require, "cdnca_banlist")
        if ok and banlist then
            local remaining = banlist.banned(site, address)
            if remaining then return banlist.deny(remaining, telemetry_vars.block_page) end
        end
    end
end

-- act carries out a segment's verdict (allow / block / log / challenge /
-- ban) like the rendered block / log code, plus challenge, ban, auto block
-- and observe mode. Returns nothing when the request goes on.
function _M.act(raw, action, rule_id)
    local spec = action_spec(raw)
    if not spec then return ngx.exit(503) end
    spec = scoped(spec)
    if action == "allow" then return end
    if action == "log" then
        return set_telemetry(spec, "log", "info", rule_id, false)
    end
    if overlay.observing(spec) then
        ngx.ctx.cdnca_waf_observed = action
        return set_telemetry(spec, "log", "info", rule_id, false)
    end
    local dict = waf_state()
    local address = client_ip()
    local config = spec.rules[rule_id] or {}
    if action == "ban" then
        if not dict or type(config.ban_seconds) ~= "number" then return ngx.exit(403) end
        ban(dict, spec, address, config.ban_seconds, rule_id)
        return send_ban(dict, spec, address)
    end
    if action == "challenge" then
        if not dict or type(config.pass_seconds) ~= "number" then return ngx.exit(503) end
        if valid_pass(dict, spec, address) then return end
        return challenge(dict, spec, address, rule_id, config)
    end
    -- block
    set_telemetry(spec, "block", "high", rule_id, true)
    if dict and auto_block(dict, spec, address, rule_id) then return send_ban(dict, spec, address) end
    return ngx.exit(403)
end

-- evidence records what the security log reports for a block / log /
-- challenge / ban decision (ge-waf S4): the deciding policy, the detector
-- and matched fragment of the last inspect clause that held. Values are cut
-- to fixed sizes so one event never outgrows the log line.
-- TF-E01: a fragment of a sensitive name (evidence.sensitive, the Agent's
-- eventspool.sensitiveName) or of a cookie keeps only the name and
-- [REDACTED]. The request body is not copied here: evidence only marks that
-- a rule decided (ngx.ctx.cdnca_evidence_body), and the log phase
-- (cdnca_telemetry.evidence_body) writes a redacted excerpt only for a site
-- whose capture policy collects request body fields.
-- One table (the main chunk is at Lua's 200 local limit).
local evidence = { REDACTED = "[REDACTED]", TOKENS = {
    authorization = true, cookie = true, password = true, passwd = true, token = true, key = true,
    apikey = true, secret = true, certificate = true, cert = true, privatekey = true, setcookie = true,
} }
function evidence.printable(value, limit)
    if type(value) ~= "string" or value == "" then return "" end
    if #value > limit then value = value:sub(1, limit) end
    return (value:gsub("[%z\1-\31\127]", "?"))
end

-- evidence.sensitive: the Agent's sensitiveName (camelCase split, tokens
-- on every non-alphanumeric byte), same as cdnca_telemetry.sensitive_name.
function evidence.sensitive(name)
    if type(name) ~= "string" or name == "" then return false end
    local split = name:gsub("(%u)(%u%l)", "%1 %2")
    split = split:gsub("([%l%d])(%u)", "%1 %2")
    local lowered = split:lower()
    if lowered:find("authorization", 1, true) then return true end
    for token in lowered:gmatch("[a-z0-9]+") do
        if evidence.TOKENS[token] then return true end
    end
    return false
end

function evidence.matched(last)
    if last.overflow then return "body over inspection limit" end
    local fragment = last.fragment or ""
    local key = last.key or ""
    if key ~= "" and (last.target == "cookie" or evidence.sensitive(key)) then
        return key .. "=" .. evidence.REDACTED
    end
    if last.target == "cookie" and fragment ~= "" then return evidence.REDACTED end
    if key ~= "" then fragment = key .. "=" .. fragment end
    return evidence.scrub(fragment)
end

-- evidence.scrub: a fragment cut from a body or query keeps its text, but
-- the value after a sensitive name= or "name": is replaced (the Agent's
-- scrubEvidenceText does the same).
function evidence.scrub(text)
    text = text:gsub('("([^"]*)"%s*:%s*)"[^"]*"?', function(prefix, name)
        if evidence.sensitive(name) then return prefix .. '"' .. evidence.REDACTED .. '"' end
    end)
    return (text:gsub("([%w_%-%.%[%]]+)=([^&;%s]*)", function(name)
        if evidence.sensitive(name) then return name .. "=" .. evidence.REDACTED end
    end))
end

function _M.evidence(policy_id)
    pcall(function()
        ngx.var.cdnca_security_policy_id = policy_id or ""
        local last = ngx.ctx.cdnca_inspect_last
        if last then
            ngx.var.cdnca_security_detector = last.detector or ""
            ngx.var.cdnca_security_matched = evidence.printable(evidence.matched(last), INSPECT_FRAGMENT_BYTES + 64)
        end
        ngx.ctx.cdnca_evidence_body = true
    end)
end
_M._evidence_sensitive = evidence.sensitive
_M._evidence_matched = evidence.matched

-- unban removes a ban (the agent's unban command, S5); returns whether one existed.
function _M.unban(scope, address)
    local dict = waf_state()
    if not dict or type(scope) ~= "string" or type(address) ~= "string" then return false end
    local key = "wafs:ban:" .. scope .. ":" .. address
    local existed = dict:get(key) ~= nil
    dict:delete(key)
    return existed
end

-- Test hook for the detector corpus (scripts/security/waf-detector-corpus.sh).
-- detect_args(names): the detectors of names (in that order) that match a
-- request argument value (query, form and JSON leaves, inspect_values
-- "args", as operator detect sees them), as ",a,b," ("," when none). The
-- dynamic routing managed WAF passes it to ModSecurity as a strong signal
-- (libs/edgeconfig DynamicWAFContext d=, waf-strict-algo 2b).
--
-- waf-cookie-fp: cookie values are inspected too, parsed by structure first
-- (CRS weak rules no longer read cookies, libs/edgeconfig
-- renderDynamicWAFCookieWeak, so the detectors are the strong signal there):
-- a pure token (identifier, hex, UUID, plain base64 that decodes to binary)
-- is skipped; a JWT's header and payload, a base64 value that decodes to
-- text and URL-encoded JSON (its string leaves) are inspected decoded.
-- waf-gap4: request headers detect_args does not inspect: protocol and
-- content negotiation (their syntax is not user data), the ones with their
-- own handling (Host: routing, Cookie: above, User-Agent / Referer: CRS
-- PL1 reads them, Authorization / Proxy-Authorization: credentials), and
-- the browser's client hints (sec-*, by prefix).
DETECTORS.STANDARD_HEADERS = DETECTORS.words({}, [[host cookie user-agent referer authorization proxy-authorization accept accept-encoding
    accept-language accept-charset connection content-length content-type content-encoding transfer-encoding te
    trailer upgrade cache-control pragma if-match if-none-match if-modified-since if-unmodified-since if-range range
    origin priority dnt upgrade-insecure-requests expect keep-alive via forwarded x-forwarded-for x-forwarded-proto
    x-forwarded-host x-forwarded-port x-real-ip x-request-id x-requested-with purpose viewport-width device-memory
    dpr ect rtt downlink save-data width early-data x-cdnca-waf]])

-- waf-gap5: argument names and JSON keys are values here too (inspect
-- "args" pushes both: prototype pollution sits in the key); an argument
-- value that is base64 of text is inspected decoded as well
-- (DETECTORS.base64_text); detector "path" also reads the request path as
-- sent (nginx has already resolved "../" in $uri), the other detectors do
-- not (a path is no user data they read).
function _M.detect_args(names)
    local values = {}
    for _, value in ipairs(inspect_values("args")) do
        values[#values + 1] = value
        local decoded = DETECTORS.base64_text(value)
        if decoded then push_value(values, decoded) end
    end
    local function text(raw)
        return raw and #raw > 0 and not raw:find("[%z\1-\8\14-\31\127-\255]") and raw or nil
    end
    local function b64(token)
        local padded = token:gsub("-", "+"):gsub("_", "/")
        return text(ngx.decode_base64(padded .. string.rep("=", (4 - #padded % 4) % 4)))
    end
    local function push_cookie(value, depth)
        if #values >= INSPECT_MAX_VALUES or depth > 2 or value == "" then return end
        if value:find("^[%w_.%-:|]+$") and not value:find("^eyJ") and (#value < 16 or not value:find("^[%w+/_%-]+=*$")) then
            return -- identifier, number, hex, UUID, packed key:value tokens
        end
        local head, body = value:match("^(eyJ[%w_%-]+)%.([%w_%-]+)%.[%w_%-]*$")
        if head then -- JWT: header and payload are JSON
            for _, part in ipairs({ head, body }) do
                local decoded = b64(part)
                if decoded then push_cookie(decoded, depth + 1) end
            end
            return
        end
        local first = value:sub(1, 1)
        if first == "{" or first == "[" then
            local parsed = cjson.decode(value)
            if type(parsed) == "table" then
                local leaves = {}
                push_json_leaves(leaves, parsed, 0)
                for _, leaf in ipairs(leaves) do push_value(values, leaf) end
                return
            end
        end
        push_value(values, value) -- as sent (a serialized Java object is base64 of binary: rO0AB...)
        if #value >= 16 and value:find("^[%w+/_%-]+=*$") then
            local decoded = b64(value)
            if decoded then push_cookie(decoded, depth + 1) end
        end
    end
    for pair in (ngx.var.http_cookie or ""):gmatch("[^;]+") do
        local name, value = pair:match("^%s*([^=]*)=(.*)$")
        if not name then name, value = pair:match("^%s*(.-)%s*$"), "" end -- a pair without "=" is a name
        if #values < INSPECT_MAX_VALUES then
            push_cookie(url_decode_all(name), 0)
            push_cookie(url_decode_all(value), 0)
        end
    end
    -- waf-gap4: a JSON body's operator keys as key[$op] (nosql: the leaves
    -- above lose which key an operator object sits under)
    local body = content_type():find("json", 1, true) and decoded_json_body()
    if type(body) == "table" then
        local function walk(node, depth)
            if depth > 8 or #values >= INSPECT_MAX_VALUES then return end
            for key, child in pairs(node) do
                if type(child) == "table" then
                    for op in pairs(child) do
                        if type(key) == "string" and type(op) == "string" and op:find("^%$") then
                            push_value(values, key .. "[" .. op .. "]")
                        end
                    end
                    walk(child, depth + 1)
                end
            end
        end
        walk(body, 0)
    end
    -- waf-gap4: non-standard request headers (CRS reads few of them), parsed
    -- like cookie values; the standard ones (DETECTORS.STANDARD_HEADERS) have
    -- their own handling or carry protocol syntax.
    for name, value in pairs(request_headers()) do
        name = string.lower(name)
        if not DETECTORS.STANDARD_HEADERS[name] and not name:find("^sec%-") then
            for _, item in ipairs(type(value) == "table" and value or { value }) do
                -- a long opaque token (device fingerprints, signed blobs: x-ua
                -- 140#...: base64-like characters only) is no text a
                -- detector reads
                if type(item) == "string" and #values < INSPECT_MAX_VALUES then
                    -- (as sent: decoding turns "+" into spaces)
                    if not (#item >= 64 and item:find("^[%w+/=_#.:;@%-]+$")) then push_cookie(url_decode_all(item), 0) end
                end
            end
        end
    end
    local found = { "" }
    for _, name in ipairs(names) do
        local detector = DETECTORS[name]
        if name == "upload" then
            for _, file in ipairs((upload_names())) do
                if detector(file) then
                    found[#found + 1] = name
                    break
                end
            end
        elseif type(detector) == "function" then
            local hit = name == "path" and detector(url_decode_all((ngx.var.request_uri or ""):match("^[^?]*")))
            for _, value in ipairs(values) do
                if hit then break end
                hit = detector(value)
            end
            if hit then found[#found + 1] = name end
        end
    end
    found[#found + 1] = ""
    return #found == 2 and "," or table.concat(found, ",")
end

-- Grey zone challenge of the dynamic routing managed WAF (ADR 0011 RI-03,
-- PoC-3): the node rules deny a grey zone request of a browser-like client
-- without a pass with status 599, the skeleton's error_page serves it here.
-- The page and the POST 307 probe are challenge()'s; spec is the site's
-- (cdnca_managed_waf: scope "waf-grey:<site>", its own pass cookie, no
-- telemetry, no auto block). One table (the main chunk is at Lua's 200
-- local limit).
_M.grey = {}

-- passed(spec): the request carries a valid pass of spec (context g=1).
function _M.grey.passed(spec)
    local dict = waf_state()
    return dict ~= nil and valid_pass(dict, spec, client_ip())
end

-- challenge(spec, config): answers the request (config: pass_seconds, pow_bits).
function _M.grey.challenge(spec, config)
    local dict = waf_state()
    if not dict then return ngx.exit(503) end
    ngx.ctx.cdnca_own_page = true
    return challenge(dict, spec, client_ip(), "grey", config)
end

-- verify(spec): the verification POST of a grey zone challenge page; returns
-- when the nonce is not spec's (another policy's challenge: gate verifies it).
function _M.grey.verify(spec)
    local dict = waf_state()
    if not dict or ngx.req.get_method() ~= "POST" then return end
    ngx.req.read_body()
    local args = ngx.req.get_post_args(4) or {}
    local token = type(args.token) == "string" and args.token or ""
    local raw = #token == 32 and token:match("^%x+$") and dict:get("wafs:nonce:" .. token)
    local state = raw and cjson.decode(raw)
    if type(state) ~= "table" or state.scope ~= spec.scope then return end
    ngx.ctx.cdnca_own_page = true
    return verify(dict, spec, client_ip())
end

_M._detect = DETECTORS
_M._filters = FILTERS

return _M
