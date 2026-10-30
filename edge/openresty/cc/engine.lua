local bit = require("bit")
local cjson = require("cjson.safe")

-- The public port. A composed node dispatches plaintext and TLS that share one
-- port through internal unix sockets, where $server_port is empty; those
-- listeners alone accept PROXY protocol, which carries the public port.
local function public_server_port()
    return ngx.var.proxy_protocol_server_port or ngx.var.server_port
end

local _M = {}

local SCHEMA_VERSION = "cdnca.edge.cc/v1"
local MAX_POLICY_BYTES = 1024 * 1024
local MAX_RULES = 512
local MAX_PROXY_CIDRS = 64
local MAX_ALLOWLIST_CIDRS = 256
local MAX_IDENTIFIER_BYTES = 128
local MAX_HOST_BYTES = 253
local MAX_METHOD_BYTES = 32
local MAX_PATH_BYTES = 1024
local MAX_REQUESTS = 1000000
local MAX_WINDOW_SECONDS = 3600
local MAX_RATE_PER_SECOND = 100000
local MAX_BURST = 1000000
local MAX_BAN_SECONDS = 86400
local MAX_XFF_BYTES = 2048
local MAX_XFF_HOPS = 32
local MAX_SAFE_SECONDS = 9007199254740991
local METRICS_SCHEMA = "cdnca.edge.cc-metrics/v1"

local current_policy
local current_digest
local policy_path
local fallback_path
local state_dict_name
local reload_interval = 1
local next_reload_at = 0

local function record_capacity_failure(policy, tenant_id, site_id, forcible)
    if ngx.ctx.cdnca_cc_capacity_recorded then return end
    ngx.ctx.cdnca_cc_capacity_recorded = true
    local prefix = "cc:v" .. tostring(policy.policy_version) .. ":t:" .. tenant_id .. ":s:" .. site_id .. ":metrics:"
    local dict = ngx.shared[state_dict_name]
    local capacity, capacity_error = dict:incr(prefix .. "capacity", 1, 0)
    if not capacity then ngx.log(ngx.ERR, "cc metrics capacity counter unavailable: ", tostring(capacity_error)) end
    if forcible then
        local evictions, eviction_error = dict:incr(prefix .. "evictions", 1, 0)
        if not evictions then ngx.log(ngx.ERR, "cc metrics eviction counter unavailable: ", tostring(eviction_error)) end
    end
    local degraded, degraded_error = dict:safe_set(prefix .. "degraded", true)
    if not degraded then ngx.log(ngx.ERR, "cc metrics degraded marker unavailable: ", tostring(degraded_error)) end
end

local function metric_counter(dict, key)
    local value = dict:get(key)
    if value == nil then return 0 end
    if not integer(value, 0, MAX_SAFE_SECONDS) then return nil end
    return value
end

local function integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum
end

local function identifier(value)
    return type(value) == "string" and #value >= 1 and #value <= MAX_IDENTIFIER_BYTES
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
    return integer(cidr.prefix_length, 0, cidr.family == 4 and 32 or 128)
end

local function validate_cidr_list(value, maximum)
    local length = array_length(value, maximum)
    if not length then
        return false
    end
    local seen = {}
    for index = 1, length do
        local cidr = value[index]
        if not validate_cidr(cidr) then
            return false
        end
        local key = cidr.family .. "/" .. cidr.prefix_length .. "/" .. table.concat(cidr.network, ".")
        if seen[key] then
            return false
        end
        seen[key] = true
    end
    return true
end

local path_fields = { kind = true, value = true }
local match_fields = { host = true, port = true, method = true, path = true }

local function validate_match(value)
    if not has_only(value, match_fields) then
        return false
    end
    if value.host ~= nil and (not bounded_string(value.host, MAX_HOST_BYTES)
        or value.host ~= string.lower(value.host) or value.host:find("[:/\\%%]") ~= nil) then
        return false
    end
    if value.port ~= nil and not integer(value.port, 1, 65535) then
        return false
    end
    if value.method ~= nil and (not bounded_string(value.method, MAX_METHOD_BYTES)
        or value.method ~= string.upper(value.method) or value.method:find("[^!#$&'*+.%^_`|~A-Z0-9-]") ~= nil) then
        return false
    end
    if value.path ~= nil then
        if not has_only(value.path, path_fields) or (value.path.kind ~= "exact" and value.path.kind ~= "prefix")
            or not bounded_string(value.path.value, MAX_PATH_BYTES) or value.path.value:sub(1, 1) ~= "/"
            or value.path.value:find("[\\%%?#]") ~= nil or value.path.value:find("//", 1, true) ~= nil
            or value.path.value:find("/%.%.?/") ~= nil then
            return false
        end
        for segment in value.path.value:gmatch("[^/]+") do
            if segment == "." or segment == ".." then
                return false
            end
        end
    end
    return true
end

local limit_fields = {
    algorithm = true, requests = true, window_seconds = true, rate_per_second = true, burst = true,
}

local function validate_limit(value)
    if not has_only(value, limit_fields) then
        return false
    end
    if value.algorithm == "fixed_window" then
        return integer(value.requests, 1, MAX_REQUESTS) and integer(value.window_seconds, 1, MAX_WINDOW_SECONDS)
            and value.rate_per_second == nil and value.burst == nil
    end
    if value.algorithm == "leaky_bucket" then
        return integer(value.rate_per_second, 1, MAX_RATE_PER_SECOND) and integer(value.burst, 1, MAX_BURST)
            and value.requests == nil and value.window_seconds == nil
    end
    return false
end

local action_fields = { kind = true, ban_seconds = true }

local function validate_action(value, dimension)
    if not has_only(value, action_fields) then
        return false
    end
    if value.kind == "log" or value.kind == "reject_429" then
        return value.ban_seconds == nil
    end
    return value.kind == "temporary_ban" and dimension == "client_ip"
        and integer(value.ban_seconds, 1, MAX_BAN_SECONDS)
end

local rule_fields = {
    rule_id = true, priority = true, tenant_id = true, site_id = true, match = true,
    dimension = true, limit = true, action = true,
}

local function validate_rule(value)
    if not has_only(value, rule_fields) or not identifier(value.rule_id) or not integer(value.priority, 0, 4294967295)
        or not identifier(value.tenant_id) or not identifier(value.site_id) or not validate_match(value.match) then
        return false
    end
    if value.dimension ~= "client_ip" and value.dimension ~= "path" and value.dimension ~= "site" then
        return false
    end
    return validate_limit(value.limit) and validate_action(value.action, value.dimension)
end

local policy_fields = {
    schema_version = true, policy_version = true, trusted_proxies = true, allowlist = true, rules = true,
}

local function validate_policy(value)
    if not has_only(value, policy_fields) or value.schema_version ~= SCHEMA_VERSION
        or not integer(value.policy_version, 1, 9007199254740991)
        or not validate_cidr_list(value.trusted_proxies, MAX_PROXY_CIDRS)
        or not validate_cidr_list(value.allowlist, MAX_ALLOWLIST_CIDRS) then
        return nil, "invalid policy envelope"
    end
    local length = array_length(value.rules, MAX_RULES)
    if not length then
        return nil, "invalid rule array"
    end
    local ids = {}
    local previous
    for index = 1, length do
        local rule = value.rules[index]
        if not validate_rule(rule) or ids[rule.rule_id] then
            return nil, "invalid or duplicate rule"
        end
        ids[rule.rule_id] = true
        if previous and (rule.priority < previous.priority
            or (rule.priority == previous.priority and rule.rule_id <= previous.rule_id)) then
            return nil, "rules are not deterministically sorted"
        end
        previous = rule
    end
    return value
end

local function read_candidate(path)
    local file, open_error = io.open(path, "rb")
    if not file then
        return nil, "open policy: " .. tostring(open_error)
    end
    local raw = file:read(MAX_POLICY_BYTES + 1)
    file:close()
    if not raw or #raw == 0 or #raw > MAX_POLICY_BYTES then
        return nil, "policy size is invalid"
    end
    local decoded, decode_error = cjson.decode(raw)
    if not decoded then
        return nil, "decode policy: " .. tostring(decode_error)
    end
    local validated, validation_error = validate_policy(decoded)
    if not validated then
        return nil, validation_error
    end
    return validated, nil, ngx.md5(raw)
end

local function reload(force)
    local now = ngx.now()
    if not force and now < next_reload_at then
        return true
    end
    next_reload_at = now + reload_interval
    local candidate, candidate_error, candidate_digest = read_candidate(policy_path)
    if not candidate and not current_policy then
        candidate, candidate_error, candidate_digest = read_candidate(fallback_path)
    end
    if not candidate then
        ngx.log(ngx.ERR, "cc policy reload rejected; retaining LKG: ", candidate_error)
        return false, candidate_error
    end
    if current_policy and candidate.policy_version < current_policy.policy_version then
        ngx.log(ngx.ERR, "cc policy reload rejected; retaining newer LKG")
        return false, "policy version moved backwards"
    end
    if current_policy and candidate.policy_version == current_policy.policy_version and candidate_digest ~= current_digest then
        ngx.log(ngx.ERR, "cc policy reload rejected; retaining same-version LKG")
        return false, "same policy version has different content"
    end
    if not current_policy or candidate.policy_version > current_policy.policy_version then
        current_policy = candidate
        current_digest = candidate_digest
        ngx.log(ngx.NOTICE, "cc policy activated version=", candidate.policy_version)
    end
    return true
end

local function parse_ipv4(value)
    if type(value) ~= "string" or #value == 0 or #value > 15 then
        return nil
    end
    local bytes = {}
    for part in (value .. "."):gmatch("(.-)%.") do
        if part == "" or part:find("[^0-9]") or (#part > 1 and part:sub(1, 1) == "0") then
            return nil
        end
        local byte = tonumber(part)
        if not byte or byte > 255 then
            return nil
        end
        bytes[#bytes + 1] = byte
    end
    if #bytes ~= 4 then
        return nil
    end
    return { family = 4, bytes = bytes, text = value }
end

local function ipv6_side(value)
    local words = {}
    if value == "" then
        return words
    end
    if value:sub(1, 1) == ":" or value:sub(-1) == ":" or value:find("::", 1, true) then
        return nil
    end
    for part in value:gmatch("[^:]+") do
        if #part > 4 or not part:match("^[0-9A-Fa-f]+$") then
            return nil
        end
        words[#words + 1] = tonumber(part, 16)
    end
    return words
end

local function parse_ipv6(value)
    if type(value) ~= "string" or #value < 2 or #value > 45 or value:find("[%%%.]") then
        return nil
    end
    local marker = value:find("::", 1, true)
    if marker and value:find("::", marker + 2, true) then
        return nil
    end
    local left_text = marker and value:sub(1, marker - 1) or value
    local right_text = marker and value:sub(marker + 2) or ""
    local left = ipv6_side(left_text)
    local right = ipv6_side(right_text)
    if not left or not right then
        return nil
    end
    local missing = 8 - #left - #right
    if (marker and missing < 1) or (not marker and missing ~= 0) then
        return nil
    end
    local words = {}
    for _, word in ipairs(left) do words[#words + 1] = word end
    for _ = 1, missing do words[#words + 1] = 0 end
    for _, word in ipairs(right) do words[#words + 1] = word end
    if #words ~= 8 then
        return nil
    end
    local bytes = {}
    for _, word in ipairs(words) do
        bytes[#bytes + 1] = math.floor(word / 256)
        bytes[#bytes + 1] = word % 256
    end
    return { family = 6, bytes = bytes, text = string.lower(value) }
end

local function parse_ip(value)
    if type(value) ~= "string" or #value > 64 or value:find("[%c%s]") then
        return nil
    end
    return value:find(":", 1, true) and parse_ipv6(value) or parse_ipv4(value)
end

local function cidr_contains(cidr, address)
    if cidr.family ~= address.family then
        return false
    end
    local full_bytes = math.floor(cidr.prefix_length / 8)
    for index = 1, full_bytes do
        if cidr.network[index] ~= address.bytes[index] then
            return false
        end
    end
    local remaining = cidr.prefix_length % 8
    if remaining == 0 then
        return true
    end
    local mask = bit.band(bit.lshift(255, 8 - remaining), 255)
    return bit.band(cidr.network[full_bytes + 1], mask) == bit.band(address.bytes[full_bytes + 1], mask)
end

local function in_cidrs(address, cidrs)
    for _, cidr in ipairs(cidrs) do
        if cidr_contains(cidr, address) then
            return true
        end
    end
    return false
end

local function client_address(policy)
    local peer = parse_ip(ngx.var.remote_addr)
    if not peer then
        return nil, "invalid peer address"
    end
    local forwarded = ngx.var.http_x_forwarded_for
    if not forwarded or not in_cidrs(peer, policy.trusted_proxies) then
        return peer
    end
    if #forwarded == 0 or #forwarded > MAX_XFF_BYTES or forwarded:find("[%c]") then
        return peer
    end
    local chain = {}
    for part in (forwarded .. ","):gmatch("(.-),") do
        part = part:match("^[ \t]*(.-)[ \t]*$")
        local address = parse_ip(part)
        if not address or #chain >= MAX_XFF_HOPS then
            return peer
        end
        chain[#chain + 1] = address
    end
    if #chain == 0 then
        return peer
    end
    chain[#chain + 1] = peer
    for index = #chain - 1, 1, -1 do
        if not in_cidrs(chain[index], policy.trusted_proxies) then
            return chain[index]
        end
    end
    return chain[1]
end

local function rule_matches(rule, tenant_id, site_id)
    if rule.tenant_id ~= tenant_id or rule.site_id ~= site_id then
        return false
    end
    local match = rule.match
    if match.host and match.host ~= string.lower(ngx.var.host or "") then
        return false
    end
    if match.port and match.port ~= tonumber(public_server_port()) then
        return false
    end
    if match.method and match.method ~= ngx.req.get_method() then
        return false
    end
    if match.path then
        local path = ngx.var.uri or ""
        if match.path.kind == "exact" and path ~= match.path.value then
            return false
        end
        if match.path.kind == "prefix" and path:sub(1, #match.path.value) ~= match.path.value then
            return false
        end
    end
    return true
end

local function state_key(policy, rule, tenant_id, site_id, kind, value)
    return "cc:v" .. policy.policy_version .. ":t:" .. tenant_id .. ":s:" .. site_id
        .. ":r:" .. rule.rule_id .. ":" .. kind .. ":" .. ngx.md5(value)
end

local function site_ban_key(policy, tenant_id, site_id, address)
    return "cc:v" .. policy.policy_version .. ":t:" .. tenant_id .. ":s:" .. site_id
        .. ":ban:" .. ngx.md5(address.text)
end

local function dimension_value(rule, address)
    if rule.dimension == "client_ip" then
        return address.text
    end
    if rule.dimension == "path" then
        return ngx.var.uri or "/"
    end
    return "site"
end

local function consume_fixed(dict, key, limit, now)
    now = now or ngx.now()
    local bucket = math.floor(now / limit.window_seconds)
    local count, increment_error, forcible = dict:incr(key .. ":" .. bucket, 1, 0, limit.window_seconds + 1)
    if not count or forcible then
        return nil, increment_error or "shared dict eviction", forcible
    end
    local retry_after = math.max(1, math.ceil((bucket + 1) * limit.window_seconds - now))
    return count > limit.requests, retry_after, false
end

local function release_lock(dict, key, token)
    if dict:get(key) == token then
        dict:delete(key)
    end
end

local function consume_leaky(dict, key, limit, now)
    local lock_key = key .. ":lock"
    local token = (ngx.var.request_id or "request") .. ":" .. tostring(coroutine.running())
    local acquired = false
    for _ = 1, 40 do
        local added, add_error, forcible = dict:add(lock_key, token, 0.2)
        if added and not forcible then
            acquired = true
            break
        end
        if add_error ~= "exists" then
            return nil, add_error or "state capacity exhausted"
        end
        ngx.sleep(0.001)
    end
    if not acquired then
        return nil, "state lock timeout"
    end
    now = now or ngx.now()
    local level = 0
    local stored = dict:get(key)
    if stored then
        local prior_level, prior_time = stored:match("^([0-9.]+)|([0-9.]+)$")
        if prior_level and prior_time then
            level = math.max(0, tonumber(prior_level) - (now - tonumber(prior_time)) * limit.rate_per_second)
        end
    end
    level = level + 1
    local over = level > limit.burst
    level = math.min(level, limit.burst)
    local ttl = math.ceil((limit.burst + 1) / limit.rate_per_second) + 1
    local stored_ok, store_error, forcible = dict:set(key, string.format("%.6f|%.6f", level, now), ttl)
    release_lock(dict, lock_key, token)
    if not stored_ok or forcible then
        return nil, store_error or "shared dict eviction", forcible
    end
    return over, math.max(1, math.ceil(1 / limit.rate_per_second)), false
end

local function reject(retry_after)
    ngx.status = ngx.HTTP_TOO_MANY_REQUESTS
    ngx.header["Retry-After"] = tostring(math.max(1, math.min(MAX_BAN_SECONDS, retry_after or 1)))
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.say("Too Many Requests")
    return ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
end

function _M.init(options)
    if type(options) ~= "table" or type(options.policy_path) ~= "string" or options.policy_path:sub(1, 1) ~= "/"
        or type(options.state_dict) ~= "string" or not ngx.shared[options.state_dict] then
        error("invalid CC engine options")
    end
    if options.reload_interval ~= nil and (type(options.reload_interval) ~= "number"
        or options.reload_interval < 0.05 or options.reload_interval > 60) then
        error("invalid CC reload interval")
    end
    policy_path = options.policy_path
    fallback_path = policy_path:match("^(.*)/[^/]+$") .. "/fallback.json"
    state_dict_name = options.state_dict
    reload_interval = options.reload_interval or 1
    next_reload_at = 0
    local ok, load_error = reload(true)
    if not ok and not current_policy then
        error("no valid CC policy: " .. tostring(load_error))
    end
    return current_policy.policy_version
end

function _M.policy_version()
    reload(false)
    return current_policy and current_policy.policy_version or 0
end

function _M.metrics(context)
    reload(false)
    local node_id = ngx.var.cdnca_node_id
    if not current_policy or type(context) ~= "table" or not identifier(context.tenant_id) or not identifier(context.site_id)
        or type(node_id) ~= "string" or #node_id == 0 then
        return nil, "metrics identity unavailable"
    end
    local prefix = "cc:v" .. tostring(current_policy.policy_version) .. ":t:" .. context.tenant_id .. ":s:" .. context.site_id .. ":metrics:"
    local dict = ngx.shared[state_dict_name]
    local capacity = metric_counter(dict, prefix .. "capacity")
    local evictions = metric_counter(dict, prefix .. "evictions")
    if capacity == nil or evictions == nil then return nil, "metrics state unavailable" end
    return {
        schema_version = METRICS_SCHEMA, node_id = node_id,
        tenant_scope_id = context.tenant_id, site_id = context.site_id,
        policy_id = "legacy-cc", policy_version = current_policy.policy_version,
        capacity_failures = capacity, shared_dict_evictions = evictions,
        degraded = dict:get(prefix .. "degraded") == true,
    }
end

function _M.access(context)
    reload(false)
    if not current_policy or type(context) ~= "table" or not identifier(context.tenant_id) or not identifier(context.site_id) or
        (context.now_seconds ~= nil and (type(context.now_seconds) ~= "number" or context.now_seconds < 0 or
            context.now_seconds > MAX_SAFE_SECONDS or context.now_seconds ~= context.now_seconds)) then
        ngx.log(ngx.ERR, "cc request context or policy is unavailable")
        return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    local policy = current_policy
    local address, address_error = client_address(policy)
    if not address then
        ngx.log(ngx.ERR, "cc client address rejected: ", address_error)
        return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    ngx.ctx.cdnca_cc_client_ip = address.text
    ngx.ctx.cdnca_cc_policy_version = policy.policy_version
    if in_cidrs(address, policy.allowlist) then
        return
    end
    local dict = ngx.shared[state_dict_name]
    local ban_key = site_ban_key(policy, context.tenant_id, context.site_id, address)
    local active_ban = dict:get(ban_key)
    if active_ban then
        return reject(type(active_ban) == "number" and active_ban or 1)
    end
    for _, rule in ipairs(policy.rules) do
        if rule_matches(rule, context.tenant_id, context.site_id) then
            local value = dimension_value(rule, address)
            local key = state_key(policy, rule, context.tenant_id, context.site_id, rule.dimension, value)
            local over, retry_or_error, forcible
            if rule.limit.algorithm == "fixed_window" then
                over, retry_or_error, forcible = consume_fixed(dict, key, rule.limit, context.now_seconds)
            else
                over, retry_or_error, forcible = consume_leaky(dict, key, rule.limit, context.now_seconds)
            end
            if over == nil then
                ngx.log(ngx.ERR, "cc state unavailable rule_id=", rule.rule_id, ": ", retry_or_error)
                record_capacity_failure(policy, context.tenant_id, context.site_id, forcible)
                if rule.action.kind ~= "log" then
                    return reject(1)
                end
            elseif over then
                if rule.action.kind == "log" then
                    ngx.log(ngx.WARN, "cc rate exceeded action=log rule_id=", rule.rule_id,
                        " policy_version=", policy.policy_version)
                else
                    if rule.action.kind == "temporary_ban" then
                        local set_ok, set_error, forcible = dict:set(ban_key, rule.action.ban_seconds, rule.action.ban_seconds)
                        if not set_ok or forcible then
                            record_capacity_failure(policy, context.tenant_id, context.site_id, forcible)
                            ngx.log(ngx.ERR, "cc ban state unavailable rule_id=", rule.rule_id, ": ",
                                set_error or "state capacity exhausted")
                        end
                        retry_or_error = rule.action.ban_seconds
                    end
                    return reject(retry_or_error)
                end
            end
        end
    end
end

return _M
