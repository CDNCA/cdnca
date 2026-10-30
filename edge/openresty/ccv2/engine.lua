local bit = require("bit")
local cjson = require("cjson.safe")
local resty_lock = require("resty.lock")
local resty_random = require("resty.random")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

-- The public port. A composed node dispatches plaintext and TLS that share one
-- port through internal unix sockets, where $server_port is empty; those
-- listeners alone accept PROXY protocol, which carries the public port.
local function public_server_port()
    return ngx.var.proxy_protocol_server_port or ngx.var.server_port
end

local _M = {}

-- FX60/NF38: every response this engine answers itself (ban / 429 / challenge
-- page / challenge redirect / 403/405/503 exit) is a block page, tagged via
-- edgeconfig.MarkBlockPageLua so its traffic is kept out of package traffic.
-- Servers rendered without the telemetry variable simply skip the tag.
-- Telemetry variable names: $cdnca_security_* (configure may rename them).
local vars = {
    block_page = "cdnca_security_block_page", type = "cdnca_security_type", action = "cdnca_security_action",
    severity = "cdnca_security_severity", rule_id = "cdnca_security_rule_id", emit = "cdnca_security_emit",
    aggregate = "cdnca_security_aggregate",
}

local function block_exit(status)
    pcall(function() ngx.var[vars.block_page] = "1" end)
    return ngx.exit(status)
end

local REGISTRY_SCHEMA = "cdnca.edge.cc-registry/v1"
local POLICY_SCHEMA = "cdnca.edge.cc/v2"
local POLICY_STATE_OK = "ok"
local POLICY_STATE_FAILED = "failed"
local POLICY_RELOAD_ERROR = "active CC v2 policy is unavailable"
local POLICY_DEPENDENCY_ERROR = "CC v2 policy reload state is unavailable"
local POLICY_FAILURE_ACTIVE = "active_policy_unavailable"
local POLICY_FAILURE_DEPENDENCY = "reload_state_unavailable"
local METRICS_SCHEMA = "cdnca.edge.cc-metrics/v1"
local MAX_POLICY_BYTES = 1024 * 1024
local MAX_RULES = 128
local MAX_ENTRIES = 1000
local MAX_SAFE_INTEGER = 9007199254740991
local MAX_STAT_THRESHOLD = 1024
local MAX_USER_AGENT_BYTES = 1024

local entries
local state_dict_name
-- scoped_state: a node composing several configuration scopes keeps every
-- per-client key (counters, bans, challenge state, the challenge cookie
-- secret) under the entry's tenant scope, so one tenant's traffic, bans and
-- passes never reach another's. Single-scope runtimes keep the original keys.
local scoped_state = false

-- Dynamic routing entries (access_object) are always scoped: one node serves
-- every scope's sites from the same shared dictionary.
local function is_scoped(entry)
    return scoped_state or entry.scoped == true
end

local function scoped(entry, key)
    if not is_scoped(entry) then return key end
    return "t:" .. entry.config.tenant_scope_id .. ":" .. key
end
local release_root
local reload_interval = 1

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

local function canonical_uuid(value)
    return type(value) == "string" and value ~= "00000000-0000-0000-0000-000000000000"
        and value:match("^[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]%-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]%-[1-8][0-9a-f][0-9a-f][0-9a-f]%-[89ab][0-9a-f][0-9a-f][0-9a-f]%-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]$") ~= nil
end

local function lower_hex(value, length)
    return type(value) == "string" and #value == length and value:match("^[0-9a-f]+$") ~= nil
end

local function sha256(value)
    local digest = resty_sha256:new()
    if not digest or not digest:update(value) then
        return nil
    end
    return resty_string.to_hex(digest:final())
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
        if #part > 4 or not part:match("^[0-9a-f]+$") then
            return nil
        end
        words[#words + 1] = tonumber(part, 16)
    end
    return words
end

local function parse_ipv6(value)
    if type(value) ~= "string" or #value < 2 or #value > 39 or value ~= string.lower(value) or value:find("[%%%.]") then
        return nil
    end
    local marker = value:find("::", 1, true)
    if marker and value:find("::", marker + 2, true) then
        return nil
    end
    local left = ipv6_side(marker and value:sub(1, marker - 1) or value)
    local right = ipv6_side(marker and value:sub(marker + 2) or "")
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
    return { family = 6, bytes = bytes, text = value }
end

local function parse_address(value)
    return parse_ipv4(value) or parse_ipv6(value)
end

local function parse_cidr(value)
    if type(value) ~= "string" then
        return nil
    end
    local address_text, prefix_text = value:match("^(.-)/([0-9]+)$")
    local address = parse_address(address_text)
    local prefix = tonumber(prefix_text)
    local maximum = address and (address.family == 4 and 32 or 128)
    if not address or not prefix or prefix ~= math.floor(prefix) or prefix < 0 or prefix > maximum then
        return nil
    end
    local full = math.floor(prefix / 8)
    local partial = prefix % 8
    for index = full + 1, #address.bytes do
        local mask = index == full + 1 and partial > 0 and bit.band(0xff, bit.lshift(0xff, 8 - partial)) or 0
        if bit.band(address.bytes[index], mask) ~= address.bytes[index] then
            return nil
        end
    end
    return { family = address.family, bytes = address.bytes, prefix = prefix }
end

local function cidr_contains(cidr, address)
    if not cidr or not address or cidr.family ~= address.family then
        return false
    end
    local full = math.floor(cidr.prefix / 8)
    local partial = cidr.prefix % 8
    for index = 1, full do
        if cidr.bytes[index] ~= address.bytes[index] then
            return false
        end
    end
    if partial > 0 then
        local mask = bit.band(0xff, bit.lshift(0xff, 8 - partial))
        return bit.band(cidr.bytes[full + 1], mask) == bit.band(address.bytes[full + 1], mask)
    end
    return true
end

local function valid_host(value)
    if type(value) ~= "string" or #value == 0 or #value > 253 or value ~= string.lower(value)
        or value:find("[:/\\%%]") or value:sub(-1) == "." then
        return false
    end
    for label in (value .. "."):gmatch("(.-)%.") do
        if #label == 0 or #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-"
            or label:find("[^a-z0-9-]") then
            return false
        end
    end
    return true
end

-- A registry entry's hostname is the site's primary domain: an exact host or
-- a leading wildcard ("*.x.example", edgeconfig normalizeSiteDomainName). It
-- identifies the entry only; requests are bound by entry_id. A rule's
-- match.host is any domain the server serves: exact, or a wildcard alias
-- (host_matches).
local function valid_site_domain(value)
    if type(value) == "string" and value:sub(1, 2) == "*." and #value <= 253 then
        local base = value:sub(3)
        return base:find(".", 1, true) ~= nil and valid_host(base)
    end
    return valid_host(value)
end

local function valid_path(value)
    if type(value) ~= "string" or #value == 0 or #value > 1024 or value:sub(1, 1) ~= "/"
        or value:find("[\\%%?#%c]") or value:find("//", 1, true) then
        return false
    end
    for segment in value:gmatch("[^/]+") do
        if segment == "." or segment == ".." then
            return false
        end
    end
    return true
end

local path_fields = { kind = true, value = true }
local match_fields = {
    host = true, port = true, method = true, path = true, source_cidr = true,
    distinct_user_agents = true, status_404_count = true, path_contains = true,
    client_ip = true, headers = true,
    -- CC API v7: the request's JA4 is one of the values.
    ja4 = true,
}
-- CC API v6 (edgeconfig.CCV2IPMatch / CCV2HeaderMatch / CCV2TrustedCrawler).
local ip_match_fields = { negate = true, cidrs = true }
local header_match_fields = { name = true, kind = true, values = true }
local HEADER_KINDS = { exact = true, prefix = true, contains = true, regex = true }
local crawler_fields = { name = true, user_agent_tokens = true, networks = true, rdns_suffixes = true }
local limit_fields = {
    algorithm = true, requests = true, requests_per_uri = true, window_seconds = true, rate_per_second = true, burst = true,
}
local action_fields = { kind = true, ban_seconds = true, challenge = true, target = true }
local challenge_fields = {
    mode = true, delay_seconds = true, failure_window_seconds = true, max_failures = true,
    pass_seconds = true, log_only = true, pass_limit = true, pow_bits = true, challenge_seconds = true,
    bind_ipv4_prefix = true, bind_ipv6_prefix = true, key_rotate_seconds = true,
}
local CHALLENGE_MODES = {
    delay = true, js = true, redirect = true, click = true, easy_click = true,
    slider = true, easy_slider = true, captcha = true, rotate = true,
}
local rule_fields = {
    rule_id = true, priority = true, flow = true, match = true, dimension = true, count_by = true, limit = true, action = true,
}
-- Counting keys (CC API v4) in their canonical order (edgeconfig.ccV2CountKeyOrder).
local COUNT_KEY_ORDER = { client_ip = 1, client_cidr = 2, host = 3, uri = 4, uri_path = 5, ja4 = 6,
    -- CC API v7 (edgeconfig.CCV2CountUserAgent ... CCV2CountQuery).
    user_agent = 7, referer = 8, header = 9, cookie = 10, query = 11 }
-- CC API v7 helpers and the count key fields, one table: the
-- main chunk is at LuaJIT's 200 local limit.
local v7 = { count_key_fields = { key = true, ipv4_prefix = true, ipv6_prefix = true, name = true } }
-- count key names (edgeconfig ccV2CountHeaderNamePattern / ccV2CountParamNamePattern).
function v7.valid_count_name(key)
    local name = key.name
    if key.key == "header" then
        return type(name) == "string" and #name >= 1 and #name <= 64 and not name:find("[^a-z0-9!#$%%&'*+.%^_`|~-]")
    end
    if key.key == "cookie" or key.key == "query" then
        return type(name) == "string" and #name >= 1 and #name <= 128 and not name:find("[^A-Za-z0-9_.:%[%]-]")
    end
    return name == nil
end
local MAX_COUNT_URI_BYTES = 1024
local policy_fields = {
    schema_version = true, tenant_scope_id = true, site_id = true, policy_id = true, policy_version = true,
    binding_id = true, binding_revision = true, publication_id = true, enabled = true,
    trusted_proxies = true, allowlist = true, rules = true, auto_switch = true,
    trusted_crawlers = true, challenge_cookie_domain = true,
}
-- CC API v5 auto switch (edgeconfig.CCV2AutoSwitch).
local auto_switch_fields = { qps_total = true, qps_5xx = true, recover_seconds = true, rules = true,
    overrides = true, rule_sets = true }
-- CC API v8 auto switch overrides live under the
-- auto_switch_fields table: the main chunk is at LuaJIT's 200 locals.
auto_switch_fields._overrides = {
    fields = { nodes = true, qps_total = true, qps_5xx = true, recover_seconds = true, rule_set = true },
    set_fields = { name = true, rules = true },
    max = 64, max_nodes = 10000,
    node_id = "",                         -- this node (configure / init)
    cache = setmetatable({}, { __mode = "k" }),
}
local MAX_AUTO_SWITCH_QPS = 1000000

-- strictly ascending strings (canonical lists from control).
local function ascending(values, length)
    for index = 2, length do
        if values[index - 1] >= values[index] then return false end
    end
    return true
end

-- client_ip (CC API v6): 1..16 entries of 1..256 sorted canonical CIDRs,
-- never a single plain CIDR (that is source_cidr) nor mixed with it.
local function validate_ip_list(value)
    local length = array_length(value.client_ip, 16)
    if not length or length == 0 or value.source_cidr ~= nil then return false end
    local parsed = {}
    for index = 1, length do
        local entry = value.client_ip[index]
        local count = has_only(entry, ip_match_fields) and array_length(entry.cidrs, 256)
        if not count or count == 0 or (entry.negate ~= nil and entry.negate ~= true) then return false end
        local cidrs = {}
        for position = 1, count do
            local text = entry.cidrs[position]
            cidrs[position] = type(text) == "string" and parse_cidr(text)
            if not cidrs[position] then return false end
        end
        if not ascending(entry.cidrs, count) then return false end
        parsed[index] = { negate = entry.negate == true, cidrs = cidrs }
    end
    if length == 1 and not parsed[1].negate and #parsed[1].cidrs == 1 then return false end
    value._client_ip = parsed
    return true
end

-- headers (CC API v6): 1..16 entries; a lower-case field name, a kind and
-- 1..64 sorted values without control characters; regex values compile.
local function validate_headers(value)
    local length = array_length(value.headers, 16)
    if not length or length == 0 then return false end
    for index = 1, length do
        local entry = value.headers[index]
        local count = has_only(entry, header_match_fields) and array_length(entry.values, 64)
        if not count or count == 0 or type(entry.name) ~= "string" or #entry.name == 0 or #entry.name > 128
            or entry.name:find("[^!#$%%&'*+.%^_`|~0-9a-z-]") or not HEADER_KINDS[entry.kind] then
            return false
        end
        for position = 1, count do
            local item = entry.values[position]
            if type(item) ~= "string" or #item == 0 or #item > 1024 or item:find("%c") then return false end
            if entry.kind == "regex" then
                local ok, _, _, err = pcall(ngx.re.find, "", item, "jo")
                if not ok or err then return false end
            end
        end
        if not ascending(entry.values, count) then return false end
    end
    return true
end

local function validate_match(value)
    if not has_only(value, match_fields) then
        return false
    end
    if value.client_ip ~= nil and not validate_ip_list(value) then return false end
    if value.headers ~= nil and not validate_headers(value) then return false end
    if value.host ~= nil and not valid_site_domain(value.host) then return false end
    if value.port ~= nil and not integer(value.port, 1, 65535) then return false end
    if value.method ~= nil and (type(value.method) ~= "string" or #value.method == 0 or #value.method > 32
        or value.method ~= string.upper(value.method) or value.method:find("[^!#$&'*+.%^_`|~A-Z0-9-]")) then
        return false
    end
    if value.path ~= nil and (not has_only(value.path, path_fields)
        or (value.path.kind ~= "exact" and value.path.kind ~= "prefix") or not valid_path(value.path.value)) then
        return false
    end
    if value.source_cidr ~= nil then
        value._source_cidr = parse_cidr(value.source_cidr)
        if not value._source_cidr then return false end
    end
    if value.distinct_user_agents ~= nil
        and not integer(value.distinct_user_agents, 1, MAX_STAT_THRESHOLD) then return false end
    if value.status_404_count ~= nil
        and not integer(value.status_404_count, 1, MAX_STAT_THRESHOLD) then return false end
    if value.ja4 ~= nil then
        local length = array_length(value.ja4, 64)
        if not length or length == 0 then return false end
        local set = {}
        for index = 1, length do
            local item = value.ja4[index]
            if type(item) ~= "string" or #item == 0 or #item > 64 or (index > 1 and value.ja4[index - 1] >= item) then return false end
            set[item] = true
        end
        value._ja4 = set
    end
    if value.path_contains ~= nil then
        local length = array_length(value.path_contains, 64)
        if not length or length == 0 or value.path ~= nil then return false end
        for index = 1, length do
            local needle = value.path_contains[index]
            if type(needle) ~= "string" or #needle == 0 or #needle > 256 or needle:find("%c") then return false end
        end
    end
    return true
end

local function validate_limit(value)
    if not has_only(value, limit_fields) then return false end
    if value.algorithm == "fixed_window" then
        return integer(value.requests, 1, 1000000) and integer(value.window_seconds, 1, 3600)
            and (value.requests_per_uri == nil or integer(value.requests_per_uri, 1, 1000000))
            and value.rate_per_second == nil and value.burst == nil
    end
    if value.algorithm == "leaky_bucket" then
        return integer(value.rate_per_second, 1, 1000000) and integer(value.burst, 1, 1000000)
            and value.requests == nil and value.window_seconds == nil and value.requests_per_uri == nil
    end
    if value.algorithm == "always" then
        return value.requests == nil and value.window_seconds == nil and value.requests_per_uri == nil
            and value.rate_per_second == nil and value.burst == nil
    end
    return false
end

local function validate_challenge(value, ban_seconds)
    if not has_only(value, challenge_fields) or not CHALLENGE_MODES[value.mode]
        or not integer(value.failure_window_seconds, 1, 86400) or not integer(value.max_failures, 1, 1000)
        or not integer(value.pass_seconds, 60, 604800)
        or (value.log_only ~= nil and value.log_only ~= true)
        or (value.log_only == true) ~= (ban_seconds == nil)
        or (ban_seconds ~= nil and not integer(ban_seconds, 1, 86400))
        or (value.mode == "delay") ~= (value.delay_seconds ~= nil)
        or (value.delay_seconds ~= nil and not integer(value.delay_seconds, 1, 30))
        or not integer(value.pow_bits, value.mode == "redirect" and 0 or 8, value.mode == "redirect" and 0 or 26)
        or not integer(value.challenge_seconds, 30, 3600)
        or not integer(value.bind_ipv4_prefix, 8, 32) or not integer(value.bind_ipv6_prefix, 32, 128)
        or not integer(value.key_rotate_seconds, value.pass_seconds, 2592000) then
        return false
    end
    return value.pass_limit == nil or (validate_limit(value.pass_limit) and value.pass_limit.algorithm == "fixed_window")
end

-- count_by in the canonical form control and the agent compile (absent for
-- the default client IP): one or two keys in COUNT_KEY_ORDER, client_cidr
-- with both prefixes, never client_ip alone, client_ip+client_cidr or
-- uri+uri_path, no per-client statistics, a challenge only through its
-- fixed-window trigger. action.target count_key is a temporary ban's only.
local function validate_count_by(rule)
    local target = rule.action.target
    if target ~= nil and (target ~= "count_key" or rule.action.kind ~= "temporary_ban" or rule.count_by == nil) then
        return false
    end
    if rule.count_by == nil then return true end
    local length = array_length(rule.count_by, 2)
    if not length or length == 0 or rule.match.distinct_user_agents ~= nil or rule.match.status_404_count ~= nil
        or (rule.action.kind == "challenge" and rule.limit.algorithm ~= "fixed_window") then
        return false
    end
    local seen, previous = {}, 0
    for index = 1, length do
        local key = rule.count_by[index]
        local position = type(key) == "table" and COUNT_KEY_ORDER[key.key]
        if not has_only(key, v7.count_key_fields) or not position or position <= previous then return false end
        if key.key == "client_cidr" then
            if not integer(key.ipv4_prefix, 8, 32) or not integer(key.ipv6_prefix, 32, 128) then return false end
        elseif key.ipv4_prefix ~= nil or key.ipv6_prefix ~= nil then
            return false
        end
        if not v7.valid_count_name(key) then return false end
        previous, seen[key.key] = position, true
    end
    if (length == 1 and seen.client_ip) or (seen.client_ip and seen.client_cidr) or (seen.uri and seen.uri_path) then
        return false
    end
    rule._count_by = rule.count_by
    rule._counts_ja4 = seen.ja4 == true
    return true
end

local function validate_action(value, flow, algorithm)
    if not has_only(value, action_fields) then return false end
    if value.kind == "challenge" then
        return flow == "stop" and validate_challenge(value.challenge, value.ban_seconds)
    end
    if value.challenge ~= nil or algorithm == "always" then return false end
    if value.kind == "log" then
        return value.ban_seconds == nil and (flow == "continue" or flow == "stop")
    end
    if value.kind == "reject_429" then
        return value.ban_seconds == nil and flow == "stop"
    end
    return value.kind == "temporary_ban" and flow == "stop" and integer(value.ban_seconds, 1, 86400)
end

-- validate_rules checks one ordered rule set of policy; seen collects IDs.
local function validate_rules(policy, rules, length, seen)
    local previous_priority, previous_id
    for index = 1, length do
        local rule = rules[index]
        if not has_only(rule, rule_fields) or not canonical_uuid(rule.rule_id)
            or not integer(rule.priority, 1, 1000000) or rule.dimension ~= "client_ip"
            or (rule.flow ~= "continue" and rule.flow ~= "stop") or not validate_match(rule.match)
            or not validate_limit(rule.limit) or not validate_action(rule.action, rule.flow, rule.limit.algorithm)
            or ((rule.match.distinct_user_agents ~= nil or rule.match.status_404_count ~= nil)
                and rule.limit.algorithm ~= "fixed_window")
            or not validate_count_by(rule)
            or seen[rule.rule_id] then
            return "invalid or duplicate policy rule"
        end
        if previous_priority and (rule.priority < previous_priority
            or (rule.priority == previous_priority and rule.rule_id <= previous_id)) then
            return "policy rules are not sorted"
        end
        seen[rule.rule_id] = true
        if rule.action.kind == "challenge" then policy._has_challenge = true end
        previous_priority, previous_id = rule.priority, rule.rule_id
    end
    return nil
end

-- A cookie domain / rDNS suffix: a lower-case host of two labels or more.
local function valid_domain(value)
    return valid_host(value) and value:find(".", 1, true) ~= nil
end

-- trusted_crawlers (CC API v6): 1..32 crawlers sorted by name, each with
-- sorted User-Agent tokens and networks and/or rDNS suffixes.
local function validate_trusted_crawlers(policy)
    local length = array_length(policy.trusted_crawlers, 32)
    if not length or length == 0 then return false end
    local crawlers = {}
    for index = 1, length do
        local crawler = policy.trusted_crawlers[index]
        local tokens = has_only(crawler, crawler_fields) and array_length(crawler.user_agent_tokens, 16)
        if not tokens or tokens == 0 or type(crawler.name) ~= "string" or #crawler.name == 0 or #crawler.name > 64
            or crawler.name:find("[^a-z0-9_.-]") or (index > 1 and policy.trusted_crawlers[index - 1].name >= crawler.name)
            or (crawler.networks == nil and crawler.rdns_suffixes == nil) or not ascending(crawler.user_agent_tokens, tokens) then
            return false
        end
        for position = 1, tokens do
            local token = crawler.user_agent_tokens[position]
            if type(token) ~= "string" or #token < 3 or #token > 128 or token:find("[^!-~]") then return false end
        end
        local compiled = { name = crawler.name, tokens = crawler.user_agent_tokens, networks = {}, suffixes = {} }
        if crawler.networks ~= nil then
            local count = array_length(crawler.networks, 256)
            if not count or count == 0 or not ascending(crawler.networks, count) then return false end
            for position = 1, count do
                local cidr = parse_cidr(crawler.networks[position])
                if not cidr or cidr.prefix == 0 then return false end
                compiled.networks[position] = cidr
            end
        end
        if crawler.rdns_suffixes ~= nil then
            local count = array_length(crawler.rdns_suffixes, 16)
            if not count or count == 0 or not ascending(crawler.rdns_suffixes, count) then return false end
            for position = 1, count do
                if not valid_domain(crawler.rdns_suffixes[position]) then return false end
                compiled.suffixes[position] = crawler.rdns_suffixes[position]
            end
        end
        crawlers[index] = compiled
    end
    policy._crawlers = crawlers
    return true
end

-- validate_auto_switch_overrides (CC API v8): each override
-- names distinct canonical node IDs (no node twice), is off (both
-- thresholds and recovery 0, no rule set) or a usable value running the
-- global rules (no rule set, global on) or a named rule set; every rule set
-- is sorted by name and used; rule IDs stay distinct across all sets.
function auto_switch_fields._overrides.validate(value, switch, global_off, seen)
    local sets = {}
    if switch.rule_sets ~= nil then
        local count = array_length(switch.rule_sets, auto_switch_fields._overrides.max)
        if not count then return "invalid auto switch rule sets" end
        local previous
        for index = 1, count do
            local set = switch.rule_sets[index]
            local length = type(set) == "table" and has_only(set, auto_switch_fields._overrides.set_fields) and array_length(set.rules, MAX_RULES)
            if not length or length == 0 or type(set.name) ~= "string" or #set.name == 0 or #set.name > 128
                or (previous and previous >= set.name) then
                return "invalid auto switch rule set"
            end
            local rules_error = validate_rules(value, set.rules, length, seen)
            if rules_error then return rules_error end
            sets[set.name], previous = 0, set.name
        end
    end
    local nodes = {}
    for _, override in ipairs(switch.overrides) do
        local count = type(override) == "table" and has_only(override, auto_switch_fields._overrides.fields)
            and array_length(override.nodes, auto_switch_fields._overrides.max_nodes)
        if not count or count == 0 or not integer(override.qps_total, 0, MAX_AUTO_SWITCH_QPS)
            or not integer(override.qps_5xx, 0, MAX_AUTO_SWITCH_QPS) or not integer(override.recover_seconds, 0, 86400)
            or (override.rule_set ~= nil and type(override.rule_set) ~= "string") then
            return "invalid auto switch override"
        end
        for index = 1, count do
            local node = override.nodes[index]
            if not canonical_uuid(node) or nodes[node] or (index > 1 and override.nodes[index - 1] >= node) then
                return "invalid auto switch override nodes"
            end
            nodes[node] = true
        end
        if override.qps_total == 0 and override.qps_5xx == 0 then
            if override.recover_seconds ~= 0 or override.rule_set ~= nil then return "invalid auto switch override" end
        elseif override.recover_seconds < 60 then
            return "invalid auto switch override"
        elseif override.rule_set == nil then
            if global_off then return "invalid auto switch override" end
        elseif sets[override.rule_set] == nil then
            return "invalid auto switch override rule set"
        else
            sets[override.rule_set] = sets[override.rule_set] + 1
        end
    end
    for _, used in pairs(sets) do
        if used == 0 then return "unused auto switch rule set" end
    end
end

local function validate_policy(value, entry)
    if not has_only(value, policy_fields) or value.schema_version ~= POLICY_SCHEMA
        or value.tenant_scope_id ~= entry.tenant_scope_id or value.site_id ~= entry.site_id
        or value.policy_id ~= entry.policy_id or value.policy_version ~= entry.policy_version
        or value.binding_id ~= entry.binding_id or value.binding_revision ~= entry.binding_revision
        or value.publication_id ~= entry.publication_id or type(value.enabled) ~= "boolean"
        or array_length(value.trusted_proxies, 0) ~= 0 or array_length(value.allowlist, 0) ~= 0 then
        return nil, "invalid policy envelope"
    end
    local length = array_length(value.rules, MAX_RULES)
    if not length or (not value.enabled and length ~= 0) then
        return nil, "invalid policy rules"
    end
    if (value.trusted_crawlers ~= nil or value.challenge_cookie_domain ~= nil) and not value.enabled
        or (value.trusted_crawlers ~= nil and not validate_trusted_crawlers(value))
        or (value.challenge_cookie_domain ~= nil and not valid_domain(value.challenge_cookie_domain)) then
        return nil, "invalid trusted crawlers or challenge cookie domain"
    end
    -- Rule IDs are distinct across the policy's and the auto switch's rules.
    local seen = {}
    local rules_error = validate_rules(value, value.rules, length, seen)
    if rules_error then return nil, rules_error end
    local switch = value.auto_switch
    if switch ~= nil then
        local switch_length = switch._overrides == nil and has_only(switch, auto_switch_fields) and array_length(switch.rules, MAX_RULES)
        local override_count = switch.overrides ~= nil and array_length(switch.overrides, auto_switch_fields._overrides.max)
        -- CC API v8: with overrides the global value may be off (all zero, no rules).
        local global_off = override_count and override_count > 0 and switch_length == 0 and switch.qps_total == 0
            and switch.qps_5xx == 0 and switch.recover_seconds == 0
        if not value.enabled or not switch_length or (switch.overrides ~= nil and (not override_count or override_count == 0))
            or (switch.rule_sets ~= nil and switch.overrides == nil) then
            return nil, "invalid auto switch"
        end
        if not global_off and (switch_length == 0
            or not integer(switch.qps_total, 0, MAX_AUTO_SWITCH_QPS) or not integer(switch.qps_5xx, 0, MAX_AUTO_SWITCH_QPS)
            or (switch.qps_total == 0 and switch.qps_5xx == 0) or not integer(switch.recover_seconds, 60, 86400)) then
            return nil, "invalid auto switch"
        end
        rules_error = validate_rules(value, switch.rules, switch_length, seen)
        if rules_error then return nil, rules_error end
        if override_count then
            local override_error = auto_switch_fields._overrides.validate(value, switch, global_off, seen)
            if override_error then return nil, override_error end
        end
    end
    return value
end

local registry_fields = { schema_version = true, config_version_id = true, entries = true }
local entry_fields = {
    entry_id = true, tenant_scope_id = true, site_id = true, hostname = true, listen_port = true,
    protocol = true, policy_id = true, policy_version = true, binding_id = true, binding_revision = true,
    publication_id = true, source_sha256 = true, compiled_path = true, compiled_sha256 = true,
}

local function validate_entry(value)
    if not has_only(value, entry_fields) or not lower_hex(value.entry_id, 32)
        or not canonical_uuid(value.tenant_scope_id) or not canonical_uuid(value.site_id)
        or not valid_site_domain(value.hostname) or not integer(value.listen_port, 1, 65535)
        or (value.protocol ~= "http" and value.protocol ~= "https") or not canonical_uuid(value.policy_id)
        or not integer(value.policy_version, 1, MAX_SAFE_INTEGER) or not canonical_uuid(value.binding_id)
        or not integer(value.binding_revision, 1, MAX_SAFE_INTEGER) or not canonical_uuid(value.publication_id)
        or not lower_hex(value.source_sha256, 64) or not lower_hex(value.compiled_sha256, 64)
        or value.compiled_path ~= "security/" .. value.site_id .. "/cc.compiled.json" then
        return false
    end
    local key = table.concat({ value.tenant_scope_id, value.site_id, value.hostname,
        tostring(value.listen_port), value.protocol }, "\0")
    local digest = sha256(key)
    return digest and value.entry_id == digest:sub(1, 32)
end

-- new_entry is the per-binding runtime state of config (a registry entry,
-- or for dynamic routing the binding identity of a policy object); identity
-- names its shared policy reload state.
local function new_entry(config, identity)
    local metrics = "ccv2:metrics:" .. config.tenant_scope_id .. ":" .. config.site_id .. ":" .. config.policy_id
        .. ":v" .. tostring(config.policy_version)
    return {
        config = config,
        next_reload_at = 0,
        policy_state_key = "ccv2:policy-state:" .. identity,
        policy_lock_key = "ccv2:policy-lock:" .. identity,
        policy_failure_epoch_key = "ccv2:policy-failure-epoch:" .. identity,
        policy_failure_reason_key = "ccv2:policy-failure-reason:" .. identity,
        policy_ok_epoch_key = "ccv2:policy-ok-epoch:" .. identity,
        metrics_capacity_key = metrics .. ":capacity",
        metrics_eviction_key = metrics .. ":evictions",
        metrics_degraded_key = metrics .. ":degraded",
        -- Requests a ja4 counting rule skipped for lack of a TLS fingerprint.
        metrics_ja4_unavailable_key = metrics .. ":ja4_unavailable",
    }
end

local function decode_registry(raw)
    if type(raw) ~= "string" or #raw == 0 or #raw > MAX_POLICY_BYTES then
        return nil, "registry size is invalid"
    end
    local value, decode_error = cjson.decode(raw)
    if not value then return nil, "decode registry: " .. tostring(decode_error) end
    if not has_only(value, registry_fields) or value.schema_version ~= REGISTRY_SCHEMA
        or type(value.config_version_id) ~= "string" or #value.config_version_id == 0
        or #value.config_version_id > 128 or value.config_version_id:find("[^A-Za-z0-9._-]") then
        return nil, "registry envelope is invalid"
    end
    local length = array_length(value.entries, MAX_ENTRIES)
    if not length or length == 0 then return nil, "registry entries are invalid" end
    local by_id, listeners = {}, {}
    local previous
    for index = 1, length do
        local entry = value.entries[index]
        local order = string.format("%05d\0%s\0%s\0%s", entry.listen_port or 0,
            tostring(entry.hostname), tostring(entry.protocol), tostring(entry.entry_id))
        local listener = table.concat({ tostring(entry.tenant_scope_id), tostring(entry.site_id),
            tostring(entry.hostname), tostring(entry.listen_port), tostring(entry.protocol) }, "\0")
        if not validate_entry(entry) or by_id[entry.entry_id] or listeners[listener] or (previous and order <= previous) then
            return nil, "registry entry is invalid, duplicate, or unsorted"
        end
        local identity = entry.compiled_path .. ":" .. entry.compiled_sha256
        by_id[entry.entry_id] = new_entry(entry, identity)
        listeners[listener] = true
        previous = order
    end
    return by_id
end

local function record_capacity_failure(entry, forcible)
    if ngx.ctx.ccv2_capacity_recorded then return end
    ngx.ctx.ccv2_capacity_recorded = true
    local dict = ngx.shared[state_dict_name]
    local capacity, capacity_error = dict:incr(entry.metrics_capacity_key, 1, 0)
    if not capacity then
        ngx.log(ngx.ERR, "cc v2 metrics capacity counter unavailable: ", tostring(capacity_error))
    end
    if forcible then
        local evictions, eviction_error = dict:incr(entry.metrics_eviction_key, 1, 0)
        if not evictions then
            ngx.log(ngx.ERR, "cc v2 metrics eviction counter unavailable: ", tostring(eviction_error))
        end
    end
    local degraded, degraded_error = dict:safe_set(entry.metrics_degraded_key, true)
    if not degraded then
        ngx.log(ngx.ERR, "cc v2 metrics degraded marker unavailable: ", tostring(degraded_error))
    end
end

local function metric_counter(dict, key)
    local value = dict:get(key)
    if value == nil then return 0 end
    if not integer(value, 0, MAX_SAFE_INTEGER) then return nil end
    return value
end

local function read_policy_bytes(entry)
    local file, open_error = io.open(release_root .. "/" .. entry.config.compiled_path, "rb")
    if not file then return nil, "open policy: " .. tostring(open_error) end
    local raw = file:read(MAX_POLICY_BYTES + 1)
    file:close()
    if not raw or #raw == 0 or #raw > MAX_POLICY_BYTES then return nil, "policy size is invalid" end
    local digest = sha256(raw)
    if not digest or digest ~= entry.config.compiled_sha256 then return nil, "policy digest mismatch" end
    return raw, digest
end

local function read_policy(entry)
    local raw, digest_or_error = read_policy_bytes(entry)
    if not raw then return nil, digest_or_error end
    local value, decode_error = cjson.decode(raw)
    if not value then return nil, "decode policy: " .. tostring(decode_error) end
    local validated, validation_error = validate_policy(value, entry.config)
    if not validated then return nil, validation_error end
    return validated, digest_or_error
end

local function set_policy_state(entry, state)
    local dict = ngx.shared[state_dict_name]
    local ok, err = dict:safe_set(entry.policy_state_key, state)
    if ok then return true end
    ngx.log(ngx.ERR, "cc v2 shared policy state write failed: ", tostring(err))
    if state == POLICY_STATE_FAILED then
        ok, err = dict:set(entry.policy_state_key, state)
        if ok then return true end
        ngx.log(ngx.ERR, "cc v2 shared policy failure fallback write failed: ", tostring(err))
        dict:delete(entry.policy_state_key)
        return dict:get(entry.policy_state_key) ~= POLICY_STATE_OK
    end
    return false
end

local function mark_policy_failed(entry, reason)
    local dict = ngx.shared[state_dict_name]
    reason = reason or POLICY_FAILURE_DEPENDENCY
    local epoch, epoch_error = dict:incr(entry.policy_failure_epoch_key, 1, 0)
    if not epoch then
        ngx.log(ngx.ERR, "cc v2 shared policy failure epoch write failed: ", tostring(epoch_error))
        dict:delete(entry.policy_state_key)
        entry.reload_error = POLICY_DEPENDENCY_ERROR
        return false
    end
    dict:delete(entry.policy_ok_epoch_key)
    local ok, reason_error = dict:safe_set(entry.policy_failure_reason_key, reason)
    if not ok then
        ngx.log(ngx.ERR, "cc v2 shared policy failure reason write failed: ", tostring(reason_error))
        dict:delete(entry.policy_state_key)
        entry.reload_error = POLICY_DEPENDENCY_ERROR
        return false
    end
    if not set_policy_state(entry, POLICY_STATE_FAILED) then
        entry.reload_error = POLICY_DEPENDENCY_ERROR
        return false
    end
    if dict:get(entry.policy_failure_reason_key) ~= reason then
        dict:delete(entry.policy_state_key)
        entry.reload_error = POLICY_DEPENDENCY_ERROR
        return false
    end
    entry.reload_error = reason == POLICY_FAILURE_ACTIVE and POLICY_RELOAD_ERROR or POLICY_DEPENDENCY_ERROR
    return true
end

local function shared_policy_state(entry)
    local dict = ngx.shared[state_dict_name]
    local state = dict:get(entry.policy_state_key)
    if state ~= POLICY_STATE_OK then return state, dict:get(entry.policy_failure_reason_key) end
    local failure_epoch = dict:get(entry.policy_failure_epoch_key)
    local ok_epoch = dict:get(entry.policy_ok_epoch_key)
    if type(failure_epoch) == "number" and ok_epoch == failure_epoch then
        return POLICY_STATE_OK
    end
    return POLICY_STATE_FAILED, dict:get(entry.policy_failure_reason_key)
end

local function publish_policy_ok(entry, expected_epoch)
    local dict = ngx.shared[state_dict_name]
    local current_epoch = dict:get(entry.policy_failure_epoch_key)
    if current_epoch ~= expected_epoch then return false end
    local ok, err = dict:safe_set(entry.policy_ok_epoch_key, expected_epoch)
    if not ok then
        ngx.log(ngx.ERR, "cc v2 shared policy ok epoch write failed: ", tostring(err))
        return false
    end
    if dict:get(entry.policy_failure_epoch_key) ~= expected_epoch then return false end
    dict:delete(entry.policy_failure_reason_key)
    ok, err = dict:safe_set(entry.policy_state_key, POLICY_STATE_OK)
    if not ok then
        ngx.log(ngx.ERR, "cc v2 shared policy state write failed: ", tostring(err))
        return false
    end
    return dict:get(entry.policy_failure_epoch_key) == expected_epoch
        and dict:get(entry.policy_ok_epoch_key) == expected_epoch
end

local function unlock_reload(lock, entry)
    local ok, err = lock:unlock()
    if ok then return true end
    ngx.log(ngx.ERR, "cc v2 policy reload unlock failed: ", tostring(err))
    mark_policy_failed(entry)
    return false
end

local function reload(entry, force)
    local now = ngx.now()
    local reload_error = entry.reload_error
    local lkg_usable = reload_error == POLICY_RELOAD_ERROR and entry.policy ~= nil
    if not force and now < entry.next_reload_at then
        local raw, integrity_error = read_policy_bytes(entry)
        if not raw then
            ngx.log(ngx.ERR, "cc v2 cached policy integrity rejected; retaining LKG: ", integrity_error)
            if not mark_policy_failed(entry, POLICY_FAILURE_ACTIVE) then
                return entry.policy, POLICY_DEPENDENCY_ERROR, false
            end
            return entry.policy, POLICY_RELOAD_ERROR, entry.policy ~= nil
        end
        local shared_state, failure_reason = shared_policy_state(entry)
        if shared_state ~= POLICY_STATE_OK then
            lkg_usable = failure_reason == POLICY_FAILURE_ACTIVE and entry.policy ~= nil
            reload_error = lkg_usable and POLICY_RELOAD_ERROR or POLICY_DEPENDENCY_ERROR
        end
        return entry.policy, reload_error, lkg_usable
    end
    local shared_state, failure_reason = shared_policy_state(entry)
    if shared_state ~= POLICY_STATE_OK then
        lkg_usable = failure_reason == POLICY_FAILURE_ACTIVE and entry.policy ~= nil
        reload_error = lkg_usable and POLICY_RELOAD_ERROR or POLICY_DEPENDENCY_ERROR
    end
    entry.next_reload_at = now + reload_interval

    local lock_error
    local lock
    lock, lock_error = resty_lock:new(state_dict_name, { timeout = force and 0 or 0.05, exptime = 5 })
    if not lock then
        ngx.log(ngx.ERR, "cc v2 policy reload lock creation failed: ", tostring(lock_error))
        if force then
            local candidate, read_error = read_policy(entry)
            if not candidate then
                mark_policy_failed(entry, POLICY_FAILURE_ACTIVE)
                return entry.policy, read_error, entry.policy ~= nil
            end
        end
        entry.reload_error = POLICY_DEPENDENCY_ERROR
        return entry.policy, POLICY_DEPENDENCY_ERROR, false
    end
    local elapsed
    elapsed, lock_error = lock:lock(entry.policy_lock_key)
    if not elapsed then
        ngx.log(ngx.ERR, "cc v2 policy reload lock failed: ", tostring(lock_error))
        -- Another worker holds the reload: that is contention, not a broken
        -- dependency. Keep serving the LKG under the shared verdict.
        if not force and lock_error == "timeout" and entry.policy then
            return entry.policy, reload_error, lkg_usable
        end
        if force then
            local candidate, read_error = read_policy(entry)
            if not candidate then
                mark_policy_failed(entry, POLICY_FAILURE_ACTIVE)
                return entry.policy, read_error, entry.policy ~= nil
            end
        end
        entry.reload_error = POLICY_DEPENDENCY_ERROR
        return entry.policy, POLICY_DEPENDENCY_ERROR, false
    end
    local failure_epoch
    failure_epoch, lock_error = ngx.shared[state_dict_name]:incr(entry.policy_failure_epoch_key, 0, 0)
    if not failure_epoch then
        ngx.log(ngx.ERR, "cc v2 shared policy failure epoch read failed: ", tostring(lock_error))
        mark_policy_failed(entry)
        unlock_reload(lock, entry)
        return entry.policy, POLICY_DEPENDENCY_ERROR, false
    end

    local candidate, digest_or_error = read_policy(entry)
    if not candidate then
        if entry.policy then
            ngx.log(ngx.ERR, "cc v2 policy reload rejected; retaining LKG: ", digest_or_error)
            local marked = mark_policy_failed(entry, POLICY_FAILURE_ACTIVE)
            local unlocked = unlock_reload(lock, entry)
            if not marked or not unlocked then return entry.policy, POLICY_DEPENDENCY_ERROR, false end
            return entry.policy, POLICY_RELOAD_ERROR, true
        end
        mark_policy_failed(entry, POLICY_FAILURE_ACTIVE)
        unlock_reload(lock, entry)
        return nil, digest_or_error, false
    end
    if entry.policy and entry.digest ~= digest_or_error then
        ngx.log(ngx.ERR, "cc v2 same-version policy drift rejected; retaining LKG")
        local marked = mark_policy_failed(entry, POLICY_FAILURE_ACTIVE)
        local unlocked = unlock_reload(lock, entry)
        if not marked or not unlocked then return entry.policy, POLICY_DEPENDENCY_ERROR, false end
        return entry.policy, POLICY_RELOAD_ERROR, true
    end
    if not publish_policy_ok(entry, failure_epoch) then
        if ngx.shared[state_dict_name]:get(entry.policy_failure_epoch_key) ~= failure_epoch then
            -- A newer failure was published while this read was in flight; it
            -- stands. Do not overwrite its reason with a dependency failure.
            if not unlock_reload(lock, entry) then return entry.policy, POLICY_DEPENDENCY_ERROR, false end
            local state, reason = shared_policy_state(entry)
            if state == POLICY_STATE_OK then return entry.policy end
            local usable = reason == POLICY_FAILURE_ACTIVE and entry.policy ~= nil
            return entry.policy, usable and POLICY_RELOAD_ERROR or POLICY_DEPENDENCY_ERROR, usable
        end
        mark_policy_failed(entry)
        unlock_reload(lock, entry)
        return entry.policy, POLICY_DEPENDENCY_ERROR, false
    end
    if not unlock_reload(lock, entry) then
        return entry.policy, POLICY_DEPENDENCY_ERROR, false
    end
    entry.policy, entry.digest = candidate, digest_or_error
    entry.reload_error = nil
    return entry.policy
end

-- client_ip list: every entry holds (in one of its CIDRs, or none if negated).
local function client_ip_matches(entries, peer)
    for _, entry in ipairs(entries) do
        local inside = false
        for _, cidr in ipairs(entry.cidrs) do
            if cidr_contains(cidr, peer) then inside = true break end
        end
        if inside == entry.negate then return false end
    end
    return true
end

-- The request's values of one header (lower-case name), cached per request.
-- v7.ja4: $cdnca_ja4 (native JA4 module); nil when undefined (module
-- absent) or empty (plaintext, HTTP/3).
function v7.ja4()
    local ok, value = pcall(function() return ngx.var.cdnca_ja4 end)
    if not ok or type(value) ~= "string" or value == "" then return nil end
    return value
end

local function header_values(name)
    local headers = ngx.ctx.ccv2_headers
    if headers == nil then
        headers = ngx.req.get_headers(100) or {}
        ngx.ctx.ccv2_headers = headers
    end
    local value = headers[name]
    if type(value) == "string" then return { value } end
    return type(value) == "table" and value or {}
end

local function header_value_matches(kind, actual, expected)
    if kind == "exact" then return actual == expected end
    if kind == "prefix" then return actual:sub(1, #expected) == expected end
    if kind == "contains" then return actual:find(expected, 1, true) ~= nil end
    return (ngx.re.find(actual, expected, "jo")) ~= nil
end

-- headers: every entry holds (one of the header's values matches one of
-- its values); a missing header matches no entry.
local function headers_match(entries)
    for _, entry in ipairs(entries) do
        local found = false
        for _, actual in ipairs(header_values(entry.name)) do
            for _, expected in ipairs(entry.values) do
                if type(actual) == "string" and header_value_matches(entry.kind, actual, expected) then found = true break end
            end
            if found then break end
        end
        if not found then return false end
    end
    return true
end

-- host_matches: "*.x.example" matches every host under x.example (not
-- x.example itself), as nginx server_name does.
local function host_matches(pattern, host)
    if pattern:sub(1, 2) == "*." then
        local suffix = pattern:sub(2)
        return #host > #suffix and host:sub(-#suffix) == suffix
    end
    return host == pattern
end

local function static_rule_matches(rule, peer)
    local match = rule.match
    if match.host ~= nil and not host_matches(match.host, string.lower(ngx.var.host or "")) then return false end
    if match.port ~= nil and tonumber(public_server_port()) ~= match.port then return false end
    if match.method ~= nil and ngx.req.get_method() ~= match.method then return false end
    local uri = ngx.var.uri or ""
    if match.path ~= nil then
        if match.path.kind == "exact" and uri ~= match.path.value then return false end
        if match.path.kind == "prefix" and uri:sub(1, #match.path.value) ~= match.path.value then return false end
    end
    if match.path_contains ~= nil then
        local found = false
        for _, needle in ipairs(match.path_contains) do
            if uri:find(needle, 1, true) then found = true break end
        end
        if not found then return false end
    end
    if match._client_ip ~= nil and not client_ip_matches(match._client_ip, peer) then return false end
    if match.headers ~= nil and not headers_match(match.headers) then return false end
    if match._ja4 ~= nil and not match._ja4[v7.ja4() or ""] then return false end
    return match._source_cidr == nil or cidr_contains(match._source_cidr, peer)
end

local function matcher_prefix(entry, rule, peer)
    return scoped(entry, table.concat({ "sec11", entry.config.policy_id, tostring(entry.config.policy_version),
        entry.config.binding_id, tostring(entry.config.binding_revision), rule.rule_id, peer.text }, ":"))
end

local function matcher_bucket(prefix, window_seconds, now)
    return prefix .. ":" .. math.floor(now / window_seconds)
end

local function matcher_ttl(window_seconds, now)
    return math.max(2, math.ceil(window_seconds - (now % window_seconds)) + 1)
end

local function request_user_agent()
    local headers, err = ngx.req.get_headers(100, true)
    if type(headers) ~= "table" or err ~= nil then return nil, "invalid_user_agent" end
    local found
    for name, value in pairs(headers) do
        if type(name) == "string" and string.lower(name) == "user-agent" then
            if found ~= nil or type(value) ~= "string" then return nil, "invalid_user_agent" end
            found = value
        end
    end
    if found == nil or #found == 0 or #found > MAX_USER_AGENT_BYTES or found:find("[%c]") then
        return nil, "invalid_user_agent"
    end
    return found
end

local function with_matcher_lock(key, callback)
    local lock, err = resty_lock:new(state_dict_name, { timeout = 0.05, exptime = 1 })
    if not lock then return nil, err or "create matcher lock failed" end
    local elapsed, lock_error = lock:lock("lock:" .. key)
    if not elapsed then return nil, "matcher lock timeout: " .. tostring(lock_error) end
    local result, callback_error, callback_forcible = callback()
    local unlocked, unlock_error = lock:unlock()
    if not unlocked then return nil, unlock_error or "matcher unlock failed" end
    return result, callback_error, callback_forcible
end

local function observe_user_agent(dict, bucket, ttl, threshold, user_agent)
    return with_matcher_lock("ua:" .. bucket, function()
        local count_key = "ua-count:" .. bucket
        local count = dict:get(count_key) or 0
        if not integer(count, 0, threshold) then return nil, "distinct-UA state is invalid" end
        if count >= threshold then return count end
        local digest = sha256(user_agent)
        if not digest then return nil, "distinct-UA digest failed" end
        local marker = "ua-seen:" .. bucket .. ":" .. digest
        if dict:get(marker) then return count end
        local added, add_error = dict:safe_add(marker, true, ttl)
        if not added then
            if add_error == "exists" then return count end
            return nil, add_error or "distinct-UA marker write failed"
        end
        local next_count, count_error, forcible = dict:incr(count_key, 1, 0, ttl)
        if not next_count or next_count > threshold or forcible then
            dict:delete(marker)
            return nil, count_error or "shared dict eviction", forcible
        end
        return next_count
    end)
end

local function remember_404_observation(entry, prefix, bucket, ttl, threshold)
    local observations = ngx.ctx.ccv2_404_observations
    if observations == nil then
        observations = {}
        ngx.ctx.ccv2_404_observations = observations
    end
    if observations[prefix] == nil then
        observations[prefix] = { entry = entry, bucket = bucket, ttl = ttl, threshold = threshold }
    end
end

local function matcher_failure(reason)
    ngx.log(ngx.ERR, "cc v2 SEC-11 matcher failure: ", reason)
    ngx.header["X-CC-Reason"] = reason
    ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
    return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end

local function count_match(entry, rule, peer, dict, now)
    local match = rule.match
    if match.distinct_user_agents == nil and match.status_404_count == nil then return true end
    local prefix = matcher_prefix(entry, rule, peer)
    if dict:get("stat-failed:" .. prefix) then return nil, "matcher_state_unavailable" end
    local bucket = matcher_bucket(prefix, rule.limit.window_seconds, now)
    local ttl = matcher_ttl(rule.limit.window_seconds, now)
    if match.status_404_count ~= nil then
        remember_404_observation(entry, prefix, bucket, ttl, match.status_404_count)
    end
    if match.distinct_user_agents ~= nil then
        local user_agent, user_agent_error = request_user_agent()
        if not user_agent then return nil, user_agent_error end
        local count, count_error, forcible = observe_user_agent(dict, bucket, ttl, match.distinct_user_agents, user_agent)
        if not count then return nil, count_error or "matcher_state_unavailable", forcible end
        if count < match.distinct_user_agents then return false end
    end
    if match.status_404_count ~= nil then
        local count = dict:get("404-count:" .. bucket) or 0
        if not integer(count, 0, match.status_404_count) then return nil, "matcher_state_unavailable" end
        if count < match.status_404_count then return false end
    end
    return true
end

local function fixed_window(dict, key, limit, now)
    local bucket = math.floor(now / limit.window_seconds)
    local count, err, forcible = dict:incr(key .. ":" .. bucket, 1, 0, limit.window_seconds + 1)
    if not count or forcible then return nil, err or "shared dict eviction", forcible end
    if count > limit.requests then return true, nil, false end
    if limit.requests_per_uri ~= nil then
        local uri_key = key .. ":" .. bucket .. ":u:" .. ngx.md5(ngx.var.uri or "")
        local uri_count, uri_error, uri_forcible = dict:incr(uri_key, 1, 0, limit.window_seconds + 1)
        if not uri_count or uri_forcible then return nil, uri_error or "shared dict eviction", uri_forcible end
        return uri_count > limit.requests_per_uri, nil, false
    end
    return false, nil, false
end

-- reset_window forgets a counter's current fixed window or bucket (a
-- released ban).
local function reset_window(dict, key, limit, now)
    if limit.algorithm == "fixed_window" then
        local bucket = math.floor(now / limit.window_seconds)
        dict:delete("fixed:" .. key .. ":" .. bucket)
    else
        dict:delete("bucket:" .. key)
    end
end

local function leaky_bucket(dict, key, limit, now)
    local lock, err = resty_lock:new(state_dict_name, { timeout = 0.05, exptime = 1 })
    if not lock then return nil, err or "create state lock failed" end
    local elapsed, lock_error = lock:lock("lock:" .. key)
    if not elapsed then return nil, "state lock timeout: " .. tostring(lock_error) end
    local raw = dict:get("bucket:" .. key)
    local tokens, at = limit.burst, now
    if raw then
        tokens, at = raw:match("^([0-9.]+),([0-9.]+)$")
        tokens, at = tonumber(tokens), tonumber(at)
        if not tokens or not at or at > now then
            lock:unlock()
            return nil, "leaky-bucket state is invalid"
        end
        tokens = math.min(limit.burst, tokens + (now - at) * limit.rate_per_second)
    end
    local exceeded = tokens < 1
    if not exceeded then tokens = tokens - 1 end
    local ok, set_error, forcible = dict:set("bucket:" .. key, string.format("%.9f,%.6f", tokens, now),
        math.max(2, math.ceil(limit.burst / limit.rate_per_second) + 1))
    local unlocked, unlock_error = lock:unlock()
    if not ok or forcible then return nil, set_error or "shared dict eviction", forcible end
    if not unlocked then return nil, unlock_error or "state unlock failed", false end
    return exceeded, nil, false
end

local function state_failure(entry, rule, err, forcible)
    record_capacity_failure(entry, forcible)
    ngx.log(ngx.ERR, "cc v2 state failure rule=", rule.rule_id, ": ", tostring(err))
    if rule.action.kind == "log" then return false end
    ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
    return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end

-- Records the moment a CC rule auto-bans a client in the site's security log
-- (security_type=cc, action=temporary_ban) so the control plane can count and
-- list CC-banned IPs (FX36/NF34). Servers rendered without the telemetry
-- variables simply skip it.
-- A temporary ban of the client itself (not of a count_by key)
-- is queued for the Agent, which raises it to the node's kernel firewall on
-- the site's ports while it lasts (DDoS protection cc_kernel_ban). The queue
-- is bounded; a full queue drops the oldest (the OpenResty ban stands either
-- way). The Agent drains it through kernel_bans() on the loopback health
-- server.
local KERNEL_BAN_QUEUE = "kban"
local KERNEL_BAN_QUEUE_LIMIT = 10000

local function queue_kernel_ban(entry, rule, peer)
    local dict = ngx.shared[state_dict_name]
    local until_epoch = math.floor(ngx.now()) + rule.action.ban_seconds
    local length = dict:lpush(KERNEL_BAN_QUEUE, table.concat({ entry.config.tenant_scope_id, entry.config.site_id,
        peer.text, tostring(until_epoch) }, "|"))
    if length and length > KERNEL_BAN_QUEUE_LIMIT then
        dict:rpop(KERNEL_BAN_QUEUE)
        dict:incr("kban_dropped", 1, 0)
    end
end

-- kernel_bans drains the queue: "<tenant scope>|<site>|<client>|<until>".
function _M.kernel_bans()
    local dict = ngx.shared[state_dict_name]
    local lines = {}
    for _ = 1, KERNEL_BAN_QUEUE_LIMIT do
        local line = dict:rpop(KERNEL_BAN_QUEUE)
        if not line then break end
        lines[#lines + 1] = line
    end
    return lines
end

local function emit_temporary_ban(rule)
    pcall(function()
        ngx.var[vars.type] = "cc"
        ngx.var[vars.action] = "temporary_ban"
        ngx.var[vars.severity] = "high"
        ngx.var[vars.rule_id] = rule.rule_id
        ngx.var[vars.emit] = "1"
    end)
end

-- aggregate marks a challenge page / 429 for the per-minute security log
-- (sec-log-agg): the log phase counts it by (site, client, rule, action) and
-- one line with the count is written after the minute. A request that emits
-- (temporary ban) is logged on its own instead.
local function aggregate(rule, action, severity)
    pcall(function()
        ngx.var[vars.type] = "cc"
        ngx.var[vars.action] = action
        ngx.var[vars.severity] = severity
        ngx.var[vars.rule_id] = rule.rule_id
        ngx.var[vars.aggregate] = "1"
    end)
end

local function reject429(rule)
    if rule then aggregate(rule, "block", "high") end
    ngx.header["Retry-After"] = "1"
    ngx.status = ngx.HTTP_TOO_MANY_REQUESTS
    return block_exit(ngx.HTTP_TOO_MANY_REQUESTS)
end

-- ---------------------------------------------------------------------------
-- Verification pages for catalog CC rules (5秒盾 / 无感验证 / 点击 / 滑块 /
-- 验证码 / 旋转图片 / 302跳转). A client without a valid pass gets the page;
-- more than max_failures unpassed pages within failure_window_seconds ban the
-- client IP for ban_seconds (403). Passing sets an HMAC pass cookie bound to
-- site + client IP + User-Agent for pass_seconds; the optional pass_limit is a
-- rate limit for passed clients ("临时白名单") whose breach revokes the pass.
-- ---------------------------------------------------------------------------
local GUARD_VERIFY = "/_guard/verify"
local PASS_COOKIE = "__cdnca_cc_pass"
local REDIRECT_COOKIE = "__cdnca_cc_probe"
local SECRET_KEY = "challenge:secret"
local MAX_TARGET_BYTES = 2048
local CAPTCHA_ALPHABET = "ACEFHKLMNPRTXY34"
local SHAPES = { "圆形", "方形", "三角形", "菱形" }
-- An interactive page cannot be solved by a person faster than this.
local MIN_HUMAN_SECONDS = 0.5

-- Node master secret (32 random bytes, per node start). Pass cookies are
-- signed with a per-period key derived from it (key_rotate_seconds), so keys
-- rotate without coordination; the previous period's key is still accepted.
-- A composed node keeps one master secret per tenant scope (scoped_state).
local function master_secret(entry, dict)
    local key = scoped(entry, SECRET_KEY)
    local secret = dict:get(key)
    if secret then return secret end
    local bytes = resty_random.bytes(32, true)
    if not bytes then return nil end
    dict:safe_add(key, resty_string.to_hex(bytes))
    return dict:get(key)
end

local function random_hex(length)
    local bytes = resty_random.bytes(length, true) or resty_random.bytes(length)
    return bytes and resty_string.to_hex(bytes) or nil
end

local function random_int(minimum, maximum)
    local bytes = resty_random.bytes(4) or ""
    local value = 0
    for index = 1, #bytes do value = value * 256 + bytes:byte(index) end
    return minimum + value % (maximum - minimum + 1)
end

local function sha256_bin(value)
    local digest = resty_sha256:new()
    digest:update(value)
    return digest:final()
end

-- HMAC-SHA256 (RFC 2104) over resty.sha256.
local function hmac_sha256(key, value)
    if #key > 64 then key = sha256_bin(key) end
    key = key .. string.rep("\0", 64 - #key)
    local inner, outer = {}, {}
    for index = 1, 64 do
        local byte = key:byte(index)
        inner[index] = string.char(bit.bxor(byte, 0x36))
        outer[index] = string.char(bit.bxor(byte, 0x5c))
    end
    return resty_string.to_hex(sha256_bin(table.concat(outer) .. sha256_bin(table.concat(inner) .. value)))
end

local function constant_equal(left, right)
    if type(left) ~= "string" or type(right) ~= "string" or #left ~= #right then return false end
    local diff = 0
    for index = 1, #left do diff = bit.bor(diff, bit.bxor(left:byte(index), right:byte(index))) end
    return diff == 0
end

local function user_agent_digest()
    local user_agent = ngx.var.http_user_agent or ""
    return (sha256(user_agent) or ""):sub(1, 16)
end

local function site_key(entry, peer, suffix)
    return scoped(entry, table.concat({ "chal", entry.config.site_id, peer.text, suffix }, ":"))
end

-- The client network the pass is bound to: the address masked to the rule's
-- bind_ipv4_prefix / bind_ipv6_prefix.
local function masked_network(peer, ipv4_prefix, ipv6_prefix)
    local prefix = peer.family == 4 and ipv4_prefix or ipv6_prefix
    local parts = {}
    for index, byte in ipairs(peer.bytes) do
        local keep = prefix - (index - 1) * 8
        if keep >= 8 then parts[index] = byte
        elseif keep <= 0 then parts[index] = 0
        else parts[index] = bit.band(byte, bit.band(0xff, bit.lshift(0xff, 8 - keep))) end
    end
    return peer.family .. ":" .. table.concat(parts, ".") .. "/" .. prefix
end

local function peer_network(peer, challenge)
    return masked_network(peer, challenge.bind_ipv4_prefix, challenge.bind_ipv6_prefix)
end

-- The value a count_by key takes for this request; nil when the request has
-- none (no TLS fingerprint, header, cookie or argument).
local function count_value(key, peer)
    local name = key.key
    if name == "client_ip" then return peer.text end
    if name == "client_cidr" then return masked_network(peer, key.ipv4_prefix, key.ipv6_prefix) end
    if name == "host" then return string.lower(ngx.var.host or "") end
    if name == "uri" then return (ngx.var.request_uri or ""):sub(1, MAX_COUNT_URI_BYTES) end
    if name == "uri_path" then return (ngx.var.uri or ""):sub(1, MAX_COUNT_URI_BYTES) end
    if name == "ja4" then return v7.ja4() end
    -- CC API v7: the first value of the header / cookie / argument; an
    -- absent or empty one is not counted.
    local value
    if name == "user_agent" then value = header_values("user-agent")[1]
    elseif name == "referer" then value = header_values("referer")[1]
    elseif name == "header" then value = header_values(key.name)[1]
    elseif name == "cookie" then value = ngx.var["cookie_" .. key.name]
    elseif name == "query" then
        value = ngx.req.get_uri_args(100)[key.name]
        if type(value) == "table" then value = value[1] end
    end
    if type(value) ~= "string" or value == "" then return nil end
    return value:sub(1, MAX_COUNT_URI_BYTES)
end

-- count_key is the per-rule counter identity for a count_by rule: the
-- binding, revision and rule, then the first 128 bits of SHA-256 over the
-- key values joined with NUL (fixed length whatever the URI or host). nil:
-- the rule does not count this request.
local function count_key(entry, rule, peer)
    local parts = {}
    for index, key in ipairs(rule._count_by) do
        local value = count_value(key, peer)
        if value == nil then return nil end
        parts[index] = key.key .. "=" .. value
    end
    local digest = sha256(table.concat(parts, "\0"))
    if not digest then return nil end
    return scoped(entry, table.concat({ entry.config.binding_id, tostring(entry.config.binding_revision), rule.rule_id,
        "k", digest:sub(1, 32) }, ":"))
end

local function record_ja4_unavailable(entry, dict, rule)
    local _, err = dict:incr(entry.metrics_ja4_unavailable_key, 1, 0)
    if err then ngx.log(ngx.ERR, "cc v2 ja4_unavailable counter: ", tostring(err)) end
    ngx.log(ngx.INFO, "cc v2 rule=", rule.rule_id, " not counted: ja4_unavailable")
end

-- ---------------------------------------------------------------------------
-- Rule statistics (the CC page and automatic defense read the same counts). Every worker counts in a process-local
-- table (no shared dictionary write on the request path), keyed by site,
-- policy, rule and minute; a one-second timer encodes the table as one frame
-- and pushes it onto a bounded shared list that the Agent drains through
-- stats() on the loopback health server. A full list or table drops and
-- counts the drop; a worker crash loses at most one second.
-- ---------------------------------------------------------------------------
-- The section is a do block (the main chunk is near the 200 local variable
-- limit); only stat and acted are visible below it.
local stat, acted
do
local STATS = {
    SCHEMA = "cdnca.edge.cc-stats-frame/v1",
    QUEUE = "ccstats",
    QUEUE_LIMIT = 256,
    DROPPED = "ccstats_dropped",
    MAX_ROWS = 1024,
    MAX_CANDIDATES = 64,
    TOP = 10,
    MAX_PATH_BYTES = 256,
}

-- rows / count / dropped: this worker's pending frame; timer: flush armed.
local stats_state = { rows = {}, count = 0, dropped = 0, timer = false }

local function stats_top(candidates)
    local list = {}
    for value, count in pairs(candidates) do list[#list + 1] = { value, count } end
    table.sort(list, function(a, b) return a[2] > b[2] or (a[2] == b[2] and a[1] < b[1]) end)
    local top = {}
    for index = 1, math.min(#list, STATS.TOP) do top[list[index][1]] = list[index][2] end
    return top
end

local function stats_flush(premature)
    if premature or stats_state.count == 0 and stats_state.dropped == 0 then return end
    local rows, dropped = {}, stats_state.dropped
    for _, row in pairs(stats_state.rows) do
        row.top_clients, row.top_paths, row._candidates = stats_top(row.top_clients), stats_top(row.top_paths), nil
        rows[#rows + 1] = row
    end
    stats_state.rows, stats_state.count, stats_state.dropped = {}, 0, 0
    local dict = ngx.shared[state_dict_name]
    if dropped > 0 then dict:incr(STATS.DROPPED, dropped, 0) end
    if #rows == 0 then return end
    local frame = cjson.encode({ schema = STATS.SCHEMA, pid = ngx.worker.pid(), rows = rows })
    local length = frame and dict:lpush(STATS.QUEUE, frame)
    if not length then
        dict:incr(STATS.DROPPED, #rows, 0)
    elseif length > STATS.QUEUE_LIMIT then
        local oldest = dict:rpop(STATS.QUEUE)
        local decoded = oldest and cjson.decode(oldest)
        dict:incr(STATS.DROPPED, type(decoded) == "table" and type(decoded.rows) == "table" and #decoded.rows or 1, 0)
    end
end

-- stat(entry, rule_id, field, peer): one request of field (matched |
-- triggered | challenged | blocked | passed | ja4_unavailable). rule_id "" is
-- a site level count (a challenge ban outside any rule). Triggered requests
-- feed the client and path top lists (candidates are bounded per row; a
-- value first seen after the bound is not tracked).
local function stat_candidate(row, list, value)
    if value == "" then return end
    if list[value] then
        list[value] = list[value] + 1
    elseif row._candidates < STATS.MAX_CANDIDATES * 2 then
        list[value], row._candidates = 1, row._candidates + 1
    end
end

function stat(entry, rule_id, field, peer)
    if not stats_state.timer then
        stats_state.timer = ngx.timer.every(1, stats_flush) and true or false
    end
    local config = entry.config
    local minute = math.floor(ngx.now() / 60) * 60
    local key = table.concat({ config.tenant_scope_id, config.site_id, config.policy_id, tostring(config.policy_version),
        rule_id, tostring(minute) }, "|")
    local row = stats_state.rows[key]
    if not row then
        if stats_state.count >= STATS.MAX_ROWS then
            stats_state.dropped = stats_state.dropped + 1
            return
        end
        row = { tenant_scope_id = config.tenant_scope_id, site_id = config.site_id, policy_id = config.policy_id,
            -- Decimal text: cjson encodes numbers with 14 significant digits.
            policy_version = string.format("%d", config.policy_version), rule_id = rule_id, minute = minute,
            matched = 0, triggered = 0,
            challenged = 0, blocked = 0, passed = 0, ja4_unavailable = 0, top_clients = {}, top_paths = {},
            _candidates = 0 }
        stats_state.rows[key], stats_state.count = row, stats_state.count + 1
    end
    row[field] = row[field] + 1
    if field == "triggered" then
        stat_candidate(row, row.top_clients, peer.text)
        stat_candidate(row, row.top_paths, (ngx.var.uri or ""):sub(1, STATS.MAX_PATH_BYTES))
    end
end

-- acted: the rule acted on the request (triggered) with outcome field.
function acted(entry, rule_id, field, peer)
    stat(entry, rule_id, "triggered", peer)
    stat(entry, rule_id, field, peer)
end

-- stats drains the frames (one JSON object per line) and reports the drops
-- since the previous drain as a last line {"dropped":n}.
function _M.stats()
    local dict = ngx.shared[state_dict_name]
    local lines = {}
    if not dict then return lines end
    for _ = 1, STATS.QUEUE_LIMIT do
        local frame = dict:rpop(STATS.QUEUE)
        if not frame then break end
        lines[#lines + 1] = frame
    end
    local dropped = dict:get(STATS.DROPPED)
    if type(dropped) == "number" and dropped > 0 then
        dict:incr(STATS.DROPPED, -dropped, 0)
        lines[#lines + 1] = '{"dropped":' .. string.format("%d", dropped) .. '}'
    end
    return lines
end
end

local function period_key(entry, dict, challenge, epoch)
    local master = master_secret(entry, dict)
    return master and hmac_sha256(master, "cc-pass-key/v2|" .. challenge.key_rotate_seconds .. "|" .. epoch)
end

local function pass_material(entry, rule, peer, epoch, expires_at, issued_ms)
    return table.concat({ "pass/v2", entry.config.site_id, rule.rule_id, peer_network(peer, rule.action.challenge),
        user_agent_digest(), tostring(epoch), tostring(expires_at), tostring(issued_ms) }, "|")
end

-- Cookie: v2.<epoch>.<expires>.<issued_ms>.<hmac-sha256 hex>; valid for the
-- rule that issued it, the same client network and User-Agent, before
-- expires, signed with the key of the current or previous period, and not
-- revoked (pass limit) after issue.
local function valid_pass(entry, rule, peer, dict)
    local raw = ngx.var["cookie_" .. PASS_COOKIE]
    if type(raw) ~= "string" or #raw > 160 then return false end
    local epoch, expires_at, issued_ms, signature = raw:match("^v2%.(%d+)%.(%d+)%.(%d+)%.(%x+)$")
    epoch, expires_at, issued_ms = tonumber(epoch), tonumber(expires_at), tonumber(issued_ms)
    local challenge = rule.action.challenge
    local now = ngx.time()
    local current = math.floor(now / challenge.key_rotate_seconds)
    if not epoch or not expires_at or not issued_ms or expires_at < now or (epoch ~= current and epoch ~= current - 1)
        or expires_at > now + challenge.pass_seconds then
        return false
    end
    local key = period_key(entry, dict, challenge, epoch)
    if not key or not constant_equal(signature, hmac_sha256(key, pass_material(entry, rule, peer, epoch, expires_at, issued_ms))) then
        return false
    end
    local revoked = dict:get(site_key(entry, peer, "revoked"))
    return revoked == nil or issued_ms > revoked
end

-- NF28: "; Domain=<d>" when the policy has challenge_cookie_domain and the
-- request host is it or under it (a browser rejects any other Domain);
-- otherwise the cookie stays host-only.
local function cookie_domain_attribute(policy)
    local domain = policy and policy.challenge_cookie_domain
    if domain == nil then return "" end
    local host = string.lower(ngx.var.host or "")
    if host == domain or (#host > #domain and host:sub(-#domain - 1) == "." .. domain) then
        return "; Domain=" .. domain
    end
    return ""
end

local function issue_pass_cookie(entry, rule, peer, dict)
    local challenge = rule.action.challenge
    local now = ngx.time()
    local epoch = math.floor(now / challenge.key_rotate_seconds)
    local key = period_key(entry, dict, challenge, epoch)
    if not key then return false end
    local expires_at = now + challenge.pass_seconds
    local issued_ms = math.floor(ngx.now() * 1000)
    local value = table.concat({ "v2", epoch, expires_at, issued_ms,
        hmac_sha256(key, pass_material(entry, rule, peer, epoch, expires_at, issued_ms)) }, ".")
    local secure = ngx.var.scheme == "https" and "; Secure" or ""
    ngx.header["Set-Cookie"] = PASS_COOKIE .. "=" .. value .. "; Path=/; Max-Age=" .. challenge.pass_seconds ..
        cookie_domain_attribute(entry.policy) .. "; HttpOnly; SameSite=Lax" .. secure
    return true
end

-- Proof of work (Anubis / ALTCHA style): the page receives a random salt and
-- must find a decimal counter n such that SHA-256(salt .. ":" .. n) starts
-- with pow_bits zero bits. Verifying costs one hash; solving costs about
-- 2^pow_bits hashes in the browser.
local function leading_zero_bits(digest)
    local bits = 0
    for index = 1, #digest do
        local byte = digest:byte(index)
        if byte == 0 then
            bits = bits + 8
        else
            while bit.band(byte, 0x80) == 0 do bits, byte = bits + 1, bit.lshift(byte, 1) end
            return bits
        end
    end
    return bits
end

local function pow_ok(state, counter)
    if state.pow_bits == 0 then return true end
    if type(counter) ~= "string" or #counter == 0 or #counter > 12 or counter:find("[^0-9]") then return false end
    return leading_zero_bits(sha256_bin(state.pow_salt .. ":" .. counter)) >= state.pow_bits
end

-- Compact SHA-256 + chunked search (keeps the page responsive). Calls
-- done(counter) when SHA-256(salt:counter) has `bits` leading zero bits.
local POW_SCRIPT = "const K=[];for(let i=0,n=2;i<64;n++){let p=1;for(let d=2;d*d<=n;d++)if(n%d==0){p=0;break}" ..
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
    "function solve(salt,bits,done){let n=0;(function step(){const end=n+20000;for(;n<end;n++){if(Z(H(salt+':'+n))>=bits){done(String(n));return}}setTimeout(step,0)})()}"

-- safe_target is where a challenge returns the client: the request URI when
-- it is a plain origin-form path, else "/". Non-idempotent requests keep their
-- URI too: the redirect challenge answers them 307 (redirect_status), so the
-- browser repeats the method and body there, instead of
-- the old "/" that lost the URL and the form.
local function safe_target()
    local target = ngx.var.request_uri or "/"
    if target:sub(1, 1) ~= "/" or target:sub(1, 2) == "//"
        or #target > MAX_TARGET_BYTES or target:find("[%c\\]") or target:sub(1, #GUARD_VERIFY) == GUARD_VERIFY then
        return "/"
    end
    return target
end

-- redirect_status: 302 for GET / HEAD, 307 (method and body preserved) else.
local function redirect_status()
    local method = ngx.req.get_method()
    if method == "GET" or method == "HEAD" then return 302 end
    return 307
end

local GLYPHS = {
    A = { "01110", "10001", "10001", "11111", "10001", "10001", "10001" },
    C = { "01111", "10000", "10000", "10000", "10000", "10000", "01111" },
    E = { "11111", "10000", "10000", "11110", "10000", "10000", "11111" },
    F = { "11111", "10000", "10000", "11110", "10000", "10000", "10000" },
    H = { "10001", "10001", "10001", "11111", "10001", "10001", "10001" },
    K = { "10001", "10010", "10100", "11000", "10100", "10010", "10001" },
    L = { "10000", "10000", "10000", "10000", "10000", "10000", "11111" },
    M = { "10001", "11011", "10101", "10101", "10001", "10001", "10001" },
    N = { "10001", "11001", "10101", "10011", "10001", "10001", "10001" },
    P = { "11110", "10001", "10001", "11110", "10000", "10000", "10000" },
    R = { "11110", "10001", "10001", "11110", "10100", "10010", "10001" },
    T = { "11111", "00100", "00100", "00100", "00100", "00100", "00100" },
    X = { "10001", "10001", "01010", "00100", "01010", "10001", "10001" },
    Y = { "10001", "10001", "01010", "00100", "00100", "00100", "00100" },
    ["3"] = { "11110", "00001", "00001", "01110", "00001", "00001", "11110" },
    ["4"] = { "00010", "00110", "01010", "10010", "11111", "00010", "00010" },
}

local function captcha_svg(text)
    local parts = { '<svg viewBox="0 0 200 70" width="200" height="70" role="img" aria-label="验证码图片">' }
    for index = 1, #text do
        local glyph = GLYPHS[text:sub(index, index)]
        local x0, y0 = 14 + (index - 1) * 46 + random_int(0, 6), 10 + random_int(0, 8)
        for row = 1, 7 do
            for column = 1, 5 do
                if glyph[row]:sub(column, column) == "1" then
                    parts[#parts + 1] = string.format('<rect x="%d" y="%d" width="6" height="6" fill="#%02x%02x%02x"/>',
                        x0 + (column - 1) * 6 + random_int(0, 2), y0 + (row - 1) * 7 + random_int(0, 2),
                        random_int(20, 90), random_int(20, 90), random_int(60, 140))
                end
            end
        end
    end
    for _ = 1, 6 do
        parts[#parts + 1] = string.format('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#889" stroke-width="2"/>',
            random_int(0, 200), random_int(0, 70), random_int(0, 200), random_int(0, 70))
    end
    parts[#parts + 1] = "</svg>"
    return table.concat(parts)
end

local function shape_svg(index)
    local body = ({ '<circle cx="24" cy="24" r="18"/>', '<rect x="7" y="7" width="34" height="34"/>',
        '<polygon points="24,5 44,42 4,42"/>', '<polygon points="24,3 45,24 24,45 3,24"/>' })[index]
    return '<svg viewBox="0 0 48 48" width="48" height="48" aria-hidden="true" fill="#3a5bd9">' .. body .. "</svg>"
end

local PAGE_TITLES = {
    delay = "正在进行 5 秒安全检查", js = "正在检查浏览器环境", click = "请点击指定图形", easy_click = "请点击按钮继续访问",
    slider = "请拖动滑块到指定位置", easy_slider = "请把滑块拖到最右侧", captcha = "请输入图片中的字符", rotate = "请把箭头转正",
}

-- Renders the page body for one mode; returns html, script and the state the
-- verifier checks (expected answer, tolerance, earliest submit time).
-- Each widget returns body, script and the expected answer. The script calls
-- send() when the visitor is done; the page submits once the proof of work
-- (render_challenge) is also solved. 5秒盾 / 无感验证 have no visible answer:
-- the proof of work is the check (and the 5 s wait for 5秒盾).
local function challenge_widget(mode, delay_seconds)
    if mode == "delay" or mode == "js" then
        local wait = mode == "delay" and delay_seconds or 0
        return '<p id="status" role="status" aria-live="polite">' ..
            (wait > 0 and ("请稍候 " .. wait .. " 秒，浏览器会自动完成验证。") or "正在验证浏览器，请稍候。") .. "</p>" ..
            '<noscript><p>需要启用 JavaScript 才能完成验证。</p></noscript>',
            "let left=" .. wait .. ";const st=document.getElementById('status');const go=()=>{if(left>0){st.textContent='请稍候 '+left+' 秒，浏览器会自动完成验证。';left--;setTimeout(go,1000);return;}st.textContent='正在完成验证，请稍候。';send();};go();",
            { not_before = wait }
    end
    if mode == "easy_click" then
        local answer = random_hex(8) or "0"
        return '<button type="button" id="go" data-a="' .. answer .. '">点击继续访问</button>',
            "const g=document.getElementById('go');g.addEventListener('click',()=>{document.getElementById('answer').value=g.dataset.a;send();});",
            { answer = answer, not_before = MIN_HUMAN_SECONDS }
    end
    if mode == "click" then
        local target = random_int(1, 4)
        local ids, buttons = {}, {}
        for index = 1, 4 do
            ids[index] = random_hex(4) or tostring(index)
            buttons[#buttons + 1] = '<button type="button" class="shape" data-id="' .. ids[index] .. '" aria-label="图形 ' ..
                index .. '">' .. shape_svg(index) .. "</button>"
        end
        return "<p>请点击 <strong>" .. SHAPES[target] .. "</strong>。</p><div class=\"shapes\">" .. table.concat(buttons) .. "</div>",
            "document.querySelectorAll('.shape').forEach(b=>b.addEventListener('click',()=>{document.getElementById('answer').value=b.dataset.id;send();}));",
            { answer = ids[target], not_before = MIN_HUMAN_SECONDS }
    end
    if mode == "slider" or mode == "easy_slider" or mode == "rotate" then
        local target = mode == "slider" and random_int(20, 80) or 100
        local label, extra, expected = "滑块位置", "", { answer = tostring(target), tolerance = mode == "slider" and 4 or 3, not_before = MIN_HUMAN_SECONDS }
        if mode == "slider" then
            label = "把滑块拖到 " .. target .. "% 的位置"
            extra = '<svg viewBox="0 0 100 8" width="100%" height="8" aria-hidden="true"><rect width="100" height="8" fill="#ccd"/><rect x="' ..
                (target - 1) .. '" width="2" height="8" fill="#d33"/></svg>'
        elseif mode == "rotate" then
            local angle = random_int(40, 320)
            label = "拖动滑块旋转箭头，直到箭头朝上"
            extra = '<svg viewBox="0 0 80 80" width="80" height="80" role="img" aria-label="箭头"><polygon id="arrow" data-base="' ..
                angle .. '" transform="rotate(' .. angle .. ' 40 40)" points="40,6 60,40 46,40 46,74 34,74 34,40 20,40" fill="#3a5bd9"/></svg>'
            expected = { answer = tostring(360 - angle), tolerance = 12, not_before = MIN_HUMAN_SECONDS, angle = angle }
        else
            label = "把滑块拖到最右侧"
        end
        local maximum = mode == "rotate" and 360 or 100
        return extra .. '<label for="range">' .. label .. '</label><input id="range" type="range" min="0" max="' .. maximum ..
            '" value="0"><button type="button" id="go">提交</button>',
            "const r=document.getElementById('range');const ar=document.getElementById('arrow');" ..
            "if(ar){const base=Number(ar.dataset.base);r.addEventListener('input',()=>{ar.setAttribute('transform','rotate('+(base+Number(r.value))+' 40 40)');});}" ..
            "document.getElementById('go').addEventListener('click',()=>{document.getElementById('answer').value=r.value;send();});",
            expected
    end
    local text = {}
    for index = 1, 4 do
        local position = random_int(1, #CAPTCHA_ALPHABET)
        text[index] = CAPTCHA_ALPHABET:sub(position, position)
    end
    text = table.concat(text)
    return captcha_svg(text) .. '<label for="code">输入上图中的 4 个字符（不区分大小写）</label>' ..
        '<input id="code" autocomplete="off" maxlength="8"><button type="button" id="go">提交</button>',
        "document.getElementById('go').addEventListener('click',()=>{document.getElementById('answer').value=document.getElementById('code').value;send();});",
        { answer = text, not_before = MIN_HUMAN_SECONDS, text = true }
end

local function send_page(status, title, body, script, headers)
    local nonce = random_hex(12) or "0"
    ngx.status = status
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["Content-Security-Policy"] = "default-src 'none'; img-src data:; style-src 'nonce-" .. nonce ..
        "'; script-src 'nonce-" .. nonce .. "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    for name, value in pairs(headers or {}) do ngx.header[name] = value end
    ngx.print('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>',
        title, '</title><style nonce="', nonce, '">body{font-family:system-ui,sans-serif;background:#f5f6f8;color:#1f2329;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}main{background:#fff;padding:32px;border-radius:8px;max-width:420px;width:90%;box-shadow:0 2px 12px rgba(0,0,0,.08)}h1{font-size:20px;margin:0 0 16px}button{font-size:16px;padding:8px 16px;margin:8px 4px 0 0;cursor:pointer}input[type=range]{width:100%}.shapes{display:flex;gap:8px}.shape{padding:4px}label{display:block;margin:12px 0 4px}</style></head><body><main><h1>',
        title, "</h1>", body, "</main>")
    if script then ngx.print('<script nonce="', nonce, '">', script, "</script>") end
    ngx.print("</body></html>")
    return block_exit(status)
end

local function html_escape(value)
    return (tostring(value):gsub("[<>\"'&]", { ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;", ["&"] = "&amp;" }))
end

local function ban_key(entry, peer) return site_key(entry, peer, "ban") end

-- A ban of the client the ban list library released
-- (cdnca_banlist) no longer applies. A ban value is its start time (epoch
-- seconds; true from engines before it, read as 0); a release at or after
-- the start lifts the ban and deletes its key.
local banlist
local function active_ban(dict, entry, peer, key)
    local value = dict:get(key)
    if not value then return false end
    if banlist == nil then
        local ok, module = pcall(require, "cdnca_banlist")
        banlist = ok and module or false
    end
    if banlist and banlist.released_since(entry.config.site_id, peer.text, tonumber(value) or 0) then
        dict:delete(key)
        return false
    end
    return true
end

local function send_ban(entry, peer, dict)
    local retry = math.max(1, math.ceil(tonumber((dict:ttl(ban_key(entry, peer)))) or 1))
    return send_page(403, "访问已被临时限制", "<p>验证失败次数过多，请 " .. retry .. " 秒后再试。</p>", nil,
        { ["Retry-After"] = tostring(retry), ["X-Cdnca-Challenge"] = "banned" })
end

-- Counts one unpassed page / failed proof; returns true when the client is
-- now banned. Log-only rules record the breach and keep serving the page.
local function record_failure(entry, rule, peer, dict, reason)
    local challenge = rule.action.challenge
    local key = site_key(entry, peer, "fail:" .. rule.rule_id)
    local count = dict:incr(key, 1, 0, challenge.failure_window_seconds)
    if not count or count <= challenge.max_failures then return false end
    if challenge.log_only then
        ngx.log(ngx.WARN, "cc challenge threshold exceeded (log only) rule=", rule.rule_id, " ip=", peer.text, " reason=", reason)
        return false
    end
    ngx.log(ngx.WARN, "cc challenge ban rule=", rule.rule_id, " ip=", peer.text, " seconds=", rule.action.ban_seconds, " reason=", reason)
    dict:set(ban_key(entry, peer), math.floor(ngx.now()), rule.action.ban_seconds)
    emit_temporary_ban(rule)
    queue_kernel_ban(entry, rule, peer)
    dict:delete(key)
    return true
end

local function render_challenge(entry, rule, peer, dict)
    local challenge = rule.action.challenge
    aggregate(rule, "challenge", "medium")
    local target = safe_target()
    if challenge.mode == "redirect" then
        local nonce = random_hex(16)
        if not nonce or not dict:set(scoped(entry, "probe:" .. nonce), cjson.encode({ rule_id = rule.rule_id, ip = peer.text,
            ua = user_agent_digest() }), challenge.challenge_seconds) then
            return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
        end
        ngx.header["Set-Cookie"] = REDIRECT_COOKIE .. "=" .. nonce .. "; Path=/; Max-Age=" .. challenge.challenge_seconds ..
            "; HttpOnly; SameSite=Lax"
        ngx.header["Cache-Control"] = "no-store"
        ngx.header["X-Cdnca-Challenge"] = "redirect"
        ngx.header["Location"] = target
        return block_exit(redirect_status())
    end
    local body, script, expected = challenge_widget(challenge.mode, challenge.delay_seconds or 0)
    local token, salt = random_hex(16), random_hex(16)
    local state = { rule_id = rule.rule_id, policy_version = entry.config.policy_version, mode = challenge.mode,
        ip = peer.text, ua = user_agent_digest(), not_before = ngx.now() + expected.not_before,
        answer = expected.answer, tolerance = expected.tolerance, text = expected.text, target = target,
        pow_salt = salt, pow_bits = challenge.pow_bits }
    if is_scoped(entry) then state.site_id = entry.config.site_id end
    if not token or not salt or not dict:set(scoped(entry, "nonce:" .. token), cjson.encode(state), challenge.challenge_seconds) then
        return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    body = '<form id="f" method="post" action="' .. GUARD_VERIFY .. '"><input type="hidden" name="token" value="' .. token ..
        '"><input type="hidden" id="answer" name="answer" value=""><input type="hidden" id="pow" name="pow" value="">' ..
        '<div id="powp" data-salt="' .. salt .. '" data-bits="' .. challenge.pow_bits .. '" data-nb="' ..
        expected.not_before .. '" hidden></div>' .. body .. "</form>"
    -- The page submits once the proof of work is solved, the visitor is done
    -- (send()) and the server's earliest submit time has passed.
    local runner = POW_SCRIPT .. "const F=document.getElementById('f'),PD=document.getElementById('powp').dataset,T0=Date.now();" ..
        "let ready=false,want=false;function fire(){const w=Number(PD.nb)*1000+100-(Date.now()-T0);if(w>0)setTimeout(()=>F.submit(),w);else F.submit();}" ..
        "function send(){want=true;if(ready)fire();}" ..
        "solve(PD.salt,Number(PD.bits),(n)=>{document.getElementById('pow').value=n;ready=true;if(want)fire();});"
    return send_page(503, PAGE_TITLES[challenge.mode], body, runner .. script,
        { ["X-Cdnca-Challenge"] = challenge.mode, ["Retry-After"] = tostring(math.max(1, challenge.delay_seconds or 0)) })
end

local function answer_ok(state, answer)
    if state.answer == nil then return true end -- 5秒盾 / 无感验证: proof of work only
    if type(answer) ~= "string" or #answer == 0 or #answer > 64 then return false end
    if state.tolerance then
        local value, expected = tonumber(answer), tonumber(state.answer)
        if not value or not expected then return false end
        local diff = math.abs(value - expected) % 360
        if state.mode == "rotate" then diff = math.min(diff, 360 - diff) end
        return diff <= state.tolerance
    end
    if state.text then answer = string.upper((answer:gsub("%s", ""))) end
    return constant_equal(answer, state.answer)
end

-- verify's result when the page belongs to another CC policy of the request.
local DEFERRED = {}

local function verify(entry, policy, peer, dict)
    if ngx.req.get_method() ~= "POST" then
        ngx.header["Allow"] = "POST"
        return block_exit(ngx.HTTP_NOT_ALLOWED)
    end
    ngx.req.read_body()
    local args = ngx.req.get_post_args(8) or {}
    if type(args.pow) ~= "string" then args.pow = nil end
    local token = type(args.token) == "string" and args.token or ""
    local nonce_key = scoped(entry, "nonce:" .. token)
    local raw = #token == 32 and token:match("^%x+$") and dict:get(nonce_key)
    local state = raw and cjson.decode(raw)
    if is_scoped(entry) and type(state) == "table" and state.site_id ~= entry.config.site_id then state = nil end
    local rule
    local rule_lists = { policy.rules, policy.auto_switch and policy.auto_switch.rules or {} }
    for _, set in ipairs(policy.auto_switch and policy.auto_switch.rule_sets or {}) do rule_lists[#rule_lists + 1] = set.rules end
    for _, rules in ipairs(rule_lists) do
        for _, candidate in ipairs(rules) do
            if type(state) == "table" and candidate.rule_id == state.rule_id and candidate.action.kind == "challenge" then rule = candidate end
        end
    end
    -- Dynamic routing runs a site's rule pack CC policy after its own
    -- (ngx.ctx.ccv2_more): a page another of the request's policies issued
    -- is left to that policy. The nonce stays single use for its owner.
    if not rule and ngx.ctx.ccv2_more then return DEFERRED end
    if raw then dict:delete(nonce_key) end
    if not rule then
        return send_page(403, "验证已失效", '<p>验证信息已过期，请<a href="/">返回首页</a>重新访问。</p>', nil,
            { ["X-Cdnca-Challenge"] = "expired" })
    end
    if state.policy_version ~= entry.config.policy_version or state.ip ~= peer.text or state.ua ~= user_agent_digest()
        or ngx.now() < state.not_before or not pow_ok(state, args.pow) or not answer_ok(state, args.answer) then
        acted(entry, rule.rule_id, "blocked", peer)
        if record_failure(entry, rule, peer, dict, "proof_invalid") then return send_ban(entry, peer, dict) end
        return send_page(403, "验证未通过", '<p>验证未通过或提交过早，请<a href="' .. html_escape(state.target) ..
            '">返回重试</a>。</p>', nil, { ["X-Cdnca-Challenge"] = "failed" })
    end
    dict:delete(site_key(entry, peer, "fail:" .. rule.rule_id))
    if not issue_pass_cookie(entry, rule, peer, dict) then
        return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    stat(entry, rule.rule_id, "passed", peer)
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Location"] = state.target
    return block_exit(303)
end

-- Returns "passed" (let the request through), "continue" (rule not
-- triggered) or terminates the request with a page / ban.
-- key is the client's counter identity; trigger_key the rule's counting key
-- (key unless the rule has count_by): the pass, its limit, failures and the
-- ban stay per client; only the trigger threshold counts by count_by.
local function challenge_rule(entry, rule, peer, dict, now, key, trigger_key)
    local challenge = rule.action.challenge
    if valid_pass(entry, rule, peer, dict) then
        if not challenge.pass_limit or fixed_window(dict, "passlimit:" .. key, challenge.pass_limit, now) == false then
            stat(entry, rule.rule_id, "passed", peer)
            return "passed"
        end
        dict:set(site_key(entry, peer, "revoked"), math.floor(now * 1000), challenge.pass_seconds)
        ngx.log(ngx.NOTICE, "cc challenge pass revoked by pass limit rule=", rule.rule_id, " ip=", peer.text)
    elseif challenge.mode == "redirect" then
        local probe = ngx.var["cookie_" .. REDIRECT_COOKIE]
        local probe_key = type(probe) == "string" and scoped(entry, "probe:" .. probe)
        local raw = probe_key and #probe == 32 and probe:match("^%x+$") and dict:get(probe_key)
        local state = raw and cjson.decode(raw)
        -- a probe of another rule (another policy of the request) is not
        -- this rule's to consume
        if raw and (type(state) ~= "table" or state.rule_id == rule.rule_id) then dict:delete(probe_key) end
        if type(state) == "table" and state.rule_id == rule.rule_id and state.ip == peer.text and state.ua == user_agent_digest() then
            dict:delete(site_key(entry, peer, "fail:" .. rule.rule_id))
            if not issue_pass_cookie(entry, rule, peer, dict) then return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE) end
            stat(entry, rule.rule_id, "passed", peer)
            ngx.header["Cache-Control"] = "no-store"
            ngx.header["Location"] = safe_target()
            return block_exit(redirect_status())
        end
    end
    if rule.limit.algorithm == "fixed_window" and fixed_window(dict, "fixed:" .. trigger_key, rule.limit, now) == false then
        return "continue"
    end
    if record_failure(entry, rule, peer, dict, "challenge_required") then
        acted(entry, rule.rule_id, "blocked", peer)
        return send_ban(entry, peer, dict)
    end
    acted(entry, rule.rule_id, "challenged", peer)
    return render_challenge(entry, rule, peer, dict)
end

-- Auto switch (CC API v5, 自动切换). Each node counts a site's requests
-- and its proxied 5xx responses per second; when the previous second reached
-- qps_total or qps_5xx the site runs auto_switch.rules instead of its rules,
-- until neither was reached for recover_seconds. One worker evaluates each
-- second. The state is per site, not per publication: a republished policy
-- keeps an engaged switch until it recovers. Every engage and recovery
-- advances the site's sequence (read by the agent, auto_switch_status).
local AUTO_SWITCH_STATUS_SCHEMA = "cdnca.edge.cc-auto-switch/v1"
-- auto_switch_fields._overrides.node_id: this node's ID (configure), picking its override.

local AUTO_SWITCH_COUNTER_TTL = 5

local function auto_switch_prefix(entry)
    return scoped(entry, "ccv2:autoswitch:" .. entry.config.site_id .. ":")
end

local function auto_switch_evaluate(entry, switch, dict, now)
    local prefix = auto_switch_prefix(entry)
    local second = math.floor(now)
    local active = dict:get(prefix .. "active") == true
    if not dict:add(prefix .. "eval:" .. second, true, AUTO_SWITCH_COUNTER_TTL) then return active end
    local previous = second - 1
    local total = dict:get(prefix .. "req:" .. previous) or 0
    local errors = dict:get(prefix .. "5xx:" .. previous) or 0
    dict:set(prefix .. "observed_qps", total)
    dict:set(prefix .. "observed_5xx", errors)
    local over = (switch.qps_total > 0 and total >= switch.qps_total) or (switch.qps_5xx > 0 and errors >= switch.qps_5xx)
    if over then
        dict:set(prefix .. "last_over", previous)
        if active then return true end
        dict:set(prefix .. "active", true)
        dict:set(prefix .. "since", previous)
        dict:set(prefix .. "trigger_qps", total)
        dict:set(prefix .. "trigger_5xx", errors)
        dict:incr(prefix .. "seq", 1, 0)
        ngx.log(ngx.WARN, "cc auto switch engaged site=", entry.config.site_id, " qps=", total, " qps_5xx=", errors)
        return true
    end
    if not active then return false end
    local last_over = dict:get(prefix .. "last_over") or previous
    if previous - last_over < switch.recover_seconds then return true end
    dict:delete(prefix .. "active")
    dict:set(prefix .. "since", previous)
    dict:incr(prefix .. "seq", 1, 0)
    ngx.log(ngx.WARN, "cc auto switch recovered site=", entry.config.site_id, " after=", previous - last_over, "s")
    return false
end

-- effective_auto_switch (CC API v8) is the auto switch this
-- node runs and the layer it came from: the override naming this node (off,
-- or its thresholds with the global rules or its rule set), else the global
-- value (nil when that is off). Cached per policy table.
function auto_switch_fields._overrides.effective(policy)
    local hit = policy.auto_switch and auto_switch_fields._overrides.cache[policy.auto_switch]
    if hit then return hit.value or nil, hit.source end
    local switch = policy.auto_switch
    if not switch then return nil, "global" end
    if not switch.overrides then return switch, "global" end
    local value, source = switch, "global"
    if #switch.rules == 0 then value = nil end
    for _, override in ipairs(switch.overrides) do
        for _, node in ipairs(override.nodes) do
            if node == auto_switch_fields._overrides.node_id then
                source = "override"
                if override.qps_total == 0 and override.qps_5xx == 0 then
                    value = nil
                else
                    local rules = switch.rules
                    if override.rule_set then
                        for _, set in ipairs(switch.rule_sets or {}) do
                            if set.name == override.rule_set then rules = set.rules end
                        end
                    end
                    value = { qps_total = override.qps_total, qps_5xx = override.qps_5xx,
                        recover_seconds = override.recover_seconds, rules = rules }
                end
            end
        end
    end
    auto_switch_fields._overrides.cache[switch] = { value = value or false, source = source }
    return value, source
end

-- auto_switch_status reports every site with an auto switch on this node
-- (the agent polls it to notify; it also lets an idle site recover).
function _M.auto_switch_status()
    local dict = ngx.shared[state_dict_name]
    local now = ngx.now()
    local sites, seen = {}, {}
    for _, entry in pairs(entries or {}) do
        local policy, config = entry.policy, entry.config
        local key = config.tenant_scope_id .. ":" .. config.site_id
        local switch, source = nil, "global"
        if policy and policy.enabled then switch, source = auto_switch_fields._overrides.effective(policy) end
        if switch and not seen[key] then
            seen[key] = true
            local prefix = auto_switch_prefix(entry)
            local active = auto_switch_evaluate(entry, switch, dict, now)
            sites[#sites + 1] = {
                tenant_scope_id = config.tenant_scope_id, site_id = config.site_id,
                policy_id = config.policy_id, policy_version = config.policy_version,
                active = active, sequence = dict:get(prefix .. "seq") or 0,
                since = dict:get(prefix .. "since") or 0,
                trigger_qps = dict:get(prefix .. "trigger_qps") or 0,
                trigger_5xx = dict:get(prefix .. "trigger_5xx") or 0,
                observed_qps = dict:get(prefix .. "observed_qps") or 0,
                observed_5xx = dict:get(prefix .. "observed_5xx") or 0,
                qps_total = switch.qps_total, qps_5xx = switch.qps_5xx, recover_seconds = switch.recover_seconds,
                source = source,
            }
        end
    end
    table.sort(sites, function(left, right)
        return left.tenant_scope_id .. left.site_id < right.tenant_scope_id .. right.site_id
    end)
    return { schema_version = AUTO_SWITCH_STATUS_SCHEMA, observed_at = math.floor(now), sites = sites }
end

-- ---------------------------------------------------------------------------
-- Trusted crawlers (FX47, CC API v6). A request whose User-Agent contains a
-- crawler's token is that crawler when the client is in its networks, or when
-- the client address forward-confirms to a hostname under one of its rDNS
-- suffixes: the PTR names of the address are looked up, and a name counts
-- only when its A / AAAA records contain the address again. The lookup never
-- runs in the request: a miss schedules it in a timer (at most
-- RDNS_LOOKUPS_PER_SECOND per node) and the request is treated as an ordinary
-- client until the result is cached. The cache holds the verified hostname
-- per address (a public fact, shared by every site and tenant); each policy
-- applies its own suffixes to it.
-- ---------------------------------------------------------------------------
local RDNS_HOST_TTL = 86400
local RDNS_NEGATIVE_TTL = 3600
local RDNS_PENDING_TTL = 10
local RDNS_LOOKUPS_PER_SECOND = 20
local RDNS_TIMEOUT_MS = 1000
local RDNS_MAX_PTR = 4

local rdns_nameserver_cache
local rdns_nameserver_until = 0

local function rdns_nameservers()
    local now = ngx.now()
    if rdns_nameserver_cache and now < rdns_nameserver_until then return rdns_nameserver_cache end
    local file = io.open("/etc/resolv.conf", "rb")
    if not file then return nil end
    local values = {}
    for line in file:lines() do
        local value = line:match("^%s*nameserver%s+([^%s#]+)")
        if value and parse_address(value) and #values < 3 then values[#values + 1] = value end
    end
    file:close()
    if #values == 0 then return nil end
    rdns_nameserver_cache, rdns_nameserver_until = values, now + 60
    return values
end

local function reverse_name(peer)
    local parts = {}
    if peer.family == 4 then
        for index = 4, 1, -1 do parts[#parts + 1] = tostring(peer.bytes[index]) end
        return table.concat(parts, ".") .. ".in-addr.arpa"
    end
    for index = 16, 1, -1 do
        local byte = peer.bytes[index]
        parts[#parts + 1] = string.format("%x", byte % 16)
        parts[#parts + 1] = string.format("%x", math.floor(byte / 16))
    end
    return table.concat(parts, ".") .. ".ip6.arpa"
end

-- A / AAAA answer text (lua-resty-dns prints AAAA as eight uncompressed
-- hex words, which parse_ipv6 reads) is the peer's address.
local function same_address(text, peer)
    local address = type(text) == "string" and parse_address(string.lower(text))
    if not address or address.family ~= peer.family then return false end
    for index, byte in ipairs(address.bytes) do
        if byte ~= peer.bytes[index] then return false end
    end
    return true
end

-- The forward-confirmed hostname of peer, "" when it has none; nil, err
-- when DNS could not answer (retried later).
local function rdns_lookup(peer)
    local ok, resolver_module = pcall(require, "resty.dns.resolver")
    local nameservers = rdns_nameservers()
    if not ok or not nameservers then return nil, "no DNS resolver" end
    local resolver, err = resolver_module:new({ nameservers = nameservers, retrans = 1, timeout = RDNS_TIMEOUT_MS })
    if not resolver then return nil, err end
    local answers, query_error = resolver:query(reverse_name(peer), { qtype = resolver_module.TYPE_PTR })
    if not answers then return nil, query_error end
    if answers.errcode and answers.errcode ~= 3 then return nil, "PTR rcode " .. tostring(answers.errcode) end
    local forward_type = peer.family == 4 and resolver_module.TYPE_A or resolver_module.TYPE_AAAA
    local checked = 0
    for _, answer in ipairs(answers) do
        local host = answer.type == resolver_module.TYPE_PTR and type(answer.ptrdname) == "string"
            and (string.lower(answer.ptrdname):gsub("%.$", "")) or nil
        if host and valid_domain(host) and checked < RDNS_MAX_PTR then
            checked = checked + 1
            local forward, forward_error = resolver:query(host, { qtype = forward_type })
            if not forward then return nil, forward_error end
            for _, record in ipairs(forward) do
                if record.type == forward_type and same_address(record.address, peer) then return host end
            end
        end
    end
    return ""
end

local function rdns_key(peer) return "ccv2:rdns:" .. peer.text end

local function rdns_verify(premature, text)
    if premature then return end
    local dict = ngx.shared[state_dict_name]
    local peer = parse_address(text)
    if not peer then return end
    local host, err = rdns_lookup(peer)
    if host == nil then
        -- Left pending until it expires: a failing resolver is not hammered.
        ngx.log(ngx.WARN, "cc v2 crawler rDNS lookup failed ip=", text, ": ", tostring(err))
        return
    end
    dict:set(rdns_key(peer), host, host == "" and RDNS_NEGATIVE_TTL or RDNS_HOST_TTL)
    dict:delete(rdns_key(peer) .. ":pending")
end

-- The cached verified hostname of peer ("" none); nil when unknown, after
-- scheduling a lookup.
local function rdns_host(peer, dict)
    local key = rdns_key(peer)
    local host = dict:get(key)
    if host ~= nil then return host end
    if not dict:add(key .. ":pending", true, RDNS_PENDING_TTL) then return nil end
    local count = dict:incr("ccv2:rdns:rate:" .. math.floor(ngx.now()), 1, 0, 2)
    if not count or count > RDNS_LOOKUPS_PER_SECOND then return nil end
    local ok, err = ngx.timer.at(0, rdns_verify, peer.text)
    if not ok then
        ngx.log(ngx.ERR, "cc v2 crawler rDNS timer: ", tostring(err))
        dict:delete(key .. ":pending")
    end
    return nil
end

local function host_under(host, suffix)
    return host == suffix or (#host > #suffix and host:sub(-#suffix - 1) == "." .. suffix)
end

-- The name of the trusted crawler this request is, or nil; second result
-- (only when nil): the request claims a crawler and the client is
-- definitely not it (every claimed crawler's networks miss, and its rDNS
-- suffixes miss a cached lookup result; a pending lookup is not definite).
local function trusted_crawler(policy, peer, dict)
    local crawlers = policy._crawlers
    if crawlers == nil then return nil end
    local user_agent = ngx.var.http_user_agent
    if type(user_agent) ~= "string" or user_agent == "" then return nil end
    local host
    local claims, pending = false, false
    for _, crawler in ipairs(crawlers) do
        local claimed = false
        for _, token in ipairs(crawler.tokens) do
            if user_agent:find(token, 1, true) then claimed = true break end
        end
        if claimed then
            for _, cidr in ipairs(crawler.networks) do
                if cidr_contains(cidr, peer) then return crawler.name end
            end
            local definite = true
            if #crawler.suffixes > 0 then
                if host == nil then host = rdns_host(peer, dict) end
                if host == nil then
                    definite, host = false, false
                elseif host ~= false and host ~= "" then
                    for _, suffix in ipairs(crawler.suffixes) do
                        if host_under(host, suffix) then return crawler.name end
                    end
                elseif host == false then
                    definite = false
                end
            end
            claims, pending = true, pending or not definite
        end
    end
    return nil, claims and not pending
end

function _M.init(settings)
    if entries ~= nil or type(settings) ~= "table" or type(settings.state_dict) ~= "string"
        or not ngx.shared[settings.state_dict] or type(settings.release_root) ~= "string"
        or settings.release_root:sub(1, 1) ~= "/" or settings.release_root:find("/%.[%.]?/")
        or type(settings.registry_json) ~= "string"
        or (settings.scoped_state ~= nil and settings.scoped_state ~= true) then
        error("invalid CC v2 engine settings")
    end
    state_dict_name = settings.state_dict
    if settings.node_id ~= nil then
        if settings.node_id ~= "" and not canonical_uuid(settings.node_id) then error("invalid CC v2 engine node_id") end
        auto_switch_fields._overrides.node_id = settings.node_id
    end
    scoped_state = settings.scoped_state == true
    release_root = settings.release_root:gsub("/+$", "")
    local decoded, registry_error = decode_registry(settings.registry_json)
    if not decoded then error(registry_error) end
    entries = decoded
    for _, entry in pairs(entries) do
        local _, policy_error = reload(entry, true)
        if policy_error then error("load CC v2 policy: " .. tostring(policy_error)) end
    end
end

local run

function _M.access(entry_id)
    local entry = entries and entries[entry_id]
    if not entry then
        ngx.log(ngx.ERR, "unknown CC v2 registry entry")
        return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    return run(entry, reload(entry, false))
end

-- ---------------------------------------------------------------------------
-- Dynamic routing (ADR 0009, D7): no registry, no release files. A site
-- object binds a port to a CC policy object by digest (edgesite.CCBinding);
-- the caller (dynroute cdnca_security) reads the verified bytes from the node
-- object directory. One entry per policy digest, cached per worker: the
-- digest is the identity, so an entry never needs invalidation, and the
-- per-client keys (binding_id / binding_revision / rule_id / client) are the
-- v7 ones, always under the tenant scope.
-- ---------------------------------------------------------------------------
local object_entries
local object_entry_items = 10000

-- configure readies the engine for access_object (init_by_lua). It does not
-- conflict with init: a node runs one of them.
function _M.configure(settings)
    if type(settings) ~= "table" or type(settings.state_dict) ~= "string" then
        error("invalid CC v2 engine settings")
    end
    if state_dict_name ~= nil and state_dict_name ~= settings.state_dict then
        error("CC v2 engine already configured with another state dictionary")
    end
    state_dict_name = settings.state_dict
    if settings.node_id ~= nil then
        if settings.node_id ~= "" and not canonical_uuid(settings.node_id) then error("invalid CC v2 engine node_id") end
        auto_switch_fields._overrides.node_id = settings.node_id
    end
    if settings.object_items ~= nil then
        if not integer(settings.object_items, 1, 10000000) then error("invalid CC v2 engine object_items") end
        object_entry_items = settings.object_items
    end
    object_entries = require("resty.lrucache").new(object_entry_items)
    if settings.variables ~= nil then
        if type(settings.variables) ~= "table" then error("invalid CC v2 engine variables") end
        for key in pairs(vars) do
            local name = settings.variables[key]
            if type(name) ~= "string" or not name:match("^[a-z][a-z0-9_]*$") then error("invalid CC v2 engine variables") end
            vars[key] = name
        end
    end
end

local function object_entry(digest, read)
    local entry = object_entries:get(digest)
    if entry then return entry end
    local raw, read_error = read(digest)
    if not raw then return nil, "read policy object: " .. tostring(read_error) end
    if #raw == 0 or #raw > MAX_POLICY_BYTES or sha256(raw) ~= digest then
        return nil, "policy object digest mismatch"
    end
    local value, decode_error = cjson.decode(raw)
    if type(value) ~= "table" then return nil, "decode policy: " .. tostring(decode_error) end
    -- The envelope's identity is the binding: validate_policy checks the
    -- policy against it, as against a registry entry.
    local config = {
        tenant_scope_id = value.tenant_scope_id, site_id = value.site_id, policy_id = value.policy_id,
        policy_version = value.policy_version, binding_id = value.binding_id,
        binding_revision = value.binding_revision, publication_id = value.publication_id,
    }
    if not canonical_uuid(config.tenant_scope_id) or not canonical_uuid(config.site_id) or not canonical_uuid(config.policy_id)
        or not integer(config.policy_version, 1, MAX_SAFE_INTEGER) or not canonical_uuid(config.binding_id)
        or not integer(config.binding_revision, 1, MAX_SAFE_INTEGER) or not canonical_uuid(config.publication_id) then
        return nil, "invalid policy envelope"
    end
    local policy, validation_error = validate_policy(value, config)
    if not policy then return nil, validation_error end
    entry = new_entry(config, "object:" .. digest)
    entry.scoped, entry.policy, entry.digest = true, policy, digest
    object_entries:set(digest, entry)
    return entry
end

-- Auto defense module overlay (ADR 0010 §7A.2, contract §4): the values in
-- force of cc.per_ip_requests, cc.ban_seconds and cc.auto_switch_qps that
-- the agent wrote into the auto defense gate for the site (a person's locked
-- value, or the automatic value while the CC module runs "智能自动"). Each
-- only tightens the policy, never relaxes it: a client IP fixed window
-- counts at most per_ip_requests per window, a ban (temporary ban, failed
-- challenge) lasts at least ban_seconds, the auto switch engages at most at
-- auto_switch_qps total requests per second. per_ip_requests applies to
-- client IP fixed windows only; cc.limit_permille scales every rate rule
-- (count_by keys and leaky buckets too). The derived policy is cached per entry and
-- overlay values; rule IDs (and so the per-client state) are unchanged.
-- bot.fake_crawler_block = 1 (ADR 0010 §7A.6): a request whose
-- User-Agent claims one of the policy's trusted crawlers but whose client is
-- definitely not it (outside its networks, and its rDNS result is cached and
-- not under its suffixes; a pending lookup is not definite) is refused 403.
local OVERLAY_REQUESTS, OVERLAY_BAN, OVERLAY_QPS = "cc.per_ip_requests", "cc.ban_seconds", "cc.auto_switch_qps"
local OVERLAY_FAKE_CRAWLER = "bot.fake_crawler_block"
-- cc.limit_permille: every rate rule (fixed windows of any
-- count_by key, leaky buckets) runs at this share of its own limits:
-- requests / requests_per_uri, rate_per_second / burst = ceil(limit x
-- permille / 1000), at least 1, never above the rule's own value.
local OVERLAY_PERMILLE = "cc.limit_permille"

local function scaled(value, permille)
    if not permille or value == nil then return value end
    local tightened = math.max(1, math.ceil(value * permille / 1000))
    if tightened < value then return tightened end
    return value
end

local function overlay_rules(rules, requests, ban, permille)
    local out = {}
    for index, rule in ipairs(rules) do
        local copy = rule
        local limit, action = rule.limit, rule.action
        local want = {}
        if limit.algorithm == "fixed_window" then
            want.requests = scaled(limit.requests, permille)
            if requests and rule._count_by == nil and want.requests > requests then want.requests = requests end
            want.requests_per_uri = scaled(limit.requests_per_uri, permille)
        elseif limit.algorithm == "leaky_bucket" then
            want.rate_per_second = scaled(limit.rate_per_second, permille)
            want.burst = scaled(limit.burst, permille)
        end
        local changed = false
        for key, value in pairs(want) do
            if value ~= limit[key] then changed = true end
        end
        if changed then
            copy = {}
            for key, value in pairs(rule) do copy[key] = value end
            copy.limit = {}
            for key, value in pairs(limit) do copy.limit[key] = value end
            for key, value in pairs(want) do copy.limit[key] = value end
        end
        if ban and action.ban_seconds ~= nil and action.ban_seconds < ban then
            if copy == rule then
                copy = {}
                for key, value in pairs(rule) do copy[key] = value end
            end
            copy.action = {}
            for key, value in pairs(action) do copy.action[key] = value end
            copy.action.ban_seconds = ban
        end
        out[index] = copy
    end
    return out
end

local function overlay_value(overlay, field, minimum, maximum)
    local value = overlay[field]
    if integer(value, minimum, maximum) then return value end
    return nil
end

local function overlay_policy(entry, overlay)
    local policy = entry.policy
    if type(overlay) ~= "table" or not policy.enabled then return policy end
    local requests = overlay_value(overlay, OVERLAY_REQUESTS, 1, 1000000)
    local ban = overlay_value(overlay, OVERLAY_BAN, 1, 86400)
    local qps = overlay_value(overlay, OVERLAY_QPS, 1, MAX_AUTO_SWITCH_QPS)
    local fake = overlay[OVERLAY_FAKE_CRAWLER] == 1 and policy._crawlers ~= nil
    local permille = overlay_value(overlay, OVERLAY_PERMILLE, 100, 999)
    if not requests and not ban and not qps and not fake and not permille then return policy end
    local key = table.concat({ requests or "", ban or "", qps or "", fake and "f" or "", permille or "" }, "|")
    local cached = entry.overlay
    if cached and cached.key == key then return cached.policy end
    local derived = {}
    for field, value in pairs(policy) do derived[field] = value end
    derived._fake_crawler_block = fake
    derived.rules = overlay_rules(policy.rules, requests, ban, permille)
    local switch = policy.auto_switch
    if switch then
        derived.auto_switch = {}
        for field, value in pairs(switch) do derived.auto_switch[field] = value end
        derived.auto_switch.rules = overlay_rules(switch.rules, requests, ban, permille)
        if qps and (switch.qps_total == 0 or switch.qps_total > qps) and #switch.rules > 0 then derived.auto_switch.qps_total = qps end
        if switch.rule_sets then
            derived.auto_switch.rule_sets = {}
            for index, set in ipairs(switch.rule_sets) do
                derived.auto_switch.rule_sets[index] = { name = set.name, rules = overlay_rules(set.rules, requests, ban, permille) }
            end
        end
        if switch.overrides and qps then
            derived.auto_switch.overrides = {}
            for index, override in ipairs(switch.overrides) do
                local copy = {}
                for field, value in pairs(override) do copy[field] = value end
                -- an off override stays off; the overlay only tightens
                if (override.qps_total > 0 or override.qps_5xx > 0) and (override.qps_total == 0 or override.qps_total > qps) then
                    copy.qps_total = qps
                end
                derived.auto_switch.overrides[index] = copy
            end
        end
    end
    entry.overlay = { key = key, policy = derived }
    return derived
end

-- access_object(digest, read[, overlay]): the CC decision for the request
-- with the policy object digest; read(digest) returns the object's verified
-- bytes; overlay is the site's auto defense overlay values (nil: none).
-- An unreadable or invalid object fails closed (503), as an unknown v7
-- registry entry does.
function _M.access_object(digest, read, overlay)
    if not state_dict_name then
        ngx.log(ngx.ERR, "CC v2 engine is not configured")
        return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    local entry, entry_error = object_entry(digest, read)
    if not entry then
        ngx.log(ngx.ERR, "CC v2 policy object unavailable: ", tostring(entry_error))
        return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    return run(entry, overlay_policy(entry, overlay))
end

-- A run that ends by an explicit pass (a trusted crawler, a passed
-- challenge, a matching log rule with flow stop) sets ngx.ctx.ccv2_stopped:
-- dynamic routing then runs no further CC policy for the request (rule pack
-- layering: the site's own exceptions come first).
run = function(entry, policy, reload_error, lkg_usable)
    if not policy then
        ngx.log(ngx.ERR, "CC v2 policy unavailable: ", tostring(reload_error))
        return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    if not policy.enabled then
        if reload_error and not lkg_usable then return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE) end
        return
    end
    local peer = parse_address(ngx.var.remote_addr)
    if not peer then
        ngx.log(ngx.ERR, "CC v2 peer address is invalid")
        return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    local dict = ngx.shared[state_dict_name]
    local now = ngx.now()
    local rules = policy.rules
    local switch = auto_switch_fields._overrides.effective(policy)
    if switch then
        local prefix = auto_switch_prefix(entry)
        ngx.ctx.ccv2_auto_switch_prefix = prefix
        dict:incr(prefix .. "req:" .. math.floor(now), 1, 0, AUTO_SWITCH_COUNTER_TTL)
        if auto_switch_evaluate(entry, switch, dict, now) then rules = switch.rules end
    end
    -- FX47: a verified search engine crawler skips every rule, ban and
    -- challenge (it still counts towards the auto switch's load).
    local crawler, fake_crawler = trusted_crawler(policy, peer, dict)
    if crawler then
        ngx.log(ngx.INFO, "cc v2 trusted crawler=", crawler, " ip=", peer.text)
        ngx.ctx.ccv2_stopped = true
        -- the auto defense bot classes never act on a verified crawler (ad-bot-cc)
        ngx.ctx.ccv2_crawler = crawler
        if reload_error and not lkg_usable then return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE) end
        return
    end
    if fake_crawler and policy._fake_crawler_block then
        pcall(function()
            ngx.var[vars.type] = "cc"
            ngx.var[vars.action] = "block"
            ngx.var[vars.severity] = "high"
            ngx.var[vars.rule_id] = "autodefense:bot.fake_crawler_block"
            ngx.var[vars.emit] = "1"
        end)
        return block_exit(ngx.HTTP_FORBIDDEN)
    end
    -- A ban of the ban list library (another node's
    -- automatic ban of the client on this site, or a manual one).
    if banlist == nil then
        local ok, module = pcall(require, "cdnca_banlist")
        banlist = ok and module or false
    end
    if banlist then
        local remaining = banlist.banned(entry.config.site_id, peer.text)
        if remaining then return banlist.deny(remaining, vars.block_page) end
    end
    if policy._has_challenge then
        if active_ban(dict, entry, peer, ban_key(entry, peer)) then
            acted(entry, "", "blocked", peer)
            return send_ban(entry, peer, dict)
        end
        if ngx.var.uri == GUARD_VERIFY then
            local verified = verify(entry, policy, peer, dict)
            -- another policy's page: no rule of this one runs on the
            -- engine's own verification URI
            if verified == DEFERRED then return end
            return verified
        end
    end
    for _, rule in ipairs(rules) do
        if static_rule_matches(rule, peer) then
            local count_matched, matcher_error, matcher_forcible = count_match(entry, rule, peer, dict, now)
            if count_matched == nil then
                record_capacity_failure(entry, matcher_forcible)
                return matcher_failure(matcher_error or "matcher_state_unavailable")
            end
            local key = scoped(entry, table.concat({ entry.config.binding_id, tostring(entry.config.binding_revision), rule.rule_id, peer.text }, ":"))
            -- counter: what the rule counts by (the client unless count_by);
            -- ban_ref: what a temporary ban applies to (the client unless
            -- action.target is count_key).
            local counter, ban_ref = key, key
            if count_matched and rule._count_by then
                counter = count_key(entry, rule, peer)
                if counter == nil then
                    count_matched = false
                    -- Only a missing fingerprint is ja4_unavailable (cc-metrics
                    -- contract); a missing CC v7 header / cookie / argument just
                    -- is not counted.
                    if rule._counts_ja4 and v7.ja4() == nil then
                        record_ja4_unavailable(entry, dict, rule)
                        stat(entry, rule.rule_id, "ja4_unavailable", peer)
                    end
                elseif rule.action.target == "count_key" then
                    ban_ref = counter
                end
            end
            if count_matched then stat(entry, rule.rule_id, "matched", peer) end
            if count_matched and rule.action.kind == "challenge" then
                if challenge_rule(entry, rule, peer, dict, now, key, counter) == "passed" then
                    ngx.ctx.ccv2_stopped = true
                    if reload_error and not lkg_usable then return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE) end
                    return
                end
            elseif count_matched then
                -- A count_key ban covers every client of the key: a release of
                -- one client does not lift it.
                if rule.action.kind == "temporary_ban" and ban_ref == key and dict:get("ban:" .. ban_ref) then
                    if active_ban(dict, entry, peer, "ban:" .. ban_ref) then
                        acted(entry, rule.rule_id, "blocked", peer)
                        return reject429(rule)
                    end
                    -- Released: the client starts a fresh window (its count
                    -- before the release would ban it again at once).
                    reset_window(dict, counter, rule.limit, now)
                elseif rule.action.kind == "temporary_ban" and ban_ref ~= key and dict:get("ban:" .. ban_ref) then
                    acted(entry, rule.rule_id, "blocked", peer)
                    return reject429(rule)
                end
                local exceeded, state_error, forcible
                if rule.limit.algorithm == "fixed_window" then
                    exceeded, state_error, forcible = fixed_window(dict, "fixed:" .. counter, rule.limit, now)
                else
                    exceeded, state_error, forcible = leaky_bucket(dict, counter, rule.limit, now)
                end
                if exceeded == nil then
                    local terminal = state_failure(entry, rule, state_error, forcible)
                    if terminal then return terminal end
                elseif exceeded then
                    stat(entry, rule.rule_id, "triggered", peer)
                    if rule.action.kind == "log" then
                        ngx.log(ngx.NOTICE, "cc v2 rate limit observed rule=", rule.rule_id)
                        if rule.flow == "stop" then
                            ngx.ctx.ccv2_stopped = true
                            if reload_error and not lkg_usable then return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE) end
                            return
                        end
                    else
                        if rule.action.kind == "temporary_ban" then
                            local ok, ban_error, ban_forcible = dict:set("ban:" .. ban_ref, math.floor(ngx.now()), rule.action.ban_seconds)
                            if not ok or ban_forcible then return state_failure(entry, rule, ban_error or "shared dict eviction", ban_forcible) end
                            emit_temporary_ban(rule)
                            if ban_ref == key then queue_kernel_ban(entry, rule, peer) end
                        end
                        stat(entry, rule.rule_id, "blocked", peer)
                        -- the ban's own request is its temporary_ban line
                        return reject429(rule.action.kind ~= "temporary_ban" and rule or nil)
                    end
                end
            end
        end
    end
    if reload_error and not lkg_usable then return block_exit(ngx.HTTP_SERVICE_UNAVAILABLE) end
end

function _M.metrics(entry_id)
    local entry = entries and entries[entry_id]
    local node_id = ngx.var.cdnca_node_id
    if not entry or not canonical_uuid(node_id) then return nil, "metrics identity unavailable" end
    local dict = ngx.shared[state_dict_name]
    local capacity = metric_counter(dict, entry.metrics_capacity_key)
    local evictions = metric_counter(dict, entry.metrics_eviction_key)
    local ja4_unavailable = metric_counter(dict, entry.metrics_ja4_unavailable_key)
    if capacity == nil or evictions == nil or ja4_unavailable == nil then return nil, "metrics state unavailable" end
    return {
        schema_version = METRICS_SCHEMA, node_id = node_id,
        tenant_scope_id = entry.config.tenant_scope_id, site_id = entry.config.site_id,
        policy_id = entry.config.policy_id, policy_version = entry.config.policy_version,
        capacity_failures = capacity, shared_dict_evictions = evictions,
        ja4_unavailable = ja4_unavailable,
        degraded = dict:get(entry.metrics_degraded_key) == true,
    }
end

function _M.log()
    if ngx.ctx.ccv2_404_logged then return end
    ngx.ctx.ccv2_404_logged = true
    -- Auto switch 5xx: only responses of the origin (or of the proxy for it);
    -- the engine's own 503 pages must not keep the switch engaged. Counted in
    -- the second the response completed (an origin timeout ends long after
    -- its access second was evaluated); unlike the SEC-11 404 window this is
    -- not a per-client access-phase bucket.
    local switch_prefix = ngx.ctx.ccv2_auto_switch_prefix
    local status = tonumber(ngx.status) or 0
    if switch_prefix and status >= 500 and status <= 599 and (ngx.var.upstream_status or "") ~= "" then
        ngx.shared[state_dict_name]:incr(switch_prefix .. "5xx:" .. ngx.time(), 1, 0, AUTO_SWITCH_COUNTER_TTL)
    end
    local observations = ngx.ctx.ccv2_404_observations
    if tonumber(ngx.status) ~= 404 or type(observations) ~= "table" then return end
    local dict = ngx.shared[state_dict_name]
    for prefix, observation in pairs(observations) do
        local bucket = observation.bucket
        local ttl = observation.ttl
        local _, state_error, forcible = with_matcher_lock("404:" .. bucket, function()
            local count_key = "404-count:" .. bucket
            local count = dict:get(count_key) or 0
            if not integer(count, 0, observation.threshold) then return nil, "404 count state is invalid" end
            if count >= observation.threshold then return count end
            local next_count, count_error, increment_forcible = dict:incr(count_key, 1, 0, ttl)
            if not next_count or next_count > observation.threshold or increment_forcible then
                return nil, count_error or "shared dict eviction", increment_forcible
            end
            return next_count
        end)
        if state_error then
            record_capacity_failure(observation.entry, forcible)
            dict:set("stat-failed:" .. prefix, true, ttl)
            ngx.log(ngx.ERR, "cc v2 SEC-11 completed-response write failed: matcher_state_unavailable")
        end
    end
end

return _M
