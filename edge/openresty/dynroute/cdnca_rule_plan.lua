-- cdnca dynamic routing: the rule plan (cdnca.edge.rule-plan/v1, the D6
-- interpreter's input) of a site object's security.rules (edgesite.RulePlan:
-- the site's bound ACL/WAF policies, rules in edgeconfig.WAFRule form). It is
-- edgeconfig.CompileSecurityRulePlan in Lua - same segments, same condition
-- order, same spec strings - so a site object decides every request as the
-- v7 rewrite_by_lua_block of the same policies does
-- (libs/edgeconfig dynroute_rule_plan_integration_test.go compares the two).
-- Pure: no ngx; LuaJIT's bit and cjson only.
local cjson = require "cjson.safe"
local bit = require "bit"

local type, tonumber, ipairs = type, tonumber, ipairs

local _M = { _VERSION = "1" }
local SCHEMA = "cdnca.edge.rule-plan/v1"

-- days_from_civil: days since 1970-01-01 of a proleptic Gregorian date.
local function days_from_civil(y, m, d)
    if m <= 2 then y = y - 1 end
    local era = math.floor(y / 400)
    local yoe = y - era * 400
    local mp = (m + 9) % 12
    local doy = math.floor((153 * mp + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    return era * 146097 + doe - 719468
end

-- RFC 3339 UTC "2006-01-02T15:04:05Z" (the normalized form) -> unix seconds.
local function unix_seconds(value)
    local y, mo, d, h, mi, s = string.match(value or "", "^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)Z$")
    if not y then return nil end
    return days_from_civil(tonumber(y), tonumber(mo), tonumber(d)) * 86400 + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(s)
end

-- ip_intel spec (edgeconfig.IPIntelConditionSpec); tag names -> library bits.
local IPINTEL_TAG_BITS = {
    ["carrier:cn-telecom"] = 0, ["carrier:cn-unicom"] = 1, ["carrier:cn-mobile"] = 2, ["carrier:cn-cernet"] = 3,
    ["carrier:cn-cstnet"] = 4, ["carrier:cn-drpeng"] = 5, ["carrier:cn-cbn"] = 6,
    ["idc:cn"] = 16, ["idc:global"] = 17,
}

local function ipintel_spec(condition)
    local operator = condition.negate and "!=" or "="
    local list
    if condition.field == "tag" then
        -- Go: fmt.Sprintf("%016x", mask) of a uint64 bit mask.
        local hi, lo = 0, 0
        for _, value in ipairs(condition.values) do
            local position = IPINTEL_TAG_BITS[value]
            if position == nil then return nil end
            if position >= 32 then
                hi = bit.bor(hi, bit.lshift(1, position - 32))
            else
                lo = bit.bor(lo, bit.lshift(1, position))
            end
        end
        list = bit.tohex(hi, 8) .. bit.tohex(lo, 8)
    else
        list = table.concat(condition.values, ",")
    end
    return condition.field .. operator .. list
end

-- inspect clause JSON as Go's json.Marshal(WAFInspect) writes it: field
-- order target, key (omitempty), operator, values, filters (omitempty),
-- body_overflow (omitempty); strings escaped as Go.
local function go_json_string(value)
    local encoded = cjson.encode(value)
    -- cjson escapes "/" as "\/"; Go does not. Go escapes <, >, & (HTML safe).
    encoded = encoded:gsub("\\/", "/")
    encoded = encoded:gsub("<", "\\u003c"):gsub(">", "\\u003e"):gsub("&", "\\u0026")
    return encoded
end

local function inspect_json(inspect)
    local parts = { '{"target":', go_json_string(inspect.target) }
    if inspect.key and inspect.key ~= "" then
        parts[#parts + 1] = ',"key":'
        parts[#parts + 1] = go_json_string(inspect.key)
    end
    parts[#parts + 1] = ',"operator":'
    parts[#parts + 1] = go_json_string(inspect.operator)
    parts[#parts + 1] = ',"values":['
    for index, value in ipairs(inspect.values or {}) do
        if index > 1 then parts[#parts + 1] = "," end
        parts[#parts + 1] = go_json_string(value)
    end
    parts[#parts + 1] = "]"
    if type(inspect.filters) == "table" and #inspect.filters > 0 then
        parts[#parts + 1] = ',"filters":['
        for index, value in ipairs(inspect.filters) do
            if index > 1 then parts[#parts + 1] = "," end
            parts[#parts + 1] = go_json_string(value)
        end
        parts[#parts + 1] = "]"
    end
    if inspect.body_overflow and inspect.body_overflow ~= "" then
        parts[#parts + 1] = ',"body_overflow":'
        parts[#parts + 1] = go_json_string(inspect.body_overflow)
    end
    parts[#parts + 1] = "}"
    return table.concat(parts)
end

-- ip_list spec as Go's IPListConditionSpec writes it: {"id","revision",
-- "negate","cidrs"}.
local function ip_list_spec(list)
    local parts = { '{"id":', go_json_string(list.list_id), ',"revision":', string.format("%d", tonumber(list.revision) or 0),
        ',"negate":', list.negate == true and "true" or "false", ',"cidrs":[' }
    for index, cidr in ipairs(list.cidrs or {}) do
        if index > 1 then parts[#parts + 1] = "," end
        parts[#parts + 1] = go_json_string(cidr)
    end
    parts[#parts + 1] = "]}"
    return table.concat(parts)
end

-- WAF v2 (ge-waf): a policy with observe mode, auto block or challenge / ban
-- rules gets a segment action spec (edgeconfig SecurityPolicyUsesWAFActions).
local function uses_waf_actions(policy)
    if (policy.mode and policy.mode ~= "") or type(policy.auto_block) == "table" then return true end
    for _, rule in ipairs(policy.rules or {}) do
        if rule.action == "challenge" or rule.action == "ban" then return true end
    end
    return false
end

local function go_int(value)
    return string.format("%d", tonumber(value) or 0)
end

-- action_spec is edgeconfig.WAFActionSpecJSON byte for byte: scope, kind,
-- policy_id, mode (omitempty), auto_block (omitempty), telemetry, rules (rule
-- ID -> action_config, keys sorted as Go writes a map, zero fields omitted).
local function action_spec(site_id, policy, telemetry)
    local scope = "site"
    if type(site_id) == "string" and site_id ~= "" then scope = "site:" .. site_id end
    local parts = { '{"scope":', go_json_string(scope), ',"kind":', go_json_string(policy.kind),
        ',"policy_id":', go_json_string(policy.policy_id) }
    if policy.mode and policy.mode ~= "" then
        parts[#parts + 1] = ',"mode":'
        parts[#parts + 1] = go_json_string(policy.mode)
    end
    local auto = policy.auto_block
    if type(auto) == "table" then
        parts[#parts + 1] = ',"auto_block":{"window_seconds":' .. go_int(auto.window_seconds) ..
            ',"hit_threshold":' .. go_int(auto.hit_threshold) .. ',"block_seconds":' .. go_int(auto.block_seconds) .. "}"
    end
    parts[#parts + 1] = ',"telemetry":' .. (telemetry and "true" or "false") .. ',"rules":{'
    local configs, ids = {}, {}
    for _, rule in ipairs(policy.rules or {}) do
        if type(rule.action_config) == "table" and type(rule.rule_id) == "string" then
            if configs[rule.rule_id] == nil then ids[#ids + 1] = rule.rule_id end
            configs[rule.rule_id] = rule.action_config
        end
    end
    table.sort(ids)
    for index, id in ipairs(ids) do
        local config, fields = configs[id], {}
        for _, name in ipairs({ "ban_seconds", "pass_seconds", "pow_bits" }) do
            local value = tonumber(config[name])
            if value and value ~= 0 then fields[#fields + 1] = '"' .. name .. '":' .. go_int(value) end
        end
        if index > 1 then parts[#parts + 1] = "," end
        parts[#parts + 1] = go_json_string(id) .. ":{" .. table.concat(fields, ",") .. "}"
    end
    parts[#parts + 1] = "}}"
    return table.concat(parts)
end

local function rule_conditions(rule)
    local match = rule.match or {}
    local conditions = {}
    local function add(condition) conditions[#conditions + 1] = condition end
    if rule.expires_at and rule.expires_at ~= "" then
        local seconds = unix_seconds(rule.expires_at)
        if not seconds then return nil, "expires_at" end
        add({ op = "expires_before", number = seconds })
    end
    if match.host and match.host ~= "" then add({ op = "host_eq", value = match.host }) end
    if match.port and match.port ~= 0 then add({ op = "port_eq", number = match.port }) end
    if match.method and match.method ~= "" then add({ op = "method_eq", value = match.method }) end
    if type(match.path) == "table" then
        local op = "path_prefix"
        if match.path.kind == "exact" then op = "path_exact" elseif match.path.kind == "raw_prefix" then op = "path_raw_prefix" end
        add({ op = op, value = match.path.value })
    end
    if type(match.header) == "table" then
        if match.header.kind == "exists" then
            add({ op = "header_exists", name = match.header.name })
        else
            add({ op = "header_eq", name = match.header.name, value = match.header.value })
        end
    end
    if match.source_cidr and match.source_cidr ~= "" then add({ op = "source_cidr", value = match.source_cidr }) end
    if type(match.ja4) == "table" then add({ op = "ja4_in", values = match.ja4 }) end
    if type(match.not_ja4) == "table" then add({ op = "ja4_not_in", values = match.not_ja4 }) end
    for _, condition in ipairs(match.ip_intel or {}) do
        local spec = ipintel_spec(condition)
        if not spec then return nil, "ip_intel" end
        add({ op = "ip_intel", value = spec })
    end
    for _, list in ipairs(match.ip_lists or {}) do add({ op = "ip_list", value = ip_list_spec(list) }) end
    for _, inspect in ipairs(match.inspect or {}) do add({ op = "inspect", value = inspect_json(inspect) }) end
    return conditions
end

-- unix_seconds(text) -> the unix seconds of a normalized expires_at | nil
-- (cdnca_managed_waf: a temporary allow's CRS exemption, SF-E01).
_M.unix_seconds = unix_seconds

-- plan(site_rules, telemetry, site_id): the rule plan table of a site
-- object's security.rules, as CompileSiteSecurityRulePlan(site_id, ...)
-- builds it (site_id scopes WAF v2 bans).
function _M.plan(rules, telemetry, site_id)
    local plan = { schema = SCHEMA, header_overflow = "none", telemetry = telemetry == true, segments = {} }
    for index, policy in ipairs(rules.policies or {}) do
        local segment = { kind = policy.kind, policy_id = policy.policy_id, policy_version = policy.policy_version,
            binding_revision = policy.binding_revision, runtime_sha256 = policy.runtime_sha256, enabled = policy.enabled,
            default_action = policy.default_action, default_rule_id = policy.policy_id .. ":default", rules = {} }
        if uses_waf_actions(policy) then segment.action = action_spec(site_id, policy, telemetry == true) end
        for _, rule in ipairs(policy.rules or {}) do
            if type(rule.match) == "table" and type(rule.match.header) == "table" then
                plan.header_overflow = rules.header_overflow == "block" and "block" or "no_match"
            end
            if policy.enabled then
                local conditions, problem = rule_conditions(rule)
                if not conditions then return nil, "rule " .. tostring(rule.rule_id) .. ": " .. problem end
                segment.rules[#segment.rules + 1] = { rule_id = rule.rule_id, action = rule.action, flow = rule.flow,
                    conditions = conditions }
            end
        end
        plan.segments[index] = segment
    end
    return plan
end

return _M
