local cjson = require("cjson.safe")

local _M = {}
local SCHEMA = "cdnca.edge.firewall-action/v1"
local lkg = {}

local POLICY_KEYS = {
    schema_version = true, policy_version = true, normal_action = true, escalated_action = true,
    tenant_id = true, site_id = true, policy_id = true, expected_active_policy_version = true,
    engage_threshold = true, recover_threshold = true, recovery_windows = true,
    block_networks = true, trusted_proxies = true, trusted_crawlers = true, return_page = true,
}
local RETURN_PAGE_KEYS = { status = true, content_type = true, body = true }
local CRAWLER_KEYS = { name = true, networks = true, user_agent_prefixes = true }

local function only_keys(value, allowed)
    for key, _ in pairs(value) do
        if not allowed[key] then return false end
    end
    return true
end

local function integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value)
        and value >= minimum and value <= maximum
end

local function canonical_uuid(value)
    if type(value) ~= "string" or #value ~= 36
        or value:sub(9, 9) ~= "-" or value:sub(14, 14) ~= "-"
        or value:sub(19, 19) ~= "-" or value:sub(24, 24) ~= "-" then return false end
    local compact = value:gsub("-", "")
    return #compact == 32 and not compact:find("[^0-9a-f]")
end

local function array(value, maximum)
    if type(value) ~= "table" then return false end
    local count = 0
    local maximum_index = 0
    for key, _ in pairs(value) do
        if type(key) ~= "number" or key ~= math.floor(key) or key < 1 then return false end
        count = count + 1
        if key > maximum_index then maximum_index = key end
    end
    return count <= maximum and maximum_index == count
end

local function text(value, maximum)
    return type(value) == "string" and #value > 0 and #value <= maximum
        and not value:find("[%z\1-\8\11\12\14-\31\127]")
end

local function valid_networks(values)
    if not array(values, 10000) then return false end
    for _, value in ipairs(values) do
        if not text(value, 64) or value:find("/0+$") then return false end
    end
    return true
end

local function valid_policy(policy)
    if type(policy) ~= "table" or not only_keys(policy, POLICY_KEYS) or policy.schema_version ~= SCHEMA
        or not integer(policy.policy_version, 1, 9007199254740991)
        or not canonical_uuid(policy.tenant_id) or not canonical_uuid(policy.site_id)
        or not canonical_uuid(policy.policy_id)
        or not integer(policy.expected_active_policy_version, 0, 9007199254740991)
        or (policy.normal_action ~= "disconnect" and policy.normal_action ~= "return_page")
        or policy.escalated_action ~= "nftables"
        or not integer(policy.engage_threshold, 1, 9007199254740991)
        or not integer(policy.recover_threshold, 0, policy.engage_threshold - 1)
        or not integer(policy.recovery_windows, 1, 60)
        or not valid_networks(policy.block_networks)
        or #policy.block_networks == 0
        or not valid_networks(policy.trusted_proxies)
        or not array(policy.trusted_crawlers, 64)
        or type(policy.return_page) ~= "table" or not only_keys(policy.return_page, RETURN_PAGE_KEYS)
        or not integer(policy.return_page.status, 400, 599)
        or (policy.return_page.content_type ~= "text/html; charset=utf-8"
            and policy.return_page.content_type ~= "text/plain; charset=utf-8")
        or not text(policy.return_page.body, 16384) then
        return nil
    end
    if policy.return_page.body:find("[<>]") then return nil end
    for _, crawler in ipairs(policy.trusted_crawlers) do
        if type(crawler) ~= "table" or not only_keys(crawler, CRAWLER_KEYS) or not text(crawler.name, 64)
            or not valid_networks(crawler.networks)
            or not array(crawler.user_agent_prefixes, 32)
            or #crawler.networks == 0 or #crawler.user_agent_prefixes == 0 then return nil end
        for _, prefix in ipairs(crawler.user_agent_prefixes) do
            if not text(prefix, 128) or prefix:find("*", 1, true) or prefix:find("?", 1, true) then return nil end
        end
    end
    return policy
end

local function read_candidate(path)
    local file = io.open(path, "rb")
    if not file then return nil end
    local bytes = file:read(262145)
    file:close()
    if not bytes or #bytes > 262144 then return nil end
    return bytes
end

local function build_matcher(networks)
    local ok, ipmatcher = pcall(require, "resty.ipmatcher")
    if not ok then return nil end
    local built_ok, matcher = pcall(ipmatcher.new, networks)
    if not built_ok then return nil end
    return matcher
end

local function compile_policy(policy)
    local compiled = {
        policy = policy,
        block_networks = build_matcher(policy.block_networks),
        trusted_proxy = build_matcher(policy.trusted_proxies),
        crawlers = {},
    }
    if not compiled.block_networks then return nil end
    if #policy.trusted_proxies > 0 and not compiled.trusted_proxy then return nil end
    for _, crawler in ipairs(policy.trusted_crawlers) do
        local matcher = build_matcher(crawler.networks)
        if not matcher then return nil end
        compiled.crawlers[#compiled.crawlers + 1] = {
            trusted_crawler = crawler.name,
            matcher = matcher,
            prefixes = crawler.user_agent_prefixes,
        }
    end
    return compiled
end

local function skip_space(bytes, index)
    while bytes:sub(index, index):find("%s") do index = index + 1 end
    return index
end

local function scan_json_string(bytes, index)
    if bytes:sub(index, index) ~= '"' then return nil end
    local start = index
    index = index + 1
    while index <= #bytes do
        local character = bytes:sub(index, index)
        if character == '"' then
            local value = cjson.decode(bytes:sub(start, index))
            if type(value) ~= "string" then return nil end
            return index + 1, value
        end
        if character == "\\" then
            if bytes:sub(index + 1, index + 1) == "u" then index = index + 6 else index = index + 2 end
        else
            if character:byte() < 32 then return nil end
            index = index + 1
        end
    end
    return nil
end

local scan_json_value

local function scan_json_object(bytes, index)
    local seen = {}
    index = skip_space(bytes, index + 1)
    if bytes:sub(index, index) == "}" then return index + 1 end
    while index <= #bytes do
        local next_index, key = scan_json_string(bytes, index)
        if not next_index or seen[key] then return nil end
        seen[key] = true
        index = skip_space(bytes, next_index)
        if bytes:sub(index, index) ~= ":" then return nil end
        index = scan_json_value(bytes, skip_space(bytes, index + 1))
        if not index then return nil end
        index = skip_space(bytes, index)
        local separator = bytes:sub(index, index)
        if separator == "}" then return index + 1 end
        if separator ~= "," then return nil end
        index = skip_space(bytes, index + 1)
    end
    return nil
end

local function scan_json_array(bytes, index)
    index = skip_space(bytes, index + 1)
    if bytes:sub(index, index) == "]" then return index + 1 end
    while index <= #bytes do
        index = scan_json_value(bytes, index)
        if not index then return nil end
        index = skip_space(bytes, index)
        local separator = bytes:sub(index, index)
        if separator == "]" then return index + 1 end
        if separator ~= "," then return nil end
        index = skip_space(bytes, index + 1)
    end
    return nil
end

scan_json_value = function(bytes, index)
    local character = bytes:sub(index, index)
    if character == "{" then return scan_json_object(bytes, index) end
    if character == "[" then return scan_json_array(bytes, index) end
    if character == '"' then return scan_json_string(bytes, index) end
    local start = index
    while index <= #bytes and not bytes:sub(index, index):find("[%s,%]}]") do index = index + 1 end
    if index == start then return nil end
    return index
end

local function unique_json_keys(bytes)
    local index = scan_json_value(bytes, skip_space(bytes, 1))
    return index ~= nil and skip_space(bytes, index) > #bytes
end

local function load_policy(path)
    local bytes = read_candidate(path)
    local policy = bytes and unique_json_keys(bytes) and valid_policy(cjson.decode(bytes)) or nil
    local compiled = policy and compile_policy(policy) or nil
    local previous = lkg[path]
    if not compiled or (previous and policy.policy_version < previous.policy.policy_version) then
        if previous then return previous, "candidate_rejected_lkg" end
        return nil, "candidate_rejected"
    end
    if previous and policy.policy_version == previous.policy.policy_version then
        if bytes == previous.bytes then return previous end
        return previous, "candidate_rejected_lkg"
    end
    compiled.bytes = bytes
    lkg[path] = compiled
    return compiled
end

-- Dynamic routing (ADR 0009, D7): the policy is a content-addressed object
-- (edgesite Ref kind firewall_action) read through read(digest); compiled
-- once per worker per digest.
local objects = require("resty.lrucache").new(10000)

-- configure_objects(items): the per-worker compiled policy cache size.
function _M.configure_objects(items)
    if not integer(items, 1, 10000000) then error("invalid firewall action object cache size") end
    objects = require("resty.lrucache").new(items)
end

local function load_object(digest, read)
    local compiled = objects:get(digest)
    if compiled then return compiled end
    local bytes = read(digest)
    if type(bytes) ~= "string" or #bytes == 0 or #bytes > 262144 then return nil end
    local hash = require("resty.sha256"):new()
    hash:update(bytes)
    if require("resty.string").to_hex(hash:final()) ~= digest then return nil end
    local policy = unique_json_keys(bytes) and valid_policy(cjson.decode(bytes)) or nil
    compiled = policy and compile_policy(policy) or nil
    if not compiled then return nil end
    objects:set(digest, compiled)
    return compiled
end

local function split_forwarded(value)
    local result = {}
    if type(value) ~= "string" then return result end
    for item in value:gmatch("[^,]+") do
        item = item:match("^%s*(.-)%s*$")
        if item == "" or item:find("[%s%[%]]") then return {} end
        result[#result + 1] = item
    end
    return result
end

local function matches(matcher, address)
    if not matcher then return false end
    local ok, matched = pcall(matcher.match, matcher, address)
    return ok and matched == true
end

local function resolve_client(compiled)
    local peer = ngx.var.remote_addr
    if not matches(compiled.trusted_proxy, peer) then return peer end
    local current = peer
    local forwarded = split_forwarded(ngx.var.http_x_forwarded_for)
    for index = #forwarded, 1, -1 do
        if not matches(compiled.trusted_proxy, current) then break end
        current = forwarded[index]
    end
    return current
end

local function crawler_trusted(compiled, client)
    local user_agent = ngx.var.http_user_agent or ""
    for _, crawler in ipairs(compiled.crawlers) do
        if matches(crawler.matcher, client) then
            for _, prefix in ipairs(crawler.prefixes) do
                if user_agent:sub(1, #prefix) == prefix then return true end
            end
        end
    end
    return false
end

-- FX45 escalation state. The load is the number of requests this site's
-- action blocked (block_networks clients) in the previous second, counted on
-- this node. The state is evaluated once per second, by the first request or
-- status poll of that second: engaged when a second reached
-- engage_threshold, recovered after recovery_windows evaluated seconds at or
-- below recover_threshold. The agent polls status() and mirrors the state
-- into nftables (firewall.ActionEngine.Mirror); once the kernel drops the
-- blocked networks their requests stop counting, so the site recovers back
-- to the per-request action when the attack ends. State belongs to one
-- tenant's site policy: sites of different tenants on one node often share a
-- policy version number.
local COUNTER_TTL = 5

local function state_prefix(policy)
    return table.concat({ "firewall-action", policy.tenant_id, policy.site_id, policy.policy_id,
        tostring(policy.policy_version), "" }, ":")
end

local function evaluate(policy, dictionary, now)
    local prefix = state_prefix(policy)
    local second = math.floor(now)
    local active = dictionary:get(prefix .. "active") == 1
    if not dictionary:add(prefix .. "eval:" .. second, true, COUNTER_TTL) then return active end
    local load = dictionary:get(prefix .. "blocked:" .. (second - 1)) or 0
    dictionary:set(prefix .. "load", load)
    if not active then
        if load < policy.engage_threshold then return false end
        dictionary:set(prefix .. "active", 1)
        dictionary:set(prefix .. "recovery", 0)
        dictionary:set(prefix .. "since", second - 1)
        dictionary:incr(prefix .. "seq", 1, 0)
        ngx.log(ngx.WARN, "firewall action engaged site=", policy.site_id, " load=", load)
        return true
    end
    if load > policy.recover_threshold then
        dictionary:set(prefix .. "recovery", 0)
        return true
    end
    local recovery = (dictionary:get(prefix .. "recovery") or 0) + 1
    if recovery < policy.recovery_windows then
        dictionary:set(prefix .. "recovery", recovery)
        return true
    end
    dictionary:set(prefix .. "active", 0)
    dictionary:set(prefix .. "recovery", 0)
    dictionary:set(prefix .. "since", second - 1)
    dictionary:incr(prefix .. "seq", 1, 0)
    ngx.log(ngx.WARN, "firewall action recovered site=", policy.site_id)
    return false
end

local function escape_html(value)
    return (value:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
        :gsub('"', "&quot;"):gsub("'", "&#39;"))
end

local function execute(policy, action)
    ngx.header["Cache-Control"] = "no-store"
    if action == "disconnect" then return ngx.exit(444) end
    ngx.status = policy.return_page.status
    ngx.header["Content-Type"] = policy.return_page.content_type
    if policy.return_page.content_type == "text/html; charset=utf-8" then
        ngx.print("<!doctype html><html><head><meta charset=\"utf-8\"><title>Request blocked</title></head><body><main>"
            .. escape_html(policy.return_page.body) .. "</main></body></html>")
    else
        ngx.print(policy.return_page.body)
    end
    return ngx.exit(policy.return_page.status)
end

local run

-- handle runs the site's action: a block_networks client gets the normal
-- action, or a disconnect while the site is escalated (its networks are then
-- dropped by nftables, so only requests racing the kernel rules arrive).
-- Every other client passes, escalated or not.
function _M.handle(path)
    local compiled, reload_reason = load_policy(path)
    if not compiled then return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE) end
    return run(compiled, reload_reason)
end

-- handle_object(digest, read, site_id): handle for a policy object; one whose
-- bytes, digest or site do not hold fails closed (503).
function _M.handle_object(digest, read, site_id)
    local compiled = load_object(digest, read)
    if not compiled or compiled.policy.site_id ~= site_id then
        ngx.log(ngx.ERR, "firewall action object rejected")
        return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    return run(compiled)
end

run = function(compiled, reload_reason)
    local client = resolve_client(compiled)
    if crawler_trusted(compiled, client) then return nil, "trusted_crawler" end
    local dictionary = ngx.shared.cdnca_firewall_action
    if not dictionary then return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE) end
    local policy = compiled.policy
    local active = evaluate(policy, dictionary, ngx.now())
    if not matches(compiled.block_networks, client) then
        return nil, "client_not_blocked", active
    end
    dictionary:incr(state_prefix(policy) .. "blocked:" .. ngx.time(), 1, 0, COUNTER_TTL)
    if reload_reason == "candidate_rejected_lkg" then
        ngx.log(ngx.ERR, "firewall action candidate_rejected_lkg")
    end
    if active then
        execute(policy, "disconnect")
        return nil, "escalated", true
    end
    execute(policy, policy.normal_action)
    return nil, "blocked", false
end

local STATUS_SCHEMA = "cdnca.edge.firewall-action-status/v1"

-- status_objects reports every site of sites ({ { site_id, sha256 } }, the
-- running sites' firewall_action references, posted by the agent) whose
-- policy object loads through read(digest), and evaluates it, so an idle site
-- still recovers. A site whose policy cannot load is left out: the agent
-- keeps its nftables state rather than recover what it cannot see.
function _M.status_objects(sites, read)
    local dictionary = ngx.shared.cdnca_firewall_action
    local now = ngx.now()
    local result = {}
    for _, site in ipairs(dictionary and sites or {}) do
        local compiled = type(site) == "table" and type(site.sha256) == "string" and #site.sha256 == 64
            and load_object(site.sha256, read) or nil
        if compiled and compiled.policy.site_id == site.site_id then
            local policy = compiled.policy
            local prefix = state_prefix(policy)
            local active = evaluate(policy, dictionary, now)
            result[#result + 1] = {
                tenant_id = policy.tenant_id, site_id = policy.site_id, policy_id = policy.policy_id,
                policy_version = policy.policy_version, active = active,
                sequence = dictionary:get(prefix .. "seq") or 0, since = dictionary:get(prefix .. "since") or 0,
                load = dictionary:get(prefix .. "load") or 0,
            }
        end
    end
    return { schema_version = STATUS_SCHEMA, observed_at = math.floor(now), sites = result }
end

return _M
