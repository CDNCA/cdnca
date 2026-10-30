local cjson = require("cjson.safe")

local _M = {}
local SCHEMA = "cdnca.edge.l4/v2"
local MAX_SAFE_INTEGER = 9007199254740991
local MAX_CONFIG_BYTES = 1048576
local MAX_LISTENERS = 256
local MAX_REGIONS = 256
local MAX_CIDRS = 4096
local MAX_TRUSTED_PROXIES = 64
local lkg = {}

local TOP_KEYS = {
    schema_version = true, version_id = true, revision = true, listeners = true,
}
local LISTENER_KEYS = {
    id = true, tenant_id = true, site_id = true, stream_id = true, geo = true, resource_revision = true,
    guard = true,
}
local GEO_KEYS = {
    enabled = true, tenant_id = true, site_id = true, stream_id = true, revision = true,
    unknown_region_action = true, blocked_regions = true,
    trusted_proxy_cidrs = true, region_cidrs = true,
}
local REGION_KEYS = { region = true, cidrs = true }

local function only_keys(value, allowed)
    if type(value) ~= "table" then return false end
    for key, _ in pairs(value) do
        if not allowed[key] then return false end
    end
    return true
end

local function integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value)
        and value >= minimum and value <= maximum
end

local function array_length(value, maximum)
    if type(value) ~= "table" then return nil end
    local count = 0
    local highest = 0
    for key, _ in pairs(value) do
        if type(key) ~= "number" or key ~= math.floor(key) or key < 1 then return nil end
        count = count + 1
        if key > highest then highest = key end
    end
    if count ~= highest or count > maximum then return nil end
    return count
end

local function text(value, maximum)
    return type(value) == "string" and #value > 0 and #value <= maximum
        and not value:find("[%z\1-\31\127]")
end

local function identifier(value)
    return text(value, 128) and value:match("^[A-Za-z0-9][A-Za-z0-9_.:-]*$") ~= nil
end

local function canonical_uuid(value)
    if type(value) ~= "string" or #value ~= 36
        or value:sub(9, 9) ~= "-" or value:sub(14, 14) ~= "-"
        or value:sub(19, 19) ~= "-" or value:sub(24, 24) ~= "-" then return false end
    local compact = value:gsub("-", "")
    return #compact == 32 and not compact:find("[^0-9a-f]")
end

local function split_plain(value, separator)
    local result = {}
    local start = 1
    while true do
        local finish = value:find(separator, start, true)
        if not finish then
            result[#result + 1] = value:sub(start)
            return result
        end
        result[#result + 1] = value:sub(start, finish - 1)
        start = finish + #separator
    end
end

local function parse_ipv4(value)
    local parts = split_plain(value, ".")
    if #parts ~= 4 then return nil end
    local bytes = {}
    for index = 1, 4 do
        local part = parts[index]
        if part == "" or #part > 3 or part:find("[^0-9]") then return nil end
        local number = tonumber(part, 10)
        if not number or number > 255 then return nil end
        bytes[index] = number
    end
    return bytes
end

local function parse_hex_groups(value)
    if value == "" then return {} end
    local groups = split_plain(value, ":")
    for index = 1, #groups do
        if groups[index] == "" or #groups[index] > 4 or groups[index]:find("[^0-9a-fA-F]") then return nil end
        groups[index] = tonumber(groups[index], 16)
    end
    return groups
end

local function parse_ipv6(value)
    if value:find("%", 1, true) then return nil end
    if value:find(".", 1, true) then
        local last_colon
        local search = 1
        while true do
            local found = value:find(":", search, true)
            if not found then break end
            last_colon = found
            search = found + 1
        end
        if not last_colon then return nil end
        local ipv4 = parse_ipv4(value:sub(last_colon + 1))
        if not ipv4 then return nil end
        value = value:sub(1, last_colon)
            .. string.format("%x:%x", ipv4[1] * 256 + ipv4[2], ipv4[3] * 256 + ipv4[4])
    end
    local double = value:find("::", 1, true)
    if double and value:find("::", double + 2, true) then return nil end
    local groups = {}
    if double then
        local left = parse_hex_groups(value:sub(1, double - 1))
        local right = parse_hex_groups(value:sub(double + 2))
        if not left or not right or #left + #right >= 8 then return nil end
        for _, group in ipairs(left) do groups[#groups + 1] = group end
        for _ = 1, 8 - #left - #right do groups[#groups + 1] = 0 end
        for _, group in ipairs(right) do groups[#groups + 1] = group end
    else
        groups = parse_hex_groups(value)
        if not groups or #groups ~= 8 then return nil end
    end
    local bytes = {}
    for index = 1, 8 do
        bytes[#bytes + 1] = math.floor(groups[index] / 256)
        bytes[#bytes + 1] = groups[index] % 256
    end
    local mapped = true
    for index = 1, 10 do
        if bytes[index] ~= 0 then mapped = false; break end
    end
    if mapped and bytes[11] == 255 and bytes[12] == 255 then return nil end
    return bytes
end

local function parse_address(value)
    if type(value) ~= "string" or #value == 0 or #value > 64 then return nil end
    local family = value:find(":", 1, true) and 6 or 4
    local bytes = family == 6 and parse_ipv6(value) or parse_ipv4(value)
    if not bytes then return nil end
    return { family = family, bytes = bytes }
end

local function network_is_canonical(bytes, prefix_length)
    local full = math.floor(prefix_length / 8)
    local remaining = prefix_length % 8
    if remaining > 0 then
        local divisor = 2 ^ (8 - remaining)
        if bytes[full + 1] % divisor ~= 0 then return false end
        full = full + 1
    end
    for index = full + 1, #bytes do
        if bytes[index] ~= 0 then return false end
    end
    return true
end

local function parse_cidr(value, trusted)
    if type(value) ~= "string" or #value > 80 then return nil end
    local parts = split_plain(value, "/")
    if #parts ~= 2 or parts[2] == "" or parts[2]:find("[^0-9]") then return nil end
    local address = parse_address(parts[1])
    local bits = tonumber(parts[2], 10)
    local maximum = address and (address.family == 4 and 32 or 128) or 0
    if not address or not integer(bits, trusted and 1 or 0, maximum)
        or not network_is_canonical(address.bytes, bits) then return nil end
    if trusted then
        if address.family == 4 and address.bytes[1] >= 224 and address.bytes[1] <= 239 then return nil end
        if address.family == 6 and address.bytes[1] == 255 then return nil end
    end
    return {
        family = address.family, network = address.bytes, prefix_length = bits,
        key = address.family .. "/" .. bits .. "/" .. table.concat(address.bytes, "."),
    }
end

local function prefix_matches(cidr, address)
    if cidr.family ~= address.family then return false end
    local full = math.floor(cidr.prefix_length / 8)
    for index = 1, full do
        if cidr.network[index] ~= address.bytes[index] then return false end
    end
    local remaining = cidr.prefix_length % 8
    if remaining == 0 then return true end
    local divisor = 2 ^ (8 - remaining)
    return math.floor(cidr.network[full + 1] / divisor)
        == math.floor(address.bytes[full + 1] / divisor)
end

local function region_name(value)
    return text(value, 32) and value:match("^[a-z0-9][a-z0-9_-]*$") ~= nil
end

local function compile_geo(listener, revision)
    local geo = listener.geo
    if geo == nil then return false end
    if not only_keys(geo, GEO_KEYS) or not canonical_uuid(geo.tenant_id)
        or not canonical_uuid(geo.site_id) or not identifier(geo.stream_id)
        or geo.tenant_id ~= listener.tenant_id or geo.site_id ~= listener.site_id
        or geo.stream_id ~= listener.stream_id or geo.stream_id ~= listener.id
        or geo.revision ~= revision then return nil, "geo_scope_mismatch" end
    if geo.enabled == false then return false end
    if geo.enabled ~= true then return nil, "geo_enabled_invalid" end
    if geo.unknown_region_action ~= "allow" and geo.unknown_region_action ~= "block" then
        return nil, "geo_unknown_action_invalid"
    end
    local region_cidrs = geo.region_cidrs or {}
    local blocked_regions = geo.blocked_regions or {}
    local trusted_proxy_cidrs = geo.trusted_proxy_cidrs or {}
    local region_count = array_length(region_cidrs, MAX_REGIONS)
    local blocked_count = array_length(blocked_regions, MAX_REGIONS)
    local proxy_count = array_length(trusted_proxy_cidrs, MAX_TRUSTED_PROXIES)
    if not region_count or not blocked_count or not proxy_count then return nil, "geo_array_invalid" end

    local compiled = { unknown_action = geo.unknown_region_action, blocked = {}, networks = {}, trusted = {} }
    local known_regions = {}
    local seen_cidrs = {}
    for _, entry in ipairs(region_cidrs) do
        local count = type(entry) == "table" and array_length(entry.cidrs, MAX_CIDRS) or nil
        if not only_keys(entry, REGION_KEYS) or not region_name(entry.region) or not count or count == 0
            or known_regions[entry.region] then return nil, "geo_region_invalid" end
        known_regions[entry.region] = true
        for _, raw in ipairs(entry.cidrs) do
            local cidr = parse_cidr(raw, false)
            if not cidr or seen_cidrs[cidr.key] then return nil, "geo_region_cidr_invalid" end
            seen_cidrs[cidr.key] = true
            cidr.region = entry.region
            compiled.networks[#compiled.networks + 1] = cidr
            if #compiled.networks > MAX_CIDRS then return nil, "geo_region_cidr_limit" end
        end
    end
    for _, region in ipairs(blocked_regions) do
        if not region_name(region) or not known_regions[region] or compiled.blocked[region] then
            return nil, "geo_blocked_region_invalid"
        end
        compiled.blocked[region] = true
    end
    local seen_proxies = {}
    for _, raw in ipairs(trusted_proxy_cidrs) do
        local cidr = parse_cidr(raw, true)
        if not cidr or seen_proxies[cidr.key] then return nil, "geo_trusted_proxy_invalid" end
        seen_proxies[cidr.key] = true
        compiled.trusted[#compiled.trusted + 1] = cidr
    end
    return compiled
end

local function compile_config(value)
    if not only_keys(value, TOP_KEYS) or value.schema_version ~= SCHEMA
        or not identifier(value.version_id) or not integer(value.revision, 1, MAX_SAFE_INTEGER) then
        return nil, "geo_schema_invalid"
    end
    local count = array_length(value.listeners, MAX_LISTENERS)
    if not count or count == 0 then return nil, "geo_listeners_invalid" end
    local listeners = {}
    for _, listener in ipairs(value.listeners) do
        if not only_keys(listener, LISTENER_KEYS) or not identifier(listener.id)
            or not canonical_uuid(listener.tenant_id) or not canonical_uuid(listener.site_id)
            or not identifier(listener.stream_id) or listener.id ~= listener.stream_id
            or listeners[listener.id] then return nil, "geo_listener_invalid" end
        local revision = listener.resource_revision or value.revision
        if not integer(revision, 1, MAX_SAFE_INTEGER) then return nil, "geo_revision_invalid" end
        local geo, err = compile_geo(listener, revision)
        if geo == nil then return nil, err end
        local guard, guard_err = false, nil
        if listener.guard ~= nil then
            guard, guard_err = _M.compile_guard(listener.guard)
            if not guard then return nil, guard_err end
        end
        listeners[listener.id] = {
            tenant_id = listener.tenant_id, site_id = listener.site_id,
            stream_id = listener.stream_id, geo = geo, guard = guard,
        }
    end
    return { revision = value.revision, version_id = value.version_id, listeners = listeners }
end

local function skip_space(bytes, index)
    while index <= #bytes and bytes:sub(index, index):find("%s") do index = index + 1 end
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

local function decode_unique(bytes)
    local finish = scan_json_value(bytes, skip_space(bytes, 1))
    if not finish or skip_space(bytes, finish) <= #bytes then return nil end
    return cjson.decode(bytes)
end

local function read_file(path)
    local file = io.open(path, "rb")
    if not file then return nil end
    local bytes = file:read(MAX_CONFIG_BYTES + 1)
    file:close()
    if not bytes or #bytes > MAX_CONFIG_BYTES then return nil end
    return bytes
end

-- Bytes the master read in init_by_lua for this configuration generation.
local preloaded = {}

local function read_candidate(path)
    return preloaded[path] or read_file(path)
end

local function config_path()
    local prefix = ngx.config and ngx.config.prefix and ngx.config.prefix()
    if type(prefix) ~= "string" or prefix == "" then return nil end
    return prefix .. "config.json"
end

-- Runs in the master before workers fork: workers drop to the unprivileged
-- nginx user and cannot open the agent's sealed version directory. A reload
-- runs it again for the new generation; workers inherit the bytes by fork.
function _M.preload()
    local path = config_path()
    if not path then return end
    preloaded[path] = read_file(path)
    if not preloaded[path] then ngx.log(ngx.WARN, "l4_geo geo_config_preload_failed") end
end

local function load(path)
    local previous = lkg[path]
    local bytes = read_candidate(path)
    -- The configuration a worker already compiled (every connection asks).
    if previous and bytes == previous.bytes then return previous end
    local decoded = bytes and decode_unique(bytes)
    local candidate
    local detail = "geo_candidate_invalid"
    if decoded then candidate, detail = compile_config(decoded) end
    if not candidate then
        if previous then return previous, "candidate_rejected_lkg", detail end
        return nil, "candidate_rejected_cold", detail
    end
    if previous and candidate.revision < previous.revision then
        return previous, "candidate_rejected_lkg", "geo_revision_rollback"
    end
    if previous and candidate.revision == previous.revision then
        if bytes == previous.bytes then return previous end
        return previous, "candidate_rejected_lkg", "geo_revision_conflict"
    end
    candidate.bytes = bytes
    lkg[path] = candidate
    return candidate
end

local function trusted_peer(policy, peer)
    for _, cidr in ipairs(policy.trusted) do
        if prefix_matches(cidr, peer) then return true end
    end
    return false
end

-- The client a connection is judged by, parsed and as text: the PROXY
-- protocol address when the socket peer is a trusted proxy, else the peer.
local function source_address(policy)
    local remote = ngx.var.remote_addr
    local peer = parse_address(remote)
    if not peer then return nil, "geo_peer_address_invalid" end
    local forwarded = ngx.var.proxy_protocol_addr
    if type(forwarded) ~= "string" or forwarded == "" or forwarded == remote then
        return peer, nil, remote
    end
    if not trusted_peer(policy, peer) then
        ngx.log(ngx.WARN, "l4_geo geo_untrusted_proxy_ignored")
        return peer, nil, remote
    end
    local client = parse_address(forwarded)
    if not client then return nil, "geo_proxy_address_invalid" end
    return client, nil, forwarded
end

local function client_region(policy, address)
    local region
    local prefix_length = -1
    for _, cidr in ipairs(policy.networks) do
        if cidr.prefix_length > prefix_length and prefix_matches(cidr, address) then
            region = cidr.region
            prefix_length = cidr.prefix_length
        end
    end
    return region, prefix_length
end

-- Session log end reasons (session_log, tcp/udp v7) of the sessions this
-- module refuses; the agent derives the others from $status.
local END_REASONS = {
    geo_blocked = "geo_blocked", geo_unknown_blocked = "geo_blocked",
    geo_peer_address_invalid = "bad_request", geo_proxy_address_invalid = "bad_request",
    rate_exceeded = "rate_limited", rate_exceeded_banned = "rate_limited", rate_banned = "banned",
    guard_dropped = "guard_blocked", guard_banned_now = "guard_blocked", guard_banned = "banned",
    -- market supply limits (subscription_enter): existing session log reasons
    subscription_stopped = "forbidden", subscription_new_exceeded = "conn_limited",
    subscription_connections_exceeded = "conn_limited",
}

-- Only servers with a session log declare $cdnca_l4_end_reason and
-- $cdnca_l4_client; log is true exactly there.
local function record_end_reason(log, reason)
    if log then ngx.var.cdnca_l4_end_reason = END_REASONS[reason] or "config_error" end
end

local function close_connection(reason, listener_id, log)
    ngx.log(ngx.WARN, "l4_geo ", reason, " listener=", listener_id)
    record_end_reason(log, reason)
    ngx.exit(ngx.ERROR)
    return false, reason
end

-- log: the server writes a session log (session_log), so the client and a
-- refusal's reason are recorded in its variables.
function _M.enforce(listener_id, log)
    if not identifier(listener_id) then return close_connection("geo_listener_invalid", tostring(listener_id), log) end
    local path = config_path()
    if not path then
        return close_connection("geo_config_prefix_invalid", listener_id, log)
    end
    local active, reload_reason, detail = load(path)
    if reload_reason then
        ngx.log(ngx.ERR, "l4_geo ", reload_reason, " detail=", detail or "unknown")
    end
    if not active then return close_connection(reload_reason or "candidate_rejected_cold", listener_id, log) end
    local listener = active.listeners[listener_id]
    if not listener then return close_connection("geo_listener_missing", listener_id, log) end
    if listener.stream_id ~= listener_id then return close_connection("geo_scope_mismatch", listener_id, log) end
    -- The third result names the client for later checks (limit_new_connections).
    if listener.geo == false then
        if log then ngx.var.cdnca_l4_client = ngx.var.remote_addr end
        return true, "geo_not_configured", ngx.var.remote_addr
    end

    local client, source_error, client_text = source_address(listener.geo)
    if not client then return close_connection(source_error, listener_id, log) end
    if log then ngx.var.cdnca_l4_client = client_text end
    local region = client_region(listener.geo, client)
    if not region then
        if listener.geo.unknown_action == "allow" then return true, "geo_unknown_allowed", client_text end
        return close_connection("geo_unknown_blocked", listener_id, log)
    end
    if listener.geo.blocked[region] then return close_connection("geo_blocked", listener_id, log) end
    return true, "geo_allowed", client_text
end

-- Per-client new connection rate of a stream (new_conn_rate, tcp/udp v6):
-- a token bucket of rate+burst refilled at rate per second, in the
-- lua_shared_dict l4_v2_rate the agent declares for limited streams, so all
-- workers and sockets of the stream share it. Over the limit the connection
-- (UDP: the session) is closed and, with ban_seconds > 0, the client's new
-- connections to the stream are closed for that long. Keys:
-- "rate:<stream>:<client>" and "ban:<stream>:<client>" (#8 reuses the ban key).
-- The read-modify-write is per worker, so concurrent workers may admit a few
-- connections beyond the limit; the bucket never goes negative.
local function rate_closed(reason, stream_id, client, log)
    ngx.log(ngx.WARN, "l4_rate ", reason, " stream=", stream_id, " client=", client)
    record_end_reason(log, reason)
    ngx.exit(ngx.ERROR)
    return false, reason
end

function _M.limit_new_connections(stream_id, client, rate, burst, ban_seconds, log)
    local dict = ngx.shared and ngx.shared.l4_v2_rate
    if not identifier(stream_id) then return rate_closed("rate_stream_invalid", tostring(stream_id), tostring(client), log) end
    if not dict or not text(client, 64) or not integer(rate, 1, 100000)
        or not integer(burst, 0, 100000) or not integer(ban_seconds, 0, 86400) then
        return rate_closed("rate_config_invalid", stream_id, tostring(client), log)
    end
    local ban_key = "ban:" .. stream_id .. ":" .. client
    if dict:get(ban_key) then return rate_closed("rate_banned", stream_id, client, log) end
    local key = "rate:" .. stream_id .. ":" .. client
    local capacity = rate + burst
    local now = ngx.now()
    local tokens, last = capacity, now
    local stored = dict:get(key)
    if type(stored) == "string" then
        local saved_tokens, saved_last = stored:match("^([0-9.]+) ([0-9.]+)$")
        saved_tokens, saved_last = tonumber(saved_tokens), tonumber(saved_last)
        if saved_tokens and saved_last then
            tokens = math.min(capacity, saved_tokens + math.max(0, now - saved_last) * rate)
            last = now
        end
    end
    -- An idle bucket refills completely within capacity/rate seconds.
    local ttl = math.ceil(capacity / rate) + 1
    if tokens < 1 then
        dict:set(key, string.format("%.6f %.3f", tokens, last), ttl)
        if ban_seconds > 0 then dict:set(ban_key, true, ban_seconds) end
        return rate_closed(ban_seconds > 0 and "rate_exceeded_banned" or "rate_exceeded", stream_id, client, log)
    end
    dict:set(key, string.format("%.6f %.3f", tokens - 1, last), ttl)
    return true
end

-- Market supply limits of a stream's subscription (subscription_limits,
-- SUBSCRIPTION_LIMITS v1, ADR 0012 ML-07), shared by every stream of the
-- subscription on the node (lua_shared_dict l4_v2_subscriptions):
-- subscription_enter() in preread (after the Geo, guard and per-client
-- checks) closes the session when the subscription is stopped, over its new
-- sessions this second ("new|<sub>|<second>") or over its concurrent
-- sessions ("conn|<sub>"), else counts it and sets the session's download
-- rate to the subscription's bandwidth_bps, which the session draws from the
-- subscription's shared bucket (proxy_download_rate_shared, native patch 28);
-- subscription_leave() in log uncounts it (a session counts once, the
-- variable remembers it). Worker crashes leave counts behind until the
-- dictionary is flushed (reload with a size change).
local SUBSCRIPTION_DICT = "l4_v2_subscriptions"

function _M.subscription_enter(sub, max_conns, per_second, bps, stopped, log)
    local dict = ngx.shared[SUBSCRIPTION_DICT]
    if not dict or not canonical_uuid(sub) then return rate_closed("subscription_config_invalid", tostring(sub), "-", log) end
    if stopped then return rate_closed("subscription_stopped", sub, "-", log) end
    local window = "new|" .. sub .. "|" .. math.floor(ngx.now())
    local started = dict:incr(window, 1, 0, 2) or 1
    if per_second > 0 and started > per_second then
        dict:incr(window, -1)
        return rate_closed("subscription_new_exceeded", sub, "-", log)
    end
    local open = dict:incr("conn|" .. sub, 1, 0) or 1
    if max_conns > 0 and open > max_conns then
        dict:incr("conn|" .. sub, -1)
        dict:incr(window, -1)
        return rate_closed("subscription_connections_exceeded", sub, "-", log)
    end
    ngx.var.cdnca_l4_subscription = sub
    if bps > 0 then
        -- the subscription's whole budget: the sessions keyed by sub share it
        -- (proxy_download_rate_shared), so a session entering later slows
        -- the ones already open and a leaving one gives its share back
        ngx.var.cdnca_l4_subscription_rate = math.max(math.floor(bps / 8), 1)
    end
    return true
end

function _M.subscription_leave()
    local sub = ngx.var.cdnca_l4_subscription
    if not sub or sub == "" then return end
    ngx.var.cdnca_l4_subscription = ""
    local dict = ngx.shared[SUBSCRIPTION_DICT]
    local left = dict and dict:incr("conn|" .. sub, -1)
    if left and left < 0 then dict:set("conn|" .. sub, 0) end
end

-- subscription_sessions(sub): the counted sessions (acceptance).
function _M.subscription_sessions(sub)
    local dict = ngx.shared[SUBSCRIPTION_DICT]
    return dict and dict:get("conn|" .. sub) or 0
end

-- L4 guard rules (guard_rules, tcp/udp v10; docs/architecture/l4-v6-fields.md
-- #8): the agent writes a stream's rules to config.json (listeners[].guard),
-- compiled with the rest of the configuration, so an invalid candidate keeps
-- the last known good one. guard() runs in preread after enforce(); the
-- first rule whose conditions all hold decides. Bans share the new
-- connection rate's dictionary and key (ban:<stream>:<client>); hit
-- counters are "hit:<stream>:<rule>:<client>" with the rule's window as TTL.
local MAX_GUARD_RULES = 64
local MAX_GUARD_CIDRS = 4096
local GUARD_FIRST_BYTES = 512
-- How long guard() waits for a TCP client's first data; the agent renders
-- preread_timeout 3s for servers with first packet rules, so a client that
-- never sends (server-first protocols) is passed on, not cut off.
local GUARD_WAIT = 2.5
-- Kernel ban queue the agent drains through control() "bans".
local KERNEL_QUEUE = "kban"
local KERNEL_QUEUE_MAX = 10000
local GUARD_RULE_KEYS = {
    id = true, action = true, first_packet = true, server_names = true, client_ip = true, geo = true,
    ban_seconds = true, threshold = true, window_seconds = true,
}
local FIRST_PACKET_KEYS = { match = true, value = true }
local CLIENT_IP_KEYS = { cidrs = true, negate = true }

local function unhex(value)
    if type(value) ~= "string" or #value < 2 or #value > 512 or #value % 2 ~= 0 or value:find("[^0-9a-f]") then return nil end
    return (value:gsub("..", function(pair) return string.char(tonumber(pair, 16)) end))
end

local function guard_server_name(value)
    if not text(value, 255) then return false end
    local base = value:sub(1, 2) == "*." and value:sub(3) or value
    return base:find("^[a-z0-9][a-z0-9.-]*[a-z0-9]$") ~= nil and base:find(".", 1, true) ~= nil
        and not base:find("..", 1, true)
end

local function compile_first_packet(value)
    if not only_keys(value, FIRST_PACKET_KEYS) or type(value.value) ~= "string" then return nil end
    local pattern = value.value
    if value.match == "prefix_hex" then
        local bytes = unhex(pattern)
        return bytes and { kind = "prefix", bytes = bytes } or nil
    end
    if #pattern < 1 or #pattern > 256 or pattern:find("%z") then return nil end
    if value.match == "contains" then return { kind = "contains", bytes = pattern } end
    if value.match == "regex" then
        local _, _, err = ngx.re.find("", pattern, "jo")
        if err then return nil end
        return { kind = "regex", pattern = pattern }
    end
    return nil
end

local function compile_guard_rule(rule, seen)
    if not only_keys(rule, GUARD_RULE_KEYS) or not canonical_uuid(rule.id) or seen[rule.id] then return nil end
    seen[rule.id] = true
    local compiled = { id = rule.id, action = rule.action }
    if rule.action == "ban" then
        if not integer(rule.ban_seconds, 1, 86400) or not integer(rule.threshold, 1, 10000) then return nil end
        if rule.threshold == 1 then
            if rule.window_seconds ~= nil then return nil end
        elseif not integer(rule.window_seconds, 1, 3600) then
            return nil
        end
        compiled.ban_seconds, compiled.threshold, compiled.window = rule.ban_seconds, rule.threshold, rule.window_seconds or 0
    elseif rule.action == "drop" or rule.action == "allow" then
        if rule.ban_seconds ~= nil or rule.threshold ~= nil or rule.window_seconds ~= nil then return nil end
    else
        return nil
    end
    local conditions = 0
    if rule.client_ip ~= nil then
        local value = rule.client_ip
        local count = type(value) == "table" and array_length(value.cidrs, 1024) or nil
        if not only_keys(value, CLIENT_IP_KEYS) or not count or count == 0
            or (value.negate ~= nil and type(value.negate) ~= "boolean") then return nil end
        compiled.cidrs, compiled.negate = {}, value.negate == true
        for _, raw in ipairs(value.cidrs) do
            local cidr = parse_cidr(raw, false)
            if not cidr then return nil end
            compiled.cidrs[#compiled.cidrs + 1] = cidr
        end
        conditions = conditions + 1
    end
    if rule.server_names ~= nil then
        local count = array_length(rule.server_names, 32)
        if not count or count == 0 then return nil end
        compiled.exact, compiled.wildcards = {}, {}
        for _, name in ipairs(rule.server_names) do
            if not guard_server_name(name) then return nil end
            if name:sub(1, 2) == "*." then
                compiled.wildcards[#compiled.wildcards + 1] = name:sub(2)
            else
                compiled.exact[name] = true
            end
        end
        conditions = conditions + 1
    end
    if rule.geo ~= nil then
        local count = array_length(rule.geo, 4)
        if not count or count == 0 then return nil end
        for _, spec in ipairs(rule.geo) do
            if not text(spec, 1024) or not spec:find("^%l+!?=[%w,]+$") then return nil end
        end
        compiled.geo = rule.geo
        conditions = conditions + 1
    end
    if rule.first_packet ~= nil then
        compiled.first_packet = compile_first_packet(rule.first_packet)
        if not compiled.first_packet then return nil end
        conditions = conditions + 1
    end
    if conditions == 0 then return nil end
    return compiled
end

function _M.compile_guard(rules)
    local count = array_length(rules, MAX_GUARD_RULES)
    if not count or count == 0 then return nil, "guard_rules_invalid" end
    local compiled, seen, cidrs = {}, {}, 0
    for index, rule in ipairs(rules) do
        local item = compile_guard_rule(rule, seen)
        if not item then return nil, "guard_rule_invalid" end
        cidrs = cidrs + (item.cidrs and #item.cidrs or 0)
        compiled[index] = item
    end
    if cidrs > MAX_GUARD_CIDRS then return nil, "guard_cidr_limit" end
    return compiled
end

-- First packet: stream-lua's peek() waits for the full count (a client that
-- sends less, or nothing, is cut off at preread_timeout) and UDP has no
-- peek, so the data is read through the connection itself (LuaJIT FFI):
-- TCP recv(MSG_PEEK|MSG_DONTWAIT) on its socket (nginx 1.25+ prereads by
-- peeking, so the kernel still holds everything; a PROXY header is already
-- consumed), UDP the datagram nginx put in c->buffer (not consumed). The
-- ngx_connection_t prefix below is the same in nginx 1.27.1 and 1.31.1 with
-- --with-compat (both node builds); a self-check against $remote_addr and
-- the socket type turns the condition off (no match, logged) on any other
-- layout instead of reading the wrong memory.
local ffi_ok, ffi = pcall(require, "ffi")
local first_packet_state -- nil: not set up; false: unavailable; true: ready
local first_packet_problem
local first_packet_buffer
local EAGAIN, EINTR = 11, 4
local MSG_PEEK, MSG_DONTWAIT = 0x2, 0x40
local SOCK_STREAM, SOCK_DGRAM = 1, 2

local function first_packet_unavailable(reason)
    if first_packet_problem ~= reason then
        first_packet_problem = reason
        ngx.log(ngx.ERR, "l4_guard first_packet_unavailable ", reason)
    end
    return nil
end

local function first_packet_ffi()
    if first_packet_state ~= nil then return first_packet_state end
    first_packet_state = ffi_ok and pcall(ffi.cdef, [[
        typedef struct { unsigned char *pos; unsigned char *last; int64_t file_pos; int64_t file_last;
            unsigned char *start; unsigned char *end_; } cdnca_l4_buf_t;
        typedef struct {
            void *data; void *read; void *write; int fd;
            void *recv; void *send; void *recv_chain; void *send_chain; void *listening;
            int64_t sent; void *log; void *pool; int type;
            void *sockaddr; unsigned int socklen; size_t addr_text_len; unsigned char *addr_text_data;
            void *proxy_protocol; void *quic; void *ssl; void *udp;
            void *local_sockaddr; unsigned int local_socklen; cdnca_l4_buf_t *buffer;
        } cdnca_l4_conn_t;
        long cdnca_l4_recv(int fd, void *buf, size_t n, int flags) __asm__("recv");
    ]]) or false
    return first_packet_state
end

-- read_first_packet returns the client's first data, at most 512 bytes: the
-- UDP datagram, or what a TCP client sent once data arrives within wait
-- seconds; "" when it sent nothing; nil when it cannot be read (logged).
-- Both mean "no match": guard() never refuses for want of data.
function _M.read_first_packet(wait)
    if not first_packet_ffi() then return first_packet_unavailable("ffi") end
    local ok, base = pcall(require, "resty.core.base")
    local request = ok and base.get_request and base.get_request()
    if not request then return first_packet_unavailable("request") end
    local c = ffi.cast("cdnca_l4_conn_t **", request)[0]
    local remote = ngx.var.remote_addr or ""
    if c == nil or tonumber(c.addr_text_len) ~= #remote or ffi.string(c.addr_text_data, #remote) ~= remote then
        return first_packet_unavailable("layout")
    end
    if ngx.var.protocol == "UDP" then
        local b = c.buffer
        if c.type ~= SOCK_DGRAM or c.udp == nil or b == nil or b.start > b.pos or b.pos > b.last or b.last > b.end_
            or b.last - b.pos > 65535 then
            return first_packet_unavailable("udp_buffer")
        end
        return ffi.string(b.pos, math.min(tonumber(b.last - b.pos), GUARD_FIRST_BYTES))
    end
    if c.type ~= SOCK_STREAM or c.fd < 0 then return first_packet_unavailable("tcp_socket") end
    first_packet_buffer = first_packet_buffer or ffi.new("char[?]", GUARD_FIRST_BYTES)
    local deadline, pause = ngx.now() + wait, 0.005
    while true do
        -- No yield between recv and the copy: the buffer is shared.
        local n = tonumber(ffi.C.cdnca_l4_recv(c.fd, first_packet_buffer, GUARD_FIRST_BYTES, MSG_PEEK + MSG_DONTWAIT))
        if n > 0 then return ffi.string(first_packet_buffer, n) end
        local errno = n < 0 and ffi.errno() or 0
        if n == 0 or (errno ~= EAGAIN and errno ~= EINTR) then return "" end -- closed or reset
        if ngx.now() >= deadline then return "" end
        ngx.sleep(pause)
        pause = math.min(pause * 2, 0.1)
    end
end

local iplib
local function iplib_module()
    if iplib == nil then
        local ok, module = pcall(require, "cdnca_iplib")
        iplib = ok and module or false
        if not ok then ngx.log(ngx.ERR, "l4_guard iplib_unavailable") end
    end
    return iplib
end

local function address_binary(address)
    local bytes = {}
    for index = 1, #address.bytes do bytes[index] = string.char(address.bytes[index]) end
    return table.concat(bytes)
end

local function sni_matches(rule, name)
    if type(name) ~= "string" or name == "" then return false end
    name = name:lower()
    if rule.exact[name] then return true end
    for _, suffix in ipairs(rule.wildcards) do
        if #name > #suffix and name:sub(-#suffix) == suffix then return true end
    end
    return false
end

local function first_packet_matches(matcher, data)
    if not data or data == "" then return false end
    if matcher.kind == "prefix" then return data:sub(1, #matcher.bytes) == matcher.bytes end
    if matcher.kind == "contains" then return data:find(matcher.bytes, 1, true) ~= nil end
    local from, _, err = ngx.re.find(data, matcher.pattern, "jo")
    if err then ngx.log(ngx.WARN, "l4_guard regex ", err) end
    return from ~= nil
end

local function guard_closed(reason, stream_id, client, rule_id, log)
    ngx.log(ngx.WARN, "l4_guard ", reason, " stream=", stream_id, " rule=", rule_id or "-", " client=", client)
    record_end_reason(log, reason)
    ngx.exit(ngx.ERROR)
    return false, reason
end

-- guard applies stream_id's guard rules to client (enforce()'s third
-- result). log: the server writes a session log. kernel: the socket is the
-- stream's own (not behind a shared port's dispatcher), so a ban of a client
-- that is the socket peer is queued for the agent's kernel (nftables) ban.
-- Returns true when the connection may go on.
function _M.guard(stream_id, client, log, kernel)
    local dict = ngx.shared and ngx.shared.l4_v2_rate
    if not identifier(stream_id) then return guard_closed("guard_stream_invalid", tostring(stream_id), tostring(client), nil, log) end
    local path = config_path()
    local active = path and load(path)
    local listener = active and active.listeners[stream_id]
    if not dict or not listener or not text(client, 64) then
        return guard_closed("guard_config_invalid", stream_id, tostring(client), nil, log)
    end
    local rules = listener.guard
    if not rules then return true end
    local ban_key = "ban:" .. stream_id .. ":" .. client
    if dict:get(ban_key) then return guard_closed("guard_banned", stream_id, client, nil, log) end
    local address, attrs, attrs_ready, data, data_ready, sni
    for _, rule in ipairs(rules) do
        local hit = true
        if rule.cidrs then
            address = address or parse_address(client)
            local inside = false
            for _, cidr in ipairs(address and rule.cidrs or {}) do
                if prefix_matches(cidr, address) then inside = true; break end
            end
            hit = inside ~= rule.negate
        end
        if hit and rule.exact then
            sni = sni or ngx.var.ssl_preread_server_name or ""
            hit = sni_matches(rule, sni)
        end
        if hit and rule.geo then
            local lib = iplib_module()
            if not attrs_ready then
                attrs_ready = true
                address = address or parse_address(client)
                if lib and address then attrs = lib.lookup(address_binary(address)) end
            end
            for _, spec in ipairs(rule.geo) do
                if not lib or not lib.test(attrs, spec) then hit = false; break end
            end
        end
        if hit and rule.first_packet then
            if not data_ready then
                data_ready = true
                data = _M.read_first_packet(GUARD_WAIT)
            end
            hit = first_packet_matches(rule.first_packet, data)
        end
        if hit then
            if rule.action == "allow" then return true end
            if rule.action == "drop" then return guard_closed("guard_dropped", stream_id, client, rule.id, log) end
            local hits = 1
            if rule.threshold > 1 then
                hits = dict:incr("hit:" .. stream_id .. ":" .. rule.id .. ":" .. client, 1, 0, rule.window) or 1
            end
            if hits < rule.threshold then return guard_closed("guard_dropped", stream_id, client, rule.id, log) end
            dict:set(ban_key, true, rule.ban_seconds)
            if kernel and client == ngx.var.remote_addr then
                if (dict:llen(KERNEL_QUEUE) or 0) < KERNEL_QUEUE_MAX then
                    dict:lpush(KERNEL_QUEUE, stream_id .. "|" .. client .. "|" ..
                        string.format("%d", math.ceil(ngx.now()) + rule.ban_seconds))
                else
                    dict:incr("kban_dropped", 1, 0)
                end
            end
            return guard_closed("guard_banned_now", stream_id, client, rule.id, log)
        end
    end
    return true
end

-- Live TCP sessions of streams with a session log (session_log, tcp/udp v7).
-- The agent lists a stream's connections from the kernel (sock_diag on its
-- ports) and asks control() what this module recorded for them: the stream,
-- the client (PROXY protocol address from a trusted proxy) and the start.
-- Keys are the kernel socket tuple "<local addr>|<local port>|<peer addr>|
-- <peer port>" of the connection the node accepted (behind a dispatcher: the
-- public one the PROXY header names). Values: "<stream>|<listener>|<client>|
-- <client port>|<started>|<token>|<killed 0/1>"; the token (worker pid and
-- $connection) keeps a session from removing a later one on the same tuple.
-- The dictionary is an LRU: entries a crashed worker leaves are evicted.
local LIVE_DICT = "l4_v2_live"
local MAX_CONTROL_KEYS = 20000

function _M.session_track(stream_id, listener_id, client, dispatched)
    local dict = ngx.shared[LIVE_DICT]
    if not dict then return end
    local var = ngx.var
    local local_addr, local_port = var.server_addr, var.server_port
    if dispatched then local_addr, local_port = var.proxy_protocol_server_addr, var.proxy_protocol_server_port end
    local peer = var.remote_addr
    local key = local_addr .. "|" .. local_port .. "|" .. peer .. "|" .. var.remote_port
    local client_port = var.remote_port
    if client ~= peer then client_port = var.proxy_protocol_port or "" end
    local token = ngx.worker.pid() .. ":" .. var.connection
    local ok = dict:set(key, stream_id .. "|" .. listener_id .. "|" .. client .. "|" .. client_port .. "|" ..
        string.format("%.3f", ngx.now()) .. "|" .. token .. "|0")
    if not ok then
        dict:incr("untracked", 1, 0)
        return
    end
    var.cdnca_l4_live_key = key
    var.cdnca_l4_live_token = token
end

function _M.session_end()
    local var = ngx.var
    local key = var.cdnca_l4_live_key
    if not key or key == "" then return end
    local dict = ngx.shared[LIVE_DICT]
    if not dict then return end
    local value = dict:get(key)
    if type(value) ~= "string" then return end
    local token, killed = value:match("|([^|]+)|([01])$")
    if token ~= var.cdnca_l4_live_token then return end
    dict:delete(key)
    if killed == "1" then var.cdnca_l4_end_reason = "killed" end
end

-- control() serves the agent on the root-only control socket. Commands:
-- "stats" -> "untracked <n>"; "bans" -> the queued kernel bans (guard());
-- "get" or "kill", then one key per line and
-- "end" -> one "<key>\t<value or ->" line per key, then "end". "kill" marks
-- the sessions so their log says killed; the agent closes the socket.
function _M.control()
    local sock = ngx.req.socket(true)
    if not sock then return end
    sock:settimeouts(5000, 5000, 5000)
    local dict = ngx.shared[LIVE_DICT]
    local command = sock:receive("*l")
    if command == "stats" then
        sock:send("untracked " .. tostring(dict and dict:get("untracked") or 0) .. "\n")
        return
    end
    if command == "bans" then
        -- Guard bans queued for the kernel (guard()): one
        -- "<stream>|<client>|<until epoch>" line each, then "end".
        local rate = ngx.shared.l4_v2_rate
        local out = {}
        for _ = 1, rate and MAX_CONTROL_KEYS or 0 do
            local item = rate:rpop(KERNEL_QUEUE)
            if not item then break end
            out[#out + 1] = item .. "\n"
            if #out >= 256 then
                if not sock:send(out) then return end
                out = {}
            end
        end
        out[#out + 1] = "end\n"
        sock:send(out)
        return
    end
    if not dict or (command ~= "get" and command ~= "kill") then
        sock:send("error\n")
        return
    end
    local out, count = {}, 0
    while true do
        local key = sock:receive("*l")
        if not key or key == "end" then break end
        count = count + 1
        if count > MAX_CONTROL_KEYS or #key > 160 or key:find("[%s]") then
            sock:send("error\n")
            return
        end
        local value = dict:get(key)
        if type(value) ~= "string" then
            value = "-"
        elseif command == "kill" then
            value = value:gsub("|[01]$", "|1")
            dict:set(key, value)
        end
        out[#out + 1] = key .. "\t" .. value .. "\n"
        if #out >= 256 then
            if not sock:send(out) then return end
            out = {}
        end
    end
    out[#out + 1] = "end\n"
    sock:send(out)
end

return _M
