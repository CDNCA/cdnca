-- Dynamic routing cache (ADR 0009 section 4, D8). The executable spec is
-- libs/edgeconfig/edgecache (Go): zone pool, key, per-site plan; this module
-- derives the same plan from the site object (cdnca_site.current()) and must
-- agree with edgecache.Build (tests/dynroute-cache compares them).
--
-- Request flow (access phase, after security):
--   * no cache plan, or a rules policy whose rules name nothing: an empty
--     $cdnca_cache_zone; a range site goes to @cdnca_cache_bypass (Range
--     forwarded, proxy_force_ranges), any other stays in location / (v7's
--     bypass route);
--   * a request bypass (method, authorization, cookie, upgrade, a rule that
--     caches nothing): the plan's variant without slices, empty zone (v7
--     proxy_cache_bypass in the rule location: Accept-Ranges as v7);
--   * cacheable -> ngx.exec to the plan's named variant (edgecache.Variants)
--     @cdnca_cache_<override|follow>[_stale|_stalebg][_s<KiB>]: origin
--     expiry headers, stale-if-error, background update and slice size are
--     configuration-time; lock, revalidate and proxy_force_ranges are in
--     every variant; everything else is variables:
--       $cdnca_cache_zone  pool zone (edgecache.ZoneIndex, ZoneName)
--       $cdnca_cache_key   <key_prefix>|<generation>|<purge gen>|<host or domain>|<port>|<policy key>
--       $cdnca_cache_ttls  " 200=60 404=0 any=60 " (patch 24 proxy_cache_valid via map)
--       $cdnca_cache_browsers expires per status (schema v2 rules), "" = none
--   * the site's purge generation is node state (shared dict, written by the
--     agent through the admin socket): "purge
--     everything" is O(1) and immediate. Until the agent has loaded the
--     generations after a start, nothing is cached (purged objects must not
--     come back).
-- Semantics follow ge-cache and its v7 rendering (libs/edgeconfig
-- site_runtime_cache_v2.go): request cookies are ignored on rule-matched
-- requests (C), every caching site answers Range from cached objects (D),
-- X-CDN-Cache tells STALE/UPDATING/REVALIDATED/EXPIRED apart and every
-- BYPASS carries X-CDN-Cache-Reason with v7's names and order (H); policy
-- min/max_object_bytes stop storing in the header filter (object_size).
-- ge36 (CACHE_RULE_MATCH): a rule's path_regex must also match $uri
-- (ngx.re, PCRE2 under lua_regex_match_limit: a match over the limit is no
-- match); a rule's content_types are decided in the header filter: the
-- request's rules whose content_types the response does not satisfy are
-- dropped and the remaining rules' route sets the TTLs and browser expiry
-- (patch 24 reads $cdnca_cache_ttls after the header filter); none left
-- caching = not stored (content_type). The request is looked up in the
-- cache when some Content-Type would cache it (route.may_cache).
-- Per-rule settings (edgeconfig.CacheRuleExtras): a rule may name one exact
-- path (path_exact); the deciding rule (the request's first candidate)
-- picks the route's variant (force_cache = override, ignore_vary = _nv,
-- slice_bytes), drops the query from the key (ignore_query) and bypasses
-- the cache on a 不缓存条件 match (no_cache_condition), as edgecache.Route.
local resty_sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex
local lrucache = require "resty.lrucache"
local cjson = require "cjson.safe"
local site_mod = require "cdnca_site"
local bit = require "bit"

local ngx_var = ngx.var
local byte, sub, find, match, lower = string.byte, string.sub, string.find, string.match, string.lower
local tonumber, tostring, type, pairs, ipairs = tonumber, tostring, type, pairs, ipairs
local concat, sort = table.concat, table.sort

local _M = { version = "1" }

local purge = ngx.shared.cdnca_cache_purge
local LOADED, PREWARM = "loaded", "prewarm_token"
local config = { zones = 0, zone_suffix = "" }
local plans -- site digest -> plan

local MAX_RAW_QUERY_BYTES, MAX_QUERY_PAIRS = 8192, 256
local MAX_HEADER_VALUE_BYTES, MAX_HEADER_TOTAL_BYTES = 4096, 16384

function _M.configure(opts)
    assert(purge, "cdnca_cache: lua_shared_dict cdnca_cache_purge missing")
    local zones = tonumber(opts and opts.zones) or 0
    assert(zones >= 0 and zones <= 64 and (zones == 0 or bit.band(zones, zones - 1) == 0), "cdnca_cache: zones")
    config.zones = zones
    -- edgecache.ZoneSuffix: "" (default cache directory) or _<8 hex>
    local suffix = opts.zone_suffix or ""
    assert(suffix == "" or match(suffix, "^_%x%x%x%x%x%x%x%x$"), "cdnca_cache: zone_suffix")
    config.zone_suffix = suffix
    plans = assert(lrucache.new(tonumber(opts.lru_items) or 10000))
end

-- v7 simple policy TTLs (edgecache.simpleTTLs); schema v1 status rules are
-- the status-only rules (CachePolicyFromDocument).
local SLICE_SIZES = { 262144, 1048576, 4194304, 16777216, 67108864 }

-- rule content_types (edgeconfig.CacheContentTypeMatches): nil = any
local function compile_types(values)
    if type(values) ~= "table" or #values == 0 then
        return nil
    end
    local exact, prefixes = {}, {}
    for _, value in ipairs(values) do
        if byte(value, #value) == 42 then -- "*"
            prefixes[#prefixes + 1] = sub(value, 1, #value - 1)
        else
            exact[value] = true
        end
    end
    return { exact = exact, prefixes = prefixes }
end

local function types_match(types, media)
    if types.exact[media] then
        return true
    end
    if media == "" then
        return false
    end
    for _, prefix in ipairs(types.prefixes) do
        if sub(media, 1, #prefix) == prefix then
            return true
        end
    end
    return false
end

-- edgecache.SliceVariantBytes
local function slice_variant(bytes)
    local size = 0
    for _, candidate in ipairs(SLICE_SIZES) do
        if candidate <= (tonumber(bytes) or 0) then
            size = candidate
        end
    end
    return size
end

-- edgecache.sliceTTLs: a slice (206) is cached like 200
local function slice_ttls(status, sliced)
    if sliced and status["200"] ~= nil and status["206"] == nil then
        status["206"] = status["200"]
    end
    return status
end

local function simple_ttls(policy)
    local ttl = 60
    local status = { ["200"] = ttl, ["301"] = ttl, ["302"] = ttl }
    if (policy.schema_version or 0) == 0 then
        for index, rule in ipairs(policy.rules) do
            if index == 1 and policy.mode == "override" then
                ttl = rule.ttl_seconds
                status["200"], status["301"], status["302"] = ttl, ttl, ttl
            end
        end
        for _, rule in ipairs(policy.rules) do
            if (rule.extensions == nil or #rule.extensions == 0) and (rule.path_prefix or "") == "" then
                for _, code in ipairs(rule.status_codes or {}) do
                    status[tostring(code)] = rule.ttl_seconds
                end
            end
        end
    end
    return status, 0
end

local function ttl_value(status, any)
    local keys = {}
    for code in pairs(status) do
        keys[#keys + 1] = tonumber(code)
    end
    sort(keys)
    local out = { " " }
    for _, code in ipairs(keys) do
        out[#out + 1] = code .. "=" .. status[tostring(code)] .. " "
    end
    out[#out + 1] = "any=" .. any .. " "
    return concat(out)
end

local function contains(list, value)
    for _, item in ipairs(list or {}) do
        if item == value then
            return true
        end
    end
    return false
end

local function browser_value(rule)
    if not rule or rule.action ~= "cache" then
        return "epoch"
    end
    local seconds = rule.browser_ttl_seconds or 0
    if seconds == 0 then
        return "off"
    end
    return seconds .. "s"
end

-- decide(policy, candidates): edgecache.decide (v7 cachePolicyV2Route /
-- cachePolicyRouteTTLs) for 1-based rule indexes.
local function decide(policy, candidates, sliced)
    local rules = policy.rules
    local v2 = policy.schema_version == 2
    local function pick(code)
        for _, index in ipairs(candidates) do
            local rule = rules[index]
            local codes = rule.status_codes or {}
            if #codes == 0 or (code ~= 0 and contains(codes, code)) then
                return rule
            end
        end
    end
    local function cacheable(rule)
        return rule ~= nil and (not v2 or rule.action == "cache")
    end
    local status, any, cache = {}, 0, false
    local any_rule = pick(0)
    if cacheable(any_rule) then
        any, cache = any_rule.ttl_seconds, true
    end
    local browser_any = v2 and browser_value(any_rule) or ""
    local browser = {}
    local codes, seen = {}, {}
    for _, index in ipairs(candidates) do
        for _, code in ipairs(rules[index].status_codes or {}) do
            if not seen[code] then
                seen[code] = true
                codes[#codes + 1] = code
            end
        end
    end
    sort(codes)
    for _, code in ipairs(codes) do
        local rule = pick(code)
        status[tostring(code)] = 0
        if cacheable(rule) then
            status[tostring(code)], cache = rule.ttl_seconds, true
        end
        if v2 then
            local value = browser_value(rule)
            if value ~= browser_any then
                browser[tostring(code)] = value
            end
        end
    end
    local browsers = ""
    if v2 then
        local out = { " " }
        local keys = {}
        for code in pairs(browser) do
            keys[#keys + 1] = tonumber(code)
        end
        sort(keys)
        for _, code in ipairs(keys) do
            out[#out + 1] = code .. "=" .. browser[tostring(code)] .. " "
        end
        out[#out + 1] = "any=" .. browser_any .. " "
        browsers = concat(out)
    end
    return { cache = cache, ttls = ttl_value(slice_ttls(status, sliced), any), browsers = browsers }
end

-- subsets(list, optional): list with every combination of the members
-- optional(index) selects left out (edgecache subsets), non-empty only.
local function subsets(list, optional)
    local picked = {}
    for _, index in ipairs(list) do
        if optional(index) then
            picked[#picked + 1] = index
        end
    end
    local result = {}
    for mask = 0, bit.lshift(1, #picked) - 1 do
        local set, position = {}, 0
        for _, index in ipairs(list) do
            local drop = false
            if optional(index) then
                drop = bit.band(mask, bit.lshift(1, position)) ~= 0
                position = position + 1
            end
            if not drop then
                set[#set + 1] = index
            end
        end
        if #set > 0 then
            result[#result + 1] = set
        end
    end
    return result
end

-- variant_name(override, stale, ignore_vary, slice): edgecache.variantName
local function variant_name(override, stale, ignore_vary, slice)
    local name = override and "@cdnca_cache_override" or "@cdnca_cache_follow"
    name = name .. stale
    if ignore_vary then
        name = name .. "_nv"
    end
    if slice > 0 then
        name = name .. "_s" .. (slice / 1024)
    end
    return name
end

-- rule_settings(plan, route, rule): edgecache Plan.ruleSettings
local function rule_settings(plan, route, rule)
    route.ignore_query = rule.ignore_query == true
    route.slice_bytes = plan.slice_bytes
    if type(rule.no_cache) == "table" and #rule.no_cache > 0 then
        route.no_cache = rule.no_cache
    end
    if rule.slice_bytes == nil and rule.force_cache == nil and rule.ignore_vary ~= true then
        return
    end
    local override = plan.mode == "override"
    if rule.force_cache ~= nil then
        override = rule.force_cache == true
    end
    if rule.slice_bytes ~= nil then
        route.slice_bytes = slice_variant(rule.slice_bytes)
    end
    route.variant = variant_name(override, plan.stale, rule.ignore_vary == true, route.slice_bytes)
    -- a bypassed request of the rule runs unsliced
    route.bypass_variant = variant_name(override, plan.stale, rule.ignore_vary == true, 0)
end

-- route_of(plan, candidates): the route of a candidate set, cached by its
-- signature; may_cache (edgecache Route.MayCache): it or a set its
-- content_types rules can leave caches.
local function route_of(plan, candidates)
    local signature = concat(candidates, ",")
    local route = plan.routes[signature]
    if route then
        return route, signature
    end
    local deciding = plan.policy.rules[candidates[1]]
    local sliced = plan.slice_bytes > 0
    if deciding.slice_bytes ~= nil then
        sliced = slice_variant(deciding.slice_bytes) > 0
    end
    route = decide(plan.policy, candidates, sliced)
    rule_settings(plan, route, deciding)
    route.may_cache = route.cache
    route.typed = false
    for _, index in ipairs(candidates) do
        if plan.rules[index].content_types then
            route.typed = true
        end
    end
    if route.typed then
        for _, set in ipairs(subsets(candidates, function(index) return plan.rules[index].content_types ~= nil end)) do
            if not route.may_cache and #set < #candidates then
                route.may_cache = decide(plan.policy, set, sliced).cache
            end
        end
    end
    plan.routes[signature] = route
    return route, signature
end

local function zone_index(prefix)
    if config.zones == 0 then
        return nil
    end
    local value = tonumber(sub(prefix, 1, 8), 16)
    return bit.band(value, config.zones - 1)
end

-- plan(site): the site's compiled cache plan, nil when the site does not cache.
local function build_plan(site)
    local cache = site.cache
    if type(cache) ~= "table" or type(cache.policy) ~= "table" or cache.policy.mode == "disabled" then
        return false
    end
    local policy = cache.policy
    local plan = {
        key_prefix = cache.key_prefix, generation = cache.generation, domain = cache.domain,
        key_by_host = cache.key_by_host == true, mode = policy.mode, query_mode = policy.query_mode,
        query_names = policy.query_names or {}, vary_headers = policy.vary_headers or {},
        projected = policy.query_mode ~= "preserve" or #(policy.vary_headers or {}) ~= 0,
        rules = {}, has_rules = #(policy.rules or {}) ~= 0, policy = policy,
        range = site.range == true,
        quota_bytes = policy.disk_quota_bytes,
        slice_bytes = slice_variant(policy.slice_bytes),
        stale_if_error = policy.stale_if_error == true, background_update = policy.background_update == true,
        min_object_bytes = tonumber(policy.min_object_bytes) or 0, max_object_bytes = tonumber(policy.max_object_bytes) or 0,
    }
    -- edgecache.Plan.Variant
    local base = policy.mode == "override" and "@cdnca_cache_override" or "@cdnca_cache_follow"
    plan.stale = ""
    if plan.stale_if_error then
        plan.stale = plan.background_update and "_stalebg" or "_stale"
        base = base .. plan.stale
    end
    plan.bypass_variant = base
    plan.variant = plan.slice_bytes > 0 and (base .. "_s" .. (plan.slice_bytes / 1024)) or base
    plan.size_bounds = plan.min_object_bytes > 0 or plan.max_object_bytes > 0
    for index, rule in ipairs(policy.rules or {}) do
        plan.rules[index] = {
            path_prefix = rule.path_prefix or "", extensions = rule.extensions,
            path_regex = rule.path_regex ~= "" and rule.path_regex or nil,
            content_types = compile_types(rule.content_types),
            path_exact = rule.path_exact ~= "" and rule.path_exact or nil,
        }
    end
    local zone = zone_index(plan.key_prefix)
    plan.zone = zone and ("cdnca_cache_" .. zone .. config.zone_suffix) or nil
    if not plan.has_rules then
        local status, any = simple_ttls(policy)
        plan.simple = { cache = true, ttls = ttl_value(slice_ttls(status, plan.slice_bytes > 0), any), browsers = "" }
    end
    plan.routes = {}
    return plan
end

function _M.plan(site, digest)
    local plan = plans:get(digest)
    if plan == nil then
        plan = build_plan(site)
        plans:set(digest, plan)
    end
    return plan or nil
end

-- key projection (cachepolicy/key.lua, same frames and digests)
local function add_frame(frames, tag, value)
    frames[#frames + 1] = tag .. ":" .. #value .. ":" .. value .. ";"
end

local function digest_frames(frames)
    local digest = resty_sha256:new()
    for _, frame in ipairs(frames) do
        digest:update(frame)
    end
    return to_hex(digest:final())
end

local function valid_percent(value)
    local index = 1
    while index <= #value do
        if byte(value, index) == 37 then
            if index + 2 > #value or not match(sub(value, index + 1, index + 2), "^[0-9A-Fa-f][0-9A-Fa-f]$") then
                return false
            end
            index = index + 3
        else
            index = index + 1
        end
    end
    return true
end

local function decode_name(value)
    return (value:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex, 16)) end))
end

local function query_digest(mode, names)
    local request_uri = ngx_var.request_uri or ""
    local marker = find(request_uri, "?", 1, true)
    local present, raw = marker ~= nil, marker and sub(request_uri, marker + 1) or ""
    if #raw > MAX_RAW_QUERY_BYTES or not valid_percent(raw) then
        return nil
    end
    local frames = {}
    add_frame(frames, "schema", "cdnca-cache-query-v1")
    add_frame(frames, "mode", mode)
    if mode == "ignore" then
        add_frame(frames, "state", "ignored")
        return digest_frames(frames)
    end
    add_frame(frames, "state", present and (#raw == 0 and "empty" or "present") or "absent")
    if mode == "preserve" then
        if present and #raw > 0 then
            add_frame(frames, "raw", raw)
        end
        return digest_frames(frames)
    end
    if not present or #raw == 0 then
        return digest_frames(frames)
    end
    local selected = {}
    for _, name in ipairs(names) do
        selected[name] = true
    end
    local start, count = 1, 0
    while start <= #raw + 1 do
        count = count + 1
        if count > MAX_QUERY_PAIRS then
            return nil
        end
        local boundary = find(raw, "&", start, true)
        local pair
        if boundary then
            pair, start = sub(raw, start, boundary - 1), boundary + 1
        else
            pair, start = sub(raw, start), #raw + 2
        end
        local equals = find(pair, "=", 1, true)
        local keep = selected[decode_name(equals and sub(pair, 1, equals - 1) or pair)] == true
        if mode == "exclude" then
            keep = not keep
        end
        if keep then
            add_frame(frames, "pair", pair)
        end
    end
    return digest_frames(frames)
end

local function header_digest(names)
    local frames = {}
    add_frame(frames, "schema", "cdnca-cache-vary-v1")
    if #names == 0 then
        return digest_frames(frames)
    end
    local raw, header_error = ngx.req.get_headers(100, true)
    if header_error == "truncated" then
        return nil
    end
    local indexed, repeated = {}, {}
    for name, value in pairs(raw) do
        local normalized = lower(name)
        if indexed[normalized] ~= nil or type(value) == "table" then
            repeated[normalized] = true
        end
        indexed[normalized] = value
    end
    local total = 0
    for _, name in ipairs(names) do
        if repeated[name] then
            return nil
        end
        local value = indexed[name]
        add_frame(frames, "name", name)
        if value == nil then
            add_frame(frames, "state", "absent")
        elseif type(value) ~= "string" or #value > MAX_HEADER_VALUE_BYTES or total > MAX_HEADER_TOTAL_BYTES - #value then
            return nil
        else
            total = total + #value
            add_frame(frames, "state", #value == 0 and "empty" or "value")
            add_frame(frames, "value", value)
        end
    end
    return digest_frames(frames)
end

local function request_extension(uri)
    local name = match(uri, "([^/]*)$") or ""
    local extension = match(name, "(%.[^.]*)$")
    return extension and lower(extension) or ""
end

-- regex_matches(regex, uri): PCRE2 find under lua_regex_match_limit; an
-- error (the match limit) is no match
local function regex_matches(regex, uri)
    local from, _, err = ngx.re.find(uri, regex, "jo")
    if err then
        ngx.log(ngx.WARN, "cdnca cache: path_regex ", regex, ": ", err)
        return false
    end
    return from ~= nil
end

local function candidates(rules, uri)
    local extension = request_extension(uri)
    local result = {}
    for index, rule in ipairs(rules) do
        local prefix = rule.path_prefix
        local path_match
        if rule.path_exact then
            path_match = uri == rule.path_exact
        else
            path_match = prefix == "" or sub(uri, 1, #prefix) == prefix
        end
        local extension_match = rule.extensions == nil or #rule.extensions == 0 or contains(rule.extensions, extension)
        if path_match and extension_match and (not rule.path_regex or regex_matches(rule.path_regex, uri)) then
            result[#result + 1] = index
        end
    end
    return result
end

-- route(plan): the request's decision and the signature, or nil + reason
local function route_for(plan, uri)
    if not plan.has_rules then
        return plan.simple
    end
    local matched = candidates(plan.rules, uri)
    if #matched == 0 then
        return nil
    end
    return route_of(plan, matched)
end

-- cacheable(site, digest, uri): a cache rule of the site caches the URI (or
-- may, by Content-Type): the L2 cache mode's test (A19-b, L2_ROUTING;
-- 只有设了缓存的 URL 走 L2). A site that does not cache caches nothing.
function _M.cacheable(site, digest, uri)
    local plan = site and _M.plan(site, digest)
    if not plan or not plan.zone then
        return false
    end
    local route = route_for(plan, uri)
    return route ~= nil and (route.may_cache or route.cache) == true
end

-- following: the request's site follows origin redirects (ge36): every
-- dispatch goes to a location that intercepts them (<variant>_f, or
-- @cdnca_origin_follow instead of location /); a sliced variant does not
-- follow (slice subrequests cannot be redirected).
local FOLLOW_LOCATION = "@cdnca_origin_follow"

-- bypass(reason, variant, following): not read from or stored in the cache;
-- variant (a named location) proxies it with Accept-Ranges as v7's location
-- did.
-- bypass: a request the cache does not serve. The site's unbuffered
-- location (数据实时返回/发送, ngx.ctx.cdnca_unbuffered) takes it before a
-- bypass variant: neither caches, and the variant buffers.
local function bypass(reason, variant, following)
    ngx_var.cdnca_cache_zone = ""
    ngx_var.cdnca_cache_reason = reason
    if following then
        return ngx.exec(variant and (variant .. "_f") or FOLLOW_LOCATION)
    end
    local unbuffered = ngx.ctx.cdnca_unbuffered
    if unbuffered then
        return ngx.exec(unbuffered)
    end
    if variant then
        return ngx.exec(variant)
    end
end

-- prewarm_request(): a cache task prewarm from the agent: loopback peer and
-- the node prewarm token (written by the agent through the admin socket).
-- The header never reaches the origin (skeleton proxy_set_header "").
local function prewarm_request()
    local token = ngx_var.http_x_cdnca_cache_task
    if not token then
        return false
    end
    local peer = ngx_var.remote_addr
    local expected = purge:get(PREWARM)
    return (peer == "127.0.0.1" or peer == "::1") and expected ~= nil and #token == #expected and token == expected
end
_M.prewarm_request = prewarm_request

-- generation(prefix): the site's purge generation; nil until the agent has
-- loaded the generations (fail closed: do not cache).
local function generation(prefix)
    if purge:get(LOADED) ~= 1 then
        return nil
    end
    return purge:get(prefix) or 0
end
_M.generation = generation

function _M.policy_key(plan, ignore_query)
    local uri = ngx_var.uri or ""
    if not plan.projected and not ignore_query then
        return uri .. (ngx_var.is_args or "") .. (ngx_var.args or "")
    end
    local query = query_digest(ignore_query and "ignore" or plan.query_mode, ignore_query and {} or plan.query_names)
    local vary = header_digest(plan.vary_headers)
    if not query or not vary then
        return nil
    end
    return uri .. "?~q=" .. query .. "&~v=" .. vary
end

-- condition_value(condition): the request value a 不缓存条件 reads ("" when
-- absent; a repeated header joined with ", ").
local function condition_value(condition)
    local source = condition.source
    local value
    if source == "uri" then
        value = ngx_var.request_uri
    elseif source == "path" then
        value = ngx_var.uri
    elseif source == "client_ip" then
        -- the visitor behind an L1's trusted hop, else the peer
        local origin = package.loaded["cdnca_origin"]
        value = origin and origin.hop_visitor and origin.hop_visitor() or ngx_var.remote_addr
    elseif source == "scheme" then
        value = ngx_var.scheme
    elseif source == "args" then
        value = ngx_var.args
    elseif source == "host" then
        value = ngx_var.host
    elseif source == "header" then
        value = ngx.req.get_headers(100)[condition.name]
        if type(value) == "table" then
            value = concat(value, ", ")
        end
    end
    return value or ""
end

-- no_cache_matches(conditions): whether one of the deciding rule's
-- 不缓存条件 matches (PCRE2 under lua_regex_match_limit; an error is no
-- match, logged).
local function no_cache_matches(conditions)
    for _, condition in ipairs(conditions) do
        local from, _, err = ngx.re.find(condition_value(condition), condition.pattern, "jo")
        if err then
            ngx.log(ngx.WARN, "cdnca cache: no_cache ", condition.pattern, ": ", err)
        elseif from then
            return true
        end
    end
    return false
end

-- access(): the cache decision of this request. Idempotent: a named
-- variant re-runs the access phase.
function _M.access()
    if ngx_var.cdnca_cache_dispatched == "1" then
        return
    end
    ngx_var.cdnca_cache_dispatched = "1"
    ngx_var.cdnca_cache_range = ngx_var.http_range or ""
    ngx_var.cdnca_cache_if_range = ngx_var.http_if_range or ""
    local prewarm = prewarm_request()
    if prewarm then
        ngx_var.cdnca_cache_prewarm = "1"
    end
    local site = site_mod.current()
    -- 响应头显示缓存状态: X-CDN-Cache and
    -- X-CDN-Cache-Reason only for a site whose object carries
    -- cache_status_header (published off at attack escalation B and above);
    -- the agent's prewarm always gets them (cache task verification)
    if prewarm or (site ~= nil and site.cache_status_header == true) then
        ngx_var.cdnca_cache_show = "1"
    end
    -- cdnca_origin is loaded by the entry module (cdnca_dynroute)
    local origin_mod = package.loaded["cdnca_origin"] or package.loaded["dynroute.cdnca_origin"]
    local following = site ~= nil and origin_mod ~= nil and origin_mod.follows(site)
    if following then
        ngx_var.cdnca_follow_hops = "0"
    end
    local unbuffered = origin_mod and origin_mod.unbuffered_location(site) or nil
    ngx.ctx.cdnca_unbuffered = unbuffered
    local plan = site and _M.plan(site, ngx_var.cdnca_site_digest)
    if not plan then
        ngx_var.cdnca_cache_zone = ""
        if following then
            return ngx.exec(FOLLOW_LOCATION)
        end
        if unbuffered then
            return ngx.exec(unbuffered)
        end
        return
    end
    ngx_var.cdnca_cache_enabled = "1"
    ngx_var.cdnca_cache_size_bypass = "0"
    ngx_var.cdnca_cache_rule_bypass = "0" -- "1": a response rule replaced it (cdnca_filters)
    -- v7: a caching site forwards Range/If-Range on a bypassed request only
    -- when range is on; a cached request never does.
    if not plan.range then
        ngx_var.cdnca_cache_range, ngx_var.cdnca_cache_if_range = "", ""
    end
    if not plan.zone then
        return bypass("disabled", nil, following)
    end
    local uri = ngx_var.uri or ""
    -- v7 bypass reasons, first cause first: method, authorization, cookie
    -- (only a request no cache rule names), upgrade, no_cache_rule.
    local route, signature = route_for(plan, uri)
    local reason
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then
        reason = "method"
    elseif ngx_var.http_authorization then
        reason = "authorization"
    elseif (not plan.has_rules or not route) and ngx_var.http_cookie then
        reason = "cookie"
    elseif ngx_var.http_upgrade then
        reason = "upgrade"
    elseif origin_mod and origin_mod.search_engine(site) then
        -- 搜索引擎回源: crawlers get their own origin's answer, never the
        -- visitors' cached one (nor do they fill it)
        reason = "search_engine"
    elseif not route or not (route.may_cache or route.cache) then
        reason = "no_cache_rule"
    elseif route.no_cache and no_cache_matches(route.no_cache) then
        reason = "no_cache_condition"
    elseif byte(uri, 1) ~= 47 then
        reason = "key"
    end
    if not route then
        -- no rule names the request: v7's bypass route
        return bypass(reason, not following and plan.range and "@cdnca_cache_bypass" or nil, following)
    end
    ngx_var.cdnca_cache_browsers = route.browsers
    -- the deciding rule's variant (route.variant) or the plan's
    local variant = route.variant or plan.variant
    local slice_bytes = route.slice_bytes or plan.slice_bytes
    if reason then
        return bypass(reason, route.bypass_variant or plan.bypass_variant, following)
    end
    local gen = generation(plan.key_prefix)
    if not gen then
        return bypass("purge_state", plan.bypass_variant, following)
    end
    local policy_key = _M.policy_key(plan, route.ignore_query)
    if not policy_key then
        return bypass("key", plan.bypass_variant, following)
    end
    local name = plan.key_by_host and ngx_var.host or plan.domain
    ngx_var.cdnca_cache_zone = plan.zone
    ngx_var.cdnca_cache_key = plan.key_prefix .. "|" .. plan.generation .. "|" .. gen .. "|" .. name .. "|"
        .. ngx_var.cdnca_site_port .. "|" .. policy_key
    ngx_var.cdnca_cache_ttls = route.ttls
    -- the request's candidate set, for the content_types decision (the
    -- header filter runs after ngx.exec cleared ngx.ctx)
    ngx_var.cdnca_cache_signature = route.typed and signature or ""
    ngx_var.cdnca_cache_reason = ""
    -- cached: the origin is asked for the whole object (or one slice) and
    -- the client's Range is cut from the cache (ge-cache D, every site)
    ngx_var.cdnca_cache_range, ngx_var.cdnca_cache_if_range = "", ""
    if following and slice_bytes == 0 then
        return ngx.exec(variant .. "_f")
    end
    if following then
        -- a sliced variant does not follow: the origin's redirect goes to
        -- the visitor as without following
        ngx_var.cdnca_follow_hops = ""
    end
    return ngx.exec(variant)
end

-- size_filter(plan): v7 cacheSizeFilterLua. On a fill (MISS/EXPIRED) an
-- object whose size (Content-Length, or a slice's Content-Range total) is
-- outside the bounds is not stored; unknown size with a maximum is not
-- stored either.
local function size_filter(plan)
    local status = ngx_var.upstream_cache_status
    if status ~= "MISS" and status ~= "EXPIRED" then
        return
    end
    local length = tonumber(match(ngx_var.upstream_http_content_range or "", "/(%d+)$") or ngx_var.upstream_http_content_length or "")
    local maximum = plan.max_object_bytes
    if (length == nil and maximum > 0) or (length ~= nil and (length < plan.min_object_bytes or (maximum > 0 and length > maximum))) then
        ngx_var.cdnca_cache_size_bypass = "1"
    end
end

-- type_filter(plan, signature): the content_types decision (ge36): the
-- request's rules whose content_types the response does not satisfy are
-- dropped; the rules left decide the TTLs and browser expiry, nothing left
-- that caches = not stored (BYPASS content_type). Run on every response,
-- a HIT included (its browser expiry follows its own Content-Type).
local function type_filter(plan, signature)
    local header = ngx.header["Content-Type"]
    local media = type(header) == "string" and lower(match(header, "^%s*([^;%s]*)") or "") or ""
    local kept = {}
    for index in signature:gmatch("%d+") do
        local types = plan.rules[tonumber(index)].content_types
        if not types or types_match(types, media) then
            kept[#kept + 1] = tonumber(index)
        end
    end
    local route = #kept > 0 and route_of(plan, kept) or nil
    if not route or not route.cache then
        ngx_var.cdnca_cache_size_bypass = "2"
        ngx_var.cdnca_cache_ttls = " any=0 "
        ngx_var.cdnca_cache_browsers = plan.policy.schema_version == 2 and " any=epoch " or ""
        return
    end
    ngx_var.cdnca_cache_ttls = route.ttls
    ngx_var.cdnca_cache_browsers = route.browsers
end

-- header_filter(): the content_types decision, the object size bounds, then
-- the prewarm identity echo (cache task verification).
function _M.header_filter()
    -- ngx.exec cleared ngx.ctx: the plan comes from the site's digest
    if ngx_var.cdnca_cache_zone ~= "" then
        local site = site_mod.current()
        local plan = site and _M.plan(site, ngx_var.cdnca_site_digest)
        local signature = ngx_var.cdnca_cache_signature
        if plan and signature and signature ~= "" then
            type_filter(plan, signature)
        end
        if plan and plan.size_bounds and ngx_var.cdnca_cache_size_bypass == "0" then
            size_filter(plan)
        end
    end
    if ngx_var.cdnca_cache_prewarm == "1" then
        ngx.header["X-Cdnca-Cache-Key"] = ngx_var.cdnca_cache_zone ~= "" and ngx_var.cdnca_cache_key or nil
        ngx.header["X-Cdnca-Site"] = ngx_var.cdnca_site_id
    end
end

-- admin(): control socket endpoints (agent only):
--   POST /cache/generations  body {"generations": {"<key_prefix>": n, ...}, "replace": bool}
--   GET  /cache/generations  -> {"loaded": bool, "count": n}
--   GET  /cache/plan?digest=<site digest> -> the compiled plan (differential test)
function _M.admin()
    local method, uri = ngx.req.get_method(), ngx_var.uri
    if uri == "/cache/generations" and method == "POST" then
        ngx.req.read_body()
        local body = cjson.decode(ngx.req.get_body_data() or "")
        if type(body) ~= "table" or type(body.generations) ~= "table" then
            return ngx.exit(400)
        end
        if body.replace == true then
            purge:flush_all()
            purge:flush_expired()
        end
        local count = 0
        for prefix, value in pairs(body.generations) do
            local number = tonumber(value)
            if type(prefix) ~= "string" or not match(prefix, "^[0-9a-f]+$") or #prefix ~= 32 or not number or number < 0 then
                return ngx.exit(400)
            end
            local ok, err = purge:safe_set(prefix, number)
            if not ok then
                ngx.status = 507
                ngx.say(cjson.encode({ error = err }))
                return ngx.exit(507)
            end
            count = count + 1
        end
        purge:safe_set(LOADED, 1)
        ngx.say(cjson.encode({ applied = count }))
        return
    end
    if uri == "/cache/prewarm-token" and method == "POST" then
        ngx.req.read_body()
        local token = ngx.req.get_body_data() or ""
        if not match(token, "^[0-9a-f]+$") or #token ~= 64 then
            return ngx.exit(400)
        end
        purge:safe_set(PREWARM, token)
        ngx.say("{}")
        return
    end
    if uri == "/cache/generations" and method == "GET" then
        ngx.say(cjson.encode({ loaded = purge:get(LOADED) == 1 }))
        return
    end
    if uri == "/cache/plan" and method == "GET" then
        local digest = ngx_var.arg_digest
        local site = digest and site_mod.site(digest)
        local plan = site and build_plan(site)
        if not plan then
            return ngx.exit(404)
        end
        local routes = {}
        if plan.has_rules then
            -- every candidate set edgecache enumerates is passed by the test
            for signature in (ngx_var.arg_signatures or ""):gmatch("[^;]+") do
                local indexes = {}
                for index in signature:gmatch("%d+") do
                    indexes[#indexes + 1] = tonumber(index)
                end
                local route = route_of(plan, indexes)
                routes[signature] = { cache = route.cache, may_cache = route.may_cache, ttls = route.ttls,
                    browsers = route.browsers, variant = route.variant or cjson.null,
                    ignore_query = route.ignore_query, no_cache = route.no_cache and #route.no_cache or 0 }
            end
        else
            routes[""] = plan.simple
        end
        ngx.say(cjson.encode({ zone = plan.zone or cjson.null, projected = plan.projected, routes = routes,
            variant = plan.variant, slice_bytes = plan.slice_bytes, min_object_bytes = plan.min_object_bytes,
            max_object_bytes = plan.max_object_bytes }))
        return
    end
    return ngx.exit(404)
end

return _M
