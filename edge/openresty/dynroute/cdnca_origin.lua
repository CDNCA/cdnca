-- Dynamic routing D5a: request-time origin selection (ADR 0009 §3.2 step 6).
--
-- Reads the request's site object (cdnca_site.current(), contract §3) and
-- does what the v7 compiler wrote as static nginx: upstream{} per pool with
-- its algorithm, passive failure accounting (max_fails/fail_timeout),
-- proxy_next_upstream retries bounded by tries and a time budget,
-- conditional origin routes (map/geo + error_page 3xx), the L2 / route
-- fallback pool (proxy_intercept_errors + error_page 502 503 504), the
-- ingress source address (proxy_bind) and per-pool connection reuse.
--
-- Algorithms are ports of nginx 1.31.1 so a site behaves as it did under v7
-- (tests/edge-golden): smooth weighted round robin
-- (ngx_http_upstream_round_robin.c), ip_hash (first 3 IPv4 bytes, 89/113/6271),
-- "hash $request_uri consistent" (ketama, 160 points per weight unit),
-- least_conn (ratio conns/weight, round robin among ties). Peer state is per
-- worker and per (site object digest, pool), as nginx keeps it per worker
-- and per upstream (a new site object, like a v7 reload, starts fresh).
-- "random" is a weighted random choice (v7 rendered "random two least_conn",
-- which is not what the name says).
--
-- What the origin receives (ge-origin forwarding, v7 origin_forwarding.go):
-- Host (visitor / chosen endpoint's host / custom), X-Forwarded-For,
-- X-Real-IP and X-Forwarded-Proto describing the edge's peer unless it is a
-- trusted proxy of the site (its chain kept and extended), Upgrade and
-- Connection for WebSocket sites; Location/Refresh naming an origin address
-- are rewritten to the visitor's host; a sticky pool issues its token;
-- endpoint levels (origin failover: from the pool's active_level, a level
-- serves only when every endpoint of the levels before it is unusable; 0 is
-- the primary), per-endpoint max_conns, follow-port, the follow-protocol
-- HTTPS pool and request-host routes as v7 renders them. HTTPS endpoints go
-- through cdnca_origintls (D5b) for the trust anchor and SNI; signed pools
-- (cdnca_originauth) are signed in access and never retried elsewhere.
--
-- Differences from v7 (deliberate): a request whose method is not in the
-- pool's retry methods (GET/HEAD) or that has a body is only sent again when
-- the previous attempt sent nothing (connect error / connect timeout); v7
-- re-sent PUT/DELETE after a read timeout and re-sent anything through the
-- fallback location. Connection reuse is keyed by D5b's connection key
-- (scheme, SNI, trust anchor, signing identity) plus site and pool (the
-- skeleton's upstream has keepalive 0, ADR 0009 PoC §3).
--
-- Phases (node-skeleton.md §3): access() resolves origin names and writes
-- $cdnca_origin_scheme/host/sni; balancer() picks every attempt; log()
-- settles the last attempt. Nothing depends on ngx.ctx surviving ngx.exec:
-- the balancer derives the route again from the request.
local balancer = require "ngx.balancer"
local lrucache = require "resty.lrucache"

local ngx = ngx
local ngx_var = ngx.var
local floor, min, max = math.floor, math.min, math.max
local sub, find, byte = string.sub, string.find, string.byte

-- The built-in search engine crawlers of 搜索引擎回源 (a site without its
-- own tokens): lower-case User-Agent substrings, the crawlers CC's trusted
-- crawler list names (libs/edgeconfig SearchEngineCrawlerTokens, same list).
local SEARCH_ENGINE_TOKENS = {
    "googlebot", "bingbot", "baiduspider", "sogou", "360spider", "yisouspider",
    "bytespider", "yandexbot", "duckduckbot", "applebot", "petalbot", "slurp",
}
local tonumber, tostring, type, ipairs, pairs = tonumber, tostring, type, ipairs, pairs
local crc32 = ngx.crc32_long

-- cdnca_site is the module the skeleton configured: it may be loaded as
-- "cdnca_site" (contract §6.2 path) or "dynroute.cdnca_site" (lua root on
-- the path); a second copy would be an unconfigured module.
local site_module
local function site()
    if not site_module then
        site_module = package.loaded["cdnca_site"] or package.loaded["dynroute.cdnca_site"]
        if not site_module then
            local ok, module = pcall(require, "cdnca_site")
            site_module = ok and module or require("dynroute.cdnca_site")
        end
    end
    return site_module
end

local _M = { _VERSION = "1" }

local config = {
    node_region = "",
    node_id = "",
    ingress_source_ipv4 = nil,
    ingress_source_ipv6 = nil,
    server_addr_outgoing = false,
    resolvers = nil,
    plan_items = 10000,
    state_items = 40000,
    keepalive_requests = 1000,
    dns_timeout_ms = 2000,
    dns_max_ttl = 3600,
    dns_stale = 300,
}
local plans, states

-- nginx upstream defaults the v7 compiler relied on
local ORIGIN_MAX_FAILS, ORIGIN_FAIL_TIMEOUT = 1, 10
local CHASH_POINTS_PER_WEIGHT = 160
local HASH_MAX_TRIES = 20

local function init_caches()
    plans = assert(lrucache.new(config.plan_items))
    states = assert(lrucache.new(config.state_items))
end

-- configure(opts) in init_by_lua, after cdnca_site.configure:
--   node_region          the node's region (routes naming other regions are dropped)
--   node_id              the node's id (lower-case UUID): L2 conditions naming
--                        L1 nodes apply only on those (A19-b, L2_ROUTING)
--   ingress_source_ipv4/6 source addresses for ingress-IP origin (FX30)
--   server_addr_outgoing  origin connections leave from the address the
--                         client reached ($server_addr, nginx proxy_bind;
--                         系统设置 > Nginx > 入口 IP 回源)
--   resolvers            nameserver addresses for origin names ({} / nil = /etc/resolv.conf)
function _M.configure(opts)
    opts = opts or {}
    config.node_region = opts.node_region or ""
    config.node_id = opts.node_id or ""
    config.ingress_source_ipv4 = (opts.ingress_source_ipv4 or "") ~= "" and opts.ingress_source_ipv4 or nil
    config.ingress_source_ipv6 = (opts.ingress_source_ipv6 or "") ~= "" and opts.ingress_source_ipv6 or nil
    config.server_addr_outgoing = opts.server_addr_outgoing == true
    config.resolvers = opts.resolvers
    config.plan_items = tonumber(opts.plan_items) or config.plan_items
    config.state_items = tonumber(opts.state_items) or config.state_items
    init_caches()
end

function _M.config()
    return config
end

------------------------------------------------------------------------
-- addresses

local function parse_ipv4(text)
    local a, b, c, d = text:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil
    end
    local bytes = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
    for _, value in ipairs(bytes) do
        if value > 255 then
            return nil
        end
    end
    return { family = 4, bytes = bytes }
end

local function ipv6_words(part)
    local out = {}
    if part == "" then
        return out
    end
    for group in (part .. ":"):gmatch("([^:]*):") do
        if find(group, ".", 1, true) then
            local v4 = parse_ipv4(group)
            if not v4 then
                return nil
            end
            out[#out + 1] = v4.bytes[1] * 256 + v4.bytes[2]
            out[#out + 1] = v4.bytes[3] * 256 + v4.bytes[4]
        elseif group:match("^%x%x?%x?%x?$") then
            out[#out + 1] = tonumber(group, 16)
        else
            return nil
        end
    end
    return out
end

local function parse_ipv6(text)
    if not find(text, ":", 1, true) then
        return nil
    end
    text = text:gsub("%%.*$", "")
    local double = find(text, "::", 1, true)
    local words
    if double then
        if find(text, "::", double + 1, true) then
            return nil
        end
        local left, right = ipv6_words(sub(text, 1, double - 1)), ipv6_words(sub(text, double + 2))
        if not left or not right or #left + #right > 7 then
            return nil
        end
        words = left
        for _ = 1, 8 - #left - #right do
            words[#words + 1] = 0
        end
        for _, word in ipairs(right) do
            words[#words + 1] = word
        end
    else
        words = ipv6_words(text)
        if not words or #words ~= 8 then
            return nil
        end
    end
    local bytes = {}
    for _, word in ipairs(words) do
        bytes[#bytes + 1] = floor(word / 256)
        bytes[#bytes + 1] = word % 256
    end
    return { family = 6, bytes = bytes }
end

local function parse_ip(text)
    if type(text) ~= "string" then
        return nil
    end
    return parse_ipv4(text) or parse_ipv6(text)
end
_M.parse_ip = parse_ip

-- nginx geo looks IPv4-mapped IPv6 clients up as IPv4.
local function unmapped(address)
    if address and address.family == 6 then
        local b = address.bytes
        for index = 1, 10 do
            if b[index] ~= 0 then
                return address
            end
        end
        if b[11] == 255 and b[12] == 255 then
            return { family = 4, bytes = { b[13], b[14], b[15], b[16] } }
        end
    end
    return address
end

-- hop_visitor(): on an L2 node, the visitor's address of an L1's trusted
-- hop (fix-l2trust: X-Cdnca-L2-Hop from a node network, cdnca_dynroute sets
-- $cdnca_l2_trusted): the X-Real-IP the L1 wrote (an address, strictly
-- parsed). nil for any other request (the peer is the client).
local function hop_visitor()
    if ngx_var.cdnca_l2_trusted ~= "1" then
        return nil
    end
    local real = ngx_var.http_x_real_ip
    if type(real) == "string" and real:match("^[0-9A-Fa-f.:]+$") and parse_ip(real) then
        return real
    end
    return nil
end
_M.hop_visitor = hop_visitor

-- client_address(): the request's client (the visitor behind an L1's
-- trusted hop, else the peer) for routes and ip_hash.
local function client_address()
    return hop_visitor() or ngx_var.remote_addr
end

local function parse_cidr(text)
    local slash = find(text, "/", 1, true)
    if not slash then
        return nil
    end
    local address = parse_ip(sub(text, 1, slash - 1))
    local bits = tonumber(sub(text, slash + 1))
    if not address or not bits then
        return nil
    end
    address.bits = bits
    return address
end

local function cidr_contains(cidr, address)
    if not address or cidr.family ~= address.family then
        return false
    end
    local bits = cidr.bits
    local index = 1
    while bits >= 8 do
        if cidr.bytes[index] ~= address.bytes[index] then
            return false
        end
        bits = bits - 8
        index = index + 1
    end
    if bits == 0 then
        return true
    end
    local unit = 2 ^ (8 - bits)
    return floor(cidr.bytes[index] / unit) == floor(address.bytes[index] / unit)
end

------------------------------------------------------------------------
-- plan: the site object's origin compiled once per digest and worker

-- sticky_token: edgesite.StickyToken (v7 siteruntimev2.stickyToken), the
-- first 12 bytes of SHA-256("cdnca-sticky-v1\0" site "\0" pool "\0" endpoint).
local resty_sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex
local function sticky_token(site_id, pool_id, endpoint_id)
    local hash = resty_sha256:new()
    hash:update("cdnca-sticky-v1\0" .. site_id .. "\0" .. pool_id .. "\0" .. endpoint_id)
    return sub(to_hex(hash:final()), 1, 24)
end

local function compile_pool(site, pool)
    local compiled = {
        id = pool.id, kind = pool.kind, algorithm = pool.algorithm,
        endpoints = {}, total_weight = 0, raw = pool,
        hash_key = pool.hash_key, sticky = pool.sticky,
        request_host = pool.request_host, follow_port = pool.follow_port == true,
    }
    local primaries, backups = 0, 0
    local active = pool.active_level or 0
    local levels, seen_level = {}, {}
    for index, endpoint in ipairs(pool.endpoints) do
        local address = parse_ip(endpoint.host)
        local level = endpoint.level or 0
        local backup = level > 0
        -- levels below the active one are skipped until the control plane
        -- moves the active level back up (auto/manual failback)
        if level >= active and not seen_level[level] then
            seen_level[level] = true
            levels[#levels + 1] = level
        end
        compiled.endpoints[index] = {
            index = index, id = endpoint.id, scheme = endpoint.scheme,
            host = endpoint.host, port = endpoint.port, weight = endpoint.weight,
            sni = endpoint.sni, sni_mode = endpoint.sni_mode, trust = endpoint.trust_anchor, node_id = endpoint.node_id,
            backup = backup, level = level, max_conns = endpoint.max_conns or 0, raw = endpoint,
            family = address and address.family or nil, hostname = address == nil,
            -- the "server" text v7 wrote; consistent hashing hashes it
            server = (address and address.family == 6 and ("[" .. endpoint.host .. "]") or endpoint.host)
                .. ":" .. endpoint.port,
        }
        if backup then
            backups = backups + 1
        else
            primaries = primaries + 1
        end
        if pool.sticky then
            compiled.tokens = compiled.tokens or {}
            compiled.tokens[sticky_token(site.site_id, pool.id, endpoint.id)] = index
        end
    end
    if #levels == 0 then
        -- an active level above every endpoint (the control plane never
        -- sends one): serve from all levels rather than from none
        for _, endpoint in ipairs(pool.endpoints) do
            local level = endpoint.level or 0
            if not seen_level[level] then
                seen_level[level] = true
                levels[#levels + 1] = level
            end
        end
    end
    table.sort(levels)
    compiled.levels = levels
    -- per level: total weight (ip_hash) and the nginx peers->single case
    compiled.level_weight, compiled.level_count = {}, {}
    for _, endpoint in ipairs(compiled.endpoints) do
        local level = endpoint.level
        compiled.level_weight[level] = (compiled.level_weight[level] or 0) + endpoint.weight
        compiled.level_count[level] = (compiled.level_count[level] or 0) + 1
    end
    compiled.total_weight = compiled.level_weight[levels[1] or 0] or 0
    -- nginx peers->single: one endpoint and no other level
    compiled.single = #levels == 1 and compiled.level_count[levels[1]] == 1 and #compiled.endpoints == 1
    local retry = pool.retry
    compiled.retry_methods = {}
    for _, method in ipairs(retry.methods) do
        compiled.retry_methods[method] = true
    end
    -- nginx: tries = number of peers, capped by proxy_next_upstream_tries
    compiled.tries = min(#compiled.endpoints, retry.max_attempts)
    compiled.connect_timeout = retry.connect_timeout_ms / 1000
    compiled.read_timeout = retry.read_timeout_ms / 1000
    compiled.budget = retry.total_budget_ms / 1000
    local l2 = site.origin.l2
    if pool.kind == "l2" and l2 then
        compiled.max_fails = l2.failure_threshold
        compiled.fail_timeout = max(1, floor((l2.probe_interval_ms + 999) / 1000))
    else
        compiled.max_fails, compiled.fail_timeout = ORIGIN_MAX_FAILS, ORIGIN_FAIL_TIMEOUT
    end
    -- v7: a pool without reuse settings closes plain connections after a
    -- WebSocket-site request ($cdnca_connection_upgrade)
    local idle = pool.keepalive_idle_timeout_ms
    compiled.close_connection = idle == nil or idle == 0
    compiled.ingress = site.origin.ingress_source == true and pool.kind == "origin"
    -- Location rewrite: the pool's origin addresses, with and without the
    -- port, as authorities (v7 writeOriginLocationRewrite)
    compiled.origin_names = {}
    local seen = {}
    for _, endpoint in ipairs(compiled.endpoints) do
        local host = endpoint.host:lower()
        if endpoint.family == 6 then
            host = "[" .. host .. "]"
        end
        for _, name in ipairs({ host, host .. ":" .. endpoint.port }) do
            if not seen[name] then
                seen[name] = true
                compiled.origin_names[#compiled.origin_names + 1] = name
            end
        end
    end
    return compiled
end

------------------------------------------------------------------------
-- L2 configuration routing (A19-b, L2_ROUTING; 节点管理 > L2配置): 模式=缓存
-- sends only a URL a cache rule caches through L2 (cdnca_cache.cacheable),
-- any other straight to the direct pool; L2 conditions send a matching
-- request (every rule, on a listed L1 node) to their L2 nodes, the nodes of
-- every matching condition together, and any other to the L2 nodes no
-- condition names (none: direct). Rule regexes are RE2 (L2-REGEX-01).

-- l2_subpool(site, pool, keep, suffix): the L2 pool with only the endpoints
-- keep names, in pool order (member sort order); nil when none. The id is
-- the pool's with a suffix: peer state is per derived pool.
local function l2_subpool(site, pool, keep, suffix)
    local raw = {}
    for key, value in pairs(pool) do
        raw[key] = value
    end
    raw.id = pool.id .. "#" .. suffix
    raw.endpoints = {}
    for _, endpoint in ipairs(pool.endpoints) do
        if keep[endpoint.id] then
            raw.endpoints[#raw.endpoints + 1] = endpoint
        end
    end
    if #raw.endpoints == 0 then
        return nil
    end
    return compile_pool(site, raw)
end

local L2_NEGATED = { neq = "eq", not_contains = "contains", not_regex = "regex" }

local function compile_l2(site, plan)
    local l2 = site.origin.l2
    if not l2 or (not l2.cache_only and not (l2.conditions and #l2.conditions > 0)) then
        return nil
    end
    local pool = plan.default_pool.raw
    local compiled = { cache_only = l2.cache_only == true, site = site, pool = pool, unions = {} }
    if not l2.conditions or #l2.conditions == 0 then
        compiled.default_pool = plan.default_pool
        return compiled
    end
    compiled.conditions = {}
    local named = {}
    for index, condition in ipairs(l2.conditions) do
        local entry = { index = index, endpoints = {}, rules = {} }
        for _, id in ipairs(condition.endpoint_ids) do
            entry.endpoints[id] = true
            named[id] = true
        end
        if condition.node_ids and #condition.node_ids > 0 then
            entry.here = false
            for _, id in ipairs(condition.node_ids) do
                if id == config.node_id then
                    entry.here = true
                    break
                end
            end
        else
            entry.here = true
        end
        for _, rule in ipairs(condition.rules or {}) do
            local operator = L2_NEGATED[rule.operator] or rule.operator
            local value = rule.value
            -- the host is lower case; the scheme "http" / "https"
            if operator ~= "regex" and (rule.field == "host" or rule.field == "protocol") then
                value = value:lower()
            end
            entry.rules[#entry.rules + 1] = { field = rule.field, operator = operator, value = value,
                negated = L2_NEGATED[rule.operator] ~= nil }
        end
        -- a condition for other L1 nodes never matches here
        if entry.here then
            compiled.conditions[#compiled.conditions + 1] = entry
        end
    end
    local rest = {}
    for _, endpoint in ipairs(pool.endpoints) do
        if not named[endpoint.id] then
            rest[endpoint.id] = true
        end
    end
    compiled.default_pool = l2_subpool(site, pool, rest, "default")
    return compiled
end

local function l2_request_value(field)
    if field == "host" then
        return ngx_var.host or ""
    elseif field == "request_uri" then
        return ngx_var.request_uri or ""
    elseif field == "uri" then
        return ngx_var.uri or ""
    elseif field == "protocol" then
        return ngx_var.scheme or ""
    end
    return nil
end

-- l2_rule_matches(rule): a regex the match limit stops matches nothing,
-- negated or not (as the control plane's node rules)
local function l2_rule_matches(rule)
    local value = l2_request_value(rule.field)
    if value == nil then
        return false
    end
    local operator, pattern, matched = rule.operator, rule.value, false
    if operator == "eq" then
        matched = value == pattern
    elseif operator == "contains" then
        matched = find(value, pattern, 1, true) ~= nil
    elseif operator == "prefix" then
        matched = sub(value, 1, #pattern) == pattern
    elseif operator == "suffix" then
        matched = #value >= #pattern and sub(value, -#pattern) == pattern
    elseif operator == "regex" then
        local from, _, err = ngx.re.find(value, pattern, "jo")
        if err then
            ngx.log(ngx.WARN, "cdnca origin: L2 condition regex ", pattern, ": ", err)
            return false
        end
        matched = from ~= nil
    else
        return false
    end
    return matched ~= rule.negated
end

local function l2_condition_matches(condition)
    for _, rule in ipairs(condition.rules) do
        if not l2_rule_matches(rule) then
            return false
        end
    end
    return true
end

local function l2_cacheable(plan)
    local cache = package.loaded["cdnca_cache"] or package.loaded["dynroute.cdnca_cache"]
    if not cache then
        return false -- no cache module: nothing is cached on this node
    end
    return cache.cacheable(plan.site, plan.digest, ngx_var.uri or "")
end

-- l2_route(plan): the request's pool, fallback and route id under the L2
-- configuration
local function l2_route(plan)
    local l2 = plan.l2
    if l2.cache_only and not l2_cacheable(plan) then
        return plan.default_fallback, nil, "l2_direct"
    end
    if l2.conditions then
        local matched
        for _, condition in ipairs(l2.conditions) do
            if l2_condition_matches(condition) then
                matched = matched or {}
                matched[#matched + 1] = condition
            end
        end
        if matched then
            local signature = {}
            for index, condition in ipairs(matched) do
                signature[index] = condition.index
            end
            signature = table.concat(signature, ",")
            local pool = l2.unions[signature]
            if not pool then
                local keep = {}
                for _, condition in ipairs(matched) do
                    for id in pairs(condition.endpoints) do
                        keep[id] = true
                    end
                end
                pool = l2_subpool(l2.site, l2.pool, keep, "c" .. signature)
                l2.unions[signature] = pool
            end
            return pool, plan.default_fallback, "l2_condition"
        end
    end
    if not l2.default_pool then
        return plan.default_fallback, nil, "l2_direct"
    end
    return l2.default_pool, plan.default_fallback, "default"
end

local function compile(site)
    local origin = site.origin
    local plan = { pools = {}, routes = {}, site_id = site.site_id, site = site }
    for _, pool in ipairs(origin.pools) do
        plan.pools[pool.id] = compile_pool(site, pool)
    end
    plan.default_pool = plan.pools[origin.default_pool_id]
    if origin.https_pool_id then
        plan.https_pool = plan.pools[origin.https_pool_id]
    end
    if origin.l2 then
        plan.default_fallback = plan.pools[origin.l2.direct_fallback_pool_id]
        plan.l2 = compile_l2(site, plan)
        -- L2_ROUTING v2: pass-through hops (the visitor's protocol and port)
        -- and this node as an endpoint of the site's L2 pool: it is the L2,
        -- it goes straight to the origin (never to another L2)
        plan.l2_passthrough = origin.l2.passthrough == true
        for _, endpoint in ipairs(plan.default_pool.endpoints) do
            if config.node_id ~= "" and endpoint.node_id == config.node_id then
                plan.l2_self = true
            end
        end
    elseif origin.default_fallback_pool_id then
        plan.default_fallback = plan.pools[origin.default_fallback_pool_id]
    end
    -- v7 drops routes of other regions when compiling (compileSiteRoutes)
    for _, route in ipairs(origin.routes or {}) do
        local regions = route.node_regions
        local here = regions == nil or #regions == 0
        if not here then
            for _, region in ipairs(regions) do
                if region == config.node_region then
                    here = true
                    break
                end
            end
        end
        if here then
            local cidrs
            if route.client_cidrs and #route.client_cidrs > 0 then
                cidrs = {}
                for _, text in ipairs(route.client_cidrs) do
                    cidrs[#cidrs + 1] = assert(parse_cidr(text), "route CIDR")
                end
            end
            local hosts
            if route.hosts and #route.hosts > 0 then
                hosts = { exact = {}, suffixes = {} }
                for _, name in ipairs(route.hosts) do
                    if sub(name, 1, 2) == "*." then
                        hosts.suffixes[#hosts.suffixes + 1] = sub(name, 2) -- ".x"
                    else
                        hosts.exact[name] = true
                    end
                end
            end
            plan.routes[#plan.routes + 1] = {
                id = route.id, path = route.path_prefix, cidrs = cidrs, hosts = hosts,
                pool = plan.pools[route.pool_id],
                fallback = route.fallback_pool_id and plan.pools[route.fallback_pool_id] or nil,
            }
        end
    end
    plan.auth = {}
    for _, auth in ipairs(origin.auth or {}) do
        plan.auth[auth.pool_id] = auth
    end
    if origin.trusted_proxy_cidrs and #origin.trusted_proxy_cidrs > 0 then
        plan.trusted = {}
        for _, text in ipairs(origin.trusted_proxy_cidrs) do
            plan.trusted[#plan.trusted + 1] = assert(parse_cidr(text), "trusted proxy CIDR")
        end
    end
    -- search engine origin (搜索引擎回源, SITE_EDGE_OPTIONS)
    local engine = origin.search_engine
    if engine then
        local tokens = engine.tokens
        if not tokens or #tokens == 0 then
            tokens = SEARCH_ENGINE_TOKENS
        end
        plan.search_engine = { pool = plan.pools[engine.pool_id], tokens = tokens }
    end
    plan.unbuffered = {}
    for _, direction in ipairs(origin.unbuffered or {}) do
        plan.unbuffered[direction] = true
    end
    plan.acme_passthrough = origin.acme_passthrough == true
    plan.websocket = site.websocket == true
    if site.websocket_origins and #site.websocket_origins > 0 then
        plan.websocket_origins = {}
        for _, value in ipairs(site.websocket_origins) do
            plan.websocket_origins[value:lower()] = true
        end
    end
    return plan
end

-- plan_for(site, digest): the compiled plan of a site object, cached per
-- worker by digest (contract §3: derived structures keyed by digest).
local function plan_for(current, digest)
    if not plans then
        init_caches()
    end
    local plan = plans:get(digest)
    if not plan then
        plan = compile(current)
        plan.digest = digest
        plans:set(digest, plan)
    end
    return plan
end
_M.plan_for = plan_for

local function current_plan()
    local current = site().current()
    if not current then
        return nil
    end
    return plan_for(current, ngx_var.cdnca_site_digest), current
end
_M.compile = compile

-- path_matches(prefix, path): path segment prefix on the normalized $uri
-- (the WAF rule plan's "prefix", D6): "/api" matches "/api" and "/api/...",
-- never "/apiary"; "/api/" (a trailing slash) matches "/api/..." only;
-- "/" matches every path. v7 matched a byte prefix of $request_uri
-- (/api matched /apiary): a defect, fixed here and on the v7 side by
-- ge-origin (tests/edge-golden/cdnca-v7/compare.json semantic_changes).
local function path_matches(prefix, path)
    local length = #prefix
    if sub(path, 1, length) ~= prefix then
        return false
    end
    return #path == length or byte(prefix, length) == 47 or byte(path, length + 1) == 47 -- "/"
end
_M.path_matches = path_matches

-- select(plan): primary pool, fallback pool, route id: routes in order
-- (path prefix, request host and client CIDR all required when present);
-- the first match wins. With no route, a TLS listener uses the site's
-- follow-protocol HTTPS pool when it has one.
-- search_engine_request(plan): the request's User-Agent names one of the
-- site's search engine crawlers (lower-case substring, as CC's trusted
-- crawler tokens); at most 12 substring searches, so not memoized.
local function search_engine_request(plan)
    local engine = plan.search_engine
    if not engine or not engine.pool then
        return false
    end
    local agent = ngx_var.http_user_agent
    if type(agent) ~= "string" or agent == "" then
        return false
    end
    agent = agent:lower()
    for _, token in ipairs(engine.tokens) do
        if find(agent, token, 1, true) then
            return true
        end
    end
    return false
end

local function route_of(plan)
    -- search engine crawlers go to their own origin before any route
    if search_engine_request(plan) then
        return plan.search_engine.pool, nil, "search_engine"
    end
    local routes = plan.routes
    if #routes > 0 then
        local uri = ngx_var.uri or "/"
        local client
        for _, route in ipairs(routes) do
            local matched = true
            if route.path and not path_matches(route.path, uri) then
                matched = false
            end
            if matched and route.hosts then
                local host = ngx_var.host or ""
                matched = route.hosts.exact[host] == true
                if not matched then
                    for _, suffix in ipairs(route.hosts.suffixes) do
                        if #host > #suffix and sub(host, -#suffix) == suffix then
                            matched = true
                            break
                        end
                    end
                end
            end
            if matched and route.cidrs then
                client = client or unmapped(parse_ip(client_address())) or false
                matched = false
                for _, cidr in ipairs(route.cidrs) do
                    if cidr_contains(cidr, client or nil) then
                        matched = true
                        break
                    end
                end
            end
            if matched then
                return route.pool, route.fallback, route.id
            end
        end
    end
    if plan.https_pool and ngx_var.https == "on" then
        return plan.https_pool, nil, "https"
    end
    if plan.l2 then
        return l2_route(plan)
    end
    return plan.default_pool, plan.default_fallback, "default"
end

-- L2 loop guard (L2_ROUTING v2): an L2 never forwards to another L2. On a
-- node that is an endpoint of the site's L2 pool (l2_self), or for a
-- request an L1 marked as an L2 hop (X-Cdnca-L2-Hop, the skeleton replaces
-- a visitor's own), an L2 pool becomes the direct pool.
local function select_route(plan)
    local pool, fallback, route = route_of(plan)
    if pool.kind == "l2" and plan.default_fallback then
        if plan.l2_self then
            return plan.default_fallback, nil, "l2_self"
        elseif ngx_var.http_x_cdnca_l2_hop == "1" then
            return plan.default_fallback, nil, "l2_hop"
        end
    end
    return pool, fallback, route
end
_M.select_route = select_route

------------------------------------------------------------------------
-- origin names (v7: nginx resolver with ipv6=off, re-resolved by TTL)

local dns_cache = {}
local dns_nameservers

local function nameservers()
    if config.resolvers and #config.resolvers > 0 then
        return config.resolvers
    end
    if dns_nameservers then
        return dns_nameservers
    end
    local list = {}
    local file = io.open("/etc/resolv.conf", "rb")
    if file then
        for line in file:lines() do
            local value = line:match("^%s*nameserver%s+([^%s#]+)")
            if value and parse_ip(value) then
                list[#list + 1] = value
            end
        end
        file:close()
    end
    dns_nameservers = list
    return list
end

local function resolve(hostname)
    local now = ngx.now()
    local entry = dns_cache[hostname]
    if entry and now < entry.expires then
        return true
    end
    local servers = nameservers()
    if #servers == 0 then
        return entry ~= nil and now < entry.stale
    end
    local resolver = require("resty.dns.resolver"):new({
        nameservers = servers, retrans = 2, timeout = config.dns_timeout_ms,
    })
    local answers = resolver and resolver:query(hostname, { qtype = resolver.TYPE_A })
    local addresses, ttl = {}, nil
    if type(answers) == "table" and not answers.errcode then
        for _, answer in ipairs(answers) do
            if answer.type == resolver.TYPE_A and answer.address then
                addresses[#addresses + 1] = answer.address
                ttl = ttl and min(ttl, answer.ttl) or answer.ttl
            end
        end
    end
    if #addresses == 0 then
        if entry and now < entry.stale then
            entry.expires = now + 1
            return true
        end
        ngx.log(ngx.WARN, "cdnca origin: cannot resolve ", hostname)
        return false
    end
    ttl = min(max(ttl or 1, 1), config.dns_max_ttl)
    dns_cache[hostname] = {
        addresses = addresses, next = 0,
        expires = now + ttl, stale = now + ttl + config.dns_stale,
    }
    return true
end

local function resolved(hostname)
    local entry = dns_cache[hostname]
    return entry ~= nil and ngx.now() < entry.stale
end

local function resolved_address(hostname)
    local entry = dns_cache[hostname]
    if not entry or ngx.now() >= entry.stale then
        return nil
    end
    entry.next = entry.next % #entry.addresses + 1
    return entry.addresses[entry.next]
end

------------------------------------------------------------------------
-- peer state and the nginx algorithms

local function peer_states(plan, pool)
    local key = plan.digest .. "\0" .. pool.id
    local list = states:get(key)
    if not list then
        list = {}
        for index, endpoint in ipairs(pool.endpoints) do
            list[index] = {
                current_weight = 0, effective_weight = endpoint.weight,
                fails = 0, accessed = 0, checked = 0, conns = 0,
            }
        end
        states:set(key, list)
    end
    return list
end

local function new_phase(plan, pool)
    return {
        pool = pool, peers = peer_states(plan, pool), tried = {},
        attempts = 0, started = ngx.now(),
        hash = nil, hash_tries = 0,
        -- the level being tried (pool.levels index); nginx peers->next:
        -- the next level once none of this one is usable
        level_index = 1, level = pool.levels[1] or 0,
    }
end

-- usable(phase, i, now): not tried in this phase, not failed out, resolvable
local function usable(phase, index, now, ignore_fails)
    if phase.tried[index] then
        return false
    end
    local endpoint = phase.pool.endpoints[index]
    if endpoint.level ~= phase.level then
        return false
    end
    if endpoint.hostname and not resolved(endpoint.host) then
        return false
    end
    local peer = phase.peers[index]
    if endpoint.max_conns > 0 and peer.conns >= endpoint.max_conns then
        return false
    end
    if ignore_fails then
        return true
    end
    local pool = phase.pool
    return not (pool.max_fails > 0 and peer.fails >= pool.max_fails and now - peer.checked <= pool.fail_timeout)
end

local function chosen(phase, index, now)
    local peer = phase.peers[index]
    phase.tried[index] = true
    if now - peer.checked > phase.pool.fail_timeout then
        peer.checked = now
    end
    peer.conns = peer.conns + 1
    return index
end

-- ngx_http_upstream_get_peer (smooth weighted round robin)
local function round_robin(phase, now)
    local pool, peers = phase.pool, phase.peers
    if pool.single then
        -- a single peer ignores max_fails (peers->single)
        if not usable(phase, 1, now, true) then
            return nil
        end
        phase.tried[1] = true
        peers[1].conns = peers[1].conns + 1
        return 1
    end
    local best, total = nil, 0
    for index, endpoint in ipairs(pool.endpoints) do
        if usable(phase, index, now) then
            local peer = peers[index]
            peer.current_weight = peer.current_weight + peer.effective_weight
            total = total + peer.effective_weight
            if peer.effective_weight < endpoint.weight then
                peer.effective_weight = peer.effective_weight + 1
            end
            if best == nil or peer.current_weight > peers[best].current_weight then
                best = index
            end
        end
    end
    if not best then
        return nil
    end
    peers[best].current_weight = peers[best].current_weight - total
    return chosen(phase, best, now)
end

local function client_hash_bytes()
    local address = parse_ip(client_address())
    if not address then
        return { 0, 0, 0 } -- ngx_http_upstream_ip_hash_pseudo_addr
    end
    if address.family == 4 then
        return { address.bytes[1], address.bytes[2], address.bytes[3] }
    end
    return address.bytes
end

-- ngx_http_upstream_get_ip_hash_peer
local function ip_hash(phase, now)
    local pool = phase.pool
    if phase.hash_tries > HASH_MAX_TRIES or (pool.level_count[phase.level] or 0) < 2 then
        return round_robin(phase, now)
    end
    local total_weight = pool.level_weight[phase.level]
    local bytes = phase.client_bytes or client_hash_bytes()
    phase.client_bytes = bytes
    local hash = phase.hash or 89
    while true do
        for _, value in ipairs(bytes) do
            hash = (hash * 113 + value) % 6271
        end
        -- the weight walk over this level's endpoints (one level: nginx's)
        local w = hash % total_weight
        local index = 1
        while pool.endpoints[index].level ~= phase.level or w >= pool.endpoints[index].weight do
            if pool.endpoints[index].level == phase.level then
                w = w - pool.endpoints[index].weight
            end
            index = index + 1
        end
        if usable(phase, index, now) then
            phase.hash = hash
            return chosen(phase, index, now)
        end
        phase.hash_tries = phase.hash_tries + 1
        if phase.hash_tries > HASH_MAX_TRIES then
            return round_robin(phase, now)
        end
    end
end

local function le32(value)
    return string.char(value % 256, floor(value / 256) % 256, floor(value / 65536) % 256, floor(value / 16777216) % 256)
end

-- ngx_http_upstream_update_chash: crc32(host "\0" port prev_hash), 160
-- points per weight unit, sorted, equal hashes collapsed
-- (per level: a level's ring holds only its endpoints)
local function chash_points(pool, level)
    level = level or 0
    pool.points = pool.points or {}
    if pool.points[level] then
        return pool.points[level]
    end
    local list = {}
    for _, endpoint in ipairs(pool.endpoints) do
      if endpoint.level == level then
        local colon = endpoint.server:match("^.*():")
        local base = sub(endpoint.server, 1, colon - 1) .. "\0" .. sub(endpoint.server, colon + 1)
        local previous = 0
        for _ = 1, endpoint.weight * CHASH_POINTS_PER_WEIGHT do
            local hash = crc32(base .. le32(previous))
            list[#list + 1] = { hash = hash, server = endpoint.server }
            previous = hash
        end
      end
    end
    table.sort(list, function(a, b) return a.hash < b.hash end)
    local points = { hash = {}, server = {} }
    for _, point in ipairs(list) do
        local n = #points.hash
        if n == 0 or points.hash[n] ~= point.hash then
            points.hash[n + 1] = point.hash
            points.server[n + 1] = point.server
        end
    end
    pool.points[level] = points
    return points
end

-- first point >= hash (0-based index, may equal the count)
local function find_point(points, hash)
    local low, high = 0, #points.hash
    while low < high do
        local middle = floor((low + high) / 2)
        local value = points.hash[middle + 1]
        if hash > value then
            low = middle + 1
        elseif hash < value then
            high = middle
        else
            return middle
        end
    end
    return low
end

-- hash_key_value(template): the pool's hash key with its variables
-- expanded (edgesite.ValidHashKey allows only request variables).
local function hash_key_value(template)
    return (template:gsub("%$([a-z_][a-z0-9_]*)", function(name)
        return ngx_var[name] or ""
    end))
end
_M._hash_key_value = hash_key_value

-- ngx_http_upstream_get_chash_peer ("hash <key> consistent": url_hash's key
-- is $request_uri, hash's the pool's template)
local function consistent_hash(phase, now, key_of)
    local pool, peers = phase.pool, phase.peers
    if phase.hash_tries > HASH_MAX_TRIES or pool.single then
        return round_robin(phase, now)
    end
    local points = chash_points(pool, phase.level)
    if phase.hash == nil then
        local key = key_of(phase)
        if key == "" then
            -- nginx: an empty key is round robin
            return round_robin(phase, now)
        end
        phase.hash = find_point(points, crc32(key))
    end
    local count = #points.hash
    while true do
        local server = points.server[phase.hash % count + 1]
        local best, total = nil, 0
        for index, endpoint in ipairs(pool.endpoints) do
            if endpoint.server == server and usable(phase, index, now) then
                local peer = peers[index]
                peer.current_weight = peer.current_weight + peer.effective_weight
                total = total + peer.effective_weight
                if peer.effective_weight < endpoint.weight then
                    peer.effective_weight = peer.effective_weight + 1
                end
                if best == nil or peer.current_weight > peers[best].current_weight then
                    best = index
                end
            end
        end
        if best then
            peers[best].current_weight = peers[best].current_weight - total
            return chosen(phase, best, now)
        end
        phase.hash = phase.hash + 1
        phase.hash_tries = phase.hash_tries + 1
        if phase.hash_tries > HASH_MAX_TRIES then
            return round_robin(phase, now)
        end
    end
end

local function request_uri_key()
    return ngx_var.request_uri or ""
end

local function template_key(phase)
    return hash_key_value(phase.pool.hash_key)
end

local function url_hash(phase, now)
    return consistent_hash(phase, now, request_uri_key)
end

local function key_hash(phase, now)
    return consistent_hash(phase, now, template_key)
end

-- ngx_http_upstream_get_least_conn_peer
local function least_conn(phase, now)
    local pool, peers = phase.pool, phase.peers
    if pool.single then
        return round_robin(phase, now)
    end
    local endpoints = pool.endpoints
    local best, many
    for index in ipairs(endpoints) do
        if usable(phase, index, now) then
            local peer = peers[index]
            if best == nil or peer.conns * endpoints[best].weight < peers[best].conns * endpoints[index].weight then
                best, many = index, false
            elseif peer.conns * endpoints[best].weight == peers[best].conns * endpoints[index].weight then
                many = true
            end
        end
    end
    if not best then
        return nil
    end
    local total = 0
    if many then
        for index = best, #endpoints do
            local peer = peers[index]
            if usable(phase, index, now)
                and peer.conns * endpoints[best].weight == peers[best].conns * endpoints[index].weight then
                peer.current_weight = peer.current_weight + peer.effective_weight
                total = total + peer.effective_weight
                if peer.effective_weight < endpoints[index].weight then
                    peer.effective_weight = peer.effective_weight + 1
                end
                if peer.current_weight > peers[best].current_weight then
                    best = index
                end
            end
        end
    end
    peers[best].current_weight = peers[best].current_weight - total
    return chosen(phase, best, now)
end

local seeded = false
-- weighted random among usable peers
local function random(phase, now)
    if not seeded then
        math.randomseed(ngx.now() * 1000 + ngx.worker.pid())
        seeded = true
    end
    local pool = phase.pool
    local total, candidates = 0, {}
    for index, endpoint in ipairs(pool.endpoints) do
        if usable(phase, index, now, pool.single) then
            candidates[#candidates + 1] = index
            total = total + endpoint.weight
        end
    end
    if total == 0 then
        return nil
    end
    local point = math.random() * total
    for _, index in ipairs(candidates) do
        point = point - pool.endpoints[index].weight
        if point < 0 then
            return chosen(phase, index, now)
        end
    end
    return chosen(phase, candidates[#candidates], now)
end

-- sticky_presented(pool): the endpoint index the visitor's token names
-- (cookie, header or query argument named sticky.name), or nil
local function sticky_presented(pool)
    local name = pool.sticky.name:gsub("-", "_")
    local prefix = pool.sticky.source == "cookie" and "cookie_" or pool.sticky.source == "header" and "http_" or "arg_"
    local token = ngx_var[prefix .. name]
    return token and pool.tokens[token] or nil
end

-- sticky: the presented endpoint first; without one (or when it is not
-- usable) the pool's weighted round robin, as v7's per-origin upstreams
-- (that origin primary, the others backup). The first endpoint chosen for
-- a visitor without a token is the one whose token header_filter issues.
local function sticky(phase, now)
    if phase.presented == nil then
        phase.presented = sticky_presented(phase.pool) or false
    end
    if phase.presented and not phase.tried[phase.presented] and usable(phase, phase.presented, now, true) then
        return chosen(phase, phase.presented, now)
    end
    return round_robin(phase, now)
end

local ALGORITHMS = {
    round_robin = round_robin, ip_hash = ip_hash, url_hash = url_hash,
    least_conn = least_conn, random = random, hash = key_hash, sticky = sticky,
}

-- select(phase, now): the algorithm within the phase's level; when none of
-- its endpoints is usable, the next level (origin failover), as nginx
-- switches to peers->next once no primary is usable. A level reached this
-- way stays for the rest of the request's attempts; the next request starts
-- again from the pool's first (active) level, so a recovered level serves
-- again once its passive fail_timeout has passed.
local function select_endpoint(phase, now)
    local pool = phase.pool
    while true do
        local index = ALGORITHMS[pool.algorithm](phase, now)
        if index then
            return index
        end
        local next_level = pool.levels[phase.level_index + 1]
        if next_level == nil then
            return nil
        end
        phase.level_index = phase.level_index + 1
        phase.level = next_level
        phase.hash, phase.hash_tries = nil, 0
    end
end
_M._select_endpoint = select_endpoint

-- ngx_http_upstream_free_round_robin_peer
local function free_peer(phase, index, failed, now)
    local pool, peer = phase.pool, phase.peers[index]
    peer.conns = max(0, peer.conns - 1)
    if pool.single then
        peer.fails = 0
        return
    end
    if failed then
        peer.fails = peer.fails + 1
        peer.accessed = now
        peer.checked = now
        if pool.max_fails > 0 then
            peer.effective_weight = max(0, peer.effective_weight - floor(pool.endpoints[index].weight / pool.max_fails))
        end
    elseif peer.accessed < peer.checked then
        peer.fails = 0
    end
end

-- for tests: run one selection outside a request (no conns bookkeeping)
_M._algorithms = ALGORITHMS
_M._new_phase = new_phase
_M._free_peer = free_peer
_M._find_point = find_point
_M._chash_points = chash_points

------------------------------------------------------------------------
-- request phases

-- previous_attempt_value($upstream_bytes_sent): the value of the attempt
-- that just failed. When the balancer runs again nginx has already opened
-- the next attempt's state, which prints nothing yet ("113 : " or
-- "0, 113 : "), so the last number is the failed attempt's.
local function previous_attempt_value(text)
    if type(text) ~= "string" then
        return nil
    end
    local value
    for number in text:gmatch("%d+") do
        value = number
    end
    return tonumber(value)
end

local function bodyless()
    local length = tonumber(ngx_var.http_content_length or "0") or 0
    return length == 0 and (ngx_var.http_transfer_encoding or "") == ""
end

------------------------------------------------------------------------
-- what the origin receives (v7 siteruntimev2 origin_forwarding.go)

local function default_port(scheme)
    return scheme == "https" and 443 or 80
end

local function public_port()
    return tonumber(ngx_var.cdnca_site_port) or tonumber(ngx_var.proxy_protocol_server_port or ngx_var.server_port)
end

-- endpoint_port: the endpoint's own port, or the listener's public port
-- for a follow-port pool
local function endpoint_port(pool, endpoint)
    if pool.follow_port then
        return public_port() or endpoint.port
    end
    return endpoint.port
end

local function bracketed(endpoint)
    if endpoint.family == 6 then
        return "[" .. endpoint.host .. "]"
    end
    return endpoint.host
end

-- request_host(pool, endpoint): the Host header (v7 poolRequestHost)
local function request_host(pool, endpoint)
    local followed = ngx_var.cdnca_follow_host
    if followed and followed ~= "" then
        -- a cross-origin redirect followed (ge36): its host on this pool
        return followed
    end
    local mode = pool.request_host
    if mode and mode.mode == "custom" then
        return mode.value
    elseif mode and mode.mode == "origin" then
        local host = bracketed(endpoint)
        if pool.follow_port or endpoint.port == default_port(endpoint.scheme) then
            return host
        end
        return host .. ":" .. endpoint.port
    elseif mode and mode.mode == "visitor_port" then
        -- 访问域名+端口: the visitor's host with the port it visited
        -- (always, i.e. $host:$server_port)
        local port = public_port()
        if port then
            return ngx_var.host .. ":" .. port
        end
    end
    return ngx_var.host
end

-- tls_name(pool, endpoint): the SNI and verified name (edgesite
-- Pool.TLSName): by the endpoint's sni_mode (cdnca_origintls.name: custom
-- sni / origin_host / visitor_host, nil = unusable, the attempt fails);
-- without one v7 poolTLSName: the endpoint's SNI, else the request Host
-- without its port
local function tls_name(pool, endpoint)
    if endpoint.sni_mode then
        return require("cdnca_origintls").name(endpoint)
    end
    if endpoint.sni and endpoint.sni ~= "" then
        return endpoint.sni
    end
    local mode = pool.request_host
    if mode and mode.mode == "custom" then
        local name = mode.value
        if sub(name, 1, 1) == "[" then
            return sub(name, 2, find(name, "]", 1, true) - 1)
        end
        return (name:gsub(":%d+$", ""))
    elseif mode and mode.mode == "origin" then
        return endpoint.host
    end
    local followed = ngx_var.cdnca_follow_host
    return followed and followed ~= "" and followed or ngx_var.host
end

-- hop_endpoint(plan, site, pool, endpoint): the endpoint an attempt uses.
-- A pass-through L2 pool (L2_ROUTING v2) is reached on the protocol and
-- port the visitor's request came in on: HTTPS sends the visitor's SNI (else
-- the Host) and verifies the L2 presents this site's own certificate of
-- that listener (trust "l2:<certificate version>", cdnca_origintls.verify);
-- the L2 serves the same site object and goes to the origin by the site's
-- origin settings. Any other endpoint is itself.
local function hop_endpoint(plan, current, pool, endpoint)
    if pool.kind ~= "l2" or not plan.l2_passthrough then
        return endpoint
    end
    local view = {}
    for key, value in pairs(endpoint) do
        view[key] = value
    end
    view.port = public_port() or endpoint.port
    view.sni, view.sni_mode, view.trust = nil, nil, nil
    if ngx_var.https == "on" then
        view.scheme = "https"
        local name = ngx_var.ssl_server_name
        if not name or name == "" then
            name = ngx_var.host
        end
        view.sni = name
        local listener = current and require("cdnca_tls").listener_for(current, view.port)
        -- no TLS listener on this port: "l2:" fails the attempt (direct fallback)
        view.trust = "l2:" .. (listener and listener.tls and listener.tls.certificate_version_id or "")
    else
        view.scheme = "http"
    end
    return view
end
_M._hop_endpoint = hop_endpoint

local function trusted_peer(plan)
    if not plan.trusted then
        return false
    end
    local peer = unmapped(parse_ip(ngx_var.remote_addr))
    for _, cidr in ipairs(plan.trusted) do
        if cidr_contains(cidr, peer) then
            return true
        end
    end
    return false
end

-- client_ip(): the visitor's address by the site's trusted proxy chain, the
-- address forwarded() sends as X-Real-IP: a trusted peer's X-Real-IP when it
-- is a valid address, else the peer ($remote_addr: TCP peer or the PROXY
-- protocol source of a dispatched socket). Telemetry logs it (D12,
-- docs/edge/dynroute-telemetry.md §2.3); unlike forwarded() it parses the
-- header strictly, a log line must carry a valid IP.
function _M.client_ip()
    local visitor = hop_visitor()
    if visitor then
        return visitor -- an L1's hop: the L1 resolved the visitor
    end
    local peer = ngx_var.remote_addr or ""
    local plan = current_plan()
    if not plan or not trusted_peer(plan) then
        return peer
    end
    local real = ngx_var.http_x_real_ip
    if type(real) == "string" and real:match("^[0-9A-Fa-f.:]+$") and parse_ip(real) then
        return real
    end
    return peer
end

-- forwarded(plan, pool): X-Forwarded-For, X-Real-IP, X-Forwarded-Proto for
-- the pool. An origin pool describes the edge's peer: the client's own
-- values are replaced unless the peer is a trusted proxy of the site (its
-- chain kept and extended, its X-Real-IP kept when it is an address). An
-- L2 hop is described the same way (the L2 takes the visitor from it); an
-- L2 serving an L1's trusted hop passes the L1's description on. "" =
-- header not sent.
local function forwarded(plan, pool)
    -- a cache prewarm (the agent's loopback task, D8) is not a visitor: v7's
    -- prewarm location sends no client address headers
    local prewarm = package.loaded["cdnca_cache"]
    if prewarm and prewarm.prewarm_request() then
        return "", "", ""
    end
    -- an L1's trusted hop on this L2 (fix-l2trust): the L1 described the
    -- visitor (X-Forwarded-For with the visitor first, X-Real-IP the
    -- visitor); the origin gets that, the L1 is not appended
    local visitor = hop_visitor()
    if visitor then
        local chain = ngx_var.http_x_forwarded_for
        local proto = ngx_var.http_x_forwarded_proto
        if proto ~= "http" and proto ~= "https" then
            proto = ngx_var.scheme
        end
        return chain and chain ~= "" and chain or visitor, visitor, proto
    end
    -- an origin pool and an L2 hop (every L2 pool: the L2 trusts what the L1
    -- says, fix-l2trust) describe the visitor: a visitor's own headers are
    -- only kept from a trusted proxy of the site
    local peer = ngx_var.remote_addr or ""
    if trusted_peer(plan) then
        local chain = ngx_var.http_x_forwarded_for
        local real = ngx_var.http_x_real_ip
        if not (real and real:match("^[0-9A-Fa-f.:]+$")) then
            real = peer
        end
        return chain and chain ~= "" and (chain .. ", " .. peer) or peer, real, ngx_var.scheme
    end
    return peer, peer, ngx_var.scheme
end

_M._forwarded = forwarded

-- connection(plan, pool): Upgrade and Connection (v7 writeProxyLocationHost):
-- a WebSocket site forwards an upgrade; a pool that reuses connections
-- keeps a plain request's connection, any other closes it.
local function upgrade_headers(plan, pool)
    if not plan.websocket then
        return "", ""
    end
    local upgrade = ngx_var.http_upgrade or ""
    if upgrade ~= "" then
        return upgrade, "upgrade"
    end
    return "", pool.close_connection and "close" or ""
end

-- request variables of an attempt; true when any changed (the upstream
-- request was built with the old values and must be rebuilt)
local function write_request(plan, pool, endpoint)
    local values = { request_host(pool, endpoint) }
    values[2], values[3], values[4] = forwarded(plan, pool)
    values[5], values[6] = upgrade_headers(plan, pool)
    values[7] = pool.kind == "l2" and "1" or "" -- X-Cdnca-L2-Hop (L2_ROUTING v2)
    local names = { "cdnca_origin_host", "cdnca_origin_xff", "cdnca_origin_real_ip", "cdnca_origin_proto",
        "cdnca_origin_upgrade", "cdnca_origin_connection", "cdnca_origin_l2_hop" }
    local changed = false
    for index, name in ipairs(names) do
        local value = values[index] or ""
        if ngx_var[name] ~= value then
            ngx_var[name] = value
            changed = true
        end
    end
    return changed
end

local function websocket_refused(plan)
    if not plan.websocket_origins then
        return false
    end
    if (ngx_var.http_upgrade or ""):lower() ~= "websocket" then
        return false
    end
    local origin = ngx_var.http_origin
    if not origin or origin == "" then
        return false -- not a browser (v7 allows it too)
    end
    return not plan.websocket_origins[origin:lower()]
end

-- access(): name resolution may yield here (not in the balancer); the
-- variables proxy_pass, Host, the forwarding headers and proxy_ssl_name
-- read are written for the first choice; the balancer rewrites them (and
-- rebuilds the upstream request) when an attempt needs other values.
function _M.access()
    local plan, current = current_plan()
    if not plan then
        return
    end
    if websocket_refused(plan) then
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    local pool, fallback = select_route(plan)
    local endpoint = hop_endpoint(plan, current, pool, pool.endpoints[1])
    ngx_var.cdnca_origin_scheme = endpoint.scheme
    write_request(plan, pool, endpoint)
    ngx_var.cdnca_origin_sni = endpoint.scheme == "https" and tls_name(pool, endpoint) or ""
    -- (nil from an unusable visitor host: "", the balancer fails the attempt)
    for _, candidate in ipairs({ pool, fallback }) do
        for _, value in ipairs(candidate.endpoints) do
            if value.hostname then
                resolve(value.host)
            end
        end
    end
    if plan.auth[pool.id] then
        -- origin request signing (D5b): sets the Host to the bucket and
        -- ends the request when it cannot sign
        local ok = require("cdnca_originauth").sign(current, pool.id)
        if not ok then
            return
        end
        ngx.ctx.cdnca_origin_signed_pool = pool.id
    end
end

local function exit_status(status)
    return ngx.exit(status and status >= 300 and status or ngx.HTTP_BAD_GATEWAY)
end

-- the reuse key: D5b's connection-level key (edgesite.KeepaliveKey: scheme,
-- SNI, trust anchor, signing identity) and the site and pool, so an idle
-- connection is only ever reused within its pool.
local origintls
local function peer(ctx, pool, endpoint, address, port)
    local tls = endpoint.scheme == "https"
    local view = { scheme = endpoint.scheme, host = endpoint.host, port = port,
        sni = tls and tls_name(pool, endpoint) or nil, trust_anchor = endpoint.trust }
    if tls then
        origintls = origintls or require("cdnca_origintls")
        if not view.sni then
            return nil, "no usable SNI"
        end
        ngx_var.cdnca_origin_sni = view.sni
        ngx_var.cdnca_origin_trust = view.trust_anchor or ""
        -- trust "none" (不校验源站证书, ORIGIN_TLS_NO_VERIFY): no host name
        -- check for this attempt (native patch 29); any other turns it on
        local ok, err = origintls.set_host_check(view.trust_anchor ~= "none")
        if not ok then
            return nil, err
        end
    else
        ngx_var.cdnca_origin_sni = ""
        pcall(function() ngx_var.cdnca_origin_trust = "" end)
    end
    local ok, err = balancer.set_upstream_tls(tls)
    if not ok then
        return nil, err
    end
    local key
    if tls then
        key = origintls.key(ctx.site, pool.raw, view)
    else
        key = "http||-|" .. (ctx.plan.auth[pool.id] and (ctx.plan.auth[pool.id].secret.id .. "@" ..
            string.format("%d", ctx.plan.auth[pool.id].secret.revision)) or "-")
    end
    key = key .. "|" .. ctx.plan.site_id .. "|" .. pool.id
    ok, err = balancer.set_current_peer(address, port, key)
    if not ok then
        return nil, err
    end
    local idle = pool.raw.keepalive_idle_timeout_ms
    if idle == nil or idle > 0 then
        ok, err = balancer.enable_keepalive((idle or 60000) / 1000, config.keepalive_requests)
        if not ok then
            return nil, err
        end
    end
    return true
end

-- balancer(): one call per attempt (balancer_by_lua).
function _M.balancer()
    local now = ngx.time()
    local ctx = ngx.ctx.cdnca_origin
    if not ctx then
        local plan, current = current_plan()
        if not plan then
            ngx.log(ngx.ERR, "cdnca origin: balancer reached without a selected site")
            return ngx.exit(ngx.ERROR)
        end
        local pool, fallback, route = select_route(plan)
        local method = ngx_var.request_method
        ctx = {
            plan = plan, site = current, route = route,
            phase = new_phase(plan, pool), fallback = fallback,
            -- only these may be sent twice (format: bodyless GET/HEAD)
            idempotent = pool.retry_methods[method] == true and bodyless(),
        }
        ngx.ctx.cdnca_origin = ctx
    else
        -- nginx came back for another attempt: the previous one failed
        local state, status = balancer.get_last_failure()
        local previous = ctx.last
        ctx.last = nil
        if previous then
            free_peer(previous.phase, previous.index, state == "failed", now)
        end
        if not ctx.idempotent and (previous_attempt_value(ngx_var.upstream_bytes_sent) or 0) > 0 then
            -- non-idempotent request already (partly) sent: never again
            return exit_status(status)
        end
        local phase = ctx.phase
        if phase.attempts >= phase.pool.tries or ngx.now() - phase.started >= phase.pool.budget then
            if not ctx.fallback then
                return exit_status(status)
            end
            ctx.phase = new_phase(ctx.plan, ctx.fallback)
            ctx.fallback = nil
        end
    end

    local index
    while true do
        local phase = ctx.phase
        index = select_endpoint(phase, now)
        if index then
            break
        end
        -- no live peer (nginx: "no live upstreams", 502); v7's fallback
        -- location took over on that 502 as on any other
        if not ctx.fallback then
            ngx.log(ngx.ERR, "cdnca origin: no live origin in pool ", phase.pool.id)
            return exit_status(ngx.HTTP_BAD_GATEWAY)
        end
        ctx.phase = new_phase(ctx.plan, ctx.fallback)
        ctx.fallback = nil
    end

    local phase = ctx.phase
    local pool = phase.pool
    local endpoint = hop_endpoint(ctx.plan, ctx.site, pool, pool.endpoints[index])
    phase.attempts = phase.attempts + 1
    ctx.last = { phase = phase, index = index }
    if (ngx_var.cdnca_follow_hops or "") ~= "" then
        -- a redirect answer re-enters through error_page, which clears ngx.ctx
        ngx_var.cdnca_origin_attempt = pool.id .. "|" .. index
    end
    if ctx.issue == nil then
        -- a sticky pool pins a visitor that presented no token to the first
        -- endpoint chosen (header_filter sends the token)
        ctx.issue = pool.sticky and not phase.presented and
            sticky_token(ctx.plan.site_id, pool.id, endpoint.id) or false
        ctx.issue_pool = pool
    end
    local signed = ngx.ctx.cdnca_origin_signed_pool
    if signed and signed ~= pool.id then
        -- the request was signed for another pool's bucket (D5b): never
        -- send its signature elsewhere
        ngx.log(ngx.ERR, "cdnca origin: signed request cannot move from pool ", signed, " to ", pool.id)
        return exit_status(ngx.HTTP_BAD_GATEWAY)
    end

    local address = endpoint.hostname and resolved_address(endpoint.host) or endpoint.host
    local family = endpoint.family or 4
    if family == 6 then
        address = "[" .. address .. "]"
    end

    -- Another attempt may follow (nginx decides whether the failure is a
    -- next_upstream condition; for POST/PATCH/LOCK that reached the origin
    -- it is not, and the origin's answer passes through as under v7). A
    -- request outside the pool's retry methods that was already sent is
    -- refused when the balancer comes back, so it is never sent twice.
    if phase.attempts < pool.tries or ctx.fallback then
        balancer.set_more_tries(1)
    end
    local ok, err = balancer.set_timeouts(pool.connect_timeout, nil, pool.read_timeout)
    if not ok then
        ngx.log(ngx.ERR, "cdnca origin: timeouts: ", err)
        return ngx.exit(ngx.ERROR)
    end
    ngx_var.cdnca_origin_pool = pool.id
    if not signed and write_request(ctx.plan, pool, endpoint) then
        -- nginx built the upstream request before the balancer ran
        ok, err = balancer.recreate_request()
        if not ok then
            ngx.log(ngx.ERR, "cdnca origin: rebuild request: ", err)
            return ngx.exit(ngx.ERROR)
        end
    end
    local port = endpoint_port(pool, endpoint)
    ok, err = peer(ctx, pool, endpoint, address, port)
    if not ok then
        ngx.log(ngx.ERR, "cdnca origin: peer ", address, ":", port, ": ", err)
        return ngx.exit(ngx.ERROR)
    end
    if pool.ingress then
        local source = family == 6 and config.ingress_source_ipv6 or config.ingress_source_ipv4
        if not source then
            -- v7 refused to compile this; never connect from the wrong address
            ngx.log(ngx.ERR, "cdnca origin: ingress-IP origin without an IPv", family, " source")
            return exit_status(ngx.HTTP_BAD_GATEWAY)
        end
        ok, err = balancer.bind_to_local_addr(source)
        if not ok then
            ngx.log(ngx.ERR, "cdnca origin: bind ", source, ": ", err)
            return exit_status(ngx.HTTP_BAD_GATEWAY)
        end
    elseif config.server_addr_outgoing and pool.kind == "origin" then
        -- the address the client reached, when it is of the origin's family
        -- (a client on IPv6 reaching an IPv4 origin keeps the default route;
        -- a unix socket listener has no address to bind)
        local local_addr = ngx_var.server_addr
        local parsed = local_addr and (parse_ipv4(local_addr) or parse_ipv6(local_addr))
        if parsed and parsed.family == family then
            ok, err = balancer.bind_to_local_addr(local_addr)
            if not ok then
                ngx.log(ngx.ERR, "cdnca origin: bind ", local_addr, ": ", err)
                return exit_status(ngx.HTTP_BAD_GATEWAY)
            end
        end
    end
end

-- rewrite_location(value, names): v7 proxy_redirect for each origin
-- authority "~*^<scheme>://<authority>(?:/(.*))?$" -> $scheme://$http_host/$1
-- (anchored: example.com.evil or example.com@evil never match).
-- location_authority(value, names): the length of "<scheme>://<name>" when
-- value names one of the origin authorities, else nil
local function location_authority(value, names)
    local lower = value:lower()
    for _, scheme in ipairs({ "http://", "https://" }) do
        if sub(lower, 1, #scheme) == scheme then
            local rest = sub(lower, #scheme + 1)
            for _, name in ipairs(names) do
                if rest == name or (sub(rest, 1, #name) == name and byte(rest, #name + 1) == 47) then
                    return #scheme + #name
                end
            end
        end
    end
    return nil
end
_M._rewrite_location_match = function(value, names) return location_authority(value, names) ~= nil end

local function rewrite_location(value, names)
    local length = location_authority(value, names)
    if not length then
        return nil
    end
    return ngx_var.scheme .. "://" .. (ngx_var.http_host or ngx_var.host) .. "/" .. sub(value, length + 2)
end
_M._rewrite_location = rewrite_location


-- header_filter(): Location / Refresh naming an origin's own address go
-- back to the visitor's host; a sticky pool's token for a new visitor.
function _M.header_filter()
    local ctx = ngx.ctx.cdnca_origin
    if not ctx or not ctx.last then
        return
    end
    local pool = ctx.last.phase.pool
    if pool.kind == "origin" then
        local names = pool.origin_names
        local location = ngx.header["Location"]
        if type(location) == "string" then
            local rewritten = rewrite_location(location, names)
            if rewritten then
                ngx.header["Location"] = rewritten
            end
        end
        local refresh = ngx.header["Refresh"]
        if type(refresh) == "string" then
            local head, url = refresh:match("^(.-[Uu][Rr][Ll]=)(.*)$")
            local rewritten = url and rewrite_location(url, names)
            if rewritten then
                ngx.header["Refresh"] = head .. rewritten
            end
        end
    end
    local issue_pool = ctx.issue_pool
    if ctx.issue and issue_pool and issue_pool.sticky and issue_pool.sticky.source ~= "arg" then
        if issue_pool.sticky.source == "cookie" then
            local cookie = issue_pool.sticky.name .. "=" .. ctx.issue .. "; Path=/; HttpOnly; SameSite=Lax"
            local existing = ngx.header["Set-Cookie"]
            if existing == nil then
                ngx.header["Set-Cookie"] = cookie
            elseif type(existing) == "table" then
                existing[#existing + 1] = cookie
                ngx.header["Set-Cookie"] = existing
            else
                ngx.header["Set-Cookie"] = { existing, cookie }
            end
        else
            ngx.header[issue_pool.sticky.name] = ctx.issue
        end
    end
end

-- log(): settle the last attempt (nginx frees the peer when the request
-- finishes: a failed connection or timeout counts against it).
function _M.log()
    local ctx = ngx.ctx.cdnca_origin
    local last = ctx and ctx.last
    if not last then
        return
    end
    ctx.last = nil
    if (ngx_var.cdnca_follow_hops or "") ~= "" then
        ngx_var.cdnca_origin_attempt = ""
    end
    local header_time = ngx_var.upstream_header_time or ""
    local failed = header_time:match("%-%s*$") ~= nil
    free_peer(last.phase, last.index, failed, ngx.time())
end

------------------------------------------------------------------------
-- origin redirect following (ge36, ORIGIN_FOLLOW_REDIRECT)

-- follows(site): the site follows origin redirects and this request may:
-- a bodyless GET/HEAD without an upgrade and not a cache prewarm.
-- search_engine(site): this request goes to the site's search engine
-- origin; the cache neither serves nor stores it (cdnca_cache).
function _M.search_engine(site)
    if not site or not site.origin or not site.origin.search_engine then
        return false
    end
    return search_engine_request(plan_for(site, ngx_var.cdnca_site_digest))
end

-- unbuffered_location(site): the named location proxying this site's
-- request without buffering (数据实时返回/发送), or nil. Only a request
-- the cache does not serve is moved there (the cache needs buffering).
function _M.unbuffered_location(site)
    local directions = site and site.origin and site.origin.unbuffered
    if not directions or #directions == 0 then
        return nil
    end
    local response, request = false, false
    for _, direction in ipairs(directions) do
        response = response or direction == "response"
        request = request or direction == "request"
    end
    if response and request then
        return "@cdnca_unbuffered_both"
    end
    return response and "@cdnca_unbuffered_response" or "@cdnca_unbuffered_request"
end

-- acme_origin(): content of @cdnca_acme_origin, the ACME HTTP-01 request
-- the node holds no token for (try_files fallback): proxied to the origin
-- when the site passes ACME through (源站申请证书), else 404 as before.
function _M.acme_origin_allowed()
    local current = site().current()
    return current ~= nil and current.origin ~= nil and current.origin.acme_passthrough == true
end

function _M.follows(site)
    local redirect = site and site.origin and site.origin.follow_redirect
    if type(redirect) ~= "table" then
        return false
    end
    local method = ngx_var.request_method
    if method ~= "GET" and method ~= "HEAD" or not bodyless() or ngx_var.http_upgrade then
        return false
    end
    local cache = package.loaded["cdnca_cache"]
    return not (cache and cache.prewarm_request())
end

-- follow_target(plan, location): the path and query a Location sends the
-- request to, nil when it names another host the site does not follow to.
-- Same origin: no authority, the request's host, a site host (primary,
-- alias, "*." wildcard) or an endpoint of the request's pool (with or
-- without its port); cross_origin follows any other http(s) host, which
-- becomes the request's Host on the pool's endpoints.
local function follow_target(plan, location, cross)
    if type(location) ~= "string" or #location == 0 or #location > 4096 or location:find("[%z\1-\32\127]") then
        return nil
    end
    local path, host
    if byte(location, 1) == 47 and byte(location, 2) ~= 47 then -- "/x", not "//host"
        path = location
    else
        local scheme, authority, rest = location:match("^([Hh][Tt][Tt][Pp][Ss]?)://([^/?#]+)(.*)$")
        if not scheme or authority:find("@", 1, true) then
            return nil
        end
        local name = authority:lower()
        local bare = name:match("^%[([^%]]+)%]") or name:match("^([^:]+)")
        local ok = name == (ngx_var.http_host or ""):lower() or bare == (ngx_var.host or "")
        local hosts = plan.site.hosts
        if not ok and hosts then
            ok = bare == hosts.primary
            for _, alias in ipairs(hosts.aliases or {}) do
                if ok then break end
                if sub(alias, 1, 2) == "*." then
                    ok = #bare > #alias - 1 and sub(bare, -(#alias - 1)) == sub(alias, 2)
                else
                    ok = bare == alias
                end
            end
        end
        if not ok then
            local pool = select_route(plan)
            for _, origin_name in ipairs(pool.origin_names or {}) do
                if name == origin_name then
                    ok = true
                    break
                end
            end
        end
        host = ""
        if not ok then
            if not cross then
                return nil
            end
            host = bare
        end
        path = rest == "" and "/" or rest
        if byte(path, 1) == 63 then -- "?q": the root with a query
            path = "/" .. path
        end
    end
    path = path:gsub("#.*$", "")
    local uri, args = path:match("^([^?]*)%??(.*)$")
    if not uri or uri == "" or byte(uri, 1) ~= 47 then
        return nil
    end
    local decoded = ngx.unescape_uri(uri)
    if decoded:find("%z") then
        return nil
    end
    return decoded, args, host
end

-- refuse(location, status, plan): the redirect goes to the visitor (not
-- followed), its Location rewritten as any origin redirect, never stored.
local function refuse(location, status, plan)
    ngx.status = status
    if type(location) == "string" then
        local rewritten = rewrite_location(location, select_route(plan).origin_names or {})
        ngx.header["Location"] = rewritten or location
    end
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Length"] = 0
    ngx.send_headers()
    return ngx.exit(ngx.HTTP_OK)
end

-- settle_redirected(plan): the attempt that answered the redirect is done
-- (error_page cleared ngx.ctx, so log() will not free it).
local function settle_redirected(plan)
    local attempt = ngx_var.cdnca_origin_attempt
    if not attempt or attempt == "" then
        return
    end
    ngx_var.cdnca_origin_attempt = ""
    local pool_id, index = attempt:match("^(.*)|(%d+)$")
    local pool = pool_id and plan.pools[pool_id]
    if pool and pool.endpoints[tonumber(index)] then
        free_peer({ pool = pool, peers = peer_states(plan, pool) }, tonumber(index), false, ngx.time())
    end
end

-- follow(site): the access phase of a follow location or variant
-- ($cdnca_follow_hops set by the cache dispatch). The first pass does
-- nothing; a re-entry (error_page of the origin's 30x) moves the request to
-- the Location, or returns the redirect when it may not be followed (hops
-- exhausted, another host without cross_origin, unusable Location). A cache
-- variant re-entered from a stored 30x has no upstream Location: the same
-- URI is fetched again with the cache lookup skipped ($cdnca_cache_follow).
function _M.follow(site)
    if (ngx_var.upstream_status or "") == "" and (ngx_var.upstream_cache_status or "") == "" then
        return
    end
    local plan = current_plan()
    settle_redirected(plan)
    local status = tonumber((ngx_var.upstream_status or ""):match("(%d+)%s*$") or "") or 302
    local location = ngx_var.upstream_http_location
    local refetch = ngx_var.cdnca_cache_follow ~= "1"
    ngx_var.cdnca_cache_follow = "1"
    if location == nil then
        if refetch and (ngx_var.upstream_cache_status or "") ~= "" and (ngx_var.upstream_status or "") == "" then
            return
        end
        return refuse(nil, status, plan)
    end
    local redirect = site.origin.follow_redirect
    local count = (tonumber(ngx_var.cdnca_follow_hops) or 0) + 1
    ngx_var.cdnca_follow_hops = tostring(count)
    if count > redirect.max_hops then
        return refuse(location, status, plan)
    end
    local uri, args, host = follow_target(plan, location, redirect.cross_origin == true)
    if not uri then
        return refuse(location, status, plan)
    end
    if host ~= nil then
        -- "" for an absolute same-origin Location, the host for a cross-origin
        -- one; a relative Location stays on the current host
        ngx_var.cdnca_follow_host = host
    end
    ngx.req.set_uri(uri)
    ngx.req.set_uri_args(args or "")
end

-- current_peer(): this attempt's pool and endpoint, for the origin TLS
-- verification and origin auth (D5b) in later phases of the same attempt.
function _M.current_peer()
    local ctx = ngx.ctx.cdnca_origin
    local last = ctx and ctx.last
    if not last then
        return nil
    end
    local pool = last.phase.pool
    return {
        pool_id = pool.id, kind = pool.kind, endpoint = pool.endpoints[last.index],
        trust_anchor = pool.endpoints[last.index].trust, auth = ctx.plan.auth[pool.id],
    }
end

return _M
