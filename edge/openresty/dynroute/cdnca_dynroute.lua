-- cdnca dynamic routing entry (ADR 0009, site_runtime 9). Every phase hook of
-- the node skeleton (libs/edgeconfig/edgeskeleton) calls one function of this
-- module; the calling convention is frozen in docs/edge/node-skeleton.md §3,
-- the cross-phase contract in docs/edge/dynroute-contract.md.
--
-- Site selection is cdnca_site (D3), the TLS entry cdnca_tls (D4), origin
-- selection cdnca_origin (D5a), telemetry cdnca_telemetry (D12). Later modules (D5b origin TLS, D6/D7
-- security, D8 cache, ...) are called from the functions below in their
-- fixed order (node-skeleton.md §3).
local cdnca_site = require "cdnca_site"
local cdnca_tls = require "cdnca_tls"
local cdnca_origin = require "cdnca_origin"
-- D7 security: CC, ACL/WAF rules, firewall action, JS challenge, HTTP policy
-- from the site object (docs/edge/dynroute-security.md)
local cdnca_security = require "cdnca_security"
-- D9/D10 response filters and site limits (docs/edge/dynroute-filters.md)
local cdnca_filters = require "cdnca_filters"
local cdnca_limits = require "cdnca_limits"
local cdnca_telemetry = require "cdnca_telemetry"
-- D11 managed WAF: a site with a managed WAF runs its request in its tier
-- location (docs/edge/dynroute-managed-waf.md)
local cdnca_managed_waf = require "cdnca_managed_waf"
-- D8 cache: only when the skeleton renders a zone pool (its shared dictionary)
local cdnca_cache = ngx.shared.cdnca_cache_purge and require("cdnca_cache")
-- AD-04 auto defense gate and counters: only when the skeleton renders its
-- dictionaries (docs/edge/autodefense-contract.md §6)
local cdnca_autodefense = ngx.shared.cdnca_autodefense and require("cdnca_autodefense")
-- WebP conversion: only when the skeleton renders its
-- dictionary and thread pool (a site with access.webp)
local cdnca_webp = ngx.shared.cdnca_webp and require("cdnca_webp")

local _M = { _VERSION = "d11" }

-- L2 trust: the platform's node networks (system.ddos
-- node_networks, configure). A request marked as an L2 hop
-- (X-Cdnca-L2-Hop: 1) from one of them is an L1's: the L1 ran the site's
-- security, limits and counters and logged the visitor's request, so this
-- node only serves it ($cdnca_l2_trusted = "1", which survives ngx.exec).
-- The mark alone proves nothing (a visitor can send it): from any other peer
-- it is removed and the request is an ordinary visitor's.
local node_networks = false

-- l2_hop(): decided once in server_rewrite (trusted() reads it after).
local function l2_hop()
    local mark = ngx.var.http_x_cdnca_l2_hop
    if mark == nil then
        return
    end
    if mark == "1" and node_networks and node_networks:match(ngx.var.remote_addr) then
        ngx.var.cdnca_l2_trusted = "1"
        return
    end
    ngx.req.clear_header("X-Cdnca-L2-Hop")
end

local function trusted()
    return ngx.var.cdnca_l2_trusted == "1"
end
_M.l2_trusted = trusted

-- HTTP 302 scheduling: only when the skeleton renders it
-- (its size dictionary); site objects with schedule302 call it in access.
local cdnca_sched302 = ngx.shared.cdnca_sched302_sizes and require("cdnca_sched302")
local sched302_table
local sched302_opts = setmetatable({}, { __mode = "k" })

-- schedule302_opts: the module's options from the site object (cached per
-- site object table, which cdnca_site shares by digest).
local function schedule302_opts(site)
    local value = sched302_opts[site]
    if value == nil then
        local s = site.schedule302
        value = { site_id = site.site_id, table = sched302_table, keep_path = s.keep_path, keep_query = s.keep_query,
            ttl = s.signature_ttl_seconds, https_to_http = s.https_to_http, extensions = s.extensions or {},
            path_prefixes = s.path_prefixes or {}, min_size_bytes = s.min_size_bytes or 0 }
        sched302_opts[site] = value
    end
    return value
end

local ngx = ngx

-- Site access (v7 edgeconfig.SiteAccessServer,
-- siteruntimev2 writeForceHTTPS and siteaccess.engine): host redirects and
-- forced HTTPS in server rewrite, the maintenance page and basic auth first
-- in the client's access phase, the site's gzip in header_filter. HSTS is
-- cdnca_filters' slot 4. ACME HTTP-01 challenges pass all of them.
local ACME_PREFIX = "/.well-known/acme-challenge/"
local siteaccess = require "siteaccess.engine"

-- ngx_unhex decodes a lower-case hex string (a basic auth salt).
local function ngx_unhex(value)
    return (value:gsub("..", function(pair) return string.char(tonumber(pair, 16)) end))
end
local access_settings = setmetatable({}, { __mode = "k" })
local gzip_types = setmetatable({}, { __mode = "k" })
-- the node default when the skeleton renders per-site gzip (configure);
-- false: the skeleton left gzip to the system http{} level
local site_gzip = false
-- true when the skeleton also renders Brotli and the level variables
-- (site_brotli): the gate then picks br, gzip or nothing per request
local site_brotli = false

-- accepts(header, coding): Accept-Encoding lists the coding with a non-zero
-- q (RFC 9110 §12.5.3; "*" is not taken as br, as nginx's gzip does not).
local function accepts(header, coding)
    if type(header) == "table" then
        header = table.concat(header, ",")
    end
    if type(header) ~= "string" then
        return false
    end
    for item in header:gmatch("[^,]+") do
        local name, params = item:match("^%s*([^;%s]+)%s*(.*)$")
        if name and name:lower() == coding then
            local q = params:match(";%s*[qQ]%s*=%s*([0-9.]+)")
            return not q or (tonumber(q) or 0) > 0
        end
    end
    return false
end

local function acme()
    return ngx.var.uri:sub(1, #ACME_PREFIX) == ACME_PREFIX
end

-- redirect(site): host redirect (v7 server-level return per source host),
-- then forced HTTPS on plain listeners unless the Host is excluded. The
-- nginx special response (its html body) as v7's return.
local function redirect(site)
    local access, forced = site.access, site.force_https
    if not (access and access.host_redirects) and not forced or acme() then
        return
    end
    local host = ngx.var.host
    for _, rule in ipairs(access and access.host_redirects or {}) do
        if rule.source_host == host then
            local scheme = rule.target_scheme == "follow" and ngx.var.scheme or rule.target_scheme
            local target = scheme .. "://" .. rule.target_host
            if (rule.target_port or 0) ~= 0 then
                target = target .. ":" .. rule.target_port
            end
            return ngx.redirect(target .. (rule.preserve_uri and ngx.var.request_uri or "/"), rule.status)
        end
    end
    if not forced or ngx.var.https == "on" then
        return
    end
    for _, excluded in ipairs(forced.exclude_hosts or {}) do
        if excluded == host then
            return
        end
    end
    local target = "https://" .. host
    if forced.redirect_port ~= 443 then
        target = target .. ":" .. forced.redirect_port
    end
    local status = forced.status
    if not status or status == 0 then
        status = 301
    end
    return ngx.redirect(target .. ngx.var.request_uri, status)
end

-- the siteaccess.engine settings of a site (false: none), per site object
local function settings_of(site)
    local value = access_settings[site]
    if value ~= nil then
        return value
    end
    local access = site.access
    value = false
    if access and (access.maintenance or access.basic_auth) then
        value = {}
        local page = access.maintenance
        if page then
            value.maintenance = { status = page.status, content_type = page.content_type, body = page.body,
                retry_after = (page.retry_after_seconds or 0) > 0 and page.retry_after_seconds or nil }
            if page.allowed_cidrs and #page.allowed_cidrs > 0 then
                value.allowed = require("resty.ipmatcher").new(page.allowed_cidrs)
            end
        end
        local auth = access.basic_auth
        if auth then
            local users = {}
            for _, user in ipairs(auth.users or {}) do
                -- salt hex -> bytes once per site object (one sha256 per request)
                users[user.username] = { salt = ngx_unhex(user.salt), sha256 = user.sha256 }
            end
            value.basic_auth = { realm = auth.realm, users = users, exclude = auth.exclude_path_prefixes or {} }
            value.auth_only = { basic_auth = value.basic_auth }
        end
    end
    access_settings[site] = value
    return value
end

-- site_access(site): maintenance page (the allowed networks pass), then
-- basic auth (the credential never reaches the origin).
local function site_access(site)
    local settings = settings_of(site)
    if not settings then
        return
    end
    if settings.maintenance and settings.allowed and settings.allowed:match(ngx.var.remote_addr) then
        if not settings.basic_auth then
            return
        end
        settings = settings.auth_only
    end
    return siteaccess.access(settings)
end

-- gzip(site): the skeleton turns gzip on for every type and length; a
-- response the site's compression (or the node default) leaves plain loses
-- the request's Accept-Encoding before the gzip filter tests it.
local function gzip(site)
    local compression = site.access and site.access.compression
    local policy = gzip_types[site]
    if policy == nil then
        local source = compression or site_gzip
        local types = { ["text/html"] = true }
        for _, name in ipairs(source.types or {}) do
            types[name] = true
        end
        local encodings = { gzip = true }
        if compression and compression.encodings then
            encodings = {}
            for _, name in ipairs(compression.encodings) do
                encodings[name] = true
            end
        end
        local gzip_level = compression and tonumber(compression.gzip_level) or 0
        local brotli_level = compression and tonumber(compression.brotli_level) or 0
        policy = { enabled = compression and compression.enabled or not compression and not site_gzip.disabled,
            types = types, min = (compression and compression.min_length_bytes or site_gzip.min_length) or 0,
            proxied = compression ~= nil, br = encodings.br == true, gzip = encodings.gzip == true,
            gzip_level = gzip_level > 0 and tostring(gzip_level) or "",
            brotli_level = brotli_level > 0 and tostring(brotli_level) or "" }
        gzip_types[site] = policy
    end
    -- nginx's own test order (ngx_http_gzip_header_filter): on, type,
    -- length; Vary (gzip_vary) from here on; then the request (Via)
    local ok = policy.enabled and not ngx.header["Content-Encoding"]
    if ok then
        local mime = ngx.header["Content-Type"]
        mime = type(mime) == "string" and mime:match("^%s*([^;%s]+)")
        ok = mime ~= nil and policy.types[mime:lower()] == true
    end
    if ok then
        local length = tonumber(ngx.header["Content-Length"])
        ok = not length or length >= policy.min
    end
    local status = ngx.status
    -- a site with Brotli always varies (its br and gzip variants of one URI
    -- must not be mixed by caches); otherwise the system gzip_vary applies,
    -- as in v7
    if ok and (policy.br and site_brotli or site_gzip.vary) and (status == 200 or status == 403 or status == 404) and ngx.req.get_method() ~= "HEAD" then
        -- the skeleton's gzip_vary is off: nginx would add it to every type
        local vary = ngx.header["Vary"]
        if type(vary) == "table" then
            vary[#vary + 1] = "Accept-Encoding"
        elseif vary then
            vary = { vary, "Accept-Encoding" }
        else
            vary = "Accept-Encoding"
        end
        ngx.header["Vary"] = vary
    end
    if not (ok and (policy.proxied or not ngx.var.http_via)) then
        ngx.req.clear_header("Accept-Encoding")
        return
    end
    if not site_brotli then
        if not policy.gzip then
            ngx.req.clear_header("Accept-Encoding")
        end
        return
    end
    -- Brotli is on in every server: the request keeps exactly the coding
    -- the site takes (Brotli first), and the level of that coding
    local header = ngx.req.get_headers()["Accept-Encoding"]
    if policy.br and accepts(header, "br") then
        ngx.req.set_header("Accept-Encoding", "br")
        ngx.var.cdnca_compress_brotli_level = policy.brotli_level
    elseif policy.gzip and accepts(header, "gzip") then
        ngx.req.set_header("Accept-Encoding", "gzip")
        ngx.var.cdnca_compress_gzip_level = policy.gzip_level
    else
        ngx.req.clear_header("Accept-Encoding")
    end
end

-- compression_gate(site, opts): the header_filter compression gate alone,
-- for the real-runtime smoke (scripts/security/brotli-webp-smoke.sh); opts
-- are configure's site_gzip / site_brotli.
function _M.compression_gate(site, opts)
    site_gzip, site_brotli = opts.site_gzip, opts.site_brotli == true
    gzip(site)
end

-- configure(opts): init_by_lua (the skeleton writes the paths). One call
-- for every module the skeleton serves.
function _M.configure(opts)
    site_gzip = opts.site_gzip or false
    site_brotli = opts.site_brotli == true
    node_networks = false
    if type(opts.node_networks) == "table" and #opts.node_networks > 0 then
        node_networks = assert(require("resty.ipmatcher").new(opts.node_networks), "node networks")
    end
    cdnca_site.configure({
        objects_root = opts.objects_root,
        index_root = opts.index_root,
        system_max_body = opts.system_max_body,
        lru_items = opts.lru_items,
        unknown_site = opts.unknown_site,
        no_host = opts.no_host,
        slot_pages = opts.slot_pages,
        node_id = opts.node_id,
        node_region = opts.node_region,
    })
    cdnca_tls.configure({ pool_root = opts.tls_pool_root, lru_items = opts.certificate_lru_items })
    cdnca_origin.configure({
        node_region = opts.node_region,
        node_id = opts.node_id,
        ingress_source_ipv4 = opts.ingress_source_ipv4,
        ingress_source_ipv6 = opts.ingress_source_ipv6,
        server_addr_outgoing = opts.server_addr_outgoing,
        resolvers = opts.resolvers,
    })
    -- origin TLS and request signing (D5b), loaded on first use
    require("cdnca_origintls").configure({ system_ca_file = opts.system_ca_file })
    require("cdnca_originauth").configure({ secrets_root = opts.origin_auth_root })
    if cdnca_cache then
        cdnca_cache.configure({ zones = opts.cache_zones, zone_suffix = opts.cache_zone_suffix, lru_items = opts.lru_items })
    end
    sched302_table = opts.schedule302_table
    cdnca_managed_waf.configure({ detect_profiles = opts.managed_waf_detect, grey_profiles = opts.managed_waf_grey,
        buckets = opts.managed_waf_buckets, cookie_variants = opts.managed_waf_cookie == true })
    -- aggregated CC challenge / 429 security lines (sec-log-agg, telemetry only)
    if opts.security_aggregate then cdnca_telemetry.configure_aggregate(opts.security_aggregate) end
    cdnca_security.configure({
        challenge_root = opts.challenge_root,
        challenge_lua = opts.challenge_lua,
        challenges = opts.challenges,
        cache_items = opts.lru_items,
        rule_plan_root = opts.rule_plan_root or false,
        node_id = opts.node_id or "",
    })
    -- header_filter slots 2 and 3 (dynroute-filters.md §2, contract appendix A)
    cdnca_filters.register("http_policy", function(site) cdnca_security.header_filter(site) end)
    if cdnca_cache then
        cdnca_filters.register("cache_status", function() cdnca_cache.header_filter() end)
    end
end

function _M.init_worker()
    cdnca_site.init_worker()
    cdnca_telemetry.init_worker_aggregate()
    cdnca_limits.init_worker() -- market supply limits: TCP connection release
end

-- ssl_client_hello_by_lua / ssl_certificate_by_lua: D4 (docs/edge/dynroute-tls.md).
function _M.client_hello()
    return cdnca_tls.client_hello()
end

function _M.certificate()
    return cdnca_tls.certificate()
end

local BENCHMARK_PATH = "/.well-known/cdnca-market-benchmark"
local BENCHMARK_BYTES = 8 * 1024 * 1024
local benchmark_chunk = string.rep("cdnca-market-benchmark\n", 2731):sub(1, 65536)

-- server_rewrite_by_lua: route by (public port, Host) first (contract §2):
-- not ready -> 503 inside route(); unknown -> node location or 421; ok ->
-- the TLS decisions of the Host's site; CC (D7) follows here.
function _M.server_rewrite()
    local site = cdnca_site.route()
    if not site then
        local node = ngx.var.cdnca_node_location
        if node == "" then
            return cdnca_site.reject_unknown()
        end
        if node == "probe" and ngx.var.uri == BENCHMARK_PATH then
            -- the benchmark's limit keys (PREACCESS): an unknown Host only
            ngx.var.cdnca_probe_client = ngx.var.binary_remote_addr
            ngx.var.cdnca_probe_all = "1"
        end
        return
    end
    -- level D site (攻击自动升级 黑洞): close without a response, before any
    -- other module (shared plain HTTP ports, HTTP/3 streams)
    if cdnca_site.dropped(ngx.var.cdnca_site_host) then
        return ngx.exit(444)
    end
    l2_hop()
    if trusted() then
        -- an L1's hop: TLS checks (the L1 sends its client verification
        -- headers), package pages, redirects, traffic cap, CC and package
        -- limits all ran on the L1
        return cdnca_filters.routed()
    end
    cdnca_tls.request(site)
    -- a site whose package ended (errpage-3) answers its page, nothing else
    cdnca_limits.expired(site)
    -- host redirect / forced HTTPS: v7 server-level returns, before the
    -- traffic cap page and CC
    redirect(site)
    -- the site's own traffic cap page (D10) comes before CC
    cdnca_limits.traffic(site)
    -- CC runs in server_rewrite, before ACL/WAF and every access module
    -- (v7 order: server_rewrite_by_lua CC hook)
    local result = cdnca_security.server_rewrite(site)
    if result ~= nil then
        return result
    end
    cdnca_limits.refuse(site) -- package budget 0: 503 (v7 server-level return)
    cdnca_limits.rate(site)   -- package bandwidth share
    -- last: from here on error responses get the site's pages (D9)
    cdnca_filters.routed()
end

-- probe(): the market probe paths (skeleton writeNodeLocations). A
-- configured site's Host gets the site's access phase and the location
-- proxies it as location / does (contract §1.1: node paths are the node's
-- only for an unknown Host); otherwise the node answers: GET/HEAD only, 204
-- for the probe, the benchmark object (generated in 64 KiB chunks, v7
-- siteruntimev2 writeBenchmarkLocation). The probe server (port 80 without
-- a site, no site selection) calls it from content.
function _M.probe()
    if ngx.var.cdnca_site_state == "ok" then
        return _M.access()
    end
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then
        return ngx.exit(421)
    end
    if ngx.var.uri ~= BENCHMARK_PATH then
        return ngx.exit(204)
    end
    ngx.header["Content-Type"] = "application/octet-stream"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Length"] = BENCHMARK_BYTES
    if method == "HEAD" then
        ngx.send_headers()
        return ngx.exit(ngx.HTTP_OK)
    end
    local sent = 0
    while sent < BENCHMARK_BYTES do
        local n = math.min(#benchmark_chunk, BENCHMARK_BYTES - sent)
        if not ngx.print(n == #benchmark_chunk and benchmark_chunk or benchmark_chunk:sub(1, n)) then
            return ngx.exit(ngx.OK)
        end
        sent = sent + n
        if sent % 1048576 == 0 then ngx.flush(true) end
    end
    return ngx.exit(ngx.HTTP_OK)
end

-- client_pass(): whether this rewrite/access run is the client request's
-- own: not internal, or the managed WAF's tier location (D11), which runs
-- the request's first pass (cdnca_managed_waf.rewrite moved it there before
-- anything else). A cache variant (ngx.exec into a named location) runs
-- rewrite and access again; the security decisions were taken once.
local function client_pass()
    return not ngx.req.is_internal() or ngx.var.cdnca_waf_pass == "tier"
end

-- rewrite_by_lua: the managed WAF first (a site with one is moved to its
-- tier location: ModSecurity phase 1 runs there, then this phase again),
-- then the ACL/WAF rule plan (v7: the location's rewrite_by_lua).
function _M.rewrite()
    local site = cdnca_site.current()
    if site and client_pass() and not trusted() then
        cdnca_managed_waf.rewrite(site)
        return cdnca_security.rewrite(site)
    end
end

-- access_by_lua: origin signing, firewall action, JS challenge, HTTP policy
-- and package limits come first (later tasks); then origin selection (it
-- writes $cdnca_origin_* that proxy_pass, Host and proxy_ssl_name read); the
-- cache dispatch is last (node-skeleton.md §3): it may ngx.exec into a named
-- cache variant, whose access phase runs this again (both idempotent).
function _M.access()
    local site = cdnca_site.current()
    -- an L1's hop: counted and checked on the L1; here only
    -- the origin (and the cache) serve it
    local hop = trusted()
    if site and not hop then
        -- the site's in-flight count (independent metrics, D13-b2)
        cdnca_limits.site(site)
        -- package connections first (v7 limit_conn ran in PREACCESS);
        -- counted once, also across ngx.exec
        cdnca_limits.enter(site)
        -- the site's per-client limits (v7 limit_conn/limit_rate, PREACCESS)
        cdnca_limits.client(site)
    end
    if site and client_pass() and not hop then
        -- the client pass ends here: a cache variant entered from a tier
        -- location is an ordinary internal pass
        cdnca_managed_waf.access()
        -- maintenance page, basic auth: first in v7's location access
        site_access(site)
        -- firewall action -> JS challenge -> HTTP policy (v7
        -- writeRuntimePolicyLocation); a decision ends the request here
        local result = cdnca_security.access(site)
        if result ~= nil then
            return result
        end
        -- auto defense gate after the security decisions, before origin
        -- selection: whitelist -> mitigations -> signatures (AD-04)
        if cdnca_autodefense then
            result = cdnca_autodefense.access(site)
            if result ~= nil then
                return result
            end
        end
        -- HTTP 302 scheduling after the security decisions (v7 order: after
        -- the JS challenge); a redirect ends the request
        if cdnca_sched302 and site.schedule302 then
            cdnca_sched302.access(schedule302_opts(site))
        end
    end
    -- origin redirect following (ge36): a follow location re-entered with
    -- the origin's redirect moves to its Location (or returns it) before
    -- the origin is chosen again
    if site and (ngx.var.cdnca_follow_hops or "") ~= "" then
        cdnca_origin.follow(site)
    end
    cdnca_origin.access()
    if cdnca_cache then
        return cdnca_cache.access()
    end
    if site and (ngx.var.cdnca_follow_hops or "") == "" and cdnca_origin.follows(site) then
        ngx.var.cdnca_follow_hops = "0"
        return ngx.exec("@cdnca_origin_follow")
    end
    -- 数据实时返回/发送 (no cache module: nothing is cached on this node)
    local unbuffered = not ngx.req.is_internal() and cdnca_origin.unbuffered_location(site)
    if unbuffered then
        return ngx.exec(unbuffered)
    end
end

-- acme_origin(): access of @cdnca_acme_origin (源站申请证书): an ACME
-- HTTP-01 request the node holds no token for. A site that passes ACME
-- through has it proxied to its origin (origin selection as location /,
-- none of the site's security: the CA must reach the origin); any other
-- request keeps the node's 404.
function _M.acme_origin()
    if not cdnca_origin.acme_origin_allowed() then
        return ngx.exit(ngx.HTTP_NOT_FOUND)
    end
    return cdnca_origin.access()
end

-- header_filter / body_filter: the origin's Location/Refresh rewrite (v7
-- proxy_redirect, before any interception), then the one ordered pipeline
-- (dynroute-filters.md §2): error page, HTTP policy, cache status, HSTS,
-- Alt-Svc.
function _M.header_filter()
    cdnca_origin.header_filter()
    cdnca_filters.header_filter()
    if cdnca_webp then
        -- before the compression gate, which then sees image/webp
        local site = cdnca_site.current()
        if site then
            local ok, err = pcall(cdnca_webp.header_filter, site)
            if not ok then ngx.log(ngx.ERR, "cdnca webp header filter: ", err) end
        end
    end
    if site_gzip and not ngx.is_subrequest then
        local site = cdnca_site.current()
        if site then
            gzip(site)
        else
            -- node locations, unknown Host: the skeleton's gzip is for sites
            ngx.req.clear_header("Accept-Encoding")
        end
    end
end

-- body_filter: the filter pipeline, then the telemetry capture (D12) of the
-- body the client receives (response body fields of a capture policy).
function _M.body_filter()
    cdnca_filters.body_filter()
    if cdnca_webp then
        local ok, err = pcall(cdnca_webp.body_filter)
        if not ok then ngx.log(ngx.ERR, "cdnca webp body filter: ", err) end
    end
    if ngx.var.cdnca_site_state == "ok" then
        local ok, err = pcall(cdnca_telemetry.body_filter)
        if not ok then ngx.log(ngx.ERR, "cdnca telemetry body filter: ", err) end
    end
end

-- log_by_lua: site limits release (D10), origin passive health (D5a),
-- security counters (D7 CC log), then telemetry (D12): it writes the
-- variables the access_log directives read after every log_by_lua has run,
-- so its position only matters for failures, which it isolates. Only a
-- request whose site was selected is logged (docs/edge/dynroute-telemetry.md §2.4).
function _M.log()
    cdnca_managed_waf.log()
    cdnca_limits.leave()
    cdnca_origin.log()
    local site = cdnca_site.current()
    if site and not trusted() then
        cdnca_security.log(site)
        if cdnca_sched302 and site.schedule302 then
            cdnca_sched302.log(schedule302_opts(site))
        end
        -- auto defense counters (AD-04) before telemetry, isolated
        if cdnca_autodefense then
            local ok, err = pcall(cdnca_autodefense.log, site)
            if not ok then ngx.log(ngx.ERR, "cdnca autodefense log: ", err) end
        end
    end
    if ngx.var.cdnca_site_state == "ok" then
        local ok, err = pcall(cdnca_telemetry.log)
        if not ok then ngx.log(ngx.ERR, "cdnca telemetry log: ", err) end
    end
end

function _M.balancer()
    return cdnca_origin.balancer()
end

-- proxy_ssl_verify_by_lua: the attempt's pool trust anchor
-- ($cdnca_origin_trust, written by cdnca_origintls.peer in the balancer)
-- verifies the origin's whole chain; no anchor = rejected (D5b).
function _M.proxy_ssl_verify()
    return require("cdnca_origintls").verify()
end

return _M
