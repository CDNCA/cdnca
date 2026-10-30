-- cdnca_sched302: HTTP 302 scheduling on the node ("DNS + 302
-- 双调度"). Contract: libs/edgeconfig/sched302 (Go reference of the table,
-- the landing signature and the candidate choice; tests compare both).
--
-- Entry (a schedule302 site's access phase, after firewall actions and the JS
-- challenge, before the HTTP policy): access(opts) answers 302 to the best
-- candidate node for the client's carrier / region, or returns and the node
-- serves the request itself (no table, stale table, no available candidate,
-- the candidate is this node, a filter does not match, or the request was
-- itself scheduled).
--
-- Landing (every plain HTTP default server and plain site server):
-- /_cdnca302/<expires>.<sig>/<host><uri>. land() verifies the signature and
-- hands the request over loopback to this node's site server on the same
-- port with the original Host, carrying the token (X-Cdnca-S302) and the
-- client address (X-Cdnca-S302-Client; the site server restores it with
-- realip trusted from loopback only). The site's access() verifies the token
-- again against the request it received and serves it: a scheduled request is
-- never redirected again (no loop). Expired, forged or foreign: 403.
--
-- The table (<deployment_root>/schedule302/table.json, replaced by rename)
-- is checked at most once per second per worker: its header (revision,
-- generated_at) is read and the whole file only when they changed. A table
-- older than hold_seconds stops every redirect (the control plane refreshes
-- it well within that while it is reachable).
--
-- Size threshold: log() records the full length of 200/206 responses per
-- (site, path) in the shared dict cdnca_sched302_sizes for an hour; a URL is
-- redirected once its learned size reaches min_size_bytes (the first request
-- of a URL is served here).

local cjson = require("cjson.safe")
local resty_sha256 = require("resty.sha256")
local bit = require("bit")

local byte, char, sub, find, lower, gsub, rep = string.byte, string.char, string.sub, string.find, string.lower,
    string.gsub, string.rep
local tonumber, tostring, type, ipairs, pairs = tonumber, tostring, type, ipairs, pairs
local log = math.log

local _M = { _VERSION = "1" }

local LANDING = "/_cdnca302/"
local DOMAIN = "cdnca-s302/v1"
local SIG_LEN = 22
local OVERLOADED = 90
local DEFAULT_TABLE = "/var/lib/cdnca-edge/schedule302/table.json"
local DEFAULT_HOLD = 120
local MAX_TABLE_BYTES = 4 * 1024 * 1024
local SIZE_TTL = 3600

local config = { table_path = DEFAULT_TABLE, hold = DEFAULT_HOLD, now = ngx.time }
local loaded -- { sites = {site_id = site}, generated_at, revision }
local next_check = 0
local last_problem

local function note(level, message)
    if message ~= last_problem then
        last_problem = message
        ngx.log(level, "cdnca_sched302: ", message)
    end
end

-- base64url without padding <-> bytes.
local function b64url_decode(value)
    if type(value) ~= "string" or find(value, "[^%w_%-]") then return nil end
    local padded = gsub(gsub(value, "-", "+"), "_", "/")
    local rest = #padded % 4
    if rest == 1 then return nil end
    if rest > 0 then padded = padded .. rep("=", 4 - rest) end
    return ngx.decode_base64(padded)
end

local function b64url(raw)
    return (gsub(gsub(gsub(ngx.encode_base64(raw), "+", "-"), "/", "_"), "=", ""))
end

local function sha256(data)
    local hash = resty_sha256:new()
    if not hash or not hash:update(data) then return nil end
    return hash:final()
end

local function hmac_sha256(key, message)
    if #key > 64 then key = sha256(key) end
    key = key .. rep("\0", 64 - #key)
    local inner, outer = {}, {}
    for index = 1, 64 do
        local value = byte(key, index)
        inner[index] = char(bit.bxor(value, 0x36))
        outer[index] = char(bit.bxor(value, 0x5c))
    end
    local digest = sha256(table.concat(inner) .. message)
    return digest and sha256(table.concat(outer) .. digest)
end

-- sign is sched302.Sign.
function _M.sign(key, site_id, host, uri, expires)
    local mac = hmac_sha256(key, DOMAIN .. "\n" .. site_id .. "\n" .. host .. "\n" .. uri .. "\n" .. tostring(expires))
    return mac and sub(b64url(mac), 1, SIG_LEN)
end

local function constant_equal(left, right)
    if type(left) ~= "string" or type(right) ~= "string" or #left ~= #right then return false end
    local difference = 0
    for index = 1, #left do
        difference = bit.bor(difference, bit.bxor(byte(left, index), byte(right, index)))
    end
    return difference == 0
end

-- Table --------------------------------------------------------------------

local function decode_table(raw)
    local value = cjson.decode(raw)
    if type(value) ~= "table" or value.schema ~= "cdnca.edge.sched302-table/v1" or type(value.sites) ~= "table"
        or type(value.generated_at) ~= "number" or type(value.revision) ~= "number" then
        return nil, "invalid table"
    end
    if type(value.node_id) ~= "string" or value.node_id == "" then return nil, "invalid table node" end
    local sites = {}
    for _, site in ipairs(value.sites) do
        local key = type(site) == "table" and b64url_decode(site.key)
        if not key or #key ~= 32 or type(site.site_id) ~= "string" or type(site.candidates) ~= "table"
            or type(site.hosts) ~= "table" then
            return nil, "invalid table site"
        end
        local hosts = {}
        for _, host in ipairs(site.hosts) do
            if type(host) ~= "string" then return nil, "invalid table host" end
            hosts[#hosts + 1] = host
        end
        local candidates = {}
        for _, candidate in ipairs(site.candidates) do
            if type(candidate) ~= "table" or type(candidate.node_id) ~= "string" or type(candidate.host) ~= "string"
                or type(candidate.http_port) ~= "number" or type(candidate.weight) ~= "number" then
                return nil, "invalid table candidate"
            end
            candidates[#candidates + 1] = {
                node_id = candidate.node_id, host = candidate.host, http_port = candidate.http_port,
                carrier = candidate.carrier or "", country = candidate.country or "",
                province = candidate.province or 0, weight = candidate.weight,
                available = candidate.available == true, load = candidate.load or 0,
            }
        end
        sites[site.site_id] = { key = key, hosts = hosts, candidates = candidates }
    end
    return { node_id = value.node_id, sites = sites, generated_at = value.generated_at, revision = value.revision }
end

local function refresh()
    local now = ngx.now()
    if now < next_check then return end
    next_check = now + 1
    local handle = io.open(config.table_path, "rb")
    if not handle then
        if loaded then note(ngx.WARN, "table removed") end
        loaded = nil
        return
    end
    -- Canonical encoding: schema, node_id, revision, generated_at, sites.
    local head = handle:read(512) or ""
    local revision, generated = head:match('"revision":(%d+),"generated_at":(%d+),')
    if loaded and tonumber(revision) == loaded.revision and tonumber(generated) == loaded.generated_at then
        handle:close()
        return
    end
    local rest = handle:read(MAX_TABLE_BYTES + 1 - #head) or ""
    handle:close()
    if #head + #rest > MAX_TABLE_BYTES then
        note(ngx.ERR, "table is too large")
        return
    end
    local table_, problem = decode_table(head .. rest)
    if not table_ then
        -- Keep the last good table until it goes stale.
        note(ngx.ERR, problem)
        return
    end
    last_problem = nil
    loaded = table_
end

-- use points the module at the table the rendered configuration names
-- (opts.table; the default deployment root otherwise).
local function use(path)
    path = path or DEFAULT_TABLE
    if path ~= config.table_path then
        config.table_path, loaded, next_check, last_problem = path, nil, 0, nil
    end
end

local function current_table()
    refresh()
    if not loaded then return nil, "no_table" end
    if config.now() - loaded.generated_at > config.hold then return nil, "stale_table" end
    return loaded
end

-- Hosts --------------------------------------------------------------------

local function wildcard_length(name, host)
    if sub(name, 1, 2) ~= "*." then return nil end
    local suffix = sub(name, 2)
    if #host > #suffix and sub(host, -#suffix) == suffix then return #suffix end
    return nil
end

local function host_matches(hosts, host)
    for _, name in ipairs(hosts) do
        if name == host or wildcard_length(name, host) then return true end
    end
    return false
end

-- site_for_host: exact names first, then the longest leading wildcard (as
-- nginx server_name selects).
local function site_for_host(sites, host)
    local best_id, best, best_length
    for id, site in pairs(sites) do
        for _, name in ipairs(site.hosts) do
            if name == host then return id, site end
            local length = wildcard_length(name, host)
            if length and (not best_length or length > best_length) then
                best_id, best, best_length = id, site, length
            end
        end
    end
    return best_id, best
end

-- Selection (sched302.Select) ---------------------------------------------

local function rendezvous(client_bytes, node_id, weight)
    local digest = sha256(client_bytes .. node_id)
    local b1, b2, b3, b4, b5, b6 = byte(digest, 1, 6)
    local value = ((((b1 * 256 + b2) * 256 + b3) * 256 + b4) * 256 + b5) * 256 + b6
    local u = (value + 0.5) / 281474976710656
    return weight / -log(u)
end

-- Library carrier tag bits (libs/entitlement/ipintel TagCN*).
local CARRIER_TAGS = { { 1, "telecom" }, { 2, "unicom" }, { 4, "mobile" } }

local function client_attributes()
    local ok, iplib = pcall(require, "cdnca_iplib")
    if not ok then return "", "", 0 end
    local attrs = iplib.lookup(ngx.var.binary_remote_addr)
    if not attrs then return "", "", 0 end
    local carrier = ""
    for _, entry in ipairs(CARRIER_TAGS) do
        if bit.band(attrs.tags_lo, entry[1]) ~= 0 then
            if carrier ~= "" then
                carrier = ""
                break
            end
            carrier = entry[2]
        end
    end
    local province = attrs.province or 0
    return carrier, attrs.country or "", province - province % 10000
end

function _M.select(candidates, client_bytes, carrier, country, province)
    local tiers = {
        function(c) return carrier ~= "" and c.carrier == carrier and province ~= 0 and c.province == province end,
        function(c) return carrier ~= "" and c.carrier == carrier and country ~= "" and c.country == country end,
        function(c) return (c.carrier == "bgp" or c.carrier == "") and country ~= "" and c.country == country end,
        function(c) return country ~= "" and c.country == country end,
        function() return true end,
    }
    for _, in_tier in ipairs(tiers) do
        local best, best_score, best_relieved
        for _, candidate in ipairs(candidates) do
            if candidate.available and in_tier(candidate) then
                local relieved = candidate.load < OVERLOADED
                local score = rendezvous(client_bytes, candidate.node_id, candidate.weight)
                if not best or relieved and not best_relieved or relieved == best_relieved and score > best_score then
                    best, best_score, best_relieved = candidate, score, relieved
                end
            end
        end
        if best then return best end
    end
    return nil
end

-- Filters ------------------------------------------------------------------

local function size_key(site_id, path)
    return site_id .. "\0" .. path
end

local function filters_match(opts, path)
    local extensions = opts.extensions
    if extensions and #extensions > 0 then
        local extension = path:match("%.(%w+)$")
        local found = false
        if extension then
            extension = lower(extension)
            for _, value in ipairs(extensions) do
                if value == extension then
                    found = true
                    break
                end
            end
        end
        if not found then return false end
    end
    local prefixes = opts.path_prefixes
    if prefixes and #prefixes > 0 then
        local found = false
        for _, prefix in ipairs(prefixes) do
            if sub(path, 1, #prefix) == prefix then
                found = true
                break
            end
        end
        if not found then return false end
    end
    if (opts.min_size_bytes or 0) > 0 then
        local sizes = ngx.shared.cdnca_sched302_sizes
        local learned = sizes and sizes:get(size_key(opts.site_id, path))
        if not learned or learned < opts.min_size_bytes then return false end
    end
    return true
end

-- Tokens -------------------------------------------------------------------

-- parse_landing splits /_cdnca302/<expires>.<sig>/<host><uri>.
local function parse_landing(request_uri)
    if sub(request_uri, 1, #LANDING) ~= LANDING then return nil end
    local expires, sig, host, uri = sub(request_uri, #LANDING + 1):match("^(%d+)%.([%w_%-]+)/([%w%.%-]+)(/.*)$")
    if not expires or #sig ~= SIG_LEN or #expires > 12 then return nil end
    return tonumber(expires), sig, lower(host), uri
end

local function token_valid(site, site_id, host, uri, expires, sig)
    if not expires or expires < config.now() then return false, "expired" end
    if not host_matches(site.hosts, host) then return false, "host" end
    if not constant_equal(_M.sign(site.key, site_id, host, uri, expires), sig) then return false, "signature" end
    return true
end

local function forbid(reason)
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-Cdnca-S302-Reject"] = reason
    return ngx.exit(403)
end

-- Entry --------------------------------------------------------------------

-- access(opts): opts = { site_id, keep_path, keep_query, ttl, https_to_http,
-- extensions, path_prefixes, min_size_bytes } (rendered by the agent from
-- the site's schedule302 settings). Returns nothing when the request is
-- served here.
function _M.access(opts)
    use(opts.table)
    local token = ngx.var.http_x_cdnca_s302
    if token then
        -- A scheduled request: verify it, then serve it here, never again
        -- redirected. Its client address was restored by realip (loopback).
        local table_, reason = current_table()
        local site = table_ and table_.sites[opts.site_id]
        if not site then return forbid(reason or "no_site") end
        local expires, sig = token:match("^(%d+)%.([%w_%-]+)$")
        local ok, why = token_valid(site, opts.site_id, lower(ngx.var.host or ""), ngx.var.request_uri,
            tonumber(expires), sig)
        if not ok then return forbid(why) end
        ngx.req.clear_header("X-Cdnca-S302")
        ngx.req.clear_header("X-Cdnca-S302-Client")
        return
    end
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then return end
    if ngx.var.https == "on" and not opts.https_to_http then return end
    if not filters_match(opts, ngx.var.uri) then return end
    local table_ = current_table()
    local site = table_ and table_.sites[opts.site_id]
    if not site then return end
    local host = lower(ngx.var.host or "")
    if not host_matches(site.hosts, host) then return end
    local carrier, country, province = client_attributes()
    local chosen = _M.select(site.candidates, ngx.var.binary_remote_addr, carrier, country, province)
    if not chosen or chosen.node_id == table_.node_id then return end
    local uri = ngx.var.request_uri
    local query_at = find(uri, "?", 1, true)
    local path, query = uri, nil
    if query_at then path, query = sub(uri, 1, query_at - 1), sub(uri, query_at + 1) end
    uri = opts.keep_path and path or "/"
    if opts.keep_query and query and query ~= "" then uri = uri .. "?" .. query end
    local expires = config.now() + opts.ttl
    local sig = _M.sign(site.key, opts.site_id, host, uri, expires)
    if not sig then return end
    local target = chosen.host
    if find(target, ":", 1, true) then target = "[" .. target .. "]" end
    if chosen.http_port ~= 80 then target = target .. ":" .. chosen.http_port end
    ngx.header["Cache-Control"] = "no-store"
    return ngx.redirect("http://" .. target .. LANDING .. expires .. "." .. sig .. "/" .. host .. uri, 302)
end

-- land(opts): content of the landing location (opts.table as access).
-- Verifies the token and hands the request to the site server over loopback
-- (@cdnca_sched302_land).
function _M.land(opts)
    use(opts and opts.table)
    local remote = ngx.var.realip_remote_addr or ngx.var.remote_addr
    if remote == "127.0.0.1" or remote == "::1" then
        -- The loopback hop goes to the site's server, never back here.
        return ngx.exit(421)
    end
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then return ngx.exit(405) end
    local expires, sig, host, uri = parse_landing(ngx.var.request_uri)
    if not expires then return forbid("malformed") end
    local table_, reason = current_table()
    if not table_ then return forbid(reason) end
    local site_id, site = site_for_host(table_.sites, host)
    if not site then return forbid("host") end
    local ok, why = token_valid(site, site_id, host, uri, expires, sig)
    if not ok then return forbid(why) end
    local port = ngx.var.proxy_protocol_server_port
    if not port or port == "" then port = ngx.var.server_port end
    ngx.var.cdnca_sched302_host = host
    ngx.var.cdnca_sched302_uri = uri
    ngx.var.cdnca_sched302_port = port
    ngx.var.cdnca_sched302_token = expires .. "." .. sig
    ngx.var.cdnca_sched302_client = ngx.var.remote_addr
    return ngx.exec("@cdnca_sched302_land")
end

-- log(opts): learns response sizes for min_size_bytes.
function _M.log(opts)
    if (opts.min_size_bytes or 0) <= 0 then return end
    local sizes = ngx.shared.cdnca_sched302_sizes
    local status = ngx.status
    if not sizes or status ~= 200 and status ~= 206 then return end
    local total
    if status == 200 then
        -- Content-Length, or for a chunked origin response the body bytes
        -- sent when the whole body went out (not for HEAD or an aborted
        -- transfer, which sent less).
        total = tonumber(ngx.var.sent_http_content_length or "")
        if not total and ngx.req.get_method() == "GET" and ngx.var.request_completion == "OK" then
            total = tonumber(ngx.var.body_bytes_sent or "")
        end
    else
        total = tonumber((ngx.var.sent_http_content_range or ""):match("/(%d+)$") or "")
    end
    if total and total > 0 then
        sizes:set(size_key(opts.site_id, ngx.var.uri), total, SIZE_TTL)
    end
end

-- configure (tests): { table_path, hold_seconds, now }.
function _M.configure(options)
    options = options or {}
    config.table_path = options.table_path or DEFAULT_TABLE
    config.hold = options.hold_seconds or DEFAULT_HOLD
    config.now = options.now or ngx.time
    loaded, next_check, last_problem = nil, 0, nil
end

-- status reports the loaded table (tests and logs).
function _M.status(path)
    use(path)
    refresh()
    if not loaded then return { ready = false, problem = last_problem } end
    local count = 0
    for _ in pairs(loaded.sites) do count = count + 1 end
    return { ready = true, revision = loaded.revision, generated_at = loaded.generated_at, sites = count,
        stale = config.now() - loaded.generated_at > config.hold }
end

return _M
