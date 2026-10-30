-- cdnca security ban list: the bans and releases the
-- control plane's ban list library sends a node (cdnca.security-ban-list/v1,
-- verified by the Agent, which posts the runtime part to the loopback health
-- server: POST <health>/security-bans).
--
-- State lives in lua_shared_dict cdnca_security_bans, keyed by site (site IDs
-- are unique across scopes):
--   ban:<site>:<client>  until (epoch seconds), expires with the ban
--   rel:<site>:<client>  release time; an automatic ban of the client on the
--                        site that started before it no longer applies
--                        (CC keys carry their start time, cc.lua banned()),
--                        kept 7 days (the longest ban)
--   rev                  the applied snapshot revision
--   keys                 the ban keys of the applied snapshot (JSON list)
--   nets                 network bans (BAN_CIDR): JSON
--                        {site: {"<network>/<bits>": until}}
--   nets_gen             grows when nets changes; each worker rebuilds its
--                        per-site prefix matchers (lua-resty-ipmatcher) then
-- A snapshot replaces the previous one: listed bans not in it are lifted.
-- A single address ban is one exact key (looked up first); a network ban is
-- matched by prefix. A network release only drops the network ban (the
-- node's own automatic bans are of single addresses), so nothing is stored.
local cjson = require "cjson.safe"

local _M = { _VERSION = "2" }

local DICT = "cdnca_security_bans"
local RELEASE_SECONDS = 7 * 86400
local MAX_ENTRIES = 20000
local UUID = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

local function dict() return ngx.shared[DICT] end

-- A client is an address or a network (BAN_CIDR): IPv4 /8../31, IPv6
-- /32../127 (libs/edgeconfig/securityban CanonicalClient).
local function valid_client(value)
    if type(value) ~= "string" or #value < 2 or #value > 49 then return false end
    if value:match("^[%x%.:]+$") then return true end
    local address, bits = value:match("^([%x%.:]+)/(%d%d?%d?)$")
    bits = tonumber(bits)
    if not address or not bits then return false end
    if address:find(":", 1, true) then return bits >= 32 and bits <= 127 end
    return address:match("^%d+%.%d+%.%d+%.%d+$") ~= nil and bits >= 8 and bits <= 31
end

local function is_network(value) return value:find("/", 1, true) ~= nil end

-- Per worker: the nets generation the matchers were built from, and
-- site -> matcher (value: until).
local matchers_gen, matchers = nil, {}

-- lua-resty-ipmatcher is loaded on the first network ban, so a runtime
-- without it still applies the address bans.
local function build_matchers(nets)
    local built = {}
    for site, networks in pairs(nets) do
        local loaded, ipmatcher = pcall(require, "resty.ipmatcher")
        if not loaded then return nil, ipmatcher end
        local matcher, err = ipmatcher.new_with_value(networks)
        if not matcher then return nil, err end
        built[site] = matcher
    end
    return built
end

local function network_until(state, site, client)
    local gen = state:get("nets_gen")
    if not gen then return nil end
    if gen ~= matchers_gen then
        local built = build_matchers(cjson.decode(state:get("nets") or "{}") or {})
        matchers, matchers_gen = built or {}, gen
    end
    local matcher = matchers[site]
    if not matcher then return nil end
    local until_epoch = matcher:match(client)
    return type(until_epoch) == "number" and until_epoch or nil
end

local function valid_site(value) return type(value) == "string" and value:match(UUID) ~= nil end

-- banned(site, client): the listed ban's remaining seconds, or nil.
function _M.banned(site, client)
    local state = dict()
    if not state or not site or not client then return nil end
    local until_epoch = state:get("ban:" .. site .. ":" .. client)
    local remaining = until_epoch and until_epoch - ngx.now()
    if remaining and remaining > 0 then return remaining end
    until_epoch = network_until(state, site, client)
    remaining = until_epoch and until_epoch - ngx.now()
    if remaining and remaining > 0 then return remaining end
    return nil
end

-- released_since(site, client, started): whether a release of the client on
-- the site happened at or after an automatic ban that started at started
-- (epoch seconds; a ban without its start time counts as started at 0).
function _M.released_since(site, client, started)
    local state = dict()
    if not state or not site or not client then return false end
    local released = state:get("rel:" .. site .. ":" .. client)
    if not released then return false end
    return released >= (tonumber(started) or 0)
end

-- deny answers a listed ban (403, block page, Retry-After).
function _M.deny(remaining, block_page_variable)
    pcall(function() ngx.var[block_page_variable or "cdnca_security_block_page"] = "1" end)
    ngx.status = 403
    ngx.header["Retry-After"] = tostring(math.max(1, math.ceil(remaining)))
    ngx.header["X-Cdnca-Ban"] = "listed"
    -- the platform's blacklist slot page (errpage-3, dynamic routing nodes
    -- only: package.loaded has cdnca_site there); else the plain notice
    local site_module = package.loaded["cdnca_site"]
    local page = type(site_module) == "table" and site_module.slot_page and site_module.slot_page("blacklist")
    if page then
        require("cdnca_filters").own_page("slot:blacklist")
        require("cdnca_filters").page_headers(page.mime_type, #page.body, page.style_hash)
        if ngx.req.get_method() ~= "HEAD" then
            ngx.print(page.body)
        end
        return ngx.exit(403)
    end
    -- The dynamic routing node's built-in default page
    if type(site_module) == "table" then
        return require("cdnca_filters").send_default("blacklist", 403)
    end
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.print("Forbidden\n")
    return ngx.exit(403)
end

-- check(site): deny the request when the client is on the list.
function _M.check(site, block_page_variable)
    local remaining = _M.banned(site, ngx.var.remote_addr)
    if remaining then return _M.deny(remaining, block_page_variable) end
end

local function release_local(site, client)
    -- WAF bans of the site (cdnca_waf ban scope "site:<site>").
    local ok, waf = pcall(require, "cdnca_waf")
    if ok and waf and waf.unban then pcall(waf.unban, "site:" .. site, client) end
end

-- apply(body): the runtime part of a verified snapshot
-- {"revision":n,"bans":[{"site_id","client","until"}],"releases":[{"site_id","client"}]}.
-- Returns status, result table.
function _M.apply(body)
    local state = dict()
    if not state then return 503, { error = "dictionary_unavailable" } end
    local snapshot = cjson.decode(body or "")
    if type(snapshot) ~= "table" or type(snapshot.revision) ~= "number" or snapshot.revision < 1 or
        snapshot.revision ~= math.floor(snapshot.revision) or type(snapshot.bans) ~= "table" or
        type(snapshot.releases) ~= "table" or #snapshot.bans + #snapshot.releases > MAX_ENTRIES then
        return 400, { error = "invalid_snapshot" }
    end
    for _, ban in ipairs(snapshot.bans) do
        if type(ban) ~= "table" or not valid_site(ban.site_id) or not valid_client(ban.client) or
            type(ban["until"]) ~= "number" then
            return 400, { error = "invalid_ban" }
        end
    end
    for _, release in ipairs(snapshot.releases) do
        if type(release) ~= "table" or not valid_site(release.site_id) or not valid_client(release.client) or
            type(release.released_at) ~= "number" then
            return 400, { error = "invalid_release" }
        end
    end
    local current = state:get("rev") or 0
    if snapshot.revision < current then
        return 409, { error = "stale_revision", revision = current }
    end
    local now = ngx.now()
    local keys, active, nets, net_count = {}, 0, {}, 0
    for _, ban in ipairs(snapshot.bans) do
        local seconds = ban["until"] - now
        if seconds > 0 and is_network(ban.client) then
            nets[ban.site_id] = nets[ban.site_id] or {}
            nets[ban.site_id][ban.client] = ban["until"]
            active, net_count = active + 1, net_count + 1
        elseif seconds > 0 then
            local key = "ban:" .. ban.site_id .. ":" .. ban.client
            local ok, err = state:set(key, ban["until"], seconds)
            if not ok then return 507, { error = "dictionary_full", detail = err } end
            keys[key], active = true, active + 1
        end
    end
    if net_count > 0 and not build_matchers(nets) then
        return 400, { error = "invalid_ban" }
    end
    -- Rebuild the workers' matchers only when the network bans change (the
    -- Agent re-posts the same snapshot every 30 s): compare a sorted digest.
    local lines = {}
    for site, networks in pairs(nets) do
        for network, until_epoch in pairs(networks) do lines[#lines + 1] = site .. "|" .. network .. "|" .. until_epoch end
    end
    table.sort(lines)
    local signature = ngx.md5(table.concat(lines, "\n"))
    if signature ~= state:get("nets_sig") then
        local ok, err = state:set("nets", net_count > 0 and cjson.encode(nets) or "{}")
        if not ok then return 507, { error = "dictionary_full", detail = err } end
        state:set("nets_sig", signature)
        state:incr("nets_gen", 1, 0)
    end
    local previous = cjson.decode(state:get("keys") or "[]") or {}
    for _, key in ipairs(previous) do
        if not keys[key] then state:delete(key) end
    end
    local released = 0
    for _, release in ipairs(snapshot.releases) do
        local age = now - release.released_at
        if age < RELEASE_SECONDS then
            if not is_network(release.client) then
                local key = "rel:" .. release.site_id .. ":" .. release.client
                local existing = state:get(key)
                if not existing or existing < release.released_at then
                    state:set(key, release.released_at, RELEASE_SECONDS - age)
                    release_local(release.site_id, release.client)
                end
            end
            released = released + 1
        end
    end
    local list = {}
    for key in pairs(keys) do list[#list + 1] = key end
    table.sort(list)
    state:set("keys", cjson.encode(list) or "[]")
    state:set("rev", snapshot.revision)
    return 200, { revision = snapshot.revision, bans = active, releases = released }
end

-- handle: content_by_lua of <health>/security-bans (loopback only): GET
-- drains the kernel ban queue (text lines), POST applies a snapshot.
function _M.handle()
    if ngx.req.get_method() == "GET" then
        ngx.header["Content-Type"] = "text/plain"
        for _, line in ipairs(_M.kernel_bans()) do ngx.say(line) end
        return
    end
    ngx.header["Content-Type"] = "application/json"
    if ngx.req.get_method() ~= "POST" then
        ngx.status = 405
        ngx.print('{"error":"method"}')
        return ngx.exit(405)
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local handle = io.open(file, "rb")
            if handle then body = handle:read("*a"); handle:close() end
        end
    end
    local status, result = _M.apply(body)
    ngx.status = status
    ngx.print(cjson.encode(result))
    return ngx.exit(status)
end

-- Kernel ban queue of WAF automatic bans (ge-ddos cc_kernel_ban reuse): the
-- Agent drains it with GET <health>/security-bans and raises each to the
-- node's kernel firewall on the site's ports, as CC's "kban" queue. Lines
-- "<site>|<client>|<until>" (the Agent knows the site's tenant scope).
local KERNEL_QUEUE, KERNEL_QUEUE_LIMIT = "kban", 10000

function _M.queue_kernel_ban(site, client, seconds)
    local state = dict()
    if not state or not valid_site(site) or not valid_client(client) or type(seconds) ~= "number" then return end
    local length = state:lpush(KERNEL_QUEUE, site .. "|" .. client .. "|" .. tostring(math.floor(ngx.now() + seconds)))
    if length and length > KERNEL_QUEUE_LIMIT then
        state:rpop(KERNEL_QUEUE)
        state:incr("kban_dropped", 1, 0)
    end
end

function _M.kernel_bans()
    local state = dict()
    local lines = {}
    if not state then return lines end
    for _ = 1, KERNEL_QUEUE_LIMIT do
        local line = state:rpop(KERNEL_QUEUE)
        if not line then break end
        lines[#lines + 1] = line
    end
    return lines
end

-- revision: the applied snapshot revision (0 before the first).
function _M.revision()
    local state = dict()
    return state and state:get("rev") or 0
end

return _M
