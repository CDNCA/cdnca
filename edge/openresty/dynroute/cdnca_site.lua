-- Dynamic routing site selection (ADR 0009 §3.3, dynamic routing D3).
--
-- The cross-phase contract is docs/edge/dynroute-contract.md (frozen):
--   * route() in the first line of server_rewrite_by_lua selects the site by
--     (public port, Host) from the cdnca_site_index shared dictionary and
--     writes the ngx.var.cdnca_site_* variables once per request;
--   * current() / site() / object() / lookup() are what every later phase and
--     module (D4-D12) reads; nothing else opens the object directory or the
--     index;
--   * not ready -> 503, ready but no site -> state "unknown" (the skeleton
--     serves node locations or calls reject_unknown(), a 421).
--
-- Index values (contract §4.1): a 32-byte site object digest, or a
-- transitional value written by a change set stage:
--   0x01 | generation u64 | flags u8 | [new 32 B] | [old 32 B]
-- resolved against the generation the request read: g >= generation -> new.
local lrucache = require "resty.lrucache"
local resty_sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex
local cjson = require "cjson.safe"
local bit = require "bit"

local band = bit.band
local byte, sub, find = string.byte, string.sub, string.find
local tonumber, tostring, type = tonumber, tostring, type
local io_open = io.open
local ngx_var = ngx.var
local md5_bin = ngx.md5_bin

local _M = { version = "1" }

local index_dict = ngx.shared.cdnca_site_index
local state_dict = ngx.shared.cdnca_site_state

local config = {
    objects_root = nil,
    index_root = nil,
    system_max_body = nil,
    lru_items = 10000,
    object_lru_items = 1000,
    -- this node (errpage-ovr): picks a site's error page variants
    node_id = "",
    node_region = "",
}
local sites   -- lrucache: hex digest -> entry {site, names, ports, hex}
local objects -- lrucache: hex digest -> raw bytes

-- Level D site drop (攻击自动升级 D 级, esc-node §4): cdnca_site_admin
-- writes "drop:<name>" into the state dictionary for every name of a level D
-- site. The request path checks the name the index matched (exact: an
-- exact non-D site under a D wildcard stays open).
_M.DROP_PREFIX = "drop:"

-- drop_name(host): a site name as the index keys it (lower case, no trailing
-- dot, a leading "*." only), or nil.
function _M.drop_name(host)
    if type(host) ~= "string" or #host == 0 or #host > 255 then
        return nil
    end
    host = host:lower()
    if byte(host, -1) == 46 then
        host = sub(host, 1, -2)
    end
    local rest = sub(host, 1, 2) == "*." and sub(host, 3) or host
    if rest == "" or find(rest, "[^a-z0-9._-]") or find(rest, "..", 1, true) or byte(rest, 1) == 46 then
        return nil
    end
    return host
end

-- dropped(matched): whether the matched site name is in the drop set.
function _M.dropped(matched)
    return matched ~= nil and matched ~= "" and state_dict:get("drop:" .. matched) ~= nil
end

local NOT_READY_BODY = "cdnca: site index not ready\n"
local unknown_page -- {status, mime_type, style_hash, body} or nil (421, built-in page)
local no_host_page -- the same for a request without a Host (400), or nil
-- error page slot pages (errpage-3, ERROR_PAGE_SLOTS): name -> page, the
-- agent picked this node's page of each (node, region, global)
local slot_pages = {}

local function read_node_page(page, name)
    if not page then
        return nil
    end
    local file = assert(io_open(page.body_file, "rb"), "cdnca_site.configure: " .. name .. " body_file unreadable")
    local body = file:read("*a")
    file:close()
    return { status = page.status, mime_type = page.mime_type, style_hash = page.style_hash, body = body }
end

function _M.configure(opts)
    assert(index_dict and state_dict, "cdnca_site: lua_shared_dict cdnca_site_index / cdnca_site_state missing")
    assert(type(opts) == "table" and type(opts.objects_root) == "string" and type(opts.index_root) == "string",
        "cdnca_site.configure: objects_root and index_root are required")
    local max_body = tonumber(opts.system_max_body)
    assert(max_body and max_body >= 1 and max_body == math.floor(max_body),
        "cdnca_site.configure: system_max_body must be a positive byte count")
    config.objects_root = opts.objects_root
    config.index_root = opts.index_root
    config.system_max_body = string.format("%d", max_body)
    config.lru_items = tonumber(opts.lru_items) or config.lru_items
    config.object_lru_items = tonumber(opts.object_lru_items) or config.object_lru_items
    config.node_id = opts.node_id or ""
    config.node_region = opts.node_region or ""
    sites = assert(lrucache.new(config.lru_items))
    objects = assert(lrucache.new(config.object_lru_items))
    -- The node pages (global unknown_site; no_host, D13-b2):
    -- read here, in the master, so a missing file fails nginx -t.
    unknown_page = read_node_page(opts.unknown_site, "unknown_site")
    no_host_page = read_node_page(opts.no_host, "no_host")
    slot_pages = {}
    for name, page in pairs(opts.slot_pages or {}) do
        slot_pages[name] = read_node_page(page, "slot_pages." .. name)
    end
end

-- node(): this node's ID and region (errpage-ovr error page variants).
function _M.node()
    return config.node_id, config.node_region
end

-- slot_page(name): the node's page of an error page slot, or nil.
function _M.slot_page(name)
    return slot_pages[name]
end

local function send_page(page)
    ngx.status = page.status
    require("cdnca_filters").page_headers(page.mime_type, #page.body, page.style_hash)
    if ngx.req.get_method() ~= "HEAD" then
        ngx.print(page.body)
    end
    return ngx.exit(ngx.HTTP_OK)
end

-- serve_slot(name): answer with the slot page and end the request; returns
-- false without one (the caller keeps its own response). The page is the
-- node's own (cdnca_filters never replaces it) and, like every node page,
-- not billed as package traffic (FX60 block page variable).
function _M.serve_slot(name)
    local page = slot_pages[name]
    if not page then
        return false
    end
    require("cdnca_filters").own_page("slot:" .. name)
    pcall(function() ngx_var.cdnca_security_block_page = "1" end)
    return send_page(page)
end

function _M.config()
    return config
end

-- Big-endian u64 (generations stay below 2^53, exact in a Lua number).
local function u64(raw, offset)
    local value = 0
    for position = offset, offset + 7 do
        value = value * 256 + byte(raw, position)
    end
    return value
end
_M.u64 = u64

-- resolve(raw, g): the 32-byte digest raw stands for at generation g, or nil.
local function resolve(raw, g)
    if #raw == 32 then
        return raw
    end
    if byte(raw, 1) ~= 1 or #raw < 10 then
        return nil
    end
    local flags = byte(raw, 10)
    local offset = 11
    local new, old
    if band(flags, 1) ~= 0 then
        new = sub(raw, offset, offset + 31)
        offset = offset + 32
    end
    if band(flags, 2) ~= 0 then
        old = sub(raw, offset, offset + 31)
    end
    if g >= u64(raw, 2) then
        return new
    end
    return old
end
_M.resolve = resolve

local function object_path(hex)
    return config.objects_root .. "/sha256/" .. sub(hex, 1, 2) .. "/" .. sub(hex, 3, 4) .. "/" .. hex
end

local function read_verified(hex)
    local file = io_open(object_path(hex), "rb")
    if not file then
        return nil, "missing"
    end
    local raw = file:read("*a")
    file:close()
    if not raw then
        return nil, "unreadable"
    end
    local hash = resty_sha256:new()
    hash:update(raw)
    if to_hex(hash:final()) ~= hex then
        return nil, "digest mismatch"
    end
    return raw
end

-- object(hex): the verified bytes of an object in the worker-readable object
-- directory (contract §5.5), cached per worker by digest.
function _M.object(hex)
    if type(hex) ~= "string" or #hex ~= 64 then
        return nil, "invalid digest"
    end
    local raw = objects:get(hex)
    if raw then
        return raw
    end
    local err
    raw, err = read_verified(hex)
    if not raw then
        return nil, err
    end
    objects:set(hex, raw)
    return raw
end

local function load_entry(hex)
    local entry = sites:get(hex)
    if entry then
        return entry
    end
    local raw, err = read_verified(hex)
    if not raw then
        return nil, err
    end
    local site = cjson.decode(raw)
    if type(site) ~= "table" or site.schema ~= "cdnca.edge.site/v2" or type(site.hosts) ~= "table"
        or type(site.listeners) ~= "table" or type(site.site_id) ~= "string" then
        return nil, "not a site object"
    end
    local names = { [site.hosts.primary] = true }
    for _, alias in ipairs(site.hosts.aliases or {}) do
        names[alias] = true
    end
    local ports = {}
    for _, listener in ipairs(site.listeners) do
        ports[listener.port] = true
    end
    local max_body = tonumber(site.limits and site.limits.max_body_bytes) or 0
    entry = {
        site = site, names = names, ports = ports, hex = hex,
        revision = string.format("%d", site.revision),
        max_body = max_body > 0 and string.format("%d", max_body) or nil,
    }
    sites:set(hex, entry)
    return entry
end

-- site(hex): the decoded site object of a digest (read only, shared).
function _M.site(hex)
    local entry = load_entry(hex)
    return entry and entry.site
end

function _M.generation()
    return tonumber(state_dict:get("gen")) or 0
end

local function port_ready(port, g)
    if g < 1 then
        return false
    end
    local ports = state_dict:get("ports:" .. g)
    return ports ~= nil and find(ports, "," .. port .. ",", 1, true) ~= nil
end

function _M.ready(port)
    return port_ready(tonumber(port) or 0, _M.generation())
end

-- probe one (port, name) at generation g: entry | nil, or false + reason when
-- the key routes to an object that cannot be read (not ready).
local DEFAULT_NAME = ""
local function probe(port, name, g)
    local raw = index_dict:get(md5_bin(port .. "\0" .. name))
    if not raw then
        return nil
    end
    local digest = resolve(raw, g)
    if not digest then
        return nil
    end
    local entry, err = load_entry(to_hex(digest))
    if not entry then
        return false, err
    end
    -- An md5 collision must not route to another site (contract §2.2).
    if not (entry.names[name] or name == DEFAULT_NAME and entry.site.default) or not entry.ports[port] then
        return nil
    end
    return entry
end

-- The index dictionary and the state dictionary carry the same epoch
-- (cdnca_site_admin writes both). A miss is only "unknown" when they agree:
-- after the index dictionary alone was lost (resized by a reload) every key
-- misses until the worker timer starts the rebuild, and that must be 503.
local EPOCH_KEY = "cdnca:epoch"
local function index_intact()
    local epoch = state_dict:get("epoch")
    return epoch ~= nil and index_dict:get(EPOCH_KEY) == epoch
end
_M.index_intact = index_intact

local function unknown()
    if index_intact() then
        return nil, "unknown"
    end
    return nil, "not_ready", "index lost"
end

-- unknown_or_default(port, g): the port's default site (默认站点, index
-- name "", SITE_EDGE_OPTIONS) for a Host no site serves, else unknown.
local function unknown_or_default(port, g)
    local entry, err = probe(port, DEFAULT_NAME, g)
    if entry then
        return entry, "ok", entry.site.hosts.primary
    elseif entry == false then
        return nil, "not_ready", err
    end
    return unknown()
end

-- find_site(port, host, g): entry, state, matched name.
local function find_site(port, host, g)
    if not port or not port_ready(port, g) then
        return nil, "not_ready"
    end
    if type(host) ~= "string" or host == "" then
        return unknown_or_default(port, g)
    end
    local entry, err = probe(port, host, g)
    if entry then
        return entry, "ok", host
    elseif entry == false then
        return nil, "not_ready", err
    end
    local dot = find(host, ".", 1, true)
    while dot do
        local rest = sub(host, dot + 1)
        local next_dot = find(rest, ".", 1, true)
        if not next_dot then
            break
        end
        local name = "*." .. rest
        entry, err = probe(port, name, g)
        if entry then
            return entry, "ok", name
        elseif entry == false then
            return nil, "not_ready", err
        end
        dot = dot + next_dot
    end
    return unknown_or_default(port, g)
end

-- lookup(port, host): site, state, matched name. No variables written; usable
-- in every phase including ssl_client_hello / ssl_certificate (D4).
function _M.lookup(port, host)
    local entry, state, matched = find_site(tonumber(port), host, _M.generation())
    return entry and entry.site, state, matched, entry and entry.hex
end

local function public_port()
    return tonumber(ngx_var.proxy_protocol_server_port or ngx_var.server_port)
end

local function write_vars(entry, state, matched, port, g)
    if entry then
        local site = entry.site
        ngx_var.cdnca_site_id = site.site_id
        ngx_var.cdnca_site_revision = entry.revision
        ngx_var.cdnca_site_digest = entry.hex
        ngx_var.cdnca_site_tenant = site.tenant_id
        ngx_var.cdnca_site_scope = site.configuration_scope_id
        ngx_var.cdnca_site_host = matched
        ngx_var.cdnca_site_port = tostring(port)
        ngx_var.cdnca_site_max_body = entry.max_body or config.system_max_body
    else
        ngx_var.cdnca_site_id = ""
        ngx_var.cdnca_site_revision = ""
        ngx_var.cdnca_site_digest = ""
        ngx_var.cdnca_site_tenant = ""
        ngx_var.cdnca_site_scope = ""
        ngx_var.cdnca_site_host = ""
        ngx_var.cdnca_site_port = ""
        ngx_var.cdnca_site_max_body = "1"
    end
    ngx_var.cdnca_site_generation = tostring(g)
    ngx_var.cdnca_site_state = state
end

local function exit_not_ready()
    ngx.status = 503
    ngx.header["Content-Type"] = "text/plain"
    ngx.header["Retry-After"] = "1"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Length"] = #NOT_READY_BODY
    ngx.print(NOT_READY_BODY)
    return ngx.exit(ngx.HTTP_OK)
end

-- route(): contract §2. Returns the site object for "ok", nil for "unknown"
-- (the caller decides between a node location and reject_unknown());
-- "not_ready" ends the request with 503.
function _M.route()
    -- A declared but never assigned variable reads as nil; an undeclared one
    -- fails on the first write below (contract §6.2 declares them).
    local selected = ngx_var.cdnca_site_state
    if selected and selected ~= "" then
        -- Selected already (internal redirect re-entering server rewrite):
        -- never select twice (contract §1 item 2).
        return _M.current()
    end
    local g = _M.generation()
    local port = public_port()
    local entry, state, matched = find_site(port, ngx_var.host, g)
    write_vars(entry, state, matched, port, g)
    if state == "not_ready" then
        return exit_not_ready()
    end
    return entry and entry.site
end

-- reject_unknown(): a Host no site serves gets the node's unknown_site page
-- with its status (v7 default server), else a bare 421. A request without a
-- Host (HTTP/1.0, or an empty one) gets the no_host page (400) when the node
-- has one.
-- A Host that is an IP address (the node's own, as no site is named by an
-- address it serves; errpage-3) gets the node_ip_access slot page when the
-- node has one.
local function host_is_address(host)
    if not host or host == "" then
        return false
    end
    if byte(host, 1) == 91 then -- "[v6]" or "[v6]:port"
        return true
    end
    local bare = host:match("^([^:]+):%d+$") or host
    return bare:find("^%d+%.%d+%.%d+%.%d+$") ~= nil or (bare:find(":", 1, true) ~= nil and bare:find("^[%x:.]+$") ~= nil)
end
_M.host_is_address = host_is_address

-- Without a page the node answers 421 as before,
-- with its built-in default page (no Host / an IP address / an unknown
-- domain) instead of nginx's bare one.
function _M.reject_unknown()
    local page = unknown_page
    local host = ngx_var.http_host
    local missing, address = host == nil or host == "", host_is_address(host)
    if no_host_page and missing then
        page = no_host_page
    elseif slot_pages.node_ip_access and address then
        page = slot_pages.node_ip_access
    end
    if not page then
        return require("cdnca_filters").send_default(missing and "no_host" or address and "node_ip_access" or "unknown_site", 421)
    end
    return send_page(page)
end

-- no_host(): content of the skeleton's no_host location (error_page 400,
-- B11). nginx refuses an HTTP/1.1 request without or with an empty Host
-- while parsing, before any Lua phase: such a request never ran
-- server_rewrite (cdnca_site_state unset) and has no Host; it gets the
-- no_host page. Any other 400 (another malformed request, a site's
-- ModSecurity or Lua) keeps nginx's own response: in an error page nginx
-- does not redirect again.
function _M.no_host()
    local state, host = ngx_var.cdnca_site_state, ngx_var.http_host
    if state ~= nil and state ~= "" or host ~= nil and host ~= "" then
        return ngx.exit(400)
    end
    if not no_host_page then
        -- The built-in default page (the skeleton always
        -- renders this location)
        return require("cdnca_filters").send_default("no_host", 400)
    end
    local page = no_host_page
    ngx.status = page.status
    require("cdnca_filters").page_headers(page.mime_type, #page.body, page.style_hash)
    if ngx.req.get_method() ~= "HEAD" then
        ngx.print(page.body)
    end
    return ngx.exit(ngx.HTTP_OK)
end

-- current(): this request's site (selected by route()), or nil.
function _M.current()
    if ngx_var.cdnca_site_state ~= "ok" then
        return nil
    end
    local entry = load_entry(ngx_var.cdnca_site_digest)
    return entry and entry.site
end

-- Worker timer: heartbeat (contract §5.6) and cold start rebuild (§5.3).
local function tick(premature)
    if premature then
        return
    end
    local admin = require "cdnca_site_admin"
    admin.check_epoch()
    local g = _M.generation()
    state_dict:safe_set("worker:" .. ngx.worker.pid(), g, 10)
    if g == 0 and state_dict:get("rebuild") == nil then
        admin.cold_start()
    end
end

function _M.init_worker()
    assert(config.objects_root, "cdnca_site.configure was not called")
    local ok, err = ngx.timer.every(1, tick)
    if not ok then
        ngx.log(ngx.ERR, "cdnca_site: worker timer: ", err)
    end
    ngx.timer.at(0, tick)
end

return _M
