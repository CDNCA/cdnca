-- Dynamic routing D5b: origin TLS per origin pool (ADR 0009 §4 "回源 TLS",
-- PoC results §3).
--
-- Every HTTPS endpoint of a site object names its trust anchor and how its
-- SNI is chosen (sni_mode, edgesite Pool.TLSName): "custom" sends sni,
-- "origin_host" the endpoint's host, "visitor_host" the visitor's $host (per
-- request); without sni_mode the endpoint's sni (the caller resolved it).
-- The resolved SNI is in the reuse key, so connections of different SNIs
-- (one origin address, visitor hosts a and b) are never shared. Anchors:
-- "sha256:<hex>" is a CA set object (PEM CA certificates, the plaintext whose
-- SHA-256 is <hex>, read through cdnca_site.object()), "system" is the node's
-- system CA bundle. "none" (fix-originnoverify, 回源 HTTPS 不校验源站证书,
-- ORIGIN_TLS_NO_VERIFY) accepts any chain and turns the host name check off
-- for the attempt (native patch 29, ngx_http_cdnca_upstream_set_ssl_host_check);
-- every other attempt turns it back on. Otherwise origin TLS is verified,
-- against exactly the endpoint's anchor. No tenant CA ever enters
-- the node-level proxy_ssl_trusted_certificate (the skeleton points it at a
-- placeholder).
--
-- The skeleton's location carries the three settings that must all be
-- present (PoC §3): proxy_ssl_verify on, lua_upstream_skip_openssl_default_verify
-- on, proxy_ssl_verify_by_lua -> verify(). nginx then fails the upstream when
-- verify() rejects, and checks the host name against proxy_ssl_name
-- ($cdnca_origin_sni) itself.
--
--   peer(site, pool, endpoint, address)   balancer_by_lua, every attempt (D5a
--       calls it after choosing the endpoint and resolving its address):
--       writes $cdnca_origin_sni and $cdnca_origin_trust, switches the
--       attempt to TLS or plain (set_upstream_tls), sets the peer with the
--       reuse key, and enables ngx_lua keepalive unless the pool turned
--       reuse off. The dynamic upstream has "keepalive 0" (nginx's own cache
--       keys by address only and would hand a connection verified for one
--       pool's trust to another, PoC §3).
--   name(endpoint)                        the SNI by sni_mode (nil when none).
--   key(site, pool, endpoint)             the reuse key (edgesite.KeepaliveKey,
--       same bytes): https|<resolved sni>|<anchor>|<auth identity>
--   verify()                              proxy_ssl_verify_by_lua.
--   configure(opts)                       init_by_lua, optional:
--       { system_ca_file = <path>, store_cache_items = <n> }.
--
-- Variables (declared by the skeleton, written here only):
--   $cdnca_origin_sni    real SNI and host name check (proxy_ssl_name)
--   $cdnca_origin_trust  the anchor verify() checks against
local ngx = ngx
local ffi = require "ffi"
local balancer = require "ngx.balancer"
local ngx_ssl = require "ngx.ssl"
local lrucache = require "resty.lrucache"
local x509 = require "resty.openssl.x509"
local x509_store = require "resty.openssl.x509.store"
local x509_chain = require "resty.openssl.x509.chain"
-- resty.openssl.ssl does not load on nginx 1.31.1 (auxiliary/nginx.lua knows
-- fixed versions only); the declaration of SSL_get_peer_cert_chain is enough.
require "resty.openssl.include.ssl"
-- native patch 29 (ngx_http_upstream.c); a runtime without it has no such
-- symbol and never gets an endpoint with anchor "none" (ORIGIN_TLS_NO_VERIFY)
pcall(ffi.cdef, "int ngx_http_cdnca_upstream_set_ssl_host_check(void *r, int enable);")
local base = require "resty.core.base"

local type, tostring, find, sub = type, tostring, string.find, string.sub

local _M = { version = "1" }

local TRUST_SYSTEM = "system"
local TRUST_NONE = "none"
local MAX_CA_SET_BYTES = 256 * 1024
local MAX_CA_SET_CERTIFICATES = 64
-- X509_V_ERR_CERT_REJECTED: with proxy_ssl_verify on, nginx fails the
-- upstream after the handshake (ngx_http_upstream_ssl_handshake).
local REJECTED = 28
_M.REJECTED = REJECTED

local config = {
    system_ca_file = "/etc/ssl/certs/ca-certificates.crt",
    store_cache_items = 1024,
}
local stores -- lrucache: anchor -> x509.store

function _M.configure(opts)
    opts = opts or {}
    if opts.system_ca_file ~= nil then
        assert(type(opts.system_ca_file) == "string" and sub(opts.system_ca_file, 1, 1) == "/",
            "cdnca_origintls.configure: system_ca_file must be an absolute path")
        config.system_ca_file = opts.system_ca_file
    end
    if opts.store_cache_items ~= nil then
        config.store_cache_items = assert(tonumber(opts.store_cache_items), "store_cache_items")
    end
    stores = nil
end

local function store_cache()
    if not stores then
        stores = assert(lrucache.new(config.store_cache_items))
    end
    return stores
end

-- anchor_digest("sha256:<hex>") -> <hex>; nil for anything else
local function anchor_digest(anchor)
    if type(anchor) ~= "string" or #anchor ~= 71 or sub(anchor, 1, 7) ~= "sha256:" then
        return nil
    end
    local hex = sub(anchor, 8)
    if find(hex, "[^0-9a-f]") then
        return nil
    end
    return hex
end
_M.anchor_digest = anchor_digest

local function valid_anchor(anchor)
    return anchor == TRUST_SYSTEM or anchor == TRUST_NONE or anchor_digest(anchor) ~= nil
end
_M.valid_anchor = valid_anchor

-- ca_store(pem) -> x509.store of the PEM CA set (edgesite.ValidateCASet:
-- certificates only, at most 64; each is a trust anchor, a pinned
-- self-signed origin certificate too, as in v7), or nil, err.
local function ca_store(pem)
    if type(pem) ~= "string" or #pem == 0 or #pem > MAX_CA_SET_BYTES then
        return nil, "CA set size"
    end
    local store, err = x509_store.new()
    if not store then
        return nil, err
    end
    local count, rest = 0, pem
    while true do
        rest = rest:gsub("^%s+", "")
        if rest == "" then
            break
        end
        local first, last = find(rest, "-----END CERTIFICATE-----", 1, true)
        if sub(rest, 1, 27) ~= "-----BEGIN CERTIFICATE-----" or not first then
            return nil, "CA set holds something other than certificates"
        end
        local certificate, perr = x509.new(sub(rest, 1, last), "PEM")
        if not certificate then
            return nil, "CA set certificate: " .. tostring(perr)
        end
        local ok, aerr = store:add(certificate)
        if not ok then
            return nil, aerr
        end
        count = count + 1
        if count > MAX_CA_SET_CERTIFICATES then
            return nil, "CA set holds too many certificates"
        end
        rest = sub(rest, last + 1)
    end
    if count == 0 then
        return nil, "empty CA set"
    end
    return store
end
_M.ca_store = ca_store

-- store_for(anchor) -> the anchor's x509.store, cached per worker (a CA set
-- object never changes under its digest; the system bundle is read once per
-- worker).
local function store_for(anchor)
    local cache = store_cache()
    local store = cache:get(anchor)
    if store then
        return store
    end
    local err
    if anchor == TRUST_SYSTEM then
        local file = io.open(config.system_ca_file, "rb")
        if not file then
            return nil, "system CA bundle unreadable"
        end
        file:close()
        store, err = x509_store.new()
        if store then
            local ok, lerr = store:load_file(config.system_ca_file)
            if not ok then
                store, err = nil, lerr
            end
        end
    else
        local digest = anchor_digest(anchor)
        if not digest then
            return nil, "invalid trust anchor"
        end
        local pem, oerr = require("cdnca_site").object(digest)
        if not pem then
            return nil, "CA set object " .. digest .. ": " .. tostring(oerr)
        end
        store, err = ca_store(pem)
    end
    if not store then
        return nil, err
    end
    assert(store:set_depth(8))
    cache:set(anchor, store)
    return store
end
_M.store_for = store_for

-- auth_identity(site, pool_id): the origin auth secret signing the pool's
-- requests ("<id>@<revision>"), "-" for none.
local function auth_identity(site, pool_id)
    local origin = site and site.origin
    for _, auth in ipairs(origin and origin.auth or {}) do
        if auth.pool_id == pool_id then
            return auth.secret.id .. "@" .. string.format("%d", auth.secret.revision)
        end
    end
    return "-"
end

-- name(endpoint): the SNI and verified name of an HTTPS endpoint by its
-- sni_mode; nil when there is none or it cannot go in the reuse key (a
-- visitor host holding "|" or NUL: the attempt fails, never shares a key).
function _M.name(endpoint)
    local mode, name = endpoint.sni_mode, endpoint.sni
    if mode == "origin_host" then
        name = endpoint.host
    elseif mode == "visitor_host" then
        name = ngx.var.host
    elseif mode ~= nil and mode ~= "custom" then
        return nil
    end
    if type(name) ~= "string" or name == "" or find(name, "[|%z]") then
        return nil
    end
    return name
end

-- set_host_check(enable): native patch 29 for the request's current upstream
-- attempt. Without the patch only enable = true succeeds (the stock check).
function _M.set_host_check(enable)
    local r = base.get_request()
    if not r then
        return nil, "no request"
    end
    local ok, rc = pcall(ffi.C.ngx_http_cdnca_upstream_set_ssl_host_check, r, enable and 1 or 0)
    if ok and rc == 0 then
        return true
    end
    if enable then
        return true
    end
    return nil, "trust anchor none needs native patch 29"
end

-- key(site, pool, endpoint): edgesite.KeepaliveKey. "|" separates (no field
-- holds it); never NUL, ngx_strncasecmp stops at NUL.
function _M.key(site, pool, endpoint)
    local identity = auth_identity(site, pool.id)
    if endpoint.scheme == "https" then
        return "https|" .. (_M.name(endpoint) or "") .. "|" .. endpoint.trust_anchor .. "|" .. identity
    end
    return "http||-|" .. identity
end

-- peer(site, pool, endpoint, address): see the header. Returns true or
-- nil, err (the caller fails the attempt).
function _M.peer(site, pool, endpoint, address)
    local tls = endpoint.scheme == "https"
    if tls then
        local name = _M.name(endpoint)
        if not name or not valid_anchor(endpoint.trust_anchor) then
            return nil, "TLS endpoint without SNI or trust anchor"
        end
        ngx.var.cdnca_origin_sni = name
        ngx.var.cdnca_origin_trust = endpoint.trust_anchor
        -- per attempt: a retry to another endpoint of the pool gets its own
        local ok, err = _M.set_host_check(endpoint.trust_anchor ~= TRUST_NONE)
        if not ok then
            return nil, err
        end
    else
        ngx.var.cdnca_origin_sni = ""
        ngx.var.cdnca_origin_trust = ""
    end
    local ok, err = balancer.set_upstream_tls(tls)
    if not ok then
        return nil, err
    end
    ok, err = balancer.set_current_peer(address or endpoint.host, endpoint.port, _M.key(site, pool, endpoint))
    if not ok then
        return nil, err
    end
    local idle = pool.keepalive_idle_timeout_ms
    if idle == nil or idle > 0 then
        -- nil: the node default (nginx keepalive_timeout 60s)
        ok, err = balancer.enable_keepalive((idle or 60000) / 1000, 1000)
        if not ok then
            return nil, err
        end
    end
    return true
end

local function reject(reason)
    ngx.log(ngx.WARN, "cdnca origin tls: origin certificate rejected (", reason, ") site=",
        ngx.var.cdnca_site_id or "-", " sni=", ngx.var.cdnca_origin_sni or "-",
        " trust=", ngx.var.cdnca_origin_trust or "-")
    return require("ngx.ssl.proxysslverify").set_verify_result(REJECTED)
end

-- verify(): proxy_ssl_verify_by_lua. The leaf and the chain the origin sent
-- (SSL_get_peer_cert_chain: the leaf alone fails every intermediate-issued
-- origin, PoC §3) against the attempt's anchor, SSL server purpose. An
-- attempt without an anchor is rejected (fail closed); anchor "none" is
-- accepted without a check.
-- verify_l2(version, leaf): a pass-through L2 hop (L2_ROUTING v2,
-- trust "l2:<certificate version>"): the L2 serves the same site object, so
-- it must present exactly this site's listener certificate (its leaf).
local function verify_l2(version, leaf)
    local entry = version ~= "" and require("cdnca_tls").certificate_entry(version)
    if not entry or not entry.leaf_der then
        return reject("L2 site certificate unavailable")
    end
    if leaf:tostring("DER") ~= entry.leaf_der then
        return reject("L2 certificate is not the site's")
    end
    return require("ngx.ssl.proxysslverify").set_verify_result(0)
end

function _M.verify()
    local vfy = require "ngx.ssl.proxysslverify"
    local anchor = ngx.var.cdnca_origin_trust
    local l2_version = type(anchor) == "string" and sub(anchor, 1, 3) == "l2:" and sub(anchor, 4) or nil
    if l2_version then
        local raw, cerr = vfy.get_verify_cert()
        if not raw then
            return reject("no L2 certificate: " .. tostring(cerr))
        end
        local leaf, lerr = x509.dup(ffi.cast("X509*", raw))
        if not leaf then
            return reject(lerr)
        end
        return verify_l2(l2_version, leaf)
    end
    if anchor == TRUST_NONE then
        -- 不校验源站证书: any chain; peer() turned the host name check off
        return vfy.set_verify_result(0)
    end
    if not valid_anchor(anchor) then
        return reject("no trust anchor")
    end
    local store, err = store_for(anchor)
    if not store then
        return reject(err)
    end
    local raw, cerr = vfy.get_verify_cert()
    if not raw then
        return reject("no peer certificate: " .. tostring(cerr))
    end
    local leaf, lerr = x509.dup(ffi.cast("X509*", raw))
    if not leaf then
        return reject(lerr)
    end
    local pointer, perr = ngx_ssl.get_upstream_ssl_pointer()
    if not pointer then
        return reject("upstream ssl: " .. tostring(perr))
    end
    local chain
    local stack = ffi.C.SSL_get_peer_cert_chain(ffi.cast("SSL*", pointer))
    if stack ~= nil then
        chain, err = x509_chain.dup(stack)
        if not chain then
            return reject(err)
        end
    end
    local ok, verr = store:verify(leaf, chain, false, nil, "ssl_server")
    if not ok then
        return reject(verr)
    end
    return vfy.set_verify_result(0)
end

return _M
