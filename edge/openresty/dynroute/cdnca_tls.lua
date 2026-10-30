-- Dynamic routing D4: the TLS entry of the shared servers (ADR 0009 §3.2
-- steps 1-2, docs/edge/dynroute-tls.md).
--
--   client_hello()   ssl_client_hello_by_lua: the (port, SNI) site must exist
--                    (cdnca_site.lookup; unknown / no SNI / not ready refuse
--                    the handshake, as v7), its listener must allow QUIC for
--                    an h3 handshake, its certificate must be loadable and
--                    valid now; then the site's protocols, cipher profile (a
--                    preset or the site's custom whitelisted list)
--                    (ssl_prefer_server_ciphers by preset or the site's own),
--                    HTTP/2 (off: ALPN offers only http/1.1, native patch 27)
--                    and session ID context are applied. Every connection runs
--                    this, a resumed one too (a resumed session skips the
--                    certificate phase, PoC §2).
--   certificate()    ssl_certificate_by_lua: always clear_certs, then the
--                    site's certificate (worker LRU by certificate version),
--                    the OCSP response when stapling is on, and the client CA
--                    when the site asks for client certificates.
--   request(site)    server_rewrite_by_lua, after cdnca_site.route(): the
--                    client certificate decision of the request's site (the
--                    site is chosen by Host, never by SNI: BATCH-PLUGIN 12).
--   header_filter()  Alt-Svc for a site that advertises h3 on the port.
--
-- Node files (written by the agent, internal/dyntls): <pool>/<version>.crt
-- (certificate chain PEM, leaf first), <pool>/<version>.key (private key
-- PEM), <pool>/<version>.ocsp (DER OCSP response, optional). A certificate
-- version's files never change; a new certificate is a new version.
local ffi = require "ffi"
local ssl = require "ngx.ssl"
local clienthello = require "ngx.ssl.clienthello"
local ocsp = require "ngx.ocsp"
local lrucache = require "resty.lrucache"
local x509 = require "resty.openssl.x509"
local cdnca_site = require "cdnca_site"

local C = ffi.C
local ngx = ngx
local ngx_var = ngx.var
local md5_bin = ngx.md5_bin
local lower, sub, byte, find = string.lower, string.sub, string.byte, string.find
local tonumber, tostring, type, ipairs = tonumber, tostring, type, ipairs

for _, declaration in ipairs({
    "int SSL_set_cipher_list(void *ssl, const char *str);",
    "int SSL_set_session_id_context(void *ssl, const unsigned char *ctx, unsigned int len);",
    "void *SSL_get_session(const void *ssl);",
    "const unsigned char *SSL_SESSION_get0_id_context(const void *session, unsigned int *len);",
    "unsigned long SSL_set_options(void *ssl, unsigned long op);",
    "unsigned long SSL_clear_options(void *ssl, unsigned long op);",
    -- native patch 27 (ngx_http_ssl_module.c); a runtime without it has no
    -- such symbol and never gets a site with HTTP/2 off (SITE_TLS_OPTIONS)
    "int ngx_http_cdnca_ssl_set_http2(void *ssl, int enable);",
    "typedef struct { long tv_sec; long tv_nsec; } cdnca_tls_timespec;",
    "int clock_gettime(int clock, cdnca_tls_timespec *ts);",
}) do
    pcall(ffi.cdef, declaration) -- another module may have declared it already
end

local _M = { version = "1" }

-- OpenSSL cipher strings of the site object's cipher presets (TLS 1.2 and
-- older; TLS 1.3 suites stay OpenSSL's default). Byte-equal to
-- edgeconfig.TLSCipherList (libs/edgeconfig/site_tls_profile.go), which the
-- v7 renderer writes as ssl_ciphers; "" is modern.
local MODERN = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
    .. "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
local CIPHERS = {
    [""] = MODERN,
    modern = MODERN,
    compatible = MODERN .. ":ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:"
        .. "ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:"
        .. "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA",
    -- TLSv1/TLSv1.1 sign with MD5+SHA-1: security level 0.
    legacy = "DEFAULT:@SECLEVEL=0",
}
-- ssl_prefer_server_ciphers: off for modern (only strong suites), on for
-- the wider lists and for custom, whose order is the site's
-- (edgeconfig.PresetPrefersServerCiphers).
local PREFER_SERVER = { compatible = true, legacy = true, custom = true }

-- custom (SITE_TLS_CUSTOM_CIPHERS): the site object's
-- cipher_suites, an ordered list the control plane checked against
-- edgeconfig.TLSCustomCipherSuites (the compatible list's names). The node
-- checks again (a name outside the whitelist, or an empty list, refuses
-- the handshake rather than reaching SSL_set_cipher_list as a cipher
-- string with keywords) and joins it once per site table.
local CUSTOM_WHITELIST = {}
for suite in string.gmatch(CIPHERS.compatible, "[^:]+") do
    CUSTOM_WHITELIST[suite] = true
end
local custom_lists = setmetatable({}, { __mode = "k" })
local function custom_cipher_list(tls)
    local cached = custom_lists[tls]
    if cached ~= nil then
        return cached or nil
    end
    local suites = tls.cipher_suites
    local list = false
    if type(suites) == "table" and #suites > 0 then
        for _, suite in ipairs(suites) do
            if not CUSTOM_WHITELIST[suite] then
                suites = nil
                break
            end
        end
        if suites then
            list = table.concat(suites, ":")
        end
    end
    custom_lists[tls] = list
    return list or nil
end
_M.custom_cipher_list = custom_cipher_list
-- client verification depth (edgeconfig.TLSProfileDirectives: ssl_verify_depth 3)
local VERIFY_DEPTH = 3
_M.CIPHERS = CIPHERS

local SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000
local QUIC_TRANSPORT_PARAMETERS = 57 -- only a QUIC ClientHello carries it
local ALT_SVC_MAX_AGE = 86400 -- v7: add_header Alt-Svc 'h3=":<port>"; ma=86400' always

local config = {
    pool_root = nil,
    lru_items = 10000,
    ocsp_refresh = 60, -- seconds an OCSP response is kept before the file is read again
    negative_ttl = 1, -- seconds a missing / broken certificate is not retried
}
local certificates -- lrucache: certificate version -> entry | false
local client_cas   -- lrucache: client CA object digest -> parsed chain
local stapled      -- lrucache: certificate version -> { der, next_update } | false

local counters = {
    hello = 0, refused = 0, cert_hit = 0, cert_miss = 0, cert_load_us = 0,
    ocsp_stapled = 0, client_auth = 0,
}

local timespec = ffi.new("cdnca_tls_timespec")
local function now_us()
    C.clock_gettime(1, timespec) -- CLOCK_MONOTONIC
    return tonumber(timespec.tv_sec) * 1e6 + tonumber(timespec.tv_nsec) / 1e3
end

function _M.configure(opts)
    assert(type(opts) == "table" and type(opts.pool_root) == "string" and opts.pool_root ~= "",
        "cdnca_tls.configure: pool_root is required")
    config.pool_root = opts.pool_root
    config.lru_items = tonumber(opts.lru_items) or config.lru_items
    config.ocsp_refresh = tonumber(opts.ocsp_refresh) or config.ocsp_refresh
    config.negative_ttl = tonumber(opts.negative_ttl) or config.negative_ttl
    certificates = assert(lrucache.new(config.lru_items))
    client_cas = assert(lrucache.new(256))
    stapled = assert(lrucache.new(config.lru_items))
end

local function refuse(reason, name)
    counters.refused = counters.refused + 1
    ngx.log(ngx.INFO, "cdnca tls: refuse handshake (", reason, ") sni=", name or "-")
    return ngx.exit(ngx.ERROR)
end

-- SNI as nginx compares Host: lower case, one trailing dot removed.
local function normalize(name)
    if type(name) ~= "string" or name == "" then
        return nil
    end
    name = lower(name)
    if byte(name, -1) == 46 then -- "."
        name = sub(name, 1, -2)
    end
    return name ~= "" and name or nil
end

-- listener_for(site, port): the site's listener on port. Site tables are
-- shared and read only (cdnca_site); the port map is derived once per table.
local listener_maps = setmetatable({}, { __mode = "k" })
local function listener_for(site, port)
    local map = listener_maps[site]
    if not map then
        map = {}
        for _, listener in ipairs(site.listeners) do
            map[listener.port] = listener
        end
        listener_maps[site] = map
    end
    return map[port]
end
_M.listener_for = listener_for

local function read_file(path)
    local file = io.open(path, "rb")
    if not file then
        return nil
    end
    local content = file:read("*a")
    file:close()
    return content
end

local VERSION_PATTERN = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

local function load_certificate(version)
    local base = config.pool_root .. "/" .. version
    local chain_pem, key_pem = read_file(base .. ".crt"), read_file(base .. ".key")
    if not chain_pem or not key_pem then
        return nil, "certificate files missing"
    end
    local chain, err = ssl.parse_pem_cert(chain_pem)
    if not chain then
        return nil, "certificate: " .. tostring(err)
    end
    local key
    key, err = ssl.parse_pem_priv_key(key_pem)
    if not key then
        return nil, "private key: " .. tostring(err)
    end
    local leaf
    leaf, err = x509.new(chain_pem, "PEM") -- the first certificate of the chain
    if not leaf then
        return nil, "leaf: " .. tostring(err)
    end
    local der
    der, err = ssl.cert_pem_to_der(chain_pem)
    if not der then
        return nil, "chain: " .. tostring(err)
    end
    return {
        version = version, chain = chain, key = key, chain_der = der,
        not_before = leaf:get_not_before(), not_after = leaf:get_not_after(),
        -- the leaf an L2 must present on a pass-through hop (cdnca_origintls)
        leaf_der = leaf:tostring("DER"),
    }
end

-- certificate(version): the parsed certificate of a version (worker LRU).
local function certificate(version)
    if type(version) ~= "string" or not find(version, VERSION_PATTERN) then
        return nil, "invalid certificate version"
    end
    local entry = certificates:get(version)
    if entry then
        counters.cert_hit = counters.cert_hit + 1
        return entry
    elseif entry == false then
        return nil, "certificate unavailable"
    end
    counters.cert_miss = counters.cert_miss + 1
    local started = now_us()
    local err
    entry, err = load_certificate(version)
    counters.cert_load_us = counters.cert_load_us + (now_us() - started)
    if not entry then
        certificates:set(version, false, config.negative_ttl)
        ngx.log(ngx.WARN, "cdnca tls: certificate version ", version, ": ", err)
        return nil, err
    end
    certificates:set(version, entry)
    return entry
end
_M.certificate_entry = certificate

-- Session ID context (32 bytes): md5(site_id, certificate version) ..
-- md5(client auth). OpenSSL resumes a session only under the context it was
-- made in, so a ticket of one site never resumes on another (measured
-- without it: a TLS 1.2 ticket of a.test resumed under SNI b.test, skipping
-- b's certificate phase), a new certificate version starts fresh sessions,
-- and the second half lets the request phase check which client CA the
-- handshake used.
local NO_CLIENT_AUTH = md5_bin("none")
local context_length = ffi.new("unsigned int[1]")
-- client_auth(tls): "optional" | "required" with the CA digest, or nil.
local function client_auth(tls)
    local mode = tls.client_auth
    if (mode == "optional" or mode == "required") and tls.client_ca then
        return mode, tls.client_ca.sha256
    end
    return nil
end

local function client_auth_context(tls)
    local mode, ca = client_auth(tls)
    if not mode then
        return NO_CLIENT_AUTH
    end
    return md5_bin(mode .. "\0" .. ca)
end

local function default_protocols(protocols)
    return #protocols == 2 and protocols[1] == "TLSv1.2" and protocols[2] == "TLSv1.3"
end

-- server_port is the connection's public port. On a port an L4 forward
-- shares (D13-c0) the L4 dispatcher hands the connection to the internal
-- socket <mux>/<port>-tls.sock (edgeskeleton.DispatchSocket), which has no
-- port of its own: the name carries it.
local function server_port()
    local port = ssl.server_port()
    if port then
        return port
    end
    local path, kind = ssl.raw_server_addr()
    if kind == "unix" and path then
        -- sun_path may carry trailing NULs: no end anchor
        return tonumber(path:match("/(%d+)%-tls%.sock"))
    end
    return nil
end

-- resolve(port, name): site, listener, certificate entry | nil, reason.
local function resolve(port, name)
    local site, state, matched = cdnca_site.lookup(port, name)
    if not site then
        return nil, state
    end
    -- level D site (攻击自动升级 黑洞): the handshake is closed (TCP and QUIC)
    if cdnca_site.dropped(matched) then
        return nil, "site drop"
    end
    local listener = listener_for(site, port)
    if not listener or not listener.tls then
        return nil, "no TLS listener"
    end
    local entry, err = certificate(listener.tls.certificate_version_id)
    if not entry then
        return nil, err
    end
    local now = ngx.time()
    if now < entry.not_before or now >= entry.not_after then
        -- v7 refuses the site's handshake outside the validity window
        -- (ssl_reject_handshake); here it is decided per handshake.
        return nil, "certificate not valid now"
    end
    return site, listener, entry
end

function _M.client_hello()
    counters.hello = counters.hello + 1
    local name = normalize(clienthello.get_client_hello_server_name())
    local port = server_port()
    -- no SNI: only the port's default site (默认站点, IP certificates) serves
    -- it; cdnca_site.lookup falls back to it for "" as for an unknown name
    local site, listener, entry = resolve(port, name or "")
    if not site then
        return refuse(listener, name)
    end
    local tls = listener.tls
    local quic = clienthello.get_client_hello_ext(QUIC_TRANSPORT_PARAMETERS) ~= nil
    if quic then
        -- The port listens on QUIC when any of its sites advertises h3; a
        -- site that does not (or whose package removed h3) is not served
        -- over it. QUIC is TLS 1.3 only, so protocols and the TLS 1.2 cipher
        -- list do not apply.
        if not listener.http3 then
            return refuse("http3 off", name)
        end
    else
        if not default_protocols(tls.protocols) then
            local ok, err = clienthello.set_protocols(tls.protocols)
            if not ok then
                return refuse("set_protocols: " .. tostring(err), name)
            end
        end
        -- Always set: the server's own list is nginx's default, not the
        -- site's (an absent preset is modern, as edgeconfig renders it).
        local preset = tls.cipher_preset or ""
        local list = CIPHERS[preset]
        if preset == "custom" then
            list = custom_cipher_list(tls)
        end
        local pointer = list and ssl.get_req_ssl_pointer()
        if not pointer or C.SSL_set_cipher_list(pointer, list) ~= 1 then
            return refuse("cipher preset " .. tostring(preset), name)
        end
        -- prefer_server_ciphers: the site's own when the object writes it
        -- (SITE_TLS_OPTIONS), else by preset
        local prefer = tls.prefer_server_ciphers
        if prefer == nil then
            prefer = PREFER_SERVER[preset] or false
        end
        if prefer then
            C.SSL_set_options(pointer, SSL_OP_CIPHER_SERVER_PREFERENCE)
        else
            C.SSL_clear_options(pointer, SSL_OP_CIPHER_SERVER_PREFERENCE)
        end
        -- HTTP/2 is per site: the port's server has it when any site does;
        -- a site without it negotiates http/1.1 only. OpenSSL runs the ALPN
        -- callback after this one (OpenSSL 3.5 statem_srvr.c).
        if not listener.http2 then
            local ok, rc = pcall(C.ngx_http_cdnca_ssl_set_http2, pointer, 0)
            if not ok or rc ~= 0 then
                return refuse("http2 off needs native patch 27", name)
            end
        end
    end
    local context = md5_bin(site.site_id .. "\0" .. tls.certificate_version_id) .. client_auth_context(tls)
    local pointer = ssl.get_req_ssl_pointer()
    if not pointer or C.SSL_set_session_id_context(pointer, context, #context) ~= 1 then
        return refuse("session id context", name)
    end
    -- ngx.ctx is shared by the SSL phases of one connection (PoC §2).
    ngx.ctx.cdnca_tls = { site = site, listener = listener, entry = entry, name = name }
end

local function staple(entry)
    local cached = stapled:get(entry.version)
    if cached == nil then
        cached = false
        local der = read_file(config.pool_root .. "/" .. entry.version .. ".ocsp")
        if der and der ~= "" then
            local ok, next_update = ocsp.validate_ocsp_response(der, entry.chain_der)
            if ok then
                cached = { der = der, next_update = next_update }
            else
                ngx.log(ngx.WARN, "cdnca tls: OCSP response of ", entry.version, " rejected: ", next_update)
            end
        end
        stapled:set(entry.version, cached, config.ocsp_refresh)
    end
    if not cached or cached.next_update and cached.next_update <= ngx.time() then
        return
    end
    local ok, err = ocsp.set_ocsp_status_resp(cached.der)
    if not ok then
        ngx.log(ngx.WARN, "cdnca tls: staple OCSP of ", entry.version, ": ", err)
    elseif err == nil then
        counters.ocsp_stapled = counters.ocsp_stapled + 1
    end
end

local function client_ca(digest)
    local chain = client_cas:get(digest)
    if chain then
        return chain
    end
    local raw, err = cdnca_site.object(digest)
    if not raw then
        return nil, err
    end
    chain, err = ssl.parse_pem_cert(raw)
    if not chain then
        return nil, err
    end
    client_cas:set(digest, chain)
    return chain
end

function _M.certificate()
    local state = ngx.ctx.cdnca_tls
    if not state then
        -- client hello did not run on this connection (it always does on a
        -- shared server); decide again rather than serve the placeholder.
        local name = normalize(ssl.server_name())
        local site, listener, entry = resolve(server_port(), name or "")
        if not site then
            return refuse(listener, name)
        end
        state = { site = site, listener = listener, entry = entry, name = name }
    end
    local entry, tls = state.entry, state.listener.tls
    -- Unconditional: a client never sees the placeholder certificate.
    local ok, err = ssl.clear_certs()
    if ok then
        ok, err = ssl.set_cert(entry.chain)
    end
    if ok then
        ok, err = ssl.set_priv_key(entry.key)
    end
    if not ok then
        return refuse("set certificate: " .. tostring(err), state.name)
    end
    if tls.ocsp_stapling then
        staple(entry)
    end
    local mode, ca = client_auth(tls)
    if mode then
        local chain
        chain, err = client_ca(ca)
        if not chain then
            return refuse("client CA " .. ca .. ": " .. tostring(err), state.name)
        end
        ok, err = ssl.verify_client(chain, VERIFY_DEPTH)
        if not ok then
            return refuse("verify_client: " .. tostring(err), state.name)
        end
        counters.client_auth = counters.client_auth + 1
    end
end

local function set_header(name, value)
    if value == nil or value == "" then
        ngx.req.clear_header(name)
    else
        ngx.req.set_header(name, value)
    end
end

local function allowed(protocols, protocol)
    for _, value in ipairs(protocols) do
        if value == protocol then
            return true
        end
    end
    return false
end

-- request(site): the TLS decisions of the request's site, in server_rewrite
-- right after cdnca_site.route(). The site is chosen by Host; the handshake
-- was made for the SNI's site, which may be another one (HTTP/2 and HTTP/3
-- connection coalescing). The request is served (no 421 for SNI != Host,
-- BATCH-PLUGIN 12) unless the connection does not meet the Host site's own
-- TLS settings, which only coalescing can produce; then 421, so the client
-- retries on a connection of its own for that name (what nginx answers for
-- SNI != Host with ssl_verify_client, ngx_http_request.c):
--   * HTTP/3 for a site that does not advertise h3;
--   * HTTP/2 for a site with HTTP/2 off (the handshake offered h2 for the
--     SNI's site);
--   * a TLS protocol the site does not allow;
--   * client authentication other than the site's (the handshake checked the
--     certificate against the SNI site's client CA, it proves nothing here).
-- Then the client certificate: none when required -> 496, a failed one ->
-- 495; nginx sends both as its own 400 pages ("No required SSL certificate
-- was sent", "The SSL certificate error"), exactly as ssl_verify_client.
local CLIENT_HEADERS = { "X-Client-Verify", "X-Client-Cert-Fingerprint", "X-Client-Cert-Subject" }

function _M.request(site)
    -- Every request, every site, plain or TLS: the client's own copies of
    -- the verification headers never reach an origin (a forged
    -- "X-Client-Verify: SUCCESS" must not authenticate anyone). Only a site
    -- with client authentication writes them again below, from the
    -- handshake. Security fix over v7, which passes them through for sites
    -- without mTLS (compare.json semantic_changes).
    for _, name in ipairs(CLIENT_HEADERS) do
        ngx.req.clear_header(name)
    end
    if not site or ngx_var.https ~= "on" then
        return
    end
    local listener = listener_for(site, tonumber(ngx_var.cdnca_site_port))
    local tls = listener and listener.tls
    if not tls then
        return
    end
    local protocol = ngx_var.server_protocol
    if protocol == "HTTP/3.0" then
        if not listener.http3 then
            return ngx.exit(421)
        end
    elseif protocol == "HTTP/2.0" and not listener.http2 then
        return ngx.exit(421)
    elseif not allowed(tls.protocols, ngx_var.ssl_protocol) then
        return ngx.exit(421)
    end
    local mode = client_auth(tls)
    if not mode then
        return
    end
    local pointer = ssl.get_req_ssl_pointer()
    local session = pointer and C.SSL_get_session(pointer)
    local context = session ~= nil and C.SSL_SESSION_get0_id_context(session, context_length)
    if not context or context_length[0] ~= 32 or ffi.string(context + 16, 16) ~= client_auth_context(tls) then
        return ngx.exit(421)
    end
    local verify = ngx_var.ssl_client_verify
    if verify ~= "SUCCESS" and not (verify == "NONE" and mode == "optional") then
        return ngx.exit(verify == "NONE" and 496 or 495)
    end
    -- The verification result goes to the origin (edgeconfig
    -- TLSClientAuthLocation, v7 proxy_set_header); an empty value stays
    -- removed, as nginx sends no header for it.
    set_header("X-Client-Verify", verify)
    set_header("X-Client-Cert-Fingerprint", ngx_var.ssl_client_fingerprint)
    set_header("X-Client-Cert-Subject", ngx_var.ssl_client_s_dn)
end

function _M.header_filter()
    local site = cdnca_site.current()
    if not site then
        return
    end
    local port = tonumber(ngx_var.cdnca_site_port)
    local listener = port and listener_for(site, port)
    if listener and listener.http3 then
        ngx.header["Alt-Svc"] = 'h3=":' .. port .. '"; ma=' .. ALT_SVC_MAX_AGE
    end
end

-- stats(): this worker's counters (acceptance and benchmarks).
function _M.stats()
    local result = { lru_items = config.lru_items, cached = certificates and certificates:count() or 0, pid = ngx.worker.pid() }
    for key, value in pairs(counters) do
        result[key] = value
    end
    return result
end

function _M.reset_stats()
    for key in pairs(counters) do
        counters[key] = 0
    end
end

return _M
