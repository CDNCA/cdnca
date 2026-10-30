-- ADR 0009 §8.5 item 3: per-pool origin trust with proxy_ssl_verify_by_lua on
-- one dynamic upstream. Pools are what the site object would carry.
local ffi = require "ffi"
local balancer = require "ngx.balancer"
local ngx_ssl = require "ngx.ssl"
local vfy = require "ngx.ssl.proxysslverify"
local x509 = require "resty.openssl.x509"
local x509_store = require "resty.openssl.x509.store"
local x509_chain = require "resty.openssl.x509.chain"
-- resty.openssl.ssl cannot be used: its resty.openssl.auxiliary.nginx refuses
-- nginx 1031001 (hard-coded struct offsets). Only the declaration is needed.
require "resty.openssl.include.ssl" -- OPENSSL_STACK *SSL_get_peer_cert_chain(const SSL *)

local _M = {}
local ORIGIN = "/poc/certs/origin/"
local stats = ngx.shared.poc_verify

-- pool -> origin address, SNI, trust (tenant root) and tenant
local pools = {
  a       = { port = 9441, sni = "origin-a.internal", ca = "caA.crt", tenant = "A" }, -- A's origin, A's chain
  a_noint = { port = 9442, sni = "origin-a.internal", ca = "caA.crt", tenant = "A" }, -- leaf without intermediate
  a_exp   = { port = 9443, sni = "origin-a.internal", ca = "caA.crt", tenant = "A" }, -- expired
  a_name  = { port = 9444, sni = "origin-a.internal", ca = "caA.crt", tenant = "A" }, -- other.internal
  b       = { port = 9445, sni = "origin-b.internal", ca = "caB.crt", tenant = "B" }, -- B's origin
  b_evil  = { port = 9446, sni = "origin-b.internal", ca = "caB.crt", tenant = "B" }, -- A-issued cert for B's name
  a_on_b  = { port = 9445, sni = "origin-b.internal", ca = "caA.crt", tenant = "A" }, -- A's trust, B's real origin
  -- keepalive leak pair: same address, same SNI, different trust
  leak_a  = { port = 9446, sni = "origin-b.internal", ca = "caA.crt", tenant = "A" },
  leak_b  = { port = 9446, sni = "origin-b.internal", ca = "caB.crt", tenant = "B" },
  a_slow  = { port = 9441, sni = "origin-a.internal", ca = "caA.crt", tenant = "A", slow = true },
  -- one origin address, two virtual-host names, same trust
  sni_one = { port = 9447, sni = "one.internal", ca = "caA.crt", tenant = "A" },
  sni_two = { port = 9447, sni = "two.internal", ca = "caA.crt", tenant = "A" },
}

local stores = {}
local function store_for(ca)
  if stores[ca] then return stores[ca] end
  local store = assert(x509_store.new())
  assert(store:load_file(ORIGIN .. ca))
  assert(store:set_depth(4))
  stores[ca] = store
  return store
end

function _M.pool() return pools[ngx.var.cdnca_pool] end

-- access phase: the SNI variable that proxy_ssl_name reads
function _M.access()
  local pool = pools[ngx.var.cdnca_pool]
  if not pool then return ngx.exit(404) end
  ngx.var.cdnca_origin_sni = pool.sni
  -- $request_id is not indexed here (not referenced in nginx.conf), so each
  -- ngx.var read generates a new one: keep our own key in an indexed variable
  ngx.var.poc_rid = ngx.now() .. "-" .. math.random(1e9)
end

function _M.balance(keepalive)
  local pool = assert(pools[ngx.var.cdnca_pool])
  local host = pool.sni
  if ngx.var.cdnca_key_mode == "trust" then
    -- the keepalive pool key is (host, sockaddr, local); folding the trust
    -- anchor into "host" keeps connections verified under one trust apart.
    -- proxy_ssl_name then puts the real name back for SNI and the host check.
    host = pool.sni .. "#trust=" .. pool.ca
  end
  assert(balancer.set_current_peer("127.0.0.1", pool.port, host))
  if keepalive then assert(balancer.enable_keepalive(30000, 100)) end
end

local function record(key) stats:incr(ngx.var.poc_rid .. "|" .. key, 1, 0) end

-- mode: "chain" (leaf + the peer's chain against the pool's root),
-- "leaf" (leaf only), "merged" (both tenants' roots: the anti-pattern)
function _M.verify(mode)
  local pool = pools[ngx.var.cdnca_pool]
  record("calls")
  if pool.slow then ngx.sleep(0.1) end
  local raw, err = vfy.get_verify_cert()
  if not raw then ngx.log(ngx.ERR, "get_verify_cert: ", err); return vfy.set_verify_result(28) end
  local leaf = assert(x509.dup(ffi.cast("X509*", raw)))
  local chain
  if mode ~= "leaf" then
    local ptr, perr = ngx_ssl.get_upstream_ssl_pointer()
    if not ptr then ngx.log(ngx.ERR, "upstream ssl pointer: ", perr); return vfy.set_verify_result(28) end
    local stack = ffi.C.SSL_get_peer_cert_chain(ffi.cast("SSL*", ptr))
    if stack ~= nil then chain = assert(x509_chain.dup(stack)) end
    record("chain_len_" .. (chain and #chain or 0))
  end
  local store = mode == "merged" and store_for("trustAB.crt") or store_for(pool.ca)
  local ok, verr = store:verify(leaf, chain)
  if ok then
    record("ok")
    return vfy.set_verify_result(0)
  end
  record("rejected")
  ngx.log(ngx.WARN, "pool ", ngx.var.cdnca_pool, " origin certificate rejected: ", verr)
  -- X509_V_ERR_CERT_REJECTED: with proxy_ssl_verify on, nginx fails the
  -- upstream after the handshake (ngx_http_upstream_ssl_handshake)
  return vfy.set_verify_result(28)
end

function _M.header_filter()
  local prefix = ngx.var.poc_rid .. "|"
  local parts = {}
  for _, k in ipairs({ "calls", "ok", "rejected", "chain_len_0", "chain_len_1", "chain_len_2", "chain_len_3" }) do
    local v = stats:get(prefix .. k)
    if v then parts[#parts + 1] = k .. "=" .. v end
  end
  ngx.header["X-Verify"] = #parts > 0 and table.concat(parts, ",") or "none"
end

return _M
