-- Stand-in for site selection (D3) and endpoint choice (D5a): one site
-- object whose pools all reach 127.0.0.1, the pool picked by ?pool=.
-- Anchors: /t/anchors.json {"A": "<hex>", "B": "<hex>", "missing": "<hex>"}.
local cjson = require "cjson.safe"
local origintls = require "cdnca_origintls"

local _M = {}

local file = assert(io.open("/t/anchors.json", "rb"))
local anchors = assert(cjson.decode(file:read("*a")))
file:close()
local A, B = "sha256:" .. anchors.A, "sha256:" .. anchors.B

local function pool(id, port, sni, anchor, idle)
  return { id = id, kind = "origin", algorithm = "round_robin", keepalive_idle_timeout_ms = idle,
    endpoints = { { id = "e", scheme = "https", host = "127.0.0.1", port = port, weight = 1, sni = sni, trust_anchor = anchor } } }
end

local function mode(p, sni_mode, host)
  p.endpoints[1].sni_mode = sni_mode
  p.endpoints[1].host = host or p.endpoints[1].host
  return p
end

local site = {
  site_id = "0d5b0000-0000-4000-8000-000000000001",
  origin = {
    pools = {
      a       = pool("a", 9441, "origin-a.internal", A),
      a2      = pool("a2", 9441, "origin-a.internal", A),          -- same as a: may share connections
      a_auth  = pool("a_auth", 9441, "origin-a.internal", A),      -- same, but signed by an origin auth secret
      a_noka  = pool("a_noka", 9441, "origin-a.internal", A, 0),   -- reuse off
      a_noint = pool("a_noint", 9442, "origin-a.internal", A),
      a_exp   = pool("a_exp", 9443, "origin-a.internal", A),
      a_name  = pool("a_name", 9444, "origin-a.internal", A),
      b       = pool("b", 9445, "origin-b.internal", B),
      b_evil  = pool("b_evil", 9446, "origin-b.internal", B),      -- A-issued cert for B's name
      a_on_b  = pool("a_on_b", 9445, "origin-b.internal", A),
      -- one origin address and SNI, two trusts (the origin presents an A-issued cert)
      leak_a  = pool("leak_a", 9446, "origin-b.internal", A),
      leak_b  = pool("leak_b", 9446, "origin-b.internal", B),
      sys_a   = pool("sys_a", 9441, "origin-a.internal", "system"),  -- system bundle = tenant A root here
      sys_b   = pool("sys_b", 9445, "origin-b.internal", "system"),
      missing = pool("missing", 9441, "origin-a.internal", "sha256:" .. anchors.missing),
      sni_one = pool("sni_one", 9447, "one.internal", A),
      sni_two = pool("sni_two", 9447, "two.internal", A),
      -- f16 sni_mode: one origin address, the SNI chosen per mode
      mode_custom  = pool("mode_custom", 9447, "two.internal", A),
      mode_origin  = pool("mode_origin", 9447, nil, A),
      mode_visitor = pool("mode_visitor", 9447, nil, A),
      mode_visitor_b = pool("mode_visitor_b", 9445, nil, B),
    },
    auth = { { pool_id = "a_auth", endpoint = "https://bucket.example.test",
      secret = { kind = "origin_auth_secret", id = "0d5b0000-0000-4000-8000-0000000000a1", revision = 1 } } },
  },
}

local pools = site.origin.pools
mode(pools.mode_custom, "custom")
mode(pools.mode_origin, "origin_host", "one.internal") -- the address stays 127.0.0.1
mode(pools.mode_visitor, "visitor_host")
mode(pools.mode_visitor_b, "visitor_host")

local stats = ngx.shared.t_stats

function _M.rewrite()
  local p = site.origin.pools[ngx.var.arg_pool or ""]
  if not p then return ngx.exit(404) end
  ngx.var.t_pool = p.id
  ngx.var.t_rid = ngx.now() .. "-" .. math.random(1e9)
  ngx.var.cdnca_site_id = site.site_id
  ngx.var.cdnca_origin_scheme = "https"
  ngx.var.cdnca_origin_host = origintls.name(p.endpoints[1]) or ngx.var.host
end

function _M.balancer()
  local p = site.origin.pools[ngx.var.t_pool]
  local endpoint = p.endpoints[1]
  if ngx.var.arg_mode == "snikey" then
    -- negative control: ngx_lua's default reuse key (SNI only)
    ngx.var.cdnca_origin_sni, ngx.var.cdnca_origin_trust = endpoint.sni, endpoint.trust_anchor
    assert(require("ngx.balancer").set_current_peer("127.0.0.1", endpoint.port, endpoint.sni))
    assert(require("ngx.balancer").enable_keepalive(30, 100))
    return
  end
  local ok, err = origintls.peer(site, p, endpoint, "127.0.0.1")
  if not ok then
    ngx.log(ngx.ERR, "peer: ", err)
    return ngx.exit(502)
  end
end

function _M.verify()
  stats:incr(ngx.var.t_rid .. "|calls", 1, 0)
  return origintls.verify()
end

function _M.header_filter()
  ngx.header["X-Verify-Calls"] = stats:get(ngx.var.t_rid .. "|calls") or 0
  ngx.header["X-Key"] = origintls.key(site, site.origin.pools[ngx.var.t_pool], site.origin.pools[ngx.var.t_pool].endpoints[1])
end

return _M
