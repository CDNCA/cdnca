-- A19-a (EDGE-L2-EFFECTIVE-01): an L2 pool as the control plane publishes
-- it from an L2 configuration (节点管理 > L2配置) behaves on the node as
-- configured: 轮询 is weighted round robin by the member weights in member
-- sort order, URL哈希 pins one URL to one L2 node. Run by
-- tests/edge-site/l2-config-smoke.sh inside the node runtime image.
-- A19-b: 模式=缓存 (only cached URLs through L2) and L2 conditions
-- (request rules, node_ids, union of matching conditions, direct when no
-- default candidate) below.
-- 待出包前全量跑（子任务不跑真实 OpenResty）。
package.loaded["cdnca_site"] = { current = function() return nil end }
local o = require "cdnca_origin"
o.configure({})

local fails = 0
local function expect(name, want, got)
  if want == got then
    ngx.log(ngx.WARN, "PASS ", name, " = ", tostring(got))
  else
    fails = fails + 1
    ngx.log(ngx.WARN, "FAIL ", name, " want=", tostring(want), " got=", tostring(got))
  end
end

local RETRY = { methods = { "GET", "HEAD" }, max_attempts = 2, connect_timeout_ms = 2000,
  read_timeout_ms = 5000, total_budget_ms = 10000 }

-- the site object's L2 pool: endpoints in member sort order (l2-c first),
-- member weights 3 and 1, plus the direct fallback pool
local function site(algorithm)
  return { site_id = "s", origin = {
    default_pool_id = "l2-topology", routes = {}, auth = {},
    l2 = { direct_fallback_pool_id = "primary", probe_interval_ms = 10000, failure_threshold = 3, recovery_threshold = 3 },
    pools = {
      { id = "l2-topology", kind = "l2", algorithm = algorithm, retry = RETRY, endpoints = {
        { id = "l2-c", scheme = "http", host = "127.0.0.1", port = 19431, weight = 3, node_id = "c" },
        { id = "l2-a", scheme = "http", host = "127.0.0.1", port = 19432, weight = 1, node_id = "a" },
      } },
      { id = "primary", kind = "origin", algorithm = "round_robin", retry = RETRY, endpoints = {
        { id = "origin-0", scheme = "http", host = "127.0.0.1", port = 19433, weight = 100 },
      } },
    } } }
end

local digests = 0
local function plan_of(algorithm)
  local plan = o.compile(site(algorithm))
  digests = digests + 1
  plan.digest = "l2-" .. digests
  return plan
end

-- 轮询: smooth weighted round robin over the member weights (3:1), the
-- first member in sort order first
local plan = plan_of("round_robin")
local out = {}
for _ = 1, 8 do
  local phase = o._new_phase(plan, plan.default_pool)
  local index = o._algorithms.round_robin(phase, ngx.time())
  out[#out + 1] = plan.default_pool.endpoints[index].id
  o._free_peer(phase, index, false, ngx.time())
end
expect("round robin by member weight", "l2-c,l2-c,l2-a,l2-c,l2-c,l2-c,l2-a,l2-c", table.concat(out, ","))
expect("L2 is the default pool", "l2", plan.default_pool.kind)
expect("direct fallback", "primary", plan.default_fallback.id)

-- URL哈希: one URL always the same L2 node; different URLs spread
local hashed = plan_of("url_hash")
local points = o._chash_points(hashed.default_pool)
local seen, stable = {}, true
for _, uri in ipairs({ "/a.jpg", "/b.jpg", "/c.jpg", "/d.jpg", "/e.jpg", "/f.jpg", "/g.jpg", "/h.jpg" }) do
  local first
  for _ = 1, 3 do
    local phase = o._new_phase(hashed, hashed.default_pool)
    phase.hash = o._find_point(points, ngx.crc32_long(uri))
    local index = o._algorithms.url_hash(phase, ngx.time())
    o._free_peer(phase, index, false, ngx.time())
    first = first or index
    stable = stable and first == index
  end
  seen[hashed.default_pool.endpoints[first].id] = true
end
expect("url hash pins a URL", true, stable)
expect("url hash uses both L2 nodes", true, seen["l2-a"] == true and seen["l2-c"] == true)

-- A19-b (L2_ROUTING): 模式=缓存 and L2 conditions. cdnca_origin keeps
-- ngx.var from its load; a fresh copy is loaded over a stand-in whose values
-- each case sets (timers have no request variables).
local request = {}
ngx.var = setmetatable({}, { __index = function(_, name) return request[name] end })
package.loaded["cdnca_origin"] = nil
o = require "cdnca_origin"
o.configure({ node_id = "018f47a2-5b9c-7d31-8a60-104c9c0b7a20" })
local function with_request(var, fn)
  request = var
  return fn()
end

local L1 = "018f47a2-5b9c-7d31-8a60-104c9c0b7a20"
local function routed_site(l2)
  local value = site("round_robin")
  value.origin.l2.cache_only = l2.cache_only
  value.origin.l2.conditions = l2.conditions
  value.origin.pools[1].endpoints[#value.origin.pools[1].endpoints + 1] =
    { id = "l2-b", scheme = "http", host = "127.0.0.1", port = 19434, weight = 1, node_id = "b" }
  return value
end
local function routed(l2, var)
  local plan = o.compile(routed_site(l2))
  digests = digests + 1
  plan.digest = "l2-" .. digests
  local pool, fallback, route = with_request(var, function() return o.select_route(plan) end)
  local ids = {}
  for _, endpoint in ipairs(pool.endpoints) do ids[#ids + 1] = endpoint.id end
  return table.concat(ids, ","), route, fallback and fallback.id or "-"
end

-- 模式=缓存: the cache module decides (stub: /static/ is cached)
package.loaded["cdnca_cache"] = { cacheable = function(_, _, uri) return uri:sub(1, 8) == "/static/" end }
expect("cache mode: cached URL through L2", "l2-c,l2-a,l2-b",
  (routed({ cache_only = true }, { uri = "/static/a.css", request_uri = "/static/a.css", host = "x.test", scheme = "http" })))
expect("cache mode: other URL direct", "origin-0",
  (routed({ cache_only = true }, { uri = "/api/x", request_uri = "/api/x", host = "x.test", scheme = "http" })))
package.loaded["cdnca_cache"] = nil
expect("cache mode without cache module: direct", "origin-0",
  (routed({ cache_only = true }, { uri = "/static/a.css", request_uri = "/static/a.css", host = "x.test", scheme = "http" })))

-- conditions: c1 images (regex on uri) -> l2-a; c2 https on host suffix -> l2-b;
-- l2-c no condition (the default candidate)
local conditions = {
  { id = "c1", rules = { { field = "uri", operator = "regex", value = [[^/img/.*\.(png|jpg)$]] } }, endpoint_ids = { "l2-a" } },
  { id = "c2", rules = { { field = "protocol", operator = "eq", value = "HTTPS" },
    { field = "host", operator = "suffix", value = ".Example.test" } }, endpoint_ids = { "l2-b" } },
}
local function req(uri, host, scheme)
  return { uri = uri, request_uri = uri .. "?v=1", host = host, scheme = scheme }
end
expect("condition: image -> its L2", "l2-a", (routed({ conditions = conditions }, req("/img/a.png", "a.test", "http"))))
expect("condition: no match -> default candidates", "l2-c", (routed({ conditions = conditions }, req("/a.html", "a.test", "http"))))
expect("condition: AND of rules", "l2-c", (routed({ conditions = conditions }, req("/a.html", "a.example.test", "http"))))
expect("condition: both match -> union in member order", "l2-a,l2-b",
  (routed({ conditions = conditions }, req("/img/a.png", "a.example.test", "https"))))
local _, route = routed({ conditions = conditions }, req("/img/a.png", "a.test", "http"))
expect("condition route id", "l2_condition", route)
local _, _, fallback = routed({ conditions = conditions }, req("/img/a.png", "a.test", "http"))
expect("condition keeps direct fallback", "primary", fallback)
expect("not_regex negates", "l2-a", (routed({ conditions = { { id = "c1",
  rules = { { field = "request_uri", operator = "not_regex", value = "^/api/" } }, endpoint_ids = { "l2-a" } } } },
  req("/page", "a.test", "http"))))
expect("not_contains negates", "l2-c,l2-b", (routed({ conditions = { { id = "c1",
  rules = { { field = "uri", operator = "not_contains", value = "page" } }, endpoint_ids = { "l2-a" } } } },
  req("/page", "a.test", "http"))))

-- node_ids: a condition for other L1 nodes never matches here; one for
-- this node with no request rules always does (海外节点)
expect("condition for other L1 nodes ignored", "l2-c,l2-b", (routed({ conditions = { { id = "c1",
  node_ids = { "018f47a2-5b9c-7d31-8a60-104c9c0b7a99" }, endpoint_ids = { "l2-a" } } } }, req("/x", "a.test", "http"))))
expect("condition for this L1 node", "l2-a", (routed({ conditions = { { id = "c1",
  node_ids = { L1 }, endpoint_ids = { "l2-a" } } } }, req("/x", "a.test", "http"))))

-- every member on a condition, none matching: direct
local direct, direct_route = routed({ conditions = { { id = "c1", rules = { { field = "host", operator = "eq", value = "b.test" } },
  endpoint_ids = { "l2-a", "l2-b", "l2-c" } } } }, req("/x", "a.test", "http"))
expect("no default candidate: direct", "origin-0", direct)
expect("no default candidate route", "l2_direct", direct_route)

-- cache mode first, then conditions
package.loaded["cdnca_cache"] = { cacheable = function() return false end }
expect("cache mode before conditions", "origin-0",
  (routed({ cache_only = true, conditions = conditions }, req("/img/a.png", "a.test", "http"))))
package.loaded["cdnca_cache"] = nil

-- a match-limit error is no match (logged), the request keeps the default
expect("regex error is no match", "l2-c,l2-b", (routed({ conditions = { { id = "c1",
  rules = { { field = "uri", operator = "regex", value = "(" } }, endpoint_ids = { "l2-a" } } } }, req("/x", "a.test", "http"))))

-- L2_ROUTING v2: pass-through L2, this node as an L2
-- endpoint, the hop mark.
local function passthrough_site()
  local value = site("round_robin")
  value.origin.l2.passthrough = true
  value.listeners = { { port = 8443, tls = { certificate_version_id = "018f47a2-5b9c-7d31-8a60-104c9c0b7e01" } } }
  return value
end
local function route_on(node_id, value, var)
  o.configure({ node_id = node_id })
  local plan = o.compile(value)
  digests = digests + 1
  plan.digest = "l2-" .. digests
  local pool, fallback, route = with_request(var, function() return o.select_route(plan) end)
  return pool, fallback, route, plan
end
-- 本节点是 L2 端点：直连源站，不再转 L2
local pool, fallback, route = route_on("c", passthrough_site(), req("/x", "a.test", "http"))
expect("L2 endpoint node goes direct", "origin-0", pool.endpoints[1].id)
expect("L2 endpoint node route", "l2_self", route)
expect("L2 endpoint node has no further fallback", "-", fallback and fallback.id or "-")
-- 防环：带 L2 跳标记的请求只直连
local marked = req("/x", "a.test", "http")
marked.http_x_cdnca_l2_hop = "1"
pool, _, route = route_on(L1, passthrough_site(), marked)
expect("L2 hop mark goes direct", "origin-0", pool.endpoints[1].id)
expect("L2 hop mark route", "l2_hop", route)
-- L1：走 L2，回落直连
local plan
pool, fallback, route, plan = route_on(L1, passthrough_site(), req("/x", "a.test", "http"))
expect("L1 goes through L2", "l2", pool.kind)
expect("L1 keeps direct fallback", "primary", fallback.id)
-- L1→L2 端口透传：访客 HTTP 8080 进来 → http://L2:8080
local view = with_request({ https = "", cdnca_site_port = "8080", host = "a.test" },
  function() return o._hop_endpoint(plan, plan.site, pool, pool.endpoints[1]) end)
expect("passthrough http scheme", "http", view.scheme)
expect("passthrough http port", 8080, view.port)
expect("passthrough keeps L2 address", "127.0.0.1", view.host)
-- 访客 HTTPS 8443 进来 → https://L2:8443，SNI 为访客 SNI，校验本站证书
package.loaded["cdnca_tls"] = { listener_for = function(current, port)
  for _, listener in ipairs(current.listeners or {}) do
    if listener.port == port then return listener end
  end
end }
view = with_request({ https = "on", cdnca_site_port = "8443", host = "a.test", ssl_server_name = "www.a.test" },
  function() return o._hop_endpoint(plan, plan.site, pool, pool.endpoints[1]) end)
expect("passthrough https scheme", "https", view.scheme)
expect("passthrough https port", 8443, view.port)
expect("passthrough https SNI", "www.a.test", view.sni)
expect("passthrough https pins the site certificate", "l2:018f47a2-5b9c-7d31-8a60-104c9c0b7e01", view.trust)
package.loaded["cdnca_tls"] = nil
-- 非 passthrough（快照发布）L2 端点保持原样
local snapshot = o.compile(site("round_robin"))
view = with_request({ https = "on", cdnca_site_port = "8443", host = "a.test" },
  function() return o._hop_endpoint(snapshot, nil, snapshot.default_pool, snapshot.default_pool.endpoints[1]) end)
expect("snapshot L2 endpoint unchanged", "http:19431", view.scheme .. ":" .. view.port)

-- An L2 trusts an L1's hop only from a node network. The
-- entry module runs with every security/limit module stubbed to record its
-- calls; cdnca_origin and cdnca_telemetry are the real ones.
local calls, cleared = {}, {}
local function recorder(name)
  return setmetatable({}, { __index = function(_, fn)
    return function() calls[#calls + 1] = name .. "." .. fn end
  end })
end
local hop_site = { site_id = "s", origin = { default_pool_id = "primary", routes = {}, auth = {}, pools = {
  { id = "primary", kind = "origin", algorithm = "round_robin", retry = RETRY, endpoints = {
    { id = "origin-0", scheme = "http", host = "127.0.0.1", port = 19433, weight = 100 } } } } } }
-- writes land in the case's request table (the entry sets $cdnca_l2_trusted)
getmetatable(ngx.var).__newindex = function(_, name, value) request[name] = value end
for _, name in ipairs({ "cdnca_tls", "cdnca_security", "cdnca_limits", "cdnca_managed_waf", "siteaccess.engine",
  "cdnca_origintls", "cdnca_originauth" }) do
  package.loaded[name] = recorder(name)
end
package.loaded["cdnca_filters"] = { routed = function() calls[#calls + 1] = "routed" end, register = function() end }
package.loaded["cdnca_site"] = { route = function() return hop_site end, current = function() return hop_site end,
  dropped = function() return false end, configure = function() end }
package.loaded["cdnca_origin"] = nil
package.loaded["cdnca_telemetry"] = nil
package.loaded["cdnca_dynroute"] = nil
local real_req = ngx.req
ngx.req = setmetatable({ clear_header = function(name) cleared[#cleared + 1] = name; request["http_" .. name:lower():gsub("-", "_")] = nil end,
  is_internal = function() return false end }, { __index = real_req })
local entry = require "cdnca_dynroute"
entry.configure({ node_networks = { "10.9.0.0/16", "2001:db8:9::/48" } })
local origin = require "cdnca_origin"
local telemetry = require "cdnca_telemetry"
-- origin selection and passive health are not under test here
local origin_access, origin_log = origin.access, origin.log
origin.access, origin.log = function() end, function() end
local function phase_calls(fn)
  calls = {}
  fn()
  return table.concat(calls, ",")
end
local function rewrite(var)
  calls, cleared = {}, {}
  var.cdnca_site_digest = var.cdnca_site_digest or "hop-site"
  request = var
  entry.server_rewrite()
  return table.concat(calls, ",")
end

-- 受信对端（节点网段）+ 跳标记：跳过 CC / 套餐限制 / TLS 检查，标为 L2 跳
local trusted = { http_x_cdnca_l2_hop = "1", remote_addr = "10.9.1.2", http_x_real_ip = "203.0.113.7",
  http_x_forwarded_for = "203.0.113.7", http_x_forwarded_proto = "https", scheme = "http", cdnca_site_host = "a.test" }
expect("trusted hop skips CC and limits", "routed", rewrite(trusted))
expect("trusted hop marked", "1", trusted.cdnca_l2_trusted)
expect("trusted hop keeps the mark header", 0, #cleared)
-- 受信跳：遥测与回源用访客地址，XFF 访客在首位、不追加 L1
expect("trusted hop client ip is the visitor", "203.0.113.7", origin.client_ip())
local xff, real, proto = origin._forwarded({}, { kind = "origin" })
expect("trusted hop origin XFF visitor first", "203.0.113.7", xff)
expect("trusted hop origin X-Real-IP", "203.0.113.7", real)
expect("trusted hop origin X-Forwarded-Proto from L1", "https", proto)
-- 访问日志标 l2:true（agent 跳过，不重复计费）
request.cdnca_site_generation, request.cdnca_site_scope, request.cdnca_site_digest, request.cdnca_site_port = "1", "sc", "dg", "80"
expect("trusted hop line marked l2", true, telemetry._attribute('{"a":1}'):find('"l2":true}}', 1, true) ~= nil)
-- access/log 阶段也跳过（限制、规则、自动防御、CC 计数）
expect("trusted hop access skips limits and security", "", phase_calls(entry.access))
expect("trusted hop log skips CC counters", nil, phase_calls(entry.log):find("cdnca_security.log", 1, true))

-- 非受信对端带标记：剥头，按普通访客走 CC，访客自带 X-Real-IP 不采信
local forged = { http_x_cdnca_l2_hop = "1", remote_addr = "198.51.100.9", http_x_real_ip = "203.0.113.7",
  scheme = "http", cdnca_site_host = "a.test" }
local forged_calls = rewrite(forged)
expect("untrusted mark goes through CC", true, forged_calls:find("cdnca_security.server_rewrite", 1, true) ~= nil)
expect("untrusted mark not trusted", nil, forged.cdnca_l2_trusted)
expect("untrusted access counts limits", true, phase_calls(entry.access):find("cdnca_limits.enter", 1, true) ~= nil)
expect("untrusted log counts CC", true, phase_calls(entry.log):find("cdnca_security.log", 1, true) ~= nil)
expect("untrusted mark header stripped", "X-Cdnca-L2-Hop", cleared[1])
expect("untrusted client ip is the peer", "198.51.100.9", origin.client_ip())
xff, real = origin._forwarded({}, { kind = "origin" })
expect("untrusted origin X-Real-IP is the peer", "198.51.100.9", real)
request.cdnca_site_generation, request.cdnca_site_scope, request.cdnca_site_digest, request.cdnca_site_port = "1", "sc", "dg", "80"
expect("untrusted line not marked l2", true, telemetry._attribute('{"a":1}'):find('"l2":false}}', 1, true) ~= nil)
-- 节点网段内但无标记：普通访客（节点间探测等）
expect("node peer without mark goes through CC", true,
  rewrite({ remote_addr = "10.9.1.2", scheme = "http", cdnca_site_host = "a.test" }):find("cdnca_security.server_rewrite", 1, true) ~= nil)
-- 标记值不是 1：不受信并剥掉
local odd = { http_x_cdnca_l2_hop = "yes", remote_addr = "10.9.1.2", scheme = "http", cdnca_site_host = "a.test" }
rewrite(odd)
expect("odd mark value not trusted", nil, odd.cdnca_l2_trusted)
-- L1 发往 L2：任何 L2 池都按源站规则描述访客（不透传访客伪造的头）
xff, real = with_request({ remote_addr = "203.0.113.7", http_x_forwarded_for = "6.6.6.6", http_x_real_ip = "6.6.6.6", scheme = "https" },
  function() return origin._forwarded({}, { kind = "l2" }) end)
expect("L1 to L2 XFF is the visitor", "203.0.113.7", xff)
expect("L1 to L2 X-Real-IP is the visitor", "203.0.113.7", real)
ngx.req = real_req
origin.access, origin.log = origin_access, origin_log

ngx.log(ngx.WARN, "RESULT failures=", fails)
