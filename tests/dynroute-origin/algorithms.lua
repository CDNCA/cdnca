-- Selection order of cdnca_origin's nginx ports against the v7 golden
-- (tests/edge-golden/cdnca-v7/expected/load-balancing.json) and the
-- passive failure accounting. Run by run.sh inside the node runtime.
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

local function site(algorithm, endpoints)
  local eps = {}
  for i, e in ipairs(endpoints) do
    eps[i] = { id = "o" .. (i - 1), scheme = "http", host = "127.0.0.1", port = e[1], weight = e[2] }
  end
  return { site_id = "s", origin = { default_pool_id = "p", routes = {}, auth = {},
    pools = { { id = "p", kind = "origin", algorithm = algorithm, endpoints = eps,
      retry = { methods = { "GET", "HEAD" }, max_attempts = 2, connect_timeout_ms = 2000,
        read_timeout_ms = 5000, total_budget_ms = 10000 } } } } }
end

local digests = 0
local function plan_of(algorithm, endpoints)
  local plan = o.compile(site(algorithm, endpoints))
  digests = digests + 1
  plan.digest = "t" .. digests
  return plan
end

-- n sequential requests (each finished before the next), as the golden sends them
local function run(algorithm, endpoints, n, prepare)
  local plan = plan_of(algorithm, endpoints)
  local out = {}
  for i = 1, n do
    local phase = o._new_phase(plan, plan.default_pool)
    if prepare then prepare(phase, i) end
    local index = o._algorithms[algorithm](phase, ngx.time())
    out[#out + 1] = "o" .. (index - 1)
    o._free_peer(phase, index, false, ngx.time())
  end
  return table.concat(out, ",")
end

expect("round-robin", "o0,o1,o2,o0,o1,o2", run("round_robin", { { 19211, 1 }, { 19212, 1 }, { 19213, 1 } }, 6))
expect("weighted 3:1", "o0,o0,o1,o0,o0,o0,o1,o0", run("round_robin", { { 19214, 3 }, { 19215, 1 } }, 8))
expect("ip-hash 127.0.0.x", "o2,o2", run("ip_hash", { { 19216, 1 }, { 19217, 1 }, { 19218, 1 } }, 2,
  function(phase) phase.client_bytes = { 127, 0, 0 } end))
expect("least-conn", "o0,o1,o0,o1", run("least_conn", { { 19224, 1 }, { 19225, 1 } }, 4))

local hashed = plan_of("url_hash", { { 19219, 1 }, { 19220, 1 }, { 19221, 1 } })
for uri, want in pairs({ ["/one"] = "o1", ["/two"] = "o2", ["/three?q=1"] = "o0" }) do
  local phase = o._new_phase(hashed, hashed.default_pool)
  phase.hash = o._find_point(o._chash_points(hashed.default_pool), ngx.crc32_long(uri))
  expect("url-hash " .. uri, want, "o" .. (o._algorithms.url_hash(phase, ngx.time()) - 1))
end

-- random is a weighted random choice: weight 1:3 -> about 75% on o1
local random = plan_of("random", { { 1, 1 }, { 2, 3 } })
local counts = { 0, 0 }
for _ = 1, 4000 do
  local phase = o._new_phase(random, random.default_pool)
  local index = o._algorithms.random(phase, ngx.time())
  counts[index] = counts[index] + 1
  o._free_peer(phase, index, false, ngx.time())
end
local share = counts[2] / 4000
expect("random weighted 1:3 share in 0.70..0.80", true, share > 0.70 and share < 0.80)

-- passive failure (max_fails=1 fail_timeout=10s): a failed peer is skipped
-- by the next requests, and a retry within one request never reuses a peer
local rr = plan_of("round_robin", { { 1, 1 }, { 2, 1 } })
local phase = o._new_phase(rr, rr.default_pool)
local first = o._algorithms.round_robin(phase, ngx.time())
o._free_peer(phase, first, true, ngx.time())
local second = o._algorithms.round_robin(phase, ngx.time())
expect("retry takes the other peer", 3 - first, second)
o._free_peer(phase, second, false, ngx.time())
local picks = {}
for _ = 1, 3 do
  local next_phase = o._new_phase(rr, rr.default_pool)
  local index = o._algorithms.round_robin(next_phase, ngx.time())
  picks[#picks + 1] = index
  o._free_peer(next_phase, index, false, ngx.time())
end
expect("failed peer skipped for fail_timeout", tostring(3 - first) .. tostring(3 - first) .. tostring(3 - first),
  table.concat(picks))
local exhausted = o._new_phase(rr, rr.default_pool)
o._algorithms.round_robin(exhausted, ngx.time())
expect("no live peer -> nil", nil, o._algorithms.round_robin(exhausted, ngx.time()))

-- single peer ignores max_fails (nginx peers->single)
local single = plan_of("round_robin", { { 1, 1 } })
local sp = o._new_phase(single, single.default_pool)
o._free_peer(sp, o._algorithms.round_robin(sp, ngx.time()), true, ngx.time())
local again = o._new_phase(single, single.default_pool)
expect("single peer after failure", 1, o._algorithms.round_robin(again, ngx.time()))

-- conditional routes: path byte prefix of $request_uri, client CIDR, region
local route_site = site("round_robin", { { 1, 1 } })
route_site.origin.pools[2] = { id = "q", kind = "origin", algorithm = "round_robin",
  endpoints = { { id = "x", scheme = "http", host = "127.0.0.1", port = 3, weight = 1 } },
  retry = route_site.origin.pools[1].retry }
route_site.origin.routes = {
  { id = "api", priority = 10, path_prefix = "/api", pool_id = "q" },
  { id = "far", priority = 5, node_regions = { "elsewhere" }, pool_id = "q" },
  { id = "lan", priority = 1, client_cidrs = { "10.0.0.0/8" }, pool_id = "q" },
}
local route_plan = o.compile(route_site)
expect("routes of other regions dropped", 2, #route_plan.routes)

-- path segment prefix (not v7's byte prefix of $request_uri)
for _, case in ipairs({
  { "/api", "/api", true }, { "/api", "/api/", true }, { "/api", "/api/v1/x", true },
  { "/api", "/apiary", false }, { "/api", "/ap", false }, { "/api", "/", false },
  { "/api/", "/api/v1", true }, { "/api/", "/api/", true }, { "/api/", "/api", false }, { "/api/", "/apiary", false },
  { "/", "/", true }, { "/", "/anything", true },
  { "/a/b", "/a/b/c", true }, { "/a/b", "/a/bc", false }, { "/a/b", "/a", false },
}) do
  expect("path " .. case[1] .. " ~ " .. case[2], case[3], o.path_matches(case[1], case[2]))
end

-- ge-origin forwarding: backup endpoints, max_conns, sticky, hash key
local function pool_site(algorithm, endpoints, extra)
  local s = site(algorithm, {})
  local eps = {}
  for i, e in ipairs(endpoints) do
    eps[i] = { id = e.id or ("o" .. (i - 1)), scheme = "http", host = "127.0.0.1", port = e[1], weight = e[2],
      level = e.level or (e.backup and 1 or nil), max_conns = e.max_conns }
  end
  s.origin.pools[1].endpoints = eps
  for k, v in pairs(extra or {}) do s.origin.pools[1][k] = v end
  return s
end
local function phase_of(s)
  local plan = o.compile(s)
  digests = digests + 1
  plan.digest = "f" .. digests
  return plan, o._new_phase(plan, plan.default_pool)
end

local _, ph = phase_of(pool_site("round_robin", { { 1, 1 }, { 2, 1, backup = true } }))
local first = o._select_endpoint(ph, ngx.time())
o._free_peer(ph, first, true, ngx.time())
expect("backup only after primary failed", "1,2", first .. "," .. tostring(o._select_endpoint(ph, ngx.time())))
local plan_b, ph_b = phase_of(pool_site("round_robin", { { 1, 1 }, { 2, 1, backup = true } }))
local picks_b = {}
for _ = 1, 4 do
  local p = o._new_phase(plan_b, plan_b.default_pool)
  local i = o._select_endpoint(p, ngx.time())
  picks_b[#picks_b + 1] = i
  o._free_peer(p, i, false, ngx.time())
end
expect("backup unused while primary healthy", "1111", table.concat(picks_b))

local plan_m = phase_of(pool_site("round_robin", { { 1, 1, max_conns = 1 }, { 2, 1 } }))
local busy = o._new_phase(plan_m, plan_m.default_pool)
local held = o._select_endpoint(busy, ngx.time()) -- not freed: one connection open
local next_phase = o._new_phase(plan_m, plan_m.default_pool)
local other = o._select_endpoint(next_phase, ngx.time())
expect("max_conns skips a full endpoint", true, held == 1 and other == 2 or held == 2)

-- origin failover levels: a level serves only when
-- every endpoint of the levels before it is unusable
local levels = { { 1, 1 }, { 2, 1 }, { 3, 1, level = 1 }, { 4, 1, level = 2 } }
local function prep(p)
  p.client_bytes = { 127, 0, 0 } -- ip_hash outside a request
  return p
end
local function fail_all(plan, ports, now)
  -- fail every endpoint whose port is in ports once (max_fails 1)
  for _ = 1, 8 do
    local p = prep(o._new_phase(plan, plan.default_pool))
    local i = o._select_endpoint(p, now)
    if not i then return end
    o._free_peer(p, i, ports[plan.default_pool.endpoints[i].port] == true, now)
  end
end
local function picks(plan, n, now)
  local out = {}
  for _ = 1, n do
    local p = prep(o._new_phase(plan, plan.default_pool))
    local i = o._select_endpoint(p, now)
    out[#out + 1] = i and tostring(plan.default_pool.endpoints[i].port) or "none"
    if i then o._free_peer(p, i, false, now) end
  end
  return table.concat(out, ",")
end
local t0 = ngx.time()
local plan_l = phase_of(pool_site("round_robin", levels))
expect("levels: primaries balance, backups idle", "1,2,1,2", picks(plan_l, 4, t0))
fail_all(plan_l, { [1] = true, [2] = true }, t0)
expect("levels: primary down -> backup 1", "3,3", picks(plan_l, 2, t0))
fail_all(plan_l, { [1] = true, [2] = true, [3] = true }, t0)
expect("levels: backup 1 down -> backup 2", "4,4", picks(plan_l, 2, t0))
fail_all(plan_l, { [1] = true, [2] = true, [3] = true, [4] = true }, t0)
expect("levels: all down -> no origin (502)", "none", picks(plan_l, 1, t0))
-- passive recovery after fail_timeout (10 s): auto returns to the primaries
-- (which primary first follows nginx's effective_weight recovery; only
-- the level matters here)
local back = picks(plan_l, 2, t0 + 11)
expect("levels: primaries back after fail_timeout", true, back:match("^[12],[12]$") ~= nil)
-- one request walks the levels within its own attempts
local plan_w = phase_of(pool_site("round_robin", levels))
local walk = o._new_phase(plan_w, plan_w.default_pool)
local order = {}
for _ = 1, 5 do
  local i = o._select_endpoint(walk, t0)
  order[#order + 1] = i and tostring(plan_w.default_pool.endpoints[i].port) or "none"
  if i then o._free_peer(walk, i, true, t0) end
end
expect("levels: one request tries level 0, 1, 2 in order", "1,2,3,4,none", table.concat(order, ","))
-- the control plane's active level (manual failback holds it): level 0 is
-- not used even when healthy, until a publication moves it back
local plan_a = phase_of(pool_site("round_robin", levels, { active_level = 1 }))
expect("levels: active_level 1 skips the primaries", "3,3", picks(plan_a, 2, t0))
fail_all(plan_a, { [3] = true }, t0)
expect("levels: active_level 1, backup 1 down -> backup 2", "4", picks(plan_a, 1, t0))
local plan_back = phase_of(pool_site("round_robin", levels, { active_level = 0 }))
expect("levels: switched back (active_level 0) -> primaries", "1,2", picks(plan_back, 2, t0))
-- per-level algorithms: ip_hash and consistent hash stay within the level
local plan_h = phase_of(pool_site("ip_hash", { { 1, 1 }, { 2, 1, level = 1 }, { 3, 1, level = 1 } }))
fail_all(plan_h, { [1] = true }, t0)
local hashed = picks(plan_h, 1, t0)
expect("levels: ip_hash moves to level 1", true, hashed == "2" or hashed == "3")
local plan_c = phase_of(pool_site("hash", { { 1, 1 }, { 2, 1, level = 1 } }, { hash_key = "fixed" }))
fail_all(plan_c, { [1] = true }, t0)
expect("levels: url_hash moves to level 1", "2", picks(plan_c, 1, t0))
-- hash/ip_hash/random pools walk every level too (any algorithm may have
-- backups since dynamic routing is the only node mode)
for _, algorithm in ipairs({ "hash", "ip_hash", "random" }) do
  local extra = algorithm == "hash" and { hash_key = "fixed" } or nil
  local plan_x = phase_of(pool_site(algorithm, levels, extra))
  local first = picks(plan_x, 1, t0)
  expect("levels: " .. algorithm .. " serves from the primaries", true, first == "1" or first == "2")
  fail_all(plan_x, { [1] = true, [2] = true }, t0)
  expect("levels: " .. algorithm .. " primary down -> backup 1", "3", picks(plan_x, 1, t0))
  fail_all(plan_x, { [1] = true, [2] = true, [3] = true }, t0)
  expect("levels: " .. algorithm .. " backup 1 down -> backup 2", "4", picks(plan_x, 1, t0))
  fail_all(plan_x, { [1] = true, [2] = true, [3] = true, [4] = true }, t0)
  expect("levels: " .. algorithm .. " all down -> 502", "none", picks(plan_x, 1, t0))
  local plan_xa = phase_of(pool_site(algorithm, levels, { hash_key = extra and "fixed" or nil, active_level = 1 }))
  expect("levels: " .. algorithm .. " active_level 1 skips the primaries", "3", picks(plan_xa, 1, t0))
end

-- sticky: the token of endpoint b pins it (golden token of the origin-forwarding site)
local sticky_site = pool_site("sticky", { { 1, 1, id = "a" }, { 2, 1, id = "b" } }, { sticky = { source = "cookie", name = "cdnca_route" } })
sticky_site.site_id = "0a1b2019-0000-4000-8000-000000000103"
sticky_site.origin.pools[1].id = "primary"
sticky_site.origin.default_pool_id = "primary"
local plan_s = o.compile(sticky_site)
expect("sticky token of b", 2, plan_s.pools.primary.tokens["b06dd6cb99f615b375088cc5"])

-- Location rewrite: only the origin's own authority, anchored
local names = { "127.0.0.1", "127.0.0.1:19381" }
for _, case in ipairs({
  { "http://127.0.0.1:19381/next?x=1", true }, { "http://127.0.0.1/a", true }, { "https://127.0.0.1:19381", true },
  { "http://127.0.0.1:193810/x", false }, { "http://127.0.0.1.evil/x", false }, { "http://127.0.0.1@evil/x", false },
  { "https://other.example.test/", false }, { "/relative", false },
}) do
  expect("location " .. case[1], case[2], o._rewrite_location_match(case[1], names))
end

-- custom origin route (B8): pools a route replaces keep the levels of the
-- site origins and the active level; route_levels.json is the control
-- plane's converted origin (edgepublish TestSiteObjectsV2OriginRouteKeepsFailoverLevels)
do
  local f = assert(io.open("/x/route_levels.json"))
  local route_origin = require("cjson.safe").decode(f:read("*a"))
  f:close()
  local plan_r = o.compile({ site_id = "s", origin = route_origin })
  digests = digests + 1
  plan_r.digest = "r" .. digests
  local function route_picks(pool, n, now)
    local out = {}
    for _ = 1, n do
      local p = prep(o._new_phase(plan_r, pool))
      local i = o._select_endpoint(p, now)
      out[#out + 1] = i and pool.endpoints[i].host or "none"
      if i then o._free_peer(p, i, false, now) end
    end
    return table.concat(out, ",")
  end
  local function route_fail(pool, hosts, now)
    for _ = 1, 8 do
      local p = prep(o._new_phase(plan_r, pool))
      local i = o._select_endpoint(p, now)
      if not i then return end
      o._free_peer(p, i, hosts[pool.endpoints[i].host] == true, now)
    end
  end
  local d = plan_r.pools.default
  expect("route levels: default pool from active level 1: levels 1,2", "1,2", table.concat(d.levels, ","))
  expect("route levels: active_level 1 -> backup 1", "192.0.2.11,192.0.2.11", route_picks(d, 2, t0))
  route_fail(d, { ["192.0.2.11"] = true }, t0)
  expect("route levels: backup 1 down -> backup 2", "192.0.2.12", route_picks(d, 1, t0))
  route_fail(d, { ["192.0.2.11"] = true, ["192.0.2.12"] = true }, t0)
  expect("route levels: all down -> 502", "none", route_picks(d, 1, t0))
  local pr = plan_r.pools.primary
  expect("route levels: replaced pool keeps its backup at level 1 (active)", "1", table.concat(pr.levels, ","))
  local backups = plan_r.pools.backups
  expect("route levels: pool of backups only is one level", "0", table.concat(backups.levels, ","))
  local seen = route_picks(backups, 2, t0 + 11)
  expect("route levels: pool of backups only balances", true,
    seen == "192.0.2.11,192.0.2.12" or seen == "192.0.2.12,192.0.2.11")
end

ngx.log(ngx.WARN, "RESULT failures=", fails)
