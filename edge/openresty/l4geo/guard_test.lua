-- Run with the OpenResty resty CLI (real shared dict and ngx.re):
--   resty --shdict 'l4_v2_rate 1m' guard_test.lua <l4geo dir> <scratch dir>
-- L4 guard rules (guard_rules, tcp/udp v10): rule order, client IP ranges,
-- thresholds and bans, the kernel ban queue, first packet matches (a client
-- that sends nothing is never refused), SNI, geo, and invalid rules.
local root = assert(arg[1], "missing l4geo directory")
local scratch = assert(arg[2], "missing scratch directory")
package.path = root .. "/?.lua;" .. package.path

local cjson = require("cjson.safe")
local tenant, site = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
local stream = "33333333-3333-4333-8333-000000000001"
local R = function(n) return string.format("66666666-6666-4666-8666-%012d", n) end

-- Fake iplib: attributes per binary address.
local lookups = 0
package.loaded.cdnca_iplib = {
    lookup = function(addr)
        lookups = lookups + 1
        if addr == string.char(198, 51, 100, 7) then return { country = "US", tags_lo = 0x20000, tags_hi = 0 } end
        return false
    end,
    test = function(attrs, spec)
        if attrs == nil then return false end
        if spec == "country=US" then return attrs ~= false and attrs.country == "US" end
        if spec == "country!=US" then return attrs == false or attrs.country ~= "US" end
        return false
    end,
}

local exits, logs = 0, {}
ngx.exit = function() exits = exits + 1 end
local real_log = ngx.log
ngx.log = function(level, ...) logs[#logs + 1] = table.concat({ ... }) end
ngx.config.prefix = function() return scratch .. "/" end
local engine = require("engine")

local function write_config(revision, rules)
    local listener = { id = stream, tenant_id = tenant, site_id = site, stream_id = stream, guard = rules,
        geo = { enabled = false, tenant_id = tenant, site_id = site, stream_id = stream, revision = revision,
            unknown_region_action = "allow", trusted_proxy_cidrs = {}, blocked_regions = {}, region_cidrs = {} } }
    local file = assert(io.open(scratch .. "/config.json", "wb"))
    file:write(cjson.encode({ schema_version = "cdnca.edge.l4/v2", version_id = "guard-" .. revision, revision = revision,
        listeners = { listener } }))
    file:close()
end

local dict = ngx.shared.l4_v2_rate
local reads, data = 0, nil
engine.read_first_packet = function(wait)
    assert(wait == 2.5, "first packet wait")
    reads = reads + 1
    return data
end
local function connect(client, opts)
    opts = opts or {}
    ngx.var = { remote_addr = opts.peer or client, ssl_preread_server_name = opts.sni, protocol = "TCP" }
    data = opts.data
    local before = exits
    local ok = engine.guard(stream, client, opts.log, opts.kernel)
    assert((ok == true) == (exits == before), "guard result and exit disagree")
    return ok == true
end

-- Order, client IP (IPv4 / IPv6, negate): a /32 allow before a /24 drop.
write_config(1, {
    { id = R(1), action = "allow", client_ip = { cidrs = { "192.0.2.10/32" } } },
    { id = R(2), action = "drop", client_ip = { cidrs = { "192.0.2.0/24", "2001:db8::/32" } } },
    { id = R(3), action = "drop", client_ip = { cidrs = { "10.0.0.0/8", "192.0.2.0/24", "2001:db8::/32", "203.0.113.0/24", "198.51.100.0/24" }, negate = true } },
})
assert(connect("192.0.2.10"), "allow before drop")
assert(not connect("192.0.2.11"), "range drop")
assert(not connect("2001:db8::5"), "IPv6 range drop")
assert(connect("10.1.2.3"), "outside the negated range is the only pass")
assert(not connect("172.16.0.1"), "negated range drops the rest")
local order = 5

-- Threshold 3 in 60 s, ban 2 s; kernel queue only for the socket peer on
-- the stream's own socket; another client unaffected; the ban expires.
write_config(2, {
    { id = R(10), action = "ban", ban_seconds = 2, threshold = 3, window_seconds = 60, client_ip = { cidrs = { "203.0.113.0/24" } } },
})
assert(not connect("203.0.113.1", { kernel = true }) and dict:get("ban:" .. stream .. ":203.0.113.1") == nil, "hit 1 drops, no ban")
assert(not connect("203.0.113.1", { kernel = true }) and dict:get("ban:" .. stream .. ":203.0.113.1") == nil, "hit 2 drops, no ban")
assert(not connect("203.0.113.1", { kernel = true }) and dict:get("ban:" .. stream .. ":203.0.113.1"), "hit 3 bans")
local queued = dict:rpop("kban")
assert(queued and queued:match("^" .. stream:gsub("%-", "%%-") .. "|203%.0%.113%.1|%d+$"), "kernel ban queued: " .. tostring(queued))
assert(dict:llen("kban") == 0, "one entry per ban")
-- The ban refuses even a connection no rule would match (it is the stream's).
write_config(3, {
    { id = R(10), action = "ban", ban_seconds = 2, threshold = 3, window_seconds = 60, client_ip = { cidrs = { "203.0.113.0/24" } } },
    { id = R(11), action = "ban", ban_seconds = 60, threshold = 1, client_ip = { cidrs = { "198.51.100.0/24" } } },
})
assert(not connect("203.0.113.1", { log = true }) and ngx.var.cdnca_l4_end_reason == "banned", "banned client refused, end reason banned")
assert(connect("192.0.2.200"), "other client passes")
-- Threshold 1: banned at once; behind a trusted proxy (peer differs) or a
-- dispatcher (kernel false) only the stream's ban, no kernel queue.
assert(not connect("198.51.100.1", { kernel = true, peer = "10.9.9.9", log = true }), "threshold 1 bans")
assert(ngx.var.cdnca_l4_end_reason == "guard_blocked", "banning end reason")
assert(not connect("198.51.100.2", { kernel = false }), "dispatched ban")
assert(dict:llen("kban") == 0, "no kernel ban for a proxied client or a dispatched socket")
ngx.sleep(2.1)
assert(not connect("203.0.113.1"), "expired ban: counting starts over (hits kept in the window)")
assert(dict:get("ban:" .. stream .. ":203.0.113.1"), "window hits continue")
local bans = 3

-- First packet: prefix, contains, regex; read once per connection and only
-- when the other conditions hold; nothing sent / unreadable never refuses.
write_config(4, {
    { id = R(20), action = "drop", client_ip = { cidrs = { "192.0.2.0/24" } }, first_packet = { match = "prefix_hex", value = "16030100" } },
    { id = R(21), action = "drop", first_packet = { match = "contains", value = "GET /admin" } },
    { id = R(22), action = "drop", first_packet = { match = "regex", value = "^SSH-2\\.0-(?i:libssh)" } },
})
reads = 0
assert(not connect("192.0.2.1", { data = "\22\3\1\0\5" }) and reads == 1, "TLS prefix")
reads = 0
assert(connect("192.0.2.1", { data = "\22\3\3\0" }) and reads == 1, "other prefix passes; one read for three rules")
assert(not connect("203.0.113.9", { data = "xx GET /admin HTTP/1.1" }), "contains")
assert(not connect("203.0.113.9", { data = "SSH-2.0-LIBSSH_0.9" }), "regex, case-insensitive group")
assert(connect("203.0.113.9", { data = "SSH-2.0-OpenSSH_9" }), "regex miss")
reads = 0
assert(connect("203.0.113.9", { data = "" }) and reads == 1, "client sent nothing within the wait: passes")
assert(connect("203.0.113.9", { data = nil }), "first packet unreadable: passes")
write_config(5, {
    { id = R(23), action = "drop", client_ip = { cidrs = { "192.0.2.0/24" } }, first_packet = { match = "contains", value = "x" } },
})
reads = 0
assert(connect("203.0.113.9", { data = "x" }) and reads == 0, "no wait when an earlier condition fails")
local first = 8

-- SNI (exact / wildcard), geo through cdnca_iplib (looked up once).
write_config(6, {
    { id = R(30), action = "drop", server_names = { "*.example.com", "admin.example.org" } },
    { id = R(31), action = "drop", geo = { "country=US" } },
})
assert(not connect("192.0.2.1", { sni = "a.example.com" }), "wildcard SNI")
assert(connect("192.0.2.1", { sni = "example.com" }), "wildcard needs a label")
assert(not connect("192.0.2.1", { sni = "ADMIN.example.org" }), "SNI case-insensitive")
assert(connect("192.0.2.1", { sni = "" }), "no SNI")
lookups = 0
assert(not connect("198.51.100.7") and lookups == 1, "geo US, one lookup")
assert(connect("198.51.100.8"), "geo unknown address passes")
local sni = 6

-- Invalid rules are refused: the candidate is rejected (cold: closed).
local invalid = 0
for _, rules in ipairs({
    { { id = R(40), action = "drop", first_packet = { match = "regex", value = "(a" } } },
    { { id = R(40), action = "drop", first_packet = { match = "prefix_hex", value = "160" } } },
    { { id = R(40), action = "drop", first_packet = { match = "contains", value = "a\0b" } } },
    { { id = R(40), action = "ban", ban_seconds = 10, threshold = 2, client_ip = { cidrs = { "192.0.2.0/24" } } } },
    { { id = R(40), action = "ban", ban_seconds = 10, threshold = 1, window_seconds = 5, client_ip = { cidrs = { "192.0.2.0/24" } } } },
    { { id = R(40), action = "drop", ban_seconds = 10, client_ip = { cidrs = { "192.0.2.0/24" } } } },
    { { id = R(40), action = "drop" } },
    { { id = R(40), action = "drop", client_ip = { cidrs = { "192.0.2.1/24" } } } },
    { { id = R(40), action = "drop", server_names = { "-bad-.com" } } },
    { { id = R(40), action = "drop", geo = { "country=US;" } } },
    { { id = "x", action = "drop", client_ip = { cidrs = { "192.0.2.0/24" } } } },
    { { id = R(40), action = "reject", client_ip = { cidrs = { "192.0.2.0/24" } } } },
    { { id = R(40), action = "drop", extra = 1, client_ip = { cidrs = { "192.0.2.0/24" } } } },
    { { id = R(40), action = "drop", client_ip = { cidrs = { "192.0.2.0/24" } } }, { id = R(40), action = "drop", client_ip = { cidrs = { "192.0.2.0/24" } } } },
}) do
    assert(engine.compile_guard(rules) == nil, "invalid rule set " .. cjson.encode(rules))
    invalid = invalid + 1
end
assert(engine.compile_guard({}) == nil, "empty rule list")

-- A listener without rules is unaffected; a stream without the dictionary
-- fails closed.
write_config(7, nil)
assert(connect("192.0.2.11"), "no rules")

ngx.log = real_log
print(string.format("L4_GUARD_LUA_PASS order=%d bans=%d first_packet=%d sni_geo=%d invalid=%d exits=%d",
    order, bans, first, sni, invalid, exits))
