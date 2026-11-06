-- Run with the OpenResty resty CLI (real shared dict and ngx.re):
--   resty --shdict 'l4_v2_rate 1m' guard_test.lua <l4geo dir> <scratch dir> [<nginx binary>]
-- With the nginx binary (<openresty prefix>/nginx/sbin/nginx) it also runs
-- first packet cases against a real stream server it starts (see the end).
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
local reads, data, rest, rests = 0, nil, nil, 0
engine.read_first_packet = function(wait, rules)
    assert(wait == 2.5 and type(rules) == "table" and rules.first_bytes, "first packet wait")
    reads = reads + 1
    if rest then return data, #rest, "conn" end
    return data
end
engine.read_first_rest = function(rules, got, want, conn)
    assert(type(rules) == "table" and got == data and want == #rest and conn == "conn", "first packet rest")
    rests = rests + 1
    return rest
end
local function connect(client, opts)
    opts = opts or {}
    ngx.var = { remote_addr = opts.peer or client, ssl_preread_server_name = opts.sni, protocol = "TCP" }
    data, rest = opts.data, opts.rest
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

-- More first data known to come (read_first_packet's want): judged on what
-- came while every result so far stays the same with the rest; the first
-- that may change has the rest read once and the rules judged again.
write_config(6, {
    { id = R(24), action = "drop", first_packet = { match = "contains", value = "EVIL" } },
    { id = R(25), action = "allow", first_packet = { match = "contains", value = "GOOD" } },
    { id = R(26), action = "drop", client_ip = { cidrs = { "0.0.0.0/0" } } },
})
rests = 0
assert(not connect("192.0.2.1", { data = "GOOD ", rest = "GOOD EVIL" }) and rests == 1, "a contains miss before the hit waits")
write_config(7, {
    { id = R(25), action = "allow", first_packet = { match = "contains", value = "GOOD" } },
    { id = R(24), action = "drop", first_packet = { match = "contains", value = "EVIL" } },
})
rests = 0
assert(connect("192.0.2.1", { data = "GOOD ", rest = "GOOD EVIL" }) and rests == 0, "a contains hit first settles")
write_config(8, {
    { id = R(27), action = "drop", first_packet = { match = "prefix_hex", value = "4241444b" } },
})
rests = 0
assert(not connect("192.0.2.1", { data = "BA", rest = "BADK" }) and rests == 1, "a prefix start waits")
rests = 0
assert(connect("192.0.2.1", { data = "XY", rest = "XYZW" }) and rests == 0, "a prefix departed from settles")
write_config(9, {
    { id = R(28), action = "allow", first_packet = { match = "regex", value = "^GO" } },
    { id = R(26), action = "drop", client_ip = { cidrs = { "0.0.0.0/0" } } },
})
rests = 0
assert(not connect("192.0.2.1", { data = "GO", rest = "NO" }) and rests == 1, "a regex never settles early")
local partial = 5

-- SNI (exact / wildcard), geo through cdnca_iplib (looked up once).
write_config(10, {
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
write_config(11, nil)
assert(connect("192.0.2.11"), "no rules")

ngx.log = real_log
print(string.format("L4_GUARD_LUA_PASS order=%d bans=%d first_packet=%d partial=%d sni_geo=%d invalid=%d exits=%d",
    order, bans, first, partial, sni, invalid, exits))

-- First packet in a real OpenResty stream server: the engine's own read of
-- a client socket (FFI MSG_PEEK) when the client sends its first data in
-- several TCP segments. arg[3] is the server's nginx binary (e.g.
-- <openresty prefix>/nginx/sbin/nginx); without it this part is skipped.
local binary = arg[3]
if not binary or binary == "" then
    print("L4_GUARD_PROCESS_SKIPPED no nginx binary (arg 3)")
    return
end

local function u16(n) return string.char(math.floor(n / 256) % 256, n % 256) end
local function u24(n) return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256) end
local function ext(kind, body) return u16(kind) .. u16(#body) .. body end
local function filler(n, seed)
    local bytes = {}
    for index = 1, n do bytes[index] = string.char((index * 7 + seed) % 251) end
    return table.concat(bytes)
end

-- tls_hello is a ClientHello shaped like Chrome 133's (16 suites, GREASE,
-- an X25519MLKEM768 key share of 1216 bytes plus X25519, GREASE ECH): about
-- 1.8 KB. sni_last: server_name after key_share and ECH (Chrome permutes its
-- extensions; about half of its hellos are so); small: no MLKEM or ECH (a
-- hello under 700 bytes); records: split the handshake over TLS records of
-- that many bytes.
local function tls_hello(host, opts)
    opts = opts or {}
    local sni = ext(0, u16(#host + 3) .. "\0" .. u16(#host) .. host)
    local groups = opts.small and "\0\29\0\23\0\24" or "\17\236\0\29\0\23\0\24"
    local shares = opts.small and (u16(29) .. u16(32) .. filler(32, 1))
        or (u16(0x11ec) .. u16(1216) .. filler(1216, 2) .. u16(29) .. u16(32) .. filler(32, 3))
    local list = { ext(0x0a0a, ""), ext(23, ""), ext(0xff01, "\0"), ext(10, u16(#groups) .. groups), ext(11, "\1\0"),
        ext(35, ""), ext(16, u16(12) .. "\2h2\8http/1.1"), ext(5, "\1\0\0\0\0"),
        ext(13, u16(16) .. "\4\3\8\4\4\1\5\3\8\5\5\1\8\6\6\1"), ext(18, "") }
    if not opts.sni_last then list[#list + 1] = sni end
    list[#list + 1] = ext(51, u16(#shares) .. shares)
    list[#list + 1] = ext(45, "\1\1")
    list[#list + 1] = ext(43, "\6\58\58\3\4\3\3")
    list[#list + 1] = ext(27, "\2\0\2")
    if not opts.small then
        list[#list + 1] = ext(17613, "\0\3\2h2")
        list[#list + 1] = ext(0xfe0d, "\0\0\1\0\1\45" .. u16(32) .. filler(32, 4) .. u16(144) .. filler(144, 5))
    end
    if opts.sni_last then list[#list + 1] = sni end
    list[#list + 1] = ext(0x1a1a, "\0")
    local extensions = table.concat(list)
    local suites = "\10\10\19\1\19\2\19\3\192\43\192\47\192\44\192\48\204\169\204\168\192\19\192\20\0\156\0\157\0\47\0\53"
    local body = "\3\3" .. filler(32, 6) .. "\32" .. filler(32, 7) .. u16(#suites) .. suites .. "\1\0" ..
        u16(#extensions) .. extensions
    local handshake = "\1" .. u24(#body) .. body
    local size, records = opts.records or #handshake, {}
    for index = 1, #handshake, size do
        local part = handshake:sub(index, index + size - 1)
        records[#records + 1] = "\22\3\1" .. u16(#part) .. part
    end
    return table.concat(records)
end

-- split cuts data at the given offsets.
local function split(data, ...)
    local parts, from = {}, 1
    for _, at in ipairs({ ... }) do
        parts[#parts + 1] = data:sub(from, at)
        from = at + 1
    end
    parts[#parts + 1] = data:sub(from)
    return parts
end

-- The server: two guarded TCP listeners (preread: engine.guard, then
-- proxy_pass, as the agent renders them) in front of a backend that sends
-- "OK\n" then echoes, so an admitted client also sees that the guard
-- consumed none of its data. Listener 1: TLS by
-- the host in the hello (contains / regex) or plain HTTP to /ok is allowed,
-- everything else dropped by a last catch-all rule (the case where a missed
-- allow becomes a drop). Listener 2: only a 4 byte prefix drop.
local prefix = scratch .. "/process/"
local base = 20000 + math.floor(ngx.now() * 1000) % 20000
local port1, port2, backend = base, base + 1, base + 2
local stream2 = "33333333-3333-4333-8333-000000000002"
assert(os.execute("mkdir -p '" .. prefix .. "logs'"))
local function listener(id, rules)
    return { id = id, tenant_id = tenant, site_id = site, stream_id = id, guard = rules,
        geo = { enabled = false, tenant_id = tenant, site_id = site, stream_id = id, revision = 1,
            unknown_region_action = "allow", trusted_proxy_cidrs = {}, blocked_regions = {}, region_cidrs = {} } }
end
local config = assert(io.open(prefix .. "config.json", "wb"))
config:write(cjson.encode({ schema_version = "cdnca.edge.l4/v2", version_id = "guard-process", revision = 1, listeners = {
    listener(stream, {
        { id = R(50), action = "allow", first_packet = { match = "contains", value = "allowed.test" } },
        { id = R(51), action = "allow", first_packet = { match = "regex", value = "api[0-9]+\\.allowed\\.example" } },
        { id = R(52), action = "allow", first_packet = { match = "regex", value = "^GET /ok " } },
        { id = R(53), action = "drop", client_ip = { cidrs = { "0.0.0.0/0" } } },
    }),
    listener(stream2, { { id = R(54), action = "drop", first_packet = { match = "prefix_hex", value = "4241444b" } } }),
} }))
config:close()
local server = function(port, id)
    return string.format([[
    server {
        listen 127.0.0.1:%d;
        preread_timeout 3s;
        preread_by_lua_block { if not require("engine").guard("%s", ngx.var.remote_addr, false, false) then return end }
        proxy_pass 127.0.0.1:%d;
    }
]], port, id, backend)
end
local echo = string.format([[
    server {
        listen 127.0.0.1:%d;
        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            sock:settimeout(3000)
            sock:send("OK\n")
            while true do
                local data = sock:receiveany(65536)
                if not data then break end
                sock:send(data)
            end
        }
    }
]], backend)
local nginx_conf = assert(io.open(prefix .. "nginx.conf", "wb"))
nginx_conf:write(string.format([[
daemon on;
master_process on;
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log warn;
events { worker_connections 256; }
stream {
    lua_package_path "%s/?.lua;;";
    lua_shared_dict l4_v2_rate 1m;
    lua_regex_match_limit 100000;
%s%s%s}
]], root, server(port1, stream), server(port2, stream2), echo))
nginx_conf:close()
local function shell_quote(value) return "'" .. value:gsub("'", "'\\''") .. "'" end
local control = shell_quote(binary) .. " -p " .. shell_quote(prefix) .. " -c nginx.conf"
assert(os.execute(control), "nginx did not start")

local function now() ngx.update_time(); return ngx.now() end

-- exchange sends parts (gap seconds apart, TCP_NODELAY: one segment each)
-- and reports whether the guard admitted the connection (the server's "OK"
-- and every byte echoed) and the seconds from the last write to the verdict
-- (the start for a silent client).
local function exchange(port, parts, gap)
    local sock = ngx.socket.tcp()
    sock:settimeout(5000)
    assert(sock:connect("127.0.0.1", port))
    sock:setoption("tcp-nodelay", true)
    local sent, last = {}, now()
    for index, part in ipairs(parts) do
        if index > 1 and gap > 0 then ngx.sleep(gap) end
        local ok = sock:send(part)
        last = now()
        if not ok then sock:close(); return false, 0 end
        sent[#sent + 1] = part
    end
    local reply = sock:receive(3)
    local elapsed = now() - last
    local admitted = reply == "OK\n"
    local data = table.concat(sent)
    if admitted and #data > 0 then admitted = sock:receive(#data) == data end
    sock:close()
    return admitted, elapsed
end

local early, late = tls_hello("www.allowed.test"), tls_hello("www.allowed.test", { sni_last = true })
local early_at, late_at = early:find("www.allowed.test", 1, true), late:find("www.allowed.test", 1, true)
assert(#early > 1700 and #early < 1900 and early_at < 300 and late_at > 1500, "hello shape " .. #early .. " " .. early_at .. " " .. late_at)
local regex_late = tls_hello("api7.allowed.example", { sni_last = true })
local small = tls_hello("www.allowed.test", { small = true })
local denied = tls_hello("www.denied.test")
local http = "GET /ok HTTP/1.1\r\nHost: a\r\n\r\n"
local cases = {
    -- name, port, parts, gap, admitted, at most / at least seconds from the
    -- last write to the verdict
    { "tls one segment", port1, { early }, 0, true, 0.2 },
    { "tls one segment, SNI past 512 bytes", port1, { late }, 0, true, 0.2 },
    { "tls 1st segment 100 bytes (before SNI) + rest, 20 ms", port1, split(early, 100), 0.02, true, 0.2 },
    { "tls 1st segment 1 byte + rest, 20 ms", port1, split(early, 1), 0.02, true, 0.2 },
    { "tls 1st segment 5 bytes (record header) + rest, 20 ms", port1, split(early, 5), 0.02, true, 0.2 },
    { "tls SNI past key_share, 1448 + rest, 20 ms", port1, split(late, 1448), 0.02, true, 0.2 },
    { "tls SNI past key_share, 3 segments 400/1000, 10 ms", port1, split(late, 400, 1000), 0.01, true, 0.2 },
    { "tls regex on SNI past key_share, 600 + rest, 20 ms", port1, split(regex_late, 600), 0.02, true, 0.2 },
    { "tls 512 byte records, 1 + rest, 20 ms", port1, split(tls_hello("www.allowed.test", { sni_last = true, records = 512 }), 1), 0.02, true, 0.2 },
    { "small tls one segment", port1, { small }, 0, true, 0.2 },
    { "tls other host one segment: dropped", port1, { denied }, 0, false, 0.2 },
    { "tls other host 100 + rest: dropped", port1, split(denied, 100), 0.02, false, 0.2 },
    { "http one segment", port1, { http }, 0, true, 0.2 },
    -- not TLS: judged on what came first, no wait for more (the client may
    -- have sent all), so a request split before the match is dropped
    { "http 5 + rest, 20 ms: judged on the first segment, dropped", port1, split(http, 5), 0.02, false, 0.05 },
    { "http 5 + rest, 300 ms: judged on the first segment, dropped", port1, split(http, 5), 0.3, false, 0.05 },
    { "binary one segment: dropped within the bound", port1, { filler(300, 9) }, 0, false, 0.2 },
    { "fake tls header (huge length): dropped within the bound", port1, { "\22\3\1\255\255" .. filler(40, 8) }, 0, false, 0.2 },
    -- a hello that stops short of its stated length: waited for until
    -- preread_timeout (3 s from the wait), then closed, as ssl_preread does
    { "tls hello cut short, then silent: closed at preread_timeout", port1, { early:sub(1, 100) }, 0, false, 3.5, 2.8 },
    { "silent client: dropped by the catch-all after the 2.5 s wait", port1, {}, 0, false, 3.2, 2.0 },
    { "prefix 4 bytes split 2 + 2, 20 ms: dropped", port2, { "BA", "DK" }, 0.02, false, 0.2 },
    { "prefix start then other bytes, 20 ms: admitted", port2, { "BA", "XY" }, 0.02, true, 0.2 },
    { "prefix miss one segment: admitted at once", port2, { "GOOD" }, 0, true, 0.02 },
    { "silent client, no catch-all: admitted after the 2.5 s wait", port2, {}, 0, true, 3.2, 2.0 },
}
local failures = {}
local ok, err = pcall(function()
    for _, case in ipairs(cases) do
        local name, port, parts, gap, want, most, least = unpack(case)
        local admitted, elapsed = exchange(port, parts, gap)
        if admitted ~= want or elapsed > most or elapsed < (least or 0) then
            failures[#failures + 1] = string.format("%s: admitted=%s (want %s) after %.3fs", name, tostring(admitted), tostring(want), elapsed)
        end
    end
    -- An allow the first segment already settles (a contains hit, no rule
    -- before it that the rest could change) is not held for the rest of the
    -- hello: the reply comes before the client sends it.
    do
        local sock = ngx.socket.tcp()
        sock:settimeout(5000)
        assert(sock:connect("127.0.0.1", port1))
        sock:setoption("tcp-nodelay", true)
        assert(sock:send(early:sub(1, 1000)))
        sock:settimeout(500)
        local reply = sock:receive(3)
        sock:settimeout(5000)
        local echoed = reply == "OK\n" and sock:send(early:sub(1001)) and sock:receive(#early) == early
        sock:close()
        if not echoed then
            failures[#failures + 1] = "tls allow settled by the first segment: reply " .. tostring(reply) .. " before the rest"
        end
    end
    -- Latency: what reading the first packet adds before the verdict, against
    -- a control the read cannot add to (a prefix_hex listener, a 4 byte miss
    -- judged on the first read): medians of runs taken in turn, at most 2 ms
    -- apart. Non-TLS data with contains / regex rules is judged on what came
    -- (nothing is known to follow); a TLS hello in 2 segments 1 ms apart is
    -- judged when its second segment comes.
    local function median(values)
        table.sort(values)
        return values[math.floor(#values / 2) + 1]
    end
    local runs = 31
    for _, check in ipairs({
        { "non-TLS regex hit (http one segment)", port1, function() return { http } end, 0, true },
        { "non-TLS contains / regex miss (binary one segment)", port1, function() return { filler(300, 9) } end, 0, false },
        { "tls hello 100 + rest, 1 ms", port1, function() return split(early, 100) end, 0.001, true },
    }) do
        local name, port, parts, gap, want = unpack(check)
        local case, base = {}, {}
        for run = 1, runs do
            local admitted, elapsed = exchange(port, parts(), gap)
            if admitted ~= want then
                failures[#failures + 1] = string.format("latency %s run %d: admitted=%s", name, run, tostring(admitted))
            end
            case[run] = elapsed
            local good
            good, base[run] = exchange(port2, { "GOOD" }, 0)
            assert(good, "latency control")
        end
        local extra = median(case) - median(base)
        print(string.format("L4_GUARD_LATENCY %s: median %.4fs, control %.4fs, extra %.4fs", name, median(case), median(base), extra))
        if extra > 0.002 then
            failures[#failures + 1] = string.format("latency %s: %.4fs more than the control (at most 0.002)", name, extra)
        end
    end
end)
os.execute(control .. " -s stop")
assert(ok, err)
if #failures > 0 then
    error("first packet in a real OpenResty:\n  " .. table.concat(failures, "\n  "))
end
print(string.format("L4_GUARD_PROCESS_PASS cases=%d", #cases))
