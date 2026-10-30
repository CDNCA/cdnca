-- Run with the OpenResty LuaJIT runtime; argv[1] is this test's directory.
-- Exercises limit_new_connections against a fake clock and shared dict.
local root = assert(arg[1], "missing l4geo directory")

local clock = 1000
local exits = 0
local store = {}
local dict = {}
function dict:get(key)
    local entry = store[key]
    if not entry then return nil end
    if entry.expires and entry.expires <= clock then store[key] = nil; return nil end
    return entry.value
end
function dict:set(key, value, ttl)
    store[key] = { value = value, expires = ttl and ttl > 0 and clock + ttl or nil }
    return true
end
ngx = {
    ERROR = -1, WARN = 5, ERR = 4,
    shared = { l4_v2_rate = dict },
    now = function() return clock end,
    exit = function() exits = exits + 1 end,
    log = function() end,
    var = {},
}
local engine = dofile(root .. "/engine.lua")
local stream, other = "33333333-3333-4333-8333-000000000001", "33333333-3333-4333-8333-000000000002"
local function admitted(count, client, rate, burst, ban, stream_id)
    local passed = 0
    for _ = 1, count do
        if engine.limit_new_connections(stream_id or stream, client, rate, burst, ban) then passed = passed + 1 end
    end
    return passed
end

-- rate 2, burst 3: capacity 5 at once, then 2 per second.
assert(admitted(8, "192.0.2.1", 2, 3, 0) == 5, "initial capacity is rate+burst")
assert(exits == 3, "rejected connections are closed")
assert(admitted(1, "192.0.2.2", 2, 3, 0) == 1, "another client has its own bucket")
assert(admitted(1, "192.0.2.1", 2, 3, 0, other) == 1, "another stream has its own bucket")
clock = clock + 1
assert(admitted(5, "192.0.2.1", 2, 3, 0) == 2, "refill is rate per second")
clock = clock + 10
assert(admitted(9, "192.0.2.1", 2, 3, 0) == 5, "refill stops at capacity")
assert(admitted(2, "2001:db8::1", 1, 0, 0) == 1, "IPv6 clients are counted")

-- ban: the first refusal bans the client for ban_seconds, even after refill.
assert(admitted(3, "198.51.100.7", 1, 1, 30) == 2, "ban stream capacity")
clock = clock + 10
assert(admitted(1, "198.51.100.7", 1, 1, 30) == 0, "banned client refused although tokens refilled")
assert(admitted(1, "198.51.100.8", 1, 1, 30) == 1, "ban is per client")
clock = clock + 21
assert(admitted(1, "198.51.100.7", 1, 1, 30) == 1, "ban expires")

-- invalid arguments and a missing dictionary close the connection (fail closed).
exits = 0
for _, args in ipairs({
    { stream, "192.0.2.9", 0, 0, 0 }, { stream, "192.0.2.9", 1, -1, 0 }, { stream, "192.0.2.9", 1, 0, 86401 },
    { stream, "", 1, 0, 0 }, { "bad id", "192.0.2.9", 1, 0, 0 }, { stream, nil, 1, 0, 0 },
}) do
    assert(not engine.limit_new_connections(args[1], args[2], args[3], args[4], args[5]), "invalid arguments accepted")
end
ngx.shared.l4_v2_rate = nil
assert(not engine.limit_new_connections(stream, "192.0.2.9", 1, 0, 0), "missing dictionary accepted")
assert(exits == 7, "invalid configurations must close the connection")
print("L4_NEW_CONN_RATE_PASS capacity=1 refill=1 cap=1 per_client=1 per_stream=1 ipv6=1 ban=1 ban_expiry=1 invalid=7")
