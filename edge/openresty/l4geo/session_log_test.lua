-- Run with the OpenResty LuaJIT runtime; argv[1] is this test's directory.
-- Session log (session_log, tcp/udp v7): refusal reasons and the client land
-- in the server variables only when the server logs; live session tracking,
-- its removal and the agent control protocol, against fakes.
local root = assert(arg[1], "missing l4geo directory")

local function read(path)
    local file = assert(io.open(path, "rb"))
    local value = file:read("*a")
    file:close()
    return value
end
local prefix = os.tmpname() .. ".d/"
assert(os.execute("mkdir -p " .. prefix))
local config = assert(io.open(prefix .. "config.json", "wb"))
config:write(read(root .. "/fixtures/config-v2.json"))
config:close()

local clock = 1000
local exits = 0
local function fake_dict(capacity)
    local store, size = {}, 0
    local dict = {}
    function dict:get(key)
        local entry = store[key]
        if not entry then return nil end
        if entry.expires and entry.expires <= clock then store[key] = nil; size = size - 1; return nil end
        return entry.value
    end
    function dict:set(key, value, ttl)
        if not store[key] then
            if capacity and size >= capacity then return false, "no memory" end
            size = size + 1
        end
        store[key] = { value = value, expires = ttl and ttl > 0 and clock + ttl or nil }
        return true
    end
    function dict:delete(key)
        if store[key] then size = size - 1 end
        store[key] = nil
    end
    function dict:incr(key, value, init)
        local current = (store[key] and store[key].value) or init
        store[key] = { value = current + value }
        return current + value
    end
    return dict, store
end
local rate_dict = fake_dict()
local live, live_store = fake_dict()

local var = {}
local function connection(values)
    var = values
    ngx.var = values
end
ngx = {
    ERROR = -1, WARN = 5, ERR = 4,
    shared = { l4_v2_rate = rate_dict, l4_v2_live = live },
    now = function() return clock end,
    exit = function() exits = exits + 1 end,
    log = function() end,
    var = var,
    config = { prefix = function() return prefix end },
    worker = { pid = function() return 4242 end },
}
local engine = dofile(root .. "/engine.lua")

-- enforce: a refused session records its reason only on logging servers.
connection({ remote_addr = "203.0.113.200", proxy_protocol_addr = "" })
assert(not engine.enforce("stream-public", true), "cn-north admitted")
assert(var.cdnca_l4_end_reason == "geo_blocked" and var.cdnca_l4_client == "203.0.113.200",
    "geo refusal not recorded: " .. tostring(var.cdnca_l4_end_reason))
connection({ remote_addr = "198.51.100.7", proxy_protocol_addr = "" })
assert(not engine.enforce("stream-public", true), "unknown region admitted")
assert(var.cdnca_l4_end_reason == "geo_blocked", "unknown region reason")
connection({ remote_addr = "203.0.113.200", proxy_protocol_addr = "" })
assert(not engine.enforce("stream-public"), "cn-north admitted without log")
assert(var.cdnca_l4_end_reason == nil and var.cdnca_l4_client == nil, "non-logging server variables touched")
connection({ remote_addr = "198.51.100.7", proxy_protocol_addr = "" })
assert(not engine.enforce("stream-missing", true), "missing listener admitted")
assert(var.cdnca_l4_end_reason == "config_error", "missing listener reason")
-- A trusted proxy's client is the PROXY protocol address.
connection({ remote_addr = "192.0.2.9", proxy_protocol_addr = "203.0.113.10" })
local ok, _, client = engine.enforce("stream-public", true)
assert(ok and client == "203.0.113.10" and var.cdnca_l4_client == "203.0.113.10", "trusted proxy client")
assert(var.cdnca_l4_end_reason == nil, "admitted session got a reason")
connection({ remote_addr = "198.51.100.7" })
ok = engine.enforce("stream-private", true)
assert(ok and var.cdnca_l4_client == "198.51.100.7", "stream without Geo records the peer")

-- limit_new_connections: rate_limited, then banned.
connection({})
assert(engine.limit_new_connections("stream-public", "203.0.113.10", 1, 0, 60, true), "first admitted")
assert(not engine.limit_new_connections("stream-public", "203.0.113.10", 1, 0, 60, true), "second admitted")
assert(var.cdnca_l4_end_reason == "rate_limited", "rate reason " .. tostring(var.cdnca_l4_end_reason))
connection({})
assert(not engine.limit_new_connections("stream-public", "203.0.113.10", 1, 0, 60, true), "banned admitted")
assert(var.cdnca_l4_end_reason == "banned", "ban reason")
connection({})
assert(not engine.limit_new_connections("stream-public", "203.0.113.10", 1, 0, 60), "banned admitted (no log)")
assert(var.cdnca_l4_end_reason == nil, "non-logging rate refusal touched variables")

-- session_track keys by the kernel tuple: direct, trusted proxy, dispatched.
connection({ server_addr = "10.0.0.1", server_port = "9000", remote_addr = "198.51.100.7", remote_port = "40001", connection = "11" })
engine.session_track("stream-a", "listener-a", "198.51.100.7", false)
local direct = "10.0.0.1|9000|198.51.100.7|40001"
assert(var.cdnca_l4_live_key == direct and live_store[direct].value == "stream-a|listener-a|198.51.100.7|40001|1000.000|4242:11|0",
    "direct key/value: " .. tostring(live_store[direct] and live_store[direct].value))
local direct_var = var
connection({ server_addr = "10.0.0.1", server_port = "9001", remote_addr = "192.0.2.9", remote_port = "50000",
    proxy_protocol_addr = "203.0.113.10", proxy_protocol_port = "61000", connection = "12" })
engine.session_track("stream-b", "listener-b", "203.0.113.10", false)
assert(live_store["10.0.0.1|9001|192.0.2.9|50000"].value:find("|203.0.113.10|61000|", 1, true), "trusted proxy client port")
connection({ server_addr = "unix:", server_port = "", proxy_protocol_server_addr = "10.0.0.1", proxy_protocol_server_port = "443",
    remote_addr = "2001:db8::5", remote_port = "40002", connection = "13" })
engine.session_track("stream-c", "listener-c", "2001:db8::5", true)
local dispatched = "10.0.0.1|443|2001:db8::5|40002"
assert(live_store[dispatched] and live_store[dispatched].value:find("|2001:db8::5|40002|", 1, true), "dispatched key")
local dispatched_var = var

-- control: get, kill (marks), stats; unknown keys answer "-".
local function control(lines)
    local input, index, output = lines, 0, {}
    ngx.req = { socket = function()
        return {
            settimeouts = function() end,
            receive = function() index = index + 1; return input[index] end,
            send = function(_, data)
                if type(data) == "table" then data = table.concat(data) end
                output[#output + 1] = data
                return #data
            end,
        }
    end }
    engine.control()
    return table.concat(output)
end
local reply = control({ "get", direct, "10.9.9.9|1|10.9.9.9|2", "end" })
assert(reply == direct .. "\tstream-a|listener-a|198.51.100.7|40001|1000.000|4242:11|0\n10.9.9.9|1|10.9.9.9|2\t-\nend\n",
    "get reply: " .. reply)
reply = control({ "kill", dispatched, "end" })
assert(reply:find("|1\nend\n$"), "kill reply: " .. reply)
assert(control({ "bogus" }) == "error\n", "unknown command accepted")
assert(control({ "get", "bad key", "end" }) == "error\n", "key with spaces accepted")

-- session_end removes only its own entry; a killed one logs "killed".
connection(dispatched_var)
engine.session_end()
assert(live_store[dispatched] == nil and var.cdnca_l4_end_reason == "killed", "killed session end")
live_store[direct].value = "stream-a|listener-a|198.51.100.7|40001|1000.000|4242:99|0" -- a later session on the tuple
connection(direct_var)
engine.session_end()
assert(live_store[direct] ~= nil and var.cdnca_l4_end_reason == nil, "session removed a later session's entry")
connection({ cdnca_l4_live_key = "" })
engine.session_end()

-- A full registry counts untracked sessions instead of failing the session.
local full = fake_dict(0)
ngx.shared.l4_v2_live = full
connection({ server_addr = "10.0.0.1", server_port = "9000", remote_addr = "198.51.100.8", remote_port = "40003", connection = "14" })
engine.session_track("stream-a", "listener-a", "198.51.100.8", false)
assert(var.cdnca_l4_live_key == nil and full:get("untracked") == 1, "full registry")
ngx.shared.l4_v2_live = live
assert(control({ "stats" }) == "untracked 0\n", "stats")
os.remove(prefix .. "config.json")
os.remove(prefix:sub(1, -2))
print("L4_SESSION_LOG_LUA_PASS reasons=8 tracked=3 control=4 end=3 full=1 exits=" .. exits)
