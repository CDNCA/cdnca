-- Parity, reload and condition tests of cdnca_iplib against the Go
-- reference lookup ((*Table).Lookup). Fixtures come from
-- libs/entitlement/ipintel TestWriteLuaParityFixtures; run with the
-- production LuaJIT (scripts/security/iplib-smoke.sh):
--   luajit parity_test.lua <fixture dir> <scratch dir>
package.path = arg[0]:gsub("[^/]+$", "") .. "?.lua;" .. package.path
local iplib = require("cdnca_iplib")
local bit = require("bit")

local fixtures, scratch = arg[1], arg[2]
local failures = 0

local function check(name, ok, detail)
    if ok then
        print("PASS " .. name .. (detail and (" " .. detail) or ""))
    else
        failures = failures + 1
        print("FAIL " .. name .. (detail and (" " .. detail) or ""))
    end
end

local function unhex(value)
    return (value:gsub("..", function(pair) return string.char(tonumber(pair, 16)) end))
end

local function copy(from, to)
    local input = assert(io.open(from, "rb"))
    local data = input:read("*a")
    input:close()
    local output = assert(io.open(to, "wb"))
    output:write(data)
    output:close()
end

local function sleep_past_second()
    os.execute("sleep 1.1")
end

-- parity compares every case line with lookup().
local function parity(name)
    iplib.configure({ path = fixtures .. "/" .. name .. ".ipi" })
    local mismatches, total, found = 0, 0, 0
    local addresses = {}
    for line in io.lines(fixtures .. "/" .. name .. ".cases") do
        local addr_hex, found_flag, tags, asn, country, province, city =
            line:match("^(%x+) ([01]) (%x+) (%d+) (%S+) (%d+) (%d+)$")
        local addr = unhex(addr_hex)
        addresses[#addresses + 1] = addr
        local attrs, err = iplib.lookup(addr)
        local ok
        if found_flag == "0" then
            ok = attrs == false
        else
            found = found + 1
            ok = type(attrs) == "table"
                and bit.tohex(attrs.tags_hi, 8) .. bit.tohex(attrs.tags_lo, 8) == tags
                and attrs.asn == tonumber(asn) and (attrs.country or "-") == country
                and attrs.province == tonumber(province) and attrs.city == tonumber(city)
        end
        total = total + 1
        if not ok then
            mismatches = mismatches + 1
            if mismatches <= 5 then
                print("  mismatch " .. line .. " got " .. tostring(err or (type(attrs) == "table" and
                    (bit.tohex(attrs.tags_hi, 8) .. bit.tohex(attrs.tags_lo, 8) .. " " .. attrs.asn .. " " ..
                    tostring(attrs.country) .. " " .. attrs.province .. " " .. attrs.city) or tostring(attrs))))
            end
        end
    end
    check("PARITY-" .. name, mismatches == 0 and total > 0,
        string.format("%d addresses (%d found in library), %d mismatches vs Go (*Table).Lookup", total, found, mismatches))
    return addresses
end

parity("boundary")
local addresses = parity("large")

-- Cost per lookup: distinct addresses (cache misses, binary search) and the
-- same address again (one connection, cached).
iplib.configure({ path = fixtures .. "/large.ipi" })
iplib.lookup(addresses[1])
local rounds = 5
local started = os.clock()
for _ = 1, rounds do
    for index = 1, #addresses do iplib.lookup(addresses[index]) end
end
local cold = (os.clock() - started) / (rounds * #addresses) * 1e9
started = os.clock()
local same = addresses[2]
for _ = 1, 2000000 do iplib.lookup(same) end
local warm = (os.clock() - started) / 2000000 * 1e9
local status = iplib.status()
print(string.format("BENCH lookup distinct=%.0f ns cached=%.0f ns (%d IPv4 + %d IPv6 ranges, %d bytes mapped)",
    cold, warm, status.ipv4_ranges, status.ipv6_ranges, status.size))

-- One address (one connection) is searched once, then served from the cache.
iplib.configure({ path = fixtures .. "/boundary.ipi" })
for _ = 1, 100 do iplib.lookup(unhex("08080808")) end
iplib.lookup(unhex("01000001"))
check("CACHE-once-per-address", iplib.status().searches == 2, "searches=" .. tostring(iplib.status().searches))

-- Conditions (specs as libs/edgeconfig renders them).
iplib.configure({ path = fixtures .. "/boundary.ipi" })
local telecom = iplib.lookup(unhex("01000001"))      -- 1.0.0.1: telecom, CN
local google = iplib.lookup(unhex("08080808"))       -- 8.8.8.8: idc:global, AS15169, US
local unknown = iplib.lookup(unhex("01000200"))      -- 1.0.2.0: not in the library
check("SPEC-carrier", iplib.test(telecom, "tag=0000000000000001") and not iplib.test(google, "tag=0000000000000001"))
check("SPEC-carrier-any", iplib.test(telecom, "tag=0000000000000003"))
check("SPEC-idc", iplib.test(google, "tag=0000000000020000") and not iplib.test(google, "tag=0000000000010000"))
check("SPEC-asn", iplib.test(google, "asn=4134,15169") and not iplib.test(telecom, "asn=15169"))
check("SPEC-country", iplib.test(google, "country=US") and iplib.test(telecom, "country!=US"))
check("SPEC-unknown", not iplib.test(unknown, "country=CN") and iplib.test(unknown, "country!=CN")
    and not iplib.test(unknown, "tag=0000000000000001") and iplib.test(unknown, "tag!=0000000000000001"))
check("SPEC-invalid", not iplib.test(telecom, "country=cn") and not iplib.test(telecom, "tag=1")
    and not iplib.test(telecom, "province=440300") and not iplib.test(telecom, "asn!=CN"))
check("SPEC-not-ready", not iplib.test(nil, "country=CN") and not iplib.test(nil, "country!=CN"))

-- Reload: the file is replaced by rename; the switch happens at the next
-- second boundary, never mid-request, and keeps the LKG on a bad file.
local current = scratch .. "/current.ipi"
os.remove(current)
iplib.configure({ path = current })
local attrs, err = iplib.lookup(unhex("01000001"))
check("RELOAD-missing", attrs == nil and err == "not_ready" and not iplib.status().ready)
copy(fixtures .. "/boundary.ipi", current)
sleep_past_second()
attrs = iplib.lookup(unhex("01000001"))
check("RELOAD-first", type(attrs) == "table" and attrs.tags_lo == 1 and iplib.status().revision == 7)
copy(fixtures .. "/boundary-next.ipi", scratch .. "/incoming.ipi")
assert(os.rename(scratch .. "/incoming.ipi", current))
sleep_past_second()
attrs = iplib.lookup(unhex("01000001"))
check("RELOAD-switch", type(attrs) == "table" and attrs.tags_lo == 2 and iplib.status().revision == 8,
    "revision " .. tostring(iplib.status().revision))
local broken = assert(io.open(scratch .. "/incoming.ipi", "wb"))
broken:write("CDNIPI01 truncated")
broken:close()
assert(os.rename(scratch .. "/incoming.ipi", current))
sleep_past_second()
attrs = iplib.lookup(unhex("01000001"))
check("RELOAD-bad-keeps-lkg", type(attrs) == "table" and iplib.status().revision == 8 and iplib.status().problem ~= nil,
    tostring(iplib.status().problem))
os.remove(current)
sleep_past_second()
attrs = iplib.lookup(unhex("01000001"))
check("RELOAD-removed-keeps-lkg", type(attrs) == "table" and iplib.status().revision == 8)

print(failures == 0 and "ALL PASS" or (failures .. " FAILED"))
os.exit(failures == 0 and 0 or 1)
