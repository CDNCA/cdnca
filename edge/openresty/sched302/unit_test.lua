-- Unit tests of cdnca_sched302 against libs/edgeconfig/sched302 (the Go
-- reference): the pinned landing signature vector and the candidate choice
-- vectors written by TestWriteSched302LuaVectors. Run with the node's resty:
--   resty -I <dir> unit_test.lua <vectors.json>
local sched302 = require("cdnca_sched302")
local cjson = require("cjson.safe")

local failures = 0
local function check(name, ok, detail)
    if ok then
        print("PASS " .. name)
    else
        failures = failures + 1
        print("FAIL " .. name .. (detail and (" " .. tostring(detail)) or ""))
    end
end

-- Signature vector (sched302_test.go TestSignVector).
local key = {}
for index = 0, 31 do key[#key + 1] = string.char(index) end
key = table.concat(key)
check("sign vector", sched302.sign(key, "11111111-1111-4111-8111-111111111111", "dl.example.test", "/v/a.mp4?x=1",
    1800000060) == "b31jbohLec6U7CFe-WwoRM")

local path = arg[1]
local handle = assert(io.open(path, "rb"))
local vectors = assert(cjson.decode(handle:read("*a")))
handle:close()

local function unhex(value)
    return (value:gsub("..", function(pair) return string.char(tonumber(pair, 16)) end))
end

local candidates = {}
for _, candidate in ipairs(vectors.candidates) do
    candidates[#candidates + 1] = {
        node_id = candidate.node_id, host = candidate.host, http_port = candidate.http_port,
        carrier = candidate.carrier, country = candidate.country, province = candidate.province,
        weight = candidate.weight, available = candidate.available, load = candidate.load,
    }
end
local mismatches = 0
for _, case in ipairs(vectors.cases) do
    local chosen = sched302.select(candidates, unhex(case.address), case.carrier, case.country, case.province)
    local got = chosen and chosen.node_id or ""
    if got ~= case.want then
        mismatches = mismatches + 1
        if mismatches <= 5 then print("  mismatch " .. case.address .. " want " .. case.want .. " got " .. got) end
    end
end
check("select parity (" .. #vectors.cases .. " cases)", mismatches == 0, mismatches .. " mismatches")

if failures > 0 then
    print(failures .. " failed")
    os.exit(1)
end
print("all passed")
