-- Minimal IPv4/IPv6 CIDR matcher with the lua-resty-ipmatcher interface the
-- firewall action engine uses (new(list), :match(address)). Fixture only.
local bit = require("bit")

local _M = {}
local mt = { __index = _M }

local function ipv4_bytes(value)
    local a, b, c, d = value:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    local bytes = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
    for _, byte in ipairs(bytes) do if byte > 255 then return nil end end
    return bytes
end

local function ipv6_bytes(value)
    if not value:find(":", 1, true) then return nil end
    local head, tail = value:match("^(.-)::(.*)$")
    local function groups(text)
        local result = {}
        if text == "" then return result end
        for group in text:gmatch("[^:]+") do
            local number = tonumber(group, 16)
            if not number or #group > 4 then return nil end
            result[#result + 1] = number
        end
        return result
    end
    local left, right
    if head then left, right = groups(head), groups(tail) else left, right = groups(value), {} end
    if not left or not right or #left + #right > 8 then return nil end
    local all = {}
    for _, group in ipairs(left) do all[#all + 1] = group end
    for _ = 1, 8 - #left - #right do all[#all + 1] = 0 end
    for _, group in ipairs(right) do all[#all + 1] = group end
    if #all ~= 8 then return nil end
    local bytes = {}
    for _, group in ipairs(all) do
        bytes[#bytes + 1] = bit.rshift(group, 8)
        bytes[#bytes + 1] = bit.band(group, 255)
    end
    return bytes
end

local function parse(value)
    return ipv4_bytes(value) or ipv6_bytes(value)
end

function _M.new(list)
    local networks = {}
    for _, item in ipairs(list) do
        local address, bits = item:match("^([^/]+)/(%d+)$")
        address = address or item
        local bytes = parse(address)
        if not bytes then return nil, "invalid network " .. tostring(item) end
        networks[#networks + 1] = { bytes = bytes, bits = tonumber(bits) or #bytes * 8 }
    end
    return setmetatable({ networks = networks }, mt)
end

function _M.match(self, address)
    local bytes = parse(address or "")
    if not bytes then return false end
    for _, network in ipairs(self.networks) do
        if #network.bytes == #bytes then
            local remaining, matched = network.bits, true
            for index = 1, #bytes do
                if remaining <= 0 then break end
                local take = math.min(8, remaining)
                local mask = bit.band(bit.lshift(255, 8 - take), 255)
                if bit.band(bytes[index], mask) ~= bit.band(network.bytes[index], mask) then matched = false; break end
                remaining = remaining - take
            end
            if matched then return true end
        end
    end
    return false
end

return _M
