local bit = require("bit")
local resty_string = require("resty.string")

local _M = {}

local MAX_XFF_BYTES = 2048
local MAX_XFF_HOPS = 32

local function parse_ipv4(value)
    if type(value) ~= "string" or #value == 0 or #value > 15 then
        return nil
    end
    local bytes = {}
    for part in (value .. "."):gmatch("(.-)%.") do
        if part == "" or part:find("[^0-9]") or (#part > 1 and part:sub(1, 1) == "0") then
            return nil
        end
        local byte = tonumber(part)
        if not byte or byte > 255 then
            return nil
        end
        bytes[#bytes + 1] = byte
    end
    if #bytes ~= 4 then
        return nil
    end
    return { family = 4, bytes = bytes, display = value, canonical = "4:" .. resty_string.to_hex(string.char(unpack(bytes))) }
end

local function ipv6_side(value)
    local words = {}
    if value == "" then
        return words
    end
    if value:sub(1, 1) == ":" or value:sub(-1) == ":" or value:find("::", 1, true) then
        return nil
    end
    for part in value:gmatch("[^:]+") do
        if #part > 4 or not part:match("^[0-9A-Fa-f]+$") then
            return nil
        end
        words[#words + 1] = tonumber(part, 16)
    end
    return words
end

local function parse_ipv6(value)
    if type(value) ~= "string" or #value < 2 or #value > 45 or value:find("[%%%.]") then
        return nil
    end
    local marker = value:find("::", 1, true)
    if marker and value:find("::", marker + 2, true) then
        return nil
    end
    local left = ipv6_side(marker and value:sub(1, marker - 1) or value)
    local right = ipv6_side(marker and value:sub(marker + 2) or "")
    if not left or not right then
        return nil
    end
    local missing = 8 - #left - #right
    if (marker and missing < 1) or (not marker and missing ~= 0) then
        return nil
    end
    local words = {}
    for _, word in ipairs(left) do words[#words + 1] = word end
    for _ = 1, missing do words[#words + 1] = 0 end
    for _, word in ipairs(right) do words[#words + 1] = word end
    if #words ~= 8 then
        return nil
    end
    local bytes = {}
    for _, word in ipairs(words) do
        bytes[#bytes + 1] = math.floor(word / 256)
        bytes[#bytes + 1] = word % 256
    end
    return {
        family = 6,
        bytes = bytes,
        display = string.lower(value),
        canonical = "6:" .. resty_string.to_hex(string.char(unpack(bytes))),
    }
end

local function parse_ip(value)
    if type(value) ~= "string" or #value > 64 or value:find("[%c%s]") then
        return nil
    end
    return value:find(":", 1, true) and parse_ipv6(value) or parse_ipv4(value)
end

local function cidr_contains(cidr, address)
    if cidr.family ~= address.family then
        return false
    end
    local full_bytes = math.floor(cidr.prefix_length / 8)
    for index = 1, full_bytes do
        if cidr.network[index] ~= address.bytes[index] then
            return false
        end
    end
    local remaining = cidr.prefix_length % 8
    if remaining == 0 then
        return true
    end
    local mask = bit.band(bit.lshift(255, 8 - remaining), 255)
    return bit.band(cidr.network[full_bytes + 1], mask) == bit.band(address.bytes[full_bytes + 1], mask)
end

local function in_cidrs(address, cidrs)
    for _, cidr in ipairs(cidrs) do
        if cidr_contains(cidr, address) then
            return true
        end
    end
    return false
end

function _M.client_address(trusted_proxies)
    local peer = parse_ip(ngx.var.remote_addr)
    if not peer then
        return nil
    end
    local forwarded = ngx.var.http_x_forwarded_for
    if not forwarded or not in_cidrs(peer, trusted_proxies) then
        return peer
    end
    if #forwarded == 0 or #forwarded > MAX_XFF_BYTES or forwarded:find("[%c]") then
        return peer
    end
    local chain = {}
    for part in (forwarded .. ","):gmatch("(.-),") do
        part = part:match("^[ ]*(.-)[ ]*$")
        local address = parse_ip(part)
        if not address or #chain >= MAX_XFF_HOPS then
            return peer
        end
        chain[#chain + 1] = address
    end
    if #chain == 0 then
        return peer
    end
    chain[#chain + 1] = peer
    for index = #chain - 1, 1, -1 do
        if not in_cidrs(chain[index], trusted_proxies) then
            return chain[index]
        end
    end
    return chain[1]
end

return _M
