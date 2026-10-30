local bit = require("bit")
local random = require("resty.random")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

local _M = {}

local function sha256_binary(value)
    local digest = resty_sha256:new()
    if not digest or not digest:update(value) then
        return nil
    end
    return digest:final()
end

function _M.sha256_hex(value)
    local digest = sha256_binary(value)
    return digest and resty_string.to_hex(digest) or nil
end

function _M.constant_time_equal(left, right)
    if type(left) ~= "string" or type(right) ~= "string" then
        return false
    end
    local maximum = math.max(#left, #right)
    local difference = bit.bxor(#left, #right)
    for index = 1, maximum do
        difference = bit.bor(difference, bit.bxor(left:byte(index) or 0, right:byte(index) or 0))
    end
    return difference == 0
end

function _M.hmac_sha256_hex(secret, message)
    if #secret > 64 then
        secret = sha256_binary(secret)
        if not secret then
            return nil
        end
    end
    secret = secret .. string.rep("\0", 64 - #secret)
    local inner_pad = {}
    local outer_pad = {}
    for index = 1, 64 do
        local byte = secret:byte(index)
        inner_pad[index] = string.char(bit.bxor(byte, 0x36))
        outer_pad[index] = string.char(bit.bxor(byte, 0x5c))
    end
    local inner = sha256_binary(table.concat(inner_pad) .. message)
    if not inner then
        return nil
    end
    return _M.sha256_hex(table.concat(outer_pad) .. inner)
end

function _M.base64url_encode(value)
    return (ngx.encode_base64(value):gsub("+", "-"):gsub("/", "_"):gsub("=+$", ""))
end

function _M.base64url_decode(value)
    if type(value) ~= "string" or value == "" or value:find("[^A-Za-z0-9_-]") then
        return nil
    end
    local remainder = #value % 4
    if remainder == 1 then
        return nil
    end
    local padded = value:gsub("-", "+"):gsub("_", "/") .. string.rep("=", (4 - remainder) % 4)
    return ngx.decode_base64(padded)
end

function _M.random_token(bytes)
    local value = random.bytes(bytes, true)
    if not value or #value ~= bytes then
        return nil
    end
    return _M.base64url_encode(value)
end

return _M
