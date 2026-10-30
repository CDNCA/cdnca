local bit = require("bit")
local resty_sha1 = require("resty.sha1")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

local _M = {}

local function digest(module, value)
    local state = module:new()
    if not state or not state:update(value) then
        return nil
    end
    return state:final()
end

function _M.sha1_binary(value)
    return digest(resty_sha1, value)
end

function _M.sha1_hex(value)
    local value_digest = _M.sha1_binary(value)
    return value_digest and resty_string.to_hex(value_digest) or nil
end

function _M.sha256_binary(value)
    return digest(resty_sha256, value)
end

function _M.sha256_hex(value)
    local value_digest = _M.sha256_binary(value)
    return value_digest and resty_string.to_hex(value_digest) or nil
end

local function hmac(hash, key, message)
    if #key > 64 then
        key = hash(key)
        if not key then
            return nil
        end
    end
    key = key .. string.rep("\0", 64 - #key)
    local inner_pad = {}
    local outer_pad = {}
    for index = 1, 64 do
        local byte = key:byte(index)
        inner_pad[index] = string.char(bit.bxor(byte, 0x36))
        outer_pad[index] = string.char(bit.bxor(byte, 0x5c))
    end
    local inner = hash(table.concat(inner_pad) .. message)
    return inner and hash(table.concat(outer_pad) .. inner) or nil
end

function _M.hmac_sha1_binary(key, message)
    return hmac(_M.sha1_binary, key, message)
end

function _M.hmac_sha1_hex(key, message)
    local value = _M.hmac_sha1_binary(key, message)
    return value and resty_string.to_hex(value) or nil
end

function _M.hmac_sha256_binary(key, message)
    return hmac(_M.sha256_binary, key, message)
end

function _M.hmac_sha256_hex(key, message)
    local value = _M.hmac_sha256_binary(key, message)
    return value and resty_string.to_hex(value) or nil
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

return _M
