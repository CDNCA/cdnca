-- Site access: the maintenance page and basic
-- authentication of one site, run first in the site's access phase. The
-- agent renders the site's settings as a Lua table literal (siteruntimev2
-- compiler) and the maintenance allowlist as an nginx geo variable; this
-- module never reads files.
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

local _M = {}

local ACME_PREFIX = "/.well-known/acme-challenge/"

local function sha256_hex(value)
    local digest = resty_sha256:new()
    digest:update(value)
    return resty_string.to_hex(digest:final())
end

-- equal compares two hex digests in time independent of where they differ.
local function equal(left, right)
    if #left ~= #right then
        return false
    end
    local difference = 0
    for index = 1, #left do
        difference = bit.bor(difference, bit.bxor(string.byte(left, index), string.byte(right, index)))
    end
    return difference == 0
end

local function has_prefix(prefixes, uri)
    for _, prefix in ipairs(prefixes or {}) do
        if uri:sub(1, #prefix) == prefix then
            return true
        end
    end
    return false
end

local function require_basic(auth)
    ngx.header["WWW-Authenticate"] = 'Basic realm="' .. auth.realm .. '", charset="UTF-8"'
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.status = 401
    ngx.say("Authentication required")
    return ngx.exit(401)
end

-- basic checks the Authorization header against the site's users (each
-- { salt = 16 raw bytes, sha256 = hex of SHA-256(salt .. password) }, one
-- sha256 per request); the credential is removed before the request goes to
-- the origin.
local function basic(auth, uri)
    if has_prefix(auth.exclude, uri) then
        return
    end
    local header = ngx.var.http_authorization
    local encoded = header and header:match("^[Bb][Aa][Ss][Ii][Cc]%s+([A-Za-z0-9+/=]+)%s*$")
    local decoded = encoded and ngx.decode_base64(encoded)
    local username, password
    if decoded then
        username, password = decoded:match("^([^:]*):(.*)$")
    end
    local user = username and auth.users[username]
    if not user or not user.salt or not equal(sha256_hex(user.salt .. password), user.sha256) then
        return require_basic(auth)
    end
    ngx.req.clear_header("Authorization")
end

local function maintenance(page)
    if ngx.var.cdnca_maintenance_allowed == "1" then
        return
    end
    ngx.status = page.status
    ngx.header["Content-Type"] = page.content_type .. "; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    if page.retry_after then
        ngx.header["Retry-After"] = tostring(page.retry_after)
    end
    if ngx.req.get_method() ~= "HEAD" then
        ngx.print(page.body)
    end
    return ngx.exit(page.status)
end

-- access runs the site's maintenance page, then its basic authentication.
-- ACME HTTP-01 challenges pass both (the certificate must still renew).
function _M.access(settings)
    local uri = ngx.var.uri or "/"
    if uri:sub(1, #ACME_PREFIX) == ACME_PREFIX then
        return
    end
    if settings.maintenance then
        maintenance(settings.maintenance)
    end
    if settings.basic_auth then
        basic(settings.basic_auth, uri)
    end
end

return _M
