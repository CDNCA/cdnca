-- Dynamic routing D5b: origin request signing (COS/OSS/S3 private buckets)
-- from the site object, without a reload.
--
-- The site object binds a pool to a secret: origin.auth[] {pool_id,
-- endpoint, secret {kind "origin_auth_secret", id = rule ID, revision =
-- publication revision}}. The agent writes the secret object from the
-- node-sealed snapshot (agents/edge-agent/internal/originauth
-- secret_objects.go):
--   <secrets_root>/<rule_id>/<revision>.json   0440, worker group
--   {"schema":"cdnca.edge.origin-auth-secret/v1","rule_id","revision","rule":{...}}
-- with each key's credential inline. Signing itself is the v7 engine's
-- (originauth/engine.lua sign(): the same canonical request, headers and
-- refusals), so both runtimes send byte-identical signed requests.
--
--   configure(opts)        init_by_lua: { secrets_root = <abs path>, cache_items = <n> }
--   sign(site, pool_id)    access_by_lua, once the request's pool is known
--                          (D5a calls it first in access, before firewall
--                          action / challenge / HTTP policy, as v7 does).
--                          No binding for the pool: returns true, nothing
--                          signed. Bound: signs, sets the origin Host to the
--                          bucket endpoint ($cdnca_origin_host), returns
--                          true; anything that cannot be signed ends the
--                          request (403/503) and is never sent unsigned.
--
-- A bound pool's endpoints must reach the bucket over HTTPS (the signature
-- covers host = the endpoint's name; ge-origin "回源鉴权与 HTTPS 回源一致"):
-- a plain endpoint in a signed pool is refused (502) rather than sending
-- credentials-derived headers in clear text. The upstream reuse key carries
-- the secret identity (cdnca_origintls.key), so connections of different
-- signing identities are never shared.
local ngx = ngx
local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"
local engine = require "originauth.engine"

local type, tostring, find = type, tostring, string.find

local _M = { version = "1" }

local SCHEMA = "cdnca.edge.origin-auth-secret/v1"
local MAX_BYTES = 64 * 1024
local MAX_REVISION = 9007199254740991

local config = { secrets_root = nil, cache_items = 1024 }
local cache

function _M.configure(opts)
    assert(type(opts) == "table" and type(opts.secrets_root) == "string" and opts.secrets_root:sub(1, 1) == "/"
        and not find(opts.secrets_root, "%.%."), "cdnca_originauth.configure: secrets_root must be an absolute path")
    config.secrets_root = opts.secrets_root
    config.cache_items = tonumber(opts.cache_items) or config.cache_items
    cache = nil
end

local function lru()
    if not cache then
        cache = assert(lrucache.new(config.cache_items))
    end
    return cache
end

local uuid_pattern = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

local function valid_key(value)
    return engine.has_only(value, { key_id = true, credential = true }) and engine.identifier(value.key_id, 64)
        and type(value.credential) == "table"
end

-- decode(raw, rule_id, revision): the validated rule (keys carry
-- .credential), or nil, reason.
local function decode(raw, rule_id, revision)
    local value = cjson.decode(raw)
    if not engine.has_only(value, { schema = true, rule_id = true, revision = true, rule = true })
        or value.schema ~= SCHEMA or value.rule_id ~= rule_id or value.revision ~= revision then
        return nil, "secret_identity"
    end
    local rule = value.rule
    if type(rule) ~= "table" or rule.rule_id ~= rule_id or not engine.validate_rule(rule, valid_key) then
        return nil, "secret_rule_invalid"
    end
    for _, key in ipairs({ rule.current_key, rule.previous_key }) do
        if not engine.valid_credential(rule.provider, key.credential) then
            return nil, "secret_credential_invalid"
        end
    end
    return rule
end
_M.decode = decode

-- secret(ref): the rule of a site object's secret ref, cached per worker by
-- (id, revision): an object never changes under its revision.
local function secret(ref)
    if type(ref) ~= "table" or ref.kind ~= "origin_auth_secret" or type(ref.id) ~= "string"
        or not ref.id:match(uuid_pattern) or type(ref.revision) ~= "number" or ref.revision < 1
        or ref.revision > MAX_REVISION or ref.revision ~= math.floor(ref.revision) then
        return nil, "secret_ref_invalid"
    end
    if not config.secrets_root then
        return nil, "secret_root_unconfigured"
    end
    local revision = string.format("%d", ref.revision)
    local key = ref.id .. "@" .. revision
    local rule = lru():get(key)
    if rule then
        return rule
    end
    local file = io.open(config.secrets_root .. "/" .. ref.id .. "/" .. revision .. ".json", "rb")
    if not file then
        return nil, "secret_missing"
    end
    local raw = file:read(MAX_BYTES + 1)
    file:close()
    if not raw or #raw > MAX_BYTES then
        return nil, "secret_unreadable"
    end
    local err
    rule, err = decode(raw, ref.id, ref.revision)
    if not rule then
        return nil, err
    end
    lru():set(key, rule)
    return rule
end
_M.secret = secret

local function refuse(status, code)
    ngx.log(ngx.WARN, "cdnca origin auth: refused (", code, ") site=", ngx.var.cdnca_site_id or "-")
    ngx.ctx.cdnca_origin_auth_reject_code = code
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.status = status
    ngx.say(status == ngx.HTTP_FORBIDDEN and "Forbidden" or "Service Unavailable")
    return ngx.exit(status)
end

function _M.binding(site, pool_id)
    for _, auth in ipairs(site and site.origin and site.origin.auth or {}) do
        if auth.pool_id == pool_id then
            return auth
        end
    end
    return nil
end

function _M.sign(site, pool_id)
    local auth = _M.binding(site, pool_id)
    if not auth then
        return true
    end
    for _, pool in ipairs(site.origin.pools) do
        if pool.id == pool_id then
            for _, endpoint in ipairs(pool.endpoints) do
                if endpoint.scheme ~= "https" then
                    return refuse(ngx.HTTP_BAD_GATEWAY, "signed_pool_not_https")
                end
            end
        end
    end
    local rule, err = secret(auth.secret)
    if not rule then
        return refuse(ngx.HTTP_SERVICE_UNAVAILABLE, err)
    end
    local ok = engine.sign(rule, auth.endpoint, nil)
    if not ok then
        return ok
    end
    ngx.var.cdnca_origin_host = rule.endpoint.host
    ngx.ctx.cdnca_origin_auth_secret = tostring(auth.secret.id) .. "@" .. string.format("%d", auth.secret.revision)
    return true
end

return _M
