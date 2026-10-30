-- Stand-in site object for the origin auth acceptance (D3/D5a replace it):
-- one pool per provider bound to its secret, plus negative cases.
local origintls = require "cdnca_origintls"
local originauth = require "cdnca_originauth"

local _M = {}

local function pool(id, port, sni, scheme)
  return { id = id, kind = "origin", algorithm = "round_robin",
    endpoints = { { id = "e", scheme = scheme or "https", host = "127.0.0.1", port = port, weight = 1,
      sni = scheme ~= "http" and sni or nil, trust_anchor = scheme ~= "http" and ANCHOR or nil } } }
end
local function secret(id, revision)
  return { kind = "origin_auth_secret", id = id, revision = revision }
end

local S3, OSS, COS = "examplebucket.s3.us-east-1.amazonaws.com", "bucket.oss-cn-hangzhou.aliyuncs.com",
  "testbucket-125000000.cos.ap-guangzhou.myqcloud.com"
local site = {
  site_id = "0d5b0000-0000-4000-8000-000000000002",
  origin = {
    pools = {
      pool("s3", 19501, S3), pool("oss", 19502, OSS), pool("cos", 19503, COS),
      pool("s3r2", 19501, S3), pool("missing", 19501, S3), pool("plain", 19501, S3, "http"),
      pool("unsigned", 19501, S3),
    },
    auth = {
      { pool_id = "s3", endpoint = "https://" .. S3, secret = secret("0d5b0000-0000-4000-8000-0000000000a1", 1) },
      { pool_id = "oss", endpoint = "https://" .. OSS, secret = secret("0d5b0000-0000-4000-8000-0000000000a2", 1) },
      { pool_id = "cos", endpoint = "https://" .. COS, secret = secret("0d5b0000-0000-4000-8000-0000000000a3", 1) },
      { pool_id = "s3r2", endpoint = "https://" .. S3, secret = secret("0d5b0000-0000-4000-8000-0000000000a1", 2) },
      { pool_id = "missing", endpoint = "https://" .. S3, secret = secret("0d5b0000-0000-4000-8000-0000000000ff", 1) },
      { pool_id = "plain", endpoint = "https://" .. S3, secret = secret("0d5b0000-0000-4000-8000-0000000000a1", 1) },
    },
  },
}
local pools = {}
for _, p in ipairs(site.origin.pools) do pools[p.id] = p end

function _M.rewrite()
  local p = pools[ngx.var.arg_pool or ""]
  if not p then return ngx.exit(404) end
  ngx.var.t_pool = p.id
  ngx.var.cdnca_site_id = site.site_id
  ngx.var.cdnca_origin_scheme = p.endpoints[1].scheme
  ngx.var.cdnca_origin_host = ngx.var.host
end

function _M.access()
  originauth.sign(site, ngx.var.t_pool)
end

function _M.balancer()
  local p = pools[ngx.var.t_pool]
  local ok, err = origintls.peer(site, p, p.endpoints[1], "127.0.0.1")
  if not ok then
    ngx.log(ngx.ERR, "peer: ", err)
    return ngx.exit(502)
  end
end

return _M
