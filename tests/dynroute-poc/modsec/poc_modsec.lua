-- ADR 0009 §8.5 item 5: managed WAF (ModSecurity + CRS) on one shared server.
-- Lua resolves the site and hands ModSecurity the site's WAF parameters in the
-- transaction id; nothing in the ModSecurity configuration is per site.
local _M = {}
local policy = ngx.shared.poc_waf

-- Site policies live in a shared dict (the site object's "managed_waf" in the
-- dynamic runtime) so the test changes them live, without a reload:
--   poc_waf["<host>"] = "pl=<n>;thr=<n>;mode=<block|detect>;sets=<set>,<set>;ex=<prefix>=<ids>|<prefix>=<ids>"
-- ("" prefix = whole site). "broken.test" is routed but never given a context.
local routed = { ["a.test"] = true, ["b.test"] = true, ["c.test"] = true, ["d.test"] = true, ["broken.test"] = true }

local function parse(value)
  local pl, thr, mode, sets, ex = (value or ""):match("^pl=([1-4]);thr=([0-9]+);mode=(%a+);sets=([a-z0-9,]*);ex=(.*)$")
  if not pl then return nil end
  return { pl = tonumber(pl), thr = tonumber(thr), mode = mode, sets = sets, ex = ex }
end

local function exclusions(site, uri)
  -- prefixes are matched on the normalised $uri, the path ModSecurity's
  -- REQUEST_FILENAME is built from
  local ids = {}
  for rule in site.ex:gmatch("[^|]+") do
    local prefix, list = rule:match("^([^=]*)=([0-9,]+)$")
    if prefix and (prefix == "" or uri:sub(1, #prefix) == prefix) then
      ids[#ids + 1] = list
    end
  end
  return "," .. table.concat(ids, ",") .. ","
end

function _M.server_rewrite()
  local host = (ngx.var.host or ""):lower()
  if not routed[host] then return ngx.exit(421) end
  ngx.var.cdnca_site = host
  ngx.req.set_header("X-Poc-Server-Rewrite", "set-in-server-rewrite")
  local site = parse(policy:get(host))
  if not site then return end -- no transaction id: ModSecurity must fail closed
  ngx.var.cdnca_waf_txid = string.format("s=%s;pl=%d;thr=%d;mode=%s;sets=,%s,;ex=%s;|%08x%08x", host, site.pl,
    site.thr, site.mode, site.sets, exclusions(site, ngx.var.uri), math.random(0, 0x7fffffff), math.random(0, 0x7fffffff))
end

function _M.rewrite()
  ngx.req.set_header("X-Poc-Rewrite", "set-in-rewrite")
end

function _M.access()
  ngx.log(ngx.WARN, "POC-ACCESS uri=", ngx.var.uri, " txid=", ngx.var.cdnca_waf_txid)
  if ngx.var.uri:sub(1, 5) == "/exec" then return ngx.exec("@variant") end
end

-- admin: /set?host=a.test&policy=<policy string>
function _M.admin()
  policy:set(ngx.var.arg_host, ngx.unescape_uri(ngx.var.arg_policy or ""))
  ngx.say(ngx.var.arg_host, " -> ", policy:get(ngx.var.arg_host))
end

return _M
