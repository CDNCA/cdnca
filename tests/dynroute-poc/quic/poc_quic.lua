-- ADR 0009 §8.5 item 2: SNI routing in ssl_client_hello_by_lua and dynamic
-- certificates in ssl_certificate_by_lua on one shared server, TCP and QUIC.
local ssl = require "ngx.ssl"
local clienthello = require "ngx.ssl.clienthello"

local _M = {}
local hits = ngx.shared.poc_hits
local state = ngx.shared.poc_state
local cert_root = "/poc/certs/edge/"

-- site table: SNI -> certificate name, protocols, delay, alt-svc
local sites = {
  ["a.test"] = { cert = "a.test", altsvc = true },
  ["b.test"] = { cert = "b.test" },
  ["*.w.test"] = { cert = "wild.w.test", altsvc = true },
  ["tls12.test"] = { cert = "tls12.test", protocols = { "TLSv1.2" } },
  ["tls13.test"] = { cert = "tls13.test", protocols = { "TLSv1.3" } },
  ["slow.test"] = { cert = "slow.test", delay = 0.2 },
  ["rot.test"] = { cert = "rot.test", rotate = true },
  ["ctl.test"] = { cert = "b.test" }, -- control requests of the test script
}

-- exact name, then the longest leading wildcard (ADR §3.3)
local function lookup(name)
  if not name then return nil end
  name = name:lower()
  if sites[name] then return sites[name], name end
  local rest = name
  while true do
    local dot = rest:find(".", 1, true)
    if not dot then return nil end
    rest = rest:sub(dot + 1)
    local wild = "*." .. rest
    if sites[wild] then return sites[wild], wild end
  end
end
_M.lookup = lookup

local function count(key) hits:incr(key, 1, 0) end

function _M.client_hello()
  local name = clienthello.get_client_hello_server_name()
  -- quic_transport_parameters (57) is present only in a QUIC ClientHello
  local transport = clienthello.get_client_hello_ext(57) and "quic" or "tcp"
  ngx.ctx.transport = transport
  local site, key = lookup(name)
  count((key or name or "-") .. "|" .. transport .. "|hello")
  if not site then
    count("reject|" .. transport)
    return ngx.exit(ngx.ERROR)
  end
  if site.delay then ngx.sleep(site.delay) end -- yield in client hello
  if site.protocols then
    local ok, err = clienthello.set_protocols(site.protocols)
    if not ok then ngx.log(ngx.ERR, "set_protocols: ", err); return ngx.exit(ngx.ERROR) end
  end
end

local parsed = {}
local function load(name)
  if parsed[name] then return parsed[name] end
  local f = assert(io.open(cert_root .. name .. ".crt"))
  local crt = f:read("*a"); f:close()
  f = assert(io.open(cert_root .. name .. ".key"))
  local key = f:read("*a"); f:close()
  parsed[name] = { cert = assert(ssl.parse_pem_cert(crt)), key = assert(ssl.parse_pem_priv_key(key)) }
  return parsed[name]
end

function _M.certificate()
  local name = ssl.server_name()
  local site, key = lookup(name)
  -- ngx.ctx is shared by the SSL phases of one connection
  local transport = ngx.ctx.transport or "noctx"
  count((key or name or "-") .. "|" .. transport .. "|cert")
  if not site then return ngx.exit(ngx.ERROR) end
  if site.delay then ngx.sleep(site.delay) end -- yield in certificate
  local cert_name = site.cert
  if site.rotate then cert_name = cert_name .. "-" .. (state:get("rot") or "v1") end
  local pair = load(cert_name)
  assert(ssl.clear_certs())
  assert(ssl.set_cert(pair.cert))
  assert(ssl.set_priv_key(pair.key))
end

function _M.header_filter()
  local site = lookup(ngx.var.ssl_server_name)
  if site and site.altsvc then ngx.header["Alt-Svc"] = 'h3=":8443"; ma=60' end
end

function _M.content()
  local site, key = lookup(ngx.var.host)
  ngx.say("site=", key or "-", " proto=", ngx.var.server_protocol, " sni=", ngx.var.ssl_server_name or "-",
    " tls=", ngx.var.ssl_protocol or "-")
end

function _M.hits()
  local keys = hits:get_keys(0)
  table.sort(keys)
  for _, k in ipairs(keys) do ngx.say(k, "=", hits:get(k)) end
end

return _M
