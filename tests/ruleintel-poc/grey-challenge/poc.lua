-- ADR 0011 §3.2 grey-zone challenge, PoC shape. server_rewrite writes the
-- context "g=<0|1>;b=<0|1>;|<request id>" into the transaction ID:
--   g=1  a valid challenge cookie: HMAC(site, client address, hour) (AD-04 L1 form)
--   b=1  a browser-class request (Accept text/html, or GET/HEAD/form POST
--        without X-Requested-With / Authorization / a JSON-like body)
-- challenge() is the named location the node rule's deny,status:<code>
-- lands on through error_page: GET/HEAD get a JS page that sets the cookie
-- and reloads; any other method gets a 307 to the same URL with the cookie
-- (the browser repeats method and body), as cdnca_waf.lua challenge().
local _M = {}
local SECRET = "ri01-poc-secret"
local COOKIE = "cdnca_wc"

local function token(hour)
  return ngx.encode_base64(ngx.hmac_sha1(SECRET, (ngx.var.host or "") .. "|" .. ngx.var.remote_addr .. "|" .. hour))
    :gsub("[+/=]", { ["+"] = "-", ["/"] = "_", ["="] = "" })
end

local function passed()
  local value = ngx.var["cookie_" .. COOKIE]
  if not value then return false end
  local hour = math.floor(ngx.time() / 3600)
  return value == token(hour) or value == token(hour - 1)
end

local function browser()
  local h = ngx.req.get_headers()
  if h["authorization"] or h["x-requested-with"] then return false end
  local accept = h["accept"] or ""
  if type(accept) == "table" then accept = table.concat(accept, ",") end
  if accept:find("text/html", 1, true) then return true end
  if accept:find("application/json", 1, true) then return false end
  local method = ngx.req.get_method()
  local ctype = (type(h["content-type"]) == "string" and h["content-type"] or ""):lower()
  if method == "GET" or method == "HEAD" then return true end
  return method == "POST" and (ctype:find("application/x-www-form-urlencoded", 1, true) == 1 or
    ctype:find("multipart/form-data", 1, true) == 1)
end

function _M.server_rewrite()
  ngx.var.cdnca_waf_txid = string.format("g=%d;b=%d;|%s", passed() and 1 or 0, browser() and 1 or 0, ngx.var.request_id)
end

function _M.challenge()
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-Cdnca-WAF"] = "challenge"
  ngx.header["X-Poc-Challenge-Method"] = ngx.req.get_method()
  ngx.header["X-Poc-Txid"] = ngx.var.cdnca_waf_txid
  local cookie = COOKIE .. "=" .. token(math.floor(ngx.time() / 3600)) .. "; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax"
  local method = ngx.req.get_method()
  if method ~= "GET" and method ~= "HEAD" then
    ngx.header["Set-Cookie"] = cookie
    ngx.header["Location"] = ngx.var.request_uri
    return ngx.exit(307)
  end
  -- the real page runs a proof of work first; the PoC client reads the
  -- cookie from the page the way the script would set it
  ngx.status = 200
  ngx.header["Content-Type"] = "text/html; charset=utf-8"
  ngx.say('<script data-cookie="', cookie, '">document.cookie=document.currentScript.dataset.cookie;location.reload()</script>')
  return ngx.exit(200)
end

-- origin: what reached it
function _M.origin()
  ngx.req.read_body()
  local body = ngx.req.get_body_data() or ""
  ngx.say("origin method=", ngx.req.get_method(), " len=", #body, " body=", body)
end
return _M
