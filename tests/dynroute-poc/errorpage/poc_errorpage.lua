-- ADR 0009 §8.5 item 4: custom error pages by header/body filter (no
-- proxy_intercept_errors) compared with the v7 way (error_page + intercept +
-- content handler, compiler.go:686-720 and edge/openresty/errorpage/handler.lua).
local _M = {}

-- the site's pages (in the dynamic runtime these come from the site object)
local pages = {
  [403] = "<h1>site 403 page</h1>\n",
  [404] = "<h1>site 404 page</h1>\n",
  [500] = "<h1>site 500 page</h1>\n",
  [502] = "<h1>site 502 page</h1>\n",
}

-- headers the edge itself produces and keeps on a replaced response; every
-- other header came from the origin and is dropped, as proxy_intercept_errors
-- drops them (it runs before ngx_http_upstream_process_headers copies them).
local keep = { ["x-edge"] = true }

local function page_headers(status, body)
  ngx.header["Content-Type"] = "text/html; charset=utf-8"
  ngx.header["Content-Length"] = tostring(#body)
  ngx.header["Cache-Control"] = "no-store, max-age=0"
  ngx.header["X-Content-Type-Options"] = "nosniff"
  ngx.header["X-Error-Page"] = tostring(status)
end

-- v7: content handler of the named location error_page sends to
function _M.v7_content()
  local status = tonumber(ngx.var.status)
  local body = pages[status]
  for _, h in ipairs({ "Content-Encoding", "Content-Range", "ETag", "Expires", "Last-Modified",
    "Location", "Set-Cookie", "Vary", "Via", "WWW-Authenticate", "X-Powered-By" }) do
    ngx.header[h] = nil
  end
  page_headers(status, body)
  ngx.status = status
  if ngx.req.get_method() ~= "HEAD" then ngx.print(body) end
  return ngx.exit(ngx.OK)
end

-- dynamic runtime: decide in header_filter, replace in body_filter
function _M.header_filter(naive)
  ngx.header["X-Edge"] = "1"
  local body = pages[ngx.status]
  if not body then return end -- no page for this status: origin response passes through
  ngx.ctx.error_page = body
  if naive then
    -- only what is obviously needed: drop the length, keep everything else
    ngx.header["Content-Length"] = nil
    return
  end
  for name in pairs(ngx.resp.get_headers(0, true)) do
    if not keep[name] then ngx.header[name] = nil end
  end
  page_headers(ngx.status, body)
end

function _M.body_filter()
  local body = ngx.ctx.error_page
  if not body then return end
  if ngx.ctx.error_page_sent then
    ngx.arg[1] = nil -- origin bytes after the page are dropped
    return
  end
  ngx.ctx.error_page_sent = true
  ngx.arg[1] = body
  -- end the response now: anything the origin still sends, or a premature
  -- close of the origin, no longer reaches the client
  ngx.arg[2] = true
end

return _M
