-- Dynamic routing D9: the one header_filter / body_filter entry of the shared
-- servers (docs/edge/dynroute-filters.md, contract appendix A).
--
--   header_filter()  runs the site's response rules first
--                    (dynroute-filters.md §2.1: status / header conditions;
--                    headers, log, error_page, block), then the response
--                    header slots in a fixed order:
--                      1 error_page    replace an error response with the
--                                      site's page (this module)
--                      2 http_policy   custom response headers + CORS
--                                      (skipped on a replaced page)
--                      3 cache_status  cache hit header
--                      4 hsts          Strict-Transport-Security (this module)
--                      5 alt_svc       Alt-Svc (cdnca_tls, D4)
--                    Each slot writes only its own headers; slots 3-5 own
--                    their header names (a later slot never sees an earlier
--                    one's name, HTTP policy may not set them).
--   body_filter()    sends the replacement page and ends the response.
--   own_page(kind)   a module that answers with its own page calls this
--                    before it sends it (traffic exceeded, a module page
--                    that sets Content-Length itself): it is never replaced.
--   register(slot, fn)  init_by_lua: fn(site, state) for slot http_policy or
--                    cache_status; state.replaced is true on a replaced page.
--
-- Which responses are replaced (the v7 error_page + proxy_intercept_errors
-- set, agents/edge-agent/internal/siteruntimev2/compiler.go:700-727): a
-- response whose status is one the site has a page for under any category,
-- and that is either the origin's own response (origin_response) or a
-- response nginx generated itself (ngx.exit(status) without a body, return,
-- 413, limit 503, 502/504 of a failed upstream: edge_route / edge_connect).
-- nginx's own error responses always carry Content-Length
-- (ngx_http_special_response.c, send_special_response); a page a Lua module
-- printed has none (ngx_http_lua_util.c send_header_if_needed clears it),
-- and v7's error_page never replaced those either.
local cdnca_site = require "cdnca_site"
local lrucache = require "resty.lrucache"

local ngx = ngx
local ngx_var = ngx.var
local ngx_header = ngx.header
local type, tostring, tonumber, pairs, ipairs = type, tostring, tonumber, pairs, ipairs

local _M = { _VERSION = "1" }

_M.HEADER_SLOTS = { "error_page", "http_policy", "cache_status", "hsts", "alt_svc" }

local registered = {}
local compiled = assert(lrucache.new(10000)) -- site digest -> {pages, statuses}

function _M.register(slot, handler)
    assert(slot == "http_policy" or slot == "cache_status", "cdnca_filters.register: unknown slot " .. tostring(slot))
    assert(type(handler) == "function", "cdnca_filters.register: handler must be a function")
    registered[slot] = handler
end

function _M.own_page(kind)
    ngx.ctx.cdnca_own_page = kind or "module"
end

-- routed(): the last line of server_rewrite. A response decided before it
-- (a server rewrite module's exit: CC, not ready) is never replaced: v7's
-- error_page lived in the locations, which server rewrite precedes. Errors
-- from location selection on (413 at find_config, rewrite/access exits,
-- upstream) are. A variable, not ngx.ctx: ngx.exec clears ngx.ctx.
function _M.routed()
    ngx_var.cdnca_filters_routed = "1"
end

-- The v7 handler's headers (edge/openresty/errorpage/handler.lua).
local CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox"
local function page_headers(mime, length, style_hash)
    if mime == "text/html" or mime == "text/plain" then
        ngx_header["Content-Type"] = mime .. "; charset=utf-8"
    else
        ngx_header["Content-Type"] = mime
    end
    ngx_header["Content-Length"] = tostring(length)
    ngx_header["Cache-Control"] = "no-store, max-age=0"
    ngx_header["Pragma"] = "no-cache"
    ngx_header["Expires"] = "0"
    if mime == "text/html" and style_hash and style_hash ~= "" then
        ngx_header["Content-Security-Policy"] = CSP .. "; style-src '" .. style_hash .. "'"
    else
        ngx_header["Content-Security-Policy"] = CSP
    end
    ngx_header["Referrer-Policy"] = "no-referrer"
    ngx_header["X-Content-Type-Options"] = "nosniff"
end
_M.page_headers = page_headers

-- Headers the v7 handler removes from an edge-generated error response.
local EDGE_DROP = { "Content-Encoding", "Content-Range", "ETag", "Expires", "Last-Modified",
    "Location", "Set-Cookie", "Vary", "Via", "WWW-Authenticate", "X-Powered-By" }

-- ------------------------------------------------- built-in default pages
-- What the node answers itself when no page is
-- configured for the response (no custom page, no slot page): one HTML page
-- (error code and title, the browser -> CDN node -> origin path with the
-- failing hop, "what happened / what can I do", request ID, node, time),
-- Chinese with English, no external resource. Statuses stay the callers'.
-- states: browser, CDN node, origin; o working, e error, n unknown.
local DEFAULT_PAGES = {
    unknown_site = { states = "oen",
        title = { "域名未接入本 CDN", "This domain is not configured on this CDN" },
        what = { "请求已到达 CDN 节点，但本 CDN 上没有任何网站绑定这个域名。常见原因：直接打开了 CNAME 接入地址，或该域名尚未添加到网站、网站已删除或停用。",
            "The request reached a CDN edge node, but no website on this CDN is bound to this domain. Common causes: the CNAME target itself was opened, or the domain has not been added to a website, or the website was removed or disabled." },
        todo = { "访问者：请检查网址是否正确。网站管理员：请在 CDN 控制台把该域名添加到网站，将域名 CNAME 到分配的接入地址，并用网站域名访问。",
            "Visitors: check the address. Website owner: add this domain to a website in the CDN console, point it by CNAME to the assigned target and open the site by its own domain." } },
    no_host = { states = "eon",
        title = { "请求缺少 Host", "Bad request: missing Host header" },
        what = { "请求没有携带 Host 头，CDN 节点无法判断要访问哪个网站。", "The request carries no Host header, so the edge node cannot tell which website it is for." },
        todo = { "请通过网址（域名）访问，或在客户端请求中带上 Host 头。", "Open the site by its address (domain name), or send a Host header with the request." } },
    node_ip_access = { states = "oen",
        title = { "不允许通过 IP 直接访问", "Direct IP access is not allowed" },
        what = { "请求使用 IP 地址访问了 CDN 节点。节点只为已接入网站的域名提供服务。", "The request addressed the CDN edge node by IP address. The node only serves the domains of configured websites." },
        todo = { "请使用网站域名访问。", "Open the website by its domain name." } },
    package_expired = { states = "oen",
        title = { "网站套餐已到期", "This website's plan has expired" },
        what = { "该网站所属的 CDN 套餐已到期，CDN 节点已暂停为其提供服务，请求不会转发到源站。",
            "The CDN plan of this website has expired. The edge node has suspended service for it and does not forward requests to the origin." },
        todo = { "访问者：请稍后再试或联系网站管理员。网站管理员：请在 CDN 控制台续费或更换套餐，续费后几分钟内恢复。",
            "Visitors: try again later or contact the website owner. Website owner: renew or change the plan in the CDN console; service resumes within minutes." } },
    traffic_exceeded = { states = "oen",
        title = { "网站流量已超出限制", "Traffic limit exceeded" },
        what = { "该网站本周期的流量已用完，CDN 节点已暂停为其提供服务。", "This website has used up its traffic for the current period, and the edge node has suspended service for it." },
        todo = { "访问者：请稍后再试或联系网站管理员。网站管理员：请在 CDN 控制台购买流量包或升级套餐。",
            "Visitors: try again later or contact the website owner. Website owner: buy a traffic package or upgrade the plan in the CDN console." } },
    blacklist = { states = "eon",
        title = { "您的 IP 已被封禁", "Your IP address has been blocked" },
        what = { "本网站的安全防护暂时封禁了您的 IP 地址，通常是因为来自该地址的请求触发了安全规则。",
            "This website's security protection has temporarily blocked your IP address, usually because requests from it triggered a security rule." },
        todo = { "请稍后再试。如果您认为这是误封，请联系网站管理员并提供下方的请求 ID。",
            "Try again later. If you believe this is a mistake, contact the website owner with the request ID below." } },
    http_403 = { states = "eon",
        title = { "访问被拒绝", "Access denied" },
        what = { "本网站的安全策略拦截了此请求（访问控制、IP 名单、地区限制或防火墙规则）。",
            "The website's security policy blocked this request (access control, IP lists, region restrictions or firewall rules)." },
        todo = { "如果您认为这是误拦截，请联系网站管理员并提供下方的请求 ID。",
            "If you believe this is a mistake, contact the website owner with the request ID below." } },
    connection_limit = { states = "oen",
        title = { "连接数超出限制", "Too many connections" },
        what = { "该网站当前的连接数或带宽已达到套餐上限，CDN 节点暂时拒绝了新的请求。",
            "This website has reached the connection or bandwidth limit of its plan, so the edge node is refusing new requests for now." },
        todo = { "访问者：请稍后刷新重试。网站管理员：请在 CDN 控制台升级套餐或调整连接限制。",
            "Visitors: refresh in a moment. Website owner: upgrade the plan or adjust the connection limits in the CDN console." } },
    http_502 = { states = "ooe",
        title = { "源站无法连接", "Origin server unreachable" },
        what = { "CDN 节点工作正常，但无法连接到该网站的源站服务器：源站可能已停止、拒绝连接，或回源地址、端口配置有误。",
            "The edge node is working, but could not connect to the website's origin server: it may be down or refusing connections, or the origin address or port is misconfigured." },
        todo = { "访问者：请几分钟后重试。网站管理员：请确认源站服务正在运行、防火墙放行了 CDN 节点的回源 IP，并检查回源地址、端口与协议。",
            "Visitors: try again in a few minutes. Website owner: make sure the origin is running, its firewall allows the CDN nodes, and check the origin address, port and protocol." } },
    http_504 = { states = "ooe",
        title = { "源站响应超时", "Origin server timed out" },
        what = { "CDN 节点已连接到源站，但源站没有在规定时间内返回响应。", "The edge node reached the origin server, but it did not answer in time." },
        todo = { "访问者：请几分钟后重试。网站管理员：请检查源站负载与慢请求，或在 CDN 控制台适当调大回源超时。",
            "Visitors: try again in a few minutes. Website owner: check the origin's load and slow requests, or raise the origin timeout in the CDN console." } },
}
_M.DEFAULT_PAGES = DEFAULT_PAGES

-- The page's one <style>: the CSP allows it by hash (page_headers), so
-- nothing else on the page may style (no style attributes; the SVG icons
-- use presentation attributes, which CSP does not restrict).
local DEFAULT_STYLE = "*{box-sizing:border-box}body{margin:0;background:#f6f7f9;color:#1f2329;font:15px/1.6 -apple-system,BlinkMacSystemFont,\"Segoe UI\",\"PingFang SC\",\"Microsoft YaHei\",sans-serif}" ..
    ".w{max-width:1040px;margin:0 auto;padding:48px 24px 32px}" ..
    ".hd h1{margin:0;font-size:15px;font-weight:600;color:#646a73;letter-spacing:.02em}.hd h1 b{color:#d83931;font-size:17px;margin-right:12px}" ..
    ".t{margin:10px 0 0;font-size:34px;line-height:1.25;font-weight:700}.te{margin:4px 0 0;font-size:18px;color:#646a73}" ..
    ".path{display:flex;margin:40px 0;padding:32px 16px;background:#fff;border:1px solid #e4e6eb;border-radius:12px}" ..
    ".hop{flex:1;text-align:center;padding:0 8px;position:relative}.hop+.hop:before{content:\"\";position:absolute;left:-14%;top:38px;width:28%;border-top:2px dashed #c9cdd4}" ..
    ".ic{position:relative;display:inline-block;width:96px;height:80px}.ic svg.m{width:96px;height:80px}.ic svg.s{position:absolute;right:-4px;bottom:-4px;width:32px;height:32px}" ..
    ".hop h3{margin:12px 0 0;font-size:16px}.hop .sub{margin:2px 0 0;font-size:13px;color:#8f959e;word-break:break-all}" ..
    ".st{margin:6px 0 0;font-size:14px;font-weight:600}.o .st{color:#2ea121}.e .st{color:#d83931}.n .st{color:#8f959e}" ..
    ".info{display:flex;gap:40px}.info div{flex:1}.info h2{margin:0 0 8px;font-size:20px}.info h2 span{display:block;font-size:14px;font-weight:400;color:#8f959e}" ..
    ".info p{margin:0 0 6px}.info p.en{color:#646a73;font-size:14px}" ..
    "footer{margin-top:44px;padding-top:16px;border-top:1px solid #e4e6eb;font-size:13px;color:#646a73;display:flex;flex-wrap:wrap;gap:6px 28px}" ..
    "footer code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#1f2329}" ..
    "@media (max-width:720px){.w{padding:28px 16px}.t{font-size:26px}.path{flex-direction:column;gap:28px}.hop+.hop:before{display:none}.info{flex-direction:column;gap:24px}}"
local DEFAULT_STYLE_HASH = "sha256-" .. ngx.encode_base64((function()
    local digest = require("resty.sha256"):new()
    digest:update(DEFAULT_STYLE)
    return digest:final()
end)())
_M.DEFAULT_STYLE_HASH = DEFAULT_STYLE_HASH

-- Icons (drawn here): browser window, edge node (globe), origin (server).
local ICONS = {
    '<svg class="m" viewBox="0 0 96 80" aria-hidden="true"><rect x="6" y="8" width="84" height="64" rx="8" fill="#fff" stroke="#4e5969" stroke-width="4"/>' ..
        '<path d="M6 24h84" stroke="#4e5969" stroke-width="4"/><circle cx="18" cy="16" r="3" fill="#4e5969"/><circle cx="28" cy="16" r="3" fill="#4e5969"/>' ..
        '<circle cx="38" cy="16" r="3" fill="#4e5969"/></svg>',
    '<svg class="m" viewBox="0 0 96 80" aria-hidden="true"><circle cx="48" cy="40" r="32" fill="#fff" stroke="#3370ff" stroke-width="4"/>' ..
        '<ellipse cx="48" cy="40" rx="14" ry="32" fill="none" stroke="#3370ff" stroke-width="3"/><path d="M17 30h62M17 50h62" stroke="#3370ff" stroke-width="3"/></svg>',
    '<svg class="m" viewBox="0 0 96 80" aria-hidden="true"><rect x="18" y="6" width="60" height="30" rx="5" fill="#fff" stroke="#4e5969" stroke-width="4"/>' ..
        '<rect x="18" y="44" width="60" height="30" rx="5" fill="#fff" stroke="#4e5969" stroke-width="4"/><circle cx="30" cy="21" r="3.5" fill="#4e5969"/>' ..
        '<circle cx="30" cy="59" r="3.5" fill="#4e5969"/><path d="M44 21h22M44 59h22" stroke="#4e5969" stroke-width="4" stroke-linecap="round"/></svg>',
}
local BADGES = {
    o = '<svg class="s" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="#2ea121" stroke="#fff" stroke-width="3"/>' ..
        '<path d="M9.5 16.5l4.5 4.5 8.5-9" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    e = '<svg class="s" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="#d83931" stroke="#fff" stroke-width="3"/>' ..
        '<path d="M11 11l10 10M21 11L11 21" stroke="#fff" stroke-width="3.2" stroke-linecap="round"/></svg>',
    n = '<svg class="s" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="#8f959e" stroke="#fff" stroke-width="3"/>' ..
        '<path d="M12.5 12.5a3.5 3.5 0 1 1 5 3.2c-1 .5-1.5 1.2-1.5 2.3M16 22.5v.1" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"/></svg>',
}
local STATE_TEXT = { o = "正常 · Working", e = "错误 · Error", n = "未知 · Unknown" }
local HOPS = { { "您的浏览器", "Browser" }, { "CDN 节点", "CDN node" }, { "源站", "Origin server" } }

local ESCAPES = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;" }
local function escape(value)
    return (tostring(value or ""):sub(1, 255):gsub("[&<>\"']", ESCAPES))
end

-- default_page(name, status): the built-in page body (nil for an unknown
-- name). The request's values (Host, client address, request ID, node,
-- time) are escaped.
local function default_page(name, status)
    local page = DEFAULT_PAGES[name]
    if not page then
        return nil
    end
    local node_id, node_region = cdnca_site.node()
    local node = (node_id or ""):sub(1, 8)
    if node_region and node_region ~= "" then
        node = node ~= "" and node_region .. " · " .. node or node_region
    end
    local host = ngx_var.http_host
    local subs = { escape(ngx_var.remote_addr), escape(node ~= "" and node or "-"), escape(host and host ~= "" and host or "-") }
    local hops = {}
    for index = 1, 3 do
        local state = page.states:sub(index, index)
        hops[index] = '<div class="hop ' .. state .. '"><div class="ic">' .. ICONS[index] .. BADGES[state] .. "</div><h3>" ..
            HOPS[index][1] .. '</h3><p class="sub">' .. HOPS[index][2] .. " · " .. subs[index] .. '</p><p class="st">' ..
            STATE_TEXT[state] .. "</p></div>"
    end
    local request_id = escape(ngx_var.request_id)
    return '<!DOCTYPE html>\n<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' ..
        '<meta name="robots" content="noindex"><title>' .. status .. " " .. page.title[1] .. " | " .. page.title[2] .. "</title><style>" ..
        DEFAULT_STYLE .. '</style></head><body><main class="w"><header class="hd"><h1><b>错误代码 ' .. status .. "</b>" ..
        escape(ngx.utctime()) .. ' UTC</h1><p class="t">' .. page.title[1] .. '</p><p class="te">' .. page.title[2] ..
        '</p></header><section class="path">' .. table.concat(hops) .. '</section><section class="info"><div><h2>发生了什么？<span>What happened?</span></h2><p>' ..
        page.what[1] .. '</p><p class="en">' .. page.what[2] .. '</p></div><div><h2>我该怎么办？<span>What can I do?</span></h2><p>' ..
        page.todo[1] .. '</p><p class="en">' .. page.todo[2] .. "</p></div></section><footer><span>请求 ID / Request ID: <code>" ..
        request_id .. "</code></span><span>节点 / Node: <code>" .. subs[2] .. "</code></span><span>您的 IP / Your IP: <code>" ..
        subs[1] .. "</code></span></footer></main></body></html>\n"
end
_M.default_page = default_page

-- send_default(name, status): answer with the built-in page and end the
-- request (a module's own answer: never replaced, like a slot page).
function _M.send_default(name, status)
    local body = default_page(name, status)
    _M.own_page("default:" .. name)
    ngx.status = status
    page_headers("text/html", #body, DEFAULT_STYLE_HASH)
    if ngx.req.get_method() ~= "HEAD" then
        ngx.print(body)
    end
    return ngx.exit(ngx.HTTP_OK)
end

local function fallback(status)
    if status >= 500 then
        return "Service temporarily unavailable.\n"
    end
    return "Request could not be completed.\n"
end

local function site_pages(site)
    local digest = ngx_var.cdnca_site_digest
    local entry = compiled:get(digest)
    if entry then
        return entry
    end
    entry = { pages = {}, statuses = {}, any = false, rules = nil }
    for _, page in ipairs(site.error_pages or {}) do
        entry.pages[page.category .. "|" .. page.status] = page
        -- a theme's block pages (edge_route 403/429, rule theme.edge_route.*)
        -- answer only the node's own block responses (block_page below):
        -- intercepting their statuses would replace an origin 403/429
        if not (page.category == "edge_route" and type(page.rule_id) == "string"
            and page.rule_id:sub(1, 17) == "theme.edge_route.") then
            entry.statuses[page.status] = true
            entry.any = true
        end
    end
    -- errpage-ovr: the platform's region / node overrides of the edge_connect
    -- pages (http_502 / http_504) replace the site's page on this node: the
    -- variant naming this node, else its region (the node page pick)
    local variants = site.error_page_variants
    if type(variants) == "table" and #variants > 0 then
        local node_id, node_region = cdnca_site.node()
        local best = {}
        for _, variant in ipairs(variants) do
            local rank = 0
            if variant.node_id and variant.node_id ~= "" then
                if variant.node_id == node_id then rank = 2 end
            elseif variant.region and variant.region ~= "" and variant.region == node_region then
                rank = 1
            end
            local key = variant.category .. "|" .. variant.status
            if rank > 0 and (best[key] == nil or rank > best[key]) then
                best[key] = rank
                entry.pages[key] = variant
                entry.statuses[variant.status] = true
                entry.any = true
            end
        end
    end
    local rules = site.access and site.access.response_rules
    if type(rules) == "table" and #rules > 0 then
        entry.rules = rules -- response rules
    end
    compiled:set(digest, entry)
    return entry
end

-- v7 classify(): origin_response when the last upstream answered with this
-- status (its header time is known), edge_connect when an upstream was tried
-- but gave no such answer, edge_route when none was tried.
local function classify(status)
    local upstream = ngx_var.upstream_status
    if upstream == nil or upstream == "" or upstream == "-" then
        return "edge_route"
    end
    local last = upstream:match("([^,%s:]+)%s*$")
    local header_time = (ngx_var.upstream_header_time or ""):match("([^,%s:]+)%s*$")
    if tonumber(last) == status and header_time ~= nil and header_time ~= "-" then
        return "origin_response"
    end
    return "edge_connect"
end

-- Served from the cache: the headers are the origin's (stored), whatever
-- the category says (v7 cached only the error status, never its headers).
local FROM_CACHE = { HIT = true, STALE = true, UPDATING = true, REVALIDATED = true }

-- serve(page, status, origin): the response becomes page (nil: the built-in
-- text page of status). origin: nothing of the response's own headers
-- survives (an origin or cached response); else the v7 edge set is dropped.
local function serve(page, status, origin)
    local body, mime, style
    if page then
        local err
        body, err = cdnca_site.object(page.asset.sha256)
        if body then
            mime, style = page.mime_type, page.style_hash
        else
            ngx.log(ngx.ERR, "cdnca_filters: error page ", page.rule_id, " asset ", page.asset.sha256, ": ", err)
        end
    end
    if not body then
        body, mime = fallback(status), "text/plain"
    end
    if origin then
        -- Nothing of the origin's response survives (PoC §4: dropping only the
        -- length leaks Set-Cookie/ETag and a wrong Content-Encoding).
        for name in pairs(ngx.resp.get_headers(0, true)) do
            ngx_header[name] = nil
        end
    else
        for _, name in ipairs(EDGE_DROP) do
            ngx_header[name] = nil
        end
    end
    page_headers(mime, #body, style)
    ngx.ctx.cdnca_error_page = body
    return true
end

-- block_page(site, status): sec-followup P13. A block response of the
-- node's own security modules ($cdnca_security_block_page 1: WAF / ACL 403,
-- CC / auto defense 429, also the CC ones server_rewrite ends before
-- routed()) gets the site's edge_route page (a theme's branded page when the
-- site has no own one). Only a response nginx generated itself (ngx.exit
-- without a body: Content-Length set); a page a module printed (challenge,
-- ban notice) is its own. Retry-After stays (not in EDGE_DROP).
--
-- errpage-3 (403 与 WAF 拦截按拦截来源分开): a 403 of a WAF
-- rule (managed WAF / CRS, the site's WAF rules: $cdnca_security_type waf)
-- keeps the edge_route page (the waf_block slot); any other block 403 the
-- node gives itself (ACL, IP lists, region, Referer/UA, response rules)
-- gets the http_403 slot page when the platform bound one, unless the site
-- has its own edge_route 403 page (a site page beats the platform's).
local BLOCK_STATUSES = { [403] = true, [429] = true }

-- slot_serve(name, status): the node's slot page as a replacement.
local function slot_serve(name, status)
    local page = cdnca_site.slot_page(name)
    if not page or page.status ~= status then
        return false
    end
    for _, header in ipairs(EDGE_DROP) do
        ngx_header[header] = nil
    end
    page_headers(page.mime_type, #page.body, page.style_hash)
    ngx.ctx.cdnca_error_page = page.body
    return true
end

-- default_serve(name, status): the built-in default page as
-- the replacement of a response nginx generated itself.
local function default_serve(name, status)
    local body = default_page(name, status)
    for _, header in ipairs(EDGE_DROP) do
        ngx_header[header] = nil
    end
    page_headers("text/html", #body, DEFAULT_STYLE_HASH)
    ngx.ctx.cdnca_error_page = body
    return true
end

local function block_page(site, status)
    if not BLOCK_STATUSES[status] or ngx_var.cdnca_security_block_page ~= "1"
        or ngx_header["Content-Length"] == nil then
        return false
    end
    local page = site_pages(site).pages["edge_route|" .. status]
    local themed = page and type(page.rule_id) == "string" and page.rule_id:sub(1, 17) == "theme.edge_route."
    if status == 403 and (not page or themed) and ngx_var.cdnca_security_type ~= "waf"
        and slot_serve("http_403", 403) then
        return true
    end
    if not page then
        -- A node block 403 without any page gets the built-in one
        return status == 403 and default_serve("http_403", 403)
    end
    return serve(page, status, false)
end

-- limit_page(site, status): a 503 the connection / QPS / bandwidth limits
-- gave (cdnca_limits.refused, errpage-3) gets the site's own edge_route 503
-- page, else the connection_limit slot page. The site page is served here,
-- not left to replace(): budget 0 (cdnca_limits.refuse) refuses in
-- server_rewrite before routed(), where v7's server-level return still got
-- the site's error_page.
local function limit_page(site, status)
    if status ~= 503 or ngx.ctx.cdnca_limit_refused ~= true or ngx_header["Content-Length"] == nil then
        return false
    end
    local page = site_pages(site).pages["edge_route|503"]
    if page then
        return serve(page, 503, false)
    end
    return slot_serve("connection_limit", 503) or default_serve("connection_limit", 503)
end

local function replace(site)
    if ngx.ctx.cdnca_own_page then
        return false
    end
    local status = ngx.status
    if block_page(site, status) or limit_page(site, status) then
        return true
    end
    if ngx_var.cdnca_filters_routed ~= "1" then
        return false
    end
    if not status or status < 400 or status > 599 then
        return false
    end
    local entry = site_pages(site)
    if (status == 502 or status == 504) and not entry.pages["edge_connect|" .. status]
        and ngx_header["Content-Length"] ~= nil and classify(status) == "edge_connect" then
        -- The origin unreachable / timed out without a page
        -- (the site's, a theme's or an override) gets the built-in one
        return default_serve("http_" .. status, status)
    end
    if not entry.any or not entry.statuses[status] then
        return false
    end
    local category = classify(status)
    if category ~= "origin_response" and ngx_header["Content-Length"] == nil then
        return false -- a module's own page (v7: error_page never saw it)
    end
    return serve(entry.pages[category .. "|" .. status], status,
        category == "origin_response" or FROM_CACHE[ngx_var.upstream_cache_status or ""])
end

-- ------------------------------------------------------------ response rules
-- Site response rules (dynroute-filters.md §2.1, edgeconfig.SiteResponseRule).
-- Header rules run on origin and cached responses,
-- log/error_page/block on origin responses only;
-- a response a rule replaced is not stored in the cache.
local re_find = ngx.re.find

-- the variables exist only in a skeleton that declares them (security
-- telemetry, the cache module); a write elsewhere raises, so it is guarded
local function set_var(name, value)
    pcall(function() ngx_var[name] = value end)
end

local function status_matches(rule, status)
    local ranges = rule.statuses
    if type(ranges) ~= "table" or #ranges == 0 then
        return true
    end
    for _, range in ipairs(ranges) do
        if status >= range.from and status <= range.to then
            return true
        end
    end
    return false
end

local function header_matches(condition, value)
    local op = condition.op
    if op == "exists" then
        return value ~= nil
    elseif op == "absent" then
        return value == nil
    end
    if value == nil then
        return false
    end
    local values = type(value) == "table" and value or { value }
    for _, item in ipairs(values) do
        if op == "equals" then
            if item == (condition.value or "") then
                return true
            end
        elseif op == "regex" and re_find(item, condition.value, "jo") then
            return true -- a match limit error is no match
        end
    end
    return false
end

local function rule_matches(rule, status, headers)
    if not status_matches(rule, status) then
        return false
    end
    for _, condition in ipairs(type(rule.headers) == "table" and rule.headers or {}) do
        if not header_matches(condition, headers[condition.name]) then
            return false
        end
    end
    return true
end

local function security_log(rule, action)
    if action == "log" and ngx_var.cdnca_security_emit == "1" then
        return -- an earlier module's record of this request stays
    end
    set_var("cdnca_security_emit", "1")
    set_var("cdnca_security_type", "response")
    set_var("cdnca_security_action", action)
    set_var("cdnca_security_severity", action == "block" and "high" or "info")
    set_var("cdnca_security_rule_id", rule.id)
    if action == "block" then
        set_var("cdnca_security_block_page", "1")
    end
end

-- respond(site): evaluate the site's rules in order. Returns whether a
-- rule replaced the response, and the header actions of the matching
-- headers rules (applied unless an error page replaces the response).
local function respond(site)
    if ngx.ctx.cdnca_own_page or ngx_var.cdnca_filters_routed ~= "1" then
        return false, nil
    end
    local entry = site_pages(site)
    local rules = entry.rules
    local status = ngx.status
    if not rules or not status then
        return false, nil
    end
    local cached = FROM_CACHE[ngx_var.upstream_cache_status or ""] == true
    local origin = not cached and classify(status) == "origin_response"
    if not cached and not origin then
        return false, nil -- the edge's own response
    end
    local headers = ngx.resp.get_headers(0)
    local actions
    for _, rule in ipairs(rules) do
        local kind = rule.action
        if (kind == "headers" or origin) and rule_matches(rule, status, headers) then
            if kind == "headers" then
                actions = actions or {}
                for _, action in ipairs(rule.header_actions) do
                    actions[#actions + 1] = action
                end
            elseif kind == "log" then
                security_log(rule, "log")
            else
                local code = rule.status
                local page
                if kind == "error_page" then
                    page = entry.pages["origin_response|" .. code] or entry.pages["edge_route|" .. code]
                else
                    security_log(rule, "block")
                end
                ngx.status = code
                set_var("cdnca_cache_rule_bypass", "1") -- not stored
                return serve(page, code, true), nil
            end
        end
    end
    return false, actions
end

local function apply_header_actions(actions)
    for _, action in ipairs(actions) do
        local name = action.name
        if action.kind == "delete" then
            ngx_header[name] = nil
        elseif action.kind == "set" then
            ngx_header[name] = action.value
        else
            local current = ngx_header[name]
            if current == nil then
                ngx_header[name] = action.value
            elseif type(current) == "table" then
                current[#current + 1] = action.value
                ngx_header[name] = current
            else
                ngx_header[name] = { current, action.value }
            end
        end
    end
end

local function hsts(site)
    local value = site.hsts
    if not value or ngx_var.https ~= "on" then
        return
    end
    local header = "max-age=" .. string.format("%d", value.max_age_seconds)
    if value.include_subdomains then
        header = header .. "; includeSubDomains"
    end
    if value.preload then
        header = header .. "; preload"
    end
    ngx_header["Strict-Transport-Security"] = header
end

local function alt_svc()
    require("cdnca_tls").header_filter()
end

function _M.header_filter()
    if ngx.is_subrequest then
        return
    end
    local site = cdnca_site.current()
    if not site then
        return
    end
    local replaced, actions = respond(site)
    if not replaced then
        replaced = replace(site)
        if not replaced and actions then
            apply_header_actions(actions)
        end
    end
    local state = { replaced = replaced }
    local policy = registered.http_policy
    if policy and not state.replaced then
        policy(site, state)
    end
    local cache = registered.cache_status
    if cache then
        cache(site, state)
    end
    hsts(site)
    alt_svc()
end

function _M.body_filter()
    local ctx = ngx.ctx
    local body = ctx.cdnca_error_page
    if not body then
        return
    end
    if ctx.cdnca_error_page_sent then
        ngx.arg[1] = nil -- what follows the page (origin or nginx body) is dropped
        return
    end
    ctx.cdnca_error_page_sent = true
    ngx.arg[1] = body
    ngx.arg[2] = true -- the response ends with the page (PoC §4: partial origin bodies)
end

return _M
