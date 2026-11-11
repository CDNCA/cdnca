-- Real user monitoring. Loaded only when the skeleton
-- declares lua_shared_dict cdnca_rum (some site of the node has rum);
-- cdnca_dynroute calls it only for a site whose object carries rum:
--   rewrite(site)       GET /.cdnca/rum/v1.js (the browser script) and
--                       POST /.cdnca/rum/collect (beacons), before the WAF
--   sampled(site)       access, client pass: whether this request is a
--                       document navigation the node samples (site rate,
--                       one math.random per request); cdnca_dynroute then
--                       fetches it plain unless it is served from the cache
--   header_filter(site) a sampled request ($cdnca_plain_want has "r")
--                       with a plain HTML answer gets the script
--   body_filter()       inserts the script tag before </head> (or <body)
--                       within the first 64 KiB; never decompresses
--   admin()             GET /rum-minutes on the control socket: the
--                       finished minutes, handed out once
-- No beacon is stored: each is folded into per (site, minute) histograms
-- (edgeconfig.RUMBucket) and error counts. The client address is only used
-- for the per IP limit (a salted digest) and the country lookup.
local cjson = require "cjson.safe"

local ngx = ngx
local ngx_var = ngx.var
local ngx_header = ngx.header
local type, tostring, tonumber, pairs, ipairs, pcall = type, tostring, tonumber, pairs, ipairs, pcall
local floor, log, min, random = math.floor, math.log, math.min, math.random
local byte, sub, find, lower, gmatch = string.byte, string.sub, string.find, string.lower, string.gmatch
local concat = table.concat

local _M = { _VERSION = "1" }

local dict = ngx.shared.cdnca_rum
local SCRIPT_PATH, COLLECT_PATH = "/.cdnca/rum/v1.js", "/.cdnca/rum/collect"
local MAX_BODY, IP_LIMIT, SITE_LIMIT = 2048, 30, 20000
local MAX_PAGES, MAX_COUNTRIES, MAX_ERRORS, MAX_BUCKETS, MAX_BUCKET = 50, 30, 100, 4000, 200
local MAX_EVENTS, MAX_METRIC, TTL, SCAN_LIMIT, TAIL = 10, 120000, 360, 65536, 7
local LN108 = log(1.08)
local OTHER, NO_COUNTRY = "(other)", "--"
local NODE_SCHEMA = "cdnca.edge.rum-minute/v1"
local METRICS = { "lcp", "inp", "cls", "fcp", "ttfb" }
local METRIC_SET = { lcp = true, inp = true, cls = true, fcp = true, ttfb = true }
local NAV = { navigate = true, reload = true, back_forward = true, prerender = true }
local KINDS = { resource = true, navigation = true, fetch = true, xhr = true }
local ELEMENTS = { [""] = true, img = true, script = true, link = true, iframe = true, video = true, audio = true }
local BEACON_KEYS = { v = true, p = true, n = true, m = true, e = true }
local EVENT_KEYS = { k = true, t = true, u = true, s = true }

-- The per IP limit key salt: made once in init_by_lua (every worker forks
-- with it), never written or reported.
local salt = (function()
    local ok, bytes = pcall(function() return require("resty.random").bytes(16, true) end)
    return ok and bytes or tostring(ngx.now()) .. tostring(math.random())
end)()

-- The browser script: the node sampled the page view (only a
-- sampled document carries the tag, §5.2), so every page that runs it
-- reports; Web Vitals by PerformanceObserver (INP: the longest interaction),
-- resource / navigation / fetch / XHR errors, one sendBeacon when the page is
-- hidden. No cookie, no storage, no identifier; paths are normalised as
-- normalize_path does (the node normalises again).
local SCRIPT = [==[(function(){var d=document,w=window;if(!w.PerformanceObserver||!navigator.sendBeacon)return;
var L=location,m={},e=[],sup={},sent=0,cls=0,sv=0,sf=0,sl=0,inp=0;
function seg(x){return/^\d+$/.test(x)?":id":/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(x)?":uuid":/^[0-9a-f]{16,}$/i.test(x)?":hash":x.length>=32?":long":x}
function np(p){return p.split("/").map(seg).join("/").slice(0,128)}
function tg(u){try{var x=new URL(u,L.href);if(x.protocol!="http:"&&x.protocol!="https:")return"";return x.origin==L.origin?np(x.pathname):x.host}catch(_){return""}}
function er(k,t,u,st){if(e.length<10&&u)e.push({k:k,t:t,u:u,s:st})}
function ob(t,f,o){try{new PerformanceObserver(function(l){l.getEntries().forEach(f)}).observe(Object.assign({type:t,buffered:true},o||{}));sup[t]=1}catch(_){}}
ob("paint",function(x){if(x.name=="first-contentful-paint")m.fcp=x.startTime});
ob("largest-contentful-paint",function(x){m.lcp=x.startTime});
ob("layout-shift",function(x){if(x.hadRecentInput)return;if(sv&&x.startTime-sl<1000&&x.startTime-sf<5000){sv+=x.value}else{sv=x.value;sf=x.startTime}sl=x.startTime;if(sv>cls)cls=sv});
ob("event",function(x){if(x.interactionId&&x.duration>inp)inp=x.duration},{durationThreshold:40});
w.addEventListener("error",function(v){var t=v.target;if(t&&t!==w&&t.tagName){var n=t.tagName.toLowerCase();if(n=="img"||n=="script"||n=="link"||n=="iframe"||n=="video"||n=="audio")er("resource",n,tg(t.src||t.href||""),0)}},true);
var F=w.fetch;if(F)w.fetch=function(i,o){var u=tg(typeof i=="string"?i:i&&i.url||"");return F.call(w,i,o).then(function(r){if(r.status>=500)er("fetch","",u,r.status);return r},function(x){if(!x||x.name!="AbortError")er("fetch","",u,0);throw x})};
var X=w.XMLHttpRequest&&XMLHttpRequest.prototype,O=X&&X.open;if(O)X.open=function(a,u){var q=this,t=tg(String(u));q.addEventListener("error",function(){er("xhr","",t,0)});q.addEventListener("timeout",function(){er("xhr","",t,0)});q.addEventListener("load",function(){if(q.status>=500)er("xhr","",t,q.status)});return O.apply(q,arguments)};
function send(){if(sent)return;sent=1;var n=performance.getEntriesByType("navigation")[0],r={v:1,p:np(L.pathname),n:"navigate",m:{},e:e};
if(n){r.n=n.type=="back_forward"?"back_forward":n.type=="reload"?"reload":n.type=="prerender"?"prerender":"navigate";m.ttfb=n.responseStart-(n.activationStart||0);if(n.responseStatus>=400)er("navigation","",r.p,n.responseStatus)}
if(sup["layout-shift"])m.cls=cls*1000;if(sup.event&&inp)m.inp=inp;
for(var k in m){var x=Math.round(m[k]);if(x>=0&&x<=120000)r.m[k]=x}
navigator.sendBeacon("/.cdnca/rum/collect",new Blob([JSON.stringify(r)],{type:"text/plain"}))}
d.addEventListener("visibilitychange",function(){if(d.visibilityState=="hidden")send()});w.addEventListener("pagehide",send)})();
]==]
local SCRIPT_ETAG = '"' .. ngx.md5(SCRIPT) .. '"'
local TAG = '<script src="' .. SCRIPT_PATH .. '" defer></script>'
_M.SCRIPT, _M.SCRIPT_PATH, _M.COLLECT_PATH = SCRIPT, SCRIPT_PATH, COLLECT_PATH

-- bucket(v): edgeconfig.RUMBucket (0 for v <= 0, else floor(ln v / ln 1.08) + 1).
local function bucket(v)
    if v <= 0 then return 0 end
    return min(MAX_BUCKET, floor(log(v) / LN108) + 1)
end
_M.bucket = bucket

local function segment(value)
    if find(value, "^%d+$") then return ":id" end
    if #value == 36 and find(value, "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") then return ":uuid" end
    if #value >= 16 and find(value, "^%x+$") then return ":hash" end
    if #value >= 32 then return ":long" end
    return value
end

-- normalize_path: a path without query or fragment, printable ASCII only,
-- id-like segments replaced, at most 128 bytes; nil when not a path.
local function normalize_path(value)
    if type(value) ~= "string" or byte(value, 1) ~= 47 or #value > 2048 then return nil end
    local cut = find(value, "[?#]")
    if cut then value = sub(value, 1, cut - 1) end
    if find(value, "[^\33-\126]") then return nil end
    local parts = {}
    for part in gmatch(value .. "/", "([^/]*)/") do parts[#parts + 1] = segment(part) end
    local path = sub(concat(parts, "/"), 1, 128)
    return path ~= "" and path or "/"
end
_M.normalize_path = normalize_path

-- normalize_target: a same-origin path (normalised) or a cross-origin host.
local function normalize_target(value)
    if type(value) ~= "string" or value == "" then return nil end
    if byte(value, 1) == 47 then return normalize_path(value) end
    value = lower(value)
    local host, port = value:match("^([^:]+):(%d+)$")
    host = host or value
    if #host > 253 or not find(host, "^[a-z0-9][a-z0-9.-]*$") or find(host, "[.-]$") or (port and #port > 5) then return nil end
    return value
end
_M.normalize_target = normalize_target

-- device(): three classes from User-Agent (the raw value is never kept).
local function device()
    local ua = ngx_var.http_user_agent or ""
    if find(ua, "iPad", 1, true) or find(ua, "Tablet", 1, true) then return "tablet" end
    if find(ua, "Mobi", 1, true) or find(ua, "Android", 1, true) then return "mobile" end
    return "desktop"
end

local iplib
local function country()
    if iplib == nil then
        local ok, module = pcall(require, "cdnca_iplib")
        iplib = ok and type(module) == "table" and module or false
    end
    if not iplib then return NO_COUNTRY end
    local ok, attrs = pcall(iplib.lookup_client)
    local code = ok and type(attrs) == "table" and type(attrs.country) == "string" and attrs.country:upper() or ""
    return find(code, "^%u%u$") and code or NO_COUNTRY
end

-- ------------------------------------------------------------ aggregation
-- Keys (all with TTL; take() deletes what it hands out):
--   s|m          list of sites with data in minute m
--   k|m|site     list of series "dim\0value"     n|m|site|dim  distinct count
--   b|m|site|ser|metric  list of buckets         h|m|site|ser|metric|b  count
--   v|m|site|ser views     d|m|site dropped   c|m|site bucket total
--   g|m|site     list of error groups            x|m|site|group  count
local function incr(key, by)
    local value = dict:incr(key, by or 1, 0, TTL)
    return value
end

local function push(list, value)
    local length = dict:lpush(list, value)
    if length == 1 then pcall(dict.expire, dict, list, TTL) end
end

local function dropped(minute, site_id)
    incr("d|" .. minute .. "|" .. site_id)
end

-- series(m, site, dim, value): the series a beacon counts in; a page or
-- country beyond its limit folds into (other).
local function series(minute, site_id, dim, value, limit)
    local name = dim .. "\0" .. value
    local base = minute .. "|" .. site_id .. "|"
    if dict:get("v|" .. base .. name) == nil and limit then
        if (dict:get("n|" .. base .. dim) or 0) >= limit then
            name = dim .. "\0" .. OTHER
        else
            incr("n|" .. base .. dim)
        end
    end
    if incr("v|" .. base .. name) == 1 then push("k|" .. base, name) end
    return name
end

local function count_metric(minute, site_id, name, metric, value)
    local base = minute .. "|" .. site_id .. "|" .. name .. "|" .. metric
    local b = bucket(value)
    if dict:get("h|" .. base .. "|" .. b) == nil and incr("c|" .. minute .. "|" .. site_id) > MAX_BUCKETS then
        return dropped(minute, site_id)
    end
    if incr("h|" .. base .. "|" .. b) == 1 then push("b|" .. base, b) end
end

local function count_error(minute, site_id, event)
    local group = event.k .. "\0" .. event.t .. "\0" .. event.u .. "\0" .. event.s
    local base = minute .. "|" .. site_id .. "|"
    if dict:get("x|" .. base .. group) == nil and incr("y|" .. base) > MAX_ERRORS then
        return dropped(minute, site_id)
    end
    if incr("x|" .. base .. group) == 1 then push("g|" .. base, group) end
end

-- valid(beacon): §6, strict (an unknown key or a bad value drops
-- the whole beacon); paths and targets are normalised here, not trusted.
local function valid(beacon)
    if type(beacon) ~= "table" or beacon.v ~= 1 or not NAV[beacon.n] or type(beacon.m) ~= "table" then return false end
    for key in pairs(beacon) do if not BEACON_KEYS[key] then return false end end
    beacon.p = normalize_path(beacon.p)
    if not beacon.p then return false end
    for name, value in pairs(beacon.m) do
        if not METRIC_SET[name] or type(value) ~= "number" or value < 0 or value > MAX_METRIC or value ~= floor(value) then return false end
    end
    local events = beacon.e or {}
    if type(events) ~= "table" or #events > MAX_EVENTS then return false end
    for _, event in ipairs(events) do
        if type(event) ~= "table" then return false end
        for key in pairs(event) do if not EVENT_KEYS[key] then return false end end
        local status = event.s
        if not KINDS[event.k] or not ELEMENTS[event.t or ""] or type(status) ~= "number" or
            (status ~= 0 and (status < 400 or status > 599 or status ~= floor(status))) then return false end
        event.t, event.u = event.t or "", normalize_target(event.u)
        if not event.u then return false end
    end
    beacon.e = events
    return true
end

local function record(site_id, beacon)
    local minute = floor(ngx.time() / 60) * 60
    if dict:add("a|" .. minute .. "|" .. site_id, true, TTL) then push("s|" .. minute, site_id) end
    local names = {
        series(minute, site_id, "all", ""),
        series(minute, site_id, "device", device()),
        series(minute, site_id, "page", beacon.p, MAX_PAGES),
        series(minute, site_id, "country", country(), MAX_COUNTRIES),
    }
    for metric, value in pairs(beacon.m) do
        for _, name in ipairs(names) do count_metric(minute, site_id, name, metric, value) end
    end
    for _, event in ipairs(beacon.e) do count_error(minute, site_id, event) end
end

-- ------------------------------------------------------------ endpoints
-- Every refused beacon is answered 204 with no body (no signal to a
-- prober) and counted in the minute's dropped.
local function refuse(site_id)
    dropped(floor(ngx.time() / 60) * 60, site_id)
    return ngx.exit(204)
end

local function same_origin()
    local origin = ngx_var.http_origin
    local host = ngx_var.host
    if type(origin) ~= "string" or not host then return false end
    local origin_host = origin:match("^https?://([^/]+)$")
    if not origin_host then return false end
    origin_host = lower(origin_host):gsub(":%d+$", "")
    return origin_host == lower(host):gsub(":%d+$", "")
end

local function collect(site)
    local site_id = site.site_id
    local length = tonumber(ngx_var.http_content_length)
    if not length or length <= 0 or length > MAX_BODY or not same_origin() then return refuse(site_id) end
    local minute = floor(ngx.time() / 60) * 60
    local client = ngx.md5_bin(salt .. (ngx_var.binary_remote_addr or "") .. site_id)
    if incr("i|" .. minute .. "|" .. client) > IP_LIMIT or incr("t|" .. minute .. "|" .. site_id) > SITE_LIMIT then
        return refuse(site_id)
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body or #body ~= length then return refuse(site_id) end
    local beacon = cjson.decode(body)
    if not valid(beacon) then return refuse(site_id) end
    record(site_id, beacon)
    return ngx.exit(204)
end

local function serve_script()
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then return ngx.exit(405) end
    ngx_header["Content-Type"] = "application/javascript; charset=utf-8"
    ngx_header["Cache-Control"] = "public, max-age=86400"
    ngx_header["ETag"] = SCRIPT_ETAG
    if ngx_var.http_if_none_match == SCRIPT_ETAG then return ngx.exit(304) end
    ngx_header["Content-Length"] = #SCRIPT
    if method == "HEAD" then
        ngx.send_headers()
        return ngx.exit(ngx.HTTP_OK)
    end
    ngx.print(SCRIPT)
    return ngx.exit(ngx.HTTP_OK)
end

-- rewrite(site): the two RUM paths of a site with rum (any other path
-- returns, the site's own paths stay the origin's).
function _M.rewrite(site)
    local uri = ngx_var.uri
    if uri == SCRIPT_PATH then return serve_script() end
    if uri == COLLECT_PATH then
        if ngx.req.get_method() ~= "POST" then return ngx.exit(405) end
        return collect(site)
    end
end

-- sampled(site): the client pass of a GET document navigation
-- (Sec-Fetch-Dest: document, or no such header and Accept has text/html),
-- taken at the site's rate. The cheap random draw comes before the header
-- reads; the workers are seeded in init_worker (cdnca_dynroute).
function _M.sampled(site)
    if ngx.req.get_method() ~= "GET" or random() * 100 >= site.rum.sample_percent then return false end
    local dest = ngx_var.http_sec_fetch_dest
    if dest then return dest == "document" end
    local accept = ngx_var.http_accept
    return accept ~= nil and find(accept, "text/html", 1, true) ~= nil
end

local function no_transform()
    local value = ngx_header["Cache-Control"]
    if type(value) == "table" then value = concat(value, ",") end
    return type(value) == "string" and find(lower(value), "no-transform", 1, true) ~= nil
end

-- header_filter(site): before the compression gate (cdnca_dynroute put the
-- visitor's Accept-Encoding back); only a sampled request ("r" in
-- $cdnca_plain_want, cleared when the request is served from the cache and
-- kept its Accept-Encoding: then a plain answer is still injected, a
-- compressed one is skipped).
function _M.header_filter(site)
    if not find(ngx_var.cdnca_plain_want or "", "r", 1, true) then return end
    local ctx = ngx.ctx
    if ngx.status ~= 200 or ngx.req.get_method() ~= "GET" or ngx.is_subrequest or ctx.cdnca_own_page or ctx.cdnca_error_page then
        return
    end
    local mime = ngx_header["Content-Type"]
    if type(mime) ~= "string" or not find(lower(mime), "^%s*text/html") then return end
    if ngx_header["Content-Encoding"] or ngx_header["Content-Range"] or no_transform() then return end
    ngx_header["Content-Length"] = nil
    local etag = ngx_header["ETag"]
    if type(etag) == "string" and sub(etag, 1, 2) ~= "W/" then ngx_header["ETag"] = "W/" .. etag end
    ctx.cdnca_rum = { tag = TAG, scanned = 0, tail = "" }
end

-- body_filter(): the tag goes before the first </head>, else before the
-- first <body, within the first SCAN_LIMIT bytes; a marker split across
-- chunks is found through the kept tail (TAIL bytes, "</head>" is 7).
function _M.body_filter()
    local state = ngx.ctx.cdnca_rum
    if not state or state.done then return end
    local chunk, eof = ngx.arg[1] or "", ngx.arg[2]
    local data = state.tail .. chunk
    local lowered = lower(data)
    local at = find(lowered, "</head", 1, true) or find(lowered, "<body", 1, true)
    if at then
        state.done = true
        ngx.arg[1] = sub(data, 1, at - 1) .. state.tag .. sub(data, at)
        return
    end
    state.scanned = state.scanned + #chunk
    if eof or state.scanned >= SCAN_LIMIT then
        state.done = true
        ngx.arg[1] = data
        return
    end
    local keep = min(TAIL - 1, #data)
    state.tail = sub(data, #data - keep + 1)
    ngx.arg[1] = sub(data, 1, #data - keep)
end

-- ------------------------------------------------------------ hand-out
local function split(value, count)
    local parts, from = {}, 1
    for _ = 1, count - 1 do
        local at = find(value, "\0", from, true)
        if not at then return nil end
        parts[#parts + 1] = sub(value, from, at - 1)
        from = at + 1
    end
    parts[#parts + 1] = sub(value, from)
    return parts
end

local function take_site(minute, site_id)
    local base = minute .. "|" .. site_id .. "|"
    local out = { schema = NODE_SCHEMA, minute = minute, site_id = site_id, series = setmetatable({}, cjson.empty_array_mt), errors = setmetatable({}, cjson.empty_array_mt),
        dropped = dict:get("d|" .. base:sub(1, -2)) or 0 }
    while true do
        local name = dict:lpop("k|" .. base)
        if not name then break end
        local parts = split(name, 2)
        local views = dict:get("v|" .. base .. name) or 0
        dict:delete("v|" .. base .. name)
        local histograms = {}
        for _, metric in ipairs(METRICS) do
            local histogram
            while true do
                local b = dict:lpop("b|" .. base .. name .. "|" .. metric)
                if not b then break end
                local key = "h|" .. base .. name .. "|" .. metric .. "|" .. b
                local count = dict:get(key)
                dict:delete(key)
                if count and count > 0 then
                    histogram = histogram or {}
                    histogram[tostring(b)] = count
                end
            end
            histograms[metric] = histogram
        end
        if parts then
            out.series[#out.series + 1] = { dimension = parts[1], value = parts[2], views = views, histograms = histograms }
        end
    end
    while true do
        local group = dict:lpop("g|" .. base)
        if not group then break end
        local count = dict:get("x|" .. base .. group)
        dict:delete("x|" .. base .. group)
        local parts = split(group, 4)
        if parts and count and count > 0 then
            out.errors[#out.errors + 1] = { kind = parts[1], element = parts[2], target = parts[3],
                status = tonumber(parts[4]) or 0, count = count }
        end
    end
    for _, key in ipairs({ "d|" .. base:sub(1, -2), "c|" .. base:sub(1, -2), "y|" .. base,
        "n|" .. base .. "page", "n|" .. base .. "country", "a|" .. base:sub(1, -2) }) do
        dict:delete(key)
    end
    return out
end

-- minutes(): every finished minute still held (the keys live TTL seconds),
-- each (site, minute) once: what is handed out is deleted.
function _M.minutes()
    local result = setmetatable({}, cjson.empty_array_mt)
    local current = floor(ngx.time() / 60) * 60
    for minute = current - TTL - 60, current - 60, 60 do
        while true do
            local site_id = dict:lpop("s|" .. minute)
            if not site_id then break end
            result[#result + 1] = take_site(minute, site_id)
        end
    end
    return result
end

-- admin(): GET /rum-minutes on the control socket.
function _M.admin()
    local records = _M.minutes()
    ngx_header["Content-Type"] = "application/json"
    ngx.say(#records == 0 and '{"minutes":[]}' or cjson.encode({ minutes = records }))
end

return _M
