-- Dynamic routing D10: per-site limits on the shared servers
-- (docs/edge/dynroute-filters.md §4).
--
--   traffic(site)  server_rewrite, right after cdnca_site.route() and the
--                  TLS request check: a site over its own traffic cap
--                  (site.traffic_limit, ge-analytics; present only while
--                  exceeded) answers the notice page with 509 for every
--                  request and method except ACME HTTP-01, before CC, WAF
--                  and the origin (v7: server-level return 509 ->
--                  @cdnca_traffic_limit, edgeconfig.SiteTrafficLimitDirectives;
--                  order: plan, traffic limit, WAF).
--   refuse(site)   server_rewrite, after CC and before cdnca_filters.routed():
--                  a package subscription with a budget of 0, or a market
--                  subscription that is stopped (connections.stopped, ADR
--                  0012 stop), refuses every request with 503 (v7:
--                  server-level "return 503", which runs after
--                  server_rewrite_by_lua and is outside the locations'
--                  error_page, so it is never replaced by a site page).
--   enter(site)    first in access (where v7's limit_conn ran: PREACCESS,
--                  after the rewrite phase's ACL/WAF and managed WAF phase 2,
--                  before every access_by_lua step): the market supply limits
--                  (ADR 0012 §6.2, below), then counts the request against the
--                  subscription's concurrent request budget (并发请求数),
--                  shared by all its sites on the node (lua_shared_dict
--                  cdnca_limits_conn, key = subscription ID). max -1 = no
--                  limit; over the budget = 503 (v7 limit_conn_status 503;
--                  inside the location, so a site page for 503 replaces it,
--                  as v7's error_page did).
--   rate(site)     server_rewrite, after refuse(): the subscription's
--                  bandwidth budget (limits.connections.bandwidth_bps, bit/s)
--                  split between its responses in flight, written into
--                  $limit_rate (v7 PackageBandwidthDirective: set_by_lua in
--                  SERVER_REWRITE + limit_rate, the same rounding, a response
--                  keeps the rate it started with, the counter key expires
--                  after an hour). Counted once per request (the variable
--                  survives ngx.exec); released in leave().
--   client(site)   access, right after enter(): the site's own per-client
--                  limits (site.access.limits; v7
--                  edgeconfig.SiteAccessServer): connections_per_ip counts
--                  the client address's requests in flight on this site
--                  (v7 limit_conn cdnca_site_conn_ip, key site + address,
--                  limit_conn_status 429), rate_bytes_per_second /
--                  rate_after_bytes are the response's $limit_rate and
--                  $cdnca_limits_rate_after (the skeleton's limit_rate_after;
--                  v7 limit_rate / limit_rate_after). With a package bandwidth
--                  share the lower rate wins.
--   site(site)     access, before enter(): every selected request is counted
--                  in flight for its site and public port (key
--                  "site|<site_id>|<port>"), the independent connections
--                  metric of a shared server (D13-b2; v7 read the listener's
--                  connections of a port only one site used). Never refuses.
--   connections()  control socket GET /connections: the site counters.
--   leave()        log: releases what site(), enter(), client() and rate()
--                  counted (also after ngx.exec and error pages; never twice).
--
-- Market supply limits (connections.max_connections / new_per_second / qps,
-- SUBSCRIPTION_LIMITS v1; the node's share of the supply total):
--   TCP connections  a client connection ($connection; an HTTP/2 stream has
--                  its connection's number, HTTP/3 has no TCP connection and
--                  is not counted) is counted against a subscription at its
--                  first request for one of its sites, in this worker's table
--                  and the shared "tcp|<subscription>" count, until the socket
--                  closes: every second the worker reads /proc/self/fd/<fd>
--                  (fd by FFI from r->connection, self-checked against
--                  $connection) and releases connections whose socket is gone.
--                  Without the FFI layout a connection is released 75 s after
--                  its last request started (logged once). A worker that
--                  exits (reload) releases all it counted.
--   new connections  per second window "new|<subscription>|<second>".
--                  Over either limit the request is 503 and the connection is
--                  not counted: its next request tries again.
--   QPS            resty.limit.req per subscription (qps a second, a burst
--                  of one second's share, no delay): over it 503 with
--                  Retry-After: 1.
--   minute stats   per (subscription, minute): the maxima of requests in
--                  flight, TCP connections, new connections per second and
--                  requests per second, bytes sent and the peak bit/s (bytes
--                  counted in the second a response ends);
--                  the control socket hands each finished minute out once
--                  (GET /subscription-minutes,
--                  cdnca.edge.subscription-minute/v1). Maxima are read and
--                  written without a lock: concurrent workers may lose an
--                  update of the same second.
--
-- Upload size is not here: cdnca_site.route() writes $cdnca_site_max_body
-- (contract §1.2) for client_max_body_size (native patch 23) before
-- location selection, which is the only point that limits chunked, HTTP/2
-- and HTTP/3 bodies too.
--
-- Counting unit: v7 limit_conn counts requests in flight, per HTTP/2 or
-- HTTP/3 stream as well (ngx_http_limit_conn_module keys r, not the
-- connection); enter/leave count the same unit, so the budget means the same.
local cdnca_site = require "cdnca_site"
local cjson = require "cjson.safe"
local limit_req = require "resty.limit.req"

local ngx = ngx
local ngx_var = ngx.var
local tostring, tonumber, pairs, ipairs, pcall, assert = tostring, tonumber, pairs, ipairs, pcall, assert

local _M = { _VERSION = "1", DICT = "cdnca_limits_conn", BANDWIDTH_DICT = "cdnca_package_bandwidth" }

local dict = ngx.shared[_M.DICT]
local bandwidth = ngx.shared[_M.BANDWIDTH_DICT]
local floor, max = math.floor, math.max

local TRAFFIC_STATUS = 509 -- edgeconfig.SiteTrafficLimitStatus

-- refused(): a connection / QPS / bandwidth refusal (503, nginx's own
-- response); cdnca_filters answers it with the connection_limit slot page
-- (errpage-3), else the built-in default page. Lookup
-- failures (a missing dictionary) stay plain 503s.
local function refused()
    ngx.ctx.cdnca_limit_refused = true
    return ngx.exit(503)
end

local function is_acme()
    return ngx_var.uri:sub(1, 28) == "/.well-known/acme-challenge/"
end

-- A site's own notice: the v7 response exactly (its content_by_lua prints
-- the page: no Content-Length, chunked on HTTP/1.1; Cache-Control from
-- add_header).
function _M.traffic(site)
    local limit = site.traffic_limit
    if not limit or is_acme() then
        return
    end
    local body = limit.notice_html
    if not body or body == "" then
        -- the platform's traffic_exceeded slot page (errpage-3), else the
        -- node's built-in default page (was v7's short notice)
        if require("cdnca_site").serve_slot("traffic_exceeded") ~= false then
            return
        end
        pcall(function() ngx_var.cdnca_security_block_page = "1" end) -- not billed as package traffic (FX60)
        return require("cdnca_filters").send_default("traffic_exceeded", TRAFFIC_STATUS)
    end
    require("cdnca_filters").own_page("traffic_limit")
    pcall(function() ngx_var.cdnca_security_block_page = "1" end) -- not billed as package traffic (FX60)
    ngx.status = TRAFFIC_STATUS
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.print(body)
    return ngx.exit(ngx.HTTP_OK)
end

-- expired(site): a site whose package ended (errpage-3:
-- published with package_expired instead of withdrawn) answers
-- every request (ACME HTTP-01 excepted) with the package_expired slot page,
-- else the node's built-in default page (403), and never
-- reaches the origin or the cache. Its block page variable keeps the
-- response out of package traffic (FX60).
function _M.expired(site)
    if not site.package_expired or is_acme() then
        return
    end
    if require("cdnca_site").serve_slot("package_expired") ~= false then
        return
    end
    pcall(function() ngx_var.cdnca_security_block_page = "1" end)
    return require("cdnca_filters").send_default("package_expired", 403)
end

function _M.refuse(site)
    local limit = site.limits and site.limits.connections
    if limit and (limit.max == 0 or limit.stopped) then
        return refused()
    end
end

function _M.rate(site)
    local limit = site.limits and site.limits.connections
    local bps = limit and tonumber(limit.bandwidth_bps) or 0
    if bps <= 0 then
        return
    end
    local counted = ngx_var.cdnca_limits_rate_key
    if counted and counted ~= "" then
        return
    end
    if not bandwidth then
        ngx.log(ngx.ERR, "cdnca_limits: lua_shared_dict ", _M.BANDWIDTH_DICT, " missing; refusing")
        return ngx.exit(503)
    end
    local key = limit.subscription_id
    local active = bandwidth:incr(key, 1, 0, 3600) or 1
    ngx_var.cdnca_limits_rate_key = key
    ngx_var.limit_rate = max(floor(max(floor(bps / 8), 1) / max(active, 1)), 1)
end

-- ------------------------------------------------- market supply limits
_M.MARKET_DICT = "cdnca_limits_market"
local market = ngx.shared[_M.MARKET_DICT]
local FALLBACK_IDLE = 75 -- nginx keepalive_timeout default
local STATS_TTL = 300
local conns = {}  -- this worker: "<connection>|<subscription>" -> entry
local ffi_state   -- nil: not set up; false: unavailable; true: ready
local ffi, link_buffer
local limiters = {}

local function minute_of(now) return floor(now / 60) * 60 end

-- The subscription's record of the current minute; the first touch lists
-- the subscription under the minute for minutes().
local function stat_key(sub, field)
    local minute = minute_of(ngx.now())
    if market:add("seen|" .. minute .. "|" .. sub, true, STATS_TTL) then
        market:rpush("subs|" .. minute, sub)
        market:expire("subs|" .. minute, STATS_TTL)
    end
    return "m|" .. minute .. "|" .. sub .. "|" .. field
end

local function stat_max(sub, field, value)
    local key = stat_key(sub, field)
    if (market:get(key) or 0) < value then market:set(key, value, STATS_TTL) end
end

local function setup_ffi()
    if ffi_state ~= nil then return ffi_state end
    local ok
    ok, ffi = pcall(require, "ffi")
    -- ngx_connection_t up to number (nginx 1.31 with QUIC and SSL, as the
    -- node builds), ngx_http_request_t's first two fields.
    ffi_state = ok and pcall(ffi.cdef, [[
        typedef struct {
            void *data; void *read; void *write; int fd;
            void *recv; void *send; void *recv_chain; void *send_chain; void *listening;
            int64_t sent; void *log; void *pool; int type;
            void *sockaddr; unsigned int socklen; size_t addr_text_len; unsigned char *addr_text_data;
            void *proxy_protocol; void *quic; void *ssl; void *udp;
            void *local_sockaddr; unsigned int local_socklen; void *buffer;
            void *queue_prev; void *queue_next; unsigned long number;
        } cdnca_limits_conn_t;
        typedef struct { uint32_t signature; cdnca_limits_conn_t *connection; } cdnca_limits_req_t;
        long cdnca_limits_readlink(const char *path, char *buf, size_t n) __asm__("readlink");
    ]]) or false
    if ffi_state then link_buffer = ffi.new("char[64]") end
    return ffi_state
end

local function link_of(fd)
    local n = tonumber(ffi.C.cdnca_limits_readlink("/proc/self/fd/" .. fd, link_buffer, 64))
    return n > 0 and ffi.string(link_buffer, n) or nil
end

-- socket_of(): the request's client socket fd and its /proc link ("socket:
-- [inode]"), or nil: the layout check failed (logged once; idle release).
local function socket_of()
    if not setup_ffi() then return nil end
    local r = require("resty.core.base").get_request()
    local c = r and ffi.cast("cdnca_limits_req_t *", r).connection
    if c == nil or tostring(tonumber(c.number)) ~= ngx_var.connection or c.fd < 0 then
        ngx.log(ngx.ERR, "cdnca_limits: connection layout check failed; TCP connections released by idle time")
        ffi_state = false
        return nil
    end
    local fd = tonumber(c.fd)
    local link = link_of(fd)
    if not link or link:sub(1, 7) ~= "socket:" then return nil end
    return fd, link
end

-- "tcp|<subscription>" is the node's count; each worker releases what it
-- counted (all of it when the worker exits: premature timer). A worker that
-- crashes leaves its count behind until the dictionary is flushed.
local function tcp_total(sub)
    return market:get("tcp|" .. sub) or 0
end

local function release(premature)
    local now = ngx.now()
    for key, entry in pairs(conns) do
        local gone = premature
        if not gone then
            if entry.fd then
                gone = link_of(entry.fd) ~= entry.link
            else
                gone = now - entry.last >= FALLBACK_IDLE
            end
        end
        if gone then
            conns[key] = nil
            local left = market:incr("tcp|" .. entry.sub, -1)
            if left and left < 0 then market:set("tcp|" .. entry.sub, 0) end
        end
    end
end

-- connection(limit, sub, now): count the client TCP connection against the
-- subscription at its first admitted request for it; false = over a
-- connection limit (503; the next request on it tries again).
local function connection(limit, sub, now)
    if ngx_var.server_protocol == "HTTP/3.0" then return true end -- QUIC: no TCP connection
    local key = ngx_var.connection .. "|" .. sub
    local entry = conns[key]
    if entry then
        entry.last = now
        return true
    end
    local per_second = tonumber(limit.new_per_second) or 0
    local window = "new|" .. sub .. "|" .. floor(now)
    local started = market:incr(window, 1, 0, 2) or 1
    local most = tonumber(limit.max_connections) or 0
    if per_second > 0 and started > per_second then
        market:incr(window, -1)
        return false
    end
    local open = market:incr("tcp|" .. sub, 1, 0) or 1
    if most > 0 and open > most then
        market:incr("tcp|" .. sub, -1)
        market:incr(window, -1)
        return false
    end
    local fd, link = socket_of()
    conns[key] = { sub = sub, fd = fd, link = link, last = now }
    stat_max(sub, "max_new_cps", started)
    stat_max(sub, "max_connections", open)
    return true
end

-- market_enter(limit): the market supply limits of the request, once per
-- request (also across ngx.exec); returns only when admitted.
local function market_enter(limit)
    local counted = ngx_var.cdnca_limits_sub_key
    if counted and counted ~= "" then return end
    if not market then
        ngx.log(ngx.ERR, "cdnca_limits: lua_shared_dict ", _M.MARKET_DICT, " missing; refusing")
        return ngx.exit(503)
    end
    local sub, now = limit.subscription_id, ngx.now()
    if not connection(limit, sub, now) then return refused() end
    local qps = tonumber(limit.qps) or 0
    if qps > 0 then
        local limiter = limiters[qps]
        if not limiter then
            -- a burst of one second's share: qps requests at once, then qps a second
            limiter = assert(limit_req.new(_M.MARKET_DICT, qps, qps - 1))
            limiters[qps] = limiter
        end
        -- resty.limit.req reads, computes and writes the bucket without a
        -- lock: two workers admitting at once lose an update and let more
        -- than qps through. One worker at a time per subscription (add() is
        -- atomic; held for microseconds, expires on its own if a worker dies);
        -- not acquired within ~20 ms it admits unlocked (precision, not 503).
        local lock_key, locked = "qpsl|" .. sub, false
        for _ = 1, 20 do
            if market:add(lock_key, true, 0.01) then locked = true break end
            ngx.sleep(0.001)
        end
        local delay, err = limiter:incoming("qps|" .. sub, true)
        if locked then market:delete(lock_key) end
        if not delay then
            if err ~= "rejected" then ngx.log(ngx.ERR, "cdnca_limits: qps ", sub, ": ", err) end
            ngx.header["Retry-After"] = "1"
            return refused()
        end
    end
    -- admitted: counted in flight until leave()
    ngx_var.cdnca_limits_sub_key = sub
    stat_max(sub, "max_qps", market:incr("rps|" .. sub .. "|" .. floor(now), 1, 0, 2) or 1)
    stat_max(sub, "max_requests", market:incr("req|" .. sub, 1, 0) or 1)
end

local function market_leave()
    local sub = ngx_var.cdnca_limits_sub_key
    if not sub or sub == "" or not market then return end
    ngx_var.cdnca_limits_sub_key = ""
    local left = market:incr("req|" .. sub, -1)
    if left and left < 0 then market:set("req|" .. sub, 0) end
    local bytes = tonumber(ngx_var.bytes_sent) or 0
    if bytes > 0 then
        market:incr(stat_key(sub, "bytes_out"), bytes, 0, STATS_TTL)
        local second = market:incr("bps|" .. sub .. "|" .. floor(ngx.now()), bytes, 0, 2) or bytes
        stat_max(sub, "peak_bps", second * 8)
    end
end

-- init_worker(): the connection release timer (every worker).
function _M.init_worker()
    if not market then return end
    local ok, err = ngx.timer.every(1, release)
    if not ok then ngx.log(ngx.ERR, "cdnca_limits: release timer: ", err) end
end

-- minutes(): the finished minutes' records (cdnca.edge.subscription-minute/v1),
-- oldest first; each is handed out once (the minute is removed).
local FIELDS = { "max_requests", "max_connections", "max_new_cps", "max_qps", "bytes_out", "peak_bps" }
function _M.minutes()
    local result, current = {}, minute_of(ngx.now())
    if not market then return result end
    for minute = current - STATS_TTL + 60, current - 60, 60 do
        while true do
            local sub = market:lpop("subs|" .. minute)
            if not sub then break end
            local record = { schema = "cdnca.edge.subscription-minute/v1", minute = minute, subscription_id = sub }
            for _, field in ipairs(FIELDS) do
                local key = "m|" .. minute .. "|" .. sub .. "|" .. field
                record[field] = market:get(key) or 0
                market:delete(key)
            end
            result[#result + 1] = record
        end
    end
    return result
end

-- admin(): GET /subscription-minutes on the control socket.
function _M.admin()
    local records = _M.minutes()
    ngx.header["Content-Type"] = "application/json"
    ngx.say(#records == 0 and '{"minutes":[]}' or cjson.encode({ minutes = records }))
end

-- tcp_connections(subscription): the counted TCP connections (acceptance).
function _M.tcp_connections(subscription)
    return market and tcp_total(subscription) or 0
end

function _M.enter(site)
    local limit = site.limits and site.limits.connections
    if not limit then
        return
    end
    market_enter(limit)
    if limit.max <= 0 then
        return
    end
    -- Counted once per request: an access phase re-run after ngx.exec into a
    -- named location (ngx.ctx is new there) sees the variable.
    local counted = ngx_var.cdnca_limits_conn_key
    if ngx.ctx.cdnca_conn_key or counted and counted ~= "" then
        return
    end
    if not dict then
        ngx.log(ngx.ERR, "cdnca_limits: lua_shared_dict ", _M.DICT, " missing; refusing")
        return ngx.exit(503)
    end
    local key = limit.subscription_id
    local count, err = dict:incr(key, 1, 0)
    if not count then
        ngx.log(ngx.ERR, "cdnca_limits: count ", key, ": ", err)
        return ngx.exit(503)
    end
    if count > limit.max then
        dict:incr(key, -1)
        return refused()
    end
    ngx.ctx.cdnca_conn_key = key
    -- ngx.exec (cache dispatch) clears ngx.ctx; the variable survives it.
    ngx_var.cdnca_limits_conn_key = key
end

function _M.client(site)
    local limits = site.access and site.access.limits
    if not limits then
        return
    end
    local counted = ngx_var.cdnca_limits_ip_key
    if ngx.ctx.cdnca_ip_key or counted and counted ~= "" then
        return
    end
    local rate = tonumber(limits.rate_bytes_per_second) or 0
    if rate > 0 then
        local current = tonumber(ngx_var.limit_rate) or 0
        if current <= 0 or rate < current then
            ngx_var.limit_rate = rate
        end
        local after = tonumber(limits.rate_after_bytes) or 0
        if after > 0 then
            ngx_var.cdnca_limits_rate_after = after
        end
    end
    local most = tonumber(limits.connections_per_ip) or 0
    if most <= 0 then
        return
    end
    if not dict then
        ngx.log(ngx.ERR, "cdnca_limits: lua_shared_dict ", _M.DICT, " missing; refusing")
        return ngx.exit(503)
    end
    local key = "ip|" .. site.site_id .. "|" .. ngx_var.binary_remote_addr
    local count, err = dict:incr(key, 1, 0)
    if not count then
        ngx.log(ngx.ERR, "cdnca_limits: count client: ", err)
        return ngx.exit(503)
    end
    if count > most then
        dict:incr(key, -1)
        return ngx.exit(429)
    end
    ngx.ctx.cdnca_ip_key = key
    ngx_var.cdnca_limits_ip_key = key
end

local SITE_PREFIX = "site|"

function _M.site(site)
    local counted = ngx_var.cdnca_limits_site_key
    if not dict or ngx.ctx.cdnca_site_key or counted and counted ~= "" then
        return
    end
    local key = SITE_PREFIX .. site.site_id .. "|" .. (ngx_var.cdnca_site_port or "")
    if dict:incr(key, 1, 0) then
        ngx.ctx.cdnca_site_key = key
        ngx_var.cdnca_limits_site_key = key
    end
end

local function release_site()
    local key = ngx.ctx.cdnca_site_key or ngx_var.cdnca_limits_site_key
    if not key or key == "" or not dict then
        return
    end
    ngx.ctx.cdnca_site_key = nil
    ngx_var.cdnca_limits_site_key = ""
    local count = dict:incr(key, -1)
    if count and count <= 0 then
        dict:delete(key) -- removed sites leave nothing behind
    end
end

-- connections(): {"<site_id>|<port>": in flight} of every site with one.
function _M.connections()
    local result = {}
    if dict then
        for _, key in ipairs(dict:get_keys(0)) do
            if key:sub(1, #SITE_PREFIX) == SITE_PREFIX then
                local count = dict:get(key)
                if count and count > 0 then
                    result[key:sub(#SITE_PREFIX + 1)] = count
                end
            end
        end
    end
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.print(require("cjson.safe").encode(result))
end

local function release_client()
    local key = ngx.ctx.cdnca_ip_key or ngx_var.cdnca_limits_ip_key
    if not key or key == "" or not dict then
        return
    end
    ngx.ctx.cdnca_ip_key = nil
    ngx_var.cdnca_limits_ip_key = ""
    local count = dict:incr(key, -1)
    if count and count <= 0 then
        dict:delete(key) -- one key per client address: none left behind
    end
end

function _M.leave()
    release_site()
    release_client()
    market_leave()
    local rated = ngx_var.cdnca_limits_rate_key
    if rated and rated ~= "" and bandwidth then
        ngx_var.cdnca_limits_rate_key = ""
        local active = bandwidth:incr(rated, -1)
        if active and active < 0 then
            bandwidth:set(rated, 0, 3600)
        end
    end
    local key = ngx.ctx.cdnca_conn_key or ngx_var.cdnca_limits_conn_key
    if not key or key == "" or not dict then
        return
    end
    ngx.ctx.cdnca_conn_key = nil
    ngx_var.cdnca_limits_conn_key = ""
    local count, err = dict:incr(key, -1)
    if not count then
        ngx.log(ngx.ERR, "cdnca_limits: release ", key, ": ", err)
    elseif count < 0 then
        dict:set(key, 0) -- the dictionary was flushed by a resize reload
    end
end

-- in_flight(subscription): the current count (acceptance and status).
function _M.in_flight(subscription)
    return dict and (dict:get(subscription) or 0) or 0
end

return _M
