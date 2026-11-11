-- User-Agent parsing of the WAF v6 client conditions (§2.2-2.3,
-- §4.3; CAPABILITY_NAME_WAF v6): the browser, its version and the device kind
-- a request's User-Agent claims. It is libs/edgeconfig ParseUserAgent in Lua
-- (same browser order, tokens and version rule); both are tested against
-- libs/edgeconfig/testdata/user_agents.json (cdnca_ua_test.sh). A User-Agent
-- is client supplied: the conditions route and filter, never authenticate.
--
--   local ua = require "cdnca_ua"
--   local info = ua.request()   -- {browser, version (number|nil), device}
--
-- parse() is pure (string.find plain only, no ngx). request() parses the
-- request's User-Agent once and keeps the result in ngx.ctx.cdnca_ua; a
-- worker LRU (lookup) keyed by the parsed prefix saves the parse for
-- repeated User-Agents. Nothing here runs unless a rule plan has a
-- browser_in / browser_version / device_in condition (cdnca_rule_interp).
local find, sub, byte, lower = string.find, string.sub, string.byte, string.lower

local _M = { _VERSION = "1" }

-- MaxParsedUserAgentBytes: only this prefix is parsed.
local MAX_BYTES = 512
-- MaxBrowserVersionPart has 5 digits; version = major * SCALE^2 + minor *
-- SCALE + patch keeps the order of [major, minor, patch] (< 2^53).
local SCALE = 100000
_M.VERSION_SCALE = SCALE

-- Detection order (edgeconfig uaBrowserRules): tokens (any one present),
-- require (also needed), version (the first present one precedes the version).
local RULES = {
    { "wechat_browser", { "MicroMessenger/" }, nil, { "MicroMessenger/" } },
    { "qq_browser", { "MQQBrowser/", "QQBrowser/" }, nil, { "MQQBrowser/", "QQBrowser/" } },
    { "uc_browser", { "UCBrowser/", "UCWEB" }, nil, { "UCBrowser/" } },
    { "baidu_browser", { "baiduboxapp/", "BIDUBrowser", "baidubrowser/" }, nil, { "baiduboxapp/", "BIDUBrowser/", "baidubrowser/" } },
    { "sogou_browser", { "SogouMobileBrowser/", "SE 2.X MetaSr" }, nil, { "SogouMobileBrowser/" } },
    { "360_browser", { "QihooBrowser", "360SE", "360EE" }, nil, {} },
    { "microsoft_edge", { "Edg/", "EdgA/", "EdgiOS/", "Edge/" }, nil, { "Edg/", "EdgA/", "EdgiOS/", "Edge/" } },
    { "opera", { "OPR/", "OPiOS/", "Opera/" }, nil, { "OPR/", "OPiOS/", "Opera/" } },
    { "samsung_browser", { "SamsungBrowser/" }, nil, { "SamsungBrowser/" } },
    { "firefox", { "Firefox/", "FxiOS/" }, nil, { "Firefox/", "FxiOS/" } },
    { "google_chrome", { "Chrome/", "CriOS/" }, nil, { "Chrome/", "CriOS/" } },
    { "safari", { "Safari/" }, "Version/", { "Version/" } },
}

-- BROWSERS / DEVICES: the names a condition may use (edgeconfig
-- WAFBrowserNames / WAFDeviceKinds); VERSIONED: browsers that can carry a
-- version (WAFBrowserHasVersion).
_M.BROWSERS, _M.VERSIONED = { unknown = true }, {}
for _, rule in ipairs(RULES) do
    _M.BROWSERS[rule[1]] = true
    if #rule[4] > 0 then _M.VERSIONED[rule[1]] = true end
end
_M.DEVICES = { bot = true, desktop = true, mobile = true, tablet = true }

-- Found in the ASCII lower-cased User-Agent (string.lower: C locale, A-Z only).
local BOT_TOKENS = { "bot", "spider", "crawl", "slurp", "curl/", "wget/", "python-requests", "python-urllib",
    "go-http-client", "okhttp", "headless" }
local MOBILE_TOKENS = { "Mobile", "iPhone", "Android", "HarmonyOS", "Windows Phone" }

local function has(value, token) return find(value, token, 1, true) ~= nil end

local function has_any(value, tokens)
    for index = 1, #tokens do
        if find(value, tokens[index], 1, true) then return true end
    end
    return false
end

local function device(ua)
    if ua == "" or has_any(lower(ua), BOT_TOKENS) then return "bot" end
    if has(ua, "iPad") or (has(ua, "Android") and not has(ua, "Mobile")) or has(ua, "Tablet") then return "tablet" end
    if has_any(ua, MOBILE_TOKENS) then return "mobile" end
    return "desktop"
end

-- digits: the run of ASCII digits of ua from position start; its end + 1.
local function digits(ua, start)
    local position = start
    while true do
        local value = byte(ua, position)
        if not value or value < 48 or value > 57 then return position end
        position = position + 1
    end
end

-- version at position start (parseUserAgentVersion): 1-5 digits of major,
-- then up to two ".<1-5 digits>"; nil without a major (or more than 5 of its
-- digits); a longer minor or patch ends the version there.
local function version_at(ua, start)
    local parts, position = { 0, 0, 0 }, start
    for part = 1, 3 do
        if part > 1 then
            if byte(ua, position) ~= 46 then break end
            position = position + 1
        end
        local stop = digits(ua, position)
        local count = stop - position
        if count == 0 or count > 5 then
            if part == 1 then return nil end
            break
        end
        parts[part] = tonumber(sub(ua, position, stop - 1))
        position = stop
    end
    return (parts[1] * SCALE + parts[2]) * SCALE + parts[3]
end

-- parse(ua) -> browser, version (major*SCALE^2+minor*SCALE+patch | nil), device.
function _M.parse(ua)
    if type(ua) ~= "string" then ua = "" end
    if #ua > MAX_BYTES then ua = sub(ua, 1, MAX_BYTES) end
    for index = 1, #RULES do
        local rule = RULES[index]
        if has_any(ua, rule[2]) and (rule[3] == nil or has(ua, rule[3])) then
            local version
            local tokens = rule[4]
            for token_index = 1, #tokens do
                local token = tokens[token_index]
                local at = find(ua, token, 1, true)
                if at then
                    version = version_at(ua, at + #token)
                    break
                end
            end
            return rule[1], version, device(ua)
        end
    end
    return "unknown", nil, device(ua)
end

-- Worker cache of parsed User-Agents (10 000 entries).
local LRU_ITEMS = 10000
local cache

-- lookup(ua) -> info {browser, version, device} (shared, read only).
function _M.lookup(ua)
    if type(ua) ~= "string" then ua = "" end
    if #ua > MAX_BYTES then ua = sub(ua, 1, MAX_BYTES) end
    if not cache then cache = assert(require("resty.lrucache").new(LRU_ITEMS)) end
    local info = cache:get(ua)
    if info then return info end
    local browser, version, kind = _M.parse(ua)
    info = { browser = browser, version = version, device = kind }
    cache:set(ua, info)
    return info
end

-- request() -> the current request's info, parsed once per request from
-- $http_user_agent (the value cdnca_waf's user_agent target reads).
function _M.request()
    local ctx = ngx.ctx
    local info = ctx.cdnca_ua
    if info then return info end
    info = _M.lookup(ngx.var.http_user_agent or "")
    ctx.cdnca_ua = info
    return info
end

return _M
