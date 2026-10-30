-- cdnca managed WAF on dynamic routing (task D11, ADR 0009 PoC section 5).
--
-- The node skeleton loads one ModSecurity rule set for every site (the http
-- level node rules) and one named location per tier (a CRS profile pack plus
-- the limits ModSecurity reads only at configuration time). location / never
-- runs ModSecurity. For a request of a site with a managed WAF, rewrite()
-- (the first thing the entry module's rewrite phase does, in location /)
-- writes the site context into $cdnca_waf_txid and ngx.exec()s into the
-- site's tier location: there ModSecurity creates the transaction with that
-- ID (phase 1), then the rewrite phase runs again (rule plan), then phase 2
-- (request body), then access. Same order as v7 (PoC section 5 item 5).
--
-- Context (libs/edgeconfig DynamicWAFContext, cdnca managed WAF context v3,
-- ADR 0011 3.1):
--   c3;s=<site>;i=<l|b>;e=<1|0>;g=<0|1>;b=<0|1>;p=<0-100>;d=,..,;f=<0-99>;
--   k=,..,;u=,..,;x=,<id>,..,;|<request id>
-- i: inspection limit log/block; e=0: the client is in the site's allow
-- CIDRs (engine off; everything else empty). g=1: a valid grey zone pass
-- cookie; b=1: a browser-like request of a site whose grey zone challenges
-- (the node rules challenge only b=1, g=0; an API-like request or a site
-- with grey_challenge off is b=0). p: platform intelligence (ad-10; 0).
-- d: the structural detectors (cdnca_waf detect_args) and "shape" (a typed
-- parameter's value out of type), only for a site whose CRS profile pack
-- scores in two levels (严格防护 and above: configure managed_waf_detect).
-- d also carries "repeat" (after shape): the source (site x client address
-- x JA4 over TLS, site x client address without one: repeat_key) had
-- REPEAT.threshold grey zone transactions on the site in the current or
-- the previous REPEAT.window seconds (waf-gap6, research §3.9; the site's
-- waf_adapt repeat_threshold / repeat_window when set, defer-small2); the node
-- rules then score the two-level sets' weak sums as strong. log() counts a
-- transaction as grey when $modsecurity_rule_ids (ModSecurity-nginx patch
-- 01) names a grey zone rule (edgeconfig DynamicWAFGreyRule).
-- f: the site's grey zone floor (waf_adapt grey_floor, 0 = none). k: the
-- sets the auto defense overlay tightens (waf.tighten:<set>). u: tuning
-- entries (none yet). x: the site's exclusions. The node rules refuse a
-- missing or malformed context with 500; a tier location that is not in the
-- skeleton makes ngx.exec answer 500: both fail closed.
--
-- A site's application types (CRS application exclusion packs) are part of
-- its tier: the tier key ends with "_x<first 8 hex of the pack digest>" per
-- app (site object order, sorted by pack ID) and the tier's rule file
-- carries their text, so nothing per request names them.
--
-- Automatic exclusions (ADR 0011 3.4) are not in
-- the context: a site with some in force runs in an exclusion bucket
-- location of its tier (its tier's rules plus one rule per bucket site,
-- edgeconfig RenderDynamicWAFBucket), mapped in configure
-- managed_waf_buckets by the same skeleton; the plan looks the site up once
-- and enters that location instead of the tier's.
--
-- Adaptive state (ADR 0011 3.10): the agent writes each site's waf_adapt
-- (grey_challenge, grey_floor, typed_params) through the control socket
-- (admin(), POST /waf-adapt/) into the dictionary cdnca_waf_adapt; no entry:
-- no grey zone challenge, no floor, no shape.
--
-- Cookies (waf-cookie-fp2): a two-level tier's weak rules do not read
-- cookies; a request with a cookie out of the site's typed cookie parameter
-- (adapt.shape) enters the tier's cookie variant @cdnca_waf_<key>_c, whose
-- weak rules do (edgeconfig RenderDynamicWAFTierCookies); so does, on a
-- cookie mature site (waf_adapt cookie_names), a cookie name the site never
-- saw. A site without a typed cookie and not cookie mature never does.
--
-- The site's derived data (tier location, context prefix, allow networks)
-- is cached per site object digest: a new site object is a new digest.
local ffi = require "ffi"
local bit = require "bit"
local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"

local ngx = ngx
local ngx_var = ngx.var
local type, tonumber, ipairs, pairs, next, concat, format = type, tonumber, ipairs, pairs, next, table.concat, string.format
local byte, sub = string.byte, string.sub

local _M = { _VERSION = "2" }

local TIER_PREFIX = "@cdnca_waf_"
local CACHE_ITEMS = 10000
local ADAPT_DICT = "cdnca_waf_adapt"
local VERIFY_PATH = "/.cdnca/waf/verify" -- cdnca_waf WAF_VERIFY_PATH

-- Linux socket families (the node runtime is Linux only).
local AF_INET, AF_INET6 = 2, 10
pcall(ffi.cdef, [[ int inet_pton(int af, const char *src, void *dst); ]])
local address_buffer = ffi.new("unsigned char[16]")

local cache = assert(lrucache.new(CACHE_ITEMS))

-- edgeconfig DynamicWAFDetectors names, in that order
local DETECTORS = { "sqli", "xss", "ssti", "java_deser", "php_deser", "ssrf", "cmd", "crlf", "redirect", "format", "nosql",
    "ldap", "upload", "xxe", "proto", "path" }
-- CRS profile pack digests whose sites get detector verdicts, and those
-- whose grey zone challenges (grey_action challenge: 严格/极严格, Q3); the
-- sites with exclusions in force (site ID -> bucket location)
local detect_profiles, grey_profiles, site_buckets = {}, {}, {}
-- the skeleton has the two-level tiers' cookie variants (managed_waf_cookie)
local cookie_variants = false

-- configure(opts): init_by_lua (cdnca_dynroute.configure).
function _M.configure(opts)
    detect_profiles, grey_profiles, site_buckets = {}, {}, {}
    cookie_variants = opts ~= nil and opts.cookie_variants == true
    for _, digest in ipairs(opts and opts.detect_profiles or {}) do
        detect_profiles[digest] = true
    end
    for _, digest in ipairs(opts and opts.grey_profiles or {}) do
        grey_profiles[digest] = true
    end
    for site_id, location in pairs(opts and opts.buckets or {}) do
        site_buckets[site_id] = location
    end
end

-- ngx.exec clears ngx.ctx; what server_rewrite left there (CC's 404 and
-- auto-switch bookkeeping, the TLS request state) must survive the hop to
-- the tier location, where v7 never hopped. Kept per request ID in the
-- worker; the tier location's rewrite takes it back, log() drops what a
-- failed hop left.
local stash = {}

local function integer(value, low, high)
    return type(value) == "number" and value == math.floor(value) and value >= low and value <= high
end

-- network(text) -> { bytes = "<4|16 raw bytes>", bits = n } | nil
local function network(text)
    if type(text) ~= "string" then return nil end
    local address, bits = text:match("^([^/]+)/(%d+)$")
    bits = tonumber(bits)
    if not address or not bits then return nil end
    local size, family = 4, AF_INET
    if address:find(":", 1, true) then size, family = 16, AF_INET6 end
    if bits > size * 8 or ffi.C.inet_pton(family, address, address_buffer) ~= 1 then return nil end
    return { bytes = ffi.string(address_buffer, size), bits = bits }
end

local function contains(net, client)
    if #client ~= #net.bytes then return false end
    local full = math.floor(net.bits / 8)
    if full > 0 and sub(client, 1, full) ~= sub(net.bytes, 1, full) then return false end
    local rest = net.bits % 8
    if rest == 0 then return true end
    local unit = 2 ^ (8 - rest) -- compare the top `rest` bits of the next byte
    local a, b = byte(client, full + 1), byte(net.bytes, full + 1)
    return a - a % unit == b - b % unit
end

-- tier_key: libs/edgeconfig DynamicWAFTier.Key (same text, same order).
local function tier_key(waf)
    local profile, limits = waf.crs_profile, waf.profile
    if type(profile) ~= "table" or type(limits) ~= "table" or type(profile.sha256) ~= "string" or
        not profile.sha256:match("^[0-9a-f]+$") or #profile.sha256 ~= 64 then
        return nil
    end
    local action = limits.request_body_limit_action
    if action == "partial" then action = "p" elseif action == "reject" then action = "r" else return nil end
    for _, name in ipairs({ "request_body_limit", "request_body_no_files_limit", "arguments_limit",
        "json_depth_limit", "pcre_match_limit" }) do
        if not integer(limits[name], 1, 1e9) then return nil end
    end
    local key = format("%s_b%d_n%d_%s_a%d_j%d_p%d", sub(profile.sha256, 1, 16), limits.request_body_limit,
        limits.request_body_no_files_limit, action, limits.arguments_limit, limits.json_depth_limit,
        limits.pcre_match_limit)
    local apps = waf.apps
    if apps == nil or apps == ngx.null then return key end
    if type(apps) ~= "table" or #apps > 16 then return nil end
    local parts = { key }
    for _, app in ipairs(apps) do
        if type(app) ~= "table" or type(app.sha256) ~= "string" or #app.sha256 ~= 64 or
            not app.sha256:match("^[0-9a-f]+$") then
            return nil
        end
        parts[#parts + 1] = "_x" .. sub(app.sha256, 1, 8)
    end
    return concat(parts)
end

-- tuning_off(security) -> the c3 u= list (ADR 0011 RI-13): the official CRS
-- tuning entries the site disables, ascending, from its system/crs-tuning
-- mount's exclusions (rulepack TuningOf); ",0," without that mount (no entry
-- applies, edgeconfig DynamicWAFTuningAllOff) | nil, reason.
local TUNING_PACK = "system/crs-tuning"
local MAX_TUNING_OFF = 64 -- edgeconfig DynamicWAFMaxTuningOff

local function tuning_off(security)
    local mounts = security.mounts
    if mounts == nil or mounts == ngx.null then return ",0," end
    if type(mounts) ~= "table" then return nil, "mounts" end
    for _, mount in ipairs(mounts) do
        if type(mount) == "table" and mount.pack_id == TUNING_PACK then
            local params = mount.params
            local excluded = type(params) == "table" and params.exclusions or nil
            if excluded == nil or excluded == ngx.null then return "," end
            if type(excluded) ~= "table" or #excluded > MAX_TUNING_OFF then return nil, "tuning exclusions" end
            local numbers = {}
            for _, id in ipairs(excluded) do
                local number = type(id) == "string" and id:match("^[1-9]%d?%d?%d?%d?%d?$") and tonumber(id)
                if not number then return nil, "tuning exclusion" end
                numbers[#numbers + 1] = number
            end
            table.sort(numbers)
            if #numbers == 0 then return "," end
            return "," .. concat(numbers, ",") .. ","
        end
    end
    return ",0,"
end

-- timed_allows(security) -> { {net, expires}, ... } | nil, reason: the
-- temporary client_ip-only allow rules of the site's enabled policies
-- (security.rules, edgesite.RulePlan). Control puts only permanent ones in
-- allow_cidrs (securitypublication unconditionalAllowCIDRs, SF-E01): these
-- exempt the client from CRS only while now < expires_at, the expiry the
-- rule plan applies to the same rule.
local function timed_allows(security)
    local result = {}
    local rules = security.rules
    if type(rules) ~= "table" or type(rules.policies) ~= "table" then return result end
    for _, policy in ipairs(rules.policies) do
        if type(policy) == "table" and policy.enabled == true and type(policy.rules) == "table" then
            for _, rule in ipairs(policy.rules) do
                local match = type(rule) == "table" and rule.match
                if rule.action == "allow" and type(rule.expires_at) == "string" and rule.expires_at ~= "" and
                    type(match) == "table" and type(match.source_cidr) == "string" and next(match, next(match)) == nil then
                    local expires = require("cdnca_rule_plan").unix_seconds(rule.expires_at)
                    local net = network(match.source_cidr)
                    if not expires then return nil, "allow expires_at" end
                    if not net then return nil, "allow_cidr" end
                    result[#result + 1] = { net = net, expires = expires }
                end
            end
        end
    end
    return result
end

-- compile(site) -> plan | false (the site has no managed WAF) | nil, reason
local function compile(site)
    local security = site.security
    local waf = type(security) == "table" and security.managed_waf
    if waf == nil or waf == ngx.null then return false end
    if type(waf) ~= "table" or type(site.site_id) ~= "string" or not site.site_id:match("^[0-9a-f-]+$") or
        #site.site_id ~= 36 then
        return nil, "managed_waf"
    end
    local key = tier_key(waf)
    if not key then return nil, "tier" end
    local inspection = waf.profile.inspection_limit_action
    if inspection ~= "log" and inspection ~= "block" then return nil, "inspection_limit_action" end
    local ids = { "" }
    if type(waf.exclusions) ~= "table" or #waf.exclusions > 256 then return nil, "exclusions" end
    for _, id in ipairs(waf.exclusions) do
        if not integer(id, 900000, 999999) then return nil, "exclusion" end
        ids[#ids + 1] = format("%d", id)
    end
    ids[#ids + 1] = ""
    local allow = {}
    if type(waf.allow_cidrs) ~= "table" then return nil, "allow_cidrs" end
    for _, text in ipairs(waf.allow_cidrs) do
        local net = network(text)
        if not net then return nil, "allow_cidr" end
        allow[#allow + 1] = net
    end
    local timed, timed_reason = timed_allows(security)
    if not timed then return nil, timed_reason end
    local tuning, tuning_reason = tuning_off(security)
    if not tuning then return nil, tuning_reason end
    local prefix = "c3;s=" .. site.site_id .. ";i=" .. sub(inspection, 1, 1) .. ";e="
    local detect = detect_profiles[waf.crs_profile.sha256] == true
    -- configure ran before any request: the site's bucket (automatic
    -- exclusions in force) is known when the plan is compiled. A two-level
    -- tier (detect) has a cookie variant when the skeleton renders them,
    -- and so has each of its buckets (<bucket>_c: the bucket's exclusions
    -- over the tier's cookie variant), so exclusions never turn the
    -- adaptive cookie reading off.
    local location = site_buckets[site.site_id] or TIER_PREFIX .. key
    return { location = location,
        cookie_location = (detect and cookie_variants) and location .. "_c" or nil,
        on = prefix .. "1;g=", off = prefix .. "0;g=0;b=0;p=0;d=,;f=0;k=,;u=,;x=",
        exclude = concat(ids, ","), tuning = tuning, allow = allow, timed = timed, site_id = site.site_id,
        detect = detect, grey = grey_profiles[waf.crs_profile.sha256] == true }
end

local function plan_of(digest, site)
    local plan = cache:get(digest)
    if plan == nil then
        local reason
        plan, reason = compile(site)
        if plan == nil then return nil, reason end
        cache:set(digest, plan)
    end
    return plan
end

local function allowed(plan)
    if #plan.allow == 0 and #plan.timed == 0 then return false end
    local client = ngx_var.binary_remote_addr
    if not client then return false end
    for _, net in ipairs(plan.allow) do
        if contains(net, client) then return true end
    end
    if #plan.timed == 0 then return false end
    -- a temporary allow exempts the client only before its expiry, checked
    -- per request as the rule plan checks it (now < expires_at): the same
    -- site object stops exempting it at expiry, without a new publication
    local now = ngx.time()
    for _, entry in ipairs(plan.timed) do
        if now < entry.expires and contains(entry.net, client) then return true end
    end
    return false
end

-- ---------------------------------------------------------------------------
-- Adaptive state (ADR 0011 RI-03). Everything new lives in this table.
-- ---------------------------------------------------------------------------
local adapt = { cache = assert(lrucache.new(CACHE_ITEMS)),
    -- grey zone challenge parameters (cdnca_waf challenge config)
    challenge = { pass_seconds = 3600, pow_bits = 12 },
    pass_cookie = "__cdnca_waf_grey",
    -- WAFValueTypes subsets a typed parameter accepts, by its type
    TYPES = { number = { number = true }, ident = { number = true, ident = true }, binary = { number = true, ident = true, binary = true } },
    -- WAFCharsetClasses bits (libs/edgeconfig/autodefense wafadapt.go)
    CHARSET = { { "['\"]", 1 }, { "[<>]", 2 }, { "[()]", 4 }, { ";", 8 }, { "|", 16 }, { "`", 32 }, { "%$", 64 },
        { "[{}]", 128 }, { "%%%x%x", 256 }, { "%s", 512 }, { "%c", 1024 }, { "[\128-\255]", 2048 }, { "\\", 4096 } },
    MAX_PARAMS = 64, -- request parameters typed per request
}

-- adapt.state(site_id): the site's adaptive WAF entry (agent written,
-- decoded once per version), or nil.
function adapt.state(site_id)
    local dict = ngx.shared[ADAPT_DICT]
    local version = dict and dict:get("v:" .. site_id)
    if not version then return nil end
    local cached = adapt.cache:get(site_id)
    if cached and cached.version == version then return cached end
    local entry = cjson.decode(dict:get("a:" .. site_id) or "")
    if type(entry) ~= "table" then return nil end
    local state = { version = version, grey = entry.grey_challenge == true, floor = entry.grey_floor or 0, typed = {},
        -- the site's repeat setting (WAF_REPEAT_SITE), else the REPEAT constants
        repeat_threshold = entry.repeat_threshold, repeat_window = entry.repeat_window }
    -- a cookie mature site's known cookie names, by CRC-32 of "cookie:<name>"
    if type(entry.cookie_names) == "table" and #entry.cookie_names > 0 then
        state.cookies = {}
        for _, low in ipairs(entry.cookie_names) do
            local value = tonumber(low, 16)
            if value then state.cookies[value] = true end
        end
    end
    -- by the key's halves as numbers (no hex formatting per request):
    -- typed[low] = { [high] = typed }, high 0 for a site level key
    for _, typed in ipairs(type(entry.typed_params) == "table" and entry.typed_params or {}) do
        local high, low = tonumber(typed.key:sub(1, 8), 16), tonumber(typed.key:sub(9), 16)
        if high and low then
            state.typed[low] = state.typed[low] or {}
            state.typed[low][high] = typed
        end
    end
    adapt.cache:set(site_id, state)
    return state
end

-- adapt.browser(): ADR 0011 3.2 browser-like request (PoC-3 classification):
-- no Authorization / X-Requested-With; Accept text/html, else GET / HEAD or
-- a form POST without a JSON-like Accept.
function adapt.browser()
    if ngx_var.http_authorization or ngx_var.http_x_requested_with then return false end
    local accept = ngx_var.http_accept or ""
    if accept:find("text/html", 1, true) then return true end
    if accept:find("application/json", 1, true) then return false end
    local method = ngx.req.get_method()
    if method == "GET" or method == "HEAD" then return true end
    local ctype = (ngx_var.content_type or ""):lower()
    return method == "POST" and (ctype:find("application/x-www-form-urlencoded", 1, true) == 1 or
        ctype:find("multipart/form-data", 1, true) == 1)
end

-- adapt.spec(plan): the grey zone challenge's cdnca_waf spec.
function adapt.spec(plan)
    local spec = plan.grey_spec
    if not spec then
        spec = { scope = "waf-grey:" .. plan.site_id, policy_id = plan.site_id, rules = {}, pass_cookie = adapt.pass_cookie }
        plan.grey_spec = spec
    end
    return spec
end

-- adapt.template(path): the path template of a profile key (ADR 0010 4.2:
-- a numeric segment is {n}, a hex segment of 16+ digits or a UUID {h}).
function adapt.template(path)
    local parts = {}
    for segment in path:gmatch("[^/]+") do
        if segment:find("^%d+$") then
            segment = "{n}"
        elseif #segment >= 16 and (segment:find("^%x+$") or segment:find("^%x+%-%x+%-%x+%-%x+%-%x+$")) then
            segment = "{h}"
        end
        parts[#parts + 1] = segment
    end
    return "/" .. concat(parts, "/")
end

-- adapt.kind(value): the value's WAFValueTypes class among those typed.
function adapt.kind(value)
    if value:find("^%-?%d+%.?%d*$") then return "number" end
    if #value <= 64 and value:find("^[%w_.%-]+$") then return "ident" end
    if value:find("^[%w+/_%-]+=*$") then return "binary" end
    return "other"
end

-- adapt.misfit(typed, value): the value is out of the typed parameter's
-- type, length bucket or charset (section 3.3 shape).
function adapt.misfit(typed, value)
    if not adapt.TYPES[typed.type] or not adapt.TYPES[typed.type][adapt.kind(value)] then return true end
    local length, bucket = #value, 0
    while length > 0 and bucket < 7 do bucket, length = bucket + 1, math.floor(length / 2) end
    if type(typed.max_len_bucket) == "number" and bucket > typed.max_len_bucket then return true end
    local allowed_bits = type(typed.charset) == "number" and typed.charset or 0
    for _, class in ipairs(adapt.CHARSET) do
        if value:find(class[1]) and bit.band(allowed_bits, class[2]) == 0 then return true end
    end
    return false
end

-- adapt.shape(state) -> shape, cookie: some request parameter (query or
-- form argument, cookie) of a typed key has a value out of its type; cookie:
-- one of them is a cookie (its weak score then counts, cookie variant). On
-- a cookie mature site (state.cookies) a cookie name it never saw is a
-- cookie deviation as well (cookie only: an unseen name has no type, so no
-- shape score). The platform's own cookies (__cdnca*) are not the site's.
function adapt.shape(state)
    local known = state.cookies
    if not next(state.typed) and not known then return false, false end
    local high
    local seen = 0
    local function misfit(location, name, value)
        if type(name) ~= "string" or seen >= adapt.MAX_PARAMS then return false end
        seen = seen + 1
        local by_template = state.typed[ngx.crc32_long(location .. ":" .. name)]
        if not by_template then return false end
        high = high or ngx.crc32_long(adapt.template(ngx_var.uri or "/"))
        local typed = by_template[high] or by_template[0]
        if not typed then return false end
        if type(value) == "table" then
            for _, item in ipairs(value) do
                if type(item) == "string" and adapt.misfit(typed, item) then return true end
            end
            return false
        end
        return type(value) == "string" and adapt.misfit(typed, value)
    end
    -- cookies first: a cookie misfit decides both results
    local unseen = false
    for pair in (ngx_var.http_cookie or ""):gmatch("[^;]+") do
        local name, value = pair:match("^%s*([^=]+)=(.*)$")
        if name and misfit("cookie", name, value) then return true, true end
        if known and name and not unseen and name:sub(1, 7) ~= "__cdnca" and not known[ngx.crc32_long("cookie:" .. name)] then
            unseen = true
        end
    end
    if unseen then return false, true end
    for name, value in pairs(ngx.req.get_uri_args(adapt.MAX_PARAMS)) do
        if misfit("args", name, value) then return true, false end
    end
    -- waf-gap4: a typed request header (lower-case name, ADR 0011 3.3 loc
    -- header) out of its type, as for a cookie but no variant (CRS weak
    -- rules hardly read custom headers: the detectors do, detect_args)
    for name, value in pairs(ngx.req.get_headers(adapt.MAX_PARAMS)) do
        if misfit("header", name, value) then return true, false end
    end
    if ngx.req.get_method() == "POST" and (ngx_var.content_type or ""):lower():find("application/x-www-form-urlencoded", 1, true) == 1 then
        ngx.req.read_body()
        for name, value in pairs(ngx.req.get_post_args(adapt.MAX_PARAMS) or {}) do
            if misfit("args", name, value) then return true, false end
        end
    end
    return false, false
end

-- Repeated grey zone source (edgeconfig DynamicWAFRepeat*): fixed windows
-- per site x client address x JA4 ($cdnca_ja4, native patch 21; plain
-- HTTP and HTTP/3 have none: site x client address) in a fixed size
-- dictionary (LRU evicts, nothing queues); the previous window counts too,
-- so a source at the threshold stays repeated for one more window. The JA4
-- keeps a NAT exit's other clients out of one scanner's count (waf-gap8).
local REPEAT = { dict = "cdnca_waf_grey", threshold = 20, window = 60,
    -- the grey zone rules: 31000 + set position * 8 + 3, set positions < 124
    first = 31000, last = 31000 + 124 * 8 }

local function repeat_key(site_id, window)
    local client = ngx_var.binary_remote_addr
    if not client then return nil end
    -- fixed length site ID and address; the JA4 ("" or 36 bytes) then "|"
    return site_id .. client .. (ngx_var.cdnca_ja4 or "") .. "|" .. window
end

-- repeat_setting(site_id): the site's threshold and window seconds
-- (waf_adapt repeat_threshold / repeat_window, defer-small2), else REPEAT's.
-- repeated() and count() read the same so their windows line up.
local function repeat_setting(site_id)
    local state = adapt.state(site_id)
    if state and state.repeat_threshold then return state.repeat_threshold, state.repeat_window end
    return REPEAT.threshold, REPEAT.window
end

-- adapt.repeated(plan): the source is a repeated grey zone source.
function adapt.repeated(plan)
    local dict = ngx.shared[REPEAT.dict]
    if not dict then return false end
    local threshold, seconds = repeat_setting(plan.site_id)
    local window = math.floor(ngx.time() / seconds)
    local now = repeat_key(plan.site_id, window)
    if not now then return false end
    if (dict:get(now) or 0) >= threshold then return true end
    return (dict:get(repeat_key(plan.site_id, window - 1)) or 0) >= threshold
end

-- grey(ids): $modsecurity_rule_ids names a grey zone rule.
local function grey(ids)
    for id in ids:gmatch("3%d%d%d%d") do
        local number = tonumber(id)
        if number >= REPEAT.first and number < REPEAT.last and (number - REPEAT.first) % 8 == 3 then
            return true
        end
    end
    return false
end

-- adapt.count(): log phase of a request that ran its tier location with
-- detection on: one grey zone transaction more for its source.
function adapt.count()
    local site_id = ngx_var.cdnca_waf_repeat_site
    if not site_id or site_id == "" then return end
    local ids = ngx_var.modsecurity_rule_ids
    if not ids or not grey(ids) then return end
    local dict = ngx.shared[REPEAT.dict]
    if not dict then return end
    local _, seconds = repeat_setting(site_id)
    local key = repeat_key(site_id, math.floor(ngx.time() / seconds))
    if key then
        -- two windows' worth: the next window still reads this one
        dict:incr(key, 1, 0, seconds * 2)
    end
end

-- adapt.tighten(plan): k=, the sets the auto defense overlay tightens.
function adapt.tighten(plan)
    local autodefense = ngx.shared.cdnca_autodefense and package.loaded.cdnca_autodefense
    local values = autodefense and autodefense.overlay(plan.site_id)
    if not values then return "," end
    local sets = {}
    for field, value in pairs(values) do
        local set = value == 1 and field:match("^waf%.tighten:([%w._%-]+)$")
        if set and #set <= 64 then sets[#sets + 1] = set end
    end
    if #sets == 0 then return "," end
    table.sort(sets)
    return "," .. concat(sets, ",", 1, math.min(#sets, 10)) .. ","
end

-- context(plan) -> this request's transaction ID, its tier location (the
-- cookie variant for a cookie out of the site's profile). The detectors
-- read the request body (ngx.req.read_body: ModSecurity's phase 2 then
-- finds it read).
function _M.context(plan)
    if allowed(plan) then
        return plan.off .. ",;|" .. ngx_var.request_id, plan.location
    end
    local state = adapt.state(plan.site_id)
    local grey = plan.grey and state ~= nil and state.grey
    local passed = grey and require("cdnca_waf").grey.passed(adapt.spec(plan))
    local detected, location = ",", plan.location
    if plan.detect then
        detected = require("cdnca_waf").detect_args(DETECTORS)
        local shaped, cookie = false, false
        if state then shaped, cookie = adapt.shape(state) end
        if shaped then detected = detected .. "shape," end
        if adapt.repeated(plan) then detected = detected .. "repeat," end
        if cookie and plan.cookie_location then location = plan.cookie_location end
        ngx_var.cdnca_waf_repeat_site = plan.site_id
    end
    -- every segment is bounded (edgeconfig DynamicWAFContextMax): the
    -- context always fits, nothing is dropped
    return plan.on .. (passed and "1" or "0") .. ";b=" .. ((grey and adapt.browser()) and "1" or "0") ..
        ";p=0;d=" .. detected .. ";f=" .. (state and state.floor or 0) .. ";k=" .. adapt.tighten(plan) ..
        ";u=" .. plan.tuning .. ";x=" .. plan.exclude .. ";|" .. ngx_var.request_id, location
end

-- challenge(): the grey zone challenge location (error_page 599). A site
-- that does not challenge (or an object that changed since) answers 403.
function _M.challenge()
    local site = require("cdnca_site").current()
    local plan = site and plan_of(ngx_var.cdnca_site_digest, site)
    if not plan or not plan.grey then return ngx.exit(403) end
    return require("cdnca_waf").grey.challenge(adapt.spec(plan), adapt.challenge)
end

-- admin(): the agent's control socket, POST /waf-adapt/ with
-- {sites:[{site_id, grey_challenge, grey_floor, typed_params:[{key,type,
-- max_len_bucket,charset}], cookie_names:[<8 hex>], repeat_threshold,
-- repeat_window}], remove_sites:[]}
-- (autodefense WAFAdapt, cookie_names only for a cookie mature site; the
-- automatic exclusions are in the site's exclusion bucket, not here).
function _M.admin()
    local dict = ngx.shared[ADAPT_DICT]
    if not dict then return ngx.exit(404) end
    if ngx.req.get_method() ~= "POST" then return ngx.exit(405) end
    ngx.req.read_body()
    local update = cjson.decode(ngx.req.get_body_data() or "")
    if type(update) ~= "table" then return ngx.exit(400) end
    for _, site_id in ipairs(type(update.remove_sites) == "table" and update.remove_sites or {}) do
        dict:delete("a:" .. tostring(site_id)); dict:delete("v:" .. tostring(site_id))
    end
    for _, site in ipairs(type(update.sites) == "table" and update.sites or {}) do
        if type(site) ~= "table" or type(site.site_id) ~= "string" or not site.site_id:match("^[0-9a-f-]+$") or #site.site_id ~= 36 then
            return ngx.exit(400)
        end
        local floor = site.grey_floor
        if floor == nil then floor = 0 end
        if not integer(floor, 0, 99) then return ngx.exit(400) end -- edgeconfig DynamicWAFMaxGreyFloor
        local entry = { grey_challenge = site.grey_challenge == true, grey_floor = floor, typed_params = {} }
        -- both or neither; bounds = edgeconfig DynamicWAFRepeat{Threshold,Window}{Min,Max}
        local threshold, seconds = site.repeat_threshold, site.repeat_window
        if (threshold == nil) ~= (seconds == nil) or threshold ~= nil and
            (not integer(threshold, 2, 1000) or not integer(seconds, 10, 600)) then
            return ngx.exit(400)
        end
        entry.repeat_threshold, entry.repeat_window = threshold, seconds
        for _, typed in ipairs(type(site.typed_params) == "table" and site.typed_params or {}) do
            if type(typed.key) ~= "string" or not typed.key:match("^%x+$") or #typed.key ~= 16 or not adapt.TYPES[typed.type] or
                #entry.typed_params >= 32 then
                return ngx.exit(400)
            end
            entry.typed_params[#entry.typed_params + 1] = typed
        end
        local names = site.cookie_names
        if names ~= nil then
            if type(names) ~= "table" or #names > 64 then return ngx.exit(400) end -- autodefense MaxWAFCookieNames
            for _, name in ipairs(names) do
                if type(name) ~= "string" or #name ~= 8 or not name:match("^%x+$") then return ngx.exit(400) end
            end
            entry.cookie_names = names
        end
        local ok = dict:set("a:" .. site.site_id, cjson.encode(entry))
        if not ok or not dict:incr("v:" .. site.site_id, 1, 0) then return ngx.exit(507) end
    end
    ngx.status = 204
    return ngx.exit(204)
end

-- rewrite(site): hand a managed WAF site's request to its tier location.
-- Returns when there is nothing to do (no engine in this skeleton, not
-- location /, already in the tier location, no managed WAF); otherwise it
-- does not return (ngx.exec, or 500 for a site object it cannot read).
function _M.rewrite(site)
    -- "1" only in location / of a skeleton that runs the engine; a request
    -- re-entering rewrite in its tier location has its context already.
    if ngx_var.cdnca_waf_engine ~= "1" then return end
    local txid = ngx_var.cdnca_waf_txid
    if txid and txid ~= "" then
        -- in the tier location: the request's context comes back
        local id = ngx_var.request_id
        local saved = stash[id]
        if saved then
            stash[id] = nil
            ngx.ctx = saved
        end
        return
    end
    local plan, reason = plan_of(ngx_var.cdnca_site_digest, site)
    if plan == false then return end
    if not plan then
        ngx.log(ngx.ERR, "cdnca managed waf: site ", ngx_var.cdnca_site_id, " object rejected (", reason, ")")
        return ngx.exit(500)
    end
    -- a grey zone challenge page's verification (another policy's nonce
    -- goes on to the rule plan's gate)
    if plan.grey and ngx_var.uri == VERIFY_PATH then
        require("cdnca_waf").grey.verify(adapt.spec(plan))
    end
    local txid_value, location = _M.context(plan)
    ngx_var.cdnca_waf_txid = txid_value
    -- the tier location runs the client request's first pass (entry
    -- client_pass); access() ends it
    ngx_var.cdnca_waf_pass = "tier"
    stash[ngx_var.request_id] = ngx.ctx
    return ngx.exec(location)
end

-- access(): the client pass ends (a later ngx.exec, e.g. a cache variant, is
-- an ordinary internal pass).
function _M.access()
    if ngx_var.cdnca_waf_pass == "tier" then
        ngx_var.cdnca_waf_pass = ""
    end
end

-- The node rules' set decisions (edgeconfig renderManagedSetEvaluation):
-- strong sum 30100 + position*2 (+0 block, +1 log), combined sum 30600 +
-- position*3 (+1 block, +2 log; +0 is the nolog sum), positions < 124. The
-- CRS detection rules are 900000-948999 (949xxx/980xxx score and correlate).
local DECISION = { strong = 30100, combined = 30600, sets = 124, crs_first = 900000, crs_last = 949000 }

-- decision(ids): the security event of a transaction by $modsecurity_rule_ids
-- (",<id>,...,", match order): "block" or "log" (block wins over another
-- set's log) and the rule ID it is logged by, the first CRS detection rule
-- that matched ("managed-waf-<decision id>" without one); nil when no set
-- decided.
local function decision(ids)
    local verdict, decided, crs
    for id in ids:gmatch("%d+") do
        local n = tonumber(id)
        local found
        if n >= DECISION.strong and n < DECISION.strong + DECISION.sets * 2 then
            found = (n - DECISION.strong) % 2 == 0 and "block" or "log"
        elseif n >= DECISION.combined and n < DECISION.combined + DECISION.sets * 3 then
            local offset = (n - DECISION.combined) % 3
            found = offset == 1 and "block" or offset == 2 and "log" or nil
        elseif not crs and n >= DECISION.crs_first and n < DECISION.crs_last then
            crs = id
        end
        if found and verdict ~= "block" then verdict, decided = found, id end
    end
    if not verdict then return nil end
    return verdict, crs or ("managed-waf-" .. decided)
end
_M._decision = decision
_M._compile = compile -- tests (managed_waf_allow_expiry_test.sh)

-- record(): log phase of a tier location's request: a set decision becomes
-- the $cdnca_security_* event the telemetry logs (type waf, as a rule plan
-- WAF rule; the rule ID tells CRS apart), unless a module already emitted.
-- A block decision is the rule's own deny (403): its ID in the list means
-- the request was denied, whatever page error_page then serves. The
-- variables exist only with telemetry: writes are guarded.
local function record()
    local ids = ngx_var.modsecurity_rule_ids
    if not ids or ids == "," or ngx_var.cdnca_security_emit == "1" then return end
    local verdict, rule_id = decision(ids)
    if not verdict then return end
    pcall(function()
        ngx_var.cdnca_security_emit = "1"
        ngx_var.cdnca_security_type = "waf"
        ngx_var.cdnca_security_action = verdict
        ngx_var.cdnca_security_rule_id = rule_id
        if verdict == "block" then
            ngx_var.cdnca_security_severity = "high"
            ngx_var.cdnca_security_block_page = "1"
        else
            ngx_var.cdnca_security_severity = "info"
        end
    end)
end

-- log(): a hop that never reached its tier location (500) leaves its stash;
-- a two-level site's grey zone transaction counts for its source; a set
-- decision is logged as a security event.
function _M.log()
    if ngx_var.cdnca_waf_pass ~= nil then
        stash[ngx_var.request_id] = nil
    end
    local txid = ngx_var.cdnca_waf_txid
    if txid and txid ~= "" then
        local ok, err = pcall(record)
        if not ok then ngx.log(ngx.ERR, "cdnca managed waf security event: ", err) end
    end
    if ngx_var.cdnca_waf_repeat_site ~= nil and ngx_var.cdnca_waf_repeat_site ~= "" then
        local ok, err = pcall(adapt.count)
        if not ok then ngx.log(ngx.ERR, "cdnca managed waf grey count: ", err) end
    end
end

-- for tests and benchmarks
_M.tier_key = tier_key
_M.compile = compile
_M._adapt = adapt

return _M
