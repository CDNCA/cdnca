local cjson = require("cjson.safe")
local bit = require("bit")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

local _M = {}

local SCHEMA_VERSION = "cdnca.edge.http-policy/v1"
local COMMIT_SCHEMA_VERSION = "cdnca.edge.http-policy-commit/v1"
local MAX_POLICY_BYTES = 1024 * 1024
local MAX_COMMIT_BYTES = 1024
local MAX_POLICY_VERSION = 9007199254740991
local MAX_SITES = 128
local MAX_ACTIONS = 64
local MAX_VALUES = 16
local MAX_HEADER_VALUE_BYTES = 1024
local MAX_RULES = 128
local MAX_PATH_BYTES = 2048
local MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
local MAX_ORIGINS = 64
local MAX_REWRITE_HOPS = 16
local MAX_REQUEST_HEADERS = 256
local RELOAD_INTERVAL_SECONDS = 0.1

local states = {}

local common_forbidden_headers = {
    connection = true, ["content-length"] = true, host = true, ["keep-alive"] = true,
    ["proxy-authenticate"] = true, ["proxy-authorization"] = true, ["proxy-connection"] = true,
    te = true, trailer = true, ["transfer-encoding"] = true, upgrade = true,
}

local request_forbidden_headers = {
    cookie = true, forwarded = true, origin = true, ["x-forwarded-for"] = true,
    ["x-forwarded-host"] = true, ["x-forwarded-proto"] = true, ["x-real-ip"] = true,
    ["access-control-request-headers"] = true, ["access-control-request-method"] = true,
}

local response_forbidden_headers = { location = true, refresh = true, vary = true }

local function integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum
end

local function only_keys(value, allowed)
    if type(value) ~= "table" then
        return false
    end
    for key, _ in pairs(value) do
        if type(key) ~= "string" or not allowed[key] then
            return false
        end
    end
    return true
end

local function array_length(value, maximum)
    if type(value) ~= "table" then
        return nil
    end
    local count = 0
    local largest = 0
    for key, _ in pairs(value) do
        if type(key) ~= "number" or key < 1 or key ~= math.floor(key) then
            return nil
        end
        count = count + 1
        if key > largest then
            largest = key
        end
    end
    if count ~= largest or count > maximum then
        return nil
    end
    return count
end

local function identifier(value)
    return type(value) == "string" and #value >= 1 and #value <= 128
        and value:match("^[A-Za-z0-9._:-]+$") ~= nil
end

local function token(value)
    return type(value) == "string" and #value >= 1 and #value <= 128
        and value:match("^[!#$%%&'*+.^_`|~0-9A-Za-z-]+$") ~= nil
end

local function safe_header_value(value)
    if type(value) ~= "string" or #value == 0 or #value > MAX_HEADER_VALUE_BYTES then
        return false
    end
    for index = 1, #value do
        local byte = string.byte(value, index)
        if byte < 32 or byte > 126 then
            return false
        end
    end
    return true
end

local function safe_path(value, prefix)
    if type(value) ~= "string" or #value == 0 or #value > MAX_PATH_BYTES or value:sub(1, 1) ~= "/"
        or value:find("[\\%%?#]") or value:find("//", 1, true) then
        return false
    end
    if prefix and value ~= "/" and value:sub(-1) ~= "/" then
        return false
    end
    local checked = prefix and value ~= "/" and value:sub(1, -2) or value
    for segment in checked:gmatch("[^/]+") do
        if segment == "." or segment == ".." then
            return false
        end
    end
    return true
end

local function sorted(previous_a, previous_b, current_a, current_b)
    return previous_a == nil or current_a > previous_a or current_a == previous_a and current_b > previous_b
end

local action_fields = { kind = true, name = true, values = true, allow_duplicate = true }

-- Header value variables (edgeconfig.HeaderVariables).
local VARIABLES = {
    areacode = true, args = true, city = true, country = true, host = true, http_referer = true,
    http_user_agent = true, isp = true, province = true, remote_addr = true, request_method = true,
    request_uri = true, scheme = true, server_port = true, tls_fp = true, uri = true,
}

-- valid_variables(value): every "$" starts "$$" or a VARIABLES name
-- followed by a byte that cannot continue a name ([a-z0-9_]).
local function valid_variables(value)
    local index = 1
    while true do
        local at = value:find("$", index, true)
        if not at then return true end
        if value:sub(at + 1, at + 1) == "$" then
            index = at + 2
        else
            local name = value:match("^[a-z][a-z0-9_]*", at + 1)
            if not name or not VARIABLES[name] then return false end
            index = at + 1 + #name
        end
    end
end

-- Rule conditions (edgeconfig.RuleCondition).
local MAX_CONDITIONS = 8
local condition_fields = { source = true, name = true, pattern = true }
local condition_sources = {
    host = true, user_agent = true, referer = true, country = true, accept_language = true,
    province = true, city = true, isp = true, asn = true, header = true,
}

local function validate_conditions(conditions)
    if conditions == nil then return true end
    local length = array_length(conditions, MAX_CONDITIONS)
    if not length or length == 0 then return false end
    for index = 1, length do
        local condition = conditions[index]
        if not only_keys(condition, condition_fields) or not condition_sources[condition.source]
            or type(condition.pattern) ~= "string" or #condition.pattern == 0 or #condition.pattern > 256
            or condition.pattern:find("[^\32-\126]")
            or (condition.source == "header") ~= (condition.name ~= nil)
            or condition.name ~= nil and (type(condition.name) ~= "string"
                or not condition.name:match("^[a-z0-9][a-z0-9-]*$") or #condition.name > 64) then
            return false
        end
        local _, _, err = ngx.re.find("", condition.pattern, "jo")
        if err then return false end
    end
    return true
end

local function validate_actions(actions, request)
    local length = array_length(actions, MAX_ACTIONS)
    if length == nil then
        return false
    end
    local previous_name
    for index = 1, length do
        local action = actions[index]
        if not only_keys(action, action_fields) or not token(action.name) or action.name ~= string.lower(action.name)
            or common_forbidden_headers[action.name] or action.name:sub(1, 9) == "x-cdnca-"
            or previous_name and action.name <= previous_name then
            return false
        end
        if request then
            if request_forbidden_headers[action.name] or action.name:sub(1, 15) == "access-control-" then
                return false
            end
        elseif response_forbidden_headers[action.name] or action.name:sub(1, 15) == "access-control-" then
            return false
        end
        if action.allow_duplicate ~= nil and (type(action.allow_duplicate) ~= "boolean" or action.kind ~= "add") then
            return false
        end
        local value_count = array_length(action.values, MAX_VALUES)
        if action.kind == "delete" then
            if value_count ~= 0 then
                return false
            end
        elseif action.kind == "add" or action.kind == "set" then
            if not value_count or value_count == 0 then
                return false
            end
            for value_index = 1, value_count do
                if not safe_header_value(action.values[value_index]) or not valid_variables(action.values[value_index]) then
                    return false
                end
            end
        else
            return false
        end
        previous_name = action.name
    end
    return true
end

local rewrite_fields = {
    rule_id = true, priority = true, match_kind = true, match_path = true, target_path = true,
    preserve_query = true, preserve_cookie = true, conditions = true,
}

local redirect_fields = {
    rule_id = true, priority = true, match_kind = true, match_path = true, status = true,
    target_url = true, preserve_query = true, preserve_path = true, conditions = true,
}

local MAX_REGEX_BYTES = 512

-- A regex rule's pattern: anchored at the path start, printable ASCII, and
-- compilable here (the agent checked it is RE2 with at most 9 groups).
local function valid_regex(pattern)
    if type(pattern) ~= "string" or #pattern < 2 or #pattern > MAX_REGEX_BYTES or pattern:sub(1, 2) ~= "^/"
        or pattern:find("[^\32-\126]") then
        return false
    end
    local _, _, err = ngx.re.find("/", pattern, "jo")
    return err == nil
end

-- A regex rule's target: an absolute path template, "$" only as $1..$9.
local function valid_regex_target(value)
    if type(value) ~= "string" or #value == 0 or #value > MAX_PATH_BYTES or value:sub(1, 1) ~= "/"
        or value:find("[\\%%?#]") or value:find("//", 1, true) or value:find("[^\32-\126]") then
        return false
    end
    if value:gsub("%$[1-9]", ""):find("$", 1, true) then
        return false
    end
    for segment in value:gmatch("[^/]+") do
        if segment == "." or segment == ".." then
            return false
        end
    end
    return true
end

local function validate_match(kind, path)
    if kind == "regex" then
        return valid_regex(path)
    end
    return (kind == "exact" or kind == "prefix") and safe_path(path, kind == "prefix")
end

local function validate_rewrites(rules)
    local length = array_length(rules, MAX_RULES)
    if length == nil then
        return false
    end
    local ids = {}
    local prior_priority
    local prior_id
    for index = 1, length do
        local rule = rules[index]
        if not only_keys(rule, rewrite_fields) or not identifier(rule.rule_id) or ids[rule.rule_id]
            or not integer(rule.priority, 0, 4294967295) or not validate_match(rule.match_kind, rule.match_path)
            or rule.match_kind == "regex" and not valid_regex_target(rule.target_path)
            or rule.match_kind ~= "regex" and (not safe_path(rule.target_path, rule.match_kind == "prefix")
                or rule.match_path == rule.target_path)
            or type(rule.preserve_query) ~= "boolean" or type(rule.preserve_cookie) ~= "boolean"
            or not validate_conditions(rule.conditions)
            or not sorted(prior_priority, prior_id, rule.priority, rule.rule_id) then
            return false
        end
        ids[rule.rule_id] = true
        prior_priority = rule.priority
        prior_id = rule.rule_id
    end
    return true
end

local function validate_authority(value)
    if type(value) ~= "string" or #value == 0 or #value > 512 or value ~= string.lower(value)
        or value:find("[%c%s/\\?#@]") then
        return false
    end
    if value:sub(1, 1) == "[" then
        local closing = value:find("]", 2, true)
        if not closing then
            return false
        end
        local host = value:sub(2, closing - 1)
        local suffix = value:sub(closing + 1)
        if host == "" or not host:find(":", 1, true) or host:find("[^0-9a-f:]") then
            return false
        end
        if suffix == "" then
            return true
        end
        local port = suffix:match("^:([1-9][0-9]*)$")
        return port ~= nil and tonumber(port) <= 65535
    end
    local host, port = value:match("^(.-):([1-9][0-9]*)$")
    if not host then
        host = value
    end
    if host == "" or host:find("[^a-z0-9.-]") or (port and tonumber(port) > 65535) then
        return false
    end
    return true
end

-- redirect_parts is the target URL's authority, its path checked as kind:
-- "exact" (fixed), "prefix" (a directory the kept suffix joins) or "regex".
local function redirect_parts(value, kind)
    if type(value) ~= "string" or #value == 0 or #value > 4096 or value:find("[%c%s\\]") then
        return nil
    end
    local scheme, remainder = value:match("^([a-z]+)://(.+)$")
    local authority
    local path
    if remainder then
        authority, path = remainder:match("^([^/]+)(/.*)$")
    end
    local path_ok
    if kind == "regex" then
        path_ok = valid_regex_target(path)
    else
        path_ok = safe_path(path, kind == "prefix")
    end
    if (scheme ~= "http" and scheme ~= "https") or not authority
        or not validate_authority(authority) or not path_ok then
        return nil
    end
    return authority
end

local function validate_redirects(rules, authorities)
    local length = array_length(rules, MAX_RULES)
    if length == nil then
        return false
    end
    local allowed = {}
    for _, authority in ipairs(authorities) do
        allowed[authority] = true
    end
    local ids = {}
    local prior_priority
    local prior_id
    for index = 1, length do
        local rule = rules[index]
        local target_kind = "exact"
        if type(rule) == "table" and rule.match_kind == "regex" then
            target_kind = "regex"
        elseif type(rule) == "table" and rule.preserve_path == true then
            target_kind = "prefix"
        end
        local authority = type(rule) == "table" and redirect_parts(rule.target_url, target_kind) or nil
        if not only_keys(rule, redirect_fields) or not identifier(rule.rule_id) or ids[rule.rule_id]
            or not integer(rule.priority, 0, 4294967295) or not validate_match(rule.match_kind, rule.match_path)
            or (rule.status ~= 301 and rule.status ~= 302 and rule.status ~= 307 and rule.status ~= 308)
            or not authority or not allowed[authority] or type(rule.preserve_query) ~= "boolean"
            or type(rule.preserve_path) ~= "boolean" or rule.preserve_path and rule.match_kind ~= "prefix"
            or not validate_conditions(rule.conditions)
            or not sorted(prior_priority, prior_id, rule.priority, rule.rule_id) then
            return false
        end
        ids[rule.rule_id] = true
        prior_priority = rule.priority
        prior_id = rule.rule_id
    end
    return true
end

local cors_fields = {
    allowed_origins = true, allowed_methods = true, allowed_headers = true, exposed_headers = true,
    allow_credentials = true, max_age_seconds = true,
}

local function validate_sorted_strings(values, maximum, validator)
    local length = array_length(values, maximum)
    if length == nil then
        return false
    end
    local previous
    for index = 1, length do
        local value = values[index]
        if not validator(value) or previous and value <= previous then
            return false
        end
        previous = value
    end
    return true
end

local function valid_origin(value)
    if value == "*" then
        return true
    end
    if type(value) ~= "string" or value ~= string.lower(value) or value:find("[%c%s\\/?#@]", 9) then
        return false
    end
    local scheme, authority = value:match("^([a-z]+)://(.+)$")
    return (scheme == "http" or scheme == "https") and validate_authority(authority)
end

local function validate_cors(cors)
    if cors == nil then
        return true
    end
    if not only_keys(cors, cors_fields)
        or not validate_sorted_strings(cors.allowed_origins, MAX_ORIGINS, valid_origin) or #cors.allowed_origins == 0
        or not validate_sorted_strings(cors.allowed_methods, MAX_ORIGINS, function(value)
            return token(value) and value == string.upper(value)
        end)
        or #cors.allowed_methods == 0
        or not validate_sorted_strings(cors.allowed_headers, MAX_ORIGINS, function(value)
            return value == "*" or token(value) and value == string.lower(value)
        end)
        or not validate_sorted_strings(cors.exposed_headers, MAX_ORIGINS, function(value)
            return value == "*" or token(value) and value == string.lower(value)
        end)
        or type(cors.allow_credentials) ~= "boolean" or not integer(cors.max_age_seconds, 0, 86400) then
        return false
    end
    if cors.allowed_origins[1] == "*" and #cors.allowed_origins ~= 1 then
        return false
    end
    if cors.allow_credentials and (cors.allowed_origins[1] == "*" or cors.allowed_headers[1] == "*" or cors.exposed_headers[1] == "*") then
        return false
    end
    return true
end

local referer_fields = {
    allow_empty = true, allow_same_domain = true, allowed_domains = true, denied_domains = true,
    check_origin = true, extensions = true,
}

local function valid_hostname(value)
    if type(value) ~= "string" or #value < 1 or #value > 253 or value:sub(-1) == "." then
        return false
    end
    for label in (value .. "."):gmatch("([^.]*)%.") do
        if #label < 1 or #label > 63 or not label:match("^[a-z0-9]$") and not label:match("^[a-z0-9][a-z0-9-]*[a-z0-9]$") then
            return false
        end
    end
    return true
end

local function valid_referer_domain(value)
    if type(value) ~= "string" then
        return false
    end
    if value:sub(1, 2) == "*." then
        local host = value:sub(3)
        return host:find(".", 1, true) ~= nil and valid_hostname(host)
    end
    return valid_hostname(value)
end

-- validate_referer_check mirrors the agent normalizeRefererCheck (sorted,
-- disjoint domain lists, something restricted, sorted extensions).
local function validate_referer_check(check)
    if check == nil then
        return true
    end
    if not only_keys(check, referer_fields) or type(check.allow_empty) ~= "boolean"
        or type(check.allow_same_domain) ~= "boolean" or type(check.check_origin) ~= "boolean"
        or not validate_sorted_strings(check.allowed_domains, 64, valid_referer_domain)
        or not validate_sorted_strings(check.denied_domains, 64, valid_referer_domain)
        or not validate_sorted_strings(check.extensions, 32, function(value)
            return type(value) == "string" and value:match("^[a-z0-9]+$") ~= nil and #value <= 16
        end) then
        return false
    end
    local allowed = {}
    for _, domain in ipairs(check.allowed_domains) do allowed[domain] = true end
    for _, domain in ipairs(check.denied_domains) do
        if allowed[domain] then return false end
    end
    return check.allow_same_domain or #check.allowed_domains > 0 or #check.denied_domains > 0
end

local site_fields = {
    site_id = true, max_upload_bytes = true, request_headers = true, response_headers = true,
    rewrites = true, redirect_allowed_hosts = true, redirects = true, cors = true, referer_check = true,
}

local function validate_site(site)
    -- The agent publishes a site without CORS as "cors":null; cjson decodes it
    -- to cjson.null, which would otherwise read as a malformed CORS object.
    if type(site) == "table" and site.cors == cjson.null then site.cors = nil end
    if type(site) == "table" and site.referer_check == cjson.null then site.referer_check = nil end
    if not only_keys(site, site_fields) or not identifier(site.site_id)
        or not integer(site.max_upload_bytes, 1, MAX_UPLOAD_BYTES)
        or not validate_actions(site.request_headers, true) or not validate_actions(site.response_headers, false)
        or not validate_rewrites(site.rewrites)
        or not validate_sorted_strings(site.redirect_allowed_hosts, MAX_ORIGINS, validate_authority)
        or not validate_redirects(site.redirects, site.redirect_allowed_hosts) or not validate_cors(site.cors)
        or not validate_referer_check(site.referer_check) then
        return false
    end
    return true
end

local function site_validation_reason(site)
    if not only_keys(site, site_fields) then return "site_envelope" end
    if not identifier(site.site_id) then return "site_id" end
    if not integer(site.max_upload_bytes, 1, MAX_UPLOAD_BYTES) then return "max_upload_bytes" end
    if not validate_actions(site.request_headers, true) then return "request_headers" end
    if not validate_actions(site.response_headers, false) then return "response_headers" end
    if not validate_rewrites(site.rewrites) then return "rewrites" end
    if not validate_sorted_strings(site.redirect_allowed_hosts, MAX_ORIGINS, validate_authority) then
        return "redirect_allowed_hosts"
    end
    if not validate_redirects(site.redirects, site.redirect_allowed_hosts) then return "redirects" end
    if not validate_cors(site.cors) then return "cors" end
    if not validate_referer_check(site.referer_check) then return "referer_check" end
    return "unknown"
end

local policy_fields = { schema_version = true, policy_version = true, sites = true }

local function validate_policy(policy)
    if not only_keys(policy, policy_fields) or policy.schema_version ~= SCHEMA_VERSION
        or not integer(policy.policy_version, 1, MAX_POLICY_VERSION) then
        return nil, "policy_envelope"
    end
    local length = array_length(policy.sites, MAX_SITES)
    if not length or length == 0 then
        return nil, "sites"
    end
    local site_map = {}
    local previous
    for index = 1, length do
        local site = policy.sites[index]
        if not validate_site(site) or site_map[site.site_id] or previous and site.site_id <= previous then
            return nil, "site_" .. tostring(index) .. "_" .. site_validation_reason(site)
        end
        site_map[site.site_id] = site
        previous = site.site_id
    end
    return site_map, nil
end

local function read_bounded(path, maximum)
    local file = io.open(path, "rb")
    if not file then
        return nil
    end
    local raw = file:read(maximum + 1)
    file:close()
    if not raw or #raw == 0 or #raw > maximum then
        return nil
    end
    return raw
end

local function sha256_hex(value)
    local digest = resty_sha256:new()
    if not digest or not digest:update(value) then
        return nil
    end
    local final = digest:final()
    if not final then
        return nil
    end
    return resty_string.to_hex(final)
end

local function read_candidate(path)
    local raw = read_bounded(path, MAX_POLICY_BYTES)
    if not raw then
        return nil, "artifact_read"
    end
    local policy = cjson.decode(raw)
    local site_map, validation_error
    if policy then
        site_map, validation_error = validate_policy(policy)
    else
        validation_error = "json"
    end
    if not site_map then
        return nil, "artifact_" .. validation_error
    end
    local digest = sha256_hex(raw)
    if not digest then
        return nil, "artifact_digest"
    end
    return { policy = policy, sites = site_map, digest = digest }, nil
end

local commit_fields = {
    schema_version = true, policy_version = true, sha256 = true, artifact = true,
}

local function read_committed(state_root)
    local raw = read_bounded(state_root .. "/committed.json", MAX_COMMIT_BYTES)
    if not raw then
        return nil, "commit_read"
    end
    local manifest = cjson.decode(raw)
    if not only_keys(manifest, commit_fields)
        or manifest.schema_version ~= COMMIT_SCHEMA_VERSION
        or not integer(manifest.policy_version, 1, MAX_POLICY_VERSION)
        or type(manifest.sha256) ~= "string" or #manifest.sha256 ~= 64
        or manifest.sha256 ~= string.lower(manifest.sha256)
        or not manifest.sha256:match("^[0-9a-f]+$") then
        return nil, "commit_envelope"
    end
    local artifact = "versions/" .. string.format("%020d.json", manifest.policy_version)
    if manifest.artifact ~= artifact then
        return nil, "commit_artifact"
    end
    local candidate, candidate_error = read_candidate(state_root .. "/" .. artifact)
    if not candidate then
        return nil, candidate_error
    end
    if candidate.policy.policy_version ~= manifest.policy_version or candidate.digest ~= manifest.sha256 then
        return nil, "commit_mismatch"
    end
    return candidate, nil
end

local function reload(options)
    local key = options.state_root
    local state = states[key]
    if not state then
        state = { next_check = 0 }
        states[key] = state
    end
    local now = ngx.now()
    if now < state.next_check then
        return state
    end
    state.next_check = now + RELOAD_INTERVAL_SECONDS
    local candidate, candidate_error = read_committed(options.state_root)
    if not candidate then
        if state.policy then
            ngx.log(ngx.ERR, "HTTP policy commit rejected reason=", candidate_error,
                "; retaining LKG version=", state.policy.policy_version)
        else
            ngx.log(ngx.ERR, "HTTP policy commit rejected reason=", candidate_error)
        end
        return state
    end
    if state.policy and candidate.policy.policy_version < state.policy.policy_version then
        ngx.log(ngx.ERR, "HTTP policy rollback rejected; retaining version=", state.policy.policy_version)
        return state
    end
    if state.policy and candidate.policy.policy_version == state.policy.policy_version and candidate.digest ~= state.digest then
        ngx.log(ngx.ERR, "HTTP policy same-version mutation rejected; retaining version=", state.policy.policy_version)
        return state
    end
    if not state.policy or candidate.policy.policy_version > state.policy.policy_version then
        state.policy = candidate.policy
        state.sites = candidate.sites
        state.digest = candidate.digest
        ngx.log(ngx.NOTICE, "HTTP policy activated version=", state.policy.policy_version)
    end
    return state
end

local function plain_reject(status, body)
    ngx.status = status
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(body)
    return ngx.exit(status)
end

local function valid_percent_encoding(value)
    local index = 1
    while true do
        local found = value:find("%", index, true)
        if not found then
            return true
        end
        if not value:sub(found + 1, found + 2):match("^[0-9A-Fa-f][0-9A-Fa-f]$") then
            return false
        end
        index = found + 3
    end
end

local function has_control(value)
    for index = 1, #value do
        local byte = string.byte(value, index)
        if byte < 32 or byte == 127 then
            return true
        end
    end
    return false
end

local function unsafe_decoded_path(value)
    if has_control(value) or value:find("\\", 1, true) or value:find("//", 1, true) then
        return true
    end
    for segment in value:gmatch("[^/]+") do
        if segment == "." or segment == ".." then
            return true
        end
    end
    return false
end

local function safe_request_target()
    local raw = ngx.var.request_uri or ""
    if #raw == 0 or #raw > 16384 or has_control(raw) then
        return false
    end
    local question = raw:find("?", 1, true)
    local raw_path = question and raw:sub(1, question - 1) or raw
    local raw_query = question and raw:sub(question + 1) or ""
    if not valid_percent_encoding(raw_path) or not valid_percent_encoding(raw_query) then
        return false
    end
    local path_once = ngx.unescape_uri(raw_path)
    local path_twice = ngx.unescape_uri(path_once)
    if unsafe_decoded_path(path_once) or unsafe_decoded_path(path_twice) then
        return false
    end
    local query_once = ngx.unescape_uri(raw_query)
    local query_twice = ngx.unescape_uri(query_once)
    if has_control(query_once) or has_control(query_twice)
        or query_once:find("../", 1, true) or query_once:find("..\\", 1, true)
        or query_twice:find("../", 1, true) or query_twice:find("..\\", 1, true) then
        return false
    end
    return true
end

local function request_body_size()
    local content_length = ngx.var.content_length
    if content_length then
        local length = tonumber(content_length)
        if not length or length < 0 or length ~= math.floor(length) then
            return nil, "invalid Content-Length"
        end
    end
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if data then
        return #data
    end
    local path = ngx.req.get_body_file()
    if not path then
        return 0
    end
    local file = io.open(path, "rb")
    if not file then
        return nil, "request body file is unavailable"
    end
    local size = file:seek("end")
    file:close()
    if not size then
        return nil, "request body size is unavailable"
    end
    return size
end

-- IP library attributes of the client (cdnca_iplib, absent: none).
local CARRIER_TAGS = { { 1, "telecom" }, { 2, "unicom" }, { 4, "mobile" } }
local function client_intel()
    local cached = ngx.ctx.cdnca_http_policy_intel
    if cached ~= nil then return cached end
    local intel = false
    local ok, iplib = pcall(require, "cdnca_iplib")
    local attrs = ok and iplib.lookup(ngx.var.binary_remote_addr) or nil
    if attrs then
        local isp = ""
        for _, entry in ipairs(CARRIER_TAGS) do
            if bit.band(attrs.tags_lo, entry[1]) ~= 0 then
                if isp ~= "" then isp = "" break end
                isp = entry[2]
            end
        end
        local province = tonumber(attrs.province) or 0
        intel = {
            country = attrs.country or "", isp = isp, asn = attrs.asn and attrs.asn ~= 0 and tostring(attrs.asn) or "",
            province = province ~= 0 and tostring(province) or "",
            city = attrs.city and attrs.city ~= 0 and tostring(attrs.city) or "",
            areacode = province ~= 0 and tostring(province - province % 10000) or "",
        }
    end
    ngx.ctx.cdnca_http_policy_intel = intel
    return intel
end

local function intel_value(name)
    local intel = client_intel()
    return intel and intel[name] or ""
end

local function first_header(name)
    local value = ngx.req.get_headers(MAX_REQUEST_HEADERS)[name]
    if type(value) == "table" then
        return table.concat(value, ", ")
    end
    return value or ""
end

local function condition_value(condition)
    local source = condition.source
    if source == "host" then return ngx.var.http_host or "" end
    if source == "user_agent" then return first_header("user-agent") end
    if source == "referer" then return first_header("referer") end
    if source == "accept_language" then return first_header("accept-language") end
    if source == "header" then return first_header(condition.name) end
    return intel_value(source) -- country, province, city, isp, asn
end

local function conditions_match(conditions)
    if not conditions then return true end
    for _, condition in ipairs(conditions) do
        local from, _, err = ngx.re.find(condition_value(condition), condition.pattern, "jo")
        if err then
            ngx.log(ngx.ERR, "HTTP policy rule condition not evaluated: ", err)
            return false
        end
        if not from then return false end
    end
    return true
end

-- rule_matches reports whether rule matches path (and its conditions); a
-- regex rule also returns its captures (a failed or over-limit match is no
-- match, logged).
local function rule_matches(rule, path)
    if rule.conditions and not conditions_match(rule.conditions) then
        return false
    end
    if rule.match_kind == "regex" then
        local captures, err = ngx.re.match(path, rule.match_path, "jo")
        if err then
            ngx.log(ngx.ERR, "HTTP policy regex rule ", rule.rule_id, " not evaluated: ", err)
            return false
        end
        return captures ~= nil, captures
    end
    if rule.match_kind == "exact" then
        return path == rule.match_path
    end
    if rule.match_path == "/" then
        return true
    end
    return path:sub(1, #rule.match_path) == rule.match_path
end

-- expand fills $1..$9 of template from captures, each passed through escape.
local function expand(template, captures, escape)
    return (template:gsub("%$([1-9])", function(digit)
        local value = captures and captures[tonumber(digit)]
        if type(value) ~= "string" then
            return ""
        end
        return escape and escape(value) or value
    end))
end

-- location_escape percent-encodes what a Location path must not carry raw
-- (the decoded request path may hold spaces or non-ASCII bytes).
local function location_escape(value)
    return (value:gsub("[^%w%-%._~/!$&'()*+,;=:@]", function(character)
        return string.format("%%%02X", string.byte(character))
    end))
end

local function rewrite_target(rule, path, captures)
    if rule.match_kind == "regex" then
        return expand(rule.target_path, captures)
    end
    if rule.match_kind == "exact" then
        return rule.target_path
    end
    if rule.match_path == "/" then
        return rule.target_path .. path:sub(2)
    end
    return rule.target_path .. path:sub(#rule.match_path + 1)
end

local function apply_rewrites(site)
    local current = ngx.var.uri or "/"
    local visited = { [current] = true }
    for _ = 1, MAX_REWRITE_HOPS do
        local matched
        local captures
        for _, rule in ipairs(site.rewrites) do
            local hit, groups = rule_matches(rule, current)
            if hit then
                matched, captures = rule, groups
                break
            end
        end
        if not matched then
            if current ~= ngx.var.uri then
                ngx.req.set_uri(current, false)
            end
            return current
        end
        if not matched.preserve_query then
            ngx.req.set_uri_args({})
        end
        if not matched.preserve_cookie then
            ngx.req.clear_header("Cookie")
        end
        current = rewrite_target(matched, current, captures)
        if current:sub(1, 1) ~= "/" or has_control(current) then
            return nil, "rewrite produced an invalid path"
        end
        if visited[current] then
            return nil, "rewrite loop"
        end
        visited[current] = true
    end
    for _, rule in ipairs(site.rewrites) do
        if rule_matches(rule, current) then
            return nil, "rewrite hop limit"
        end
    end
    if current ~= ngx.var.uri then
        ngx.req.set_uri(current, false)
    end
    return current
end

local function values_list(value)
    if value == nil then
        return {}
    end
    if type(value) == "table" then
        local result = {}
        for index = 1, #value do
            result[#result + 1] = value[index]
        end
        return result
    end
    return { value }
end

local function request_header_values(name)
    local headers, err = ngx.req.get_headers(MAX_REQUEST_HEADERS)
    if err == "truncated" then
        return nil
    end
    local result = {}
    for key, value in pairs(headers) do
        if string.lower(key) == name then
            for _, item in ipairs(values_list(value)) do
                result[#result + 1] = item
            end
        end
    end
    return result
end

-- variable_value(name): a header variable's request value (VARIABLES).
local function variable_value(name)
    if name == "tls_fp" then
        local ok, value = pcall(function() return ngx.var.cdnca_ja4 end)
        return ok and value or ""
    end
    if name == "country" or name == "province" or name == "city" or name == "isp" or name == "areacode" then
        return intel_value(name)
    end
    return ngx.var[name] or ""
end

-- expand_value(value): $name replaced by its request value, "$$" by "$";
-- the result keeps printable ASCII only (no CR/LF: no header injection) and
-- at most MAX_HEADER_VALUE_BYTES. A value without "$" is returned as is.
local function expand_value(value)
    if not value:find("$", 1, true) then
        return value
    end
    local parts, index = {}, 1
    while true do
        local at = value:find("$", index, true)
        if not at then
            parts[#parts + 1] = value:sub(index)
            break
        end
        parts[#parts + 1] = value:sub(index, at - 1)
        if value:sub(at + 1, at + 1) == "$" then
            parts[#parts + 1] = "$"
            index = at + 2
        else
            -- validated: the whole name run is a VARIABLES name
            local name = value:match("^[a-z][a-z0-9_]*", at + 1) or ""
            parts[#parts + 1] = VARIABLES[name] and tostring(variable_value(name)) or ""
            index = at + 1 + #name
        end
    end
    local out = table.concat(parts):gsub("[^\32-\126]", "")
    if #out > MAX_HEADER_VALUE_BYTES then
        out = out:sub(1, MAX_HEADER_VALUE_BYTES)
    end
    return out
end

local function expand_values(values)
    local result = {}
    for _, value in ipairs(values) do
        local expanded = expand_value(value)
        if expanded ~= "" then
            result[#result + 1] = expanded
        end
    end
    return result
end

local function apply_request_headers(actions)
    for _, action in ipairs(actions) do
        if action.kind == "delete" then
            ngx.req.clear_header(action.name)
        else
            local added = expand_values(action.values)
            if action.kind == "set" then
                if #added > 0 then
                    ngx.req.set_header(action.name, added)
                else
                    ngx.req.clear_header(action.name)
                end
            elseif #added > 0 then
                local values = request_header_values(action.name)
                if not values then
                    return false
                end
                -- 允许重复 off: add only when the header is absent
                if #values == 0 or action.allow_duplicate then
                    for _, value in ipairs(added) do
                        values[#values + 1] = value
                    end
                    ngx.req.set_header(action.name, values)
                end
            end
        end
    end
    return true
end

local function normalize_request_origin(value)
    if type(value) ~= "string" or value:find("[%c%s\\/?#@]", 9) then
        return nil
    end
    local scheme, authority = value:match("^([A-Za-z]+)://(.+)$")
    if (string.lower(scheme or "") ~= "http" and string.lower(scheme or "") ~= "https")
        or not authority or not validate_authority(string.lower(authority)) then
        return nil
    end
    return string.lower(scheme) .. "://" .. string.lower(authority)
end

local function origin_allowed(cors, origin)
    local normalized = normalize_request_origin(origin)
    if not normalized then
        return nil
    end
    if cors.allowed_origins[1] == "*" then
        return "*"
    end
    for _, allowed in ipairs(cors.allowed_origins) do
        if allowed == normalized then
            return normalized
        end
    end
    return nil
end

local function list_contains(values, target)
    for _, value in ipairs(values) do
        if value == target then
            return true
        end
    end
    return false
end

local function requested_headers_allowed(cors, value)
    if not value or value == "" then
        return true
    end
    if cors.allowed_headers[1] == "*" then
        return true
    end
    local count = 0
    for raw in (value .. ","):gmatch("(.-),") do
        local header = raw:match("^[ \t]*(.-)[ \t]*$")
        count = count + 1
        if count > MAX_ORIGINS or not token(header) or not list_contains(cors.allowed_headers, string.lower(header)) then
            return false
        end
    end
    return true
end

local function configure_cors(site)
    if not site.cors then
        return true
    end
    local origin = ngx.var.http_origin
    local requested_method = ngx.var.http_access_control_request_method
    local preflight = ngx.req.get_method() == "OPTIONS" and requested_method ~= nil
    if not origin then
        if preflight then
            return false
        end
        return true
    end
    local allowed_origin = origin_allowed(site.cors, origin)
    if not allowed_origin then
        return not preflight
    end
    ngx.ctx.cdnca_http_cors_origin = allowed_origin
    if preflight then
        local method = string.upper(requested_method)
        if not token(method) or not list_contains(site.cors.allowed_methods, method)
            or not requested_headers_allowed(site.cors, ngx.var.http_access_control_request_headers) then
            return false
        end
        ngx.ctx.cdnca_http_cors_preflight = true
    end
    return true
end

-- referer_host returns the lower-case host of a Referer / Origin value, or
-- nil when it is not an absolute URL with a host.
local function referer_host(value)
    local authority = value:match("^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)")
    if not authority then
        return nil
    end
    authority = authority:gsub("^.*@", "")
    local host = authority:match("^%[([^%]]+)%]") or authority:match("^([^:]+)")
    if not host or host == "" then
        return nil
    end
    return string.lower(host)
end

local function referer_domain_matches(domains, host)
    for _, domain in ipairs(domains) do
        if domain == host then
            return true
        end
        if domain:sub(1, 2) == "*." then
            local suffix = domain:sub(2)
            if #host > #suffix and host:sub(-#suffix) == suffix then
                return true
            end
        end
    end
    return false
end

-- referer_allowed applies hotlink protection (防盗链): deny list first, then
-- same domain / allow list; a check that only denies lets other sources pass.
local function referer_allowed(check)
    if #check.extensions > 0 then
        local extension = (ngx.var.uri or ""):match("%.([A-Za-z0-9]+)$")
        local matched = false
        if extension then
            extension = string.lower(extension)
            for _, value in ipairs(check.extensions) do
                if value == extension then matched = true break end
            end
        end
        if not matched then
            return true
        end
    end
    local source = ngx.var.http_referer
    if (source == nil or source == "") and check.check_origin then
        source = ngx.var.http_origin
        if source == "null" then source = nil end
    end
    if type(source) == "table" then
        return false
    end
    if source == nil or source == "" then
        return check.allow_empty
    end
    local host = referer_host(source)
    if not host or referer_domain_matches(check.denied_domains, host) then
        return false
    end
    if check.allow_same_domain and host == string.lower(ngx.var.host or "") then
        return true
    end
    if referer_domain_matches(check.allowed_domains, host) then
        return true
    end
    return not check.allow_same_domain and #check.allowed_domains == 0
end

local function perform_redirects(site, path)
    for _, rule in ipairs(site.redirects) do
        local hit, captures = rule_matches(rule, path)
        if hit then
            local location = rule.target_url
            if rule.match_kind == "regex" then
                local authority_end = location:find("/", location:find("://", 1, true) + 3, true)
                location = location:sub(1, authority_end - 1) .. expand(location:sub(authority_end), captures, location_escape)
            elseif rule.preserve_path then
                -- The target directory ends with "/", the kept suffix after
                -- the matched prefix does not start with one.
                local suffix = rule.match_path == "/" and path:sub(2) or path:sub(#rule.match_path + 1)
                location = location .. location_escape(suffix)
            end
            local args = ngx.var.args
            if rule.preserve_query and args and args ~= "" then
                location = location .. "?" .. args
            end
            ngx.header["Location"] = location
            ngx.header["Cache-Control"] = "no-store"
            return ngx.exit(rule.status)
        end
    end
end

local function apply_response_headers(actions)
    for _, action in ipairs(actions) do
        if action.kind == "delete" then
            ngx.header[action.name] = nil
        else
            local added = expand_values(action.values)
            if action.kind == "set" then
                ngx.header[action.name] = #added > 0 and added or nil
            elseif #added > 0 then
                local values = values_list(ngx.header[action.name])
                -- 允许重复 off: add only when the header is absent
                if #values == 0 or action.allow_duplicate then
                    for _, value in ipairs(added) do
                        values[#values + 1] = value
                    end
                    ngx.header[action.name] = values
                end
            end
        end
    end
end

local function add_vary(name)
    local values = values_list(ngx.header["Vary"])
    for _, line in ipairs(values) do
        for value in (line .. ","):gmatch("(.-),") do
            if string.lower(value:match("^[ \t]*(.-)[ \t]*$")) == string.lower(name) then
                return
            end
        end
    end
    values[#values + 1] = name
    ngx.header["Vary"] = values
end

local function apply_cors_headers(site)
    local origin = ngx.ctx.cdnca_http_cors_origin
    if not origin or not site.cors then
        return
    end
    ngx.header["Access-Control-Allow-Origin"] = origin
    if origin ~= "*" then
        add_vary("Origin")
    end
    if site.cors.allow_credentials then
        ngx.header["Access-Control-Allow-Credentials"] = "true"
    end
    if #site.cors.exposed_headers > 0 then
        ngx.header["Access-Control-Expose-Headers"] = table.concat(site.cors.exposed_headers, ", ")
    end
    if ngx.ctx.cdnca_http_cors_preflight then
        ngx.header["Access-Control-Allow-Methods"] = table.concat(site.cors.allowed_methods, ", ")
        ngx.header["Access-Control-Allow-Headers"] = table.concat(site.cors.allowed_headers, ", ")
        ngx.header["Access-Control-Max-Age"] = tostring(site.cors.max_age_seconds)
        add_vary("Access-Control-Request-Method")
        add_vary("Access-Control-Request-Headers")
    end
end

local function validate_options(options)
    if not only_keys(options, { state_root = true, site_id = true }) or not identifier(options.site_id) then
        return false
    end
    local root = options.state_root
    return type(root) == "string" and #root > 1 and #root <= 4096 and root:sub(1, 1) == "/"
        and root:sub(-1) ~= "/" and not root:find("[%c\\]") and not root:find("//", 1, true)
        and not root:find("/./", 1, true) and not root:find("/../", 1, true)
        and root:sub(-2) ~= "/." and root:sub(-3) ~= "/.."
end

local enforce

function _M.access(options)
    if not validate_options(options) then
        return plain_reject(503, "HTTP policy unavailable")
    end
    local state = reload(options)
    local site = state.sites and state.sites[options.site_id] or nil
    if not state.policy or not site then
        return plain_reject(503, "HTTP policy unavailable")
    end
    return enforce(site, state.policy.policy_version)
end

-- Dynamic routing (ADR 0009, D7): the site object references its own entry
-- of the scope's HTTP policy snapshot (edgesite Ref kind http_policy, the
-- entry's bytes in the node object directory). Entries are cached per worker
-- by digest; the digest is the identity, so they never need invalidation.
local object_sites = require("resty.lrucache").new(10000)

-- configure_objects(items): the per-worker entry cache size (default 10000;
-- a node with more sites sizes it to its hot set).
function _M.configure_objects(items)
    if not integer(items, 1, 10000000) then error("invalid HTTP policy object cache size") end
    object_sites = require("resty.lrucache").new(items)
end

local function object_site(digest, read, site_id)
    local site = object_sites:get(digest)
    if site then return site end
    local raw, read_error = read(digest)
    if not raw then return nil, "read: " .. tostring(read_error) end
    if #raw == 0 or #raw > MAX_POLICY_BYTES or sha256_hex(raw) ~= digest then return nil, "digest" end
    site = cjson.decode(raw)
    if type(site) ~= "table" or not validate_site(site) then
        return nil, "site_" .. (type(site) == "table" and site_validation_reason(site) or "json")
    end
    if site.site_id ~= site_id then return nil, "site_id" end
    object_sites:set(digest, site)
    return site
end

-- access_object(ref, read, site_id): ref is the site object's http_policy
-- reference ({ sha256, revision }); the response header reports its revision
-- (v7 reports the scope snapshot version, which a site object does not carry).
function _M.access_object(ref, read, site_id)
    local site, site_error = object_site(type(ref) == "table" and ref.sha256 or nil, read, site_id)
    if not site or not integer(ref.revision, 1, MAX_POLICY_VERSION) then
        ngx.log(ngx.ERR, "HTTP policy object rejected reason=", tostring(site_error or "revision"))
        return plain_reject(503, "HTTP policy unavailable")
    end
    return enforce(site, ref.revision)
end

enforce = function(site, version)
    ngx.ctx.cdnca_http_policy_site = site
    ngx.ctx.cdnca_http_policy_version = version
    if not safe_request_target() then
        return plain_reject(400, "Invalid request target")
    end
    if site.referer_check and not referer_allowed(site.referer_check) then
        ngx.header["X-Cdnca-Referer-Check"] = "rejected"
        return plain_reject(403, "Hotlink rejected")
    end
    if not configure_cors(site) then
        return plain_reject(403, "CORS preflight rejected")
    end
    if ngx.ctx.cdnca_http_cors_preflight then
        ngx.status = 204
        return ngx.exit(204)
    end
    local declared = ngx.var.content_length and tonumber(ngx.var.content_length) or 0
    if declared and declared > site.max_upload_bytes then
        return plain_reject(413, "Request body too large")
    end
    local body_size, body_error = request_body_size()
    if not body_size then
        ngx.log(ngx.ERR, "HTTP policy request body rejected: ", body_error)
        return plain_reject(400, "Invalid request body")
    end
    if body_size > site.max_upload_bytes then
        return plain_reject(413, "Request body too large")
    end
    local rewritten, rewrite_error = apply_rewrites(site)
    if not rewritten then
        ngx.log(ngx.ERR, "HTTP policy rewrite rejected: ", rewrite_error)
        return plain_reject(508, "Rewrite loop detected")
    end
    local redirect_result = perform_redirects(site, rewritten)
    if redirect_result then
        return redirect_result
    end
    if not apply_request_headers(site.request_headers) then
        return plain_reject(431, "Too many request headers")
    end
end

-- resume restores, in a named location an internal redirect reached after
-- access (a cache rule route, an L2 or origin route fallback), the request
-- state header_filter reads: nginx clears ngx.ctx on the redirect. The access
-- checks, rewrites and request headers already took effect and are not run
-- again; a preflight never gets here (access answered it).
function _M.resume(options)
    if not validate_options(options) then
        return plain_reject(503, "HTTP policy unavailable")
    end
    local state = reload(options)
    local site = state.sites and state.sites[options.site_id] or nil
    if not state.policy or not site then
        return plain_reject(503, "HTTP policy unavailable")
    end
    ngx.ctx.cdnca_http_policy_site = site
    ngx.ctx.cdnca_http_policy_version = state.policy.policy_version
    local origin = ngx.var.http_origin
    if site.cors and origin then
        ngx.ctx.cdnca_http_cors_origin = origin_allowed(site.cors, origin)
    end
end

function _M.header_filter()
    local site = ngx.ctx.cdnca_http_policy_site
    if not site then
        return
    end
    apply_response_headers(site.response_headers)
    ngx.header["X-CDNCA-HTTP-Policy-Version"] = tostring(ngx.ctx.cdnca_http_policy_version)
    apply_cors_headers(site)
end

return _M
