-- Dynamic routing telemetry (ADR 0009 D12, docs/edge/dynroute-telemetry.md).
--
-- On a shared server the log line's site is the one route() selected
-- (contract docs/edge/dynroute-contract.md §1): log() writes the v7 telemetry
-- variables ($cdnca_tenant_id, $cdnca_site_id, $cdnca_ja4_log, ...) from
-- $cdnca_site_* and the site object, then sets $cdnca_telemetry so the
-- skeleton's access_log directives write one access line (and a security
-- line when a module set $cdnca_security_emit) to the node-level logs:
--   "plain"   -> the v7 line plus the "cdnca" attribution object
--   "capture" -> the v7 capture event (the site's capture policy), built by
--                the same Lua as v7 (between the markers below, kept equal to
--                edgeconfig.DynamicRoutingCaptureLogBody by a Go test), plus
--                the attribution object
--   unset     -> not logged: unknown Host, index not ready, a site without
--                telemetry (contract §1.1, v7 default servers log nothing)
-- body_filter() buffers the response body for a capture policy with
-- response body fields (v7 body_filter_by_lua).
--
-- config_version_id is written empty: it is a publication identity the node
-- request path does not have; the Agent fills it from its attribution
-- registry (generation, scope) when it turns the line back into a v7 line.
local cjson = require "cjson.safe"
local site_module = require "cdnca_site"

local ngx = ngx
local ngx_var = ngx.var
local type, tostring, ipairs, pairs, pcall, tonumber = type, tostring, ipairs, pairs, pcall, tonumber
local str_sub = string.sub

local _M = { _VERSION = "1" }

-- as v7 renderTelemetryServer: `set $cdnca_security_emit 0; ... set $cdnca_security_block_page 0;`
local SERVER_DEFAULTS = {
    cdnca_security_emit = "0", cdnca_security_type = "", cdnca_security_action = "",
    cdnca_security_severity = "", cdnca_security_rule_id = "", cdnca_security_block_page = "0",
}

-- Security evidence (TF-E01). sensitive_name follows the Agent's
-- eventspool.sensitiveName (camelCase split, then tokens): a name is
-- sensitive when one token is in EVIDENCE_SENSITIVE_TOKENS or it contains
-- "authorization"; tokens split on every non-alphanumeric byte, so Lua marks
-- at least what the Agent marks (testdata/sensitive_names.json).
local EVIDENCE_REDACTED, EVIDENCE_BODY_BYTES = "[REDACTED]", 1024
local EVIDENCE_SENSITIVE_TOKENS = {
    authorization = true, cookie = true, password = true, passwd = true, token = true, key = true,
    apikey = true, secret = true, certificate = true, cert = true, privatekey = true, setcookie = true,
}
local function sensitive_name(name)
    if type(name) ~= "string" or name == "" then return false end
    local split = string.gsub(name, "(%u)(%u%l)", "%1 %2")
    split = string.gsub(split, "([%l%d])(%u)", "%1 %2")
    local lowered = string.lower(split)
    if string.find(lowered, "authorization", 1, true) then return true end
    for token in string.gmatch(lowered, "[a-z0-9]+") do
        if EVIDENCE_SENSITIVE_TOKENS[token] then return true end
    end
    return false
end
_M.sensitive_name = sensitive_name

-- Security log path (P14): the request path plus its query, the query's
-- sensitive parameter values replaced by *** before the line is written, the
-- query cut to SECURITY_QUERY_BYTES. A name is sensitive when, lowercased, it
-- is one of SENSITIVE_QUERY_NAMES or sensitive_name holds (the Agent's rule,
-- TF-E02: client_secret, api_key, refreshSecret, ...). The Agent's redactURL
-- still runs on the event ([REDACTED]) before the spool.
local SECURITY_QUERY_BYTES = 512
local SENSITIVE_QUERY_NAMES = {
    password = true, passwd = true, pwd = true, token = true, access_token = true, secret = true,
    key = true, sign = true, signature = true, auth = true, session = true, cookie = true, code = true,
}

-- ascii_prefix: value with every byte outside 0x21-0x7E %XX-encoded (the
-- line stays valid UTF-8 without control characters, as the Agent requires),
-- cut to at most limit bytes without splitting a %XX.
local function ascii_prefix(value, limit)
    value = string.gsub(value, "[^\33-\126]", function(byte) return string.format("%%%02X", string.byte(byte)) end)
    if limit <= 0 then return "" end
    if #value <= limit then return value end
    return (string.gsub(str_sub(value, 1, limit), "%%%x?$", ""))
end

-- redact_query: the query (no leading "?") with sensitive values masked,
-- at most SECURITY_QUERY_BYTES bytes. Pairs keep their order and raw
-- encoding; a name is compared after %XX decoding and "+" as space.
local function redact_query(query)
    if type(query) ~= "string" or query == "" then return "" end
    local parts = {}
    for pair in string.gmatch(query, "[^&]+") do
        local name = string.match(pair, "^([^=]*)=")
        local plain = name and string.gsub(name, "%+", " ")
        local decoded = plain and ngx.unescape_uri(plain)
        if decoded and (SENSITIVE_QUERY_NAMES[string.lower(decoded)] or sensitive_name(decoded)) then
            parts[#parts + 1] = name .. "=***"
        else
            parts[#parts + 1] = pair
        end
    end
    return ascii_prefix(table.concat(parts, "&"), SECURITY_QUERY_BYTES)
end
_M.redact_query = redact_query

-- security_path: $uri plus "?" and the redacted query ($cdnca_security_path),
-- the query shortened so the path stays within the event's 4096 bytes.
local function security_path(uri, query)
    uri = uri or ""
    local redacted = ascii_prefix(redact_query(query), 4096 - 1 - #uri)
    if redacted == "" then return uri end
    return uri .. "?" .. redacted
end
_M.security_path = security_path

-- capture policy of a site object (siteobject.TelemetryCapture), normalized
-- once per digest like edgeconfig.normalizeTelemetryCapturePolicy: zero
-- limits take the defaults.
local DEFAULT_VALUE, DEFAULT_BODY, DEFAULT_EVENT = 4096, 65536, 1048576
local policies = setmetatable({}, { __mode = "k" })

local function list(value)
    if type(value) ~= "table" then return {} end
    return value
end

local function capture_policy(site)
    local cached = policies[site]
    if cached ~= nil then return cached or nil end
    local telemetry = site.telemetry
    local capture = type(telemetry) == "table" and telemetry.capture
    local policy = false
    if type(capture) == "table" and capture.enabled == true then
        local value = tonumber(capture.max_value_bytes) or 0
        local body = tonumber(capture.max_body_bytes) or 0
        local event = tonumber(capture.max_event_bytes) or 0
        policy = {
            max_value = value > 0 and value or DEFAULT_VALUE,
            max_body = body > 0 and body or DEFAULT_BODY,
            max_event = event > 0 and event or DEFAULT_EVENT,
            methods = list(capture.methods), prefixes = list(capture.uri_prefixes),
            request_headers = list(capture.request_header_allowlist),
            response_headers = list(capture.response_header_allowlist),
            request_body = list(capture.request_body_field_allowlist),
            response_body = list(capture.response_body_field_allowlist),
        }
    end
    policies[site] = policy
    return policy or nil
end
_M.capture_policy = capture_policy

local function matches(policy, method, uri)
    local method_ok, uri_ok = #policy.methods == 0, #policy.prefixes == 0
    for _, value in ipairs(policy.methods) do if method == value then method_ok = true; break end end
    for _, value in ipairs(policy.prefixes) do if str_sub(uri, 1, #value) == value then uri_ok = true; break end end
    return method_ok and uri_ok
end


local function redact_evidence_json(value, depth)
    if type(value) ~= "table" then return value, true end
    if depth > 16 then return nil, false end
    local result = {}
    for name, item in pairs(value) do
        if type(name) == "string" and sensitive_name(name) then
            result[name] = EVIDENCE_REDACTED
        else
            local cleaned, ok = redact_evidence_json(item, depth + 1)
            if not ok then return nil, false end
            result[name] = cleaned
        end
    end
    return result, true
end

-- evidence_body: the request body excerpt of a security event. Only a site
-- whose capture policy collects request body fields, for a request the
-- policy matches, gets one; the body is the WAF's inspected copy, which must
-- be whole (not cut at the inspection limit). JSON and form bodies are
-- parsed, sensitive names' values become [REDACTED], and the result is kept
-- only when it fits EVIDENCE_BODY_BYTES as valid UTF-8 without control
-- characters; anything else (other media types, invalid JSON, too long) is
-- left out. The rule, detector and action stay in the event either way.
local function evidence_body(policy, body, truncated, content_type, method, uri)
    if type(body) ~= "string" or body == "" or truncated then return "" end
    if not policy or #policy.request_body == 0 or not matches(policy, method or "", uri or "") then return "" end
    local media = string.match(string.lower(content_type or ""), "^%s*([^;%s]+)") or ""
    local text
    if media == "application/json" or string.match(media, "^application/[a-z0-9!#$&^_.+%-]+%+json$") then
        local decoded = cjson.decode(body)
        if type(decoded) ~= "table" then return "" end
        local cleaned, ok = redact_evidence_json(decoded, 0)
        text = ok and cjson.encode(cleaned) or nil
    elseif media == "application/x-www-form-urlencoded" then
        local parts = {}
        for pair in string.gmatch(body, "[^&]+") do
            local name = string.match(pair, "^([^=]*)=") or pair
            if sensitive_name(ngx.unescape_uri((string.gsub(name, "%+", " ")))) then
                parts[#parts + 1] = name .. "=" .. EVIDENCE_REDACTED
            else
                parts[#parts + 1] = pair
            end
        end
        text = table.concat(parts, "&")
    end
    if type(text) ~= "string" or text == "" or #text > EVIDENCE_BODY_BYTES then return "" end
    -- "u": an invalid UTF-8 text is an error, as a control byte is a match
    local from, err = ngx.re.find(text, "[\\x00-\\x1f\\x7f]", "jou")
    if from or err then return "" end
    return text
end
_M.evidence_body = evidence_body

-- The v7 capture log Lua, run with the policy's values as its locals.
local function run_capture(max_value, max_body, max_event, capture_methods, capture_uri_prefixes,
    request_header_names, response_header_names, request_body_names, response_body_names)
    local null = cjson.null
    local redacted = "[REDACTED]"
-- cdnca:capture-begin (edgeconfig.DynamicRoutingCaptureLogBody, do not edit by hand)
        local function capture_matches(method, uri)
          local method_ok, uri_ok = #capture_methods == 0, #capture_uri_prefixes == 0
          for _, value in ipairs(capture_methods) do if method == value then method_ok = true; break end end
          for _, value in ipairs(capture_uri_prefixes) do if string.sub(uri, 1, #value) == value then uri_ok = true; break end end
          return method_ok and uri_ok
        end
        local capture_enabled = capture_matches(ngx.var.request_method or "", ngx.var.uri or "")
        if not capture_enabled then request_header_names, response_header_names, request_body_names, response_body_names = {}, {}, {}, {} end
        local function sensitive(name)
			  local segmented = name:gsub("([A-Z])([A-Z][a-z])", "%1 %2")
			  segmented = segmented:gsub("([a-z0-9])([A-Z])", "%1 %2")
			  local lowered = string.lower(segmented)
		  for token in string.gmatch(lowered, "[a-z0-9]+") do
		    if token == "secret" then return true end
		  end
		  local compact = lowered:gsub("[^a-z0-9]", "")
		  for _, marker in ipairs({"authorization","cookie","password","passwd","token","key","apikey","certificate","cert","privatekey","setcookie"}) do
            if string.find(compact, marker, 1, true) then return true end
          end
          return false
        end
        local function cleanse(value, depth, state)
          if depth > 8 then return nil, false end
          if value == null then return null, true end
          local kind = type(value)
          if kind == "string" then return #value <= max_value and value or nil, #value <= max_value end
          if kind == "number" or kind == "boolean" then return value, true end
          if kind ~= "table" then return nil, false end
          local result = {}
          for key, item in pairs(value) do
            if type(key) == "string" then
              state.keys = state.keys + 1
              if state.keys > 128 or #key == 0 or #key > 128 then return nil, false end
              if sensitive(key) then result[key] = redacted else
                local cleaned, ok = cleanse(item, depth + 1, state); if not ok then return nil, false end; result[key] = cleaned
              end
            elseif type(key) == "number" then
              local cleaned, ok = cleanse(item, depth + 1, state); if not ok then return nil, false end; result[key] = cleaned
            else return nil, false end
          end
          return result, true
        end
        local function capture_headers(source, source_error, names)
          if #names == 0 then return null, true end
          if source_error == "truncated" then return nil, false end
          local indexed = {}
          for name, value in pairs(source) do
            local lower = string.lower(name)
            if indexed[lower] ~= nil or type(value) == "table" then return nil, false end
            indexed[lower] = value
          end
          local result = {}
          for _, name in ipairs(names) do
            local value = indexed[string.lower(name)]
            if value ~= nil then
              if type(value) ~= "string" or #value > max_value then return nil, false end
              result[name] = sensitive(name) and redacted or value
            end
          end
          return result, true
        end
        local function is_json_content_type(value)
          if type(value) ~= "string" then return false end
          value = string.lower(value)
          local media_type = string.match(value, "^%s*([^;%s]+)")
          if media_type == nil or media_type == "" then return false end
          return media_type == "application/json" or
            string.match(media_type, "^application/[a-z0-9!#$&^_.+%-]+%+json$") ~= nil
        end
        local function header_value(source, name)
          if type(source) ~= "table" then return nil end
          local value
          for key, item in pairs(source) do
            if type(key) == "string" and string.lower(key) == name then
              if value ~= nil or type(item) ~= "string" then return nil end
              value = item
            end
          end
          return value
        end
        local function capture_body(raw, content_type, names)
          if #names == 0 then return null, true end
          if raw == nil or raw == "" then return {}, true end
          if not is_json_content_type(content_type) then return nil, false end
          if #raw > max_body then return nil, false end
          local decoded = cjson.decode(raw)
          if type(decoded) ~= "table" then return nil, false end
          local result, state = {}, {keys = 0}
          for _, name in ipairs(names) do
            local value = decoded[name]
            if value ~= nil then
              if sensitive(name) then result[name] = redacted else
                local cleaned, ok = cleanse(value, 0, state); if not ok then return nil, false end; result[name] = cleaned
              end
            end
          end
          local encoded = cjson.encode(result)
          return encoded ~= nil and #encoded <= max_body and result or nil, encoded ~= nil and #encoded <= max_body
        end
        local function timing(raw)
          if raw == nil or raw == "" or raw == "-" then return null, true end
          if string.find(raw, ",", 1, true) or string.find(raw, ":", 1, true) then return nil, false end
          local whole, fraction = string.match(raw, "^(%d+)%.(%d+)$")
          if whole == nil or #whole > 6 or #fraction > 6 then return nil, false end
          fraction = fraction .. string.rep("0", 6 - #fraction)
          return tonumber(whole) * 1000000 + tonumber(fraction), true
        end
		local request_headers_raw, request_headers_error = {}, nil
		if #request_header_names > 0 or #request_body_names > 0 then request_headers_raw, request_headers_error = ngx.req.get_headers(128, true) end
		local response_headers_raw, response_headers_error = {}, nil
		if #response_header_names > 0 or #response_body_names > 0 then response_headers_raw, response_headers_error = ngx.resp.get_headers(128, true) end
        local request_headers, ok1 = capture_headers(request_headers_raw, request_headers_error, request_header_names)
        local response_headers, ok2 = capture_headers(response_headers_raw, response_headers_error, response_header_names)
        local request_content_type = header_value(request_headers_raw, "content-type")
        local response_content_type = header_value(response_headers_raw, "content-type")
        local request_file = #request_body_names > 0 and ngx.req.get_body_file() or nil
		local request_raw = #request_body_names > 0 and not request_file and ngx.req.get_body_data() or nil
        local request_body, ok3 = capture_body(request_raw, request_content_type, request_body_names)
		local response_raw = #response_body_names > 0 and ngx.ctx.cdnca_capture_chunks and table.concat(ngx.ctx.cdnca_capture_chunks) or nil
        local response_body, ok4 = capture_body(response_raw, response_content_type, response_body_names)
        local origin_connect_us, ok5 = timing(ngx.var.upstream_connect_time)
        local origin_first_byte_us, ok6 = timing(ngx.var.upstream_header_time)
        local origin_total_us, ok7 = timing(ngx.var.upstream_response_time)
        -- 采集字段失败（重复/截断请求头、请求体落盘、超限）只置空该字段，整条访问事件必须保留。
        if not ok1 then request_headers = null end
        if not ok2 then response_headers = null end
        if request_file or not ok3 then request_body = null end
        if ngx.ctx.cdnca_capture_invalid or not ok4 then response_body = null end
        if not ok5 then origin_connect_us = null end
        if not ok6 then origin_first_byte_us = null end
        if not ok7 then origin_total_us = null end
        local ordered = (origin_connect_us == null or origin_first_byte_us == null or origin_connect_us <= origin_first_byte_us)
          and (origin_first_byte_us == null or origin_total_us == null or origin_first_byte_us <= origin_total_us)
          and (origin_connect_us == null or origin_total_us == null or origin_connect_us <= origin_total_us)
        if not ordered then origin_connect_us, origin_first_byte_us, origin_total_us = null, null, null end
        local ja4 = ngx.var.cdnca_ja4
        if ja4 == nil or ja4 == "" then ja4 = null end
        local common = {
          schema_version=1, occurred_at=ngx.var.time_iso8601, tenant_id=ngx.var.cdnca_tenant_id,
          site_id=ngx.var.cdnca_site_id, node_id=ngx.var.cdnca_node_id, config_version_id=ngx.var.cdnca_config_version_id,
		  installation_id="", task_id=null, request_id=ngx.var.request_id or "", trace_id=ngx.var.http_traceparent or "", host=ngx.var.host,
          path=ngx.var.uri, client_ip=ngx.var.cdnca_telemetry_client_ip, status_code=tonumber(ngx.var.status),
          request_bytes=tonumber(ngx.var.request_length), response_bytes=tonumber(ngx.var.bytes_sent),
          request_headers=request_headers, response_headers=response_headers, request_body=request_body, response_body=response_body,
          ja4=ja4, origin_connect_us=origin_connect_us, origin_first_byte_us=origin_first_byte_us, origin_total_us=origin_total_us
        }
        local cdnca_blocked = ngx.var.cdnca_security_block_page == "1"
        local access, security = {}, {}
        for key, value in pairs(common) do access[key]=value; security[key]=value end
        access.type="access.v1"; access.method=ngx.var.request_method; access.protocol=ngx.var.server_protocol
		access.connection=ngx.var.connection; access.connection_requests=tonumber(ngx.var.connection_requests)
        access.cache_status=ngx.var.cdnca_telemetry_cache_status; access.blocked=cdnca_blocked
        access.duration_us=tonumber(ngx.var.cdnca_duration_us) or 0
        access.client_browser=ngx.var.cdnca_client_browser or "other"; access.client_os=ngx.var.cdnca_client_os or "other"
        local upstream_addr = ngx.var.cdnca_upstream_addr_log
        if upstream_addr ~= nil then access.upstream_addr = upstream_addr end
		security.type="security.v1"; security.security_type=ngx.var.cdnca_security_type
		security.action=ngx.var.cdnca_security_action; security.severity=ngx.var.cdnca_security_severity
		security.rule_id=ngx.var.cdnca_security_rule_id; security.method=ngx.var.request_method
		security.policy_id=ngx.var.cdnca_security_policy_id or ""; security.detector=ngx.var.cdnca_security_detector or ""
		security.matched=ngx.var.cdnca_security_matched or ""; security.user_agent=ngx.var.cdnca_security_user_agent or ""
		security.request_body_excerpt=ngx.var.cdnca_security_body or ""
		security.listen_port=tonumber(ngx.var.cdnca_site_port); security.protocol=ngx.var.scheme
		security.request_class=ngx.var.cdnca_security_request_class; security.path=ngx.var.cdnca_security_path
        local access_json, security_json = cjson.encode(access), cjson.encode(security)
        if not access_json or not security_json or #access_json > max_event or #security_json > max_event then
          for _, event in ipairs({access, security}) do
            event.request_headers, event.response_headers, event.request_body, event.response_body = null, null, null, null
          end
          access_json, security_json = cjson.encode(access), cjson.encode(security)
        end
        if not access_json or not security_json or #access_json > max_event or #security_json > max_event then
          access_json, security_json = '{"schema_version":0}', '{"schema_version":0}'
        end
        ngx.var.cdnca_access_telemetry_json = access_json
        ngx.var.cdnca_security_telemetry_json = security_json
-- cdnca:capture-end
end

-- The attribution object appended to a capture event (the plain line gets it
-- from the log format).
local function attribute(json)
    if json == '{"schema_version":0}' then return json end
    return str_sub(json, 1, -2) .. ',"cdnca":{"generation":' .. ngx_var.cdnca_site_generation ..
        ',"scope":"' .. ngx_var.cdnca_site_scope .. '","digest":"' .. ngx_var.cdnca_site_digest ..
        '","port":' .. ngx_var.cdnca_site_port .. ',"l2":' .. (ngx_var.cdnca_l2_trusted == "1" and "true" or "false") .. '}}'
end

_M._attribute = attribute

-- body_filter_by_lua: buffer the response body for a capture policy with
-- response body fields (v7 renderTelemetryCaptureBodyFilterLua).
function _M.body_filter()
    local site = site_module.current()
    if not site then return end
    local policy = capture_policy(site)
    if not policy or #policy.response_body == 0 then return end
    if not matches(policy, ngx_var.request_method or "", ngx_var.uri or "") then return end
    local chunk = ngx.arg[1]
    if chunk and chunk ~= "" then
        local ctx = ngx.ctx
        local chunks = ctx.cdnca_capture_chunks or {}
        local bytes = (ctx.cdnca_capture_bytes or 0) + #chunk
        ctx.cdnca_capture_bytes = bytes
        if bytes > policy.max_body then
            ctx.cdnca_capture_invalid = true
        else
            chunks[#chunks + 1] = chunk
            ctx.cdnca_capture_chunks = chunks
        end
    end
end

-- ---------------------------------------------------------------------------
-- Aggregated security lines (sec-log-agg): a CC challenge page or 429 sets
-- $cdnca_security_aggregate instead of $cdnca_security_emit. log() counts it
-- in the shared dictionary by (minute, site, client IP, type, rule, action);
-- the first request of a key also stores the line (the plain security line's
-- fields, captures null, "count" before the attribution) and queues the key.
-- Worker 0 writes the line of every finished minute with its count through
-- the skeleton's flush server (the master-opened security.jsonl; a worker
-- cannot open the agent's 0600 file).
local AGG_PREFIX_COUNT, AGG_PREFIX_LINE, AGG_QUEUE = "n|", "l|", "queue"
local AGG_FLUSH_SECONDS, AGG_TIMEOUT_MS, AGG_BATCH = 5, 1000, 512
_M.AGGREGATE_FLUSH_PATH = "/__cdnca_security_flush"
local agg = { dict = nil, socket = nil, max_line = 16384 }

-- configure_aggregate (init_by_lua): the shared dictionary, the flush
-- server's unix socket and the longest accepted line.
function _M.configure_aggregate(opts)
    assert(type(opts) == "table" and type(opts.dict) == "string" and type(opts.socket) == "string",
        "cdnca_telemetry.configure_aggregate: dict and socket")
    agg.dict, agg.socket = opts.dict, opts.socket
    agg.max_line = tonumber(opts.max_line) or agg.max_line
end

local function json_string(value)
    return cjson.encode(value == nil and "" or tostring(value))
end

local function json_number(value)
    local number = tonumber(value)
    if number == nil or number ~= number or number < 0 then return "null" end
    return string.format("%d", number)
end

-- aggregate_line: the plain security line (libs/edgeconfig telemetrySecurityJSON
-- through dynamicRoutingLine; TestDynamicRoutingAggregateLineFields keeps the
-- keys equal) of this request, without the attribution's closing brace so the
-- flush can append the count.
local function aggregate_line(client_ip)
    local v = ngx_var
    local ja4 = v.cdnca_ja4_log
    return '{"schema_version":1,"type":"security.v1","occurred_at":' .. json_string(v.time_iso8601) ..
        ',"tenant_id":' .. json_string(v.cdnca_tenant_id) .. ',"site_id":' .. json_string(v.cdnca_site_id) ..
        ',"node_id":' .. json_string(v.cdnca_node_id) .. ',"config_version_id":' .. json_string(v.cdnca_config_version_id) ..
        ',"installation_id":"","task_id":null,"request_id":' .. json_string(v.request_id) ..
        ',"trace_id":' .. json_string(v.http_traceparent) .. ',"host":' .. json_string(v.host) ..
        ',"path":' .. json_string(v.cdnca_security_path) .. ',"client_ip":' .. json_string(client_ip) ..
        ',"method":' .. json_string(v.request_method) .. ',"listen_port":' .. json_number(v.cdnca_site_port) ..
        ',"protocol":' .. json_string(v.scheme) .. ',"request_class":' .. json_string(v.cdnca_security_request_class) ..
        ',"status_code":' .. json_number(v.status) .. ',"request_bytes":' .. json_number(v.request_length) ..
        ',"response_bytes":' .. json_number(v.bytes_sent) ..
        ',"security_type":' .. json_string(v.cdnca_security_type) .. ',"action":' .. json_string(v.cdnca_security_action) ..
        ',"severity":' .. json_string(v.cdnca_security_severity) .. ',"rule_id":' .. json_string(v.cdnca_security_rule_id) ..
        ',"policy_id":' .. json_string(v.cdnca_security_policy_id) .. ',"detector":' .. json_string(v.cdnca_security_detector) ..
        ',"matched":' .. json_string(v.cdnca_security_matched) .. ',"user_agent":' .. json_string(v.cdnca_security_user_agent) ..
        ',"request_body_excerpt":' .. json_string(v.cdnca_security_body) ..
        ',"request_headers":null,"response_headers":null,"request_body":null,"response_body":null' ..
        ',"ja4":' .. json_string(ja4) .. ',"origin_connect_us":null,"origin_first_byte_us":null,"origin_total_us":null'
end

local function attribution_json()
    return '"cdnca":{"generation":' .. json_number(ngx_var.cdnca_site_generation) .. ',"scope":' ..
        json_string(ngx_var.cdnca_site_scope) .. ',"digest":' .. json_string(ngx_var.cdnca_site_digest) ..
        ',"port":' .. json_number(ngx_var.cdnca_site_port) .. ',"l2":false}}'
end

-- count_aggregate: one request of an aggregated decision.
local function count_aggregate(client_ip)
    local dict = agg.dict and ngx.shared[agg.dict]
    if not dict then return end
    local minute = math.floor(ngx.time() / 60)
    local key = minute .. "|" .. (ngx_var.cdnca_site_id or "") .. "|" .. (client_ip or "") .. "|" ..
        (ngx_var.cdnca_security_type or "") .. "|" .. (ngx_var.cdnca_security_rule_id or "") .. "|" ..
        (ngx_var.cdnca_security_action or "")
    -- kept past the minute so a late flush still finds it
    local count, err = dict:incr(AGG_PREFIX_COUNT .. key, 1, 0, 600)
    if not count then
        ngx.log(ngx.WARN, "cdnca security aggregate: ", err)
        return
    end
    if count == 1 then
        local line = aggregate_line(client_ip)
        local ok, set_err = dict:safe_set(AGG_PREFIX_LINE .. key, line .. "\0" .. attribution_json(), 600)
        if ok then ok, set_err = dict:lpush(AGG_QUEUE, key) end
        if not ok then ngx.log(ngx.WARN, "cdnca security aggregate: ", set_err) end
    end
end

-- flush_one: POST one finished line to the flush server (keep-alive).
local function flush_send(sock, line)
    local ok, err = sock:send({ "POST ", _M.AGGREGATE_FLUSH_PATH, " HTTP/1.1\r\nHost: cdnca\r\nContent-Length: ", #line,
        "\r\n\r\n", line })
    if not ok then return nil, err end
    local status = sock:receive("*l")
    if not status then return nil, "no response" end
    -- headers until the blank line (204: no body)
    while true do
        local header = sock:receive("*l")
        if header == nil then return nil, "truncated response" end
        if header == "" then break end
    end
    -- 204: written; 400: the flush server refuses the line (it never will
    -- take it, drop); anything else is unknown, keep it for the next run
    if status:match("^HTTP/1%.1 204") then return true, status end
    return nil, status, status:match("^HTTP/1%.1 400") ~= nil
end

local function flush(premature)
    -- a reload keeps the dictionary: the next worker 0 writes the lines
    if premature then return end
    local dict = agg.dict and ngx.shared[agg.dict]
    if not dict then return end
    local current = math.floor(ngx.time() / 60)
    local sock
    for _ = 1, AGG_BATCH do
        local key = dict:rpop(AGG_QUEUE)
        if not key then break end
        local minute = tonumber(key:match("^(%d+)|"))
        if minute and minute >= current then
            dict:rpush(AGG_QUEUE, key) -- the oldest key's minute is not over yet
            break
        end
        local stored = dict:get(AGG_PREFIX_LINE .. key)
        local count = dict:get(AGG_PREFIX_COUNT .. key)
        if stored and count then
            local body, attribution = stored:match("^(.*)%z(.*)$")
            local line = body .. ',"count":' .. string.format("%d", count) .. ',' .. attribution
            if #line <= agg.max_line then
                if not sock then
                    sock = ngx.socket.tcp()
                    sock:settimeouts(AGG_TIMEOUT_MS, AGG_TIMEOUT_MS, AGG_TIMEOUT_MS)
                    local ok, err = sock:connect("unix:" .. agg.socket)
                    if not ok then
                        ngx.log(ngx.ERR, "cdnca security aggregate flush: ", err)
                        dict:rpush(AGG_QUEUE, key) -- next run
                        return
                    end
                end
                local ok, err, refused = flush_send(sock, line)
                if not ok then
                    ngx.log(ngx.ERR, "cdnca security aggregate flush: ", tostring(err))
                    sock:close()
                    sock = nil
                    if not refused then
                        -- TF-E03: a 5xx, a lost or cut response is not an
                        -- acknowledgement: keep the frozen line and count and
                        -- retry the key first next run. The line is the same
                        -- bytes, so the Agent gives a repeat the same event ID
                        -- (eventspool aggregateEventID) and counts it once.
                        dict:rpush(AGG_QUEUE, key)
                        return
                    end
                end
            end
        end
        dict:delete(AGG_PREFIX_LINE .. key)
        dict:delete(AGG_PREFIX_COUNT .. key)
    end
    if sock then sock:setkeepalive(10000, 1) end
end

_M._flush = flush

-- init_worker_aggregate: worker 0 flushes (one writer, no duplicate line).
function _M.init_worker_aggregate()
    if not agg.dict or ngx.worker.id() ~= 0 then return end
    local ok, err = ngx.timer.every(AGG_FLUSH_SECONDS, flush)
    if not ok then ngx.log(ngx.ERR, "cdnca security aggregate timer: ", err) end
end

-- flush_handler (content_by_lua of the flush server): one finished line.
-- Only workers reach the socket (run/ directory of the worker group); the
-- Agent still checks every line's attribution against its site object.
function _M.flush_handler()
    if ngx.req.get_method() ~= "POST" then return ngx.exit(405) end
    ngx.req.read_body()
    local line = ngx.req.get_body_data()
    if type(line) ~= "string" or #line == 0 or #line > agg.max_line or line:find("[\r\n]") or
        line:sub(1, 1) ~= "{" or not cjson.decode(line) then
        return ngx.exit(400)
    end
    ngx_var.cdnca_security_telemetry_json = line
    ngx_var.cdnca_security_flush = "1"
    return ngx.exit(204)
end

-- log_by_lua: write the telemetry variables of the selected site.
function _M.log()
    local site = site_module.current()
    if not site or type(site.telemetry) ~= "table" then return end
    ngx_var.cdnca_tenant_id = ngx_var.cdnca_site_tenant
    ngx_var.cdnca_config_version_id = ""
    ngx_var.cdnca_node_id = ""
    ngx_var.cdnca_ja4_log = ngx_var.cdnca_ja4 or ""
    -- the visitor by the site's trusted proxy chain (the X-Real-IP the origin
    -- is sent, cdnca_origin.client_ip); the peer without the origin module
    local origin = package.loaded["cdnca_origin"]
    local client = origin and origin.client_ip and origin.client_ip()
    ngx_var.cdnca_telemetry_client_ip = client or ngx_var.remote_addr
    -- the security line's path: path and redacted query (P14)
    ngx_var.cdnca_security_path = security_path(ngx_var.uri, ngx_var.args)
    -- The per-site v7 server set these at server level; a shared server
    -- only declares them (an unassigned variable would log "-"). Security
    -- modules (CC, rule interpreter) assign them when they emit.
    for name, default in pairs(SERVER_DEFAULTS) do
        if ngx_var[name] == nil then ngx_var[name] = default end
    end
    -- an aggregated decision (CC challenge page / 429) is counted, not
    -- logged; a request that emits (temporary ban) is logged on its own
    if ngx_var.cdnca_security_aggregate == "1" and ngx_var.cdnca_security_emit ~= "1" then
        local ok, err = pcall(count_aggregate, ngx_var.cdnca_telemetry_client_ip)
        if not ok then ngx.log(ngx.ERR, "cdnca security aggregate: ", tostring(err)) end
    end
    local policy = capture_policy(site)
    -- the request body excerpt of a WAF decision (TF-E01): only by the
    -- site's capture policy, redacted, before the line is first written
    local excerpt = ""
    if ngx.ctx.cdnca_evidence_body then
        local ok, value = pcall(evidence_body, policy, ngx.ctx.cdnca_inspect_body, ngx.ctx.cdnca_inspect_body_truncated,
            ngx_var.http_content_type, ngx_var.request_method, ngx_var.uri)
        excerpt = ok and value or ""
    end
    ngx_var.cdnca_security_body = excerpt
    if not policy then
        ngx_var.cdnca_telemetry = "plain"
        return
    end
    -- v7 builds a capture event for every request of a capture site (the
    -- allowlists only apply to requests the policy matches).
    local ok, err = pcall(run_capture, policy.max_value, policy.max_body, policy.max_event, policy.methods,
        policy.prefixes, policy.request_headers, policy.response_headers, policy.request_body, policy.response_body)
    if not ok then
        ngx.log(ngx.ERR, "cdnca telemetry capture failed: ", tostring(err))
        -- as v7 (the variables keep their unbuilt value): the Agent
        -- quarantines the line
        ngx_var.cdnca_access_telemetry_json = '{"schema_version":0}'
        ngx_var.cdnca_security_telemetry_json = '{"schema_version":0}'
    end
    ngx_var.cdnca_access_telemetry_json = attribute(ngx_var.cdnca_access_telemetry_json)
    ngx_var.cdnca_security_telemetry_json = attribute(ngx_var.cdnca_security_telemetry_json)
    ngx_var.cdnca_telemetry = "capture"
end

return _M
