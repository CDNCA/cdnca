local _M = {}
local resty_random = require("resty.random")
local sha256 = require("resty.sha256")
local resty_string = require("resty.string")
local metadata_degraded = false
local metadata_degraded_key = "metadata:degraded"
local generation_key = "cache:generation"
local current_prefix = "current:"
local record_prefix = "record:"
local completed_prefix = "completed:"
local validator_prefix = "validator:"
local freshness_prefix = "freshness:"
local transition_prefix = "transition:"
local max_origin_header_values = 16
local max_origin_header_bytes = 8192
local max_origin_freshness_seconds = 2147483647

local function valid_generation(value)
    return type(value) == "string" and #value == 64 and value:match("^[0-9a-f]+$") ~= nil
end

local function object_record_key(key, token)
    return record_prefix .. key .. ":" .. token
end

local function completed_record_key(key, token)
    return completed_prefix .. key .. ":" .. token
end

local function validator_record_key(key, token)
    return validator_prefix .. key .. ":" .. token
end

local function freshness_record_key(key, token)
    return freshness_prefix .. key .. ":" .. token
end

local function pending_record(token)
    return "pending:" .. token
end

local function blocked_record(token)
    return "blocked:" .. token
end

local function stored_record(token, stored_at)
    return "stored:" .. token .. ":" .. string.format("%.6f", stored_at)
end

local function completed_record(token, completed_at, validator, source)
    return "completed:" .. token .. ":" .. string.format("%.6f", completed_at) .. ":" .. validator .. ":" .. source
end

local function decode_record(value, expected_token)
    if type(value) ~= "string" then
        return nil, nil
    end
    if value == pending_record(expected_token) then
        return "pending", nil
    end
    if value == blocked_record(expected_token) then
        return "blocked", nil
    end
    local token, encoded_at = value:match("^stored:([0-9a-f]+):([0-9]+%.[0-9]+)$")
    local stored_at = tonumber(encoded_at)
    if token ~= expected_token or not valid_generation(token) or stored_at == nil or stored_at ~= stored_at or stored_at <= 0 or stored_at >= math.huge then
        return nil, nil
    end
    return "stored", stored_at
end

local function decode_completed_record(value, expected_token)
    if type(value) ~= "string" then
        return nil
    end
    local token, encoded_at, validator, source = value:match("^completed:([0-9a-f]+):([0-9]+%.[0-9]+):([0-9a-f]+):([a-z]+)$")
    local completed_at = tonumber(encoded_at)
    if token ~= expected_token or not valid_generation(token) or not valid_generation(validator) or (source ~= "body" and source ~= "head") or completed_at == nil or completed_at ~= completed_at or completed_at <= 0 or completed_at >= math.huge then
        return nil, nil, nil
    end
    return completed_at, validator, source
end

local function mark_metadata_degraded(dictionary, error_message)
    metadata_degraded = true
    local ok = dictionary:set(metadata_degraded_key, true)
    if not ok then
        dictionary:flush_all()
        dictionary:flush_expired()
        ok = dictionary:set(metadata_degraded_key, true)
    end
    if not ok then
        ngx.log(ngx.ALERT, "cache freshness metadata fail-closed marker failed")
    end
    ngx.log(ngx.ERR, "cache freshness metadata degraded: ", tostring(error_message))
end

local function set_metadata(dictionary, key, value, ttl)
    local ok, error_message, forcible = dictionary:set(key, value, ttl)
    if not ok or forcible then
        mark_metadata_degraded(dictionary, error_message or "forcible eviction")
        return false
    end
    return true
end

local function digest(identity)
    local hash = sha256:new()
    local ok = hash:update(identity)
    if not ok then
        return nil
    end
    return resty_string.to_hex(hash:final())
end

local function random_token()
    local random_bytes, random_error = resty_random.bytes(32, true)
    if not random_bytes then
        return nil, random_error or "cache object token random source failed"
    end
    return resty_string.to_hex(random_bytes)
end

local function fail_closed(reason)
    ngx.var.cache_freshness_fail_closed = "1"
    ngx.var.cache_freshness_hard_bypass = "1"
    ngx.ctx.cache_freshness_reason = reason or "stale_hard_limit_reached"
end

local function state_for_reason(reason)
    if reason == "cache_fresh_hit" or reason == "coalesced_follower" then
        return "fresh"
    end
    if reason == "stale_served_revalidate" then
        return "stale"
    end
    return "expired"
end

local function trim(value)
    return (value:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function valid_header_token(value)
    if type(value) ~= "string" or value == "" then
        return false
    end
    for index = 1, #value do
        local byte = value:byte(index)
        if byte <= 32 or byte >= 127 or ("()<>@,;:\\\"/[]?={}"):find(value:sub(index, index), 1, true) then
            return false
        end
    end
    return true
end

local function split_header_list(value)
    if type(value) ~= "string" or trim(value) == "" or value:find("[\r\n]") then
        return nil
    end
    local result = {}
    local start = 1
    local quoted = false
    local escaped = false
    for index = 1, #value do
        local character = value:sub(index, index)
        if escaped then
            escaped = false
        elseif quoted and character == "\\" then
            escaped = true
        elseif character == "\"" then
            quoted = not quoted
        elseif character == "," and not quoted then
            local item = trim(value:sub(start, index - 1))
            if item == "" then
                return nil
            end
            result[#result + 1] = item
            start = index + 1
        end
    end
    local item = trim(value:sub(start))
    if quoted or escaped or item == "" then
        return nil
    end
    result[#result + 1] = item
    return result
end

local function valid_quoted_string(value)
    if type(value) ~= "string" or #value < 2 or value:sub(1, 1) ~= "\"" or value:sub(-1) ~= "\"" then
        return false
    end
    local escaped = false
    for index = 2, #value - 1 do
        local byte = value:byte(index)
        local character = value:sub(index, index)
        if escaped then
            escaped = false
        elseif character == "\\" then
            escaped = true
        elseif character == "\"" or byte < 32 or byte == 127 then
            return false
        end
    end
    return not escaped
end

local function parse_delta_seconds(value)
    value = trim(value or "")
    if #value >= 2 and value:sub(1, 1) == "\"" and value:sub(-1) == "\"" then
        value = value:sub(2, -2)
    end
    if value == "" or value:find("[^0-9]") then
        return nil
    end
    local parsed = tonumber(value)
    if not parsed or parsed ~= math.floor(parsed) then
        return nil
    end
    -- RFC 9111 1.2.2: delta-seconds beyond the representable range are treated as 2^31.
    return math.min(parsed, max_origin_freshness_seconds)
end

local function origin_header_values(headers, target)
    local result = {}
    local total_bytes = 0
    for name, value in pairs(headers) do
        if type(name) == "string" and string.lower(name) == target then
            local values = type(value) == "table" and value or { value }
            for _, item in ipairs(values) do
                if type(item) ~= "string" then
                    return nil
                end
                total_bytes = total_bytes + #item
                result[#result + 1] = item
                if #result > max_origin_header_values or total_bytes > max_origin_header_bytes then
                    return nil
                end
            end
        end
    end
    return result
end

local function parse_origin_cache_control(values)
    local result = {}
    local seen = {}
    for _, value in ipairs(values) do
        local directives = split_header_list(value)
        if not directives then
            return nil
        end
        for _, directive in ipairs(directives) do
            local equals = directive:find("=", 1, true)
            local name = string.lower(trim(equals and directive:sub(1, equals - 1) or directive))
            local raw = equals and trim(directive:sub(equals + 1)) or nil
            if not valid_header_token(name) or seen[name] then
                return nil
            end
            seen[name] = true
            if name == "s-maxage" or name == "max-age" then
                local seconds = equals and parse_delta_seconds(raw) or nil
                if seconds == nil then
                    return nil
                end
                result[name] = seconds
            elseif name == "no-store" or name == "must-revalidate" or name == "public" then
                if equals then
                    return nil
                end
                result[name] = true
            elseif name == "private" or name == "no-cache" then
                if equals and not valid_quoted_string(raw) then
                    return nil
                end
                result[name] = true
            elseif equals and not valid_header_token(raw) and not valid_quoted_string(raw) then
                return nil
            end
        end
    end
    return result
end

local function parse_single_delta(values)
    if #values == 0 then
        return 0
    end
    if #values ~= 1 then
        return nil
    end
    return parse_delta_seconds(values[1])
end

local function parse_single_date(values)
    if #values == 0 then
        return false
    end
    if #values ~= 1 then
        return nil
    end
    return ngx.parse_http_time(trim(values[1]))
end

local function parse_origin_vary(values)
    local names = {}
    local star = false
    for _, value in ipairs(values) do
        local entries = split_header_list(value)
        if not entries then
            return nil
        end
        for _, name in ipairs(entries) do
            name = string.lower(trim(name))
            if name == "*" then
                star = true
            elseif not valid_header_token(name) then
                return nil
            else
                names[name] = true
            end
        end
    end
    if star and next(names) ~= nil then
        return nil
    end
    return star
end

-- default_seconds is the configured TTL used when the origin gives no explicit
-- lifetime (no s-maxage/max-age/Expires), matching proxy_cache_valid outside
-- the freshness mode.
local function parse_origin_freshness(default_seconds)
    local headers, error_message = ngx.resp.get_headers(64, true)
    if type(headers) ~= "table" or error_message ~= nil then
        return nil
    end
    local cache_control_values = origin_header_values(headers, "cache-control")
    if not cache_control_values then
        return nil
    end
    local control = parse_origin_cache_control(cache_control_values)
    if not control then
        return nil
    end
    local result = {
        uncacheable = control["no-store"] or control.private,
        force_expired = control["no-cache"] or control["must-revalidate"],
    }
    if result.uncacheable or result.force_expired then
        result.fresh_seconds = 0
        return result
    end
    local vary_values = origin_header_values(headers, "vary")
    if not vary_values then
        return nil
    end
    local vary_star = parse_origin_vary(vary_values)
    if vary_star == nil then
        return nil
    end
    if vary_star then
        result.uncacheable = true
        result.fresh_seconds = 0
        return result
    end
    local age_values = origin_header_values(headers, "age")
    if not age_values then
        return nil
    end
    local age = parse_single_delta(age_values)
    if age == nil then
        return nil
    end
    local lifetime
    if control["s-maxage"] ~= nil then
        lifetime = control["s-maxage"]
    elseif control["max-age"] ~= nil then
        lifetime = control["max-age"]
    else
        local date_values = origin_header_values(headers, "date")
        local expires_values = origin_header_values(headers, "expires")
        if not date_values or not expires_values then
            return nil
        end
        local expires = parse_single_date(expires_values)
        if expires == false then
            result.fresh_seconds = default_seconds or 0
            return result
        end
        local date = parse_single_date(date_values)
        if date == nil or expires == nil or date == false then
            return nil
        end
        lifetime = math.min(math.max(0, expires - date), max_origin_freshness_seconds)
    end
    result.fresh_seconds = math.max(0, lifetime - age)
    return result
end

local function object_fresh_seconds(dictionary, key, token, options)
    if not options.follow_origin_headers then
        return options.fresh_seconds
    end
    local value = dictionary:get(freshness_record_key(key, token))
    local seconds = tonumber(value)
    if type(value) ~= "string" or not seconds or seconds < 0 or seconds ~= math.floor(seconds) or seconds > max_origin_freshness_seconds then
        return nil
    end
    return seconds
end

local function reject_origin_freshness(reason)
    ngx.var.cache_freshness_fail_closed = "1"
    ngx.var.cache_freshness_hard_bypass = "1"
    ngx.ctx.cache_freshness_reason = reason
end

function _M.origin_header_filter(options)
    if not options.follow_origin_headers then
        return
    end
    local facts = parse_origin_freshness(options.fresh_seconds)
    if not facts then
        reject_origin_freshness("origin_headers_invalid")
    elseif facts.uncacheable then
        reject_origin_freshness("origin_headers_uncacheable")
    elseif facts.force_expired then
        reject_origin_freshness("cache_miss")
    end
end

local function transition_token(dictionary, key, old_token, options)
    local current_key = current_prefix .. key
    local transition_key = transition_prefix .. key .. ":" .. (old_token or "cold")
    for _ = 1, 3 do
        local current = dictionary:get(current_key)
        if current ~= nil and not valid_generation(current) then
            mark_metadata_degraded(dictionary, "cache object current token is invalid")
            return nil
        end
        if current ~= nil and current ~= old_token then
            return current
        end

        local candidate = dictionary:get(transition_key)
        if candidate ~= nil and not valid_generation(candidate) then
            mark_metadata_degraded(dictionary, "cache object transition token is invalid")
            return nil
        end
        if candidate ~= nil and candidate == old_token then
            mark_metadata_degraded(dictionary, "cache object transition token did not advance")
            return nil
        end
        if candidate == nil then
            local random_error
            candidate, random_error = random_token()
            if not candidate then
                mark_metadata_degraded(dictionary, random_error)
                return nil
            end
            if candidate == old_token then
                mark_metadata_degraded(dictionary, "cache object transition token collision")
                return nil
            end
            local added, add_error, forcible = dictionary:add(transition_key, candidate, options.metadata_ttl_seconds)
            if forcible then
                mark_metadata_degraded(dictionary, "cache object transition token caused forcible eviction")
                return nil
            end
            if not added and add_error ~= "exists" then
                mark_metadata_degraded(dictionary, add_error or "cache object transition token write failed")
                return nil
            end
            if not added then
                candidate = dictionary:get(transition_key)
                if candidate == nil then
                    current = dictionary:get(current_key)
                    if current ~= nil and not valid_generation(current) then
                        mark_metadata_degraded(dictionary, "cache object current token is invalid")
                        return nil
                    end
                    if current ~= nil and current ~= old_token then
                        return current
                    end
                elseif not valid_generation(candidate) then
                    mark_metadata_degraded(dictionary, "cache object transition token is invalid")
                    return nil
                end
            end
        end

        if candidate ~= nil then
            current = dictionary:get(current_key)
            if current ~= nil and not valid_generation(current) then
                mark_metadata_degraded(dictionary, "cache object current token is invalid")
                return nil
            end
            if current == candidate then
                return current
            end
            if current ~= nil and current ~= old_token and current ~= candidate then
                return current
            end

            local candidate_record_key = object_record_key(key, candidate)
            local added, add_error, forcible = dictionary:add(
                candidate_record_key,
                pending_record(candidate),
                options.metadata_ttl_seconds
            )
            if forcible then
                mark_metadata_degraded(dictionary, "cache object pending record caused forcible eviction")
                return nil
            end
            if not added and add_error ~= "exists" then
                mark_metadata_degraded(dictionary, add_error or "cache object pending record write failed")
                return nil
            end
            if not added then
                local kind = decode_record(dictionary:get(candidate_record_key), candidate)
                if kind ~= "pending" then
                    mark_metadata_degraded(dictionary, "cache object pending record collided with committed state")
                    return nil
                end
            end
            if not set_metadata(dictionary, current_key, candidate, options.metadata_ttl_seconds) then
                return nil
            end
            dictionary:delete(transition_key)
            return candidate
        end
    end
    mark_metadata_degraded(dictionary, "cache object transition could not be established")
    return nil
end

local function use_pending_namespace(dictionary, key, token, options)
    ngx.var.cache_freshness_object_token = token
    ngx.ctx.cache_freshness_object_token = token
    local active_key = "active:" .. key .. ":" .. token
    local owner, add_error, forcible = dictionary:add(active_key, true, options.lock_seconds + 1)
    if forcible then
        mark_metadata_degraded(dictionary, "active marker caused forcible eviction")
        fail_closed()
        return false
    end
    if not owner and add_error ~= "exists" then
        mark_metadata_degraded(dictionary, add_error or "active marker write failed")
        fail_closed()
        return false
    end
    ngx.ctx.cache_freshness_active_key = active_key
    ngx.ctx.cache_freshness_active_owner = owner == true
    ngx.ctx.cache_freshness_follower = owner ~= true
    return true
end

function _M.init_worker()
    local dictionary = ngx.shared.cache_freshness_meta
    local generation = dictionary:get(generation_key)
    if generation ~= nil then
        if not valid_generation(generation) then
            mark_metadata_degraded(dictionary, "cache generation is invalid")
        end
        return
    end

    local candidate, random_error = random_token()
    if not candidate then
        mark_metadata_degraded(dictionary, random_error or "cache generation random source failed")
        return
    end
    local added, add_error, forcible = dictionary:add(generation_key, candidate)
    if forcible then
        mark_metadata_degraded(dictionary, "cache generation caused forcible eviction")
        return
    end
    if not added and add_error ~= "exists" then
        mark_metadata_degraded(dictionary, add_error or "cache generation write failed")
        return
    end
    generation = dictionary:get(generation_key)
    if not valid_generation(generation) then
        mark_metadata_degraded(dictionary, "cache generation is unavailable after initialization")
    end
end

local function private_request()
    if ngx.var.http_authorization ~= nil and ngx.var.http_authorization ~= "" then
        return true
    end
    if ngx.var.http_cookie ~= nil and ngx.var.http_cookie ~= "" then
        return true
    end
    local cache_control = string.lower(ngx.var.http_cache_control or "")
    return cache_control:find("no%-store") ~= nil or cache_control:find("private") ~= nil
end

function _M.access(options)
    ngx.var.cache_freshness_hard_bypass = "0"
    ngx.var.cache_freshness_fail_closed = "0"
    ngx.var.cache_freshness_object_token = ""
    ngx.ctx.cache_freshness_started_at = ngx.now()
    local dictionary = ngx.shared.cache_freshness_meta
    if metadata_degraded or dictionary:get(metadata_degraded_key) then
        fail_closed()
        return
    end
    local generation = dictionary:get(generation_key)
    if not valid_generation(generation) then
        mark_metadata_degraded(dictionary, "cache generation is missing or invalid")
        fail_closed()
        return
    end
    ngx.var.cache_freshness_generation = generation
    ngx.ctx.cache_freshness_key = digest(generation .. "|" .. options.identity)
    if not ngx.ctx.cache_freshness_key then
        mark_metadata_degraded(dictionary, "cache identity digest failed")
        fail_closed()
        return
    end
    if options.request_bypass then
        ngx.ctx.cache_freshness_reason = private_request() and "cache_private_bypass" or "cache_request_bypass"
        return
    end
    local current_key = current_prefix .. ngx.ctx.cache_freshness_key
    for _ = 1, 4 do
        local token = dictionary:get(current_key)
        if token ~= nil and not valid_generation(token) then
            mark_metadata_degraded(dictionary, "cache object current token is invalid")
            fail_closed()
            return
        end
        if token == nil then
            token = transition_token(dictionary, ngx.ctx.cache_freshness_key, nil, options)
            if not token then
                fail_closed()
                return
            end
        end

        local record_key = object_record_key(ngx.ctx.cache_freshness_key, token)
        local encoded_record = dictionary:get(record_key)
        if encoded_record == nil then
            token = transition_token(dictionary, ngx.ctx.cache_freshness_key, token, options)
            if not token then
                fail_closed()
                return
            end
        else
            local kind, stored_at = decode_record(encoded_record, token)
            if not kind then
                mark_metadata_degraded(dictionary, "cache object record is invalid")
                fail_closed()
                return
            end
            if kind == "pending" then
                local encoded_completed = dictionary:get(completed_record_key(ngx.ctx.cache_freshness_key, token))
                if encoded_completed ~= nil then
                    local completed_at = decode_completed_record(encoded_completed, token)
                    if not completed_at then
                        mark_metadata_degraded(dictionary, "cache object completed record is invalid")
                        fail_closed()
                        return
                    end
                    local now = ngx.now()
                    local fresh_seconds = object_fresh_seconds(dictionary, ngx.ctx.cache_freshness_key, token, options)
                    if fresh_seconds == nil or now < completed_at or now >= completed_at + fresh_seconds + options.stale_seconds then
                        local next_token = transition_token(dictionary, ngx.ctx.cache_freshness_key, token, options)
                        if not next_token then
                            fail_closed()
                            return
                        end
                        ngx.ctx.cache_freshness_hard_refresh = true
                        ngx.ctx.cache_freshness_reason = "stale_hard_limit_reached"
                    else
                        ngx.var.cache_freshness_object_token = token
                        ngx.ctx.cache_freshness_object_token = token
                        return
                    end
                else
                    use_pending_namespace(dictionary, ngx.ctx.cache_freshness_key, token, options)
                    return
                end
            end

            if kind ~= "pending" then
                ngx.var.cache_freshness_object_token = token
                ngx.ctx.cache_freshness_object_token = token
                if kind == "blocked" then
                    local current_renewed, current_renew_error = dictionary:expire(current_key, options.metadata_ttl_seconds)
                    local record_renewed, record_renew_error = dictionary:expire(record_key, options.metadata_ttl_seconds)
                    if not current_renewed or not record_renewed then
                        mark_metadata_degraded(
                            dictionary,
                            current_renew_error or record_renew_error or "blocked metadata disappeared"
                        )
                        fail_closed()
                        return
                    end
                    ngx.ctx.cache_freshness_reason = "cache_private_bypass"
                    ngx.ctx.cache_freshness_blocked = true
                    ngx.var.cache_freshness_hard_bypass = "1"
                    return
                end

                ngx.ctx.cache_freshness_had_metadata = true
                local now = ngx.now()
                local fresh_seconds = object_fresh_seconds(dictionary, ngx.ctx.cache_freshness_key, token, options)
                if fresh_seconds == nil or now < stored_at or now >= stored_at + fresh_seconds + options.stale_seconds then
                    local next_token = transition_token(dictionary, ngx.ctx.cache_freshness_key, token, options)
                    if not next_token then
                        fail_closed()
                        return
                    end
                    ngx.ctx.cache_freshness_hard_refresh = true
                    ngx.ctx.cache_freshness_reason = "stale_hard_limit_reached"
                else
                    local current_renewed, current_renew_error = dictionary:expire(current_key, options.metadata_ttl_seconds)
                    local record_renewed, record_renew_error = dictionary:expire(record_key, options.metadata_ttl_seconds)
                    if not current_renewed or not record_renewed then
                        mark_metadata_degraded(
                            dictionary,
                            current_renew_error or record_renew_error or "freshness metadata disappeared"
                        )
                        fail_closed()
                    end
                    return
                end
            end
        end
    end
    mark_metadata_degraded(dictionary, "cache object state did not converge")
    fail_closed()
end

local function lock_timeout_fallback(options)
    local started_at = ngx.ctx.cache_freshness_started_at
    if not started_at or not options.lock_timeout_seconds then
        return false
    end
    return ngx.now() - started_at + 0.01 >= options.lock_timeout_seconds
end

local function response_is_private()
    if ngx.var.upstream_http_set_cookie ~= nil and ngx.var.upstream_http_set_cookie ~= "" then
        return true
    end
    local cache_control = string.lower(ngx.var.upstream_http_cache_control or "")
    if cache_control:find("private") or cache_control:find("no%-store") or cache_control:find("no%-cache") then
        return true
    end
    return (ngx.var.upstream_http_vary or ""):match("^%s*%*%s*$") ~= nil
end

local function response_validator()
    local values = {}
    local present = false
    for _, name in ipairs({ "ETag", "Last-Modified", "Content-Length", "Date" }) do
        local value = ngx.header[name]
        if type(value) == "table" then
            value = table.concat(value, "\0")
        end
        value = value == nil and "" or tostring(value)
        if value ~= "" then
            present = true
        end
        values[#values + 1] = name .. "=" .. value
    end
    if not present then
        return nil
    end
    return digest(table.concat(values, "\n"))
end

local function promote_completed(dictionary, key, token, current_key, options, validator)
    local completed_key = completed_record_key(key, token)
    local encoded_completed = dictionary:get(completed_key)
    if encoded_completed == nil then
        local record_key = object_record_key(key, token)
        local kind = decode_record(dictionary:get(record_key), token)
        if kind ~= "stored" or not validator then
            return true
        end
        local validator_key = validator_record_key(key, token)
        local stored_validator = dictionary:get(validator_key)
        if stored_validator == nil then
            return set_metadata(dictionary, validator_key, validator, options.metadata_ttl_seconds)
        end
        if not valid_generation(stored_validator) then
            mark_metadata_degraded(dictionary, "cache object validator is invalid after hit")
            return false
        end
        if stored_validator == validator then
            return true
        end
        if not set_metadata(dictionary, validator_key, validator, options.metadata_ttl_seconds) then
            return false
        end
        if not set_metadata(dictionary, record_key, stored_record(token, ngx.now()), options.metadata_ttl_seconds) then
            return false
        end
        local renewed, renew_error = dictionary:expire(current_key, options.metadata_ttl_seconds)
        if not renewed then
            mark_metadata_degraded(dictionary, renew_error or "cache object current token disappeared after refresh hit")
            return false
        end
        return true
    end
    local completed_at, completed_validator, completed_source = decode_completed_record(encoded_completed, token)
    if not completed_at or ngx.now() < completed_at then
        mark_metadata_degraded(dictionary, "cache object completed record is invalid after hit")
        return false
    end
    local record_key = object_record_key(key, token)
    local kind, stored_at = decode_record(dictionary:get(record_key), token)
    if not kind then
        mark_metadata_degraded(dictionary, "cache object record is invalid after hit")
        return false
    end
    if kind == "blocked" then
        dictionary:delete(completed_key)
        return true
    end
    if validator ~= completed_validator then
        if kind == "stored" then
            dictionary:delete(completed_key)
            return true
        end
        if completed_source == "head" or not valid_generation(validator) then
            return true
        end
        completed_at = ngx.now()
        completed_validator = validator
    end
    if kind == "stored" and stored_at >= completed_at then
        dictionary:delete(completed_key)
        return true
    end
    if not set_metadata(dictionary, validator_record_key(key, token), validator, options.metadata_ttl_seconds) then
        return false
    end
    if not set_metadata(dictionary, record_key, stored_record(token, completed_at), options.metadata_ttl_seconds) then
        return false
    end
    local renewed, renew_error = dictionary:expire(current_key, options.metadata_ttl_seconds)
    if not renewed then
        mark_metadata_degraded(dictionary, renew_error or "cache object current token disappeared after hit")
        return false
    end
    dictionary:delete(completed_key)
    return true
end

function _M.header_filter(options)
    local dictionary = ngx.shared.cache_freshness_meta
    local generation = ngx.var.cache_freshness_generation
    local key = ngx.ctx.cache_freshness_key
    local token = ngx.ctx.cache_freshness_object_token or ngx.var.cache_freshness_object_token
    if not key and valid_generation(generation) then
        key = digest(generation .. "|" .. options.identity)
    end
    if not key then
        fail_closed()
        ngx.header["X-CDNCA-Cache-Reason"] = "stale_hard_limit_reached"
        ngx.header["X-CDNCA-Cache-State"] = "expired"
        return
    end
    local status = ngx.var.upstream_cache_status or ""
    local reason = ngx.ctx.cache_freshness_reason
    local degraded = metadata_degraded or dictionary:get(metadata_degraded_key)
    local validator = response_validator()

    local hard_refresh = status == "BYPASS" and ngx.ctx.cache_freshness_hard_refresh and not degraded
    local blocked_refresh = status == "BYPASS" and ngx.ctx.cache_freshness_blocked and not degraded
    local upstream_response = status == "MISS" or status == "EXPIRED" or status == "REVALIDATED" or hard_refresh or blocked_refresh
    local unsafe_response = options.validator_bypass or options.vary_bypass
    local response_bypass = options.response_bypass or unsafe_response or response_is_private()
    local origin_freshness
    if upstream_response and options.follow_origin_headers then
        origin_freshness = parse_origin_freshness(options.fresh_seconds)
        if not origin_freshness then
            reject_origin_freshness("origin_headers_invalid")
            response_bypass = true
            reason = "origin_headers_invalid"
        elseif origin_freshness.uncacheable then
            reject_origin_freshness("origin_headers_uncacheable")
            response_bypass = true
            reason = "origin_headers_uncacheable"
        elseif origin_freshness.force_expired then
            reject_origin_freshness("cache_miss")
            response_bypass = true
            reason = "cache_miss"
        end
    end
    local current_key = current_prefix .. key
    local current = dictionary:get(current_key)
    if current ~= nil and not valid_generation(current) then
        mark_metadata_degraded(dictionary, "cache object current token is invalid after response")
        fail_closed()
        degraded = true
        reason = "stale_hard_limit_reached"
    end

    if status == "HIT" and unsafe_response then
        if current == token and valid_generation(token) then
            transition_token(dictionary, key, token, options)
        end
        fail_closed()
        reason = "stale_hard_limit_reached"
        ngx.status = 503
        ngx.header["Content-Length"] = nil
        ngx.ctx.cache_freshness_drop_body = true
    elseif status == "HIT" and current == token and valid_generation(token) then
        if not promote_completed(dictionary, key, token, current_key, options, validator) then
            fail_closed()
            degraded = true
            reason = "stale_hard_limit_reached"
        end
    end

    if upstream_response and response_bypass then
        if current == token and valid_generation(token) then
            dictionary:delete(completed_record_key(key, token))
        end
        if current == token and (ngx.ctx.cache_freshness_had_metadata or ngx.ctx.cache_freshness_blocked) then
            if not valid_generation(token) or not set_metadata(
                dictionary,
                object_record_key(key, token),
                blocked_record(token),
                options.metadata_ttl_seconds
            ) then
                fail_closed()
                reason = "stale_hard_limit_reached"
            end
        end
        if reason == nil then
            if ngx.status >= 500 then
                reason = "origin_error"
            else
                reason = "cache_private_bypass"
            end
        end
	elseif ngx.status == 200 and upstream_response then
        if not valid_generation(token) then
            mark_metadata_degraded(dictionary, "cache object token is unavailable after fill")
            fail_closed()
            reason = "stale_hard_limit_reached"
		elseif current == token then
			if origin_freshness and not set_metadata(
				dictionary,
				freshness_record_key(key, token),
				tostring(origin_freshness.fresh_seconds),
				options.metadata_ttl_seconds
			) then
				fail_closed()
				reason = "stale_hard_limit_reached"
			end
            local record_key = object_record_key(key, token)
            local encoded_record = dictionary:get(record_key)
            if encoded_record ~= nil then
                local kind = decode_record(encoded_record, token)
                if not kind then
                    mark_metadata_degraded(dictionary, "cache object record is invalid after response")
                    fail_closed()
                    reason = "stale_hard_limit_reached"
                elseif kind ~= "blocked" then
                    local content_length = ngx.var.upstream_http_content_length
                    local expected_length = nil
                    if content_length ~= nil and content_length ~= "" then
                        expected_length = tonumber(content_length)
                        if expected_length == nil or expected_length < 0 or expected_length ~= math.floor(expected_length) then
                            expected_length = false
                        end
                    end
                    ngx.ctx.cache_freshness_completion_key = completed_record_key(key, token)
                    ngx.ctx.cache_freshness_completion_validator = validator
                    ngx.ctx.cache_freshness_completion_token = token
                    ngx.ctx.cache_freshness_completion_current_key = current_key
                    ngx.ctx.cache_freshness_completion_record_key = record_key
                    ngx.ctx.cache_freshness_completion_ttl = options.metadata_ttl_seconds
                    ngx.ctx.cache_freshness_completion_expected_length = expected_length
                    ngx.ctx.cache_freshness_completion_bytes = 0
                    ngx.ctx.cache_freshness_head_fill = ngx.var.request_method == "HEAD"
                end
            end
        end
    end

    if reason == nil then
        if ngx.ctx.cache_freshness_follower and status == "HIT" then
            reason = "coalesced_follower"
        elseif ngx.ctx.cache_freshness_follower and status == "MISS" and lock_timeout_fallback(options) then
            reason = "coalesce_timeout_fallback"
        elseif status == "HIT" or status == "REVALIDATED" then
            reason = "cache_fresh_hit"
        elseif status == "STALE" or status == "UPDATING" then
            reason = "stale_served_revalidate"
        elseif ngx.status >= 500 then
            reason = "origin_error"
        else
            reason = "cache_miss"
        end
    end

    ngx.header["X-CDNCA-Cache-Reason"] = reason
    ngx.header["X-CDNCA-Cache-State"] = state_for_reason(reason)
    ngx.header["X-CDNCA-Cache-Policy"] = ngx.var.cache_freshness_policy_version
    ngx.header["X-CDNCA-Cache-Status"] = status
end

function _M.body_filter()
    if ngx.ctx.cache_freshness_drop_body then
        ngx.arg[1] = nil
        ngx.arg[2] = true
        return
    end
    if not ngx.ctx.cache_freshness_completion_key then
        return
    end
    local chunk = ngx.arg[1]
    if type(chunk) == "string" then
        ngx.ctx.cache_freshness_completion_bytes = ngx.ctx.cache_freshness_completion_bytes + #chunk
    end
    if ngx.arg[2] then
        local expected = ngx.ctx.cache_freshness_completion_expected_length
        if expected ~= false and (expected == nil or ngx.ctx.cache_freshness_completion_bytes == expected) then
            ngx.ctx.cache_freshness_body_complete = true
        end
    end
end

function _M.log(_)
    if ngx.ctx.cache_freshness_body_complete or ngx.ctx.cache_freshness_head_fill then
        local dictionary = ngx.shared.cache_freshness_meta
        local token = ngx.ctx.cache_freshness_completion_token
        local current = dictionary:get(ngx.ctx.cache_freshness_completion_current_key)
        local kind = decode_record(dictionary:get(ngx.ctx.cache_freshness_completion_record_key), token)
        local validator = ngx.ctx.cache_freshness_completion_validator
        if current == token and (kind == "pending" or kind == "stored") and valid_generation(validator) then
            local added, add_error, forcible = dictionary:add(
                ngx.ctx.cache_freshness_completion_key,
                completed_record(token, ngx.now(), validator, ngx.ctx.cache_freshness_head_fill and "head" or "body"),
                ngx.ctx.cache_freshness_completion_ttl
            )
            if forcible then
                mark_metadata_degraded(dictionary, "cache object completion candidate caused forcible eviction")
            elseif not added and add_error ~= "exists" then
                mark_metadata_degraded(dictionary, add_error or "cache object completion candidate write failed")
            end
        end
    end
    if ngx.ctx.cache_freshness_active_owner and ngx.ctx.cache_freshness_active_key then
        ngx.shared.cache_freshness_meta:delete(ngx.ctx.cache_freshness_active_key)
    end
end

return _M
