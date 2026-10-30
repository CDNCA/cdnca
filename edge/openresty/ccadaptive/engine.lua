local cjson = require "cjson.safe"
local resty_lock = require "resty.lock"
local resty_sha256 = require "resty.sha256"
local resty_string = require "resty.string"

local _M = {}
local active
local state_dict_name
local lock_dict_name
local model_dict_name
local active_path
local active_digest
local fallback_path

local ACTIVE_POLICY_KEY = "ccadaptive:active-policy"
local ACTIVE_POLICY_LOCK_KEY = "lock:ccadaptive:active-policy"
local MAX_POLICY_PATH_BYTES = 4096

local MAX_SAFE_INTEGER = 9007199254740991
local MICROS_PER_SECOND = 1000000
local MAX_ADAPTIVE_SAMPLE = math.floor(MAX_SAFE_INTEGER / MICROS_PER_SECOND)
local MAX_POLICY_BYTES = 1048576

local function integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum
end

local function identifier(value)
    return type(value) == "string" and #value >= 1 and #value <= 128 and
        value:match("^[A-Za-z0-9][A-Za-z0-9._:-]*$") ~= nil
end

local function digest(value)
    return type(value) == "string" and #value == 64 and value:match("^[0-9a-f]+$") ~= nil
end

local function has_only(value, fields)
    if type(value) ~= "table" then
        return false
    end
    for key in pairs(value) do
        if type(key) ~= "string" or not fields[key] then
            return false
        end
    end
    return true
end

local function validate_limit(value)
    return has_only(value, { rate_per_second = true, burst = true }) and
        integer(value.rate_per_second, 1, 1000000) and integer(value.burst, 1, 1000000)
end

local function validate_adaptive(value)
    if not has_only(value, {
        mode = true, auto_approved = true, frozen = true, fallback = true,
        min_samples = true, max_samples = true,
        sample_freshness_micros = true, ewma_alpha_permille = true,
        mad_multiplier_milli = true, min_rate_per_second = true, max_rate_per_second = true,
        min_burst = true, max_burst = true, max_step_permille = true,
        hysteresis_permille = true, cooldown_micros = true, max_groups = true,
    }) then
        return false
    end
    if value.mode ~= "shadow" and value.mode ~= "auto" then
        return false
    end
    if value.mode == "auto" and value.auto_approved ~= true then
        return false
    end
    if value.mode == "shadow" and value.auto_approved == true then
        return false
    end
    if value.auto_approved ~= nil and type(value.auto_approved) ~= "boolean" then
        return false
    end
    if value.frozen ~= nil and type(value.frozen) ~= "boolean" then
        return false
    end
    if value.fallback ~= "static" then
        return false
    end
    return integer(value.min_samples, 3, 4096) and
        integer(value.max_samples, value.min_samples, 4096) and
        integer(value.sample_freshness_micros, 1000000, MAX_SAFE_INTEGER) and
        integer(value.ewma_alpha_permille, 1, 1000) and
        integer(value.mad_multiplier_milli, 1000, 10000) and
        integer(value.min_rate_per_second, 1, 1000000) and
        integer(value.max_rate_per_second, value.min_rate_per_second, 1000000) and
        integer(value.min_burst, 1, 1000000) and
        integer(value.max_burst, value.min_burst, 1000000) and
        integer(value.max_step_permille, 1, 1000) and
        integer(value.hysteresis_permille, 0, 1000) and
        integer(value.cooldown_micros, 0, MAX_SAFE_INTEGER) and
        integer(value.max_groups, 1, 100000)
end

local function validate_policy(value)
    if not has_only(value, {
        schema_version = true, revision = true, enabled = true, mode = true,
        static = true, adaptive = true,
    }) or value.schema_version ~= "cdnca.edge.cc-adaptive/v1" or
        not integer(value.revision, 1, MAX_SAFE_INTEGER) or value.enabled ~= true or
        not validate_limit(value.static) then
        return nil, "invalid CC adaptive policy header or static limit"
    end
    if value.mode == "simple" then
        if value.adaptive ~= nil then
            return nil, "simple mode must not contain adaptive settings"
        end
    elseif value.mode == "expert" then
        if not validate_adaptive(value.adaptive) then
            return nil, "expert adaptive settings are invalid"
        end
    else
        return nil, "mode must be simple or expert"
    end
    return value
end

local function read_file(path)
    local file, open_error = io.open(path, "rb")
    if not file then
        return nil, open_error
    end
    local raw = file:read(MAX_POLICY_BYTES + 1)
    file:close()
    if not raw or #raw < 1 or #raw > MAX_POLICY_BYTES then
        return nil, "policy size is invalid"
    end
    return raw
end

local function lock_for(key)
    local lock, create_error = resty_lock:new(lock_dict_name, { timeout = 0.05, exptime = 0.2 })
    if not lock then
        return nil, create_error
    end
    local elapsed, lock_error = lock:lock(key)
    if not elapsed then
        return nil, lock_error
    end
    return lock
end

local function unlock(lock)
    if lock then
        lock:unlock()
    end
end

local function key_fields(value, include_scope)
    if type(value) ~= "table" or not identifier(value.tenant_id) or not identifier(value.site_id) or
        not identifier(value.rule_id) then
        return false
    end
    if include_scope and (not identifier(value.key_scope) or not digest(value.key_digest)) then
        return false
    end
    return true
end

local function encoded_field(value)
    return tostring(#value) .. ":" .. value
end

local function sha256_hex(value)
    local hash = resty_sha256:new()
    if not hash or not hash:update(value) then
        return nil
    end
    local final = hash:final()
    return final and resty_string.to_hex(final) or nil
end

local function gcra_key(request, policy, policy_digest)
    return "ccadaptive:gcra:" .. encoded_field(string.format("%.0f", policy.revision)) ..
        encoded_field(policy_digest) ..
        encoded_field(request.tenant_id) .. encoded_field(request.site_id) .. encoded_field(request.rule_id) ..
        encoded_field(request.key_scope) .. encoded_field(request.key_digest)
end

local function model_prefix(policy, policy_digest)
    return "ccadaptive:model:" .. encoded_field(string.format("%.0f", policy.revision)) ..
        encoded_field(policy_digest)
end

local function model_key(request, prefix)
    return prefix .. encoded_field(request.tenant_id) ..
        encoded_field(request.site_id) .. encoded_field(request.rule_id)
end

local function active_policy_record(revision, path, policy_digest)
    return string.format("%.0f", revision) .. ":" .. encoded_field(path) .. ":" .. policy_digest
end

local function parse_active_policy_record(record)
    if type(record) ~= "string" then
        return nil
    end
    local revision_text, length_text, remainder = record:match("^(%d+):(%d+):(.*)$")
    local revision = tonumber(revision_text)
    local length = tonumber(length_text)
    if not integer(revision, 1, MAX_SAFE_INTEGER) or not integer(length, 1, MAX_POLICY_PATH_BYTES) or
        #remainder ~= length + 65 then
        return nil
    end
    local path = remainder:sub(1, length)
    local policy_digest = remainder:sub(length + 2)
    if path:sub(1, 1) ~= "/" or remainder:sub(length + 1, length + 1) ~= ":" or
        not digest(policy_digest) then
        return nil
    end
    return revision, path, policy_digest
end

local function sync_active_policy()
    if not state_dict_name or not ngx.shared[state_dict_name] then
        return false, active and "limiter_state_unavailable" or "invalid_input"
    end
    local record = ngx.shared[state_dict_name]:get(ACTIVE_POLICY_KEY)
    if not record then
        return false, active and "limiter_state_unavailable" or "invalid_input"
    end
    local revision, path, policy_digest = parse_active_policy_record(record)
    if not revision then
        return false, "limiter_state_unavailable"
    end
    local raw = read_file(path)
    if not raw or sha256_hex(raw) ~= policy_digest then
        return false, "limiter_state_unavailable"
    end
    if ngx.shared[state_dict_name]:get(ACTIVE_POLICY_KEY) ~= record then
        return false, "limiter_state_unavailable"
    end
    if active and active.revision == revision and active_path == path and active_digest == policy_digest then
        return true
    end
    local decoded = cjson.decode(raw)
    local candidate = decoded and validate_policy(decoded) or nil
    if not candidate or candidate.revision ~= revision then
        return false, "limiter_state_unavailable"
    end
    active = candidate
    active_path = path
    active_digest = policy_digest
    return true
end

local function result(outcome, reason, retry, remaining, next_eligible)
    return {
        outcome = outcome,
        reason = reason,
        retry_after_micros = retry or 0,
        remaining = remaining or 0,
        next_eligible_micros = next_eligible or 0,
    }
end

local function fallback(reason)
    return result("fallback", reason)
end

local function safe_add(left, right)
    if right < 0 or left > MAX_SAFE_INTEGER - right then
        return nil
    end
    return left + right
end

local function ceil_divide(numerator, denominator)
    return math.floor(numerator / denominator) + (numerator % denominator == 0 and 0 or 1)
end

local function state_ttl(limit)
    local drain_micros = ceil_divide(limit.burst * MICROS_PER_SECOND, limit.rate_per_second)
    return math.max(60, math.min(14 * 86400, math.ceil(drain_micros / MICROS_PER_SECOND) + 60))
end

local function model_ttl(config)
    return math.max(1, math.ceil(config.sample_freshness_micros / MICROS_PER_SECOND) * 4)
end

local function model_count(dictionary, prefix)
    local count = 0
    for _, key in ipairs(dictionary:get_keys(0)) do
        if key:sub(1, #prefix) == prefix then
            count = count + 1
        end
    end
    return count
end

function _M.init(options)
    if type(options) ~= "table" or type(options.state_dict) ~= "string" or
        type(options.lock_dict) ~= "string" or type(options.model_dict) ~= "string" or
        not ngx.shared[options.state_dict] or not ngx.shared[options.lock_dict] or not ngx.shared[options.model_dict] then
        return nil, "invalid CC adaptive engine options"
    end
    state_dict_name = options.state_dict
    lock_dict_name = options.lock_dict
    model_dict_name = options.model_dict
    if options.policy_path then
        local policy_path = options.policy_path
        fallback_path = type(policy_path) == "string" and policy_path:match("^(.*)/[^/]+$") or nil
        fallback_path = fallback_path and fallback_path .. "/fallback.json" or nil
        local revision, load_error = _M.load(policy_path)
        if not revision and not active and fallback_path then
            local fallback_revision, fallback_error = _M.load(fallback_path)
            if fallback_revision then
                return fallback_revision
            end
            return nil, fallback_error or load_error
        end
        return revision, load_error
    end
    return true
end

function _M.load(path)
    if type(path) ~= "string" or #path < 1 or #path > MAX_POLICY_PATH_BYTES or path:sub(1, 1) ~= "/" then
        return nil, "policy path must be absolute"
    end
    local raw, read_error = read_file(path)
    if not raw then
        return nil, read_error
    end
    local decoded, decode_error = cjson.decode(raw)
    if not decoded then
        return nil, decode_error
    end
    local candidate, validation_error = validate_policy(decoded)
    if not candidate then
        return nil, validation_error
    end
    local candidate_digest = sha256_hex(raw)
    if not candidate_digest then
        return nil, "limiter_state_unavailable"
    end
    local state_dictionary = state_dict_name and ngx.shared[state_dict_name] or nil
    if not state_dictionary then
        return nil, "limiter_state_unavailable"
    end
    local lock = lock_for(ACTIVE_POLICY_LOCK_KEY)
    if not lock then
        return nil, "limiter_state_unavailable"
    end
    local record = state_dictionary:get(ACTIVE_POLICY_KEY)
    local active_revision, _, stored_digest = parse_active_policy_record(record)
    if active_revision and active_revision == candidate.revision and stored_digest ~= candidate_digest then
        unlock(lock)
        return nil, "activation_conflict"
    end
    if active and active.revision == candidate.revision and active_digest and active_digest ~= candidate_digest then
        unlock(lock)
        return nil, "activation_conflict"
    end
    local stored = state_dictionary:safe_set(
        ACTIVE_POLICY_KEY, active_policy_record(candidate.revision, path, candidate_digest), 0)
    unlock(lock)
    if not stored then
        return nil, "limiter_state_unavailable"
    end
    active = candidate
    active_path = path
    active_digest = candidate_digest
    return active.revision
end

function _M.policy_revision()
    local synced = sync_active_policy()
    if not synced then
        return 0
    end
    return active and active.revision or 0
end

function _M.decide(request)
    local synced, sync_error = sync_active_policy()
    if not synced then
        return fallback(sync_error or "limiter_state_unavailable")
    end
    local policy, policy_digest = active, active_digest
    if not policy or not key_fields(request, true) then
        return fallback("invalid_input")
    end
    local limit = request.limit or policy.static
    if not validate_limit(limit) or not integer(request.cost, 1, limit.burst) or
        not integer(request.now_micros, 0, MAX_SAFE_INTEGER) or
        limit.rate_per_second > policy.static.rate_per_second or limit.burst > policy.static.burst then
        return fallback("invalid_input")
    end
    local capacity_debt = limit.burst * MICROS_PER_SECOND
    local cost_debt = request.cost * MICROS_PER_SECOND
    local key = gcra_key(request, policy, policy_digest)
    local lock, lock_error = lock_for("lock:" .. key)
    if not lock then
        return fallback("limiter_state_unavailable")
    end
    local state = ngx.shared[state_dict_name]:get(key)
    local debt = 0
    local last_now = 0
    if state ~= nil then
        if type(state) ~= "string" then
            unlock(lock)
            return fallback("limiter_state_unavailable")
        end
        local stored_debt, stored_now = state:match("^(%d+):(%d+)$")
        debt = tonumber(stored_debt)
        last_now = tonumber(stored_now)
        if not integer(debt, 0, capacity_debt) or not integer(last_now, 0, MAX_SAFE_INTEGER) then
            unlock(lock)
            return fallback("limiter_state_unavailable")
        end
    end
    if request.now_micros < last_now then
        unlock(lock)
        return fallback("clock_regression")
    end
    local elapsed = request.now_micros - last_now
    if debt > 0 and elapsed > 0 then
        if elapsed >= ceil_divide(debt, limit.rate_per_second) then
            debt = 0
        else
            debt = debt - elapsed * limit.rate_per_second
        end
    end
    local candidate = debt + cost_debt
    local stored_debt = candidate <= capacity_debt and candidate or debt
    local stored, store_error = ngx.shared[state_dict_name]:safe_set(
        key, string.format("%.0f:%.0f", stored_debt, request.now_micros), state_ttl(limit))
    if not stored then
        unlock(lock)
        return fallback("limiter_state_unavailable")
    end
    unlock(lock)
    if candidate > capacity_debt then
        local retry = ceil_divide(candidate - capacity_debt, limit.rate_per_second)
        local next_eligible = safe_add(request.now_micros, retry) or MAX_SAFE_INTEGER
        return result("deny", "gcra_limit_applied", retry, 0, next_eligible)
    end
    local next_wait = 0
    if candidate + MICROS_PER_SECOND > capacity_debt then
        next_wait = ceil_divide(candidate + MICROS_PER_SECOND - capacity_debt, limit.rate_per_second)
    end
    local next_eligible = safe_add(request.now_micros, next_wait) or MAX_SAFE_INTEGER
    return result("allow", "gcra_limit_applied", 0,
        math.floor((capacity_debt - candidate) / MICROS_PER_SECOND), next_eligible)
end

local function median(values)
    table.sort(values)
    local middle = math.floor(#values / 2) + 1
    if #values % 2 == 1 then
        return values[middle]
    end
    return values[middle - 1] + math.floor((values[middle] - values[middle - 1]) / 2)
end

local function clamp(value, minimum, maximum)
    if value < minimum then
        return minimum, true
    end
    if value > maximum then
        return maximum, true
    end
    return value, false
end

local function difference(left, right)
    return math.abs(left - right)
end

local function fallback_suggestion(baseline, reason)
    return {
        rate_per_second = baseline.rate_per_second, burst = baseline.burst,
        confidence_permille = 0, reason = reason, apply = false, fact = "fallback",
    }
end

local function decode_model_state(encoded, config, baseline)
    if type(encoded) ~= "string" then
        return nil
    end
    local state = cjson.decode(encoded)
    if not has_only(state, {
        rates = true, ewma = true, last_sample = true, current_rate = true,
        current_burst = true, last_change = true, frozen = true, capped = true,
    }) or type(state.rates) ~= "table" or
        not integer(state.ewma, 1, config.max_rate_per_second) or
        not integer(state.last_sample, 0, MAX_SAFE_INTEGER) or
        not integer(state.current_rate, 1, baseline.rate_per_second) or
        not integer(state.current_burst, 1, baseline.burst) or
        not integer(state.last_change, 0, state.last_sample) or
        type(state.frozen) ~= "boolean" or type(state.capped) ~= "boolean" then
        return nil
    end
    local count = 0
    for index, rate in pairs(state.rates) do
        if not integer(index, 1, config.max_samples) or
            not integer(rate, 1, config.max_rate_per_second) then
            return nil
        end
        count = count + 1
    end
    if count < 1 or count ~= #state.rates then
        return nil
    end
    return state
end

local function suggestion(config, state, baseline, now_micros)
    if now_micros < state.last_sample then
        return fallback_suggestion(baseline, "clock_regression")
    end
    if config.frozen == true or state.frozen then
        return fallback_suggestion(baseline, "manual_threshold_frozen")
    end
    if #state.rates < config.min_samples then
        return fallback_suggestion(baseline, "adaptive_insufficient_samples")
    end
    if now_micros - state.last_sample > config.sample_freshness_micros then
        return fallback_suggestion(baseline, "adaptive_baseline_stale")
    end
    local values = {}
    for index, value in ipairs(state.rates) do
        values[index] = value
    end
    local median_rate = median(values)
    local deviations = {}
    for index, value in ipairs(state.rates) do
        deviations[index] = difference(value, median_rate)
    end
    local mad = median(deviations)
    local candidate = median_rate + math.floor((mad * config.mad_multiplier_milli + 999) / 1000)
    candidate = math.max(candidate, state.ewma)
    local capped
    candidate, capped = clamp(candidate, config.min_rate_per_second, config.max_rate_per_second)
    if candidate > baseline.rate_per_second then
        candidate = baseline.rate_per_second
        capped = true
    end
    local burst = baseline.burst
    if candidate < baseline.rate_per_second then
        burst = math.floor((baseline.burst * candidate + baseline.rate_per_second - 1) / baseline.rate_per_second)
    end
    local burst_capped
    burst, burst_capped = clamp(burst, config.min_burst, config.max_burst)
    if burst > baseline.burst then
        burst = baseline.burst
        burst_capped = true
    end
    capped = capped or burst_capped or state.capped

    if config.mode == "auto" then
        if state.current_rate == 0 then
            state.current_rate = candidate
            state.current_burst = burst
        end
        if candidate > state.current_rate then
            candidate = state.current_rate
            capped = true
        end
        if burst > state.current_burst then
            burst = state.current_burst
            capped = true
        end
        if state.last_change ~= 0 and now_micros - state.last_change < config.cooldown_micros then
            candidate = state.current_rate
            burst = state.current_burst
        elseif difference(candidate, state.current_rate) * 1000 <=
            state.current_rate * config.hysteresis_permille then
            candidate = state.current_rate
            burst = state.current_burst
        else
            local step = math.max(1, math.floor(state.current_rate * config.max_step_permille / 1000))
            if candidate + step < state.current_rate then
                candidate = state.current_rate - step
                capped = true
            elseif candidate > state.current_rate + step then
                candidate = state.current_rate + step
                capped = true
            end
            local burst_step = math.max(1, math.floor(state.current_burst * config.max_step_permille / 1000))
            if burst + burst_step < state.current_burst then
                burst = state.current_burst - burst_step
                capped = true
            elseif burst > state.current_burst + burst_step then
                burst = state.current_burst + burst_step
                capped = true
            end
            state.last_change = now_micros
        end
        state.current_rate = candidate
        state.current_burst = burst
    end

    local confidence = math.min(1000, math.floor(#state.rates * 1000 / config.max_samples))
    if config.mode == "shadow" then
        return {
            rate_per_second = candidate, burst = burst, confidence_permille = confidence,
            reason = "adaptive_shadow_only", apply = false, fact = "shadow_suggestion",
        }
    end
    return {
        rate_per_second = candidate, burst = burst, confidence_permille = confidence,
        reason = capped and "adaptive_change_capped" or "gcra_limit_applied",
        apply = true, fact = capped and "auto_clamped" or "static_allow",
    }
end

function _M.observe(request)
    local synced, sync_error = sync_active_policy()
    if not synced then
        return fallback_suggestion(active and active.static or { rate_per_second = 1, burst = 1 },
            sync_error or "limiter_state_unavailable")
    end
    local policy, policy_digest = active, active_digest
    if not policy or not policy.adaptive or not key_fields(request, false) or
        type(request.sample) ~= "table" or
        not integer(request.sample.at_micros, 0, MAX_SAFE_INTEGER) or
        not integer(request.sample.requests, 1, MAX_ADAPTIVE_SAMPLE) or
        not integer(request.sample.window_micros, 1, MAX_ADAPTIVE_SAMPLE) then
        return fallback_suggestion(policy and policy.static or { rate_per_second = 1, burst = 1 }, "invalid_input")
    end
    local config = policy.adaptive
    local baseline = policy.static
    if config.frozen == true then
        return fallback_suggestion(baseline, "manual_threshold_frozen")
    end
    local prefix = model_prefix(policy, policy_digest)
    local key = model_key(request, prefix)
    local lock, lock_error = lock_for("lock:" .. key)
    if not lock then
        return fallback_suggestion(baseline, "limiter_state_unavailable")
    end
    local encoded = ngx.shared[model_dict_name]:get(key)
    local state
    local group_lock
    if encoded ~= nil then
        state = decode_model_state(encoded, config, baseline)
        if not state then
            unlock(lock)
            return fallback_suggestion(baseline, "limiter_state_unavailable")
        end
    else
        group_lock = lock_for("lock:__ccadaptive_models")
        if not group_lock then
            unlock(lock)
            return fallback_suggestion(baseline, "limiter_state_unavailable")
        end
        encoded = ngx.shared[model_dict_name]:get(key)
        if encoded ~= nil then
            state = decode_model_state(encoded, config, baseline)
            if not state then
                unlock(group_lock)
                unlock(lock)
                return fallback_suggestion(baseline, "limiter_state_unavailable")
            end
        elseif model_count(ngx.shared[model_dict_name], prefix) >= config.max_groups then
            unlock(group_lock)
            unlock(lock)
            return fallback_suggestion(baseline, "limiter_state_unavailable")
        end
        if not state then
            state = {
                rates = {}, ewma = 0, last_sample = 0, current_rate = baseline.rate_per_second,
                current_burst = baseline.burst, last_change = 0, frozen = false, capped = false,
            }
        end
    end
    if #state.rates > 0 and request.sample.at_micros <= state.last_sample then
        unlock(group_lock)
        unlock(lock)
        return fallback_suggestion(baseline, "clock_regression")
    end
    local rate
    local capped = false
    local maximum_requests = math.floor(config.max_rate_per_second * request.sample.window_micros /
        MICROS_PER_SECOND)
    if request.sample.requests > maximum_requests then
        rate = config.max_rate_per_second
        capped = true
    else
        rate = ceil_divide(request.sample.requests * MICROS_PER_SECOND, request.sample.window_micros)
        rate = math.max(1, rate)
        if rate > config.max_rate_per_second then
            rate = config.max_rate_per_second
            capped = true
        end
    end
    state.capped = state.capped or capped
    state.rates[#state.rates + 1] = rate
    while #state.rates > config.max_samples do
        table.remove(state.rates, 1)
    end
    if state.ewma == 0 then
        state.ewma = rate
    else
        state.ewma = math.floor((config.ewma_alpha_permille * rate +
            (1000 - config.ewma_alpha_permille) * state.ewma + 500) / 1000)
    end
    state.last_sample = request.sample.at_micros
    local proposed = suggestion(config, state, baseline, request.sample.at_micros)
    local stored = ngx.shared[model_dict_name]:safe_set(key, cjson.encode(state), model_ttl(config))
    unlock(group_lock)
    unlock(lock)
    if not stored then
        return fallback_suggestion(baseline, "limiter_state_unavailable")
    end
    return proposed
end

function _M.freeze(request, frozen)
    local synced, sync_error = sync_active_policy()
    if not synced then
        return nil, sync_error or "limiter_state_unavailable"
    end
    local policy, policy_digest = active, active_digest
    if not policy or not policy.adaptive or not key_fields(request, false) or type(frozen) ~= "boolean" then
        return nil, "invalid_input"
    end
    local config = policy.adaptive
    local prefix = model_prefix(policy, policy_digest)
    local key = model_key(request, prefix)
    local lock = lock_for("lock:" .. key)
    if not lock then
        return nil, "limiter_state_unavailable"
    end
    local encoded = ngx.shared[model_dict_name]:get(key)
    if encoded == nil then
        unlock(lock)
        return nil, "adaptive_insufficient_samples"
    end
    local state = decode_model_state(encoded, config, policy.static)
    if not state then
        unlock(lock)
        return nil, "limiter_state_unavailable"
    end
    state.frozen = frozen
    local stored = ngx.shared[model_dict_name]:safe_set(
        key, cjson.encode(state), model_ttl(config))
    unlock(lock)
    if not stored then
        return nil, "limiter_state_unavailable"
    end
    return true
end

return _M
