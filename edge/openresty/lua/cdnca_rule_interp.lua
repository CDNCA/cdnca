-- ACL / WAF security rule interpreter (ADR 0009 §4, dynamic routing D6).
--
-- Executes a rule plan (cdnca.edge.rule-plan/v1, built by
-- libs/edgeconfig CompileSecurityRulePlan / CompileLayeredRulePlan) with the
-- exact semantics of the rewrite_by_lua_block the site renderer generates
-- (libs/edgeconfig renderWAFBlock):
--   * segments run in order; each starts at its default action / default rule
--     id, its rules run in order and the last matching rule wins until a rule
--     with flow "stop" matches (later rules are not evaluated at all);
--   * a segment ending in block exits 403 (later segments do not run), log
--     records telemetry and goes on, allow goes on;
--   * a rule's conditions are an AND chain evaluated left to right with short
--     circuit, so request-body inspection and IP library lookups run exactly
--     when the rendered code runs them.
--
--   local interp = require("cdnca_rule_interp")
--   local program = assert(interp.compile_json(raw))   -- once per plan
--   interp.enforce(program)                            -- rewrite phase
--
-- compile() validates the whole plan and returns nil, reason for anything it
-- does not understand; the caller keeps its last good program (fail closed is
-- the caller's decision). evaluate() decides without side effects on the
-- response (it may read the body for inspect conditions) and returns
-- verdict ("allow" | "block" | "log"), kind, rule_id, except for segments
-- with a WAF v2 action spec: their bans and challenge verification
-- (cdnca_waf.gate) and their verdict (cdnca_waf.act) run in evaluate()
-- exactly where the rendered code runs them.
local cjson = require "cjson.safe"
local bit = require "bit"
local ffi = require "ffi"

local band, bor, lshift = bit.band, bit.bor, bit.lshift
local byte = string.byte
local type, tonumber, ipairs, pairs = type, tonumber, ipairs, pairs
local str_lower = string.lower
local ngx_var = ngx.var
local ngx_req = ngx.req
local ngx_time = ngx.time

-- Own symbol name (redirected to libc memcmp) so no other module's cdef of
-- memcmp can conflict.
ffi.cdef [[ int cdnca_rule_interp_memcmp(const char *s1, const char *s2, size_t n) __asm__("memcmp"); ]]
local memcmp = ffi.C.cdnca_rule_interp_memcmp

local _M = { _VERSION = "1", SCHEMA = "cdnca.edge.rule-plan/v1" }

local MAX_SEGMENTS = 32
local MAX_RULES = 65536
local MAX_CONDITIONS = 16
local MAX_HEADERS = 100
local CONSUME_COLLECT = 8192

-- Condition op codes; a rule's conditions are a flat array, stride 4:
-- [op, a, b, c]; rule.limit is the array length.
local OP_EXPIRES, OP_HOST, OP_PORT, OP_METHOD = 1, 2, 3, 4
local OP_PATH_EXACT, OP_PATH_PREFIX, OP_PATH_RAW = 5, 6, 7
local OP_HEADER_EXISTS, OP_HEADER_EQ = 8, 9
local OP_CIDR4, OP_CIDR6, OP_JA4, OP_IPINTEL, OP_INSPECT = 10, 11, 12, 13, 14
-- cdnca_waf.ip_list (named IP list).
local OP_IPLIST = 15
-- ja4_not_in (WAF_JA4_NEGATION v1); never an index key.
local OP_JA4_NOT = 16

local ACTIONS = { allow = "allow", block = "block", log = "log" }
-- WAF v2 rule actions (edgeconfig waf_action.go): only in segments with an
-- action spec, which cdnca_waf.act carries out.
local SPEC_ACTIONS = { allow = "allow", block = "block", log = "log", challenge = "challenge", ban = "ban" }
local KINDS = { acl = true, waf = true }
local LAYERS = { user = true, developer = true, system = true }
local OVERFLOW = { none = true, block = true, no_match = true }

local function is_string(value, allow_empty)
    return type(value) == "string" and (allow_empty or value ~= "")
end

local function is_integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum
end

-- Prefix mask of one 32-bit word holding `bits` (0..32) leading bits.
local function word_mask(bits)
    if bits <= 0 then return 0 end
    if bits >= 32 then return -1 end
    return lshift(-1, 32 - bits)
end

local function parse_ipv4(text)
    local a, b, c, d = text:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not (a and a <= 255 and b <= 255 and c <= 255 and d <= 255) then return nil end
    return bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
end

-- Canonical (RFC 5952) IPv6 text to four 32-bit words; no embedded IPv4
-- (the compiler rejects 4-in-6 prefixes).
local function parse_ipv6(text)
    if not text:find(":", 1, true) or text:find("[^0-9a-fA-F:]") then return nil end
    local head, tail = text, nil
    local gap = text:find("::", 1, true)
    if gap then
        if text:find("::", gap + 1, true) then return nil end
        head, tail = text:sub(1, gap - 1), text:sub(gap + 2)
    end
    local function groups(part)
        local list = {}
        if part == "" then return list end
        for group in (part .. ":"):gmatch("([^:]*):") do
            if group == "" or #group > 4 then return nil end
            list[#list + 1] = tonumber(group, 16)
        end
        return list
    end
    local first, last = groups(head), groups(tail or "")
    if not first or not last then return nil end
    local missing = 8 - #first - #last
    if (gap and missing < 1) or (not gap and missing ~= 0) then return nil end
    local all = {}
    for _, value in ipairs(first) do all[#all + 1] = value end
    for _ = 1, missing do all[#all + 1] = 0 end
    for _, value in ipairs(last) do all[#all + 1] = value end
    local words = {}
    for index = 0, 3 do
        words[index + 1] = bor(lshift(all[index * 2 + 1], 16), all[index * 2 + 2])
    end
    return words
end

-- One CIDR condition: OP_CIDR4 a = network, b = mask; OP_CIDR6 a = network
-- words, b = mask words. Host bits are masked like nginx geo does.
local function compile_cidr(text)
    if not is_string(text) then return nil end
    local address, bits = text:match("^([^/]+)/(%d+)$")
    bits = tonumber(bits)
    if not address or not bits then return nil end
    local v4 = parse_ipv4(address)
    if v4 then
        if bits > 32 then return nil end
        local mask = word_mask(bits)
        return OP_CIDR4, band(v4, mask), mask
    end
    local v6 = parse_ipv6(address)
    if not v6 or bits > 128 then return nil end
    local network, masks = {}, {}
    for index = 1, 4 do
        masks[index] = word_mask(bits - (index - 1) * 32)
        network[index] = band(v6[index], masks[index])
    end
    return OP_CIDR6, network, masks
end

local function compile_condition(condition, out)
    if type(condition) ~= "table" or not is_string(condition.op) then return "condition" end
    local op, value, number = condition.op, condition.value, condition.number
    local code, a, b, c
    if op == "expires_before" then
        if not is_integer(number, 0, 9007199254740991) then return "expires_before" end
        code, a = OP_EXPIRES, number
    elseif op == "host_eq" then
        if not is_string(value) then return "host_eq" end
        code, a = OP_HOST, value
    elseif op == "port_eq" then
        if not is_integer(number, 1, 65535) then return "port_eq" end
        code, a = OP_PORT, number
    elseif op == "method_eq" then
        if not is_string(value) then return "method_eq" end
        code, a = OP_METHOD, value
    elseif op == "path_exact" then
        if not is_string(value) then return "path_exact" end
        code, a = OP_PATH_EXACT, value
    elseif op == "path_prefix" then
        if not is_string(value) then return "path_prefix" end
        code, a, b, c = OP_PATH_PREFIX, value, value .. "/", #value + 1
    elseif op == "path_raw_prefix" then
        if not is_string(value) then return "path_raw_prefix" end
        code, a, b = OP_PATH_RAW, value, #value
    elseif op == "header_exists" or op == "header_eq" then
        local name = condition.name
        if not is_string(name) or name ~= str_lower(name) then return op end
        if op == "header_exists" then
            code, a = OP_HEADER_EXISTS, name
        else
            if not is_string(value) then return op end
            code, a, b = OP_HEADER_EQ, name, value
        end
    elseif op == "source_cidr" then
        code, a, b = compile_cidr(value)
        if not code then return "source_cidr" end
    elseif op == "ja4_in" or op == "ja4_not_in" then
        local values = condition.values
        if type(values) ~= "table" or #values == 0 then return op end
        local set = {}
        for _, item in ipairs(values) do
            if not is_string(item) then return op end
            set[item] = true
        end
        code, a = op == "ja4_in" and OP_JA4 or OP_JA4_NOT, set
    elseif op == "ip_intel" then
        if not is_string(value) then return "ip_intel" end
        code, a = OP_IPINTEL, value
    elseif op == "inspect" then
        if not is_string(value) then return "inspect" end
        code, a = OP_INSPECT, value
    elseif op == "ip_list" then
        if not is_string(value) then return "ip_list" end
        code, a = OP_IPLIST, value
    else
        return "unknown op " .. op
    end
    local index = #out
    out[index + 1], out[index + 2], out[index + 3], out[index + 4] = code, a or false, b or false, c or false
    return nil, code
end

-- Match index (cdnca.edge.rule-index/v1, libs/rulepack CompileMatchIndex;
-- ADR 0011 §6.5). keys[n] names rule n's key condition (rules numbered in
-- plan order across segments); the request's own values are looked up in
-- hash buckets of pure key conditions, and every inspect clause key of one
-- (target, key, filters) is merged into one Aho-Corasick automaton over its
-- needles. Candidates are verified with their whole chain in rule order, so
-- every decision is the linear interpreter's (the index only skips rules
-- whose chain would fail before any side effect, or at their key inspect).
ffi.cdef [[ typedef struct { const uint8_t *p; } cdnca_rule_interp_bytes; ]]
local INDEX_SCHEMA = "cdnca.edge.rule-index/v1"
local BODY_TARGETS = { args = true, body = true, upload_filename = true, upload_extension = true,
    multipart_field_names = true }
local INDEX_OPERATORS = { contains = true, contains_all = true, equals = true, prefix = true, suffix = true, regex = true }
local LOWER = ffi.new("uint8_t[256]")
for index = 0, 255 do LOWER[index] = (index >= 65 and index <= 90) and index + 32 or index end
local u8p = ffi.typeof("const uint8_t *")

local function bucket_add(map, key, number)
    local list = map[key]
    if not list then
        list = {}
        map[key] = list
    end
    list[#list + 1] = number
end

local re_compile = require("resty.core.regex").re_match_compile
local exec_regex = ffi.C.ngx_http_lua_ffi_exec_regex

-- Needles per PCRE of a group (a larger group is split; a pattern PCRE
-- refuses as too large is split in halves).
local NEEDLES_PER_PATTERN = 4096

local function escape_byte(value)
    if (value >= 48 and value <= 57) or (value >= 97 and value <= 122) then return string.char(value) end
    return string.format("\\x%02x", value)
end

-- alternation is the PCRE of sorted[lo..hi], which share their first depth
-- bytes, as a trie of alternatives: it matches at a position exactly when
-- one of them starts there (a needle ending at depth ends the branch).
local function alternation(sorted, lo, hi, depth)
    for index = lo, hi do
        if #sorted[index] == depth then return "" end
    end
    local parts, index = {}, lo
    while index <= hi do
        local value = byte(sorted[index], depth + 1)
        local last = index
        while last < hi and byte(sorted[last + 1], depth + 1) == value do last = last + 1 end
        parts[#parts + 1] = escape_byte(value) .. alternation(sorted, index, last, depth + 1)
        index = last + 1
    end
    if #parts == 1 then return parts[1] end
    return "(?:" .. table.concat(parts, "|") .. ")"
end

-- patterns compiles needles[lo..hi] (sorted) into caseless JIT PCREs.
local function patterns(sorted, lo, hi, out)
    if hi - lo + 1 <= NEEDLES_PER_PATTERN then
        local compiled, _, flags = re_compile(alternation(sorted, lo, hi, 0), "ji")
        if compiled then
            out[#out + 1] = { compiled, flags }
            return true
        end
        if lo == hi then return false end
    end
    local middle = math.floor((lo + hi) / 2)
    return patterns(sorted, lo, middle, out) and patterns(sorted, middle + 1, hi, out)
end

-- automaton builds the scanner of needles (array of lower-case strings):
-- the trie of the needles in flat FFI arrays (root transitions direct,
-- other states a run of (label, target) edges, out = needle number) and the
-- PCREs that find every position where a needle starts. Returns nil when
-- PCRE refuses a needle.
local function automaton(needles)
    local child, parents, labels, targets = {}, {}, {}, {}
    local states = 1
    local out_needle = {}
    for needle_index, needle in ipairs(needles) do
        local state = 0
        for position = 1, #needle do
            local label = byte(needle, position)
            local key = state * 256 + label
            local target = child[key]
            if not target then
                target, states = states, states + 1
                child[key] = target
                parents[#parents + 1], labels[#labels + 1], targets[#targets + 1] = state, label, target
            end
            state = target
        end
        out_needle[state] = needle_index
    end
    child = nil
    local edges = #parents
    local ac = {
        root = ffi.new("int32_t[256]"), first = ffi.new("int32_t[?]", states + 1),
        label = ffi.new("uint8_t[?]", math.max(edges, 1)), target = ffi.new("int32_t[?]", math.max(edges, 1)),
        out = ffi.new("int32_t[?]", states), states = states, patterns = {},
    }
    local first, label_of, target_of = ac.first, ac.label, ac.target
    for index = 1, edges do first[parents[index] + 1] = first[parents[index] + 1] + 1 end
    for state = 1, states do first[state] = first[state] + first[state - 1] end
    local fill = ffi.new("int32_t[?]", states)
    for index = 1, edges do
        local parent = parents[index]
        local slot = first[parent] + fill[parent]
        fill[parent] = fill[parent] + 1
        label_of[slot], target_of[slot] = labels[index], targets[index]
        if parent == 0 then ac.root[labels[index]] = targets[index] end
    end
    for state, needle_index in pairs(out_needle) do ac.out[state] = needle_index end
    local sorted = {}
    for index, needle in ipairs(needles) do sorted[index] = needle end
    table.sort(sorted)
    if not patterns(sorted, 1, #sorted, ac.patterns) then return nil end
    return ac
end

-- compile_index validates index against the program and builds its tables.
local function base0(key) return (key - 1) * 4 + 1 end

local function compile_index(index, program)
    if type(index) ~= "table" or index.schema ~= INDEX_SCHEMA or type(index.keys) ~= "table" then return "index" end
    local needles_of, seconds_of = index.needles, index.second
    if needles_of ~= nil and type(needles_of) ~= "table" then return "index needles" end
    if seconds_of ~= nil and type(seconds_of) ~= "table" then return "index second" end
    local rules, segment_of = {}, {}
    for segment_index, segment in ipairs(program.segments) do
        segment.first = #rules + 1
        for _, rule in ipairs(segment.rules) do
            rules[#rules + 1] = rule
            segment_of[#rules] = segment_index
        end
        segment.last = #rules
    end
    local keys = index.keys
    if #keys ~= #rules then return "index keys" end
    local built = { rules = rules, unkeyed = {}, host = {}, method = {}, exact = {}, prefix = {}, raw = {},
        raw_lengths = {}, exists = {}, header = {}, port = {}, ja4 = {}, cidr4 = {}, masks4 = {}, cidr6 = {},
        masks6 = {}, groups = {} }
    local groups_by_name = {}
    local any = { host = false, method = false, path = false, port = false, ja4 = false, cidr4 = false, cidr6 = false }
    for number = 1, #rules do
        local rule, key = rules[number], keys[number]
        if not is_integer(key, 0, rule.limit / 4) then return "index key " .. number end
        local conditions = rule.conditions
        if key > 0 then
            for before = 1, key - 1 do
                local op = conditions[(before - 1) * 4 + 1]
                if op == OP_INSPECT or ((op == OP_IPINTEL or op == OP_IPLIST) and conditions[base0(key)] ~= OP_INSPECT) then
                    return "index key " .. number .. " after a side effect"
                end
            end
        end
        local base = (key - 1) * 4 + 1
        local op, a, b, c = conditions[base], conditions[base + 1], conditions[base + 2], conditions[base + 3]
        if key == 0 then
            built.unkeyed[#built.unkeyed + 1] = number
        elseif op == OP_HOST then
            bucket_add(built.host, a, number); any.host = true
        elseif op == OP_METHOD then
            bucket_add(built.method, a, number); any.method = true
        elseif op == OP_PATH_EXACT then
            bucket_add(built.exact, a, number); any.path = true
        elseif op == OP_PATH_PREFIX then
            bucket_add(built.prefix, a, number); any.path = true
        elseif op == OP_PATH_RAW then
            local by_length = built.raw[b]
            if not by_length then
                by_length = {}
                built.raw[b] = by_length
                built.raw_lengths[#built.raw_lengths + 1] = b
            end
            bucket_add(by_length, a, number); any.path = true
        elseif op == OP_HEADER_EXISTS then
            bucket_add(built.exists, a, number)
        elseif op == OP_HEADER_EQ then
            local by_value = built.header[a]
            if not by_value then
                by_value = {}
                built.header[a] = by_value
            end
            bucket_add(by_value, b, number)
        elseif op == OP_PORT then
            bucket_add(built.port, a, number); any.port = true
        elseif op == OP_JA4 then
            for value in pairs(a) do bucket_add(built.ja4, value, number) end
            any.ja4 = true
        elseif op == OP_CIDR4 then
            local by_network = built.cidr4[b]
            if not by_network then
                by_network = {}
                built.cidr4[b] = by_network
                built.masks4[#built.masks4 + 1] = b
            end
            bucket_add(by_network, a, number); any.cidr4 = true
        elseif op == OP_CIDR6 then
            local mask_key = table.concat(b, ":")
            local entry = built.cidr6[mask_key]
            if not entry then
                entry = { masks = b, networks = {} }
                built.cidr6[mask_key] = entry
                built.masks6[#built.masks6 + 1] = entry
            end
            bucket_add(entry.networks, table.concat(a, ":"), number); any.cidr6 = true
        elseif op == OP_INSPECT then
            local needles = needles_of and needles_of[tostring(number)]
            local clause = cjson.decode(a)
            if type(needles) ~= "table" or #needles == 0 or type(clause) ~= "table" or
                not INDEX_OPERATORS[clause.operator] or clause.body_overflow ~= nil or
                type(clause.target) ~= "string" then
                return "index key " .. number .. " inspect"
            end
            local filters = type(clause.filters) == "table" and clause.filters or {}
            for _, filter in ipairs(filters) do
                if filter == "length" then return "index key " .. number .. " inspect" end
            end
            local name = clause.target .. "\0" .. (clause.key or "") .. "\0" .. table.concat(filters, ",")
            local group = groups_by_name[name]
            if not group then
                group = { spec = { target = clause.target, key = clause.key, filters = clause.filters },
                    body = BODY_TARGETS[clause.target] or false, members = {}, member_key = {},
                    needle_rules = {}, needle_index = {}, needles = {}, second = {} }
                groups_by_name[name] = group
                built.groups[#built.groups + 1] = group
            end
            group.members[#group.members + 1] = number
            group.member_key[number] = key
            local function slot_of(needle)
                if not is_string(needle) or needle ~= str_lower(needle) then return nil end
                local slot = group.needle_index[needle]
                if not slot then
                    slot = #group.needles + 1
                    group.needles[slot], group.needle_index[needle] = needle, slot
                    group.needle_rules[slot] = {}
                end
                return slot
            end
            for _, needle in ipairs(needles) do
                local slot = slot_of(needle)
                if not slot then return "index key " .. number .. " needle" end
                local list = group.needle_rules[slot]
                list[#list + 1] = number
            end
            local seconds = seconds_of and seconds_of[tostring(number)]
            if seconds ~= nil then
                if type(seconds) ~= "table" or #seconds == 0 then return "index key " .. number .. " second" end
                local slots = {}
                for position, needle in ipairs(seconds) do
                    slots[position] = slot_of(needle)
                    if not slots[position] then return "index key " .. number .. " second" end
                end
                group.second[number] = slots
            end
        else
            return "index key " .. number .. " op"
        end
    end
    built.body_groups = {}
    for _, group in ipairs(built.groups) do
        if group.body then built.body_groups[#built.body_groups + 1] = group end
        group.ac = automaton(group.needles)
        if not group.ac then return "index needles of " .. group.spec.target end
        group.needle_index, group.needles = nil, nil
    end
    table.sort(built.raw_lengths)
    built.any = any
    built.segment_of = segment_of
    program.index = built
end

-- compile turns a decoded plan into a program. Returns nil, reason on any
-- field it does not accept. consume (compile_json's own plan): each rule is
-- dropped from the plan once compiled, so the garbage collector reclaims the
-- decoded plan while the program grows (a 50 000-rule plan would otherwise
-- hold both at once).
local function compile(plan, consume)
    if type(plan) ~= "table" or plan.schema ~= _M.SCHEMA then return nil, "schema" end
    if not OVERFLOW[plan.header_overflow] then return nil, "header_overflow" end
    if type(plan.telemetry) ~= "boolean" then return nil, "telemetry" end
    local segments = plan.segments
    if type(segments) ~= "table" or #segments > MAX_SEGMENTS then return nil, "segments" end
    local program = { overflow = plan.header_overflow, telemetry = plan.telemetry, segments = {} }
    local total, uses_headers = 0, false
    for segment_index, segment in ipairs(segments) do
        if type(segment) ~= "table" or not KINDS[segment.kind] or type(segment.enabled) ~= "boolean" or
            not ACTIONS[segment.default_action] or segment.default_action == "log" or
            not is_string(segment.default_rule_id) or type(segment.rules) ~= "table" or
            (segment.layer ~= nil and not LAYERS[segment.layer]) then
            return nil, "segment " .. segment_index
        end
        if not segment.enabled and #segment.rules ~= 0 then return nil, "segment " .. segment_index .. " disabled with rules" end
        if segment.action ~= nil and not is_string(segment.action) then return nil, "segment " .. segment_index .. " action" end
        local actions = segment.action and SPEC_ACTIONS or ACTIONS
        local rules = {}
        for rule_index, rule in ipairs(segment.rules) do
            total = total + 1
            if total > MAX_RULES then return nil, "too many rules" end
            -- No condition matches every request: a site object drops the
            -- port v7 pins every rule to when all its ports share the rule
            -- (edgesite RulePlan), so a rule with no other condition has none.
            if type(rule) ~= "table" or not is_string(rule.rule_id) or not actions[rule.action] or
                (rule.flow ~= "stop" and rule.flow ~= "continue") or type(rule.conditions) ~= "table" or
                #rule.conditions > MAX_CONDITIONS then
                return nil, "segment " .. segment_index .. " rule " .. rule_index
            end
            local conditions = {}
            for _, condition in ipairs(rule.conditions) do
                local problem, code = compile_condition(condition, conditions)
                if problem then return nil, "segment " .. segment_index .. " rule " .. rule_index .. ": " .. problem end
                if code == OP_HEADER_EXISTS or code == OP_HEADER_EQ then uses_headers = true end
            end
            rules[rule_index] = { id = rule.rule_id, action = rule.action, stop = rule.flow == "stop",
                conditions = conditions, limit = #conditions }
            if consume then
                segment.rules[rule_index] = false
                -- Reclaim the compiled part of the plan as it goes: the
                -- worker's RSS then peaks near the program, not program
                -- plus decoded plan (50 000 rules: 87 instead of 104 MiB).
                if total % CONSUME_COLLECT == 0 then collectgarbage("collect") end
            end
        end
        -- user: the site's own policies (no layer) or a user layer pack; an
        -- allow rule of one exempts the request from auto defense (mark_allow)
        program.segments[segment_index] = { kind = segment.kind, default_action = segment.default_action,
            default_rule_id = segment.default_rule_id, rules = rules, count = #rules, action = segment.action,
            policy_id = segment.policy_id, user = segment.layer == nil or segment.layer == "user" }
    end
    if uses_headers and plan.header_overflow == "none" then return nil, "header rules without header_overflow" end
    program.count = #program.segments
    if plan.index ~= nil then
        local problem = compile_index(plan.index, program)
        if problem then return nil, problem end
    end
    return program
end

function _M.compile(plan) return compile(plan, false) end

function _M.compile_json(raw)
    if type(raw) ~= "string" then return nil, "plan" end
    local plan = cjson.decode(raw)
    if not plan then return nil, "json" end
    return compile(plan, true)
end

-- Request headers as the renderer reads them: at most 100, names lower-cased,
-- a name seen twice (or with several values) is a duplicate. Returns nil when
-- the request must be refused (overflow with block).
local function read_headers(overflow)
    local raw, problem = ngx_req.get_headers(MAX_HEADERS, true)
    if problem == "truncated" then
        if overflow == "block" then return nil end
        ngx.log(ngx.WARN, "cdnca waf: more than 100 request headers, header conditions do not match")
        raw = {}
    end
    local headers, duplicates = {}, {}
    for name, value in pairs(raw) do
        local normalized = str_lower(name)
        if headers[normalized] ~= nil or type(value) == "table" then duplicates[normalized] = true end
        headers[normalized] = value
    end
    return headers, duplicates
end

local function has_prefix(value, prefix, length)
    return #value >= length and memcmp(value, prefix, length) == 0
end

-- Client address as nginx geo sees it: family 4 with one word, or 6 with
-- four; an IPv4-mapped IPv6 address is looked up as IPv4.
local function client_address()
    local raw = ngx_var.binary_remote_addr
    if not raw then return 0 end
    if #raw == 4 then
        local b1, b2, b3, b4 = byte(raw, 1, 4)
        return 4, bor(lshift(b1, 24), lshift(b2, 16), lshift(b3, 8), b4)
    end
    if #raw ~= 16 then return 0 end
    local b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16 = byte(raw, 1, 16)
    if b1 == 0 and b2 == 0 and b3 == 0 and b4 == 0 and b5 == 0 and b6 == 0 and b7 == 0 and b8 == 0 and
        b9 == 0 and b10 == 0 and b11 == 0xff and b12 == 0xff then
        return 4, bor(lshift(b13, 24), lshift(b14, 16), lshift(b15, 8), b16)
    end
    return 6, bor(lshift(b1, 24), lshift(b2, 16), lshift(b3, 8), b4), bor(lshift(b5, 24), lshift(b6, 16), lshift(b7, 8), b8),
        bor(lshift(b9, 24), lshift(b10, 16), lshift(b11, 8), b12), bor(lshift(b13, 24), lshift(b14, 16), lshift(b15, 8), b16)
end

local iplib, waf

local function evidence(policy_id)
    if not waf then waf = require("cdnca_waf") end
    waf.evidence(policy_id)
end

-- An earlier log segment's telemetry, written before a WAF v2 segment runs
-- (the names cdnca_waf is configured with, $cdnca_security_* by default).
-- mark_allow: a user ACL/WAF segment ended on a matching allow rule (not its
-- default action): the request is exempt from auto defense (ADR 0010 §7.2
-- item 5); cdnca_autodefense.access reads ngx.ctx.cdnca_user_allow.
local function mark_allow(segment, action, rule_id)
    if action == "allow" and segment.user and rule_id ~= segment.default_rule_id then
        ngx.ctx.cdnca_user_allow = rule_id
    end
end

local function set_log_telemetry(kind, rule_id)
    if not waf then waf = require("cdnca_waf") end
    local names = waf.telemetry_variables()
    ngx_var[names.emit] = "1"
    ngx_var[names.type] = kind
    ngx_var[names.action] = "log"
    ngx_var[names.severity] = "info"
    ngx_var[names.rule_id] = rule_id
end

-- Indexed evaluation ------------------------------------------------------
local HUGE = math.huge

-- chain runs a rule's whole condition chain, as the linear loop does; r
-- holds the lazily read request values.
local function chain(rule, r, limit)
    local conditions = rule.conditions
    for base = 1, limit or rule.limit, 4 do
        local op, a = conditions[base], conditions[base + 1]
        local matched
        if op == OP_PATH_EXACT or op == OP_PATH_PREFIX or op == OP_PATH_RAW then
            local uri = r.uri
            if op == OP_PATH_EXACT then
                matched = uri == a
            elseif op == OP_PATH_PREFIX then
                matched = uri == a or has_prefix(uri, conditions[base + 2], conditions[base + 3])
            else
                matched = has_prefix(uri, a, conditions[base + 2])
            end
        elseif op == OP_HOST then
            matched = r.host == a
        elseif op == OP_METHOD then
            matched = r.method == a
        elseif op == OP_HEADER_EXISTS then
            matched = r.headers[a] ~= nil
        elseif op == OP_HEADER_EQ then
            local value = r.headers[a]
            matched = not r.duplicates[a] and type(value) == "string" and value == conditions[base + 2]
        elseif op == OP_CIDR4 then
            matched = r.family == 4 and band(r.w1, conditions[base + 2]) == a
        elseif op == OP_CIDR6 then
            local masks = conditions[base + 2]
            matched = r.family == 6 and band(r.w1, masks[1]) == a[1] and band(r.w2, masks[2]) == a[2] and
                band(r.w3, masks[3]) == a[3] and band(r.w4, masks[4]) == a[4]
        elseif op == OP_PORT then
            matched = r.port == a
        elseif op == OP_EXPIRES then
            matched = r.now < a
        elseif op == OP_JA4 then
            matched = a[ngx_var.cdnca_ja4 or ""] == true
        elseif op == OP_JA4_NOT then
            local ja4 = ngx_var.cdnca_ja4 or ""
            matched = ja4 ~= "" and a[ja4] ~= true
        elseif op == OP_IPINTEL then
            if not iplib then iplib = require("cdnca_iplib") end
            matched = iplib.match(a) and true or false
        elseif op == OP_IPLIST then
            if not waf then waf = require("cdnca_waf") end
            matched = waf.ip_list(a) and true or false
        else
            if not waf then waf = require("cdnca_waf") end
            matched = waf.inspect(a) and true or false
        end
        if not matched then return false end
    end
    return true
end

local function add_all(list, numbers)
    if not numbers then return end
    for index = 1, #numbers do list[#list + 1] = numbers[index] end
end

-- walk: the trie walk from start (0-based) over bytes[0..length-1]; every
-- needle ending on the way is set in found (created when nil). Returns found.
local function walk(ac, bytes, length, start, found)
    local first, label_of, target_of, out = ac.first, ac.label, ac.target, ac.out
    local state = ac.root[LOWER[bytes[start]]]
    local position = start + 1
    while state > 0 do
        local needle = out[state]
        if needle > 0 then
            if not found then found = {} end
            found[needle] = true
        end
        if position >= length then break end
        local label, next_state = LOWER[bytes[position]], 0
        local slot, last = first[state], first[state + 1] - 1
        while slot <= last do
            if label_of[slot] == label then
                next_state, slot = target_of[slot], last
            end
            slot = slot + 1
        end
        state, position = next_state, position + 1
    end
    return found
end

-- held: whether a rule's second literal set (slots, or none) occurs.
local function held(slots, found)
    if slots == nil then return true end
    for position = 1, #slots do
        if found[slots[position]] then return true end
    end
    return false
end

-- scan runs a group's automaton over its clause values; returns the rules
-- (numbers >= from) one of whose needles occurs (and their second literal
-- set, if any), or nil.
-- Values per scan run one by one; more are joined by NUL into one text (no
-- needle contains NUL), once per request and value list.
local JOIN_VALUES = 8

local function scan_text(ac, text, found)
    local length = #text
    if length == 0 then return found end
    local bytes, patterns = ffi.cast(u8p, text), ac.patterns
    for index = 1, #patterns do
        local pattern = patterns[index]
        local compiled, flags = pattern[1], pattern[2]
        local position = 0
        while position < length do
            local rc = exec_regex(compiled, flags, text, length, position)
            if rc < 0 then
                if rc ~= -1 then
                    -- PCRE gave up (match limit): walk every remaining position.
                    for start = position, length - 1 do found = walk(ac, bytes, length, start, found) end
                end
                position = length
            else
                local start = compiled.captures[0]
                found = walk(ac, bytes, length, start, found)
                position = start + 1
            end
        end
    end
    return found
end

local function scan(group, from)
    if not waf then waf = require("cdnca_waf") end
    local ac = group.ac
    -- Each PCRE finds the positions where one of its needles starts, and the
    -- trie walk from there names every needle starting at that position.
    -- Indexed groups have no "length" filter: every value is a string.
    local values, found = waf.text_values(group.spec), nil
    if #values <= JOIN_VALUES then
        for value_index = 1, #values do found = scan_text(ac, values[value_index], found) end
    else
        local ctx = ngx.ctx
        local joined = ctx.cdnca_rule_joined
        if not joined then
            joined = setmetatable({}, { __mode = "k" })
            ctx.cdnca_rule_joined = joined
        end
        local text = joined[values]
        if not text then
            text = table.concat(values, "\0")
            joined[values] = text
        end
        found = scan_text(ac, text, found)
    end
    if not found then return nil end
    -- A rule with a second literal set is a candidate only when one of
    -- those occurs too.
    local second, needle_rules, hits = group.second, group.needle_rules, {}
    for slot in pairs(found) do
        local numbers = needle_rules[slot]
        for position = 1, #numbers do
            local number = numbers[position]
            if number >= from and held(second[number], found) then hits[#hits + 1] = number end
        end
    end
    return hits
end

-- first_after: the first position >= from in members (ascending) whose
-- number is above last (binary search; past the end stays there).
local function first_after(members, from, last)
    local high = #members + 1
    if from >= high then return from end
    while from < high do
        local middle = math.floor((from + high) / 2)
        if members[middle] <= last then from = middle + 1 else high = middle end
    end
    return from
end

local function sorted_unique(list)
    table.sort(list)
    local out, last = {}, nil
    for index = 1, #list do
        local value = list[index]
        if value ~= last then out[#out + 1], last = value, value end
    end
    return out
end

-- next_event: the next rule number <= limit to verify (state: the sorted
-- candidates and their cursor, the body groups and their member pointers),
-- or nil. A body group is scanned when it comes first and the conditions of
-- its member before the key hold; its hits join the candidates.
local function next_event(state, limit)
    local lazy, pointers = state.lazy, state.pointers
    while true do
        local candidate = state.candidates[state.cursor] or HUGE
        local group_at, group_index = HUGE, 0
        for g = 1, #lazy do
            local member = lazy[g].members[pointers[g]] or HUGE
            if member < group_at then group_at, group_index = member, g end
        end
        if candidate > limit and group_at > limit then return nil end
        if group_at >= candidate then
            state.cursor = state.cursor + 1
            return candidate
        end
        local group = lazy[group_index]
        if not chain(state.rules[group_at], state.r, (group.member_key[group_at] - 1) * 4) then
            -- The chain fails before reading the body.
            pointers[group_index] = pointers[group_index] + 1
        else
            pointers[group_index] = #group.members + 1
            local hits = scan(group, group_at) or {}
            local candidates = state.candidates
            for position = state.cursor, #candidates do hits[#hits + 1] = candidates[position] end
            state.candidates, state.cursor = sorted_unique(hits), 1
        end
    end
end

-- evaluate_indexed is evaluate() over the match index: the same segments,
-- same verdicts, rules visited only when their key condition holds.
local function evaluate_indexed(program, trace)
    local index = program.index
    local any = index.any
    local r = {}
    if program.overflow ~= "none" then
        r.headers, r.duplicates = read_headers(program.overflow)
        if not r.headers then return "block" end
    end
    r.uri, r.host, r.method = ngx_var.uri, ngx_var.host, ngx_req.get_method()
    r.port = tonumber(ngx_var.server_port) or false
    r.now = ngx_time()
    r.family, r.w1, r.w2, r.w3, r.w4 = client_address()
    -- Candidates of the pure keys.
    local list = {}
    add_all(list, index.unkeyed)
    add_all(list, index.host[r.host])
    add_all(list, index.method[r.method])
    local uri = r.uri
    if any.path and uri then
        add_all(list, index.exact[uri])
        add_all(list, index.prefix[uri])
        local from = 2
        while true do
            local slash = uri:find("/", from, true)
            if not slash then break end
            add_all(list, index.prefix[uri:sub(1, slash - 1)])
            from = slash + 1
        end
        for _, length in ipairs(index.raw_lengths) do
            if length > #uri then break end
            add_all(list, index.raw[length][uri:sub(1, length)])
        end
    end
    if r.headers then
        local exists, header, duplicates = index.exists, index.header, r.duplicates
        for name, value in pairs(r.headers) do
            add_all(list, exists[name])
            local by_value = header[name]
            if by_value and not duplicates[name] and type(value) == "string" then add_all(list, by_value[value]) end
        end
    end
    if any.port then add_all(list, index.port[r.port]) end
    if any.ja4 then add_all(list, index.ja4[ngx_var.cdnca_ja4 or ""]) end
    if r.family == 4 and any.cidr4 then
        for _, mask in ipairs(index.masks4) do add_all(list, index.cidr4[mask][band(r.w1, mask)]) end
    elseif r.family == 6 and any.cidr6 then
        for _, entry in ipairs(index.masks6) do
            local masks = entry.masks
            add_all(list, entry.networks[band(r.w1, masks[1]) .. ":" .. band(r.w2, masks[2]) .. ":" ..
                band(r.w3, masks[3]) .. ":" .. band(r.w4, masks[4])])
        end
    end
    -- Groups that read no body are scanned up front (their values are read
    -- without side effects). A body group is scanned when the walk first
    -- reaches one of its members whose conditions before its key hold (pure
    -- or IP library), so the body is read exactly when the linear chain
    -- first reads it.
    local groups, lazy, pointers = index.groups, index.body_groups, {}
    for g = 1, #groups do
        local group = groups[g]
        if not group.body then add_all(list, scan(group, 1)) end
    end
    for g = 1, #lazy do pointers[g] = 1 end
    local walk_state = { candidates = sorted_unique(list), cursor = 1, pointers = pointers, lazy = lazy,
        rules = index.rules, r = r }
    local rules = index.rules
    local verdict, verdict_kind, verdict_rule, verdict_policy = "allow", nil, nil, nil
    local segments = program.segments
    for segment_index = 1, program.count do
        local segment = segments[segment_index]
        if segment.action then
            if verdict == "log" and program.telemetry then
                set_log_telemetry(verdict_kind, verdict_rule)
                verdict, verdict_kind, verdict_rule, verdict_policy = "allow", nil, nil, nil
            end
            if not waf then waf = require("cdnca_waf") end
            waf.gate(segment.action)
        end
        local action, rule_id = segment.default_action, segment.default_rule_id
        local last = segment.last
        while true do
            local number = next_event(walk_state, last)
            if not number then break end
            local rule = rules[number]
            if chain(rule, r) then
                action, rule_id = rule.action, rule.id
                if rule.stop then break end
            end
        end
        -- The rest of a stopped segment is not visited.
        walk_state.cursor = first_after(walk_state.candidates, walk_state.cursor, last)
        for g = 1, #lazy do pointers[g] = first_after(lazy[g].members, pointers[g], last) end
        if trace then trace[#trace + 1] = segment.kind .. ":" .. action .. ":" .. rule_id end
        mark_allow(segment, action, rule_id)
        if segment.action then
            if action ~= "allow" then waf.act(segment.action, action, rule_id) end
        else
            if action == "block" then return "block", segment.kind, rule_id, segment.policy_id end
            if action == "log" then
                verdict, verdict_kind, verdict_rule, verdict_policy = "log", segment.kind, rule_id, segment.policy_id
                if program.telemetry then evidence(segment.policy_id) end
            end
        end
    end
    return verdict, verdict_kind, verdict_rule, verdict_policy
end

-- evaluate runs the program for the current request. trace (optional table)
-- receives per finished segment "kind:action:rule_id".
function _M.evaluate(program, trace)
    if program.index then return evaluate_indexed(program, trace) end
    local headers, duplicates
    if program.overflow ~= "none" then
        headers, duplicates = read_headers(program.overflow)
        if not headers then return "block" end
    end
    local method, uri, host, port, now
    local family, w1, w2, w3, w4
    local verdict, verdict_kind, verdict_rule, verdict_policy = "allow", nil, nil, nil
    local segments = program.segments
    for segment_index = 1, program.count do
        local segment = segments[segment_index]
        if segment.action then
            -- The rendered code has already set an earlier log segment's
            -- telemetry; cdnca_waf.gate / act may exit or overwrite it.
            if verdict == "log" and program.telemetry then
                set_log_telemetry(verdict_kind, verdict_rule)
                verdict, verdict_kind, verdict_rule, verdict_policy = "allow", nil, nil, nil
            end
            if not waf then waf = require("cdnca_waf") end
            waf.gate(segment.action)
        end
        local action, rule_id, stopped = segment.default_action, segment.default_rule_id, false
        local rules = segment.rules
        for rule_index = 1, segment.count do
            if stopped then break end
            local rule = rules[rule_index]
            local conditions = rule.conditions
            local matched = true
            for base = 1, rule.limit, 4 do
                local op, a = conditions[base], conditions[base + 1]
                if op == OP_PATH_EXACT or op == OP_PATH_PREFIX or op == OP_PATH_RAW then
                    if not uri then uri = ngx_var.uri end
                    if op == OP_PATH_EXACT then
                        matched = uri == a
                    elseif op == OP_PATH_PREFIX then
                        matched = uri == a or has_prefix(uri, conditions[base + 2], conditions[base + 3])
                    else
                        matched = has_prefix(uri, a, conditions[base + 2])
                    end
                elseif op == OP_HOST then
                    if not host then host = ngx_var.host end
                    matched = host == a
                elseif op == OP_METHOD then
                    if not method then method = ngx_req.get_method() end
                    matched = method == a
                elseif op == OP_HEADER_EXISTS then
                    matched = headers[a] ~= nil
                elseif op == OP_HEADER_EQ then
                    local value = headers[a]
                    matched = not duplicates[a] and type(value) == "string" and value == conditions[base + 2]
                elseif op == OP_CIDR4 or op == OP_CIDR6 then
                    if not family then family, w1, w2, w3, w4 = client_address() end
                    if op == OP_CIDR4 then
                        matched = family == 4 and band(w1, conditions[base + 2]) == a
                    else
                        local masks = conditions[base + 2]
                        matched = family == 6 and band(w1, masks[1]) == a[1] and band(w2, masks[2]) == a[2] and
                            band(w3, masks[3]) == a[3] and band(w4, masks[4]) == a[4]
                    end
                elseif op == OP_PORT then
                    if not port then port = tonumber(ngx_var.server_port) or false end
                    matched = port == a
                elseif op == OP_EXPIRES then
                    if not now then now = ngx_time() end
                    matched = now < a
                elseif op == OP_JA4 then
                    matched = a[ngx_var.cdnca_ja4 or ""] == true
                elseif op == OP_JA4_NOT then
                    local ja4 = ngx_var.cdnca_ja4 or ""
                    matched = ja4 ~= "" and a[ja4] ~= true
                elseif op == OP_IPINTEL then
                    if not iplib then iplib = require("cdnca_iplib") end
                    matched = iplib.match(a) and true or false
                elseif op == OP_IPLIST then
                    if not waf then waf = require("cdnca_waf") end
                    matched = waf.ip_list(a) and true or false
                else -- OP_INSPECT
                    if not waf then waf = require("cdnca_waf") end
                    matched = waf.inspect(a) and true or false
                end
                if not matched then break end
            end
            if matched then
                action, rule_id = rule.action, rule.id
                if rule.stop then stopped = true end
            end
        end
        if trace then trace[#trace + 1] = segment.kind .. ":" .. action .. ":" .. rule_id end
        mark_allow(segment, action, rule_id)
        if segment.action then
            -- cdnca_waf.act carries the verdict out (it exits the request
            -- for a block / challenge / ban it enforces, else goes on).
            if action ~= "allow" then waf.act(segment.action, action, rule_id) end
        else
            if action == "block" then return "block", segment.kind, rule_id, segment.policy_id end
            if action == "log" then
                verdict, verdict_kind, verdict_rule, verdict_policy = "log", segment.kind, rule_id, segment.policy_id
                -- The rendered code records the evidence when the segment
                -- ends; a later segment's inspect clauses may change it.
                if program.telemetry then evidence(segment.policy_id) end
            end
        end
    end
    return verdict, verdict_kind, verdict_rule, verdict_policy
end

-- enforce applies evaluate() like the rendered code: block -> telemetry (when
-- enabled) and ngx.exit(403); log -> telemetry; allow -> nothing.
function _M.enforce(program, trace)
    local verdict, kind, rule_id, policy_id = _M.evaluate(program, trace)
    if verdict == "allow" then return end
    if verdict == "block" then
        if kind and program.telemetry then
            ngx_var.cdnca_security_emit = "1"
            ngx_var.cdnca_security_type = kind
            ngx_var.cdnca_security_action = "block"
            ngx_var.cdnca_security_block_page = "1"
            ngx_var.cdnca_security_severity = "high"
            ngx_var.cdnca_security_rule_id = rule_id
            evidence(policy_id)
        end
        return ngx.exit(403)
    end
    if program.telemetry then set_log_telemetry(kind, rule_id) end
end

return _M
