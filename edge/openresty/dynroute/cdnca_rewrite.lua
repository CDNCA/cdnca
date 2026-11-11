-- Content rewrite: link rewrite, text replace and force
-- HTTPS on a site's HTML/CSS/JS responses. Loaded only when the skeleton's
-- configure says some site of the node has content_rewrite; cdnca_dynroute
-- calls it only for a site whose object carries it:
--   wants(site)         access, client pass: some rule's path matches $uri
--                       (the request is then fetched without
--                       Accept-Encoding, cdnca_dynroute plain_decide)
--   header_filter(site) the rules whose path and type match a plain 200
--                       response; none = no body filter
--   body_filter()       the streaming pipeline: one link stage (link and
--                       https rules merged), then one stage per replace rule
-- The algorithm is libs/edgeconfig/contentrewrite (engine.go) line by line:
-- the console's tester runs that one; any change is made in both.
local ngx = ngx
local ngx_var = ngx.var
local ngx_header = ngx.header
local re_match = ngx.re.match
local type, ipairs, pairs = type, ipairs, pairs
local byte, sub, find, lower = string.byte, string.sub, string.find, string.lower
local concat = table.concat
local max = math.max

local _M = { _VERSION = "1" }

local MAX_TAG, RAW_HOLD, MAX_PIPELINES = 4096, 7, 64
-- engine.go AttributePattern (\s spelled out: PCRE's \s also has \v)
local ATTRIBUTE = [[([^\t\n\f\r "'>/=]+)(?:([\t\n\f\r ]*=[\t\n\f\r ]*)("[^"]*"|'[^']*'|[^\t\n\f\r "'>]+))?]]
local URL_ATTRIBUTES = { href = true, src = true, srcset = true, action = true }
local SPACE = { [32] = true, [9] = true, [10] = true, [12] = true, [13] = true }
local HOST_RUN = "^[a-zA-Z0-9.-]*"

local function is_letter(value)
    return value and (value >= 65 and value <= 90 or value >= 97 and value <= 122)
end

-- ------------------------------------------------------------ compile
local function split_star(value)
    local parts, from = {}, 1
    while true do
        local at = find(value, "*", from, true)
        if not at then
            parts[#parts + 1] = sub(value, from)
            return parts
        end
        parts[#parts + 1] = sub(value, from, at - 1)
        from = at + 1
    end
end

-- template: contentrewrite.parseTemplate ($0-$9 groups, $$ is $)
local function parse_template(value)
    local out, text = {}, {}
    local index, n = 1, #value
    while index <= n do
        local c = byte(value, index)
        local next_byte = index < n and byte(value, index + 1) or nil
        if c == 36 and next_byte == 36 then
            text[#text + 1] = "$"
            index = index + 2
        elseif c == 36 and next_byte and next_byte >= 48 and next_byte <= 57 then
            if #text > 0 then
                out[#out + 1] = concat(text)
                text = {}
            end
            out[#out + 1] = next_byte - 48
            index = index + 2
        else
            text[#text + 1] = sub(value, index, index)
            index = index + 1
        end
    end
    if #text > 0 then out[#out + 1] = concat(text) end
    return out
end

local compiled = setmetatable({}, { __mode = "k" })

-- compile(node): the site object's content_rewrite, once per object.
local function compile(node)
    local c = compiled[node]
    if c then return c end
    c = { max_bytes = node.max_bytes, rules = {}, pipelines = {}, pipeline_count = 0 }
    for index, rule in ipairs(node.rules) do
        local r = { kind = rule.kind, paths = {}, types = {} }
        for _, path in ipairs(rule.paths or {}) do
            r.paths[#r.paths + 1] = find(path, "*", 1, true) and { glob = split_star(path) } or { prefix = path }
        end
        for _, name in ipairs(rule.types or {}) do r.types[name] = true end
        if rule.kind == "replace" then
            r.template = parse_template(rule.replace or "")
            if type(rule.literal) == "string" and rule.literal ~= "" then
                r.literal = rule.literal
            else
                r.pattern, r.max_len = rule.pattern, rule.max_len
            end
        elseif rule.kind == "link" then
            r.map = rule.map or {}
        elseif rule.kind == "https" then
            r.hosts = rule.hosts or {}
        end
        c.rules[index] = r
    end
    compiled[node] = c
    return c
end

-- path_matches: contentrewrite.PathMatches (prefix, or * globs on the
-- whole path).
local function glob_matches(parts, path)
    local first, last = parts[1], parts[#parts]
    if sub(path, 1, #first) ~= first then return false end
    local position = #first
    for index = 2, #parts - 1 do
        local part = parts[index]
        local at = find(path, part, position + 1, true)
        if not at then return false end
        position = at + #part - 1
    end
    return #path - position >= #last and (last == "" or sub(path, -#last) == last)
end

local function path_matches(paths, path)
    if #paths == 0 then return true end
    for _, pattern in ipairs(paths) do
        if pattern.prefix then
            if sub(path, 1, #pattern.prefix) == pattern.prefix then return true end
        elseif glob_matches(pattern.glob, path) then
            return true
        end
    end
    return false
end
_M.path_matches = function(patterns, path)
    local list = {}
    for index, value in ipairs(patterns) do
        list[index] = find(value, "*", 1, true) and { glob = split_star(value) } or { prefix = value }
    end
    return path_matches(list, path)
end

local TYPES = { ["text/html"] = "html", ["text/css"] = "css", ["application/javascript"] = "js",
    ["text/javascript"] = "js", ["application/x-javascript"] = "js" }

local function type_key(value)
    if type(value) == "table" then value = value[1] end
    if type(value) ~= "string" then return nil end
    local mime = value:match("^%s*([^;]-)%s*;") or value:match("^%s*(.-)%s*$")
    return TYPES[lower(mime)]
end
_M.type_key = type_key

-- ------------------------------------------------------------ replace
-- engine.go replaceStage.write: a match is final when its start plus the
-- longest match is inside the data; from the first undecided start on the
-- bytes wait for the next chunk.
local function expand(template, captures)
    local out = {}
    for _, part in ipairs(template) do
        if type(part) == "string" then
            out[#out + 1] = part
        elseif captures then
            local value = captures[part]
            if type(value) == "string" then out[#out + 1] = value end
        end
    end
    return concat(out)
end

local function replace_write(stage, chunk, eof)
    local data = stage.hold .. chunk
    stage.hold = ""
    local n, pos, out = #data, 1, {}
    local rule = stage.rule
    local keep = rule.literal and #rule.literal - 1 or rule.max_len - 1
    local ctx = {}
    while pos <= n do
        local start, finish, captures
        if rule.literal then
            start = find(data, rule.literal, pos, true)
            if not start then break end
            finish = start + #rule.literal - 1
        else
            ctx.pos = pos
            captures = re_match(data, rule.pattern, "jo", ctx)
            if not captures then break end
            finish = ctx.pos - 1
            start = finish - #captures[0] + 1
            if not eof and start - 1 + rule.max_len > n then break end
        end
        out[#out + 1] = sub(data, pos, start - 1)
        out[#out + 1] = expand(rule.template, captures)
        pos = finish + 1
    end
    local cut = n
    if not eof then cut = max(pos - 1, n - keep) end
    out[#out + 1] = sub(data, pos, cut)
    stage.hold = sub(data, cut + 1)
    return concat(out)
end

-- ------------------------------------------------------------ links
-- host_end: engine.go hostEnd (1-based: the host is data[start, end-1]).
-- Returns end, ok, more.
local function host_end(data, start, eof)
    local _, run = find(data, HOST_RUN, start)
    local length = run - start + 1
    if length > 253 then return start + 254, false, false end
    local stop = start + length
    if stop > #data and not eof then return stop, false, true end
    if stop > start and byte(data, stop - 1) == 46 then stop = stop - 1 end
    local after = byte(data, stop)
    if stop == start or after == 58 or after == 64 then return stop, false, false end
    return stop, true, false
end

local function force_https(stage, host)
    if stage.exact[host] then return true end
    for _, suffix in ipairs(stage.suffixes) do
        if #host > #suffix and sub(host, -#suffix) == suffix then return true end
    end
    return false
end

-- rewrite_url: engine.go linkStage.rewrite (scheme "" = protocol-relative).
local function rewrite_url(stage, scheme, host)
    local new_scheme, new_host = scheme, host
    local target = stage.hosts[lower(host)]
    if target then
        new_host = target.host
        if scheme ~= "" and target.scheme ~= "keep" then new_scheme = target.scheme end
    end
    if lower(new_scheme) == "http" and not find(new_host, ":", 1, true) and force_https(stage, lower(new_host)) then
        new_scheme = "https"
    end
    if new_scheme == scheme and new_host == host then return nil end
    if new_scheme == "" then return "//" .. new_host end
    return new_scheme .. "://" .. new_host
end

-- raw_write (CSS, JS): explicit http:// and https:// URLs.
local function raw_write(stage, data, eof)
    local n, pos, search, out = #data, 1, 1, {}
    while true do
        local at = find(data, "://", search, true)
        if not at then break end
        local start
        if at - 5 >= pos and lower(sub(data, at - 5, at - 1)) == "https" then
            start = at - 5
        elseif at - 4 >= pos and lower(sub(data, at - 4, at - 1)) == "http" then
            start = at - 4
        end
        if not start then
            search = at + 1
        else
            local stop, ok, more = host_end(data, at + 3, eof)
            if more then
                out[#out + 1] = sub(data, pos, start - 1)
                return concat(out), start
            end
            if ok then
                local value = rewrite_url(stage, sub(data, start, at - 1), sub(data, at + 3, stop - 1))
                if value then
                    out[#out + 1] = sub(data, pos, start - 1)
                    out[#out + 1] = value
                    pos = stop
                end
            end
            search = max(stop, at + 3)
        end
    end
    local cut = n
    if not eof then cut = max(pos - 1, n - (RAW_HOLD - 1)) end
    out[#out + 1] = sub(data, pos, cut)
    return concat(out), cut + 1
end

-- rewrite_value: the URL at the value's start (srcset: after each comma).
local function rewrite_value(stage, value, srcset)
    local out, pos, changed, candidate = {}, 1, false, 1
    local n = #value
    while candidate <= n + 1 do
        while candidate <= n and SPACE[byte(value, candidate)] do candidate = candidate + 1 end
        local scheme, host_start = "", nil
        local rest8, rest7 = lower(sub(value, candidate, candidate + 7)), lower(sub(value, candidate, candidate + 6))
        if rest8 == "https://" then
            scheme, host_start = sub(value, candidate, candidate + 4), candidate + 8
        elseif rest7 == "http://" then
            scheme, host_start = sub(value, candidate, candidate + 3), candidate + 7
        elseif sub(value, candidate, candidate + 1) == "//" then
            host_start = candidate + 2
        end
        if host_start then
            local stop, ok = host_end(value, host_start, true)
            if ok then
                local replaced = rewrite_url(stage, scheme, sub(value, host_start, stop - 1))
                if replaced then
                    out[#out + 1] = sub(value, pos, candidate - 1)
                    out[#out + 1] = replaced
                    pos, changed = stop, true
                end
            end
        end
        if not srcset then break end
        local from = max(candidate, pos)
        local comma = find(value, ",", from, true)
        if not comma then break end
        candidate = comma + 1
    end
    if not changed then return nil end
    out[#out + 1] = sub(value, pos)
    return concat(out)
end

local function rewrite_tag(stage, tag)
    local out, pos, changed, ctx = {}, 1, false, { pos = 2 }
    while true do
        local m = re_match(tag, ATTRIBUTE, "jo", ctx)
        if not m then break end
        local value = m[3]
        if value and URL_ATTRIBUTES[lower(m[1])] then
            local stop = ctx.pos - 1
            local start = stop - #value + 1
            local quote = byte(tag, start)
            if quote == 34 or quote == 39 then start, stop = start + 1, stop - 1 end
            local replaced = rewrite_value(stage, sub(tag, start, stop), lower(m[1]) == "srcset")
            if replaced then
                out[#out + 1] = sub(tag, pos, start - 1)
                out[#out + 1] = replaced
                pos, changed = stop + 1, true
            end
        end
    end
    if not changed then return nil end
    out[#out + 1] = sub(tag, pos)
    return concat(out)
end

-- html_write: tags "<letter ... >" up to MAX_TAG bytes; an unfinished tag
-- waits for the next chunk. Returns the output and the first held byte.
local function html_write(stage, data, eof)
    local n, pos, index, gt, out = #data, 1, 1, -2, {}
    while true do
        local lt = find(data, "<", index, true)
        if not lt then break end
        if lt + 1 > n then
            if not eof then
                out[#out + 1] = sub(data, pos, lt - 1)
                return concat(out), lt
            end
            break
        end
        if not is_letter(byte(data, lt + 1)) then
            index = lt + 1
        else
            if gt ~= -1 and gt <= lt then gt = find(data, ">", lt + 1, true) or -1 end
            if gt == -1 then
                if not eof and n - lt + 1 < MAX_TAG then
                    out[#out + 1] = sub(data, pos, lt - 1)
                    return concat(out), lt
                end
                index = lt + 1
            elseif gt - lt + 1 > MAX_TAG then
                index = lt + 1
            else
                local tag = sub(data, lt, gt)
                if find(tag, "//", 1, true) then
                    local value = rewrite_tag(stage, tag)
                    if value then
                        out[#out + 1] = sub(data, pos, lt - 1)
                        out[#out + 1] = value
                        pos = gt + 1
                    end
                end
                index = gt + 1
            end
        end
    end
    out[#out + 1] = sub(data, pos)
    return concat(out), n + 1
end

local function link_write(stage, chunk, eof)
    local data = stage.hold .. chunk
    local out, held
    if stage.html then
        out, held = html_write(stage, data, eof)
    else
        out, held = raw_write(stage, data, eof)
    end
    stage.hold = sub(data, held)
    return out
end

-- ------------------------------------------------------------ pipeline
-- pipeline(c, active, key): engine.go NewStream's stage list (link and
-- https rules merged into one link stage, the first rule naming a host
-- wins; then the replace rules in order), cached per (type, active set).
local function pipeline(c, active, key)
    local cached = c.pipelines[key]
    if cached then return cached end
    local link = { html = active.type == "html", hosts = {}, exact = {}, suffixes = {} }
    local has_link, specs = false, {}
    for _, index in ipairs(active) do
        local rule = c.rules[index]
        if rule.kind == "link" then
            for host, target in pairs(rule.map) do
                if not link.hosts[host] then link.hosts[host] = target end
                has_link = true
            end
        elseif rule.kind == "https" then
            for _, host in ipairs(rule.hosts) do
                if sub(host, 1, 2) == "*." then
                    link.suffixes[#link.suffixes + 1] = sub(host, 2)
                else
                    link.exact[host] = true
                end
                has_link = true
            end
        elseif rule.kind == "replace" then
            specs[#specs + 1] = { replace = rule }
        end
    end
    if has_link then table.insert(specs, 1, { link = link }) end
    if c.pipeline_count < MAX_PIPELINES then
        c.pipelines[key] = specs
        c.pipeline_count = c.pipeline_count + 1
    end
    return specs
end

-- stream_write: engine.go Stream.Write (input beyond max_bytes passes
-- through; at the cut each stage's held bytes go out, the last stage's
-- first).
local function stream_write(state, chunk, eof)
    if state.passthrough then return chunk end
    local rest
    if state.consumed + #chunk > state.limit then
        local cut = state.limit - state.consumed
        chunk, rest = sub(chunk, 1, cut), sub(chunk, cut + 1)
    end
    state.consumed = state.consumed + #chunk
    local data = chunk
    for _, stage in ipairs(state.stages) do
        data = stage.write(stage, data, eof and rest == nil)
    end
    if rest == nil then return data end
    state.passthrough = true
    local out = { data }
    for index = #state.stages, 1, -1 do
        out[#out + 1] = state.stages[index].hold
        state.stages[index].hold = ""
    end
    out[#out + 1] = rest
    return concat(out)
end

-- ------------------------------------------------------------ phases
-- wants(site): access, client pass.
function _M.wants(site)
    local c = compile(site.content_rewrite)
    local uri = ngx_var.uri or ""
    for _, rule in ipairs(c.rules) do
        if path_matches(rule.paths, uri) then return true end
    end
    return false
end

-- new_stream(node, uri, key): the rules whose path and type match, nil
-- for none (header_filter; the Go/Lua parity script calls it directly).
function _M.new_stream(node, uri, key)
    local c = compile(node)
    local active, names = { type = key }, { key }
    for index, rule in ipairs(c.rules) do
        if rule.types[key] and path_matches(rule.paths, uri) then
            active[#active + 1] = index
            names[#names + 1] = index
        end
    end
    if #active == 0 then return nil end
    local specs = pipeline(c, active, concat(names, ","))
    local stages = {}
    for index, spec in ipairs(specs) do
        if spec.link then
            stages[index] = { write = link_write, hold = "", html = spec.link.html, hosts = spec.link.hosts,
                exact = spec.link.exact, suffixes = spec.link.suffixes }
        else
            stages[index] = { write = replace_write, hold = "", rule = spec.replace }
        end
    end
    return { stages = stages, limit = c.max_bytes, consumed = 0 }
end
_M.stream_write = stream_write

local function no_transform()
    local value = ngx_header["Cache-Control"]
    if type(value) == "table" then value = concat(value, ",") end
    return type(value) == "string" and find(lower(value), "no-transform", 1, true) ~= nil
end

-- header_filter(site): before the compression gate (the visitor's
-- Accept-Encoding is back). A response the origin still compressed, a
-- range, no-transform, HEAD, not 200: untouched.
function _M.header_filter(site)
    local ctx = ngx.ctx
    if ngx.is_subrequest or ctx.cdnca_own_page or ctx.cdnca_error_page or ngx.status ~= 200 or
        ngx.req.get_method() == "HEAD" then
        return
    end
    if ngx_header["Content-Encoding"] or ngx_header["Content-Range"] or no_transform() then return end
    local key = type_key(ngx_header["Content-Type"])
    if not key then return end
    local state = _M.new_stream(site.content_rewrite, ngx_var.uri or "", key)
    if not state then return end
    ngx_header["Content-Length"] = nil
    local etag = ngx_header["ETag"]
    if type(etag) == "string" and sub(etag, 1, 2) ~= "W/" then ngx_header["ETag"] = "W/" .. etag end
    ctx.cdnca_rewrite = state
end

-- body_filter(): before RUM (it sees the rewritten bytes).
function _M.body_filter()
    local state = ngx.ctx.cdnca_rewrite
    if not state then return end
    local eof = ngx.arg[2] == true
    ngx.arg[1] = stream_write(state, ngx.arg[1] or "", eof)
end

return _M
