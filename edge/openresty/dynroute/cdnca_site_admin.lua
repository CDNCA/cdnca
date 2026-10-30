-- Dynamic routing site index activation (dynamic routing D3), served only on
-- the node-local control socket (docs/edge/dynroute-contract.md §5.4):
--   POST /stage            change set body (§5.2) -> transitional values (§4.3)
--   POST /commit?gen=N     one write of "gen" switches the whole generation
--   POST /abort?gen=N      undo a stage
--   POST /rollback?gen=N   one write of "gen" switches back to the previous one
--   POST /rebuild          flush and rebuild from <index_root>/current (§5.3)
--   GET  /probe?port=&host=  the request path's lookup, no request sent
--   GET  /status
-- Every state change runs under one resty.lock; the request path never takes
-- it (cdnca_site.lua reads the dictionaries only).
local cjson = require "cjson.safe"
local resty_lock = require "resty.lock"
local resty_sha256 = require "resty.sha256"
local site = require "cdnca_site"

local byte, char, sub = string.byte, string.char, string.sub
local concat = table.concat
local tonumber, tostring = tonumber, tostring

local _M = {}

local index_dict = ngx.shared.cdnca_site_index
local state_dict = ngx.shared.cdnca_site_state

local MAX_CHANGES = 65536
local SLICE = 1000
local EPOCH_KEY = "cdnca:epoch" -- not 16 bytes: never an index key

local function be64(value)
    local bytes = {}
    for position = 8, 1, -1 do
        bytes[position] = char(value % 256)
        value = math.floor(value / 256)
    end
    return concat(bytes)
end

local function be32(raw, offset)
    local b1, b2, b3, b4 = byte(raw, offset, offset + 3)
    return ((b1 * 256 + b2) * 256 + b3) * 256 + b4
end

local function be16(raw, offset)
    local b1, b2 = byte(raw, offset, offset + 1)
    return b1 * 256 + b2
end

local function sha256(raw)
    local hash = resty_sha256:new()
    hash:update(raw)
    return hash:final()
end

local function get_int(key)
    return tonumber(state_dict:get(key)) or 0
end

local function must(ok, err, what)
    if not ok then
        error({ status = 507, message = what .. ": " .. tostring(err) })
    end
end

local function fail(status, message)
    error({ status = status, message = message })
end

local function with_lock(timeout, fn)
    local lock = assert(resty_lock:new("cdnca_site_lock", { exptime = 300, timeout = timeout }))
    local elapsed, err = lock:lock("admin")
    if not elapsed then
        return false, { status = 409, message = "locked: " .. tostring(err) }
    end
    local ok, result = pcall(fn)
    lock:unlock()
    return ok, result
end

local function ports_value(ports)
    if #ports == 0 then
        return ",,"
    end
    return "," .. concat(ports, ",") .. ","
end

-- Parses a change set (contract §5.2). Returns gen, base, ports, ops, keys,
-- digests (arrays) or raises 400/413.
local function parse_change_set(raw)
    if type(raw) ~= "string" or #raw < 8 + 8 + 8 + 2 + 4 + 32 or sub(raw, 1, 8) ~= "CDNCACS1" then
        fail(400, "change set: magic")
    end
    if sha256(sub(raw, 1, -33)) ~= sub(raw, -32) then
        fail(400, "change set: trailer digest")
    end
    local body_end = #raw - 32
    local gen = site.u64(raw, 9)
    local base = site.u64(raw, 17)
    local offset = 25
    local nports = be16(raw, offset)
    offset = offset + 2
    if offset + nports * 2 + 4 - 1 > body_end then
        fail(400, "change set: truncated ports")
    end
    local ports = {}
    for position = 1, nports do
        local port = be16(raw, offset)
        if port == 0 or position > 1 and port <= ports[position - 1] then
            fail(400, "change set: ports must be ascending")
        end
        ports[position] = port
        offset = offset + 2
    end
    local count = be32(raw, offset)
    offset = offset + 4
    if count > MAX_CHANGES then
        fail(413, "change set: " .. count .. " changes exceed " .. MAX_CHANGES)
    end
    local ops, keys, digests = {}, {}, {}
    local previous
    for position = 1, count do
        if offset + 16 > body_end then
            fail(400, "change set: truncated")
        end
        local op = byte(raw, offset)
        local key = sub(raw, offset + 1, offset + 16)
        offset = offset + 17
        if previous and key <= previous then
            fail(400, "change set: keys must be ascending")
        end
        previous = key
        if op == 1 then
            if offset + 31 > body_end then
                fail(400, "change set: truncated")
            end
            digests[position] = sub(raw, offset, offset + 31)
            offset = offset + 32
        elseif op ~= 2 then
            fail(400, "change set: op")
        end
        ops[position], keys[position] = op, key
    end
    if offset ~= body_end + 1 then
        fail(400, "change set: trailing data")
    end
    if gen < 1 or gen <= base then
        fail(400, "change set: generation")
    end
    return gen, base, ports, ops, keys, digests
end

-- converge(g): replace every transitional value of the last change set by
-- what it means at generation g (a stable digest, or no key). Changes
-- nothing any reader sees at g.
local function converge(g)
    local tags = state_dict:get("tags")
    if not tags then
        return
    end
    local colon = tags:find(":", 1, true)
    for offset = colon + 1, #tags, 16 do
        local key = sub(tags, offset, offset + 15)
        local raw = index_dict:get(key)
        if raw and #raw ~= 32 then
            local digest = site.resolve(raw, g)
            if digest then
                must(index_dict:safe_set(key, digest), "converge")
            else
                index_dict:delete(key)
            end
        end
        if (offset - colon - 1) / 16 % SLICE == SLICE - 1 then
            ngx.sleep(0)
        end
    end
    state_dict:delete("tags")
end

local function tags_generation()
    local tags = state_dict:get("tags")
    if not tags then
        return nil
    end
    return tonumber(sub(tags, 1, tags:find(":", 1, true) - 1))
end

-- The index dictionary and the state dictionary carry the same epoch; a
-- mismatch means one of them is new (resized or lost) and the index has to
-- be rebuilt (contract §5.3).
local epochs_agree = site.index_intact

local function new_epoch()
    local epoch = ngx.now() .. ":" .. ngx.worker.pid() .. ":" .. math.random(1, 2 ^ 30)
    must(index_dict:safe_set(EPOCH_KEY, epoch), "epoch")
    must(state_dict:safe_set("epoch", epoch), "epoch")
end

local function flush_index()
    index_dict:flush_all()
    while index_dict:flush_expired(10000) > 0 do
        ngx.sleep(0)
    end
end

local function stage(raw)
    local gen, base, ports, ops, keys, digests = parse_change_set(raw)
    local current = site.generation()
    if state_dict:get("stage") then
        fail(409, "stage " .. state_dict:get("stage") .. " in progress")
    end
    if base ~= current then
        fail(409, "base " .. base .. " is not the active generation " .. current)
    end
    if gen <= get_int("max_gen") then
        fail(409, "generation " .. gen .. " is not after " .. get_int("max_gen"))
    end
    if current == 0 then
        -- A change set from base 0 builds on an empty index: drop whatever a
        -- lost state dictionary or a failed rebuild left behind.
        flush_index()
        new_epoch()
    elseif not epochs_agree() then
        state_dict:set("gen", 0)
        fail(409, "index dictionary was lost; rebuild required")
    end
    converge(current)
    local gen_bytes = be64(gen)
    local tag_keys = {}
    local ok, err = true, nil
    for position = 1, #keys do
        local key = keys[position]
        local old_raw = index_dict:get(key)
        local old = old_raw and site.resolve(old_raw, current)
        local new = ops[position] == 1 and digests[position] or nil
        local flags = (new and 1 or 0) + (old and 2 or 0)
        ok, err = index_dict:safe_set(key, "\1" .. gen_bytes .. char(flags) .. (new or "") .. (old or ""))
        if not ok then
            break
        end
        tag_keys[position] = key
        if position % SLICE == 0 then
            ngx.sleep(0)
        end
    end
    -- Record the tags even on failure so converge() undoes what was written.
    local saved = state_dict:safe_set("tags", gen .. ":" .. concat(tag_keys))
    if not ok or not saved then
        if saved then
            converge(current)
        end
        fail(507, "index dictionary: " .. tostring(err or "no memory for tags"))
    end
    must(state_dict:safe_set("ports:" .. gen, ports_value(ports)), "ports")
    must(state_dict:safe_set("stage", gen), "stage")
    return { gen = gen, applied = #keys }
end

local function commit(gen)
    if get_int("stage") ~= gen or gen == 0 then
        fail(409, "no stage " .. tostring(gen))
    end
    local current = site.generation()
    local old_prev = get_int("prev_gen")
    if current > 0 then
        must(state_dict:safe_set("prev_gen", current), "prev_gen")
    else
        state_dict:delete("prev_gen")
    end
    must(state_dict:safe_set("max_gen", gen), "max_gen")
    must(state_dict:safe_set("gen", gen), "gen") -- the switch
    state_dict:delete("stage")
    if old_prev > 0 and old_prev ~= current then
        state_dict:delete("ports:" .. old_prev)
    end
    return { gen = gen }
end

local function abort(gen)
    if get_int("stage") ~= gen or gen == 0 then
        fail(409, "no stage " .. tostring(gen))
    end
    converge(site.generation())
    state_dict:delete("ports:" .. gen)
    state_dict:delete("stage")
    return { gen = site.generation() }
end

local function rollback(gen)
    local current = site.generation()
    local prev = get_int("prev_gen")
    if gen == 0 or current ~= gen or prev == 0 or tags_generation() ~= gen or state_dict:get("stage") then
        fail(409, "generation " .. tostring(gen) .. " cannot be rolled back")
    end
    must(state_dict:safe_set("gen", prev), "gen") -- the switch
    converge(prev)
    state_dict:delete("prev_gen")
    state_dict:delete("ports:" .. gen)
    return { gen = prev }
end

local function set_rebuild(status)
    state_dict:set("rebuild", cjson.encode(status))
end


-- rebuild(): contract §5.3. Runs with the lock held; gen is 0 throughout, so
-- every port answers 503 until the final write.
local function current_file_generation(root)
    local pointer = io.open(root .. "/current", "rb")
    if not pointer then
        return nil
    end
    local name = pointer:read("*a")
    pointer:close()
    return tonumber(name and name:match("^gen%-([1-9][0-9]*)%.idx\n$"))
end

local function rebuild_locked(force)
    local root = site.config().index_root
    local target = current_file_generation(root)
    if not force and target and site.generation() == target and epochs_agree() then
        -- Already running the generation the file names (a cold start
        -- timer and a POST /rebuild raced): nothing to do, no 503 window.
        return target
    end
    local status = { started = ngx.now(), done = 0 }
    state_dict:set("gen", 0)
    state_dict:delete("stage")
    state_dict:delete("tags")
    state_dict:delete("prev_gen")
    for _, key in ipairs(state_dict:get_keys(0)) do
        if key:sub(1, 6) == "ports:" then
            state_dict:delete(key)
        end
    end
    set_rebuild(status)
    flush_index()

    local function failed(message)
        status.error = message
        status.finished = ngx.now()
        set_rebuild(status)
        flush_index()
        ngx.log(ngx.ERR, "cdnca_site: index rebuild failed: ", message)
        return nil, message
    end

    local pointer = io.open(root .. "/current", "rb")
    if not pointer then
        return failed("no current index file")
    end
    local name = pointer:read("*a")
    pointer:close()
    name = name and name:match("^(gen%-[1-9][0-9]*%.idx)\n$")
    if not name then
        return failed("current does not name an index file")
    end
    local file = io.open(root .. "/" .. name, "rb")
    if not file then
        return failed(name .. " missing")
    end
    local size = file:seek("end")
    file:seek("set", 0)
    local hash = resty_sha256:new()
    local header = file:read(22)
    if not header or #header ~= 22 or sub(header, 1, 8) ~= "CDNCAIX1" then
        file:close()
        return failed(name .. ": magic")
    end
    hash:update(header)
    local gen = site.u64(header, 9)
    local count = be32(header, 17)
    local nports = be16(header, 21)
    local port_bytes = file:read(nports * 2) or ""
    hash:update(port_bytes)
    if #port_bytes ~= nports * 2 or size ~= 22 + nports * 2 + count * 48 + 32 or name ~= "gen-" .. string.format("%d", gen) .. ".idx" then
        file:close()
        return failed(name .. ": size or generation")
    end
    local ports = {}
    for position = 1, nports do
        ports[position] = be16(port_bytes, position * 2 - 1)
    end
    status.gen, status.total = gen, count
    local previous
    local remaining = count
    while remaining > 0 do
        local batch = math.min(remaining, SLICE)
        local chunk = file:read(batch * 48)
        if not chunk or #chunk ~= batch * 48 then
            file:close()
            return failed(name .. ": truncated")
        end
        hash:update(chunk)
        for offset = 1, #chunk, 48 do
            local key = sub(chunk, offset, offset + 15)
            if previous and key <= previous then
                file:close()
                return failed(name .. ": keys not ascending")
            end
            previous = key
            local ok, err = index_dict:safe_set(key, sub(chunk, offset + 16, offset + 47))
            if not ok then
                file:close()
                return failed("index dictionary: " .. tostring(err))
            end
        end
        remaining = remaining - batch
        status.done = count - remaining
        ngx.sleep(0)
    end
    local trailer = file:read(32)
    file:close()
    if trailer ~= hash:final() then
        return failed(name .. ": trailer digest")
    end
    new_epoch()
    must(state_dict:safe_set("ports:" .. gen, ports_value(ports)), "ports")
    must(state_dict:safe_set("max_gen", math.max(gen, get_int("max_gen"))), "max_gen")
    status.finished = ngx.now()
    set_rebuild(status)
    must(state_dict:safe_set("gen", gen), "gen") -- the switch
    ngx.log(ngx.NOTICE, "cdnca_site: index generation ", gen, " rebuilt: ", count, " keys in ",
        string.format("%.3f", status.finished - status.started), " s")
    return gen
end

local function rebuild(force)
    return with_lock(60, function()
        local gen, err = rebuild_locked(force)
        if not gen then
            fail(500, err)
        end
        return gen
    end)
end

-- cold_start(): called by the worker timer when gen is 0 and no rebuild was
-- recorded (fresh dictionaries). One worker wins the lock; the rest skip.
function _M.cold_start()
    local root = site.config().index_root
    local pointer = io.open(root .. "/current", "rb")
    if not pointer then
        return
    end
    pointer:close()
    if not state_dict:add("rebuild", cjson.encode({ started = ngx.now(), done = 0 })) then
        return -- another worker is on it (or it already ran)
    end
    rebuild()
end

-- check_epoch(): a lost index dictionary (resized alone) with a live state
-- dictionary: reset to cold start.
function _M.check_epoch()
    if site.generation() > 0 and not epochs_agree() then
        state_dict:set("gen", 0)
        state_dict:delete("rebuild")
    end
end

local function status()
    local workers = {}
    for _, key in ipairs(state_dict:get_keys(0)) do
        if key:sub(1, 7) == "worker:" then
            workers[key:sub(8)] = state_dict:get(key)
        end
    end
    local gen = site.generation()
    local tags = state_dict:get("tags")
    return {
        gen = gen,
        prev_gen = get_int("prev_gen"),
        max_gen = get_int("max_gen"),
        stage = get_int("stage"),
        ports = state_dict:get("ports:" .. gen) or ",,",
        tags = tags and (#tags - tags:find(":", 1, true)) / 16 or 0,
        tags_gen = tags_generation() or 0,
        capacity_bytes = index_dict:capacity(),
        free_bytes = index_dict:free_space(),
        epoch_ok = gen == 0 or epochs_agree(),
        rebuild = cjson.decode(state_dict:get("rebuild") or "null"),
        workers = workers,
    }
end

local function read_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if body then
        return body
    end
    local path = ngx.req.get_body_file()
    if not path then
        return nil
    end
    local file = io.open(path, "rb")
    if not file then
        return nil
    end
    body = file:read("*a")
    file:close()
    return body
end

local function respond(status_code, value)
    ngx.status = status_code
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(cjson.encode(value))
    return ngx.exit(ngx.HTTP_OK)
end

local function run_locked(fn, ...)
    local args = { ... }
    local ok, result = with_lock(30, function()
        return fn(unpack(args))
    end)
    if ok then
        return respond(200, result)
    end
    if type(result) == "table" then
        return respond(result.status or 500, { error = result.message })
    end
    ngx.log(ngx.ERR, "cdnca_site_admin: ", tostring(result))
    return respond(500, { error = tostring(result) })
end

-- Level D site drop (攻击自动升级 D 级, esc-node §4): the names (primary and
-- aliases, leading wildcards kept, as the site index matches them) whose
-- requests and handshakes the workers close (cdnca_site.dropped). The set
-- lives in the state dictionary under "drop:<name>": it survives a reload
-- (HUP keeps the zone), a restart empties it and the agent pushes it again.
--   PUT    /site-drop  {"hosts":[...]}  replaces the whole set
--   DELETE /site-drop                   empties it
--   GET    /site-drop                   {"hosts": n}
local SITE_DROP_PATH = "/site-drop"
local MAX_DROP_HOSTS = 100000

local function drop_keys()
    local keys = {}
    for _, key in ipairs(state_dict:get_keys(0)) do
        if sub(key, 1, #site.DROP_PREFIX) == site.DROP_PREFIX then
            keys[#keys + 1] = key
        end
    end
    return keys
end

-- drop_replace(raw): the new set is written before the old names are
-- removed, so a name in both sets is never open in between. clear empties it.
local function drop_replace(raw, clear)
    local wanted = {}
    local count = 0
    if not clear then
        local body = raw and cjson.decode(raw)
        local hosts = type(body) == "table" and body.hosts
        if type(hosts) ~= "table" or #hosts > MAX_DROP_HOSTS then
            fail(400, "body must be {\"hosts\":[...]} with at most " .. MAX_DROP_HOSTS .. " names")
        end
        for _, host in ipairs(hosts) do
            local name = site.drop_name(host)
            if not name then
                fail(400, "invalid host " .. tostring(host))
            end
            if not wanted[name] then
                wanted[name] = true
                count = count + 1
            end
        end
    end
    for name in pairs(wanted) do
        must(state_dict:safe_set(site.DROP_PREFIX .. name, true), "site drop")
    end
    for _, key in ipairs(drop_keys()) do
        if not wanted[sub(key, #site.DROP_PREFIX + 1)] then
            state_dict:delete(key)
        end
    end
    return { hosts = count }
end

local function drop_clear()
    return drop_replace(nil, true)
end

function _M.handle()
    local method = ngx.req.get_method()
    local uri = ngx.var.uri
    local gen = tonumber(ngx.var.arg_gen)
    if method == "POST" and uri == "/stage" then
        return run_locked(stage, read_body())
    elseif method == "POST" and uri == "/commit" then
        return run_locked(commit, gen)
    elseif method == "POST" and uri == "/abort" then
        return run_locked(abort, gen)
    elseif method == "POST" and uri == "/rollback" then
        return run_locked(rollback, gen)
    elseif method == "POST" and uri == "/rebuild" then
        state_dict:set("rebuild", cjson.encode({ started = ngx.now(), done = 0, queued = true }))
        local ok, err = ngx.timer.at(0, function(premature)
            if not premature then
                rebuild(true)
            end
        end)
        if not ok then
            return respond(500, { error = tostring(err) })
        end
        return respond(202, { queued = true })
    elseif method == "GET" and uri == "/probe" then
        local found, state, matched, digest = site.lookup(ngx.var.arg_port, ngx.var.arg_host)
        return respond(200, {
            state = state, matched = matched or cjson.null, digest = digest or cjson.null,
            site_id = found and found.site_id or cjson.null, generation = site.generation(),
        })
    elseif method == "GET" and uri == "/status" then
        return respond(200, status())
    elseif method == "PUT" and uri == SITE_DROP_PATH then
        return run_locked(drop_replace, read_body())
    elseif method == "DELETE" and uri == SITE_DROP_PATH then
        return run_locked(drop_clear)
    elseif method == "GET" and uri == SITE_DROP_PATH then
        return respond(200, { hosts = #drop_keys() })
    end
    return respond(404, { error = "not found" })
end

return _M
