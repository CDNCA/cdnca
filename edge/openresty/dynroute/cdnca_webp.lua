-- cdnca_webp: per-site JPEG/PNG to WebP (site.access.webp,
-- capability EDGE_WEBP). The response headers are sent before the body is
-- complete, so an image is never converted while a client waits (a failure
-- could not fall back to the original any more):
--   1. A convertible response (200, image/jpeg or image/png, identity
--      encoding, ETag or Last-Modified, no Range) gets Vary: Accept.
--   2. A client whose Accept lists image/webp and whose object has a
--      variant gets it: Content-Type image/webp, the variant's length, a
--      weak ETag of its own.
--   3. Otherwise the client gets the original; the first such request for
--      an object collects its body (up to MAX_BYTES) and a timer converts it
--      in the cdnca_webp worker thread pool (cdnca_webp_codec, libgd). The
--      variant (only if smaller) or a failure mark goes to the shared
--      dictionary cdnca_webp for every worker.
-- The node cache keeps the original only (Vary is added after the cache);
-- the variant is keyed by site, request URI, ETag / Last-Modified and length,
-- so a changed original never gets an old variant. CPU and memory: one
-- conversion per object at a time, at most MAX_INFLIGHT on the node, images
-- up to MAX_BYTES and MAX_PIXELS (read from the JPEG SOF / PNG IHDR header,
-- not decoded), animated PNG skipped.
local _M = {}

local dict = ngx.shared.cdnca_webp
local THREAD_POOL = "cdnca_webp"
local MAX_BYTES = 5 * 1024 * 1024
local MAX_PIXELS = 8 * 1024 * 1024
local MAX_INFLIGHT = 8
local VARIANT_TTL = 86400
local FAILURE_TTL = 3600
local PENDING_TTL = 60
local DEFAULT_QUALITY = 80
local FAILED = "\0"
local INFLIGHT = "inflight"

local byte, sub, find, lower = string.byte, string.sub, string.find, string.lower

local function u16(data, at) local a, b = byte(data, at, at + 1); return a * 256 + b end
local function u32(data, at) local a, b, c, d = byte(data, at, at + 3); return ((a * 256 + b) * 256 + c) * 256 + d end

-- dimensions(kind, data): width and height from the header, false for an
-- animated PNG, nil if unreadable.
local function dimensions(kind, data)
    local length = #data
    if kind == "png" then
        if length < 33 or sub(data, 1, 8) ~= "\137PNG\r\n\26\n" or sub(data, 13, 16) ~= "IHDR" then
            return nil
        end
        local width, height = u32(data, 17), u32(data, 21)
        local at = 9
        while at + 8 <= length do
            local size, name = u32(data, at), sub(data, at + 4, at + 7)
            if name == "acTL" then return false end
            if name == "IDAT" then break end
            at = at + 12 + size
        end
        return width, height
    end
    if length < 4 or byte(data, 1) ~= 0xFF or byte(data, 2) ~= 0xD8 then
        return nil
    end
    local at = 3
    while at + 9 <= length do
        if byte(data, at) ~= 0xFF then return nil end
        local marker = byte(data, at + 1)
        if marker == 0xFF then
            at = at + 1
        elseif marker == 0xD8 or marker == 0x01 or marker >= 0xD0 and marker <= 0xD7 then
            at = at + 2
        else
            if marker >= 0xC0 and marker <= 0xCF and marker ~= 0xC4 and marker ~= 0xC8 and marker ~= 0xCC then
                return u16(data, at + 7), u16(data, at + 5)
            end
            if marker == 0xD9 or marker == 0xDA then return nil end
            at = at + 2 + u16(data, at + 2)
        end
    end
    return nil
end

local function kind_of(content_type)
    if type(content_type) ~= "string" then return nil end
    local mime = lower(content_type:match("^%s*([^;%s]+)") or "")
    if mime == "image/jpeg" or mime == "image/pjpeg" then return "jpeg" end
    if mime == "image/png" then return "png" end
    return nil
end

local function add_vary(value)
    local vary = ngx.header["Vary"]
    if type(vary) == "table" then
        vary[#vary + 1] = value
    elseif vary then
        if vary == "*" then return end
        vary = { vary, value }
    else
        vary = value
    end
    ngx.header["Vary"] = vary
end

local function release()
    local left = dict:incr(INFLIGHT, -1, 0)
    if left and left < 0 then dict:set(INFLIGHT, 0) end
end

local function convert(premature, key, kind, data, quality)
    if premature then
        dict:delete("p:" .. key)
        release()
        return
    end
    local ok, done, webp, reason = pcall(ngx.run_worker_thread, THREAD_POOL, "cdnca_webp_codec", "convert", kind, data, quality)
    if ok and done and webp and #webp < #data then
        local stored, err = dict:set(key, webp, VARIANT_TTL)
        if not stored then ngx.log(ngx.WARN, "cdnca webp: variant not stored: ", err) end
    else
        dict:set(key, FAILED, FAILURE_TTL)
        if not ok or not done then
            ngx.log(ngx.WARN, "cdnca webp: conversion not run: ", tostring(done or webp))
        elseif not webp then
            ngx.log(ngx.INFO, "cdnca webp: kept the original: ", tostring(reason))
        end
    end
    dict:delete("p:" .. key)
    release()
end

-- header_filter(site): before the compression gate (it sees image/webp).
function _M.header_filter(site)
    local settings = site.access and site.access.webp
    if not settings or not settings.enabled or ngx.is_subrequest or ngx.status ~= 200 then
        return
    end
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then return end
    local header = ngx.header
    local kind = kind_of(header["Content-Type"])
    if not kind or header["Content-Encoding"] or header["Content-Range"] then return end
    local etag, modified = header["ETag"], header["Last-Modified"]
    if type(etag) == "table" or type(modified) == "table" or not etag and not modified then return end
    local length = tonumber(header["Content-Length"])
    if length and length > MAX_BYTES then return end
    add_vary("Accept")
    local request = ngx.req.get_headers()
    local accept = request["Accept"]
    if type(accept) == "table" then accept = table.concat(accept, ",") end
    if type(accept) ~= "string" or not find(lower(accept), "image/webp", 1, true) or request["Range"] then
        return
    end
    local key = ngx.md5(table.concat({ site.site_id, ngx.var.request_uri, etag or "", modified or "", length or "" }, "\0"))
    local variant = dict:get(key)
    local ctx = ngx.ctx
    if variant and variant ~= FAILED then
        header["Content-Type"] = "image/webp"
        header["Content-Length"] = #variant
        if etag then
            header["ETag"] = 'W/"' .. ngx.md5(etag .. "\0webp") .. '"'
        end
        header["Accept-Ranges"] = nil
        ctx.cdnca_webp = { variant = variant }
        return
    end
    if variant or method == "HEAD" then return end
    -- one collection per object; the node-wide limit is checked at the end
    if dict:add("p:" .. key, true, PENDING_TTL) then
        ctx.cdnca_webp = { key = key, kind = kind, chunks = {}, size = 0,
            quality = tonumber(settings.quality) and settings.quality > 0 and settings.quality or DEFAULT_QUALITY }
    end
end

function _M.body_filter()
    local state = ngx.ctx.cdnca_webp
    if not state then return end
    if state.variant then
        if state.sent then
            ngx.arg[1] = nil
        else
            state.sent = true
            ngx.arg[1], ngx.arg[2] = state.variant, true
        end
        return
    end
    if state.done then return end
    local chunk, eof = ngx.arg[1], ngx.arg[2]
    if chunk and chunk ~= "" then
        state.size = state.size + #chunk
        if state.size > MAX_BYTES then
            state.done = true
            state.chunks = nil
            dict:set(state.key, FAILED, FAILURE_TTL)
            dict:delete("p:" .. state.key)
            return
        end
        state.chunks[#state.chunks + 1] = chunk
    end
    if not eof then return end
    state.done = true
    local data = table.concat(state.chunks)
    state.chunks = nil
    local width, height = dimensions(state.kind, data)
    if not width or width * height > MAX_PIXELS or width == 0 or height == 0 then
        dict:set(state.key, FAILED, FAILURE_TTL)
        dict:delete("p:" .. state.key)
        return
    end
    local inflight = dict:incr(INFLIGHT, 1, 0)
    if not inflight or inflight > MAX_INFLIGHT then
        -- busy: a later request tries again
        if inflight then release() end
        dict:delete("p:" .. state.key)
        return
    end
    local ok, err = ngx.timer.at(0, convert, state.key, state.kind, data, state.quality)
    if not ok then
        ngx.log(ngx.WARN, "cdnca webp: timer: ", err)
        release()
        dict:delete("p:" .. state.key)
    end
end

-- for tests: the header reader and the limits
_M.dimensions = dimensions
_M.MAX_BYTES, _M.MAX_PIXELS, _M.MAX_INFLIGHT = MAX_BYTES, MAX_PIXELS, MAX_INFLIGHT

return _M
