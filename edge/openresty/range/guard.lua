local _M = {}

local MAX_EXACT_INTEGER = "9007199254740991"
local MAX_UPSTREAM_STATUS_BYTES = 318

local function strip_zeroes(value)
    local stripped = value:gsub("^0+", "")
    if stripped == "" then
        return "0"
    end
    return stripped
end

local function bounded_decimal(value)
    if type(value) ~= "string" or not value:match("^%d+$") then
        return nil
    end
    value = strip_zeroes(value)
    if #value > #MAX_EXACT_INTEGER or (#value == #MAX_EXACT_INTEGER and value > MAX_EXACT_INTEGER) then
        return nil
    end
    return value
end

local function decimal_less(left, right)
    left = strip_zeroes(left)
    right = strip_zeroes(right)
    return #left < #right or (#left == #right and left < right)
end

local function single_header(headers, name)
    local value = headers[name]
    if type(value) == "table" then
        return nil, "duplicate"
    end
    if value ~= nil and type(value) ~= "string" then
        return nil, "invalid"
    end
    return value
end

local function reject(status)
    ngx.var.range_cache_guard_no_store = "1"
    ngx.ctx.range_cache_local_reject = true
    ngx.ctx.range_cache_skip_body_check = true
    ngx.status = status
    ngx.header["Content-Range"] = nil
    ngx.header["Content-Length"] = nil
    return ngx.exit(status)
end

local function trim_ows(value)
    return value:match("^[ \t]*(.-)[ \t]*$")
end

local function valid_ranges(value, max_ranges, max_span_bytes)
    local ranges = value:match("^bytes=(.*)$")
    if not ranges or ranges == "" then
        return nil
    end
    local parsed = {}
    for item in (ranges .. ","):gmatch("(.-),") do
        item = trim_ows(item)
        local first, last = item:match("^(%d*)%-(%d*)$")
        if first == nil or (first == "" and last == "") or #parsed >= max_ranges then
            return nil
        end
        if first ~= "" then
            first = bounded_decimal(first)
            if not first then
                return nil
            end
        end
        if last ~= "" then
            last = bounded_decimal(last)
            if not last or (first == "" and last == "0") then
                return nil
            end
        end
        if first ~= "" and last ~= "" then
            if decimal_less(last, first) or tonumber(last) - tonumber(first) + 1 > max_span_bytes then
                return nil
            end
        end
        parsed[#parsed + 1] = { first = first, last = last }
    end
    if #parsed == 0 then
        return nil
    end
    if #parsed > 1 then
        local total = 0
        for _, item in ipairs(parsed) do
            if item.first == "" or item.last == "" then
                return nil
            end
            total = total + tonumber(item.last) - tonumber(item.first) + 1
            if total > max_span_bytes then
                return nil
            end
        end
        table.sort(parsed, function(left, right)
            return decimal_less(left.first, right.first)
        end)
        for index = 2, #parsed do
            if not decimal_less(parsed[index - 1].last, parsed[index].first) then
                return nil
            end
        end
    end
    return #parsed
end

local function request_range_unsatisfied(value, total)
    if type(value) ~= "string" then
        return false
    end
    local first = value:match("^bytes=(%d*)%-%d*$")
    if first == nil then
        return false
    end
    if first == "" then
        return total == 0
    end
    first = bounded_decimal(first)
    return first ~= nil and tonumber(first) >= total
end

function _M.access(options)
    ngx.var.range_cache_guard_no_store = "0"
    local headers, error_message = ngx.req.get_headers(100)
    if error_message == "truncated" then
        return reject(431)
    end
    local range, range_error = single_header(headers, "range")
    if range_error then
        return reject(400)
    end
    local if_range, if_range_error = single_header(headers, "if-range")
    if if_range_error then
        return reject(400)
    end
    if range and (#range > options.max_range_bytes or ngx.req.get_method() ~= "GET" and ngx.req.get_method() ~= "HEAD") then
        return reject(#range > options.max_range_bytes and 431 or 416)
    end
    local range_count
    if range then
        range_count = valid_ranges(range, options.max_ranges or 1,
            options.max_range_span_bytes or 9007199254740991)
        if not range_count then
            return reject(416)
        end
    end
    ngx.ctx.range_cache_request = range
    ngx.ctx.range_cache_request_multi = range_count ~= nil and range_count > 1
    if if_range then
        if #if_range > options.max_if_range_bytes then
            return reject(431)
        end
        if if_range:find("[%z\1-\31\127]") then
            return reject(400)
        end
    end
end

local function response_header_size(headers)
    local total = 0
    for name, value in pairs(headers) do
        total = total + #tostring(name) + 4
        if type(value) == "table" then
            for _, item in ipairs(value) do
                total = total + #tostring(item) + 2
            end
        else
            total = total + #tostring(value) + 2
        end
    end
    return total
end

local function parse_content_range(value)
    if type(value) ~= "string" then
        return nil
    end
    local first, last, total = value:match("^bytes (%d+)%-(%d+)/(%d+)$")
    first = first and bounded_decimal(first)
    last = last and bounded_decimal(last)
    total = total and bounded_decimal(total)
    if not first or not last or not total or decimal_less(last, first) or not decimal_less(last, total) then
        return nil
    end
    return tonumber(first), tonumber(last), tonumber(total)
end

local function parse_unsatisfied_range(value)
    if type(value) ~= "string" then
        return nil
    end
    local total = value:match("^bytes %*/(%d+)$")
    total = total and bounded_decimal(total)
    return total and tonumber(total) or nil
end

local function parse_slice_range(value)
    if type(value) ~= "string" then
        return nil
    end
    local first, last = value:match("^bytes=(%d+)%-(%d+)$")
    first = first and bounded_decimal(first)
    last = last and bounded_decimal(last)
    if not first or not last or decimal_less(last, first) then
        return nil
    end
    return tonumber(first), tonumber(last)
end

local function filter_failure(reason)
    ngx.log(ngx.ERR, "range cache response rejected: ", reason or "metadata validation",
        " status=", ngx.status, " upstream_status=", tostring(ngx.var.upstream_status),
        " content_range=", tostring(ngx.header["Content-Range"]),
        " upstream_content_range=", tostring(ngx.var.upstream_http_content_range),
        " slice_range=", tostring(ngx.var.slice_range))
    ngx.var.range_cache_guard_no_store = "1"
    ngx.ctx.range_cache_drop_body = true
    ngx.header["Content-Range"] = nil
    ngx.header["Content-Length"] = nil
    ngx.header["Content-Encoding"] = nil
    ngx.status = 502
end

local function header_number(value)
    if type(value) ~= "string" then
        return nil
    end
    local decimal = bounded_decimal(value)
    return decimal and tonumber(decimal) or nil
end

local function final_upstream_status(value)
    if value == "" then
        return ""
    end
    if type(value) ~= "string" or #value > MAX_UPSTREAM_STATUS_BYTES then
        return nil
    end
    local offset = 1
    while offset <= #value do
        local status = value:sub(offset, offset + 2)
        if not status:match("^%d%d%d$") then
            return nil
        end
        offset = offset + 3
        if offset > #value then
            return status
        end
        if value:sub(offset, offset) ~= "," then
            return nil
        end
        offset = offset + 1
        if value:sub(offset, offset) == " " then
            offset = offset + 1
        end
        if offset > #value then
            return nil
        end
    end
    return nil
end

function _M.header_filter(options)
    if ngx.ctx.range_cache_local_reject then
        return
    end
    local headers, error_message = ngx.resp.get_headers(100)
    if error_message == "truncated" or response_header_size(headers) > options.max_header_bytes then
        return filter_failure()
    end

    local content_range, range_error = single_header(headers, "content-range")
    local content_length, length_error = single_header(headers, "content-length")
    local content_encoding, encoding_error = single_header(headers, "content-encoding")
    local content_type, type_error = single_header(headers, "content-type")
    if range_error or length_error or encoding_error or type_error then
        return filter_failure()
    end
    if content_encoding and content_encoding ~= "" and string.lower(content_encoding) ~= "identity" then
        return filter_failure()
    end

    local upstream_status = final_upstream_status(ngx.var.upstream_status or "")
    if upstream_status == nil then
        return filter_failure("invalid upstream status chain")
    end
    local slice_range = ngx.var.slice_range or ""
    local upstream_unsatisfied_total
    if upstream_status == "200" then
        ngx.var.range_cache_guard_no_store = "1"
    end
    if upstream_status == "206" then
        if ngx.ctx.range_cache_request_multi then
            if slice_range ~= "" then
                return filter_failure("multi-range unexpectedly used slice mode")
            end
        else
            local upstream_range = ngx.var.upstream_http_content_range
            local first, last, total = parse_content_range(upstream_range)
            local requested_first, requested_last = parse_slice_range(slice_range)
            if not first or not requested_first or first ~= requested_first or last > requested_last or
                (last < requested_last and last ~= total - 1) then
                return filter_failure()
            end
            local upstream_length = header_number(ngx.var.upstream_http_content_length)
            if upstream_length and upstream_length ~= last - first + 1 then
                return filter_failure()
            end
        end
    elseif upstream_status == "416" then
        upstream_unsatisfied_total = parse_unsatisfied_range(ngx.var.upstream_http_content_range)
        local requested_first = parse_slice_range(slice_range)
        local unsatisfied = upstream_unsatisfied_total ~= nil and
            (requested_first ~= nil and requested_first >= upstream_unsatisfied_total or
                requested_first == nil and request_range_unsatisfied(ngx.ctx.range_cache_request, upstream_unsatisfied_total))
        if not unsatisfied then
            return filter_failure("invalid upstream 416 content-range=" .. tostring(ngx.var.upstream_http_content_range))
        end
    end

    if ngx.status == 206 then
        if ngx.ctx.range_cache_request_multi and not ngx.is_subrequest then
            local boundary = type(content_type) == "string" and
                content_type:match("^multipart/byteranges;[ \t]*boundary=([%w'()+_,%-%./:=?]+)$")
            local length = content_length and header_number(content_length)
            if content_range or not boundary or content_length and (not length or length == 0) then
                return filter_failure("invalid multipart response metadata")
            end
        else
            local first, last = parse_content_range(content_range)
            local length = header_number(content_length)
            if not first or not length or length ~= last - first + 1 then
                return filter_failure()
            end
        end
    elseif ngx.status == 200 then
        if content_range then
            return filter_failure()
        end
    elseif ngx.status == 416 then
        local total = parse_unsatisfied_range(content_range)
        if total == nil or upstream_unsatisfied_total ~= nil and total ~= upstream_unsatisfied_total then
            return filter_failure("invalid downstream 416 content-range=" .. tostring(content_range))
        end
    elseif content_range then
        return filter_failure()
    end
end

function _M.body_filter()
    if ngx.ctx.range_cache_drop_body then
        ngx.arg[1] = nil
    end
end

return _M
