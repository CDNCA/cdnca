-- resty rule_client.lua <requests.jsonl> <results.jsonl> <threads>
-- Sends each request (raw bytes, base64) to 127.0.0.1:<port>, reads the whole
-- response (requests carry Connection: close) and writes
-- {"id", "status", "result"} per request.
local cjson = require("cjson")
local input, output, threads = arg[1], arg[2], tonumber(arg[3]) or 8

local requests = {}
for line in io.lines(input) do requests[#requests + 1] = cjson.decode(line) end

local results = {}
local next_index = 0

local function send(request)
    local socket = ngx.socket.tcp()
    socket:settimeout(900000)
    local ok, err = socket:connect("127.0.0.1", request.port)
    if not ok then return { id = request.id, status = -1, result = "connect: " .. tostring(err) } end
    local sent, send_err = socket:send(ngx.decode_base64(request.raw))
    if not sent then
        socket:close()
        return { id = request.id, status = -3, result = "send: " .. tostring(send_err) }
    end
    local response, receive_err, partial = socket:receive("*a")
    socket:close()
    response = response or partial or ""
    local status = tonumber(response:match("^HTTP/1%.%d (%d%d%d)")) or -2
    local head = response:match("^(.-)\r\n\r\n") or response
    local result = head:match("\r\n[Xx]%-[Cc]dnca%-[Rr]esult: ([^\r\n]*)") or ""
    if status < 0 then result = "receive: " .. tostring(receive_err) end
    return { id = request.id, status = status, result = result }
end

local function worker()
    while true do
        next_index = next_index + 1
        local request = requests[next_index]
        if not request then return end
        local ok, result = pcall(send, request)
        results[#results + 1] = ok and result or { id = request.id, status = -4, result = tostring(result) }
    end
end

local running = {}
for _ = 1, threads do running[#running + 1] = ngx.thread.spawn(worker) end
for _, thread in ipairs(running) do ngx.thread.wait(thread) end

local file = assert(io.open(output, "wb"))
for _, result in ipairs(results) do file:write(cjson.encode(result), "\n") end
file:close()
print("sent " .. #results)
