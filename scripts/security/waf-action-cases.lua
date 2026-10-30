-- Cases of scripts/security/waf-action-smoke.sh: challenge (GET page + proof of
-- work + pass cookie; POST 307 keeping method and body), ban, auto block,
-- observe mode and unban, against nginx rendered by edgeconfig.
local cjson = require("cjson")
local resty_sha256 = require("resty.sha256")
local bit = require("bit")

local function request(port, raw)
    local socket = ngx.socket.tcp()
    socket:settimeout(10000)
    assert(socket:connect("127.0.0.1", port))
    assert(socket:send(raw))
    local response = socket:receive("*a") or ""
    socket:close()
    local status = tonumber(response:match("^HTTP/1%.%d (%d%d%d)")) or -1
    local head, body = response:match("^(.-)\r\n\r\n(.*)$")
    local headers = {}
    for name, value in (head or ""):gmatch("\r\n([^:\r\n]+):%s*([^\r\n]*)") do
        local key = string.lower(name)
        if headers[key] then headers[key] = headers[key] .. "\n" .. value else headers[key] = value end
    end
    return status, headers, body or ""
end

local function build(method, target, ip, extra, body)
    local lines = { method .. " " .. target .. " HTTP/1.1", "Host: action.test", "Connection: close",
        "X-Real-IP: " .. ip, "User-Agent: smoke/1" }
    for _, header in ipairs(extra or {}) do lines[#lines + 1] = header end
    if body then
        lines[#lines + 1] = "Content-Type: application/x-www-form-urlencoded"
        lines[#lines + 1] = "Content-Length: " .. #body
    end
    return table.concat(lines, "\r\n") .. "\r\n\r\n" .. (body or "")
end

local function cookie(headers, name)
    for line in (headers["set-cookie"] or ""):gmatch("[^\n]+") do
        local value = line:match("^" .. name:gsub("%-", "%%-") .. "=([^;]*)")
        if value then return value end
    end
end

local function solve(salt, bits)
    for counter = 0, 50000000 do
        local digest = resty_sha256:new()
        digest:update(salt .. ":" .. counter)
            local raw, zeros = digest:final(), 0
        for index = 1, #raw do
            local value = raw:byte(index)
            if value == 0 then zeros = zeros + 8 else
                while bit.band(value, 0x80) == 0 do zeros, value = zeros + 1, bit.lshift(value, 1) end
                break
            end
        end
        if zeros >= bits then return tostring(counter) end
    end
end

local failures, total = 0, 0
local function check(name, ok, detail)
    total = total + 1
    if not ok then failures = failures + 1 end
    print((ok and "PASS " or "FAIL ") .. name .. (detail and (" " .. detail) or ""))
end

local PORT = 18091
-- 1. GET challenge -> page -> verify -> pass cookie -> origin.
local status, headers, body = request(PORT, build("GET", "/challenge/page?q=1", "198.51.100.10"))
check("GET challenge page 503", status == 503 and headers["x-cdnca-waf"] == "challenge", tostring(status))
local token = body:match('name="token" value="(%x+)"')
local salt, bits = body:match('data%-salt="(%x+)" data%-bits="(%d+)"')
check("page carries token and pow", token ~= nil and salt ~= nil)
local pow = solve(salt, tonumber(bits))
status, headers = request(PORT, build("POST", "/.cdnca/waf/verify", "198.51.100.10", nil, "token=" .. token .. "&pow=" .. pow))
local pass = cookie(headers, "__cdnca_waf_pass")
check("verify 303 back to target", status == 303 and headers["location"] == "/challenge/page?q=1" and pass ~= nil, tostring(status))
local _
status, _, body = request(PORT, build("GET", "/challenge/page?q=1", "198.51.100.10", { "Cookie: __cdnca_waf_pass=" .. (pass or "") }))
check("passed request reaches origin", status == 200 and body:find("origin GET", 1, true) ~= nil, tostring(status))
status = request(PORT, build("GET", "/challenge/page", "203.0.113.99", { "Cookie: __cdnca_waf_pass=" .. (pass or "") }))
check("pass bound to client network", status == 503, tostring(status))
status = request(PORT, build("POST", "/.cdnca/waf/verify", "198.51.100.10", nil, "token=" .. token .. "&pow=" .. pow))
check("token single use", status == 403, tostring(status))

-- 2. POST challenge: 307 to the same URL, the repeat (method + body) passes.
status, headers = request(PORT, build("POST", "/challenge/form?x=1", "198.51.100.20", nil, "a=1&b=2"))
local probe = cookie(headers, "__cdnca_waf_probe")
check("POST challenge 307 same URL", status == 307 and headers["location"] == "/challenge/form?x=1" and probe ~= nil, tostring(status))
status, headers = request(PORT, build("POST", "/challenge/form?x=1", "198.51.100.20", { "Cookie: __cdnca_waf_probe=" .. (probe or "") }, "a=1&b=2"))
pass = cookie(headers, "__cdnca_waf_pass")
check("repeated POST gets pass + 307", status == 307 and pass ~= nil and headers["location"] == "/challenge/form?x=1", tostring(status))
status, _, body = request(PORT, build("POST", "/challenge/form?x=1", "198.51.100.20", { "Cookie: __cdnca_waf_pass=" .. (pass or "") }, "a=1&b=2"))
check("POST with pass keeps method and body", status == 200 and body:find("origin POST a=1&b=2", 1, true) ~= nil, tostring(status) .. " " .. body)

-- 3. Ban rule: the matching request and every later one of the client.
status, headers = request(PORT, build("GET", "/ban/me", "198.51.100.30"))
check("ban rule refuses", status == 403 and headers["x-cdnca-waf"] == "banned", tostring(status))
status = request(PORT, build("GET", "/innocent", "198.51.100.30"))
check("banned client refused on any path", status == 403, tostring(status))
status = request(PORT, build("GET", "/innocent", "198.51.100.31"))
check("other client unaffected", status == 200, tostring(status))

-- 4. Auto block: 3 blocks within the window ban the client.
for attempt = 1, 2 do --
    status = request(PORT, build("GET", "/blocked", "198.51.100.40"))
    check("block " .. attempt, status == 403, tostring(status))
end
status, headers = request(PORT, build("GET", "/blocked", "198.51.100.40"))
check("third block bans", status == 403 and headers["x-cdnca-waf"] == "banned", tostring(status))
status = request(PORT, build("GET", "/innocent", "198.51.100.40"))
check("auto banned client refused everywhere", status == 403, tostring(status))

-- 5. Observe mode (second server): block / ban rules only log.
status, _, body = request(18092, build("GET", "/blocked", "198.51.100.50"))
check("observe: block passes", status == 200 and body:find("origin GET", 1, true) ~= nil, tostring(status))
status = request(18092, build("GET", "/ban/me", "198.51.100.50"))
check("observe: ban passes", status == 200, tostring(status))
status = request(18092, build("GET", "/innocent", "198.51.100.50"))
check("observe: no ban recorded", status == 200, tostring(status))

-- 6. Unban (the agent's runtime command).
status, _, body = request(18093, "POST /unban HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: " ..
    #("198.51.100.30") .. "\r\n\r\n198.51.100.30")
check("unban reports the ban", status == 200 and body:find("true", 1, true) ~= nil, tostring(status) .. body)
status = request(PORT, build("GET", "/innocent", "198.51.100.30"))
check("unbanned client served", status == 200, tostring(status))

-- 7. fix-cfl-b: ACL (ban rule) + WAF (challenge) on one
-- site. The ACL segment's gate runs first on the verification POST; the
-- nonce is the WAF policy's, so it must pass on to the WAF gate (303 + pass)
-- instead of being consumed and refused 403 ("验证已失效").
status, _, body = request(18094, build("GET", "/challenge/dual", "198.51.100.60"))
check("dual: GET challenge page 503", status == 503, tostring(status))
token = body:match('name="token" value="(%x+)"')
salt, bits = body:match('data%-salt="(%x+)" data%-bits="(%d+)"')
pow = salt and solve(salt, tonumber(bits)) or ""
status, headers = request(18094, build("POST", "/.cdnca/waf/verify", "198.51.100.60", nil, "token=" .. (token or "") .. "&pow=" .. pow))
pass = cookie(headers, "__cdnca_waf_pass")
check("dual: verify passes the ACL gate (303 + pass)", status == 303 and pass ~= nil, tostring(status))
status, _, body = request(18094, build("GET", "/challenge/dual", "198.51.100.60", { "Cookie: __cdnca_waf_pass=" .. (pass or "") }))
check("dual: passed request reaches origin", status == 200 and body:find("origin GET", 1, true) ~= nil, tostring(status))
status = request(18094, build("POST", "/.cdnca/waf/verify", "198.51.100.60", nil, "token=" .. (token or "") .. "&pow=" .. pow))
check("dual: token still single use", status == 403, tostring(status))
status = request(18094, build("POST", "/.cdnca/waf/verify", "198.51.100.61", nil, "token=" .. string.rep("0", 32) .. "&pow=1"))
check("dual: unknown token refused", status == 403, tostring(status))

print(string.format("waf actions: %d checks, %d failures", total, failures))
if failures > 0 then os.exit(1) end
