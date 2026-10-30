-- Client side of tests/dynroute-security/firewall-action.sh: requests over a
-- cosocket, the report goes to /w/logs/report.
local _M = {}

local function get(path, client)
    local sock = ngx.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", 18970)
    if not ok then return "none " .. tostring(err) end
    sock:send("GET " .. path .. " HTTP/1.0\r\nHost: t\r\nX-Forwarded-For: " .. client .. "\r\n\r\n")
    local raw = sock:receive("*a") or ""
    sock:close()
    local status = raw:match("^HTTP/1%.%d (%d+)") or "none"
    local body = raw:match("\r\n\r\n(.*)$") or ""
    return status .. " " .. body:sub(1, 20)
end

function _M.run()
    local lines, fail = {}, false
    local function say(...) lines[#lines + 1] = table.concat({ ... }) end
    for _, client in ipairs({ "198.51.100.7", "203.0.113.9", "2001:db8:dead::1", "2001:db8:beef::1" }) do
        local v7, object = get("/v7", client), get("/object", client)
        if v7 == object and v7:sub(1, 4) ~= "none" then
            say("SAME   ", client, ": ", v7)
        else
            say("DIFF   ", client, ": v7=", v7, " object=", object)
            fail = true
        end
    end
    -- the blocked and the passing client must differ (the check is real)
    if get("/object", "198.51.100.7") == get("/object", "203.0.113.9") then
        say("FAIL   blocked and passing clients answered alike")
        fail = true
    end
    for _, path in ipairs({ "/tampered", "/other-site" }) do
        local got = get(path, "203.0.113.9")
        if got:sub(1, 3) == "503" then say("PASS   ", path, " refused: ", got) else say("FAIL   ", path, ": ", got) fail = true end
    end
    say(fail and "RESULT fail" or "RESULT ok")
    local file = io.open("/w/logs/report", "w")
    file:write(table.concat(lines, "\n"), "\n")
    file:close()
end

return _M
