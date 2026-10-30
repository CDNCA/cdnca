-- Cases of scripts/security/waf-inspect-smoke.sh: each sends one request with
-- the inspect clause (JSON, base64 in X-Spec) to the test server and checks
-- whether it matched and, when given, the reported fragment / detector.
local cjson = require("cjson")

local function request(raw)
    local socket = ngx.socket.tcp()
    socket:settimeout(10000)
    assert(socket:connect("127.0.0.1", 18090))
    assert(socket:send(raw))
    local response, err, partial = socket:receive("*a")
    socket:close()
    return response or partial or ""
end

local function build(spec, options)
    options = options or {}
    local lines = { (options.method or "GET") .. " " .. (options.target or "/") .. " HTTP/" .. (options.version or "1.1"), "Host: inspect.test",
        "Connection: close", "X-Spec: " .. ngx.encode_base64(cjson.encode(spec)) }
    for _, header in ipairs(options.headers or {}) do lines[#lines + 1] = header end
    local body = options.body or ""
    if body ~= "" then
        lines[#lines + 1] = "Content-Type: " .. (options.content_type or "text/plain")
        lines[#lines + 1] = "Content-Length: " .. #body
    end
    return table.concat(lines, "\r\n") .. "\r\n\r\n" .. body
end

local failures, total = 0, 0
local function case(name, spec, options, want, fragment, detector)
    total = total + 1
    local response = request(build(spec, options))
    local got = response:match("\r\n\r\n%x*\r?\n?(%a+)\n")
    local got_fragment = response:match("\r\n[Xx]%-[Ff]ragment: ([^\r\n]*)") or ""
    local got_detector = response:match("\r\n[Xx]%-[Dd]etector: ([^\r\n]*)") or ""
    local ok = got == (want and "match" or "nomatch") and (fragment == nil or got_fragment:find(fragment, 1, true) ~= nil) and
        (detector == nil or got_detector == detector)
    if not ok then failures = failures + 1 end
    print((ok and "PASS " or "FAIL ") .. name .. " got=" .. tostring(got) .. " fragment=" .. got_fragment .. " detector=" .. got_detector)
end

local form = "application/x-www-form-urlencoded"
-- Content-Type and HTTP version.
case("content_type prefix", { target = "content_type", operator = "prefix", values = { "application/json" } },
    { method = "POST", body = "{}", content_type = "application/json; charset=utf-8" }, true)
case("content_type prefix other", { target = "content_type", operator = "prefix", values = { "application/json" } },
    { method = "POST", body = "a=1", content_type = "application/x-www-form-urlencoded" }, false)
case("content_type missing is empty", { target = "content_type", operator = "eq", values = { "0" }, filters = { "length" } },
    {}, true)
case("content_type regex", { target = "content_type", operator = "regex", values = { "(?i)^multipart/" } },
    { method = "POST", body = "x", content_type = "Multipart/form-data; boundary=x" }, true)
case("http_version 1.0", { target = "http_version", operator = "equals", values = { "1.0" } }, { version = "1.0" }, true)
case("http_version 1.1 not 1.0", { target = "http_version", operator = "equals", values = { "1.0" } }, {}, false)
case("http_version not_equals", { target = "http_version", operator = "not_equals", values = { "1.1", "2" } }, { version = "1.0" }, true)
case("http_version not_equals own", { target = "http_version", operator = "not_equals", values = { "1.1", "2" } }, {}, false)
-- IP list conditions (the client is 127.0.0.1).
local function ip_list(cidrs, negate) return { id = "0190a000-0000-7000-8000-000000000001", revision = 1, negate = negate, cidrs = cidrs } end
case("ip_list hit", ip_list({ "10.0.0.0/8", "127.0.0.0/24" }), { target = "/iplist" }, true)
case("ip_list host hit", ip_list({ "127.0.0.1/32" }), { target = "/iplist" }, true)
case("ip_list miss", ip_list({ "10.0.0.0/8", "2001:db8::/32" }), { target = "/iplist" }, false)
case("ip_list negate miss", ip_list({ "10.0.0.0/8" }, true), { target = "/iplist" }, true)
case("ip_list negate hit", ip_list({ "127.0.0.0/8" }, true), { target = "/iplist" }, false)
case("ip_list empty never", ip_list({}), { target = "/iplist" }, false)
-- Named values.
case("query key hit", { target = "query", key = "id", operator = "regex", values = { "^\\d+ or" } }, { target = "/?id=1%20or%201=1&x=ok" }, true, "1 or")
case("query key other param", { target = "query", key = "x", operator = "contains", values = { "or 1" } }, { target = "/?id=1%20or%201=1&x=ok" }, false)
case("query key missing", { target = "query", key = "nope", operator = "contains", values = { "a" } }, { target = "/?a=a" }, false)
case("args key form", { target = "args", key = "user", operator = "equals", values = { "admin" } },
    { method = "POST", body = "user=admin&pw=x", content_type = form }, true)
case("body key form", { target = "body", key = "pw", operator = "contains", values = { "'--" } },
    { method = "POST", body = "user=a&pw=%27--", content_type = form }, true, "'--")
case("body key json path", { target = "body", key = "user.roles.1", operator = "equals", values = { "root" } },
    { method = "POST", body = '{"user":{"roles":["guest","root"]}}', content_type = "application/json" }, true)
case("body key json number", { target = "body", key = "n", operator = "equals", values = { "7" } },
    { method = "POST", body = '{"n":7}', content_type = "application/json" }, true)
case("body key json other", { target = "body", key = "user.name", operator = "contains", values = { "root" } },
    { method = "POST", body = '{"user":{"name":"bob","x":"root"}}', content_type = "application/json" }, false)
case("cookie key", { target = "cookie", key = "sid", operator = "regex", values = { "^[a-f0-9]{8}$" } },
    { headers = { "Cookie: a=1; sid=deadbeef" } }, true)
case("cookie key not other", { target = "cookie", key = "a", operator = "regex", values = { "^[a-f0-9]{8}$" } },
    { headers = { "Cookie: a=1; sid=deadbeef" } }, false)
case("header names", { target = "header_names", operator = "equals", values = { "x-evil" } }, { headers = { "X-Evil: 1" } }, true)

-- Multipart uploads.
local boundary = "----cdnca"
local multipart = "--" .. boundary .. "\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--" .. boundary ..
    "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.PhP\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php ?>\r\n--" ..
    boundary .. "--\r\n"
local upload = { method = "POST", body = multipart, content_type = "multipart/form-data; boundary=" .. boundary }
case("upload extension", { target = "upload_extension", operator = "equals", values = { "php", "jsp" } }, upload, true)
case("upload filename", { target = "upload_filename", operator = "suffix", values = { ".PhP" } }, upload, true, "shell.PhP")
case("upload none", { target = "upload_extension", operator = "equals", values = { "php" } },
    { method = "POST", body = "filename=\"a.php\"", content_type = "text/plain" }, false)
local big_upload = "--" .. boundary .. "\r\nContent-Disposition: form-data; name=\"pad\"\r\n\r\n" .. string.rep("p", 200000) ..
    "\r\n--" .. boundary .. "\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.jsp\"\r\n\r\nx\r\n--" .. boundary .. "--\r\n"
case("upload past body limit (temp file)", { target = "upload_extension", operator = "equals", values = { "jsp" } },
    { method = "POST", body = big_upload, content_type = "multipart/form-data; boundary=" .. boundary }, true)
case("upload filename* rfc5987", { target = "upload_extension", operator = "equals", values = { "asp" } },
    { method = "POST", content_type = "multipart/form-data; boundary=" .. boundary, body = "--" .. boundary ..
        "\r\nContent-Disposition: form-data; name=\"f\"; filename*=UTF-8''a%20b.ASP\r\n\r\nx\r\n--" .. boundary .. "--\r\n" }, true)

-- Multipart field names, part count, longest field.
local function mp(fields, b)
    b = b or boundary
    local out = {}
    for _, field in ipairs(fields) do out[#out + 1] = "--" .. b .. "\r\n" .. field[1] .. "\r\n\r\n" .. field[2] .. "\r\n" end
    return table.concat(out) .. "--" .. b .. "--\r\n"
end
local function mpreq(body, b) return { method = "POST", body = body, content_type = "multipart/form-data; boundary=" .. (b or boundary) } end
local php2shell = { target = "multipart_field_names", operator = "equals", values = { "php_session_upload_progress" }, filters = { "lowercase" } }
case("php2shell exact", php2shell, mpreq(mp({ { 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', "x" },
    { 'Content-Disposition: form-data; name="f"; filename="a.txt"', "data" } })), true, "php_session_upload_progress")
case("php2shell lower case", php2shell, mpreq(mp({ { 'content-disposition: form-data; name="php_session_upload_progress"', "x" } })), true)
case("php2shell mixed after filename", php2shell, mpreq(mp({ { 'Content-Disposition: form-data; filename="a.txt"; name="Php_Session_Upload_Progress"', "x" } })), true)
case("php2shell unquoted", php2shell, mpreq(mp({ { "Content-Disposition: form-data; name=PHP_SESSION_UPLOAD_PROGRESS", "x" } })), true)
case("php2shell name* rfc5987", php2shell, mpreq(mp({ { "Content-Disposition: form-data; name*=UTF-8''PHP%5FSESSION_UPLOAD_PROGRESS", "x" } })), true)
case("php2shell filename only is no name", php2shell, mpreq(mp({ { 'Content-Disposition: form-data; name="f"; filename="PHP_SESSION_UPLOAD_PROGRESS"', "x" } })), false)
case("php2shell as value is no name", php2shell, mpreq(mp({ { 'Content-Disposition: form-data; name="note"', "PHP_SESSION_UPLOAD_PROGRESS" } })), false)
case("php2shell prefix name no match", php2shell, mpreq(mp({ { 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS_X"', "x" } })), false)
case("php2shell urlencoded not multipart", php2shell, { method = "POST", body = "PHP_SESSION_UPLOAD_PROGRESS=1", content_type = form }, false)
-- after 200 KB of padding (temporary body file, chunked scan)
case("php2shell in body file", php2shell, mpreq(mp({ { 'Content-Disposition: form-data; name="pad"', string.rep("p", 200000) },
    { 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', "x" } })), true)
-- across a 64 KiB chunk boundary
local split_pad = string.rep("q", 65536 - 80)
case("php2shell across chunk boundary", php2shell, mpreq(mp({ { 'Content-Disposition: form-data; name="pad"', split_pad },
    { 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', "x" } })), true)
-- WordPress media upload (async-upload.php) and an ordinary multi-field form
local wp = mp({ { 'Content-Disposition: form-data; name="name"', "photo.jpg" }, { 'Content-Disposition: form-data; name="action"', "upload-attachment" },
    { 'Content-Disposition: form-data; name="_wpnonce"', "0123456789" },
    { 'Content-Disposition: form-data; name="async-upload"; filename="photo.jpg"\r\nContent-Type: image/jpeg', string.rep("\255", 300000) } },
    "----WebKitFormBoundaryAbC123")
local wp_req = mpreq(wp, "----WebKitFormBoundaryAbC123")
case("wordpress upload not php2shell", php2shell, wp_req, false)
local parts_limit = { target = "multipart_part_count", operator = "gt", values = { "1000" } }
local field_limit = { target = "multipart_field_max_length", operator = "gt", values = { "1048576" } }
case("wordpress upload part count 4", { target = "multipart_part_count", operator = "eq", values = { "4" } }, wp_req, true)
case("wordpress upload file not a field", { target = "multipart_field_max_length", operator = "eq", values = { "17" } }, wp_req, true)
local fields = {}
for index = 1, 30 do fields[index] = { 'Content-Disposition: form-data; name="f' .. index .. '"', "value " .. index } end
case("form 30 fields under part limit", parts_limit, mpreq(mp(fields)), false)
case("form field max length", { target = "multipart_field_max_length", operator = "eq", values = { "8" } }, mpreq(mp(fields)), true)
local many = {}
for index = 1, 1001 do many[index] = { 'Content-Disposition: form-data; name="a' .. index .. '"', "1" } end
case("1001 parts over limit", parts_limit, mpreq(mp(many)), true, "1001")
local exact = {}
for index = 1, 1000 do exact[index] = { 'Content-Disposition: form-data; name="a' .. index .. '"', "1" } end
case("1000 parts at limit", parts_limit, mpreq(mp(exact)), false)
case("LF-only delimiters counted", { target = "multipart_part_count", operator = "eq", values = { "2" } },
    mpreq("--" .. boundary .. "\nContent-Disposition: form-data; name=\"a\"\n\n1\n--" .. boundary ..
        "\nContent-Disposition: form-data; name=\"b\"\n\n2\n--" .. boundary .. "--\n"), true)
case("quoted boundary", { target = "multipart_part_count", operator = "eq", values = { "1" } },
    { method = "POST", body = mp({ { 'Content-Disposition: form-data; name="a"', "1" } }, "q b"), content_type = 'multipart/form-data; boundary="q b"' }, true)
case("field over 1 MiB", field_limit, mpreq(mp({ { 'Content-Disposition: form-data; name="big"', string.rep("z", 1048577) } })), true, "1048577")
case("field at 1 MiB", field_limit, mpreq(mp({ { 'Content-Disposition: form-data; name="big"', string.rep("z", 1048576) } })), false)
case("file over 1 MiB is no field", field_limit, mpreq(mp({ { 'Content-Disposition: form-data; name="f"; filename="big.bin"', string.rep("z", 2000000) } })), false)
case("unterminated field measured", field_limit, mpreq("--" .. boundary .. '\r\nContent-Disposition: form-data; name="big"\r\n\r\n' .. string.rep("z", 1100000)), true)

-- Official pack system/waf-php-vpatch, R3 / R4 clauses as shipped.
-- R3 CVE-2024-4577: soft hyphen (%AD, decoded to 0xAD) then d and a PHP ini name in the raw request URI.
local cve4577 = { target = "request_uri", operator = "regex", values = { "(?i)\\xad-?d.*(allow_url_include|auto_prepend_file)" } }
case("cve-2024-4577 %AD d allow_url_include", cve4577,
    { method = "POST", target = "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input" }, true)
case("cve-2024-4577 lower %ad", cve4577, { target = "/index.php?%add+auto_prepend_file=php://input" }, true)
case("cve-2024-4577 %AD-d form", cve4577, { target = "/test.php?%AD-d+allow_url_include=1" }, true)
case("cve-2024-4577 plain -d is CRS business", cve4577, { target = "/test.php?-d+allow_url_include=1" }, false)
case("cve-2024-4577 %AD in a normal value", cve4577, { target = "/search?q=caf%AD&page=2" }, false)
case("cve-2024-4577 ini name alone", cve4577, { target = "/docs/allow_url_include.html" }, false)
-- R4 CVE-2026-6722 signal: SOAP content type and apache:Map in the body (both clauses).
-- Inspect values are URL-decoded (push_value), so "soap+xml" arrives as "soap xml".
local soap_type = { target = "content_type", operator = "regex", values = { "(?i)^\\s*(text/xml|application/soap[+ ]xml)" } }
local soap_map = { target = "body", operator = "contains", values = { "apache:map" } }
local soap_body = '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"' ..
    ' xmlns:apache="http://xml.apache.org/xml-soap"><SOAP-ENV:Body><m><x xsi:type="apache:Map"><item><key>a</key>' ..
    '<value>1</value></item><item><key>a</key><value>2</value></item></x></m></SOAP-ENV:Body></SOAP-ENV:Envelope>'
case("soap apache:Map content type", soap_type, { method = "POST", body = soap_body, content_type = "text/xml; charset=utf-8" }, true)
case("soap 1.2 content type", soap_type, { method = "POST", body = soap_body, content_type = "application/soap+xml" }, true)
case("soap apache:Map body", soap_map, { method = "POST", body = soap_body, content_type = "text/xml; charset=utf-8" }, true)
case("json is no soap", soap_type, { method = "POST", body = '{"apache:Map":1}', content_type = "application/json" }, false)
case("plain soap without Map", soap_map, { method = "POST", body = "<Envelope><Body><ping/></Body></Envelope>", content_type = "text/xml" }, false)

-- Number targets and the length filter.
case("uri length gt", { target = "uri_length", operator = "gt", values = { "20" } }, { target = "/" .. string.rep("a", 30) }, true)
case("uri length not gt", { target = "uri_length", operator = "gt", values = { "200" } }, { target = "/short" }, false)
case("header max length", { target = "header_max_length", operator = "gte", values = { "1000" } },
    { headers = { "X-Long: " .. string.rep("z", 1200) } }, true)
case("header count", { target = "header_count", operator = "gt", values = { "10" } }, { headers = { "A: 1", "B: 2" } }, false)
case("arg count", { target = "arg_count", operator = "gte", values = { "3" } }, { target = "/?a=1&b=2&c=3" }, true)
case("body length", { target = "body_length", operator = "gt", values = { "100000" } },
    { method = "POST", body = string.rep("b", 120000) }, true)
case("length filter on header", { target = "header", key = "user-agent", operator = "eq", values = { "0" }, filters = { "length" } },
    { headers = { "User-Agent: " } }, true)
case("missing UA is empty", { target = "user_agent", operator = "eq", values = { "0" }, filters = { "length" } }, {}, true)
case("length filter gt", { target = "query", key = "q", operator = "gt", values = { "5" }, filters = { "length" } },
    { target = "/?q=abcdefgh" }, true)

-- Operators.
case("not_contains holds", { target = "user_agent", operator = "not_contains", values = { "mozilla" } },
    { headers = { "User-Agent: curl/8" } }, true)
case("not_contains fails", { target = "user_agent", operator = "not_contains", values = { "mozilla" } },
    { headers = { "User-Agent: Mozilla/5.0" } }, false)
case("not_contains on missing value", { target = "referer", operator = "not_contains", values = { "example" } }, {}, true)
case("not_regex", { target = "path", operator = "not_regex", values = { "^/api/" } }, { target = "/admin" }, true)
case("contains_all hit", { target = "query", operator = "contains_all", values = { "union", "select" } },
    { target = "/?q=UNION%20all%20SELECT" }, true)
case("contains_all partial", { target = "query", operator = "contains_all", values = { "union", "select" } },
    { target = "/?q=union" }, false)
case("prefix", { target = "path", operator = "prefix", values = { "/wp-" } }, { target = "/wp-login.php" }, true)
case("not_equals", { target = "header", key = "x-a", operator = "not_equals", values = { "1" } }, { headers = { "X-A: 2" } }, true)

-- Filters.
case("base64 decode", { target = "query", key = "p", operator = "contains", values = { "<script" }, filters = { "base64_decode" } },
    { target = "/?p=" .. ngx.encode_base64("<script>alert(1)</script>") }, true)
case("unicode decode", { target = "query", key = "p", operator = "contains", values = { "<script" }, filters = { "unicode_decode" } },
    { target = "/?p=%5Cu003cscript%5Cu003e" }, true)
case("html unescape", { target = "query", key = "p", operator = "contains", values = { "<img" }, filters = { "html_unescape" } },
    { target = "/?p=%26lt%3Bimg%20src%3Dx%26gt%3B" }, true)
case("detect after decode", { target = "query", key = "p", operator = "detect", values = { "xss" }, filters = { "base64_decode" } },
    { target = "/?p=" .. ngx.encode_base64("<img src=x onerror=alert(1)>") }, true, nil, "xss")

-- Body overflow (64 KiB inspection limit).
local tail = string.rep("a", 70000) .. "' or 1=1--"
case("overflow inspects first bytes only", { target = "body", operator = "contains", values = { "or 1=1" } },
    { method = "POST", body = tail }, false)
case("overflow match", { target = "body", operator = "contains", values = { "never" }, body_overflow = "match" },
    { method = "POST", body = tail }, true)
case("no overflow no match", { target = "body", operator = "contains", values = { "never" }, body_overflow = "match" },
    { method = "POST", body = "small" }, false)
case("long raw body chunks", { target = "body", operator = "contains", values = { "needle" } },
    { method = "POST", body = string.rep("x", 30000) .. "needle" }, true, "needle")

print(string.format("waf inspect: %d cases, %d failures", total, failures))
if failures > 0 then os.exit(1) end
