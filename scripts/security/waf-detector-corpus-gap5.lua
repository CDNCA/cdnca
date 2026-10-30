-- waf-gap5 detector corpus: proto (JavaScript prototype pollution) and path
-- (path traversal and its encodings), run after the gap4 corpus
-- (scripts/security/waf-detector-corpus.sh). Values are given URL-decoded,
-- as inspect() sees them; names (JSON keys, query parameter names) are
-- values too (detect_args pushes both).
local d = require("cdnca_waf")._detect

local attacks = {
    proto = {
        "__proto__", "__proto__[admin]", "__proto__.isAdmin", "a[__proto__][x]", "constructor[prototype][admin]",
        "constructor.prototype.admin", "x.constructor.prototype", "constructor[prototype]", "__PROTO__",
        '{"__proto__":{"admin":true}}', '{"constructor":{"prototype":{"polluted":1}}}', "__proto__\\u0000",
        "obj['__proto__']", 'Object.prototype.polluted', "__defineGetter__", "__lookupGetter__",
    },
    path = {
        "../../../etc/passwd", "..\\..\\windows\\win.ini", "....//....//etc/passwd", "..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9cboot.ini", "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "..%252f..%252fetc%252fpasswd",
        "..%u2216..%u2216etc", ".%2e/.%2e/etc/passwd", "..;/..;/WEB-INF/web.xml", "/..%00/etc/passwd",
        "..\226\136\149..\226\136\149etc/passwd", "../\0", "/etc/passwd", "/etc/shadow", "/proc/self/environ",
        "c:\\windows\\system32\\drivers\\etc\\hosts", "C:/Windows/win.ini", "file.php/../../../etc/hosts",
        "\\\\..\\\\..\\\\boot.ini", "..././..././etc/passwd", "/var/www/../../etc/passwd", "/WEB-INF/web.xml",
        "../../../../../../../../../../", "%2e%2e%2f%2e%2e%2f", "\192\174\192\174/\192\174\192\174/etc",
    },
}

local benign = {
    -- names and values close to the attacks
    "proto", "prototype", "protocol", "constructor", "__init__", "__typename", "_proto", "proto_buf", "protobuf",
    "constructor name", "The constructor of a class", "Array.prototype.map is handy", "prototype-design.pdf",
    "a.b.c", "user[name]", "items[0][price]", "__utma", "__cf_bm", "__Secure-ID", "_ga",
    -- relative and absolute paths that are not traversal
    "/account/settings", "./index.html", "../index.html", "img/a.png", "/static/js/app.js", ".well-known/acme",
    "a..b", "version 1.2..3", "wait...", "...", "Hello... world", "/usr/share/doc", "/home/me/notes.txt",
    "C:\\Users\\me\\file.txt", "https://example.com/../a", "/etc", "etc/passwd is a file", "10/20/2026",
    "a/b/c/d/e/f", "~/Downloads", "50%25 off", "%E4%BD%A0%E5%A5%BD", "/passwd-reset", "/proc", "process",
    "..", "../", "/blog/2026/10/../11/post", "../../assets/logo.svg", "src/../lib", "node_modules/../package.json",
}

local failures, total = 0, 0
local function expect(name, detector, value, want)
    total = total + 1
    if (detector(value) == true) ~= want then
        failures = failures + 1
        print("FAIL " .. name .. " want=" .. tostring(want) .. " value=" .. value:gsub("[%z\1-\31\127-\255]", "."))
    end
end
for _, name in ipairs({ "proto", "path" }) do
    for _, value in ipairs(attacks[name]) do expect(name, d[name], value, true) end
    for _, value in ipairs(benign) do expect("benign-" .. name, d[name], value, false) end
end
-- the earlier detectors stay silent on the new benign values
for _, name in ipairs({ "sqli", "xss", "ssti", "cmd", "ssrf", "crlf", "redirect", "format", "nosql", "ldap", "xxe" }) do
    for _, value in ipairs(benign) do expect("benign-" .. name, d[name], value, false) end
end

-- b64(value): a parameter value that is base64 of text is inspected decoded
-- too (d.base64_text: the decoded text, nil for a value that is no base64 of
-- text)
local b64 = {
    { "Li4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==", "../../../../etc/passwd" },
    { "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg", "<script>alert(1)</script>" },
    { "JyBPUiAnMSc9JzEnIC0t", "' OR '1'='1' --" },
    { "e3s3Kjd9fXt7Y29uZmlnfX0=", "{{7*7}}{{config}}" },
}
for _, case in ipairs(b64) do
    total = total + 1
    if d.base64_text(case[1]) ~= case[2] then
        failures = failures + 1
        print("FAIL base64 " .. case[1] .. " -> " .. tostring(d.base64_text(case[1])))
    end
end
for _, value in ipairs({ "hello", "SGVsbG8", "1234567890123456", "abcdefghijklmnop", "deadbeefdeadbeefdeadbeef",
    "0f8e1b2c-3d4e-5f60-7182-93a4b5c6d7e8", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", "iVBORw0KGgoAAAANSUhEUgAA",
    "dGVzdA==", "Q29uZ3JhdHVsYXRpb25z" }) do
    -- too short, no text, binary, or text no detector reads: nothing new to inspect
    local decoded = d.base64_text(value)
    total = total + 1
    if decoded ~= nil and (#value < 16 or decoded:find("[%z\1-\8\14-\31\127-\255]")) then
        failures = failures + 1
        print("FAIL base64 benign " .. value .. " -> " .. tostring(decoded))
    end
end
print(string.format("detector corpus gap5: %d checks, %d failures", total, failures))

local sample = string.rep("customer review text with 50% off and (notes) 123, ", 4)
local iterations = 100000
ngx.update_time()
local started = ngx.now()
for _ = 1, iterations do d.proto(sample) d.path(sample) end
ngx.update_time()
print(string.format("detector speed: %.2f us per 200-byte value (proto+path)", (ngx.now() - started) / iterations * 1e6))
os.exit(failures == 0 and 0 or 1)
