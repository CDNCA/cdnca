-- resty scripts/security/waf-detector-corpus.lua  (package.path must reach cdnca_waf.lua)
-- Attack payloads (sqlmap / OWASP cheat-sheet style) must be detected, benign
-- inputs must not. Values are given already URL-decoded once, as inspect sees them.
local waf = require("cdnca_waf")
local sqli, xss = waf._detect.sqli, waf._detect.xss

local attacks_sqli = {
    "1' OR '1'='1", "1' OR 1=1-- -", "admin'--", "admin'#", "' or ''='", "1 OR 1=1", "1) OR (1=1",
    "1 UNION SELECT username,password FROM users", "1' UNION ALL SELECT NULL,NULL--", "-1 union/**/select 1,2,3",
    "1'/**/UnIoN/**/SeLeCt/**/1,2--", "1; DROP TABLE users--", "1'; exec xp_cmdshell 'dir'--",
    "1' AND SLEEP(5)--", "1 AND BENCHMARK(5000000,MD5(1))", "1';WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT 1 FROM dual)--", "x' AND 1=0 UNION SELECT 1--", "1' || '1'='1", "1 AND 1=1",
    "' OR 'a'='a", "\" OR \"\"=\"", "1' AND pg_sleep(5)--", "1)) OR 1=1--",
}
local attacks_xss = {
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>", "javascript:alert(1)",
    "\"><script>alert(1)</script>", "' onmouseover='alert(1)", "<iframe src=//evil>", "<body onload=alert(1)>",
    "&lt;script&gt;alert(1)&lt;/script&gt;", "<a href=\"javascript:alert(1)\">x</a>", "<details open ontoggle=alert(1)>",
    "<object data=x>", "jav&#x61;script:alert(1)", "<div style=\"width:expression(alert(1))\">", "<iframe srcdoc=x>",
    "\" autofocus onfocus=alert(1) x=\"", "<math><mtext>", "data:text/html,<b>", "javascript:void(0)",
}
local benign = {
    "hello world", "O'Brien", "it's a nice day", "select a card or union membership", "how to use SELECT in SQL",
    "I'd like 2 items -- thanks", "Tom & Jerry fan", "https://example.com/a?b=1", "rock and roll",
    "price < 100 and > 50", "1-2-3", "2024-10-14", "user@example.com", "C# and C++ jobs", "50% off; today only",
    "drop me a line", "Let's meet at 5", "SELECT * is a common anti-pattern", "a=b", "x or y",
    "He said \"yes\" and left", "Ünïcödé text", "<3 you", "3 < 4", "online shop", "onboarding guide",
    "font-family: Arial", "javascript tutorial for beginners", "update your profile", "order by price",
    "10 OR more people", "The Union Station", "mother's day; gifts", "a & b", "'quoted'", "#hashtag",
    "id=123", "page=2&sort=asc", "{\"a\":1}", "/path/to/file.html", "e=mc^2", "x -- y", "1;2;3",
    "insert coin", "SELECT FROM menu", "3 or 4 items", "and so on", "data: 42",
}

local failures, total = 0, 0
local function expect(name, detector, value, want)
    total = total + 1
    if detector(value) ~= want then
        failures = failures + 1
        print("FAIL " .. name .. " want=" .. tostring(want) .. " value=" .. value)
    end
end
for _, value in ipairs(attacks_sqli) do expect("sqli", sqli, value, true) end
for _, value in ipairs(attacks_xss) do expect("xss", xss, value, true) end
for _, value in ipairs(benign) do
    expect("benign-sqli", sqli, value, false)
    expect("benign-xss", xss, value, false)
end
print(string.format("detector corpus: %d checks, %d failures (sqli attacks %d, xss attacks %d, benign %d)",
    total, failures, #attacks_sqli, #attacks_xss, #benign))

-- microbenchmark: both detectors over a benign 200-byte value and an attack
local sample = string.rep("customer review text with words and 123 numbers, ", 4)
local iterations = 200000
ngx.update_time()
local started = ngx.now()
for _ = 1, iterations do sqli(sample) xss(sample) end
ngx.update_time()
local elapsed = ngx.now() - started
print(string.format("detector speed: %.2f us per 200-byte value (sqli+xss), %d iterations", elapsed / iterations * 1e6, iterations))
os.exit(failures == 0 and 0 or 1)
