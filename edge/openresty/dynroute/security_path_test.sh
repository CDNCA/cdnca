#!/bin/sh
# The security log path (cdnca_telemetry.security_path)
# on the pinned OpenResty with resty: path plus query, sensitive parameter
# values (password passwd pwd token access_token secret key sign signature
# auth session cookie code, any case, %XX / "+" decoded, plus the Agent's
# sensitiveName rule for compound names such as client_secret / refreshSecret,
# TF-E02) become ***, other
# pairs keep their raw encoding, the query is at most 512 bytes (never a cut
# %XX), bytes outside 0x21-0x7E are %XX-encoded, and the whole path stays
# within 4096 bytes.
# Usage: edge/openresty/dynroute/security_path_test.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
container="cdnca-security-path-$$"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true' EXIT HUP INT TERM

docker run --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 32 \
  -v "${repo_root}/edge/openresty/dynroute:/lua:ro" "${OPENRESTY_IMAGE}" \
  resty -I /lua -e '
package.loaded["cdnca_site"] = { current = function() return nil end }
local t = require("cdnca_telemetry")
local failed = 0
local function eq(name, got, want)
  if got ~= want then
    failed = failed + 1
    print("FAIL " .. name .. "\n got  " .. tostring(got) .. "\n want " .. tostring(want))
  else
    print("ok   " .. name)
  end
end
eq("no query", t.security_path("/a", nil), "/a")
eq("empty query", t.security_path("/a", ""), "/a")
eq("plain query kept", t.security_path("/search", "q=1%27%20or%201=1&page=2"), "/search?q=1%27%20or%201=1&page=2")
eq("every sensitive name",
  t.redact_query("password=a&passwd=b&pwd=c&token=d&access_token=e&secret=f&key=g&sign=h&signature=i&auth=j&session=k&cookie=l&code=m&id=7"),
  "password=***&passwd=***&pwd=***&token=***&access_token=***&secret=***&key=***&sign=***&signature=***&auth=***&session=***&cookie=***&code=***&id=7")
eq("case insensitive", t.redact_query("Token=x&ACCESS_TOKEN=y&PassWord=z"), "Token=***&ACCESS_TOKEN=***&PassWord=***")
eq("encoded name", t.redact_query("%74oken=x&access%5Ftoken=y"), "%74oken=***&access%5Ftoken=***")
eq("not a substring match", t.redact_query("keyword=x&tokens=y&codec=z"), "keyword=x&tokens=y&codec=z")
eq("compound sensitive names (TF-E02)",
  t.redact_query("client_secret=a&api_key=b&refreshSecret=c&accessToken=d&X-API-Key=e&user%5Bpassword%5D=f&keyword=g&monkey=h"),
  "client_secret=***&api_key=***&refreshSecret=***&accessToken=***&X-API-Key=***&user%5Bpassword%5D=***&keyword=g&monkey=h")
eq("bare sensitive name", t.redact_query("token&a=1"), "token&a=1")
eq("empty value masked", t.redact_query("token=&a=1"), "token=***&a=1")
eq("value with =", t.redact_query("sign=a=b&x=c=d"), "sign=***&x=c=d")
eq("empty pairs dropped", t.redact_query("&&a=1&&"), "a=1")
eq("control and non-ASCII bytes encoded", t.redact_query("q=a\"b\\c\tbr\195\169"), "q=a\"b\\c%09br%C3%A9")
local long = string.rep("a", 600)
eq("query cut to 512", #t.redact_query("q=" .. long), 512)
local cut = t.redact_query("q=" .. string.rep("b", 508) .. "%41%42")
eq("cut never splits %XX", cut, "q=" .. string.rep("b", 508))
local cut2 = t.redact_query("q=" .. string.rep("b", 508) .. "\1")
eq("cut drops an encoded byte that does not fit", cut2, "q=" .. string.rep("b", 508))
local path = "/" .. string.rep("p", 3900)
local full = t.security_path(path, "q=" .. long)
eq("path within 4096", #full <= 4096 and full:sub(1, #path + 1) == path .. "?", true)
eq("masked before the cut", t.redact_query("token=s&" .. string.rep("a=1&", 200)):sub(1, 10), "token=***&")
if failed > 0 then print(failed .. " failed"); os.exit(1) end
print("all passed")
'
