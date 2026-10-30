#!/bin/sh
# fix-telemetry TF-E01: security evidence privacy on the pinned OpenResty
# with resty. cdnca_waf evidence: a sensitive key / cookie match keeps only
# the name and [REDACTED], a keyless fragment has sensitive name=value and
# "name":"value" values scrubbed, the request body is never copied into
# $cdnca_security_body by the WAF. cdnca_telemetry.evidence_body: no excerpt
# without request body capture or for a request outside the policy, a
# truncated inspected body, invalid JSON or another media type; a JSON / form
# excerpt with sensitive values [REDACTED]. Both Lua sensitive-name functions
# agree with agents/edge-agent/internal/eventspool/testdata/sensitive_names.json
# (Go TestSensitiveNameSharedVectors).
# Usage: edge/openresty/dynroute/evidence_privacy_test.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
container="cdnca-evidence-privacy-$$"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true' EXIT HUP INT TERM

docker run --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 32 \
  -v "${repo_root}/edge/openresty/dynroute:/lua:ro" \
  -v "${repo_root}/edge/openresty/lua/cdnca_waf.lua:/waf/cdnca_waf.lua:ro" \
  -v "${repo_root}/agents/edge-agent/internal/eventspool/testdata/sensitive_names.json:/vectors.json:ro" \
  "${OPENRESTY_IMAGE}" \
  resty -I /lua -I /waf -e '
package.loaded["cdnca_site"] = { current = function() return nil end }
local cjson = require("cjson.safe")
local t = require("cdnca_telemetry")
local waf = require("cdnca_waf")
local failed = 0
local function eq(name, got, want)
  if got ~= want then
    failed = failed + 1
    print("FAIL " .. name .. "\n got  " .. tostring(got) .. "\n want " .. tostring(want))
  else
    print("ok   " .. name)
  end
end
local canary = "canary-0f3a9"

local file = assert(io.open("/vectors.json", "rb"))
local vectors = assert(cjson.decode(file:read("*a"))); file:close()
for _, name in ipairs(vectors.sensitive) do
  eq("telemetry sensitive " .. name, t.sensitive_name(name), true)
  eq("waf sensitive " .. name, waf._evidence_sensitive(name), true)
end
for _, name in ipairs(vectors.plain) do
  eq("telemetry plain " .. name, t.sensitive_name(name), false)
  eq("waf plain " .. name, waf._evidence_sensitive(name), false)
end

eq("matched sensitive key", waf._evidence_matched({ target = "body", key = "password", fragment = canary }), "password=[REDACTED]")
eq("matched nested sensitive key", waf._evidence_matched({ target = "body", key = "auth.client_secret", fragment = canary }), "auth.client_secret=[REDACTED]")
eq("matched cookie key", waf._evidence_matched({ target = "cookie", key = "sid", fragment = canary }), "sid=[REDACTED]")
eq("matched cookie keyless", waf._evidence_matched({ target = "cookie", fragment = canary }), "[REDACTED]")
eq("matched plain key", waf._evidence_matched({ target = "args", key = "id", fragment = "1 union select" }), "id=1 union select")
eq("matched keyless form scrub", waf._evidence_matched({ target = "body", fragment = "x=<script>&api_key=" .. canary }), "x=<script>&api_key=[REDACTED]")
eq("matched keyless json scrub", waf._evidence_matched({ target = "body", fragment = "{\"user\":\"a\",\"password\":\"" .. canary .. "\"" }), "{\"user\":\"a\",\"password\":\"[REDACTED]\"")
eq("matched overflow", waf._evidence_matched({ target = "body", overflow = true }), "body over inspection limit")

local capture = { methods = {}, prefixes = {}, request_body = { "user" } }
local json_body = "{\"user\":\"alice\",\"password\":\"" .. canary .. "\",\"nested\":{\"clientSecret\":\"" .. canary .. "\"}}"
eq("no policy no excerpt", t.evidence_body(nil, json_body, false, "application/json", "POST", "/login"), "")
eq("no body fields no excerpt", t.evidence_body({ methods = {}, prefixes = {}, request_body = {} }, json_body, false, "application/json", "POST", "/login"), "")
eq("uri outside policy", t.evidence_body({ methods = {}, prefixes = { "/api/" }, request_body = { "user" } }, json_body, false, "application/json", "POST", "/login"), "")
eq("truncated body", t.evidence_body(capture, json_body, true, "application/json", "POST", "/login"), "")
eq("invalid json", t.evidence_body(capture, "{\"user\":\"alice\",\"password\":\"" .. canary, false, "application/json", "POST", "/login"), "")
eq("other media type", t.evidence_body(capture, "password=" .. canary, false, "text/plain", "POST", "/login"), "")
local excerpt = t.evidence_body(capture, json_body, false, "application/json; charset=utf-8", "POST", "/login")
eq("json excerpt has no canary", excerpt:find(canary, 1, true), nil)
local decoded = cjson.decode(excerpt) or {}
eq("json excerpt keeps user", decoded.user, "alice")
eq("json excerpt password redacted", decoded.password, "[REDACTED]")
eq("json excerpt nested redacted", (decoded.nested or {}).clientSecret, "[REDACTED]")
eq("form excerpt", t.evidence_body(capture, "user=alice&api_key=" .. canary .. "&q=1", false, "application/x-www-form-urlencoded", "POST", "/login"),
  "user=alice&api_key=[REDACTED]&q=1")
eq("form encoded name", t.evidence_body(capture, "client%5Fsecret=" .. canary, false, "application/x-www-form-urlencoded", "POST", "/login"),
  "client%5Fsecret=[REDACTED]")
eq("long excerpt left out", t.evidence_body(capture, "{\"user\":\"" .. string.rep("a", 2000) .. "\"}", false, "application/json", "POST", "/login"), "")
if failed > 0 then print(failed .. " failed"); os.exit(1) end
print("all passed")
'
