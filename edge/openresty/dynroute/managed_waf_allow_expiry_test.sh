#!/bin/sh
# fix-secflow SF-E01: a temporary ACL allow (client_ip only, expires_at)
# exempts the client from the managed WAF (CRS engine off, c3 e=0) only while
# now < expires_at, on the same site object (same digest, no republication);
# a permanent allow (allow_cidrs) keeps exempting; a disabled policy, another
# address or a rule with more conditions never exempts. On the pinned
# OpenResty with resty; ngx.var and ngx.time are test stand-ins.
# Usage: edge/openresty/dynroute/managed_waf_allow_expiry_test.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
container="cdnca-managed-waf-allow-expiry-$$"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true' EXIT HUP INT TERM

docker run --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 32 \
  -v "${repo_root}/edge/openresty/dynroute:/lua:ro" -v "${repo_root}/edge/openresty/lua:/lua2:ro" "${OPENRESTY_IMAGE}" \
  resty -I /lua -I /lua2 -e '
local ffi = require("ffi")
local var = {}
ngx.var = var
local clock = 0
ngx.time = function() return clock end
local w = require("cdnca_managed_waf")
local failed = 0
local function eq(name, got, want)
  if got ~= want then
    failed = failed + 1
    print("FAIL " .. name .. "\n got  " .. tostring(got) .. "\n want " .. tostring(want))
  else
    print("ok   " .. name)
  end
end
pcall(ffi.cdef, "int inet_pton(int af, const char *src, void *dst);")
local function binary(text)
  local size, family = 4, 2
  if text:find(":", 1, true) then size, family = 16, 10 end
  local buffer = ffi.new("unsigned char[16]")
  assert(ffi.C.inet_pton(family, text, buffer) == 1)
  return ffi.string(buffer, size)
end
-- 2030-01-02T03:04:05Z
local EXPIRES = 1893553445
local SITE = "0d110000-0000-4000-8000-0000000000e1"
local function site(rules, enabled, allow)
  return { site_id = SITE, security = {
    managed_waf = { crs_profile = { sha256 = string.rep("a", 64) }, exclusions = {}, allow_cidrs = allow or {},
      profile = { request_body_limit = 1048576, request_body_no_files_limit = 1048576,
        request_body_limit_action = "reject", arguments_limit = 1000, json_depth_limit = 512,
        pcre_match_limit = 100000, inspection_limit_action = "log" } },
    rules = { header_overflow = "no_match", policies = { { kind = "acl", enabled = enabled ~= false,
      default_action = "allow", rules = rules } } } } }
end
local function engine(plan, address)
  var.binary_remote_addr = binary(address); var.request_id = "r1"
  local context = w.context(plan)
  return context:match(";e=([01]);")
end
local temporary = { { rule_id = "t", action = "allow", flow = "stop", expires_at = "2030-01-02T03:04:05Z",
  match = { source_cidr = "192.0.2.9/32" } }, { rule_id = "t6", action = "allow", flow = "stop",
  expires_at = "2030-01-02T03:04:05Z", match = { source_cidr = "2001:db8::/64" } } }
local plan = assert(w._compile(site(temporary)))
-- one plan (one digest) across the expiry
clock = EXPIRES - 1
eq("before expiry engine off", engine(plan, "192.0.2.9"), "0")
eq("before expiry ipv6 engine off", engine(plan, "2001:db8::1"), "0")
eq("before expiry other address", engine(plan, "192.0.2.10"), "1")
clock = EXPIRES
eq("at expiry engine on", engine(plan, "192.0.2.9"), "1")
eq("at expiry ipv6 engine on", engine(plan, "2001:db8::1"), "1")
clock = EXPIRES + 1
eq("after expiry engine on", engine(plan, "192.0.2.9"), "1")
-- an already expired rule exempts nobody
local past = assert(w._compile(site({ { rule_id = "p", action = "allow", flow = "stop",
  expires_at = "2020-01-02T03:04:05Z", match = { source_cidr = "192.0.2.9/32" } } })))
eq("expired rule engine on", engine(past, "192.0.2.9"), "1")
-- permanent allow (allow_cidrs, as control publishes it) keeps exempting
local permanent = assert(w._compile(site({ { rule_id = "a", action = "allow", flow = "stop",
  match = { source_cidr = "192.0.2.9/32" } } }, true, { "192.0.2.9/32" })))
eq("permanent allow engine off", engine(permanent, "192.0.2.9"), "0")
-- disabled policy / extra condition / block rule: no exemption
local disabled = assert(w._compile(site(temporary, false)))
clock = EXPIRES - 1
eq("disabled policy engine on", engine(disabled, "192.0.2.9"), "1")
local narrowed = assert(w._compile(site({ { rule_id = "n", action = "allow", flow = "stop",
  expires_at = "2030-01-02T03:04:05Z", match = { source_cidr = "192.0.2.9/32", path = { kind = "prefix", value = "/a" } } } })))
eq("rule with more conditions engine on", engine(narrowed, "192.0.2.9"), "1")
local block = assert(w._compile(site({ { rule_id = "b", action = "block", flow = "stop",
  expires_at = "2030-01-02T03:04:05Z", match = { source_cidr = "192.0.2.9/32" } } })))
eq("temporary block engine on", engine(block, "192.0.2.9"), "1")
-- a malformed expiry refuses the object (fail closed, no timeless exemption)
local bad, reason = w._compile(site({ { rule_id = "x", action = "allow", flow = "stop",
  expires_at = "tomorrow", match = { source_cidr = "192.0.2.9/32" } } }))
eq("malformed expiry refused", bad, nil); eq("malformed expiry reason", reason, "allow expires_at")
if failed > 0 then print(failed .. " failed"); os.exit(1) end
print("all passed")
'
