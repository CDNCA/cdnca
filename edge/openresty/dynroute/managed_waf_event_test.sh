#!/bin/sh
# A managed WAF (ModSecurity/CRS) set decision becomes the
# $cdnca_security_* event the telemetry logs (cdnca_managed_waf.log ->
# record/decision), on the pinned OpenResty with resty:
#   decision  $modsecurity_rule_ids -> block/log and the logged rule ID (the
#             first CRS detection rule, else managed-waf-<decision id>);
#             CRS 949xxx/980xxx and nolog/adaptive IDs are not decisions;
#   record    log() of a tier request writes emit/type waf/action/severity/
#             rule_id/block_page; nothing outside a tier location, without a
#             decision, or when another module already emitted.
# Usage: edge/openresty/dynroute/managed_waf_event_test.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
container="cdnca-managed-waf-event-$$"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true' EXIT HUP INT TERM

docker run --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 32 \
  -v "${repo_root}/edge/openresty/dynroute:/lua:ro" -v "${repo_root}/edge/openresty/lua:/lua2:ro" "${OPENRESTY_IMAGE}" \
  resty -I /lua -I /lua2 -e '
-- a plain table stands in for ngx.var (resty has no request)
local var = {}
ngx.var = var
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
local d = w._decision
-- strong block of set 0 after CRS 942100 (SQLi) and 949110 (inbound score)
local v, id = d(",942100,949110,30100,")
eq("strong block", v, "block"); eq("strong block rule", id, "942100")
v, id = d(",941100,30607,")            -- combined block of set 2 (30600+2*3+1)
eq("combined block", v, "block"); eq("combined block rule", id, "941100")
v, id = d(",932160,30101,")            -- strong log of set 0
eq("strong log", v, "log"); eq("strong log rule", id, "932160")
v, id = d(",930120,30602,")            -- combined log of set 0
eq("combined log", v, "log")
v, id = d(",30103,30100,942100,")      -- block wins over another set'"'"'s log
eq("block over log", v, "block"); eq("first CRS rule", id, "942100")
v, id = d(",30100,")                   -- a decision without a CRS rule
eq("no CRS rule", id, "managed-waf-30100")
eq("combined sum is nolog", d(",942100,30600,"), nil)
eq("grey zone only", d(",942100,31003,"), nil)
eq("CRS score rules only", d(",949110,980170,"), nil)
eq("challenge is not a decision", d(",31995,"), nil)
eq("past the set range", d(",30348,"), nil)
eq("none", d(","), nil)

local function reset(extra)
  for k in pairs(var) do var[k] = nil end
  var.request_id = "r1"; var.cdnca_security_emit = "0"
  for k, value in pairs(extra or {}) do var[k] = value end
end
reset({ cdnca_waf_txid = "ctx|r1", modsecurity_rule_ids = ",942100,949110,30100," })
w.log()
eq("block emit", var.cdnca_security_emit, "1"); eq("block type", var.cdnca_security_type, "waf")
eq("block action", var.cdnca_security_action, "block"); eq("block severity", var.cdnca_security_severity, "high")
eq("block rule id", var.cdnca_security_rule_id, "942100"); eq("block page", var.cdnca_security_block_page, "1")
reset({ cdnca_waf_txid = "ctx|r1", modsecurity_rule_ids = ",932160,30101," })
w.log()
eq("log action", var.cdnca_security_action, "log"); eq("log severity", var.cdnca_security_severity, "info")
eq("log no block page", var.cdnca_security_block_page, nil)
reset({ cdnca_waf_txid = "", modsecurity_rule_ids = ",942100,30100," })
w.log()
eq("not a tier request", var.cdnca_security_emit, "0")
reset({ cdnca_waf_txid = "ctx|r1", modsecurity_rule_ids = ",942100,949110," })
w.log()
eq("no decision", var.cdnca_security_emit, "0")
reset({ cdnca_waf_txid = "ctx|r1", modsecurity_rule_ids = ",942100,30100,", cdnca_security_emit = "1",
  cdnca_security_type = "cc", cdnca_security_rule_id = "cc-1" })
w.log()
eq("earlier emit kept", var.cdnca_security_type .. "/" .. var.cdnca_security_rule_id, "cc/cc-1")
if failed > 0 then print(failed .. " failed"); os.exit(1) end
print("all passed")
'
