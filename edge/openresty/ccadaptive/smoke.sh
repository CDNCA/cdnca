#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-ccadaptive.XXXXXX")"
container="cdnca-ccadaptive-$(basename "${workdir}")"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-ccadaptive.*) rm -rf -- "${workdir}" ;;
    *) echo "refusing to remove unexpected directory ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/policy" "${workdir}/runtime/logs"
cat >"${workdir}/policy/current.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":7,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"shadow","fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":10000000,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":1000000,"max_groups":32}}
EOF
cp "${workdir}/policy/current.json" "${workdir}/policy/current-copy.json"
cp "${workdir}/policy/current.json" "${workdir}/policy/fallback.json"
cat >"${workdir}/policy/bad.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":8,"enabled":true,"mode":"expert","static":{"rate_per_second":0,"burst":3}}
EOF
cat >"${workdir}/policy/auto.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":9,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"auto","auto_approved":true,"fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":10000000,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":1000000,"max_groups":32}}
EOF
cat >"${workdir}/policy/revision8.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":8,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"shadow","fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":10000000,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":1000000,"max_groups":32}}
EOF
cat >"${workdir}/policy/inexact.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":8,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"shadow","fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":9007199254740992,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":1000000,"max_groups":32}}
EOF
cat >"${workdir}/policy/maximum.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":8,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"shadow","fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":9007199254740991,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":9007199254740991,"max_groups":32}}
EOF
cat >"${workdir}/policy/high-rate.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":10,"enabled":true,"mode":"simple","static":{"rate_per_second":999999,"burst":1000000}}
EOF
cat >"${workdir}/policy/capacity.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":11,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"shadow","fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":1000000,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":1000000,"max_groups":2}}
EOF
cat >"${workdir}/policy/exact.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":12,"enabled":true,"mode":"expert","static":{"rate_per_second":1000000,"burst":20},"adaptive":{"mode":"auto","auto_approved":true,"fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":10000000,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000000,"min_burst":1,"max_burst":1000000,"max_step_permille":1000,"hysteresis_permille":0,"cooldown_micros":0,"max_groups":32}}
EOF
cat >"${workdir}/policy/live.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":13,"enabled":true,"mode":"simple","static":{"rate_per_second":10,"burst":2}}
EOF
cat >"${workdir}/policy/live-replacement.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":13,"enabled":true,"mode":"simple","static":{"rate_per_second":100,"burst":9}}
EOF
cat >"${workdir}/policy/snapshot-adaptive.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":13,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"shadow","fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":10000000,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":1000000,"max_groups":1}}
EOF
cat >"${workdir}/policy/snapshot-simple.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":14,"enabled":true,"mode":"simple","static":{"rate_per_second":10,"burst":2}}
EOF
cat >"${workdir}/policy/malformed-revision1.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":1,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"shadow","fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":10000000,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":1000000,"max_groups":32}}
EOF
cat >"${workdir}/policy/malformed-revision2.json" <<'EOF'
{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":2,"enabled":true,"mode":"expert","static":{"rate_per_second":100,"burst":20},"adaptive":{"mode":"shadow","fallback":"static","min_samples":5,"max_samples":32,"sample_freshness_micros":10000000,"ewma_alpha_permille":250,"mad_multiplier_milli":3000,"min_rate_per_second":1,"max_rate_per_second":1000,"min_burst":1,"max_burst":100,"max_step_permille":200,"hysteresis_permille":50,"cooldown_micros":1000000,"max_groups":32}}
EOF
cat >"${workdir}/runtime/nginx.conf" <<'EOF'
worker_processes 2;
error_log logs/error.log notice;
pid nginx.pid;

events { worker_connections 256; }

http {
    lua_package_path '/opt/cdnca-ccadaptive/?.lua;;';
    lua_shared_dict ccadaptive_state 64k;
    lua_shared_dict ccadaptive_locks 1m;
    lua_shared_dict ccadaptive_models 1m;

    init_worker_by_lua_block {
        local engine = require "engine"
        local ok, err = engine.init({
            state_dict = "ccadaptive_state",
            lock_dict = "ccadaptive_locks",
            model_dict = "ccadaptive_models",
            policy_path = "/policy/current.json",
        })
        if not ok then error(err) end
    }

    server {
        listen 18083;
        location = /ok { return 200 'origin-ok\n'; }
        location = /fail { return 503 'origin-failed\n'; }
        location = /slow {
            content_by_lua_block {
                ngx.sleep(0.2)
                ngx.say("origin-slow")
            }
        }
    }

    server {
        listen 18080;
        proxy_read_timeout 50ms;

        location ~ ^/(ok|fail|slow)$ {
            access_by_lua_block {
                local digests = {
                    a = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                    b = "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
                    c = "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
                    d = "18ac3e7343f016890c510e93f935261169d9e3f56543642903c3a1dfb32f0e4f",
                    e = "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
                    f = "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
                    ["cold-start-lkg"] = "1fd4fb165b35157db50b5a1ed01344bb9f915d3bd64992372476b7d5cdccf628",
                }
                local key = ngx.var.arg_key or "a"
                local now = tonumber(ngx.var.arg_now) or math.floor(ngx.now() * 1000000)
                local decision = require("engine").decide({
                    tenant_id = ngx.var.arg_tenant or "tenant-a", site_id = ngx.var.arg_site or "site-a",
                    rule_id = "edge-smoke",
                    key_scope = "client_ip", key_digest = digests[key], cost = 1, now_micros = now,
                    limit = { rate_per_second = 2, burst = 3 },
                })
                ngx.header["X-CC-Reason"] = decision.reason
                ngx.header["X-CC-Remaining"] = tostring(decision.remaining)
                if decision.outcome == "deny" then
                    return ngx.exit(429)
                end
                if decision.outcome == "fallback" then
                    return ngx.exit(503)
                end
            }
            proxy_pass http://127.0.0.1:18083;
        }

        location = /observe {
            content_by_lua_block {
                local profile = ngx.var.arg_profile or "normal"
                local suggestion = require("engine").observe({
                    tenant_id = "tenant-a", site_id = "site-a", rule_id = "model-" .. profile,
                    sample = {
                        at_micros = tonumber(ngx.var.arg_at), requests = tonumber(ngx.var.arg_requests),
                        window_micros = 1000000,
                    },
                })
                suggestion.worker_pid = ngx.worker.pid()
                if ngx.var.arg_hold == "1" then ngx.sleep(0.05) end
                ngx.header["Content-Type"] = "application/json"
                ngx.say(require("cjson.safe").encode(suggestion))
            }
        }

        location = /freeze {
            content_by_lua_block {
                local ok, err = require("engine").freeze({
                    tenant_id = "tenant-a", site_id = "site-a",
                    rule_id = "model-" .. (ngx.var.arg_profile or "normal"),
                }, ngx.var.arg_value == "1")
                if not ok then
                    ngx.status = 422
                    ngx.say(err)
                    return
                end
                ngx.say("ok")
            }
        }

        location = /policy-snapshot-race {
            content_by_lua_block {
                local cjson = require "cjson.safe"
                local engine = require "engine"
                local resty_lock = require "resty.lock"
                local operation = ngx.var.arg_operation
                local tenant = "snapshot-tenant"
                local site = "snapshot-site"
                local rule = "snapshot-" .. (operation or "invalid")
                local digest = "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398"
                local function field(value)
                    return tostring(#value) .. ":" .. value
                end
                local file = assert(io.open("/policy/snapshot-adaptive.json", "rb"))
                local raw = assert(file:read("*a"))
                file:close()
                local hash = assert(require("resty.sha256"):new())
                assert(hash:update(raw))
                local policy_digest = require("resty.string").to_hex(assert(hash:final()))
                local revision = "13"
                local model_prefix = "ccadaptive:model:" .. field(revision) .. field(policy_digest)
                local model_key = model_prefix .. field(tenant) .. field(site) .. field(rule)
                local gcra_key = "ccadaptive:gcra:" .. field(revision) .. field(policy_digest) ..
                    field(tenant) .. field(site) .. field(rule) .. field("site") .. field(digest)

                assert(engine.load("/policy/snapshot-adaptive.json") == 13)
                ngx.shared.ccadaptive_models:flush_all()
                ngx.shared.ccadaptive_models:flush_expired()

                local key
                if operation == "freeze" then
                    local seeded = engine.observe({
                        tenant_id = tenant, site_id = site, rule_id = rule,
                        sample = { at_micros = 1, requests = 10, window_micros = 1000000 },
                    })
                    assert(seeded.reason == "adaptive_insufficient_samples")
                    key = model_key
                elseif operation == "observe" then
                    local seeded = engine.observe({
                        tenant_id = tenant, site_id = site, rule_id = "snapshot-occupied",
                        sample = { at_micros = 1, requests = 10, window_micros = 1000000 },
                    })
                    assert(seeded.reason == "adaptive_insufficient_samples")
                    key = model_key
                elseif operation == "decide" then
                    key = gcra_key
                else
                    return ngx.exit(400)
                end

                local held = assert(resty_lock:new("ccadaptive_locks", { timeout = 0.05, exptime = 0.2 }))
                assert(held:lock("lock:" .. key))
                local marker = "snapshot-race:" .. operation
                ngx.shared.ccadaptive_state:delete(marker)
                local scheduled, schedule_error = ngx.timer.at(0, function(premature)
                    if premature then return end
                    local loaded, load_error = engine.load("/policy/snapshot-simple.json")
                    if loaded ~= 14 then
                        ngx.shared.ccadaptive_state:set(marker, load_error or tostring(loaded))
                    end
                    local unlocked, unlock_error = held:unlock()
                    if not unlocked then
                        ngx.shared.ccadaptive_state:set(marker, unlock_error or "unlock failed")
                    end
                end)
                assert(scheduled, schedule_error)

                if operation == "freeze" then
                    local frozen, freeze_error = engine.freeze({
                        tenant_id = tenant, site_id = site, rule_id = rule,
                    }, true)
                    assert(frozen, freeze_error)
                    local state = assert(cjson.decode(assert(ngx.shared.ccadaptive_models:get(model_key))))
                    assert(state.frozen == true, "old snapshot model was not frozen")
                elseif operation == "observe" then
                    local observed = engine.observe({
                        tenant_id = tenant, site_id = site, rule_id = rule,
                        sample = { at_micros = 2, requests = 10, window_micros = 1000000 },
                    })
                    assert(observed.reason == "limiter_state_unavailable", "old snapshot group limit bypassed")
                    assert(ngx.shared.ccadaptive_models:get(model_key) == nil, "old snapshot admitted excess group")
                else
                    local decision = engine.decide({
                        tenant_id = tenant, site_id = site, rule_id = rule,
                        key_scope = "site", key_digest = digest, cost = 3, now_micros = 1,
                    })
                    assert(decision.outcome == "allow", "old snapshot decision did not complete")
                    assert(ngx.shared.ccadaptive_state:get(gcra_key), "old snapshot GCRA state missing")
                end
                local timer_error = ngx.shared.ccadaptive_state:get(marker)
                ngx.shared.ccadaptive_state:delete(marker)
                assert(not timer_error, timer_error)
                assert(engine.policy_revision() == 14, "simple revision was not activated")
                ngx.say("ok")
            }
        }

        location ~ ^/(model-missing|model-wrong|gcra-nonstring)$ {
            content_by_lua_block {
                local cjson = require "cjson.safe"
                local engine = require "engine"
                local case_name = ngx.var.uri:sub(2)
                local tenant = "malformed-tenant"
                local site = "malformed-site"
                local rule = case_name
                local key_digest = "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398"
                local function field(value)
                    return tostring(#value) .. ":" .. value
                end
                local file = assert(io.open("/policy/malformed-revision1.json", "rb"))
                local raw = assert(file:read("*a"))
                file:close()
                local hash = assert(require("resty.sha256"):new())
                assert(hash:update(raw))
                local policy_digest = require("resty.string").to_hex(assert(hash:final()))
                local prefix = field("1") .. field(policy_digest) ..
                    field(tenant) .. field(site) .. field(rule)

                assert(engine.load("/policy/malformed-revision1.json") == 1)
                ngx.header["Content-Type"] = "application/json"
                if case_name == "gcra-nonstring" then
                    local key = "ccadaptive:gcra:" .. prefix .. field("site") .. field(key_digest)
                    assert(ngx.shared.ccadaptive_state:set(key, 42, 60))
                    local decision = engine.decide({
                        tenant_id = tenant, site_id = site, rule_id = rule,
                        key_scope = "site", key_digest = key_digest, cost = 1, now_micros = 2,
                    })
                    ngx.say(cjson.encode(decision))
                    return
                end

                local state = {
                    ewma = 10, last_sample = 1, current_rate = 100, current_burst = 20,
                    last_change = 0, frozen = false, capped = false,
                }
                if case_name == "model-wrong" then
                    state.rates = "wrong"
                end
                local key = "ccadaptive:model:" .. prefix
                assert(ngx.shared.ccadaptive_models:set(key, cjson.encode(state), 60))
                local observed = engine.observe({
                    tenant_id = tenant, site_id = site, rule_id = rule,
                    sample = { at_micros = 2, requests = 10, window_micros = 1000000 },
                })
                ngx.say(cjson.encode(observed))
            }
        }

        location = /freeze-timeout {
            content_by_lua_block {
                local cjson = require "cjson.safe"
                local engine = require "engine"
                local resty_lock = require "resty.lock"
                local tenant = "malformed-tenant"
                local site = "malformed-site"
                local rule = "freeze-timeout"
                local function field(value)
                    return tostring(#value) .. ":" .. value
                end
                local file = assert(io.open("/policy/malformed-revision1.json", "rb"))
                local raw = assert(file:read("*a"))
                file:close()
                local hash = assert(require("resty.sha256"):new())
                assert(hash:update(raw))
                local policy_digest = require("resty.string").to_hex(assert(hash:final()))
                local key = "ccadaptive:model:" .. field("1") .. field(policy_digest) ..
                    field(tenant) .. field(site) .. field(rule)

                assert(engine.load("/policy/malformed-revision1.json") == 1)
                local seeded = engine.observe({
                    tenant_id = tenant, site_id = site, rule_id = rule,
                    sample = { at_micros = 1, requests = 10, window_micros = 1000000 },
                })
                assert(seeded.reason == "adaptive_insufficient_samples")
                local held = assert(resty_lock:new("ccadaptive_locks", { timeout = 0.05, exptime = 5 }))
                assert(held:lock("lock:" .. key))
                local frozen, freeze_error = engine.freeze({
                    tenant_id = tenant, site_id = site, rule_id = rule,
                }, true)
                assert(held:unlock())
                if not frozen then ngx.status = 503 end
                ngx.header["Content-Type"] = "application/json"
                ngx.say(cjson.encode({ ok = frozen == true, frozen = frozen == true, error = freeze_error }))
            }
        }

        location = /revision2-probe {
            content_by_lua_block {
                local engine = require "engine"
                local tenant = "malformed-tenant"
                local site = "malformed-site"
                assert(engine.load("/policy/malformed-revision2.json") == 2)
                for _, rule in ipairs({ "model-missing", "model-wrong" }) do
                    local observed = engine.observe({
                        tenant_id = tenant, site_id = site, rule_id = rule,
                        sample = { at_micros = 3, requests = 10, window_micros = 1000000 },
                    })
                    assert(observed.reason == "adaptive_insufficient_samples", rule .. " revision isolation")
                end
                local decision = engine.decide({
                    tenant_id = tenant, site_id = site, rule_id = "gcra-nonstring",
                    key_scope = "site",
                    key_digest = "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398",
                    cost = 1, now_micros = 3,
                })
                assert(decision.outcome == "allow", "GCRA revision isolation")
                ngx.say("ok")
            }
        }

        location = /revision {
            content_by_lua_block { ngx.say(require("engine").policy_revision()) }
        }

        location = /load-hold {
            content_by_lua_block {
                local engine = require "engine"
                ngx.sleep(0.2)
                local revision, err = engine.load("/policy/maximum.json")
                if not revision then
                    ngx.status = 422
                    ngx.say(err)
                    return
                end
                ngx.sleep(1)
                ngx.say(revision)
            }
        }

        location = /worker-revision {
            content_by_lua_block {
                ngx.say(require("engine").policy_revision())
            }
        }

        location = /live-probe {
            content_by_lua_block {
                local key = ngx.var.arg_key or "a"
                local decision = require("engine").decide({
                    tenant_id = "live-probe", site_id = "site", rule_id = "probe-" .. key,
                    key_scope = "site",
                    key_digest = "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398",
                    cost = 3, now_micros = 1,
                })
                ngx.header["Content-Type"] = "application/json"
                ngx.say(require("cjson.safe").encode({
                    worker_pid = ngx.worker.pid(), revision = require("engine").policy_revision(),
                    outcome = decision.outcome, reason = decision.reason,
                }))
            }
        }

        location = /delete-active-record {
            content_by_lua_block {
                ngx.shared.ccadaptive_state:delete("ccadaptive:active-policy")
                ngx.say("ok")
            }
        }

        location = /corrupt-active-record {
            content_by_lua_block {
                assert(ngx.shared.ccadaptive_state:safe_set("ccadaptive:active-policy", "corrupt", 0))
                ngx.say("ok")
            }
        }

        location = /active-record {
            content_by_lua_block {
                ngx.say(ngx.shared.ccadaptive_state:get("ccadaptive:active-policy") or "")
            }
        }

        location = /reload-bad {
            content_by_lua_block {
                local engine = require "engine"
                local ok = engine.load("/policy/bad.json")
                if ok then return ngx.exit(500) end
                ngx.say(engine.policy_revision())
            }
        }

        location = /reload {
            content_by_lua_block {
                local files = {
                    current = "/policy/current.json", revision8 = "/policy/revision8.json",
                    maximum = "/policy/maximum.json", inexact = "/policy/inexact.json",
                    high = "/policy/high-rate.json", capacity = "/policy/capacity.json", exact = "/policy/exact.json",
                    live = "/policy/live.json", current_copy = "/policy/current-copy.json",
                }
                local path = files[ngx.var.arg_policy]
                if not path then return ngx.exit(400) end
                local revision, err = require("engine").load(path)
                if not revision then
                    ngx.status = 422
                    ngx.say(err)
                    return
                end
                ngx.say(revision)
            }
        }

        location = /high-rate {
            content_by_lua_block {
                local engine = require "engine"
                assert(engine.load("/policy/high-rate.json") == 10)
                local request = {
                    tenant_id = "tenant-a", site_id = "site-a", rule_id = "high-rate",
                    key_scope = "site",
                    key_digest = "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398",
                    now_micros = 0, cost = 1000000,
                }
                local first = engine.decide(request)
                request.now_micros = 1000000
                request.cost = 999999
                local second = engine.decide(request)
                assert(first.outcome == "allow", "high-rate initial burst")
                assert(second.outcome == "allow", "high-rate requests/s")
                assert(engine.load("/policy/auto.json") == 9)
                ngx.say("ok")
            }
        }

        location = /revision-isolation {
            content_by_lua_block {
                local engine = require "engine"
                assert(engine.load("/policy/current.json") == 7)
                local request = {
                    tenant_id = "revision", site_id = "site", rule_id = "rule",
                    key_scope = "site",
                    key_digest = "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398",
                    now_micros = 1, cost = 1, limit = { rate_per_second = 2, burst = 1 },
                }
                assert(engine.decide(request).outcome == "allow")
                assert(engine.decide(request).outcome == "deny")
                assert(engine.load("/policy/revision8.json") == 8)
                assert(engine.decide(request).outcome == "allow", "revision state collision")
                assert(engine.load("/policy/current.json") == 7)
                ngx.say("ok")
            }
        }

        location = /model-count {
            content_by_lua_block {
                local revision = string.format("%.0f", require("engine").policy_revision())
                local prefix = "ccadaptive:model:" .. tostring(#revision) .. ":" .. revision
                local count = 0
                for _, key in ipairs(ngx.shared.ccadaptive_models:get_keys(0)) do
                    if key:sub(1, #prefix) == prefix then count = count + 1 end
                end
                ngx.say(count)
            }
        }

        location = /flush-models {
            content_by_lua_block {
                ngx.shared.ccadaptive_models:flush_all()
                ngx.shared.ccadaptive_models:flush_expired()
                ngx.say("ok")
            }
        }

        location = /fill-model {
            content_by_lua_block {
                local dict = ngx.shared.ccadaptive_models
                local index = 1
                while dict:safe_set("fill-model:" .. index, string.rep("x", 1024), 60) do
                    index = index + 1
                end
                ngx.say(index - 1)
            }
        }

        location = /clear-model-fill {
            content_by_lua_block {
                local dict = ngx.shared.ccadaptive_models
                for _, key in ipairs(dict:get_keys(0)) do
                    if key:sub(1, 11) == "fill-model:" then dict:delete(key) end
                end
                ngx.say("ok")
            }
        }

        location = /fill-state {
            content_by_lua_block {
                local dict = ngx.shared.ccadaptive_state
                local index = 1
                for _, size in ipairs({ 1024, 256, 64, 1 }) do
                    while true do
                        local key = "fill:" .. string.rep("k", 150) .. ":" .. index
                        local ok = dict:safe_set(key, string.rep("x", size), 60)
                        if not ok then break end
                        index = index + 1
                    end
                end
                ngx.say(index - 1)
            }
        }

        location = /parity {
            content_by_lua_block {
                local file = assert(io.open("/vectors/parity-vectors.json", "rb"))
                local vectors = assert(require("cjson.safe").decode(file:read("*a")))
                file:close()
                local engine = require "engine"
				for index, case in ipairs(vectors.identifier_cases) do
					local decision = engine.decide({
						tenant_id = case.value, site_id = "identifier-site", rule_id = "identifier-rule",
						key_scope = "site", key_digest = "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398",
						limit = { rate_per_second = 100, burst = 20 }, cost = 1, now_micros = index,
					})
					local observed = engine.observe({
						tenant_id = case.value, site_id = "identifier-site", rule_id = "identifier-rule",
						sample = { at_micros = index, requests = 1, window_micros = 1000000 },
					})
					if case.valid then
						assert(decision.outcome == "allow", case.name .. " decision")
						assert(observed.reason == "adaptive_insufficient_samples", case.name .. " observe")
					else
						assert(decision.reason == "invalid_input", case.name .. " decision")
						assert(observed.reason == "invalid_input", case.name .. " observe")
					end
				end
                for _, case in ipairs(vectors.gcra_cases) do
                    for _, step in ipairs(case.steps) do
                        local decision = engine.decide({
                            tenant_id = case.key.tenant_id, site_id = case.key.site_id,
                            rule_id = case.key.rule_id, key_scope = case.key.key_scope,
                            key_digest = case.key.key_digest, limit = case.limit,
                            cost = step.cost, now_micros = step.now_micros,
                        })
                        assert(decision.outcome == step.outcome, case.name .. " outcome")
                        assert(decision.retry_after_micros == step.retry_after_micros, case.name .. " retry")
                        assert(decision.remaining == step.remaining, case.name .. " remaining")
                        assert(decision.next_eligible_micros == step.next_eligible_micros, case.name .. " next eligible")
                        assert(decision.reason == step.reason, case.name .. " reason")
                    end
                end
                local got
                for _, sample in ipairs(vectors.adaptive_case.samples) do
                    got = engine.observe({
                        tenant_id = vectors.adaptive_case.key.tenant_id,
                        site_id = vectors.adaptive_case.key.site_id,
                        rule_id = vectors.adaptive_case.key.rule_id,
                        sample = sample,
                    })
                end
                local want = vectors.adaptive_case.expected
                assert(got.rate_per_second == want.rate_per_second, "adaptive rate")
                assert(got.burst == want.burst, "adaptive burst")
                assert(got.confidence_permille == want.confidence_permille, "adaptive confidence")
                assert(got.reason == want.reason and got.apply == want.apply, "adaptive result")
                ngx.say("ok")
            }
        }

        location = /parity-auto {
            content_by_lua_block {
                local file = assert(io.open("/vectors/parity-vectors.json", "rb"))
                local vectors = assert(require("cjson.safe").decode(file:read("*a")))
                file:close()
                local got
                for _, sample in ipairs(vectors.adaptive_auto_case.samples) do
                    got = require("engine").observe({
                        tenant_id = vectors.adaptive_auto_case.key.tenant_id,
                        site_id = vectors.adaptive_auto_case.key.site_id,
                        rule_id = vectors.adaptive_auto_case.key.rule_id,
                        sample = sample,
                    })
                end
                local want = vectors.adaptive_auto_case.expected
                assert(got.rate_per_second == want.rate_per_second, "adaptive auto rate")
                assert(got.burst == want.burst, "adaptive auto burst")
                assert(got.confidence_permille == want.confidence_permille, "adaptive auto confidence")
                assert(got.reason == want.reason and got.apply == want.apply, "adaptive auto result")
                ngx.say("ok")
            }
        }

		location = /parity-exact {
			content_by_lua_block {
				local file = assert(io.open("/vectors/parity-vectors.json", "rb"))
				local vectors = assert(require("cjson.safe").decode(file:read("*a")))
				file:close()
				local engine = require "engine"
				assert(engine.load("/policy/exact.json") == 12)
				local case = vectors.adaptive_exact_integer_case
				local got
				for _, sample in ipairs(case.samples) do
					got = engine.observe({
						tenant_id = case.key.tenant_id, site_id = case.key.site_id,
						rule_id = case.key.rule_id, sample = sample,
					})
				end
				local want = case.expected
				assert(got.rate_per_second == want.rate_per_second, "exact adaptive rate")
				assert(got.burst == want.burst, "exact adaptive burst")
				assert(got.confidence_permille == want.confidence_permille, "exact adaptive confidence")
				assert(got.reason == want.reason and got.apply == want.apply, "exact adaptive result")
				local revision = string.format("%.0f", engine.policy_revision())
				local function field(value) return tostring(#value) .. ":" .. value end
				local file_handle = assert(io.open("/policy/exact.json", "rb"))
				local raw = assert(file_handle:read("*a"))
				file_handle:close()
				local hash = assert(require("resty.sha256"):new())
				assert(hash:update(raw))
				local policy_digest = require("resty.string").to_hex(assert(hash:final()))
				local key = "ccadaptive:model:" .. field(revision) .. field(policy_digest) .. field(case.key.tenant_id) ..
					field(case.key.site_id) .. field(case.key.rule_id)
				local state = assert(require("cjson.safe").decode(assert(ngx.shared.ccadaptive_models:get(key))))
				assert(state.capped == want.state_capped, "exact adaptive capped state")
				local too_large = 9007199255
				local invalid_requests = engine.observe({
					tenant_id = "tenant-a", site_id = "site-a", rule_id = "unsafe-requests",
					sample = { at_micros = 1, requests = too_large, window_micros = 1 },
				})
				local invalid_window = engine.observe({
					tenant_id = "tenant-a", site_id = "site-a", rule_id = "unsafe-window",
					sample = { at_micros = 1, requests = 1, window_micros = too_large },
				})
				assert(invalid_requests.reason == "invalid_input", "unsafe requests")
				assert(invalid_window.reason == "invalid_input", "unsafe window")
				assert(engine.load("/policy/auto.json") == 9)
				ngx.say("ok")
			}
		}
    }
}
EOF

docker run --rm \
  --volume "${repo_root}/edge/openresty/ccadaptive:/opt/cdnca-ccadaptive:ro" \
  --volume "${workdir}/runtime:/runtime" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" -p /runtime/ -c nginx.conf -t >/dev/null

start_container() {
  docker run --detach \
    --name "${container}" \
    --publish 127.0.0.1::18080 \
    --volume "${repo_root}/edge/openresty/ccadaptive:/opt/cdnca-ccadaptive:ro" \
    --volume "${repo_root}/agents/edge-agent/internal/ccadaptive/testdata:/vectors:ro" \
    --volume "${workdir}/policy:/policy:ro" \
    --volume "${workdir}/runtime:/runtime" \
    --entrypoint /usr/local/openresty/bin/openresty \
    "${OPENRESTY_IMAGE}" -p /runtime/ -c nginx.conf -g 'daemon off;' >/dev/null
}

wait_ready() {
  expected_revision="$1"
  attempt=0
  while [ "${attempt}" -lt 100 ]; do
    if curl --fail --silent --show-error "${base_url}/revision" 2>/dev/null | grep -Fx "${expected_revision}" >/dev/null 2>&1; then return 0; fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  docker logs "${container}" >&2
  return 1
}

wait_worker_revision_convergence() {
  convergence_target="$1"
  convergence_stage="$2"
  convergence_attempt=0
  convergence_last=""
  while [ "${convergence_attempt}" -lt 80 ]; do
    convergence_all=1
    convergence_values=""
    convergence_last=""
    for convergence_index in 1 2 3 4 5 6 7 8 9 10; do
      convergence_value="$(curl --fail --silent --show-error "${base_url}/worker-revision" 2>/dev/null || true)"
      convergence_values="${convergence_values} ${convergence_value:-unavailable}"
      convergence_last="${convergence_last} ${convergence_index}=${convergence_value:-unavailable}"
      if [ "${convergence_value}" != "${convergence_target}" ]; then
        convergence_all=0
      fi
    done
    if [ "${convergence_all}" -eq 1 ]; then
      worker_revisions="${convergence_values}"
      return 0
    fi
    convergence_attempt=$((convergence_attempt + 1))
    # Bounded retry backoff; readiness is established only by target convergence.
    sleep 0.05
  done
  echo "${convergence_stage}: revision ${convergence_target} did not converge after ${convergence_attempt} attempts; last=${convergence_last:-unavailable}" >&2
  return 1
}

status() {
  curl --silent --show-error --output "${workdir}/last.body" --dump-header "${workdir}/last.headers" \
    --write-out '%{http_code}' "${base_url}$1"
}

expect_status() {
  expected="$1"
  path="$2"
  actual="$(status "${path}")"
  if [ "${actual}" != "${expected}" ]; then
    echo "${path}: status ${actual}, want ${expected}" >&2
    cat "${workdir}/last.body" >&2 || true
    exit 1
  fi
}

expect_snapshot_race() {
  operation="$1"
  actual="$(status "/policy-snapshot-race?operation=${operation}")"
  if [ "${actual}" != 200 ] || [ "$(cat "${workdir}/last.body")" != ok ]; then
    echo "policy snapshot ${operation}: status ${actual}, want 200 ok" >&2
    cat "${workdir}/last.body" >&2 || true
    tail -n 20 "${workdir}/runtime/logs/error.log" >&2 || true
    exit 1
  fi
}

expect_stable_state_fallback() {
  path="$1"
  actual="$(status "${path}")"
  if [ "${actual}" != 200 ] || ! grep -F '"reason":"limiter_state_unavailable"' "${workdir}/last.body" >/dev/null; then
    echo "${path}: expected stable limiter_state_unavailable fallback, got status ${actual}" >&2
    cat "${workdir}/last.body" >&2 || true
    review_failures=$((review_failures + 1))
  fi
}

start_container
published="$(docker port "${container}" 18080/tcp | tail -n 1)"
case "${published}" in 127.0.0.1:*) ;; *) echo "smoke port is not loopback: ${published}" >&2; exit 1 ;; esac
base_url="http://${published}"
wait_ready 7

# A reload handled by one worker must become visible to the other worker while
# the first worker is held, otherwise the active policy diverges by worker.
curl --fail --silent --show-error "${base_url}/load-hold" >"${workdir}/load-hold.out" &
load_hold_pid=$!
wait_worker_revision_convergence 8 cross-worker-activation
wait "${load_hold_pid}"
if [ "$(cat "${workdir}/load-hold.out")" != 8 ]; then
  echo "reload worker returned $(cat "${workdir}/load-hold.out")" >&2
  exit 1
fi
for revision in ${worker_revisions}; do
  if [ "${revision}" != 8 ]; then
    echo "worker revision diverged: ${worker_revisions}" >&2
    exit 1
  fi
done
curl --fail --silent --show-error "${base_url}/reload?policy=current" >/dev/null

# A request that entered under adaptive revision 13 must retain its immutable
# policy, digest-derived key/prefix, and adaptive config after a same-worker
# timer activates simple revision 14 while the request waits on its old lock.
expect_snapshot_race freeze
expect_snapshot_race observe
expect_snapshot_race decide
curl --fail --silent --show-error "${base_url}/reload?policy=current" >/dev/null

# Malformed shared values fail closed without throwing, and infrastructure lock
# errors use only the stable public reason. Revision 2 must remain isolated from
# every malformed revision 1 key.
review_failures=0
expect_stable_state_fallback '/model-missing'
expect_stable_state_fallback '/model-wrong'
expect_stable_state_fallback '/gcra-nonstring'
freeze_status="$(status '/freeze-timeout')"
if [ "${freeze_status}" != 503 ] ||
    ! grep -F '"error":"limiter_state_unavailable"' "${workdir}/last.body" >/dev/null ||
    grep -F '"error":"timeout"' "${workdir}/last.body" >/dev/null; then
  echo "/freeze-timeout: expected stable limiter_state_unavailable, got status ${freeze_status}" >&2
  cat "${workdir}/last.body" >&2 || true
  review_failures=$((review_failures + 1))
fi
expect_status 200 '/revision2-probe'
test "$(cat "${workdir}/last.body")" = ok
curl --fail --silent --show-error "${base_url}/reload?policy=current" >/dev/null
if [ "${review_failures}" -ne 0 ]; then
  tail -n 40 "${workdir}/runtime/logs/error.log" >&2 || true
  exit 1
fi

test "$(curl --fail --silent --show-error "${base_url}/parity")" = ok
test "$(curl --fail --silent --show-error "${base_url}/reload-bad")" = 7
expect_status 422 '/reload?policy=inexact'
test "$(curl --fail --silent --show-error "${base_url}/revision")" = 7
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=maximum")" = 8
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=current")" = 7

# A path may change without changing its immutable policy bytes.
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=current_copy")" = 7
test "$(curl --fail --silent --show-error "${base_url}/revision")" = 7
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=current")" = 7

# An atomic same-revision replacement at the same path must not create mixed worker authority.
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=live")" = 13
: >"${workdir}/live-prewarm-pids"
for index in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  live_probe="$(curl --fail --silent --show-error "${base_url}/live-probe?key=prewarm-${index}")"
  worker_pid="$(echo "${live_probe}" | sed -n 's/.*"worker_pid":\([0-9][0-9]*\).*/\1/p')"
  test -n "${worker_pid}"
  echo "${worker_pid}" >>"${workdir}/live-prewarm-pids"
  echo "${live_probe}" | grep -F '"revision":13' >/dev/null
  echo "${live_probe}" | grep -F '"outcome":"fallback"' >/dev/null
  echo "${live_probe}" | grep -F '"reason":"invalid_input"' >/dev/null
done
test "$(sort -u "${workdir}/live-prewarm-pids" | wc -l | tr -d ' ')" -ge 2
record_before="$(curl --fail --silent --show-error "${base_url}/active-record")"
mv "${workdir}/policy/live-replacement.json" "${workdir}/policy/live.json"
: >"${workdir}/live-probe-pids"
for index in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  live_probe="$(curl --fail --silent --show-error "${base_url}/live-probe?key=${index}")"
  worker_pid="$(echo "${live_probe}" | sed -n 's/.*"worker_pid":\([0-9][0-9]*\).*/\1/p')"
  test -n "${worker_pid}"
  echo "${worker_pid}" >>"${workdir}/live-probe-pids"
  if ! echo "${live_probe}" | grep -F '"outcome":"fallback"' >/dev/null ||
      ! echo "${live_probe}" | grep -F '"reason":"limiter_state_unavailable"' >/dev/null ||
      ! echo "${live_probe}" | grep -F '"revision":0' >/dev/null; then
    echo "on-disk activation mismatch was not fail-closed: ${live_probe}" >&2
    exit 1
  fi
done
test "$(sort -u "${workdir}/live-probe-pids" | wc -l | tr -d ' ')" -ge 2
expect_status 422 '/reload?policy=live'
grep -F 'activation_conflict' "${workdir}/last.body" >/dev/null
test "$(curl --fail --silent --show-error "${base_url}/active-record")" = "${record_before}"

# A missing or corrupt shared activation record must stop every worker, even with local state.
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=current")" = 7
test "$(curl --fail --silent --show-error "${base_url}/delete-active-record")" = ok
for index in 1 2 3 4 5 6 7 8 9 10; do
  live_probe="$(curl --fail --silent --show-error "${base_url}/live-probe?key=missing-${index}")"
  echo "${live_probe}" | grep -F '"outcome":"fallback"' >/dev/null
  echo "${live_probe}" | grep -F '"reason":"limiter_state_unavailable"' >/dev/null
done
test "$(curl --fail --silent --show-error "${base_url}/revision")" = 0
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=current")" = 7
test "$(curl --fail --silent --show-error "${base_url}/corrupt-active-record")" = ok
for index in 1 2 3 4 5 6 7 8 9 10; do
  live_probe="$(curl --fail --silent --show-error "${base_url}/live-probe?key=corrupt-${index}")"
  echo "${live_probe}" | grep -F '"outcome":"fallback"' >/dev/null
  echo "${live_probe}" | grep -F '"reason":"limiter_state_unavailable"' >/dev/null
done
test "$(curl --fail --silent --show-error "${base_url}/revision")" = 0
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=current")" = 7

# Cold-start recovery must use the sealed fallback while current is invalid.
docker rm -f "${container}" >/dev/null
cp "${workdir}/policy/bad.json" "${workdir}/policy/current.json"
start_container
published="$(docker port "${container}" 18080/tcp | tail -n 1)"
case "${published}" in 127.0.0.1:*) ;; *) echo "smoke port is not loopback: ${published}" >&2; exit 1 ;; esac
base_url="http://${published}"
wait_ready 7
test "$(curl --fail --silent --show-error "${base_url}/revision")" = 7
expect_status 200 '/ok?key=cold-start-lkg&now=1000000'
cp "${workdir}/policy/current-copy.json" "${workdir}/policy/current.json"
test "$(curl --fail --silent --show-error "${base_url}/reload?policy=current")" = 7

# Length-prefixed fields isolate identifiers containing colons; a policy revision resets state.
expect_status 200 '/ok?key=e&tenant=a:b&site=c&now=2000000'
expect_status 200 '/ok?key=e&tenant=a:b&site=c&now=2000000'
expect_status 200 '/ok?key=e&tenant=a:b&site=c&now=2000000'
expect_status 200 '/ok?key=e&tenant=a&site=b:c&now=2000000'
test "$(curl --fail --silent --show-error "${base_url}/revision-isolation")" = ok

# Burst boundary and exact +1 microsecond retry.
expect_status 200 '/ok?key=a&now=1000000'
expect_status 200 '/ok?key=a&now=1000000'
expect_status 200 '/ok?key=a&now=1000000'
expect_status 429 '/ok?key=a&now=1000000'
grep -Fi 'X-CC-Reason: gcra_limit_applied' "${workdir}/last.headers" >/dev/null
expect_status 429 '/ok?key=a&now=1499999'
expect_status 200 '/ok?key=a&now=1500000'

# Stable flow, multiple-key isolation, and clock regression fallback without mutation.
expect_status 200 '/ok?key=b&now=1000000'
expect_status 200 '/ok?key=b&now=1500000'
expect_status 200 '/ok?key=b&now=2000000'
expect_status 200 '/ok?key=c&now=1000'
expect_status 503 '/ok?key=c&now=999'
grep -Fi 'X-CC-Reason: clock_regression' "${workdir}/last.headers" >/dev/null
expect_status 200 '/ok?key=c&now=1000'

# Upstream 503 and timeout consume rate state but do not reset or corrupt it.
expect_status 503 '/fail?key=f&now=1000000'
expect_status 504 '/slow?key=f&now=1000000'
expect_status 200 '/ok?key=f&now=1000000'
expect_status 429 '/ok?key=f&now=1000000'

# Shadow profiles never apply: low sample, normal, periodic, spike, and attack-clamped.
low="$(curl --fail --silent --show-error "${base_url}/observe?profile=low&at=0&requests=1")"
echo "${low}" | grep -F 'adaptive_insufficient_samples' >/dev/null
for requests in 50 50 50 50 50; do
  at="${at:-0}"
  normal="$(curl --fail --silent --show-error "${base_url}/observe?profile=normal&at=${at}&requests=${requests}")"
  at=$((at + 1000000))
done
echo "${normal}" | grep -F 'adaptive_shadow_only' >/dev/null
echo "${normal}" | grep -F '"apply":false' >/dev/null
test "$(curl --fail --silent --show-error "${base_url}/freeze?profile=normal&value=1")" = ok
frozen="$(curl --fail --silent --show-error "${base_url}/observe?profile=normal&at=5000000&requests=50")"
echo "${frozen}" | grep -F 'manual_threshold_frozen' >/dev/null
test "$(curl --fail --silent --show-error "${base_url}/freeze?profile=normal&value=0")" = ok
for requests in 30 70 30 70 50; do
  periodic_at="${periodic_at:-0}"
  periodic="$(curl --fail --silent --show-error "${base_url}/observe?profile=periodic&at=${periodic_at}&requests=${requests}")"
  periodic_at=$((periodic_at + 1000000))
done
echo "${periodic}" | grep -F 'adaptive_shadow_only' >/dev/null
for requests in 50 50 50 50 1000; do
  spike_at="${spike_at:-0}"
  spike="$(curl --fail --silent --show-error "${base_url}/observe?profile=spike&at=${spike_at}&requests=${requests}")"
  spike_at=$((spike_at + 1000000))
done
echo "${spike}" | grep -F '"apply":false' >/dev/null
for requests in 10000 10000 10000 10000 10000; do
  attack_at="${attack_at:-0}"
  attack="$(curl --fail --silent --show-error "${base_url}/observe?profile=attack&at=${attack_at}&requests=${requests}")"
  attack_at=$((attack_at + 1000000))
done
echo "${attack}" | grep -F '"rate_per_second":100' >/dev/null
echo "${attack}" | grep -F '"apply":false' >/dev/null

# Capacity exhaustion fails back to the baseline owner rather than evicting state.
curl --fail --silent --show-error "${base_url}/fill-state" >/dev/null
expect_status 503 '/ok?key=d&now=1000000'
grep -Fi 'X-CC-Reason: limiter_state_unavailable' "${workdir}/last.headers" >/dev/null

# A fresh container process resets node-local state and validates the approved auto release.
docker rm -f "${container}" >/dev/null
cp "${workdir}/policy/auto.json" "${workdir}/policy/current.json"
start_container
published="$(docker port "${container}" 18080/tcp | tail -n 1)"
case "${published}" in 127.0.0.1:*) ;; *) echo "smoke port is not loopback: ${published}" >&2; exit 1 ;; esac
base_url="http://${published}"
wait_ready 9
expect_status 200 '/ok?key=a&now=1000000'
test "$(curl --fail --silent --show-error "${base_url}/parity-auto")" = ok
test "$(curl --fail --silent --show-error "${base_url}/parity-exact")" = ok
for requests in 10000 10000 10000 10000 10000; do
  auto_at="${auto_at:-0}"
  auto="$(curl --fail --silent --show-error "${base_url}/observe?profile=auto&at=${auto_at}&requests=${requests}")"
  auto_at=$((auto_at + 1000000))
done
echo "${auto}" | grep -F 'adaptive_change_capped' >/dev/null
echo "${auto}" | grep -F '"rate_per_second":100' >/dev/null
echo "${auto}" | grep -F '"apply":true' >/dev/null

# Approved auto mode may tighten but cannot relax until a new policy revision.
for requests in 10 10 10 10 10; do
  monotonic_at="${monotonic_at:-0}"
  tightened="$(curl --fail --silent --show-error "${base_url}/observe?profile=monotonic&at=${monotonic_at}&requests=${requests}")"
  monotonic_at=$((monotonic_at + 1000000))
done
tightened_rate="$(echo "${tightened}" | sed -n 's/.*"rate_per_second":\([0-9][0-9]*\).*/\1/p')"
for requests in 100 100 100 100 100; do
  high="$(curl --fail --silent --show-error "${base_url}/observe?profile=monotonic&at=${monotonic_at}&requests=${requests}")"
  monotonic_at=$((monotonic_at + 1000000))
done
high_rate="$(echo "${high}" | sed -n 's/.*"rate_per_second":\([0-9][0-9]*\).*/\1/p')"
test -n "${tightened_rate}"
test "${high_rate}" -le "${tightened_rate}"
duplicate="$(curl --fail --silent --show-error "${base_url}/observe?profile=duplicate&at=1&requests=50")"
echo "${duplicate}" | grep -F 'adaptive_insufficient_samples' >/dev/null
duplicate="$(curl --fail --silent --show-error "${base_url}/observe?profile=duplicate&at=1&requests=50")"
echo "${duplicate}" | grep -F 'clock_regression' >/dev/null

# Rational debt preserves a 999999 requests/s policy without rounded-interval loss.
test "$(curl --fail --silent --show-error "${base_url}/high-rate")" = ok

# Per-revision group admission is atomically derived from live shared-dict keys.
docker rm -f "${container}" >/dev/null
cp "${workdir}/policy/capacity.json" "${workdir}/policy/current.json"
start_container
published="$(docker port "${container}" 18080/tcp | tail -n 1)"
case "${published}" in 127.0.0.1:*) ;; *) echo "smoke port is not loopback: ${published}" >&2; exit 1 ;; esac
base_url="http://${published}"
wait_ready 11
test "$(curl --fail --silent --show-error "${base_url}/flush-models")" = ok
race_jobs=""
for index in 1 2 3 4 5 6 7 8 9 10 11 12; do
  curl --fail --silent --show-error \
    "${base_url}/observe?profile=race-${index}&at=1&requests=50&hold=1" >"${workdir}/race-${index}.json" &
  race_jobs="${race_jobs} $!"
done
for job in ${race_jobs}; do wait "${job}"; done
test "$(curl --fail --silent --show-error "${base_url}/model-count")" = 2
worker_count="$(sed -n 's/.*"worker_pid":\([0-9][0-9]*\).*/\1/p' "${workdir}"/race-*.json | sort -u | wc -l | tr -d ' ')"
test "${worker_count}" -ge 2

# Failed insertion, explicit deletion, and TTL expiry all release group capacity.
test "$(curl --fail --silent --show-error "${base_url}/flush-models")" = ok
curl --fail --silent --show-error "${base_url}/fill-model" >/dev/null
blocked="$(curl --fail --silent --show-error "${base_url}/observe?profile=blocked&at=1&requests=50")"
echo "${blocked}" | grep -F 'limiter_state_unavailable' >/dev/null
test "$(curl --fail --silent --show-error "${base_url}/model-count")" = 0
test "$(curl --fail --silent --show-error "${base_url}/clear-model-fill")" = ok
recovered="$(curl --fail --silent --show-error "${base_url}/observe?profile=recovered&at=1&requests=50")"
echo "${recovered}" | grep -F 'adaptive_insufficient_samples' >/dev/null
test "$(curl --fail --silent --show-error "${base_url}/flush-models")" = ok
curl --fail --silent --show-error "${base_url}/observe?profile=ttl-a&at=1&requests=50" >/dev/null
curl --fail --silent --show-error "${base_url}/observe?profile=ttl-b&at=1&requests=50" >/dev/null
test "$(curl --fail --silent --show-error "${base_url}/model-count")" = 2
sleep 4.2
ttl_recovered="$(curl --fail --silent --show-error "${base_url}/observe?profile=ttl-c&at=5000000&requests=50")"
echo "${ttl_recovered}" | grep -F 'adaptive_insufficient_samples' >/dev/null
test "$(curl --fail --silent --show-error "${base_url}/model-count")" = 1

echo 'ccadaptive OpenResty smoke: PASS'
