#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *) echo "unsupported Docker architecture: ${docker_arch}" >&2; exit 69 ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-cache-freshness.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-cache-freshness\.//')"
network="cdnca-cache-freshness-${suffix}"
origin_container="cdnca-cache-freshness-origin-${suffix}"
edge_container="cdnca-cache-freshness-edge-${suffix}"

cleanup() {
  cleanup_status=$?
  if [ "${cleanup_status}" -ne 0 ]; then
    if [ "${origin_url:-}" != "" ]; then curl --silent --show-error "${origin_url}/counts" >&2 2>/dev/null || true; fi
    for diagnostic_headers in stale-refreshed no-validator-failed vary-hard-failed timeout-follower restart-fill restart-1; do
      test ! -f "${workdir}/${diagnostic_headers}.headers" || cat "${workdir}/${diagnostic_headers}.headers" >&2
    done
    test ! -f "${workdir}/state/error.log" || tail -n 160 "${workdir}/state/error.log" >&2
    docker logs "${edge_container}" >&2 2>/dev/null || true
    docker logs "${origin_container}" >&2 2>/dev/null || true
  fi
  docker rm -f "${edge_container}" "${origin_container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-cache-freshness.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
  return "${cleanup_status}"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/policy" "${workdir}/state/cache" "${workdir}/state/proxy_temp" "${workdir}/bin"
chmod 0700 "${workdir}/policy" "${workdir}/state" "${workdir}/state/cache" "${workdir}/state/proxy_temp" "${workdir}/bin"

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go build -trimpath -o "${workdir}/bin/policy" ./internal/cachefreshness/cmd/cache-freshness-policy
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/bin/origin" ./internal/cachefreshness/cmd/cache-freshness-origin
)

"${workdir}/bin/policy" -state-root /state -lua-root /opt/cache-freshness >"${workdir}/policy/nginx.conf" <<'JSON'
{"schema_version":"cdnca.edge.cache-freshness/v1","policy_version":1,"configuration_version":11,"tenant_id":"smoke-tenant","site_id":"smoke-site","mode":"enhancement","listen_address":"0.0.0.0","listen_port":18086,"hosts":["cache.example.test"],"origin_host":"cache-origin","origin_port":18090,"cache_max_bytes":134217728,"cache_inactive_seconds":30,"fresh_seconds":1,"cacheable_statuses":[200],"enhancement":{"enabled":true,"stale_window_seconds":3,"expert":{"lock_timeout_milliseconds":1000,"lock_age_milliseconds":5000,"background_update":true,"revalidation":true,"failure_classes":["updating","error","timeout","http_500","http_502","http_503","http_504"]}}}
JSON

cat >"${workdir}/policy/test-control.conf" <<'NGINX'
server {
  listen 18087;
  server_name _;
  location = /metadata {
    content_by_lua_block {
      local action = ngx.var.arg_action
      if action == "count-pending" then
        local pending = 0
        local dictionary = ngx.shared.cache_freshness_meta
        for _, key in ipairs(dictionary:get_keys(0)) do
          local value = dictionary:get(key)
          if key:sub(1, 7) == "record:" and type(value) == "string" and value:sub(1, 8) == "pending:" then
            pending = pending + 1
          end
        end
        ngx.say(pending)
        return
      end
      if action ~= "delete" and action ~= "corrupt" then
        return ngx.exit(400)
      end
      local dictionary = ngx.shared.cache_freshness_meta
      local changed = 0
      for _, key in ipairs(dictionary:get_keys(0)) do
        local value = dictionary:get(key)
        if key:sub(1, 7) == "record:" and type(value) == "string" and value:sub(1, 7) == "stored:" then
          if action == "delete" then
            dictionary:delete(key)
          else
            local ok, _, forcible = dictionary:set(key, "broken")
            if not ok or forcible then
              return ngx.exit(500)
            end
          end
          changed = changed + 1
        end
      end
      ngx.say(changed)
    }
  }
}
NGINX
sed '$d' "${workdir}/policy/nginx.conf" >"${workdir}/policy/nginx.conf.tmp"
printf '  include /policy/test-control.conf;\n}\n' >>"${workdir}/policy/nginx.conf.tmp"
mv "${workdir}/policy/nginx.conf.tmp" "${workdir}/policy/nginx.conf"

cat >"${workdir}/guard-harness.lua" <<'LUA'
package.path = "/opt/cache-freshness/?.lua;" .. package.path
local real_random = require("resty.random")

local function dictionary(fail_add)
    local store = {
        values = {},
        ttls = {},
        fail_add = fail_add,
        force_add = false,
        force_set = false,
        before_add = nil,
        before_set = nil,
    }
    function store:get(key) return self.values[key] end
    function store:set(key, value, ttl)
        if self.before_set then
            local callback = self.before_set
            self.before_set = nil
            callback(key, value)
        end
        self.values[key] = value
        self.ttls[key] = ttl
        if self.force_set then return true, nil, true end
        return true, nil, false
    end
    function store:add(key, value, ttl)
        if self.fail_add then return nil, "no memory", false end
        if self.before_add then
            local callback = self.before_add
            self.before_add = nil
            if callback(key, value) then return nil, "exists", false end
        end
        if self.values[key] ~= nil then return nil, "exists", false end
        self.values[key] = value
        self.ttls[key] = ttl
        if self.force_add then return true, nil, true end
        return true, nil, false
    end
    function store:expire(key, ttl)
        if self.values[key] == nil then return false, nil end
        self.ttls[key] = ttl
        return true, nil
    end
    function store:delete(key)
        self.values[key] = nil
        self.ttls[key] = nil
    end
    function store:flush_all()
        self.values = {}
        self.ttls = {}
    end
    function store:flush_expired() end
    function store:advance(seconds)
        for key, ttl in pairs(self.ttls) do
            if ttl ~= nil and ttl > 0 then
                ttl = ttl - seconds
                if ttl <= 0 then
                    self:delete(key)
                else
                    self.ttls[key] = ttl
                end
            end
        end
    end
    return store
end

local function load_guard(store, now, random_values)
    _G.ngx = {
        ALERT = 1,
        ERR = 2,
        arg = {},
        ctx = {},
        header = { ETag = '"fixture-v1"' },
        shared = { cache_freshness_meta = store },
        status = 200,
        var = {
            cache_freshness_fail_closed = "0",
            cache_freshness_generation = "",
            cache_freshness_hard_bypass = "0",
            cache_freshness_object_token = "",
            request_method = "GET",
        },
        log = function() end,
        now = function() return type(now) == "table" and now.value or now end,
    }
    _G.ngx.resp = {
        get_headers = function() return _G.ngx.header, nil end,
    }
    _G.ngx.parse_http_time = function(value)
        local fixed = {
            ["Wed, 18 Jun 2025 00:00:00 GMT"] = 1750204800,
            ["Wed, 18 Jun 2025 00:03:20 GMT"] = 1750205000,
            ["Fri, 01 Jan 2100 00:00:00 GMT"] = 4102444800,
        }
        return fixed[value]
    end
    if random_values ~= nil then
        local random_index = 0
        package.loaded["resty.random"] = {
            bytes = function()
                random_index = random_index + 1
                return random_values[random_index]
            end,
        }
    else
        package.loaded["resty.random"] = real_random
    end
    package.loaded.guard = nil
    local loaded_guard = require("guard")
    package.loaded["resty.random"] = real_random
    return loaded_guard, _G.ngx
end

local options = {
    identity = "v=1|tenant=t|site=s|config=1|scheme=http|host=cache.example.test|port=80|method=GET|request=/object",
    request_bypass = false,
    fresh_seconds = 30,
    stale_seconds = 60,
    lock_seconds = 5,
    metadata_ttl_seconds = 360,
}
local follow_options = setmetatable({ follow_origin_headers = true }, { __index = options })

local function record_key(key, token)
    return "record:" .. key .. ":" .. token
end

local function completed_key(key, token)
    return "completed:" .. key .. ":" .. token
end

local function validator_key(key, token)
    return "validator:" .. key .. ":" .. token
end

local function complete_body(loaded_guard, loaded_mock, body)
    loaded_mock.arg[1] = body
    loaded_mock.arg[2] = true
    loaded_guard.body_filter()
    loaded_guard.log({})
    loaded_mock.arg = {}
end

local function assert_origin_header_case(headers, fail_closed, reason)
    local store = dictionary(false)
    local loaded_guard, loaded_mock = load_guard(store, 100)
    loaded_mock.header = headers
    loaded_guard.origin_header_filter(follow_options)
    assert(loaded_mock.var.cache_freshness_fail_closed == (fail_closed and "1" or "0"))
    assert(loaded_mock.ctx.cache_freshness_reason == reason)
end

assert_origin_header_case({ ["Cache-Control"] = "max-age=80, s-maxage=120", Age = "20", Vary = "Accept-Encoding" }, false)
assert_origin_header_case({ Date = "Wed, 18 Jun 2025 00:00:00 GMT", Expires = "Wed, 18 Jun 2025 00:03:20 GMT", Age = "20" }, false)
assert_origin_header_case({ ["Cache-Control"] = "s-maxage=120, max-age=80", Age = "20", Date = "invalid", Expires = "invalid" }, false)
assert_origin_header_case({ ["Cache-Control"] = "max-age=80", Age = "20", Date = "invalid", Expires = "invalid" }, false)
assert_origin_header_case({ ["Cache-Control"] = "no-store", Age = "invalid", Date = "invalid", Expires = "invalid" }, true, "origin_headers_uncacheable")
assert_origin_header_case({ ["Cache-Control"] = "private", Age = "invalid", Date = "invalid", Expires = "invalid" }, true, "origin_headers_uncacheable")
assert_origin_header_case({ ["Cache-Control"] = "no-store, max-age=60" }, true, "origin_headers_uncacheable")
assert_origin_header_case({ ["Cache-Control"] = "private, max-age=60" }, true, "origin_headers_uncacheable")
assert_origin_header_case({ ["Cache-Control"] = "max-age=60", Vary = "*" }, true, "origin_headers_uncacheable")
assert_origin_header_case({ ["Cache-Control"] = "no-cache, max-age=60" }, true, "cache_miss")
assert_origin_header_case({ ["Cache-Control"] = "must-revalidate, max-age=60" }, true, "cache_miss")
for _, headers in ipairs({
    { ["Cache-Control"] = { "max-age=60", "max-age=60" } },
    { ["Cache-Control"] = "max-age=60", Age = { "1", "1" } },
}) do
    assert_origin_header_case(headers, true, "origin_headers_invalid")
end
-- FX28: 源站不带任何缓存头时与非新鲜度模式一致，按默认 TTL 缓存；超过 2^31 的寿命按 RFC 9111 截断而不是拒绝。
assert_origin_header_case({}, false)
assert_origin_header_case({ Date = "invalid" }, false)
assert_origin_header_case({ ["Cache-Control"] = "public", Date = "Wed, 18 Jun 2025 00:00:00 GMT" }, false)
assert_origin_header_case({ ["Cache-Control"] = "max-age=2147483648" }, false)
assert_origin_header_case({ ["Cache-Control"] = "max-age=99999999999999999999999" }, false)
assert_origin_header_case({ Date = "Wed, 18 Jun 2025 00:00:00 GMT", Expires = "Fri, 01 Jan 2100 00:00:00 GMT" }, false)

local function origin_fill_freshness(headers)
    local store = dictionary(false)
    local loaded_guard, loaded_mock = load_guard(store, 100)
    loaded_guard.init_worker()
    loaded_guard.access(follow_options)
    local key = loaded_mock.ctx.cache_freshness_key
    local token = loaded_mock.var.cache_freshness_object_token
    for name, value in pairs(headers) do
        loaded_mock.header[name] = value
    end
    loaded_mock.var.upstream_cache_status = "MISS"
    loaded_guard.header_filter(follow_options)
    assert(loaded_mock.var.cache_freshness_fail_closed == "0")
    return store:get("freshness:" .. key .. ":" .. token)
end
assert(origin_fill_freshness({}) == tostring(follow_options.fresh_seconds))
assert(origin_fill_freshness({ ["Cache-Control"] = "public", Age = "10" }) == tostring(follow_options.fresh_seconds))
assert(origin_fill_freshness({ ["Cache-Control"] = "max-age=2147483648" }) == "2147483647")
assert(origin_fill_freshness({ Date = "Wed, 18 Jun 2025 00:00:00 GMT", Expires = "Fri, 01 Jan 2100 00:00:00 GMT" }) == "2147483647")

local origin_store = dictionary(false)
local origin_clock = { value = 100 }
local origin_guard, origin_mock = load_guard(origin_store, origin_clock)
origin_guard.init_worker()
origin_guard.access(follow_options)
local origin_key = origin_mock.ctx.cache_freshness_key
local origin_token = origin_mock.var.cache_freshness_object_token
origin_mock.header["Cache-Control"] = "max-age=80, s-maxage=120"
origin_mock.header.Age = "20"
origin_mock.header["X-CDNCA-Cache-Reason"] = "origin-forged"
origin_mock.var.upstream_cache_status = "MISS"
origin_guard.header_filter(follow_options)
assert(origin_store:get("freshness:" .. origin_key .. ":" .. origin_token) == "100")
assert(origin_mock.header["X-CDNCA-Cache-Reason"] ~= "origin-forged")

local shared = dictionary(false)
local guard, mock = load_guard(shared, 100)
guard.init_worker()
local generation_one = shared:get("cache:generation")
assert(type(generation_one) == "string" and #generation_one == 64)
guard.access(options)
local key_one = mock.ctx.cache_freshness_key
assert(type(key_one) == "string" and #key_one == 64)
local token_one = mock.var.cache_freshness_object_token
assert(type(token_one) == "string" and #token_one == 64)

mock.var.upstream_cache_status = "HIT"
guard.header_filter(options)
assert(shared:get(record_key(key_one, token_one)) == "pending:" .. token_one)
mock.var.upstream_cache_status = nil

mock.ctx = {}
mock.var.cache_freshness_hard_bypass = "0"
guard.access(options)
assert(mock.var.cache_freshness_object_token == token_one)
assert(mock.ctx.cache_freshness_follower == true)

local commit_store = dictionary(false)
local commit_clock = { value = 100 }
guard, mock = load_guard(commit_store, commit_clock)
guard.init_worker()
guard.access(options)
local commit_key = mock.ctx.cache_freshness_key
local commit_token = mock.var.cache_freshness_object_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(options)
assert(commit_store:get(record_key(commit_key, commit_token)) == "pending:" .. commit_token)
assert(commit_store:get(completed_key(commit_key, commit_token)) == nil)
complete_body(guard, mock, "complete")
assert(commit_store:get(record_key(commit_key, commit_token)) == "pending:" .. commit_token)
assert(commit_store:get(completed_key(commit_key, commit_token)):match("^completed:" .. commit_token .. ":") ~= nil)
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
mock.var.request_method = "HEAD"
mock.var.upstream_cache_status = "HIT"
guard.header_filter(options)
mock.var.request_method = "GET"
assert(commit_store:get(record_key(commit_key, commit_token)) == "stored:" .. commit_token .. ":100.000000")
assert(commit_store:get(completed_key(commit_key, commit_token)) == nil)
local committed_validator = commit_store:get(validator_key(commit_key, commit_token))
assert(type(committed_validator) == "string" and #committed_validator == 64)
assert(commit_store:set(completed_key(commit_key, commit_token), "completed:" .. commit_token .. ":100.000000:" .. committed_validator .. ":body"))
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
mock.var.upstream_cache_status = "HIT"
guard.header_filter(options)
assert(mock.var.cache_freshness_fail_closed == "0")
assert(commit_store:get(completed_key(commit_key, commit_token)) == nil)
assert(commit_store:get(record_key(commit_key, commit_token)) == "stored:" .. commit_token .. ":100.000000")
commit_clock.value = 101
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
mock.header.ETag = '"fixture-v2"'
mock.var.upstream_cache_status = "HIT"
guard.header_filter(options)
assert(commit_store:get(record_key(commit_key, commit_token)) == "stored:" .. commit_token .. ":101.000000")
commit_clock.value = 102
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
mock.var.upstream_cache_status = "HIT"
guard.header_filter(options)
assert(commit_store:get(record_key(commit_key, commit_token)) == "stored:" .. commit_token .. ":101.000000")
commit_store:delete(record_key(commit_key, commit_token))
mock.ctx = {}
mock.var.cache_freshness_hard_bypass = "0"
mock.var.upstream_cache_status = nil
guard.access(options)
local rotated_token = mock.var.cache_freshness_object_token
assert(rotated_token ~= commit_token)
assert(commit_store:get("current:" .. commit_key) == rotated_token)

mock.ctx = {
    cache_freshness_key = commit_key,
    cache_freshness_object_token = commit_token,
    cache_freshness_had_metadata = true,
}
mock.var.cache_freshness_object_token = commit_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(options)
assert(commit_store:get("current:" .. commit_key) == rotated_token)
assert(commit_store:get(record_key(commit_key, commit_token)) == nil)
assert(commit_store:get(record_key(commit_key, rotated_token)) == "pending:" .. rotated_token)
mock.var.upstream_http_cache_control = "private"
guard.header_filter(options)
assert(commit_store:get("current:" .. commit_key) == rotated_token)
assert(commit_store:get(record_key(commit_key, commit_token)) == nil)
assert(commit_store:get(record_key(commit_key, rotated_token)) == "pending:" .. rotated_token)
mock.var.upstream_http_cache_control = nil

local truncated_store = dictionary(false)
guard, mock = load_guard(truncated_store, 100)
guard.init_worker()
guard.access(options)
local truncated_key = mock.ctx.cache_freshness_key
local truncated_token = mock.var.cache_freshness_object_token
mock.var.upstream_cache_status = "MISS"
mock.var.upstream_http_content_length = "10"
guard.header_filter(options)
complete_body(guard, mock, "short")
assert(truncated_store:get(record_key(truncated_key, truncated_token)) == "pending:" .. truncated_token)
assert(truncated_store:get(completed_key(truncated_key, truncated_token)) == nil)

local head_hit_store = dictionary(false)
local head_hit_clock = { value = 100 }
guard, mock = load_guard(head_hit_store, head_hit_clock)
guard.init_worker()
mock.var.request_method = "HEAD"
guard.access(options)
local head_hit_key = mock.ctx.cache_freshness_key
local head_hit_token = mock.var.cache_freshness_object_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(options)
guard.log({})
local head_hit_candidate = head_hit_store:get(completed_key(head_hit_key, head_hit_token))
assert(head_hit_candidate:match("^completed:" .. head_hit_token .. ":100%.000000:[0-9a-f]+:head$") ~= nil)
head_hit_clock.value = 101
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
mock.var.upstream_cache_status = "HIT"
guard.header_filter(options)
assert(head_hit_store:get(record_key(head_hit_key, head_hit_token)) == "stored:" .. head_hit_token .. ":100.000000")
assert(head_hit_store:get(completed_key(head_hit_key, head_hit_token)) == nil)

local body_replaced_store = dictionary(false)
local body_replaced_clock = { value = 100 }
guard, mock = load_guard(body_replaced_store, body_replaced_clock)
guard.init_worker()
guard.access(options)
local body_replaced_key = mock.ctx.cache_freshness_key
local body_replaced_token = mock.var.cache_freshness_object_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(options)
complete_body(guard, mock, "first")
local first_body_candidate = body_replaced_store:get(completed_key(body_replaced_key, body_replaced_token))
assert(first_body_candidate:match("^completed:" .. body_replaced_token .. ":100%.000000:[0-9a-f]+:body$") ~= nil)
body_replaced_clock.value = 101
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
mock.header.ETag = '"fixture-v2"'
mock.var.upstream_cache_status = "HIT"
guard.header_filter(options)
assert(body_replaced_store:get(record_key(body_replaced_key, body_replaced_token)) == "stored:" .. body_replaced_token .. ":101.000000")
assert(body_replaced_store:get(completed_key(body_replaced_key, body_replaced_token)) == nil)

local head_replaced_store = dictionary(false)
local head_replaced_clock = { value = 100 }
guard, mock = load_guard(head_replaced_store, head_replaced_clock)
guard.init_worker()
mock.var.request_method = "HEAD"
guard.access(options)
local head_replaced_key = mock.ctx.cache_freshness_key
local head_replaced_token = mock.var.cache_freshness_object_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(options)
guard.log({})
local first_head_replaced_candidate = head_replaced_store:get(completed_key(head_replaced_key, head_replaced_token))
assert(first_head_replaced_candidate:match("^completed:" .. head_replaced_token .. ":100%.000000:[0-9a-f]+:head$") ~= nil)
head_replaced_clock.value = 101
mock.ctx = {}
mock.var.request_method = "GET"
mock.var.upstream_cache_status = nil
guard.access(options)
mock.header.ETag = '"fixture-v2"'
mock.var.upstream_cache_status = "HIT"
guard.header_filter(options)
assert(head_replaced_store:get(record_key(head_replaced_key, head_replaced_token)) == "pending:" .. head_replaced_token)
assert(head_replaced_store:get(completed_key(head_replaced_key, head_replaced_token)) == first_head_replaced_candidate)
head_replaced_clock.value = 190
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
assert(mock.ctx.cache_freshness_reason == "stale_hard_limit_reached")
assert(head_replaced_store:get("current:" .. head_replaced_key) ~= head_replaced_token)

local head_unlanded_store = dictionary(false)
local head_unlanded_clock = { value = 100 }
guard, mock = load_guard(head_unlanded_store, head_unlanded_clock)
guard.init_worker()
mock.var.request_method = "HEAD"
guard.access(options)
local head_unlanded_key = mock.ctx.cache_freshness_key
local head_unlanded_token = mock.var.cache_freshness_object_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(options)
guard.log({})
local first_head_candidate = head_unlanded_store:get(completed_key(head_unlanded_key, head_unlanded_token))
head_unlanded_clock.value = 120
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
mock.var.upstream_cache_status = "MISS"
guard.header_filter(options)
guard.log({})
assert(head_unlanded_store:get(completed_key(head_unlanded_key, head_unlanded_token)) == first_head_candidate)
head_unlanded_clock.value = 190
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(options)
assert(mock.ctx.cache_freshness_reason == "stale_hard_limit_reached")
assert(head_unlanded_store:get("current:" .. head_unlanded_key) ~= head_unlanded_token)

local head_failure_store = dictionary(false)
guard, mock = load_guard(head_failure_store, 100)
guard.init_worker()
mock.var.request_method = "HEAD"
guard.access(options)
local head_failure_key = mock.ctx.cache_freshness_key
local head_failure_token = mock.var.cache_freshness_object_token
mock.status = 503
mock.var.upstream_cache_status = "MISS"
guard.header_filter(options)
guard.log({})
assert(head_failure_store:get(completed_key(head_failure_key, head_failure_token)) == nil)

local unverifiable_store = dictionary(false)
local unverifiable_options = {
    identity = options.identity,
    request_bypass = false,
    response_bypass = false,
    validator_bypass = true,
    fresh_seconds = options.fresh_seconds,
    stale_seconds = options.stale_seconds,
    lock_seconds = options.lock_seconds,
    lock_timeout_seconds = 1,
    metadata_ttl_seconds = options.metadata_ttl_seconds,
}
guard, mock = load_guard(unverifiable_store, 100)
guard.init_worker()
mock.header = {}
guard.access(unverifiable_options)
local unverifiable_key = mock.ctx.cache_freshness_key
local unverifiable_token = mock.var.cache_freshness_object_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(unverifiable_options)
assert(mock.header["X-CDNCA-Cache-Reason"] == "cache_private_bypass")
assert(mock.header["X-CDNCA-Cache-State"] == "expired")
guard.log({})
assert(unverifiable_store:get(completed_key(unverifiable_key, unverifiable_token)) == nil)
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(unverifiable_options)
mock.var.upstream_cache_status = "HIT"
guard.header_filter(unverifiable_options)
assert(mock.status == 503)
assert(mock.ctx.cache_freshness_drop_body == true)
assert(mock.header["X-CDNCA-Cache-Reason"] == "stale_hard_limit_reached")
assert(mock.header["X-CDNCA-Cache-State"] == "expired")
assert(unverifiable_store:get("current:" .. unverifiable_key) ~= unverifiable_token)
mock.arg = { "unverifiable-old-body", false }
guard.body_filter()
assert(mock.arg[1] == nil and mock.arg[2] == true)

local vary_legacy_store = dictionary(false)
unverifiable_options.validator_bypass = false
unverifiable_options.vary_bypass = true
guard, mock = load_guard(vary_legacy_store, 100)
guard.init_worker()
guard.access(unverifiable_options)
local vary_legacy_key = mock.ctx.cache_freshness_key
local vary_legacy_token = mock.var.cache_freshness_object_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(unverifiable_options)
guard.log({})
assert(vary_legacy_store:get(completed_key(vary_legacy_key, vary_legacy_token)) == nil)
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(unverifiable_options)
mock.var.upstream_cache_status = "HIT"
guard.header_filter(unverifiable_options)
assert(mock.status == 503)
assert(mock.ctx.cache_freshness_drop_body == true)
assert(mock.header["X-CDNCA-Cache-Reason"] == "stale_hard_limit_reached")
assert(mock.header["X-CDNCA-Cache-State"] == "expired")
assert(vary_legacy_store:get("current:" .. vary_legacy_key) ~= vary_legacy_token)
mock.arg = { "vary-old-body", false }
guard.body_filter()
assert(mock.arg[1] == nil and mock.arg[2] == true)

local delayed_store = dictionary(false)
local delayed_clock = { value = 100 }
local delayed_options = {
    identity = options.identity,
    request_bypass = false,
    fresh_seconds = options.fresh_seconds,
    stale_seconds = options.stale_seconds,
    lock_seconds = 0.1,
    metadata_ttl_seconds = options.metadata_ttl_seconds,
}
guard, mock = load_guard(delayed_store, delayed_clock)
guard.init_worker()
guard.access(delayed_options)
local delayed_key = mock.ctx.cache_freshness_key
local delayed_token = mock.var.cache_freshness_object_token
local delayed_first_ctx = mock.ctx
delayed_store:advance(1.2)
delayed_clock.value = delayed_clock.value + 1.2
assert(delayed_store:get(record_key(delayed_key, delayed_token)) == "pending:" .. delayed_token)
mock.ctx = {}
guard.access(delayed_options)
assert(mock.var.cache_freshness_object_token == delayed_token)
assert(mock.ctx.cache_freshness_active_owner == true)
mock.ctx = delayed_first_ctx
mock.var.cache_freshness_object_token = delayed_token
mock.var.upstream_cache_status = "MISS"
guard.header_filter(delayed_options)
complete_body(guard, mock, "delayed")
assert(delayed_store:get(record_key(delayed_key, delayed_token)) == "pending:" .. delayed_token)
assert(delayed_store:get(completed_key(delayed_key, delayed_token)):match("^completed:" .. delayed_token .. ":") ~= nil)
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(delayed_options)
assert(mock.var.cache_freshness_object_token == delayed_token)
mock.var.upstream_cache_status = "HIT"
guard.header_filter(delayed_options)
mock.ctx = {}
mock.var.upstream_cache_status = nil
guard.access(delayed_options)
assert(mock.ctx.cache_freshness_had_metadata == true)

local interleaved_store = dictionary(false)
guard, mock = load_guard(interleaved_store, 100)
guard.init_worker()
guard.access(options)
local interleaved_key = mock.ctx.cache_freshness_key
local interleaved_token = mock.var.cache_freshness_object_token
interleaved_store:delete(record_key(interleaved_key, interleaved_token))
local nested_token
interleaved_store.before_set = function(key)
    assert(key == "current:" .. interleaved_key)
    interleaved_store:advance(options.lock_seconds + 1.2)
    mock.ctx = {}
    mock.var.cache_freshness_hard_bypass = "0"
    guard.access(options)
    nested_token = mock.var.cache_freshness_object_token
end
mock.ctx = {}
mock.var.cache_freshness_hard_bypass = "0"
guard.access(options)
local outer_token = mock.var.cache_freshness_object_token
assert(outer_token ~= interleaved_token)
assert(nested_token == outer_token)
assert(interleaved_store:get("current:" .. interleaved_key) == outer_token)
assert(interleaved_store:get(record_key(interleaved_key, outer_token)) == "pending:" .. outer_token)

local released_store = dictionary(false)
guard, mock = load_guard(released_store, 100)
guard.init_worker()
guard.access(options)
local released_key = mock.ctx.cache_freshness_key
local released_old_token = mock.var.cache_freshness_object_token
local released_new_token = string.rep("b", 64)
assert(released_new_token ~= released_old_token)
released_store:delete(record_key(released_key, released_old_token))
released_store.before_add = function(key)
    assert(key == "transition:" .. released_key .. ":" .. released_old_token)
    released_store.values[record_key(released_key, released_new_token)] = "pending:" .. released_new_token
    released_store.values["current:" .. released_key] = released_new_token
    return true
end
mock.ctx = {}
mock.var.cache_freshness_hard_bypass = "0"
guard.access(options)
assert(mock.var.cache_freshness_fail_closed == "0")
assert(mock.var.cache_freshness_object_token == released_new_token)
assert(released_store:get("metadata:degraded") == nil)

guard, mock = load_guard(shared, 100)
guard.init_worker()
assert(shared:get("cache:generation") == generation_one)

local restarted = dictionary(false)
guard, mock = load_guard(restarted, 100)
guard.init_worker()
local generation_two = restarted:get("cache:generation")
assert(type(generation_two) == "string" and generation_two ~= generation_one)
guard.access(options)
assert(mock.ctx.cache_freshness_key ~= key_one)
assert(mock.var.cache_freshness_object_token ~= token_one)

local clock_store = dictionary(false)
guard, mock = load_guard(clock_store, 100)
guard.init_worker()
guard.access(options)
local clock_key = mock.ctx.cache_freshness_key
local clock_token = mock.var.cache_freshness_object_token
clock_store:set(record_key(clock_key, clock_token), "stored:" .. clock_token .. ":200.000000")
mock.ctx = {}
mock.var.cache_freshness_fail_closed = "0"
mock.var.cache_freshness_hard_bypass = "0"
guard.access(options)
assert(mock.var.cache_freshness_hard_bypass == "0")
assert(mock.ctx.cache_freshness_hard_refresh == true)
assert(mock.ctx.cache_freshness_reason == "stale_hard_limit_reached")
assert(mock.var.cache_freshness_object_token ~= clock_token)

local fresh_token = mock.var.cache_freshness_object_token
clock_store:set(record_key(clock_key, fresh_token), "stored:" .. fresh_token .. ":90.000000")
mock.ctx = {}
mock.var.cache_freshness_fail_closed = "0"
mock.var.cache_freshness_hard_bypass = "0"
guard.access(options)
assert(mock.ctx.cache_freshness_active_key == nil)
assert(mock.ctx.cache_freshness_follower == nil)
assert(mock.var.cache_freshness_object_token == fresh_token)

clock_store:delete(record_key(clock_key, fresh_token))
mock.ctx = {}
mock.var.cache_freshness_fail_closed = "0"
mock.var.cache_freshness_hard_bypass = "0"
guard.access(options)
assert(mock.var.cache_freshness_object_token ~= fresh_token)
assert(mock.ctx.cache_freshness_active_owner == true)

local corrupt_store = dictionary(false)
guard, mock = load_guard(corrupt_store, 100)
guard.init_worker()
guard.access(options)
local corrupt_key = mock.ctx.cache_freshness_key
local corrupt_token = mock.var.cache_freshness_object_token
corrupt_store:set(record_key(corrupt_key, corrupt_token), "broken")
mock.ctx = {}
mock.var.cache_freshness_fail_closed = "0"
mock.var.cache_freshness_hard_bypass = "0"
local access_ok = pcall(guard.access, options)
assert(access_ok)
assert(mock.var.cache_freshness_fail_closed == "1")
assert(mock.var.cache_freshness_hard_bypass == "1")

local invalid_current_store = dictionary(false)
guard, mock = load_guard(invalid_current_store, 100)
guard.init_worker()
guard.access(options)
local invalid_current_key = mock.ctx.cache_freshness_key
invalid_current_store:set("current:" .. invalid_current_key, "broken")
mock.ctx = {}
local invalid_current_ok = pcall(guard.access, options)
assert(invalid_current_ok)
assert(mock.var.cache_freshness_fail_closed == "1")
assert(invalid_current_store:get("metadata:degraded") == true)

local invalid_transition_store = dictionary(false)
guard, mock = load_guard(invalid_transition_store, 100)
guard.init_worker()
guard.access(options)
local invalid_transition_key = mock.ctx.cache_freshness_key
local invalid_transition_token = mock.var.cache_freshness_object_token
invalid_transition_store:delete(record_key(invalid_transition_key, invalid_transition_token))
invalid_transition_store:set("transition:" .. invalid_transition_key .. ":" .. invalid_transition_token, "broken")
mock.ctx = {}
local invalid_transition_ok = pcall(guard.access, options)
assert(invalid_transition_ok)
assert(mock.var.cache_freshness_fail_closed == "1")
assert(invalid_transition_store:get("metadata:degraded") == true)

local collision_store = dictionary(false)
local generation_bytes = string.rep(string.char(1), 32)
local object_bytes = string.rep(string.char(2), 32)
guard, mock = load_guard(collision_store, 100, { generation_bytes, object_bytes, object_bytes })
guard.init_worker()
guard.access(options)
local collision_key = mock.ctx.cache_freshness_key
local collision_token = mock.var.cache_freshness_object_token
collision_store:delete(record_key(collision_key, collision_token))
mock.ctx = {}
local collision_ok = pcall(guard.access, options)
assert(collision_ok)
assert(mock.var.cache_freshness_fail_closed == "1")
assert(collision_store:get("metadata:degraded") == true)

local forcible_add_store = dictionary(false)
forcible_add_store.force_add = true
guard, mock = load_guard(forcible_add_store, 100)
guard.init_worker()
assert(forcible_add_store:get("metadata:degraded") == true)

local forcible_set_store = dictionary(false)
guard, mock = load_guard(forcible_set_store, 100)
guard.init_worker()
forcible_set_store.force_set = true
mock.ctx = {}
guard.access(options)
assert(mock.var.cache_freshness_fail_closed == "1")
assert(forcible_set_store:get("metadata:degraded") == true)

local failed_store = dictionary(true)
guard, mock = load_guard(failed_store, 100)
guard.init_worker()
mock.ctx = {}
guard.access(options)
assert(mock.var.cache_freshness_fail_closed == "1")
assert(mock.var.cache_freshness_hard_bypass == "1")

io.write("cache freshness Lua harness passed\n")
LUA
chmod 0400 "${workdir}/guard-harness.lua"

docker network create "${network}" >/dev/null
docker run --rm \
  --network none \
  --volume "${workdir}/guard-harness.lua:/tmp/guard-harness.lua:ro" \
  --volume "${repo_root}/edge/openresty/cachefreshness:/opt/cache-freshness:ro" \
  --entrypoint /usr/local/openresty/bin/resty \
  "${OPENRESTY_IMAGE}" /tmp/guard-harness.lua
docker run --rm \
  --network "${network}" \
  --network-alias cache-origin \
  --volume "${workdir}/policy:/policy:ro" \
  --volume "${workdir}/state:/state" \
  --volume "${repo_root}/edge/openresty/cachefreshness:/opt/cache-freshness:ro" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" -t -c /policy/nginx.conf >"${workdir}/precheck.stdout" 2>"${workdir}/precheck.stderr"
if grep -q 'could not build optimal variables_hash' "${workdir}/precheck.stdout" "${workdir}/precheck.stderr"; then
  echo 'OpenResty precheck emitted a variables_hash warning' >&2
  exit 1
fi

docker run --detach \
  --name "${origin_container}" \
  --network "${network}" \
  --network-alias cache-origin \
  --publish 127.0.0.1::18090 \
  --volume "${workdir}/bin/origin:/usr/local/bin/cache-freshness-origin:ro" \
  --entrypoint /usr/local/bin/cache-freshness-origin \
  "${OPENRESTY_IMAGE}" >/dev/null
docker run --detach \
  --name "${edge_container}" \
  --network "${network}" \
  --publish 127.0.0.1::18086 \
  --publish 127.0.0.1::18087 \
  --volume "${workdir}/policy:/policy:ro" \
  --volume "${workdir}/state:/state" \
  --volume "${repo_root}/edge/openresty/cachefreshness:/opt/cache-freshness:ro" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" -c /policy/nginx.conf -g 'daemon off;' >/dev/null

origin_published="$(docker port "${origin_container}" 18090/tcp | tail -n 1)"
edge_published="$(docker port "${edge_container}" 18086/tcp | tail -n 1)"
metadata_published="$(docker port "${edge_container}" 18087/tcp | tail -n 1)"
origin_url="http://${origin_published}"
edge_url="http://${edge_published}"
metadata_url="http://${metadata_published}"

wait_edge() {
  attempt=0
  consecutive=0
  while [ "${attempt}" -lt 100 ]; do
    if [ "$(curl --silent --show-error -H 'Host: cache.example.test' "${edge_url}/_cdnca/cache-freshness-healthz" 2>/dev/null || true)" = 'ok:1' ]; then
      consecutive=$((consecutive + 1))
      if [ "${consecutive}" -ge 5 ]; then
        return
      fi
    else
      consecutive=0
    fi
    attempt=$((attempt + 1))
    sleep 0.05
  done
  return 1
}

assert_no_variable_hash_warning() {
  if grep -q 'could not build optimal variables_hash' "${workdir}/state/error.log" 2>/dev/null; then
    echo 'OpenResty runtime emitted a variables_hash warning' >&2
    return 1
  fi
  if docker logs "${edge_container}" 2>&1 | grep -q 'could not build optimal variables_hash'; then
    echo 'OpenResty container emitted a variables_hash warning' >&2
    return 1
  fi
}

wait_edge

control() {
  curl --fail --silent --show-error --get \
    --data-urlencode "delay_ms=$1" --data-urlencode "status=$2" --data-urlencode "body=$3" \
    --data-urlencode "truncate=${4:-false}" \
    "${origin_url}/control" >/dev/null
}

origin_count() {
  count_path="$1"
  count_json="$(curl --fail --silent --show-error "${origin_url}/counts")"
  count_value="$(printf '%s\n' "${count_json}" | sed -n "s|.*\"${count_path}\":\([0-9][0-9]*\).*|\1|p")"
  printf '%s\n' "${count_value:-0}"
}

metadata_control() {
  curl --fail --silent --show-error --get --data-urlencode "action=$1" "${metadata_url}/metadata"
}

request() {
  label="$1"
  path="$2"
  shift 2
  curl --silent --show-error \
    --dump-header "${workdir}/${label}.headers" \
    --output "${workdir}/${label}.body" \
    --write-out '%{http_code}' \
    -H 'Host: cache.example.test' "$@" "${edge_url}${path}" >"${workdir}/${label}.status"
}

header_value() {
  awk -v name="$2" 'tolower($0) ~ "^" tolower(name) ":" { sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "$1"
}

header_count() {
  awk -v name="$2" 'tolower($0) ~ "^" tolower(name) ":" { count++ } END { print count + 0 }' "$1"
}

expect_status() {
  test "$(cat "${workdir}/$1.status")" = "$2"
}

expect_uncached_twice() {
  path="$1"
  shift
  before="$(origin_count "${path}")"
  request "uncached-a-$(basename "${path}")" "${path}" "$@"
  request "uncached-b-$(basename "${path}")" "${path}" "$@"
  after="$(origin_count "${path}")"
  test $((after - before)) -eq 2
}

# Undeclared Host values terminate in the default server without reaching origin.
before="$(origin_count /unknown-host)"
curl --silent --show-error --output "${workdir}/unknown-host.body" --write-out '%{http_code}' \
  -H 'Host: unknown.example.test' "${edge_url}/unknown-host" >"${workdir}/unknown-host.status"
test "$(cat "${workdir}/unknown-host.status")" = 421
after="$(origin_count /unknown-host)"
test $((after - before)) -eq 0

# A cold burst for one complete identity is collapsed to one origin request.
control 400 200 burst-v1
before="$(origin_count /object)"
pids=""
index=1
while [ "${index}" -le 20 ]; do
  curl --silent --show-error --dump-header "${workdir}/burst-${index}.headers" \
    --output "${workdir}/burst-${index}.body" --write-out '%{http_code}' \
    -H 'Host: cache.example.test' "${edge_url}/object?burst=one" >"${workdir}/burst-${index}.status" &
  pids="${pids} $!"
  index=$((index + 1))
done

for pid in ${pids}; do wait "${pid}"; done
after="$(origin_count /object)"
test $((after - before)) -eq 1

# A truncated background refresh cannot extend the original object's hard deadline.
control 0 200 truncated-v1 false
request truncated-fill '/truncated?case=body'
request truncated-hit '/truncated?case=body'
expect_status truncated-hit 200
sleep 1.5
control 0 200 truncated-v2 true
request truncated-stale '/truncated?case=body'
expect_status truncated-stale 200
test "$(cat "${workdir}/truncated-stale.body")" = truncated-v1
sleep 2.8
control 0 503 ignored false
request truncated-failed '/truncated?case=body'
expect_status truncated-failed 503
test "$(cat "${workdir}/truncated-failed.body")" != truncated-v1
test "$(header_value "${workdir}/truncated-failed.headers" X-CDNCA-Cache-State)" = expired
index=1
while [ "${index}" -le 20 ]; do
  test "$(cat "${workdir}/burst-${index}.status")" = 200
  test "$(cat "${workdir}/burst-${index}.body")" = burst-v1
  index=$((index + 1))
done

# A HEAD first fill remains bounded: only a later physical cache HIT may commit
# its completion candidate, anchored to the original HEAD completion time.
control 0 200 head-v1 false
request head-fill '/head-first?case=head' --head
expect_status head-fill 200
test "$(header_value "${workdir}/head-fill.headers" X-CDNCA-Cache-Status)" = MISS
request head-get-hit '/head-first?case=head'
expect_status head-get-hit 200
test "$(cat "${workdir}/head-get-hit.body")" = head-v1
test "$(header_value "${workdir}/head-get-hit.headers" X-CDNCA-Cache-Status)" = HIT
head_pending_after_hit="$(metadata_control count-pending)"
sleep 4.3
control 0 503 ignored false
before="$(origin_count /head-first)"
request head-hard-failed '/head-first?case=head'
expect_status head-hard-failed 503
test "$(cat "${workdir}/head-hard-failed.body")" != head-v1
test "$(header_value "${workdir}/head-hard-failed.headers" X-CDNCA-Cache-Reason)" = stale_hard_limit_reached
test "$(header_value "${workdir}/head-hard-failed.headers" X-CDNCA-Cache-State)" = expired
after="$(origin_count /head-first)"
test $((after - before)) -eq 1
test "${head_pending_after_hit}" -eq 0

# A cacheable response without a stable validator stays origin-only. It cannot
# create an unverifiable disk object that outlives the configured hard window.
control 0 200 no-validator-v1 false
before="$(origin_count /no-validator)"
request no-validator-fill '/no-validator?case=missing'
request no-validator-second '/no-validator?case=missing'
sleep 4.3
control 0 503 ignored false
request no-validator-failed '/no-validator?case=missing'
after="$(origin_count /no-validator)"
expect_status no-validator-fill 200
expect_status no-validator-second 200
expect_status no-validator-failed 503
test $((after - before)) -eq 3
test "$(cat "${workdir}/no-validator-failed.body")" != no-validator-v1
test "$(header_value "${workdir}/no-validator-second.headers" X-CDNCA-Cache-Reason)" = cache_private_bypass
test "$(header_value "${workdir}/no-validator-second.headers" X-CDNCA-Cache-State)" = expired
test "$(header_value "${workdir}/no-validator-failed.headers" X-CDNCA-Cache-Reason)" = origin_error
test "$(header_value "${workdir}/no-validator-failed.headers" X-CDNCA-Cache-State)" = expired

# Vary representations cannot share one freshness deadline. Enhancement mode
# keeps arbitrary Vary dimensions origin-only rather than guessing their keys.
control 0 200 vary-deadline false
before="$(origin_count /vary-language)"
request vary-hard-en-fill '/vary-language?case=hard' -H 'Accept-Language: en'
request vary-hard-en-second '/vary-language?case=hard' -H 'Accept-Language: en'
sleep 3.2
request vary-hard-zh-fill '/vary-language?case=hard' -H 'Accept-Language: zh-CN'
request vary-hard-zh-second '/vary-language?case=hard' -H 'Accept-Language: zh-CN'
sleep 1.2
control 0 503 ignored false
request vary-hard-failed '/vary-language?case=hard' -H 'Accept-Language: en'
after="$(origin_count /vary-language)"
expect_status vary-hard-en-fill 200
expect_status vary-hard-en-second 200
expect_status vary-hard-zh-fill 200
expect_status vary-hard-zh-second 200
expect_status vary-hard-failed 503
test $((after - before)) -eq 5
test "$(header_value "${workdir}/vary-hard-failed.headers" X-CDNCA-Cache-Reason)" = origin_error
test "$(header_value "${workdir}/vary-hard-failed.headers" X-CDNCA-Cache-State)" = expired

# Fresh hot hits do not create active markers or claim coalesced-follower status.
control 0 200 hot-v1
request hot-fill '/hot?case=marker'
before="$(origin_count /hot)"
pids=""
index=1
while [ "${index}" -le 20 ]; do
  request "hot-${index}" '/hot?case=marker' &
  pids="${pids} $!"
  index=$((index + 1))
done
for pid in ${pids}; do wait "${pid}"; done
after="$(origin_count /hot)"
test $((after - before)) -eq 0
index=1
while [ "${index}" -le 20 ]; do
  expect_status "hot-${index}" 200
  test "$(header_value "${workdir}/hot-${index}.headers" X-CDNCA-Cache-Reason)" = cache_fresh_hit
  test "$(header_value "${workdir}/hot-${index}.headers" X-CDNCA-Cache-State)" = fresh
  index=$((index + 1))
done

# A stale object is served immediately while exactly one background refresh wins.
control 0 200 stale-v1
request stale-fill '/stale?case=swr'
expect_status stale-fill 200
sleep 2
control 700 200 stale-v2
before="$(origin_count /stale)"
pids=""
index=1
while [ "${index}" -le 12 ]; do
  curl --silent --show-error --output "${workdir}/stale-${index}.body" --write-out '%{http_code}' \
    -H 'Host: cache.example.test' "${edge_url}/stale?case=swr" >"${workdir}/stale-${index}.status" &
  pids="${pids} $!"
  index=$((index + 1))
done
for pid in ${pids}; do wait "${pid}"; done
index=1
while [ "${index}" -le 12 ]; do
  test "$(cat "${workdir}/stale-${index}.status")" = 200
  test "$(cat "${workdir}/stale-${index}.body")" = stale-v1
  index=$((index + 1))
done
sleep 0.9
attempt=0
while [ "${attempt}" -lt 80 ]; do
  request stale-refreshed '/stale?case=swr'
  if [ "$(cat "${workdir}/stale-refreshed.body")" = stale-v2 ]; then break; fi
  attempt=$((attempt + 1))
  sleep 0.05
done
test "${attempt}" -lt 80
after="$(origin_count /stale)"
test $((after - before)) -eq 1

# A successful background refresh starts a new bounded stale window. The
# original fill deadline must not expire a newer object.
control 0 200 refresh-deadline-v1
request refresh-deadline-fill '/refresh-deadline?case=reset'
expect_status refresh-deadline-fill 200
sleep 1.5
control 0 200 refresh-deadline-v2
request refresh-deadline-stale '/refresh-deadline?case=reset'
expect_status refresh-deadline-stale 200
test "$(cat "${workdir}/refresh-deadline-stale.body")" = refresh-deadline-v1
attempt=0
while [ "${attempt}" -lt 40 ]; do
  request refresh-deadline-current '/refresh-deadline?case=reset'
  if [ "$(cat "${workdir}/refresh-deadline-current.body")" = refresh-deadline-v2 ]; then break; fi
  attempt=$((attempt + 1))
  sleep 0.05
done
test "${attempt}" -lt 40
sleep 2.8
control 0 503 ignored
before="$(origin_count /refresh-deadline)"
request refresh-deadline-failed '/refresh-deadline?case=reset'
expect_status refresh-deadline-failed 200
test "$(cat "${workdir}/refresh-deadline-failed.body")" = refresh-deadline-v2
test "$(header_value "${workdir}/refresh-deadline-failed.headers" X-CDNCA-Cache-Reason)" = stale_served_revalidate
test "$(header_value "${workdir}/refresh-deadline-failed.headers" X-CDNCA-Cache-State)" = stale
sleep 0.2
after="$(origin_count /refresh-deadline)"
test $((after - before)) -eq 1

# At the exact hard window, stale is bypassed; origin failure is returned instead of stale.
control 0 200 hard-v1
request hard-fill '/hard?case=bound'
sleep 4.1
control 0 503 ignored
before="$(origin_count /hard)"
request hard-failed '/hard?case=bound'
expect_status hard-failed 503
test "$(header_value "${workdir}/hard-failed.headers" X-CDNCA-Cache-Reason)" = stale_hard_limit_reached
test "$(header_value "${workdir}/hard-failed.headers" X-CDNCA-Cache-State)" = expired
after="$(origin_count /hard)"
test $((after - before)) -eq 1
control 0 200 hard-v2
before="$(origin_count /hard)"
request hard-recovered '/hard?case=bound'
expect_status hard-recovered 200
test "$(cat "${workdir}/hard-recovered.body")" = hard-v2
request hard-recovered-hit '/hard?case=bound'
expect_status hard-recovered-hit 200
test "$(cat "${workdir}/hard-recovered-hit.body")" = hard-v2
after="$(origin_count /hard)"
test $((after - before)) -eq 1
test "$(header_value "${workdir}/hard-recovered-hit.headers" X-CDNCA-Cache-Reason)" = cache_fresh_hit

# Missing metadata after the hard deadline rotates the object namespace, so stale disk bytes stay unreachable.
control 0 200 metadata-delete-v1
request metadata-delete-fill '/metadata-delete?case=evicted'
expect_status metadata-delete-fill 200
sleep 4.1
control 0 503 ignored
deleted_count="$(metadata_control delete)"
test "${deleted_count}" -ge 1
before="$(origin_count /metadata-delete)"
pids=""
index=1
while [ "${index}" -le 8 ]; do
  request "metadata-delete-${index}" '/metadata-delete?case=evicted' &
  pids="${pids} $!"
  index=$((index + 1))
done
for pid in ${pids}; do wait "${pid}"; done
after="$(origin_count /metadata-delete)"
test $((after - before)) -ge 1
test $((after - before)) -le 8
index=1
while [ "${index}" -le 8 ]; do
  expect_status "metadata-delete-${index}" 503
  test "$(cat "${workdir}/metadata-delete-${index}.body")" != metadata-delete-v1
  test "$(header_value "${workdir}/metadata-delete-${index}.headers" X-CDNCA-Cache-Reason)" != coalesced_follower
  index=$((index + 1))
done
control 0 200 metadata-delete-v2
before="$(origin_count /metadata-delete)"
request metadata-delete-recovered '/metadata-delete?case=evicted'
request metadata-delete-hit '/metadata-delete?case=evicted'
after="$(origin_count /metadata-delete)"
test $((after - before)) -eq 1
test "$(cat "${workdir}/metadata-delete-hit.body")" = metadata-delete-v2
test "$(header_value "${workdir}/metadata-delete-hit.headers" X-CDNCA-Cache-Reason)" = cache_fresh_hit

# Private and request-specific representations never enter stale or coalescing paths.
control 0 200 private
expect_uncached_twice /private
expect_uncached_twice /no-store
expect_uncached_twice /no-cache
expect_uncached_twice /cookie
expect_uncached_twice /vary-star
expect_uncached_twice /auth -H 'Authorization: Bearer redacted'
expect_uncached_twice /request-cookie -H 'Cookie: session=redacted'
expect_uncached_twice /range -H 'Range: bytes=0-2'
expect_uncached_twice /conditional -H 'If-None-Match: "fixture"'
control 0 404 not-cacheable
expect_uncached_twice /not-cacheable

# Origin responses cannot forge or duplicate internal cache reason/state headers.
control 0 200 spoofed false
request spoof-fill /spoof-internal-headers
expect_status spoof-fill 200
test "$(header_value "${workdir}/spoof-fill.headers" X-CDNCA-Cache-Reason)" = cache_miss
test "$(header_value "${workdir}/spoof-fill.headers" X-CDNCA-Cache-State)" = expired
test "$(header_count "${workdir}/spoof-fill.headers" X-CDNCA-Cache-Reason)" -eq 1
test "$(header_count "${workdir}/spoof-fill.headers" X-CDNCA-Cache-State)" -eq 1
request spoof-hit /spoof-internal-headers
test "$(header_value "${workdir}/spoof-hit.headers" X-CDNCA-Cache-Reason)" = cache_fresh_hit
test "$(header_value "${workdir}/spoof-hit.headers" X-CDNCA-Cache-State)" = fresh
test "$(header_count "${workdir}/spoof-hit.headers" X-CDNCA-Cache-Reason)" -eq 1
test "$(header_count "${workdir}/spoof-hit.headers" X-CDNCA-Cache-State)" -eq 1

# Enhancement mode keeps arbitrary Vary representations isolated by bypassing
# storage. Disabling the enhancement restores baseline native Vary caching.
control 0 200 vary-language
before="$(origin_count /vary-language)"
request vary-language-en-fill /vary-language -H 'Accept-Language: en'
request vary-language-zh-fill /vary-language -H 'Accept-Language: zh-CN'
request vary-language-en-second /vary-language -H 'Accept-Language: en'
request vary-language-zh-second /vary-language -H 'Accept-Language: zh-CN'
after="$(origin_count /vary-language)"
test $((after - before)) -eq 4
test "$(cat "${workdir}/vary-language-en-second.body")" = en
test "$(cat "${workdir}/vary-language-zh-second.body")" = zh-CN
test "$(header_value "${workdir}/vary-language-en-second.headers" X-CDNCA-Cache-Reason)" = cache_private_bypass
test "$(header_value "${workdir}/vary-language-zh-second.headers" X-CDNCA-Cache-Reason)" = cache_private_bypass

# A failed leader cannot leave followers permanently blocked; the next healthy burst converges again.
control 200 503 leader-failed
before="$(origin_count /leader-failure)"
pids=""
index=1
while [ "${index}" -le 3 ]; do
  request "leader-failed-${index}" '/leader-failure?case=recovery' &
  pids="${pids} $!"
  index=$((index + 1))
done
for pid in ${pids}; do wait "${pid}"; done
after="$(origin_count /leader-failure)"
test $((after - before)) -ge 1
test $((after - before)) -le 3
index=1
while [ "${index}" -le 3 ]; do
  expect_status "leader-failed-${index}" 503
  index=$((index + 1))
done
control 200 200 leader-recovered
before="$(origin_count /leader-failure)"
pids=""
index=1
while [ "${index}" -le 10 ]; do
  request "leader-recovered-${index}" '/leader-failure?case=recovery' &
  pids="${pids} $!"
  index=$((index + 1))
done
for pid in ${pids}; do wait "${pid}"; done
after="$(origin_count /leader-failure)"
test $((after - before)) -eq 1

# A timed-out follower may fall back to origin, but it does not populate over the leader.
control 1800 200 timeout-v1
before="$(origin_count /timeout)"
request timeout-leader '/timeout?case=lock' &
leader_pid=$!
sleep 0.1
request timeout-follower '/timeout?case=lock'
wait "${leader_pid}"
after="$(origin_count /timeout)"
test $((after - before)) -eq 2
test "$(header_value "${workdir}/timeout-follower.headers" X-CDNCA-Cache-Reason)" = coalesce_timeout_fallback

# Timeout fallback is still reported while the original leader remains active.
control 0 200 timeout-active false
before="$(origin_count /timeout-active)"
request timeout-active-leader '/timeout-active?case=lock' -H 'X-CDNCA-Fixture-Delay-Milliseconds: 3000' &
leader_pid=$!
sleep 0.1
request timeout-active-follower '/timeout-active?case=lock' -H 'X-CDNCA-Fixture-Delay-Milliseconds: 0'
expect_status timeout-active-follower 200
test "$(header_value "${workdir}/timeout-active-follower.headers" X-CDNCA-Cache-Reason)" = coalesce_timeout_fallback
wait "${leader_pid}"
after="$(origin_count /timeout-active)"
test $((after - before)) -eq 2

# A canceled client cannot strand the native cache lock; a waiter recovers.
control 700 200 cancel-v1
before="$(origin_count /cancel)"
curl --silent --show-error --max-time 0.1 -H 'Host: cache.example.test' "${edge_url}/cancel?case=cancel" >/dev/null 2>&1 &
cancel_pid=$!
sleep 0.05
request cancel-waiter '/cancel?case=cancel'
wait "${cancel_pid}" 2>/dev/null || true
expect_status cancel-waiter 200
test "$(cat "${workdir}/cancel-waiter.body")" = cancel-v1
after="$(origin_count /cancel)"
test $((after - before)) -ge 1
test $((after - before)) -le 2

# A HUP reload keeps the shared generation, so the same disk object stays reachable.
control 0 200 reload-v1
request reload-fill '/reload-generation?case=reload'
control 0 200 reload-v2
before="$(origin_count /reload-generation)"
docker kill --signal HUP "${edge_container}" >/dev/null
wait_edge
request reload-hit '/reload-generation?case=reload'
expect_status reload-hit 200
test "$(cat "${workdir}/reload-hit.body")" = reload-v1
after="$(origin_count /reload-generation)"
test $((after - before)) -eq 0

# A full restart rotates generation. Retained disk bytes are unreachable and the new cold burst still has one winner.
control 0 200 restart-v1
request restart-fill '/restart-generation?case=restart'
control 250 200 restart-v2
before="$(origin_count /restart-generation)"
docker restart "${edge_container}" >/dev/null
edge_published="$(docker port "${edge_container}" 18086/tcp | tail -n 1)"
metadata_published="$(docker port "${edge_container}" 18087/tcp | tail -n 1)"
edge_url="http://${edge_published}"
metadata_url="http://${metadata_published}"
wait_edge
pids=""
index=1
while [ "${index}" -le 10 ]; do
  request "restart-${index}" '/restart-generation?case=restart' &
  pids="${pids} $!"
  index=$((index + 1))
done
for pid in ${pids}; do wait "${pid}"; done
after="$(origin_count /restart-generation)"
test $((after - before)) -eq 1
index=1
restart_misses=0
while [ "${index}" -le 10 ]; do
  test -s "${workdir}/restart-${index}.headers"
  test -s "${workdir}/restart-${index}.body"
  expect_status "restart-${index}" 200
  test "$(cat "${workdir}/restart-${index}.body")" = restart-v2
  if [ "$(header_value "${workdir}/restart-${index}.headers" X-CDNCA-Cache-Status)" = MISS ]; then
    restart_misses=$((restart_misses + 1))
  fi
  index=$((index + 1))
done
test "${restart_misses}" -ge 1

# Invalid stored_at values fail closed without a Lua arithmetic error or stale fallback.
control 0 200 metadata-corrupt-v1
request metadata-corrupt-fill '/metadata-corrupt?case=invalid'
expect_status metadata-corrupt-fill 200
sleep 4.1
corrupt_count="$(metadata_control corrupt)"
test "${corrupt_count}" -ge 1
control 0 503 ignored
request metadata-corrupt-failed '/metadata-corrupt?case=invalid'
expect_status metadata-corrupt-failed 503
test "$(cat "${workdir}/metadata-corrupt-failed.body")" != metadata-corrupt-v1
test "$(header_value "${workdir}/metadata-corrupt-failed.headers" X-CDNCA-Cache-Reason)" = stale_hard_limit_reached
if grep -q 'attempt to perform arithmetic\|failed to run rewrite_by_lua' "${workdir}/state/error.log"; then
  echo 'invalid metadata caused a Lua runtime error' >&2
  exit 1
fi

assert_no_variable_hash_warning

printf 'CACHE_FRESHNESS_SMOKE={"openresty_version":"%s","lua_generation_harness":true,"stable_fresh_stale_expired_states":true,"head_first_fill_hard_bounded":true,"unverifiable_response_origin_only":true,"vary_response_origin_only":true,"unknown_host_origin_requests":0,"cold_burst_requests":20,"cold_origin_requests":1,"hot_burst_reason":"cache_fresh_hit","stale_burst_requests":12,"stale_refresh_origin_requests":1,"hard_expiry_fail_closed":true,"hard_expiry_recovery":true,"metadata_missing_disk_stale_unreachable":true,"metadata_invalid_fail_closed":true,"metadata_concurrent_follower_reason_safe":true,"private_bypass":true,"vary_isolation":true,"range_conditional_bypass":true,"leader_failure_recovery":true,"lock_timeout_bounded":true,"cancel_recovery":true,"reload_generation_preserved":true,"restart_generation_rotated":true,"restart_cold_origin_requests":1,"variables_hash_warning":false}\n' "${OPENRESTY_VERSION}"
