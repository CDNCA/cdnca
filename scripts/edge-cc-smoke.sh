#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-cc.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-cc\.//')"
container="cdnca-edge-cc-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-cc.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/policy" "${workdir}/runtime/logs"
chmod 0700 "${workdir}/policy"
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go build -trimpath -o "${workdir}/cc-policy" ./internal/cc/cmd/cc-policy
)

publish_policy() {
  publish_version="$1"
  publish_trusted="$2"
  publish_allowlist="$3"
  "${workdir}/cc-policy" -root "${workdir}/policy" <<EOF
{
  "schema_version": "cdnca.edge.cc/v1",
  "policy_version": ${publish_version},
  "trusted_proxies": ${publish_trusted},
  "allowlist": ${publish_allowlist},
  "rules": [
    {
      "rule_id": "fixed-window", "priority": 10, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"host": "edge.example.test", "port": 18082, "method": "GET", "path": {"kind": "exact", "value": "/fixed"}},
      "dimension": "client_ip", "limit": {"algorithm": "fixed_window", "requests": 2, "window_seconds": 2},
      "action": {"kind": "reject_429"}
    },
    {
      "rule_id": "concurrent", "priority": 20, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"method": "GET", "path": {"kind": "exact", "value": "/concurrent"}},
      "dimension": "client_ip", "limit": {"algorithm": "fixed_window", "requests": 8, "window_seconds": 60},
      "action": {"kind": "reject_429"}
    },
    {
      "rule_id": "path-isolation", "priority": 30, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"method": "GET", "path": {"kind": "prefix", "value": "/path/"}},
      "dimension": "path", "limit": {"algorithm": "fixed_window", "requests": 1, "window_seconds": 60},
      "action": {"kind": "reject_429"}
    },
    {
      "rule_id": "site-a-isolation", "priority": 40, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"method": "GET", "path": {"kind": "prefix", "value": "/site/"}},
      "dimension": "site", "limit": {"algorithm": "fixed_window", "requests": 1, "window_seconds": 60},
      "action": {"kind": "reject_429"}
    },
    {
      "rule_id": "site-b-isolation", "priority": 40, "tenant_id": "tenant-a", "site_id": "site-b",
      "match": {"method": "GET", "path": {"kind": "prefix", "value": "/site/"}},
      "dimension": "site", "limit": {"algorithm": "fixed_window", "requests": 1, "window_seconds": 60},
      "action": {"kind": "reject_429"}
    },
    {
      "rule_id": "leaky-bucket", "priority": 50, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"method": "GET", "path": {"kind": "exact", "value": "/leaky"}},
      "dimension": "client_ip", "limit": {"algorithm": "leaky_bucket", "rate_per_second": 1, "burst": 2},
      "action": {"kind": "reject_429"}
    },
    {
      "rule_id": "temporary-ban", "priority": 60, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"method": "GET", "path": {"kind": "exact", "value": "/ban"}},
      "dimension": "client_ip", "limit": {"algorithm": "fixed_window", "requests": 1, "window_seconds": 1},
      "action": {"kind": "temporary_ban", "ban_seconds": 2}
    },
    {
      "rule_id": "log-only", "priority": 70, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"method": "GET", "path": {"kind": "exact", "value": "/log"}},
      "dimension": "site", "limit": {"algorithm": "fixed_window", "requests": 1, "window_seconds": 60},
      "action": {"kind": "log"}
    },
    {
      "rule_id": "proxy-chain", "priority": 80, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"method": "GET", "path": {"kind": "exact", "value": "/proxy"}},
      "dimension": "client_ip", "limit": {"algorithm": "fixed_window", "requests": 1, "window_seconds": 60},
      "action": {"kind": "reject_429"}
    },
    {
      "rule_id": "allowlist", "priority": 90, "tenant_id": "tenant-a", "site_id": "site-a",
      "match": {"method": "GET", "path": {"kind": "exact", "value": "/allow"}},
      "dimension": "client_ip", "limit": {"algorithm": "fixed_window", "requests": 1, "window_seconds": 60},
      "action": {"kind": "reject_429"}
    }
  ]
}
EOF
}

publish_policy 1 '[]' '[]' >"${workdir}/publish-v1.log"
test -f "${workdir}/policy/fallback.json"

cat >"${workdir}/runtime/nginx.conf" <<'EOF'
worker_processes 2;
pid /tmp/cdnca-cc-nginx.pid;
error_log /runtime/logs/error.log notice;

events { worker_connections 1024; }

http {
    lua_package_path '/opt/cdnca-cc/?.lua;;';
    lua_shared_dict cdnca_cc_state 2m;
    lua_shared_dict smoke_metrics 1m;

    map $host $cc_site {
        default site-a;
        b.example.test site-b;
    }

    init_worker_by_lua_block {
        require("engine").init({
            policy_path = "/policy/current.json",
            state_dict = "cdnca_cc_state",
            reload_interval = 0.05,
        })
    }

    server {
        listen 18082;
        location / {
            access_by_lua_block {
                return require("engine").access({
                    tenant_id = "tenant-a", site_id = ngx.var.cc_site,
                    now_seconds = tonumber(ngx.var.arg_now),
                })
            }
            proxy_set_header Host $host;
            proxy_pass http://127.0.0.1:18083;
        }
    }

    server {
        listen 18083;
        location / {
            content_by_lua_block {
                local hits = ngx.shared.smoke_metrics:incr("origin_hits", 1, 0)
                ngx.say("origin:", hits)
            }
        }
    }

    server {
        listen 18084;
        location = /status {
            content_by_lua_block { ngx.say(require("engine").policy_version()) }
        }
        location = /hits {
            content_by_lua_block { ngx.say(ngx.shared.smoke_metrics:get("origin_hits") or 0) }
        }
        location = /remote {
            content_by_lua_block { ngx.say(ngx.var.remote_addr) }
        }
    }
}
EOF

docker run --detach \
  --name "${container}" \
  --publish 127.0.0.1::18082 \
  --publish 127.0.0.1::18084 \
  --volume "${repo_root}/edge/openresty/cc:/opt/cdnca-cc:ro" \
  --volume "${workdir}/policy:/policy:ro" \
  --volume "${workdir}/runtime:/runtime" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" \
  -p /runtime/ -c nginx.conf -g 'daemon off;' >/dev/null

edge_published="$(docker port "${container}" 18082/tcp | tail -n 1)"
admin_published="$(docker port "${container}" 18084/tcp | tail -n 1)"
case "${edge_published}:${admin_published}" in
  127.0.0.1:*:127.0.0.1:*) ;;
  *) echo "CC smoke ports were not bound to loopback: ${edge_published} ${admin_published}" >&2; exit 1 ;;
esac
edge_url="http://${edge_published}"
admin_url="http://${admin_published}"

wait_version() {
  wait_stage="$1"
  wait_expected="$2"
  wait_value=""
  wait_host_value=""
  wait_attempt=0
  while [ "${wait_attempt}" -lt 100 ]; do
    wait_value="$(docker exec "${container}" curl --noproxy '*' --silent --show-error \
      http://127.0.0.1:18084/status 2>/dev/null || true)"
    wait_host_value="$(curl --noproxy '*' --silent --show-error "${admin_url}/status" 2>/dev/null || true)"
    if [ "${wait_value}" = "${wait_expected}" ] && [ "${wait_host_value}" = "${wait_expected}" ]; then
      return 0
    fi
    if ! docker inspect --format '{{.State.Running}}' "${container}" 2>/dev/null | grep -Fx true >/dev/null; then
      docker logs "${container}" >&2 || true
      return 1
    fi
    wait_attempt=$((wait_attempt + 1))
    sleep 0.1
  done
  echo "${wait_stage}: policy version did not become ${wait_expected}; container=${wait_value:-unavailable} host=${wait_host_value:-unavailable}" >&2
  docker logs "${container}" >&2 || true
  docker exec "${container}" cat /runtime/logs/error.log >&2 || true
  return 1
}

request_code() {
  request_host="$1"
  request_path="$2"
  shift 2
  curl --silent --show-error --output "${workdir}/last.body" --write-out '%{http_code}' \
    -H "Host: ${request_host}" "$@" "${edge_url}${request_path}"
}

expect_code() {
  expect_status="$1"
  expect_host="$2"
  expect_path="$3"
  shift 3
  actual_status="$(request_code "${expect_host}" "${expect_path}" "$@")"
  if [ "${actual_status}" != "${expect_status}" ]; then
    echo "${expect_host}${expect_path}: status ${actual_status}, want ${expect_status}" >&2
    cat "${workdir}/last.body" >&2 || true
    exit 1
  fi
}

origin_hits() {
  curl --fail --silent --show-error "${admin_url}/hits"
}

assert_hit_delta() {
  hit_before="$1"
  hit_expected="$2"
  hit_after="$(origin_hits)"
  hit_actual=$((hit_after - hit_before))
  if [ "${hit_actual}" -ne "${hit_expected}" ]; then
    echo "origin hit delta ${hit_actual}, want ${hit_expected}" >&2
    exit 1
  fi
}

wait_version initial 1

# Exact host/port/method/path matching, fixed-window boundary, and backend protection.
before="$(origin_hits)"
expect_code 200 edge.example.test /fixed
expect_code 200 edge.example.test /fixed
curl --silent --show-error --dump-header "${workdir}/reject.headers" --output "${workdir}/reject.body" \
  -H 'Host: edge.example.test' --write-out '%{http_code}' "${edge_url}/fixed" >"${workdir}/reject.status"
test "$(cat "${workdir}/reject.status")" = 429
test "$(cat "${workdir}/reject.body")" = 'Too Many Requests'
grep -i '^Retry-After:' "${workdir}/reject.headers" >/dev/null
if grep -Ei 'rule|policy' "${workdir}/reject.headers" "${workdir}/reject.body" >/dev/null; then
  echo "429 response leaked internal policy details" >&2
  exit 1
fi
sleep 2.1
expect_code 200 edge.example.test /fixed
assert_hit_delta "${before}" 3

before="$(origin_hits)"
expect_code 200 edge.example.test /fixed -X POST
expect_code 200 edge.example.test /fixed/child
expect_code 200 other.example.test /fixed
assert_hit_delta "${before}" 3

# Atomic fixed-window concurrency: exactly eight requests reach the backend.
before="$(origin_hits)"
concurrent_index=1
concurrent_pids=""
while [ "${concurrent_index}" -le 20 ]; do
  curl --silent --show-error --output "${workdir}/concurrent-${concurrent_index}.body" --write-out '%{http_code}' \
    -H 'Host: edge.example.test' "${edge_url}/concurrent" >"${workdir}/concurrent-${concurrent_index}.status" &
  concurrent_pids="${concurrent_pids} $!"
  concurrent_index=$((concurrent_index + 1))
done
for concurrent_pid in ${concurrent_pids}; do
  wait "${concurrent_pid}"
done
concurrent_ok="$(awk '$0 == "200" { count++ } END { print count + 0 }' "${workdir}"/concurrent-*.status)"
concurrent_limited="$(awk '$0 == "429" { count++ } END { print count + 0 }' "${workdir}"/concurrent-*.status)"
test "${concurrent_ok}" -eq 8
test "${concurrent_limited}" -eq 12
assert_hit_delta "${before}" 8

# Path and site dimensions do not share state; tenant/site are in every key.
expect_code 200 edge.example.test /path/a
expect_code 429 edge.example.test /path/a
expect_code 200 edge.example.test /path/b
expect_code 200 edge.example.test /site/a
expect_code 429 edge.example.test /site/a
expect_code 200 b.example.test /site/a
expect_code 429 b.example.test /site/a

# Leaky bucket drains, log action never blocks, and temporary bans expire.
before="$(origin_hits)"
expect_code 200 edge.example.test '/leaky?now=1000'
expect_code 200 edge.example.test '/leaky?now=1000'
expect_code 429 edge.example.test '/leaky?now=1000'
expect_code 200 edge.example.test '/leaky?now=1001'
assert_hit_delta "${before}" 3

expect_code 200 edge.example.test /log
expect_code 200 edge.example.test /log
grep -F 'cc rate exceeded action=log rule_id=log-only' "${workdir}/runtime/logs/error.log" >/dev/null

before="$(origin_hits)"
expect_code 200 edge.example.test '/ban?now=1000.999'
expect_code 200 edge.example.test '/ban?now=1001.001'
assert_hit_delta "${before}" 2
expect_code 429 edge.example.test '/ban?now=1001.001'
expect_code 429 edge.example.test '/unmatched-during-ban?now=1001.001'
expect_code 200 b.example.test '/unmatched-during-ban?now=1001.001'
sleep 2.1
expect_code 200 edge.example.test '/ban?now=1003.101'
assert_hit_delta "${before}" 4

# XFF is ignored until the direct peer is explicitly trusted.
expect_code 200 edge.example.test /proxy -H 'X-Forwarded-For: 198.51.100.10'
expect_code 429 edge.example.test /proxy -H 'X-Forwarded-For: 198.51.100.11'

peer_address="$(curl --fail --silent --show-error "${admin_url}/remote")"
case "${peer_address}" in
  *[!0-9A-Fa-f:.]*|'') echo "invalid Docker peer address: ${peer_address}" >&2; exit 1 ;;
  *:*) peer_cidr="${peer_address}/128" ;;
  *) peer_cidr="${peer_address}/32" ;;
esac
trusted_json="[\"${peer_cidr}\",\"203.0.113.0/24\"]"
allowlist_json='["198.51.100.0/24","2001:db8::/32"]'
publish_policy 2 "${trusted_json}" "${allowlist_json}" >"${workdir}/publish-v2.log"
wait_version publish-v2 2

# The right-to-left trusted chain resolves to the first untrusted client.
expect_code 200 edge.example.test /proxy -H 'X-Forwarded-For: 192.0.2.10, 203.0.113.7'
expect_code 429 edge.example.test /proxy -H 'X-Forwarded-For: 192.0.2.10, 203.0.113.7'
expect_code 200 edge.example.test /proxy -H 'X-Forwarded-For: 192.0.2.11, 203.0.113.7'
expect_code 200 edge.example.test /proxy -H 'X-Forwarded-For: malformed'
expect_code 429 edge.example.test /proxy -H 'X-Forwarded-For: still-malformed'

# Both IPv4 and IPv6 allowlists bypass counters; a non-allowlisted IPv6 client does not.
expect_code 200 edge.example.test /allow -H 'X-Forwarded-For: 198.51.100.50, 203.0.113.7'
expect_code 200 edge.example.test /allow -H 'X-Forwarded-For: 198.51.100.50, 203.0.113.7'
expect_code 200 edge.example.test /allow -H 'X-Forwarded-For: 2001:db8::50, 203.0.113.7'
expect_code 200 edge.example.test /allow -H 'X-Forwarded-For: 2001:db8::50, 203.0.113.7'
expect_code 200 edge.example.test /allow -H 'X-Forwarded-For: 2001:db9::1, 203.0.113.7'
expect_code 429 edge.example.test /allow -H 'X-Forwarded-For: 2001:db9::1, 203.0.113.7'

# A malformed on-disk candidate is rejected by Lua while the in-memory LKG remains active.
printf '{broken\n' >"${workdir}/policy/current.bad"
chmod 0600 "${workdir}/policy/current.bad"
mv "${workdir}/policy/current.bad" "${workdir}/policy/current.json"
sleep 0.1
test "$(curl --fail --silent --show-error "${admin_url}/status")" = 2
grep -F 'cc policy reload rejected; retaining LKG' "${workdir}/runtime/logs/error.log" >/dev/null

# New workers and a full process restart recover the sealed fallback while current is invalid.
docker kill --signal HUP "${container}" >/dev/null
wait_version hup-fallback 1
expect_code 200 edge.example.test /fixed
docker restart "${container}" >/dev/null
wait_version restart-fallback 1
expect_code 200 edge.example.test /fixed

# An idempotent publish of the immutable latest version repairs current without weakening fallback.
publish_policy 2 "${trusted_json}" "${allowlist_json}" >"${workdir}/repair-v2.log"
wait_version repair-v2 2

# The Go publisher also rejects a bad higher version without replacing current.json.
cp "${workdir}/policy/current.json" "${workdir}/before-bad.json"
if "${workdir}/cc-policy" -root "${workdir}/policy" >"${workdir}/bad-publish.out" 2>"${workdir}/bad-publish.err" <<'EOF'
{"schema_version":"cdnca.edge.cc/v1","policy_version":3,"trusted_proxies":["bad-cidr"],"allowlist":[],"rules":[]}
EOF
then
  echo "invalid CC policy unexpectedly published" >&2
  exit 1
fi
cmp "${workdir}/before-bad.json" "${workdir}/policy/current.json"

# A valid version activates, and a real Nginx HUP reload keeps it available.
publish_policy 3 "${trusted_json}" "${allowlist_json}" >"${workdir}/publish-v3.log"
wait_version publish-v3 3
docker kill --signal HUP "${container}" >/dev/null
wait_version hup-v3 3
expect_code 200 edge.example.test /fixed -H 'X-Forwarded-For: 192.0.2.80, 203.0.113.7'

printf '%s\n' \
  "openresty_version=${OPENRESTY_VERSION}" \
  "image=${OPENRESTY_IMAGE}" \
  "policy_version=3" \
  "fixed_window_boundary=passed" \
  "concurrency=8_allowed_12_limited" \
  "dimension_isolation=client_ip_path_site" \
  "trusted_proxy=negative_and_chain_positive" \
  "allowlist=ipv4_ipv6" \
  "temporary_ban_expiry=passed" \
	"bad_policy_lkg=passed" \
	"durable_fallback=passed" \
	"hup_bad_current_fallback=passed" \
	"restart_bad_current_fallback=passed" \
	"nginx_reload=passed" \
  "backend_overlimit_hits=0"
