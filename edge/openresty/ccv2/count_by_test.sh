#!/bin/sh
# CC v4 counting keys (count_by) on a real OpenResty: every key and the
# combinations count across the requests they group, over-limit actions
# (429, temporary ban of the client or of the counted bucket, challenge
# trigger) apply, a ja4 rule without a TLS fingerprint does not count, and a
# pre-v4 policy (dimension client_ip only) still runs unchanged.
#
# The policies are the shapes control and the agent compile
# (agents/edge-agent/internal/ccv2/testdata/count-by.*); client addresses are
# set with the realip module from X-Real-IP sent by the test client.
#
# Usage: edge/openresty/ccv2/count_by_test.sh
#        CC_ENGINE=<path to engine.lua> ...   (e.g. the pre-v4 engine)
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${CC_ENGINE:-${repo_root}/edge/openresty/ccv2/engine.lua}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-g1-ccdim-lua.XXXXXX")"
container="cdnca-g1-ccdim-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant="018f1000-0000-7000-8000-000000000001"
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
entry_id() { printf '%s\0%s\0%s\0%s\0%s' "${tenant}" "$1" localhost "$2" http | sha256sum | awk '{print substr($1,1,32)}'; }

# site <n> <port> <rules json>: one CC v2 policy, its registry entry and server.
registry=""
servers=""
site() {
  site_id="$(uuid "$1")"
  policy_id="$(uuid "$(( $1 + 100 ))")"
  binding_id="$(uuid "$(( $1 + 200 ))")"
  publication_id="$(uuid "$(( $1 + 300 ))")"
  mkdir -p "${workdir}/security/${site_id}"
  printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":%s}' \
    "${tenant}" "${site_id}" "${policy_id}" "${binding_id}" "${publication_id}" "$3" >"${workdir}/security/${site_id}/cc.compiled.json"
  sha="$(sha256sum "${workdir}/security/${site_id}/cc.compiled.json" | awk '{print $1}')"
  entry="$(entry_id "${site_id}" "$2")"
  item="{\"entry_id\":\"${entry}\",\"tenant_scope_id\":\"${tenant}\",\"site_id\":\"${site_id}\",\"hostname\":\"localhost\",\"listen_port\":$2,\"protocol\":\"http\",\"policy_id\":\"${policy_id}\",\"policy_version\":1,\"binding_id\":\"${binding_id}\",\"binding_revision\":1,\"publication_id\":\"${publication_id}\",\"source_sha256\":\"$(printf 'a%.0s' $(seq 64))\",\"compiled_path\":\"security/${site_id}/cc.compiled.json\",\"compiled_sha256\":\"${sha}\"}"
  registry="${registry:+${registry},}${item}"
  servers="${servers}
  server {
    listen $2;
    server_rewrite_by_lua_block { return require(\"cc\").access(\"${entry}\") }
    log_by_lua_block { require(\"cc\").log() }
    location / { return 200 'ok\n'; }
  }"
}
rule() { # n priority match count_by limit action
  printf '{"rule_id":"%s","priority":%s,"flow":"stop","match":%s,"dimension":"client_ip"%s,"limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "$3" "$4" "$5" "$6"
}
any='{"path":{"kind":"prefix","value":"/"}}'
fixed3='{"algorithm":"fixed_window","requests":3,"window_seconds":60}'
reject='{"kind":"reject_429"}'

# Registry entries must be ordered by port.
site 1 18101 "[$(rule 11 1 "${any}" ',"count_by":[{"key":"client_cidr","ipv4_prefix":24,"ipv6_prefix":64}]' "${fixed3}" "${reject}")]"
site 2 18102 "[$(rule 21 1 "${any}" ',"count_by":[{"key":"host"},{"key":"uri"}]' "${fixed3}" "${reject}")]"
site 3 18103 "[$(rule 31 1 "${any}" ',"count_by":[{"key":"uri_path"}]' "${fixed3}" "${reject}")]"
site 4 18104 "[$(rule 41 1 "${any}" ',"count_by":[{"key":"ja4"}]' "${fixed3}" '{"kind":"temporary_ban","ban_seconds":60,"target":"count_key"}')]"
site 5 18105 "[$(rule 51 1 "${any}" ',"count_by":[{"key":"client_ip"},{"key":"uri"}]' "${fixed3}" '{"kind":"temporary_ban","ban_seconds":60}')]"
site 6 18106 "[$(rule 61 1 "${any}" ',"count_by":[{"key":"client_cidr","ipv4_prefix":16,"ipv6_prefix":48}]' "${fixed3}" '{"kind":"challenge","ban_seconds":600,"challenge":{"mode":"js","failure_window_seconds":60,"max_failures":50,"pass_seconds":3600,"pow_bits":8,"challenge_seconds":120,"bind_ipv4_prefix":24,"bind_ipv6_prefix":64,"key_rotate_seconds":86400}}')]"
site 7 18107 "[$(rule 71 1 "${any}" '' "${fixed3}" "${reject}")]"
site 8 18108 "[$(rule 81 1 "${any}" ',"count_by":[{"key":"host"}]' '{"algorithm":"leaky_bucket","rate_per_second":1,"burst":2}' "${reject}")]"

cat >"${workdir}/nginx.conf" <<EOF
worker_processes 1;
error_log logs/error.log info;
pid nginx.pid;
events { worker_connections 64; }
http {
  lua_package_path '/usr/local/share/cdnca/security/?.lua;;';
  lua_shared_dict cdnca_cc_v2_state 4m;
  # Stands in for the native JA4 module's \$cdnca_ja4 (G2).
  map \$http_x_test_ja4 \$cdnca_ja4 { default \$http_x_test_ja4; }
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  # The registry is long for one inline Lua block; read it from a file.
  init_by_lua_block {
    local file = assert(io.open("/runtime/registry.json", "rb"))
    local registry = file:read("*a")
    file:close()
    require("cc").init({state_dict="cdnca_cc_v2_state", release_root="/runtime", registry_json=registry})
  }
  server {
    listen 18199;
    location = /metric {
      content_by_lua_block {
        local value = ngx.shared.cdnca_cc_v2_state:get(ngx.var.arg_key)
        ngx.print(tostring(value or 0))
      }
    }
    location = /snapshot {
      set \$cdnca_node_id 018f1000-0000-7000-8000-000000000999;
      content_by_lua_block {
        local snapshot, err = require("cc").metrics(ngx.var.arg_entry)
        if not snapshot then return ngx.exit(500) end
        ngx.print(require("cjson.safe").encode(snapshot))
      }
    }
  }
  ${servers}
}
EOF
printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"count-by","entries":[%s]}' "${registry}" >"${workdir}/registry.json"
mkdir -p "${workdir}/logs"

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS -o /dev/null http://127.0.0.1:18199/metric?key=x 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [ -z "${ready}" ]; then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc.lua did not start with count_by policies"
fi

ja4_metric="ccv2:metrics:${tenant}:$(uuid 4):$(uuid 104):v1:ja4_unavailable"
ja4_entry="$(entry_id "$(uuid 4)" 18104)"
if ! docker exec -i -e JA4_METRIC="${ja4_metric}" -e JA4_ENTRY="${ja4_entry}" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
# req <port> <ip> <path> [host] [ja4] -> status
req() {
  curl -sS -o /dev/null -w '%{http_code}' -H "X-Real-IP: $2" ${4:+-H "Host: $4"} ${5:+-H "X-Test-JA4: $5"} "http://127.0.0.1:$1$3"
}
expect() { # label want got
  test "$3" = "$2" || fail "$1: want $2, got $3"
}

# client_cidr /24: three addresses of one /24 share the counter, a fourth
# address there is over the limit, another /24 is not.
expect "cidr 1" 200 "$(req 18101 198.51.100.1 /)"
expect "cidr 2" 200 "$(req 18101 198.51.100.2 /)"
expect "cidr 3" 200 "$(req 18101 198.51.100.3 /)"
expect "cidr same /24 over limit" 429 "$(req 18101 198.51.100.77 /)"
expect "cidr other /24" 200 "$(req 18101 198.51.101.1 /)"
expect "cidr ipv6 /64 a" 200 "$(req 18101 2001:db8:1:1::1 /)"
expect "cidr ipv6 /64 b" 200 "$(req 18101 2001:db8:1:1::2 /)"
expect "cidr ipv6 /64 c" 200 "$(req 18101 2001:db8:1:1:ffff::3 /)"
expect "cidr ipv6 same /64 over limit" 429 "$(req 18101 2001:db8:1:1::4 /)"
expect "cidr ipv6 other /64" 200 "$(req 18101 2001:db8:1:2::1 /)"
echo "ok   client_cidr counts per /24 and /64"

# host + uri: different clients on the same host and URI (with query) add
# up; another query string or host is another bucket.
expect "host+uri 1" 200 "$(req 18102 192.0.2.1 '/a?x=1' a.test)"
expect "host+uri 2" 200 "$(req 18102 192.0.2.2 '/a?x=1' a.test)"
expect "host+uri 3" 200 "$(req 18102 192.0.2.3 '/a?x=1' a.test)"
expect "host+uri over limit" 429 "$(req 18102 192.0.2.4 '/a?x=1' a.test)"
expect "host+uri other query" 200 "$(req 18102 192.0.2.4 '/a?x=2' a.test)"
expect "host+uri other host" 200 "$(req 18102 192.0.2.4 '/a?x=1' b.test)"
echo "ok   host + uri combination"

# uri_path ignores the query string.
expect "uri_path 1" 200 "$(req 18103 192.0.2.1 '/p?q=1')"
expect "uri_path 2" 200 "$(req 18103 192.0.2.2 '/p?q=2')"
expect "uri_path 3" 200 "$(req 18103 192.0.2.3 '/p?q=3')"
expect "uri_path over limit" 429 "$(req 18103 192.0.2.4 '/p?q=4')"
expect "uri_path other path" 200 "$(req 18103 192.0.2.4 '/other')"
echo "ok   uri_path counts without the query"

# ja4 + ban of the counted bucket: one fingerprint from many addresses is
# banned as a whole; another fingerprint and requests without one pass and
# the latter are recorded as ja4_unavailable.
fp=t13d1516h2_8daaf6152771_02713d6af862
expect "ja4 1" 200 "$(req 18104 203.0.113.1 / '' "${fp}")"
expect "ja4 2" 200 "$(req 18104 203.0.113.2 / '' "${fp}")"
expect "ja4 3" 200 "$(req 18104 203.0.113.3 / '' "${fp}")"
expect "ja4 over limit" 429 "$(req 18104 203.0.113.4 / '' "${fp}")"
expect "ja4 bucket banned for a new address" 429 "$(req 18104 203.0.113.99 / '' "${fp}")"
expect "ja4 other fingerprint" 200 "$(req 18104 203.0.113.99 / '' t13d1516h2_8daaf6152771_ffffffffffff)"
for n in 1 2 3 4 5 6; do expect "no ja4 ${n}" 200 "$(req 18104 203.0.113.50 /)"; done
unavailable="$(curl -sS "http://127.0.0.1:18199/metric?key=${JA4_METRIC}")"
test "${unavailable}" -ge 6 || fail "ja4_unavailable metric = ${unavailable}"
# The cc-metrics/v1 snapshot carries the same counter.
snapshot="$(curl -fsS "http://127.0.0.1:18199/snapshot?entry=${JA4_ENTRY}")" || fail "cc-metrics snapshot unavailable"
echo "${snapshot}" | grep -F "\"ja4_unavailable\":${unavailable}" >/dev/null || fail "cc-metrics snapshot lacks ja4_unavailable=${unavailable}: ${snapshot}"
echo "ok   ja4 bans the fingerprint, no fingerprint is not counted (ja4_unavailable=${unavailable})"

# client_ip + uri, ban of the client: the ban follows the client to other
# URIs; another client on the same URI is unaffected.
expect "ip+uri 1" 200 "$(req 18105 192.0.2.10 /x)"
expect "ip+uri 2" 200 "$(req 18105 192.0.2.10 /x)"
expect "ip+uri 3" 200 "$(req 18105 192.0.2.10 /x)"
expect "ip+uri over limit" 429 "$(req 18105 192.0.2.10 /x)"
expect "ip+uri client banned elsewhere" 429 "$(req 18105 192.0.2.10 /y)"
expect "ip+uri other client" 200 "$(req 18105 192.0.2.11 /x)"
echo "ok   client_ip + uri with a client ban"

# challenge triggered by a /16: below the trigger requests pass, above it
# every address of that /16 gets the page; another /16 passes.
expect "challenge 1" 200 "$(req 18106 10.1.1.1 /)"
expect "challenge 2" 200 "$(req 18106 10.1.2.2 /)"
expect "challenge 3" 200 "$(req 18106 10.1.3.3 /)"
expect "challenge over trigger" 503 "$(req 18106 10.1.4.4 /)"
expect "challenge other /16" 200 "$(req 18106 10.2.1.1 /)"
echo "ok   challenge triggered by client_cidr"

# Pre-v4 policy: per client IP as before.
expect "legacy 1" 200 "$(req 18107 192.0.2.20 /)"
expect "legacy 2" 200 "$(req 18107 192.0.2.20 /)"
expect "legacy 3" 200 "$(req 18107 192.0.2.20 /)"
expect "legacy over limit" 429 "$(req 18107 192.0.2.20 /)"
expect "legacy other client" 200 "$(req 18107 192.0.2.21 /)"
echo "ok   policy without count_by counts per client IP"

# Leaky bucket by host: burst 2 shared across clients.
expect "leaky 1" 200 "$(req 18108 192.0.2.30 / l.test)"
expect "leaky 2" 200 "$(req 18108 192.0.2.31 / l.test)"
expect "leaky over burst" 429 "$(req 18108 192.0.2.32 / l.test)"
expect "leaky other host" 200 "$(req 18108 192.0.2.32 / m.test)"
echo "ok   leaky bucket by host"
INNER
then
  tail -n 40 "${workdir}/logs/error.log" >&2 2>/dev/null || true
  exit 1
fi
if grep -E '\[(error|crit|alert|emerg)\]' "${workdir}/logs/error.log" | grep -v 'cc v2 SEC-11' >&2; then
  fail "engine logged errors"
fi
echo "PASS ccv2 count_by"
