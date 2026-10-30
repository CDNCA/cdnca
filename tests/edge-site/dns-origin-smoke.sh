#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
# shellcheck disable=SC1091
. "$repo_root/edge/openresty/runtime.env"
image=${CDNCA_SITE_DNS_SMOKE_IMAGE:-$OPENRESTY_IMAGE}
if ! docker image inspect "$image" >/dev/null 2>&1; then
	printf '%s\n' "--- BLOCKED: required OpenResty image is not available locally: $image" >&2
	exit 69
fi

tmp_base=${TMPDIR:-/tmp}
workdir=$(mktemp -d "$tmp_base/cdnca-site-dns.XXXXXX")
chmod 700 "$workdir"
suffix=$(basename "$workdir" | sed 's/^cdnca-site-dns\.//')
container="cdnca-site-dns-$suffix"

cleanup() {
	if [ "${CDNCA_SITE_DNS_SMOKE_DEBUG:-0}" = 1 ]; then
		docker logs "$container" >&2 2>/dev/null || true
		docker exec "$container" tail -n 120 /tmp/cdnca-site-dns/originroute-error.log >&2 2>/dev/null || true
	fi
	if [ "${CDNCA_SITE_DNS_SMOKE_PRESERVE:-0}" = 1 ]; then
		printf 'preserving DNS smoke container %s and workdir %s\n' "$container" "$workdir" >&2
		return
	fi
	docker rm -f "$container" >/dev/null 2>&1 || true
	case "$workdir" in
		"$tmp_base"/cdnca-site-dns.*)
			chmod -R u+w "$workdir" 2>/dev/null || true
			rm -rf -- "$workdir"
			;;
		*) printf '%s\n' "refusing to remove unexpected path: $workdir" >&2 ;;
	esac
}
trap cleanup EXIT HUP INT TERM

docker_arch=$(docker info --format '{{.Architecture}}')
case "$docker_arch" in
	arm64|aarch64) go_arch=arm64 ;;
	amd64|x86_64) go_arch=amd64 ;;
	*) printf 'unsupported Docker architecture: %s\n' "$docker_arch" >&2; exit 69 ;;
esac
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" go build -trimpath -ldflags '-s -w -buildid=' \
	-o "$workdir/dns-origin-fixture" \
	"$repo_root/tests/edge-site/dns-origin-fixture.go"

docker run --detach --name "$container" \
	--publish 127.0.0.1::18080/tcp \
	--publish 127.0.0.1::18090/tcp \
	"$image" sh -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null

docker exec "$container" mkdir -p \
	/tmp/cdnca-site-dns/originroute \
	/tmp/cdnca-site-dns/logs \
	/tmp/cdnca-site-dns/client-body \
	/tmp/cdnca-site-dns/proxy \
	/tmp/cdnca-site-dns/fastcgi \
	/tmp/cdnca-site-dns/uwsgi \
	/tmp/cdnca-site-dns/scgi
docker cp "$workdir/dns-origin-fixture" "$container:/tmp/cdnca-site-dns/dns-origin-fixture"
docker cp "$repo_root/edge/openresty/originroute/engine.lua" \
	"$container:/tmp/cdnca-site-dns/originroute/engine.lua"
docker exec "$container" chmod 755 /tmp/cdnca-site-dns/dns-origin-fixture

cat >"$workdir/policy.json" <<'EOF'
{"schema":"cdnca.edge.origin-route/v1","revision":1,"tenant_id":"tenant-site04","site_id":"site-site04","version_id":"site04-v1","node":{"id":"node-site04","region":"cn-east","tier":"l1"},"listeners":[{"id":"http","address":"0.0.0.0","port":18080}],"pools":[{"id":"domain","kind":"origin","algorithm":"round_robin","endpoints":[{"id":"domain-1","host":"origin.dynamic.test","port":18081,"weight":1}]},{"id":"ip","kind":"origin","algorithm":"round_robin","endpoints":[{"id":"ip-1","host":"127.0.0.2","port":18081,"weight":1}]},{"id":"mixed","kind":"origin","algorithm":"round_robin","endpoints":[{"id":"mixed-domain","host":"origin.dynamic.test","port":18081,"weight":1},{"id":"mixed-ip","host":"127.0.0.2","port":18081,"weight":1}]},{"id":"ip-hash","kind":"origin","algorithm":"ip_hash","endpoints":[{"id":"ip-hash-a","host":"127.0.0.2","port":18081,"weight":1},{"id":"ip-hash-b","host":"127.0.0.3","port":18081,"weight":1}]},{"id":"url-hash","kind":"origin","algorithm":"url_hash","endpoints":[{"id":"url-hash-a","host":"127.0.0.2","port":18081,"weight":1},{"id":"url-hash-b","host":"127.0.0.3","port":18081,"weight":1}]},{"id":"least-conn","kind":"origin","algorithm":"least_conn","endpoints":[{"id":"least-conn-a","host":"127.0.0.2","port":18081,"weight":1},{"id":"least-conn-b","host":"127.0.0.3","port":18081,"weight":1}]},{"id":"random","kind":"origin","algorithm":"random","endpoints":[{"id":"random-a","host":"127.0.0.2","port":18081,"weight":1},{"id":"random-b","host":"127.0.0.3","port":18081,"weight":1}]}],"default_pool_id":"mixed","routes":[{"id":"domain-route","priority":100,"path_prefix":"/domain","pool_id":"domain"},{"id":"mixed-route","priority":90,"path_prefix":"/mixed","pool_id":"mixed"},{"id":"ip-route","priority":80,"path_prefix":"/ip","pool_id":"ip"},{"id":"ip-hash-route","priority":70,"path_prefix":"/ip-hash","pool_id":"ip-hash"},{"id":"url-hash-route","priority":60,"path_prefix":"/url-hash","pool_id":"url-hash"},{"id":"least-conn-route","priority":50,"path_prefix":"/least-conn","pool_id":"least-conn"},{"id":"random-route","priority":40,"path_prefix":"/random","pool_id":"random"}],"retry":{"methods":["GET","HEAD"],"max_attempts":2,"connect_timeout_ms":100,"read_timeout_ms":500,"total_budget_ms":800},"l2":{"failure_threshold":1,"recovery_threshold":1,"probe_interval_ms":1000,"max_hops":1},"dns":{"resolver":"127.0.0.1","query_timeout_ms":1000,"min_ttl_seconds":1,"max_ttl_seconds":2,"stale_ttl_seconds":2}}
EOF

cat >"$workdir/nginx.conf" <<'EOF'
worker_processes 1;
error_log /tmp/cdnca-site-dns/originroute-error.log notice;
pid /tmp/cdnca-site-dns/originroute.pid;
events { worker_connections 4096; }
http {
  lua_package_path "/tmp/cdnca-site-dns/originroute/?.lua;;";
  lua_shared_dict cdnca_originroute_state 1m;
  lua_shared_dict cdnca_originroute_dns_state 8m;
  access_log off;
  init_by_lua_block {
    local ok, err = require("engine").init_file(ngx.config.prefix() .. "policy.json")
    if not ok then error(err) end
  }
  init_worker_by_lua_block {
    local ok, err = require("engine").start_dns()
    if not ok then error(err) end
  }
  upstream cdnca_originroute_dynamic {
    server 127.0.0.1:9;
    balancer_by_lua_block { require("engine").balance() }
  }
  server {
    listen 0.0.0.0:18080;
    server_name _;
    set $cdnca_origin_state_key "v1|tenant=tenant-site04|site=site-site04|version=site04-v1";
    set $cdnca_origin_bind "";
    set $cdnca_origin_route "";
    set $cdnca_origin_event "";
    set $cdnca_origin_hop "0";
    set $cdnca_origin_dns_state "";
    set $cdnca_origin_dns_reason "";
    location = /__cdnca_originroute_health {
      add_header X-CDNCA-Origin-Version site04-v1 always;
      content_by_lua_block { require("engine").health("site04-v1") }
    }
    location / {
      access_by_lua_block { require("engine").access("http") }
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_set_header X-CDNCA-Origin-Hop $cdnca_origin_hop;
      proxy_connect_timeout 100ms;
      proxy_read_timeout 500ms;
      proxy_next_upstream error timeout http_502 http_503 http_504;
      proxy_next_upstream_tries 2;
      proxy_next_upstream_timeout 800ms;
      proxy_pass http://cdnca_originroute_dynamic;
      log_by_lua_block { require("engine").log_result() }
    }
  }
}
EOF

docker cp "$workdir/policy.json" "$container:/tmp/cdnca-site-dns/policy.json"
docker cp "$workdir/nginx.conf" "$container:/tmp/cdnca-site-dns/nginx.conf"
docker exec -d "$container" /tmp/cdnca-site-dns/dns-origin-fixture \
	-dns-listen 127.0.0.1:53 -control-listen 0.0.0.0:18090 >/dev/null

control_port=$(docker port "$container" 18090/tcp | tail -n 1 | sed 's/.*://')
edge_port=$(docker port "$container" 18080/tcp | tail -n 1 | sed 's/.*://')
control_url="http://127.0.0.1:$control_port"
edge_url="http://127.0.0.1:$edge_port"

for _ in $(seq 1 50); do
	if curl --silent --show-error --fail "$control_url/health" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
curl --silent --show-error --fail "$control_url/health" >/dev/null

docker exec "$container" /usr/local/openresty/bin/openresty \
	-t -p /tmp/cdnca-site-dns/ -c nginx.conf
docker exec -d "$container" /usr/local/openresty/bin/openresty \
	-p /tmp/cdnca-site-dns/ -c nginx.conf -g 'daemon off;' >/dev/null

for _ in $(seq 1 80); do
	status=$(curl --silent --output "$workdir/health" --write-out '%{http_code}' "$edge_url/__cdnca_originroute_health" || true)
	if [ "$status" = 200 ] && grep -Eq '^ok:site04-v1:' "$workdir/health"; then break; fi
	sleep 0.1
done
status=$(curl --silent --output "$workdir/health" --write-out '%{http_code}' "$edge_url/__cdnca_originroute_health" || true)
if [ "$status" != 200 ] || ! grep -Eq '^ok:site04-v1:' "$workdir/health"; then
	cat "$workdir/health" >&2 2>/dev/null || true
	docker exec "$container" tail -n 80 /tmp/cdnca-site-dns/originroute-error.log >&2 || true
	exit 1
fi

request_body() {
	curl --silent --show-error --fail "$edge_url$1"
}

assert_origin() {
	path=$1
	body=$(request_body "$path")
	case "$body" in
		A|B) ;;
		*) printf 'unexpected origin for %s: %s\n' "$path" "$body" >&2; exit 1 ;;
	esac
}

initial_domain=$(request_body /domain)
[ "$initial_domain" = A ]
assert_origin /ip
assert_origin /mixed
assert_origin /ip-hash
url_hash_first=$(request_body /url-hash/stable)
url_hash_second=$(request_body /url-hash/stable)
[ "$url_hash_first" = "$url_hash_second" ]
assert_origin /least-conn
assert_origin /random

curl --silent --show-error --fail -X POST "$control_url/set-address?value=B" >/dev/null
domain_b=false
for _ in $(seq 1 50); do
	if [ "$(request_body /domain)" = B ]; then domain_b=true; break; fi
	sleep 0.2
done
[ "$domain_b" = true ]

curl --silent --show-error --fail -X POST "$control_url/set-failure?value=true" >/dev/null
dns_lkg=false
for _ in $(seq 1 10); do
	if [ "$(request_body /domain)" = B ]; then dns_lkg=true; break; fi
	sleep 0.2
done
[ "$dns_lkg" = true ]

sleep 3.5
stale_status=$(curl --silent --output "$workdir/stale" --write-out '%{http_code}' "$edge_url/domain" || true)
case "$stale_status" in
	50[234]) ;;
	*) printf 'DNS stale state did not fail closed: HTTP %s body=%s\n' "$stale_status" "$(cat "$workdir/stale")" >&2; exit 1 ;;
esac

curl --silent --show-error --fail -X POST "$control_url/set-failure?value=false" >/dev/null
curl --silent --show-error --fail -X POST "$control_url/set-address?value=A" >/dev/null
recovered=false
for _ in $(seq 1 50); do
	if [ "$(request_body /domain)" = A ]; then recovered=true; break; fi
	sleep 0.2
done
[ "$recovered" = true ]

printf '%s\n' 'SITE_04_DNS_SMOKE_EVIDENCE={"ip_origin":true,"mixed_origin":true,"five_algorithms":true,"domain_initial":"A","domain_re_resolved":"B","dns_lkg_during_failure":true,"dns_stale_expired_fail_closed":true,"dns_recovered":"A"}'
