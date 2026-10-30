#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-error-page.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-error-page\.//')"
container="cdnca-error-page-${suffix}"
state="${workdir}/state"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-error-page.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go test -count=1 ./internal/errorpage \
    -run '^(TestCompileValidatesOwnerOnlyFileResources|TestCompileRejectsOversizedResource|TestCompileRejectsUnsafeStaticBodies)$'
) >"${workdir}/resource-safety.log"

mkdir -p "${state}/versions"
chmod 0700 "${state}" "${state}/versions"

compile_policy() {
  version="$1"
  revision="$2"
  variant="$3"
  output="$4"
  (
    cd "${repo_root}/agents/edge-agent"
    GOWORK=off go run ./internal/errorpage/cmd/errorpage-smoke-policy \
      -out "${output}" -version "${version}" -revision "${revision}" -variant "${variant}"
  )
}

compile_policy smoke-v1 1 v1 "${state}/versions/v1" >"${workdir}/v1.compile"
compile_policy smoke-v2 2 v2 "${state}/versions/v2" >"${workdir}/v2.compile"
ln -s versions/v1 "${state}/current"
ln -s versions/v1 "${state}/lkg"

cat >"${state}/nginx.conf" <<'NGINX'
worker_processes 2;
pid /tmp/cdnca-error-page/nginx.pid;
error_log /dev/stderr notice;

events { worker_connections 1024; }

http {
  access_log off;
  server_tokens off;
  lua_code_cache on;

  init_by_lua_block {
    local chunk = assert(loadfile("/state/current/policy.lua"))
    local policy = chunk()
    assert(type(policy) == "table" and type(policy.bindings) == "table" and type(policy.resources) == "table")
  }

  init_worker_by_lua_block {
    local chunk = assert(loadfile("/state/current/policy.lua"))
    cdnca_error_policy = chunk()
  }

  server {
    listen 18081;
    server_name origin.internal;
    location = /origin/403 { return 403; }
    location = /origin/404 { return 404; }
    location = /origin/500 { return 500; }
    location = /origin/502 { return 502; }
    location = /origin/503 { return 503; }
  }

  server {
    listen 18080 default_server;
    server_name _;
    error_page 400 = @cdnca_no_host;
    error_page 404 = @cdnca_unknown_site;

    location / {
      if ($http_host = "") { return 400; }
      return 404;
    }

    location @cdnca_no_host {
      internal;
      gzip off;
      set $cdnca_error_site "";
      set $cdnca_error_category no_host;
      set $cdnca_error_status 400;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
    location @cdnca_unknown_site {
      internal;
      gzip off;
      set $cdnca_error_site "";
      set $cdnca_error_category unknown_site;
      set $cdnca_error_status 404;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
  }

  server {
    listen 18080;
    server_name site.example;
    error_page 403 = @cdnca_edge_403;
    error_page 404 = @cdnca_edge_404;
    error_page 500 = @cdnca_edge_500;
    error_page 501 = @cdnca_edge_501;

    location = /healthz { return 204; }
    location = /edge/403 { return 403; }
    location = /edge/404 { return 404; }
    location = /edge/500 { return 500; }
    location = /edge/501 { return 501; }

    location /origin/ {
      proxy_intercept_errors on;
      proxy_next_upstream off;
      error_page 403 404 500 502 503 = @cdnca_origin_error;
      proxy_pass http://127.0.0.1:18081;
    }

    location = /connect/502 {
      proxy_intercept_errors on;
      proxy_next_upstream off;
      error_page 502 503 504 = @cdnca_connect_error;
      proxy_pass http://127.0.0.1:65534;
    }

    location @cdnca_origin_error {
      internal;
      gzip off;
      set $cdnca_error_site site-a;
      set $cdnca_error_category origin_response;
      set $cdnca_error_status $upstream_status;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
    location @cdnca_connect_error {
      internal;
      gzip off;
      set $cdnca_error_site site-a;
      set $cdnca_error_category edge_connect;
      set $cdnca_error_status $upstream_status;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
    location @cdnca_edge_403 {
      internal;
      gzip off;
      set $cdnca_error_site site-a;
      set $cdnca_error_category edge_route;
      set $cdnca_error_status 403;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
    location @cdnca_edge_404 {
      internal;
      gzip off;
      set $cdnca_error_site site-a;
      set $cdnca_error_category edge_route;
      set $cdnca_error_status 404;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
    location @cdnca_edge_500 {
      internal;
      gzip off;
      set $cdnca_error_site site-a;
      set $cdnca_error_category edge_route;
      set $cdnca_error_status 500;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
    location @cdnca_edge_501 {
      internal;
      gzip off;
      set $cdnca_error_site site-a;
      set $cdnca_error_category edge_route;
      set $cdnca_error_status 501;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
  }
}
NGINX

sed 's#/state/current/#/state/versions/v2/#g' "${state}/nginx.conf" >"${state}/nginx-v2.conf"
chmod 0444 "${state}/nginx.conf" "${state}/nginx-v2.conf"

docker run --detach \
  --name "${container}" \
  --publish 127.0.0.1::18080 \
  --volume "${state}:/state" \
  --volume "${repo_root}/edge/openresty/errorpage/handler.lua:/opt/cdnca/errorpage/handler.lua:ro" \
  --entrypoint /bin/sh \
  "${OPENRESTY_IMAGE}" \
  -c 'mkdir -p /tmp/cdnca-error-page && exec /usr/local/openresty/bin/openresty -p /tmp/cdnca-error-page/ -c /state/nginx.conf -g "daemon off;"' \
  >"${workdir}/container.id"

published="$(docker port "${container}" 18080/tcp | tail -n 1)"
case "${published}" in
  127.0.0.1:*) ;;
  *) echo "error-page runtime was not published to a random loopback port: ${published}" >&2; exit 1 ;;
esac
base_url="http://${published}"

ready=false
attempt=0
while [ "${attempt}" -lt 60 ]; do
  if curl --silent --fail --header 'Host: site.example' "${base_url}/healthz" >/dev/null 2>&1; then
    ready=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
if [ "${ready}" != true ]; then
  docker logs "${container}" >&2
  exit 1
fi

assert_response() {
  label="$1"
  path="$2"
  host="$3"
  expected_status="$4"
  expected_mime="$5"
  expected_text="$6"
  headers="${workdir}/${label}.headers"
  body="${workdir}/${label}.body"
  if [ "${host}" = "__empty__" ]; then
    actual_status="$(curl --silent --show-error --http1.0 --header 'Host:' --dump-header "${headers}" --output "${body}" --write-out '%{http_code}' "${base_url}${path}")"
  else
    actual_status="$(curl --silent --show-error --header "Host: ${host}" --dump-header "${headers}" --output "${body}" --write-out '%{http_code}' "${base_url}${path}")"
  fi
  tr -d '\r' <"${headers}" >"${headers}.clean"
  if [ "${actual_status}" != "${expected_status}" ]; then
    echo "${label}: expected status ${expected_status}, got ${actual_status}" >&2
    exit 1
  fi
  grep -i -F "Content-Type: ${expected_mime}" "${headers}.clean" >/dev/null
  grep -i -F 'Cache-Control: no-store, max-age=0' "${headers}.clean" >/dev/null
  grep -i -F 'Expires: 0' "${headers}.clean" >/dev/null
  grep -i -F "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox" "${headers}.clean" >/dev/null
  grep -i -F 'X-Content-Type-Options: nosniff' "${headers}.clean" >/dev/null
  if grep -i '^Content-Encoding:' "${headers}.clean" >/dev/null; then
    echo "${label}: custom error page was compressed" >&2
    exit 1
  fi
  actual_length="$(wc -c <"${body}" | tr -d ' ')"
  declared_length="$(awk 'BEGIN { IGNORECASE=1 } /^Content-Length:/ { gsub("\\r", ""); print $2 }' "${headers}" | tail -n 1)"
  if [ "${actual_length}" != "${declared_length}" ]; then
    echo "${label}: length ${actual_length} does not match ${declared_length}" >&2
    exit 1
  fi
  grep -F -- "${expected_text}" "${body}" >/dev/null
}

# The policy must preserve this literal Nginx-looking text.
# shellcheck disable=SC2016
assert_response origin403 /origin/403 site.example 403 'text/plain; charset=utf-8' '$request_uri <script>alert(1)</script> v1'
assert_response origin404 /origin/404 site.example 404 'text/html; charset=utf-8' 'origin missing v1'
assert_response origin500 /origin/500 site.example 500 'application/json' '"error":"origin_failure"'
assert_response origin502 /origin/502 site.example 502 'text/plain; charset=utf-8' 'origin returned 502 v1'
assert_response origin503 /origin/503 site.example 503 'text/plain; charset=utf-8' 'global origin fallback v1'
assert_response edge403 /edge/403 site.example 403 'text/plain; charset=utf-8' 'edge forbidden v1'
assert_response edge404 /edge/404 site.example 404 'text/html; charset=utf-8' 'edge missing v1'
assert_response edge500 /edge/500 site.example 500 'application/json' '"error":"edge_failure"'
assert_response connect502 /connect/502 site.example 502 'text/plain; charset=utf-8' 'edge connection failed v1'
assert_response nohost / __empty__ 400 'text/plain; charset=utf-8' 'host header required'
assert_response unknown / unknown.example 404 'application/json' '"error":"unknown_site"'
assert_response missing /edge/501 site.example 501 'text/plain; charset=utf-8' 'Service temporarily unavailable.'

head_headers="${workdir}/head.headers"
head_status="$(curl --silent --show-error --head --header 'Host: site.example' --dump-header "${head_headers}" --output /dev/null --write-out '%{http_code}' "${base_url}/origin/404")"
tr -d '\r' <"${head_headers}" >"${head_headers}.clean"
get_length="$(wc -c <"${workdir}/origin404.body" | tr -d ' ')"
head_length="$(awk 'BEGIN { IGNORECASE=1 } /^Content-Length:/ { gsub("\\r", ""); print $2 }' "${head_headers}" | tail -n 1)"
if [ "${head_status}" != 404 ] || [ "${head_length}" != "${get_length}" ]; then
  echo "HEAD semantics failed: status=${head_status} length=${head_length} expected=${get_length}" >&2
  exit 1
fi

compressed_headers="${workdir}/compressed.headers"
compressed_body="${workdir}/compressed.body"
curl --silent --show-error --header 'Host: site.example' --header 'Accept-Encoding: gzip' \
  --dump-header "${compressed_headers}" --output "${compressed_body}" "${base_url}/origin/404"
if grep -i '^Content-Encoding:' "${compressed_headers}" >/dev/null || ! cmp -s "${compressed_body}" "${workdir}/origin404.body"; then
  echo "custom error response compression semantics failed" >&2
  exit 1
fi

docker exec "${container}" /usr/local/openresty/bin/openresty \
  -p /tmp/cdnca-error-page/ -c /state/nginx-v2.conf -t >"${workdir}/v2.precheck" 2>&1

responses="${workdir}/concurrent.responses"
curl --silent --show-error --header 'Host: site.example' "${base_url}/edge/403" >"${responses}"
(
  index=0
  while [ "${index}" -lt 120 ]; do
    curl --silent --show-error --header 'Host: site.example' "${base_url}/edge/403"
    index=$((index + 1))
  done
) >>"${responses}" &
load_pid=$!
sleep 0.05
docker exec "${container}" /bin/sh -c \
  'ln -s versions/v2 /state/.current-next && mv -fT /state/.current-next /state/current'
docker exec "${container}" /usr/local/openresty/bin/openresty \
  -p /tmp/cdnca-error-page/ -c /state/nginx.conf -s reload >"${workdir}/reload.log" 2>&1
wait "${load_pid}"

if grep -v -E '^(edge forbidden v1|edge forbidden v2)$' "${responses}" >/dev/null; then
  echo "concurrent reload produced an invalid response" >&2
  exit 1
fi

ready_v2=false
attempt=0
last_v2_body=""
while [ "${attempt}" -lt 60 ]; do
  last_v2_body="$(curl --silent --show-error --header 'Host: site.example' "${base_url}/edge/403")"
  if [ "${last_v2_body}" = 'edge forbidden v2' ]; then
    ready_v2=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
if [ "${ready_v2}" != true ]; then
  echo "v2 did not become healthy after reload; body=${last_v2_body}" >&2
  docker exec "${container}" readlink /state/current >&2 || true
  docker logs "${container}" >&2 || true
  exit 1
fi
curl --silent --show-error --header 'Host: site.example' "${base_url}/edge/403" >>"${responses}"
if ! grep -F 'edge forbidden v1' "${responses}" >/dev/null || ! grep -F 'edge forbidden v2' "${responses}" >/dev/null; then
  echo "reload evidence is missing v1 or v2" >&2
  exit 1
fi
docker exec "${container}" /bin/sh -c \
  'ln -s versions/v2 /state/.lkg-next && mv -fT /state/.lkg-next /state/lkg'

if (
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go run ./internal/errorpage/cmd/errorpage-smoke-policy \
    -out "${state}/versions/bad" -version smoke-bad -revision 3 -variant bad -invalid-hash
) >"${workdir}/bad.compile" 2>&1; then
  echo "bad policy unexpectedly compiled" >&2
  exit 1
fi
if [ "$(docker exec "${container}" readlink /state/current)" != versions/v2 ] || \
   [ "$(docker exec "${container}" readlink /state/lkg)" != versions/v2 ]; then
  echo "bad policy changed current or LKG" >&2
  exit 1
fi
assert_response afterbad /edge/403 site.example 403 'text/plain; charset=utf-8' 'edge forbidden v2'

request_count="$(wc -l <"${responses}" | tr -d ' ')"
printf '%s\n' "EDGE_ERROR_PAGE_SMOKE_EVIDENCE={\"openresty\":true,\"statuses\":[403,404,500,502,503],\"origin_edge_distinct\":true,\"no_host\":true,\"unknown_site\":true,\"inheritance\":true,\"mime_html_text_json\":true,\"head_length\":true,\"uncompressed\":true,\"no_interpolation\":true,\"missing_fallback\":true,\"oversize_hash_permission_symlink_hardlink_rejected\":true,\"concurrent_requests\":${request_count},\"reload_v1_v2\":true,\"bad_policy_kept_lkg\":true}"
