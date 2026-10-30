#!/bin/sh
# PA-17 acceptance on real OpenResty: the control plane renders a theme's node
# default error pages, the edge agent's compiler accepts them (canonical
# <style>, declared classes only) and the handler serves them with the page's
# own style pinned by hash in an otherwise unchanged CSP. Switching the theme
# (a new policy + reload) changes the served page. Two tenants' nodes (PA-26)
# serve their own themes side by side.
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-theme-page.XXXXXX")"
chmod 0700 "${workdir}"
container="cdnca-theme-page-$(basename "${workdir}" | sed 's/^cdnca-theme-page\.//')"
state="${workdir}/state"

cleanup() {
  docker rm -f "${container}" "${container}-b" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-theme-page.*) chmod -R u+w "${workdir}" 2>/dev/null || true; rm -rf -- "${workdir}" ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

render_theme() { # render_theme <theme> <revision> <name>
  GOWORK=off go -C "${repo_root}/services/control-api" run ./internal/theme/cmd/theme-error-pages \
    -theme "$1" -out "${workdir}/pages-$3" >/dev/null
  GOWORK=off go -C "${repo_root}/agents/edge-agent" run ./internal/errorpage/cmd/errorpage-smoke-policy \
    -out "${state}/versions/$3" -version "theme-$3" -revision "$2" -theme-pages "${workdir}/pages-$3" >/dev/null
}

mkdir -p "${state}/versions"
render_theme official.slate 1 slate
render_theme default 2 default
ln -s versions/slate "${state}/current"

cat >"${state}/nginx.conf" <<'NGINX'
worker_processes 1;
pid /tmp/cdnca-theme-page/nginx.pid;
error_log /dev/stderr notice;
events { worker_connections 256; }
http {
  access_log off;
  server_tokens off;
  init_worker_by_lua_block {
    cdnca_error_policy = assert(loadfile("/state/current/policy.lua"))()
  }
  server {
    listen 18080 default_server;
    server_name _;
    error_page 400 = @no_host;
    error_page 404 = @unknown_site;
    location = /healthz { return 204; }
    location / {
      if ($http_host = "") { return 400; }
      return 404;
    }
    location @no_host {
      internal;
      set $cdnca_error_site "";
      set $cdnca_error_category no_host;
      set $cdnca_error_status 400;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
    location @unknown_site {
      internal;
      set $cdnca_error_site "";
      set $cdnca_error_category unknown_site;
      set $cdnca_error_status 404;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
  }
  server {
    listen 18080;
    server_name site.example;
    location = /connect/502 {
      proxy_intercept_errors on;
      proxy_next_upstream off;
      error_page 502 503 504 = @connect_error;
      proxy_pass http://127.0.0.1:65534;
    }
    location @connect_error {
      internal;
      set $cdnca_error_site site-a;
      set $cdnca_error_category edge_connect;
      set $cdnca_error_status $upstream_status;
      content_by_lua_file /opt/cdnca/errorpage/handler.lua;
    }
  }
}
NGINX

docker run --rm --detach --name "${container}" --publish 127.0.0.1::18080 \
  --volume "${state}:/state" \
  --volume "${repo_root}/edge/openresty/errorpage/handler.lua:/opt/cdnca/errorpage/handler.lua:ro" \
  --entrypoint /bin/sh "${OPENRESTY_IMAGE}" \
  -c 'mkdir -p /tmp/cdnca-theme-page && exec /usr/local/openresty/bin/openresty -p /tmp/cdnca-theme-page/ -c /state/nginx.conf -g "daemon off;"' >/dev/null
base_url="http://$(docker port "${container}" 18080/tcp | tail -n 1)"
attempt=0
until curl --silent --fail "${base_url}/healthz" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "${attempt}" -lt 60 ] || { docker logs "${container}" >&2; echo "openresty did not start" >&2; exit 1; }
  sleep 0.1
done

failures=0
check() { # check <label> <host|__empty__> <path> <status> <theme> <color>
  headers="${workdir}/$1.headers" body="${workdir}/$1.body"
  if [ "$2" = __empty__ ]; then
    status="$(curl --silent --http1.0 --header 'Host:' --dump-header "${headers}" --output "${body}" --write-out '%{http_code}' "${base_url}$3")"
  else
    status="$(curl --silent --header "Host: $2" --dump-header "${headers}" --output "${body}" --write-out '%{http_code}' "${base_url}$3")"
  fi
  perl -0ne 'print $1 if /<style>(.*?)<\/style>/s' "${body}" >"${workdir}/$1.style"
  hash="sha256-$(openssl dgst -sha256 -binary <"${workdir}/$1.style" | base64)"
  csp="$(tr -d '\r' <"${headers}" | sed -n 's/^[Cc]ontent-[Ss]ecurity-[Pp]olicy: //p')"
  want_csp="default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox; style-src '${hash}'"
  if [ "${status}" = "$4" ] && grep -F "$6" "${body}" >/dev/null && [ "${csp}" = "${want_csp}" ] &&
     tr -d '\r' <"${headers}" | grep -i '^content-type: text/html; charset=utf-8$' >/dev/null &&
     cmp -s "${workdir}/$1.style" "${workdir}/pages-$5/style.css" && ! grep -E 'url\(|@import|<script|<link|src=|href=' "${body}" >/dev/null; then
    echo "ok - $1 ($5): ${status}, themed body, CSP pins the page style"
  else
    echo "not ok - $1 ($5): status=${status} csp=${csp}" >&2
    failures=$((failures + 1))
  fi
}

check connect502 site.example /connect/502 502 slate '#0f766e'
check nohost __empty__ / 400 slate '#0f766e'
check unknown unknown.example / 404 slate '#0f766e'

# Switch theme: new policy revision, atomic current swap, reload.
docker exec "${container}" sh -c 'ln -s versions/default /state/.next && mv -fT /state/.next /state/current'
docker exec "${container}" /usr/local/openresty/bin/openresty -p /tmp/cdnca-theme-page/ -c /state/nginx.conf -s reload
# Reload is graceful: the old worker drains for a moment, so wait for five
# consecutive answers from the new policy.
attempt=0 streak=0
while [ "${streak}" -lt 5 ]; do
  if curl --silent --header 'Host: unknown.example' "${base_url}/" | grep -F '#2d8cf0' >/dev/null; then
    streak=$((streak + 1))
  else
    streak=0
  fi
  attempt=$((attempt + 1))
  [ "${attempt}" -lt 100 ] || { echo "not ok - theme switch did not take effect after reload" >&2; exit 1; }
  sleep 0.1
done
check connect502 site.example /connect/502 502 default '#2d8cf0'
check unknown unknown.example / 404 default '#2d8cf0'
if grep -F '#0f766e' "${workdir}/unknown.body" >/dev/null; then
  echo "not ok - the default theme page still carries the official theme's color" >&2
  failures=$((failures + 1))
fi

# PA-26 white-label: each tenant's node carries that tenant's snapshot, so
# two tenants' nodes serve different themes at the same time. The first node
# (tenant B, following the platform default) keeps its theme while a second
# node (tenant A, own theme slate) starts beside it.
state_b="${workdir}/state-b"
mkdir -p "${state_b}"
cp -R "${state}/versions" "${state_b}/versions"
ln -s versions/slate "${state_b}/current"
cp "${state}/nginx.conf" "${state_b}/nginx.conf"
docker run --rm --detach --name "${container}-b" --publish 127.0.0.1::18080 \
  --volume "${state_b}:/state" \
  --volume "${repo_root}/edge/openresty/errorpage/handler.lua:/opt/cdnca/errorpage/handler.lua:ro" \
  --entrypoint /bin/sh "${OPENRESTY_IMAGE}" \
  -c 'mkdir -p /tmp/cdnca-theme-page && exec /usr/local/openresty/bin/openresty -p /tmp/cdnca-theme-page/ -c /state/nginx.conf -g "daemon off;"' >/dev/null
tenant_a_url="http://$(docker port "${container}-b" 18080/tcp | tail -n 1)"
attempt=0
until curl --silent --fail "${tenant_a_url}/healthz" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "${attempt}" -lt 60 ] || { docker logs "${container}-b" >&2; echo "tenant A openresty did not start" >&2; exit 1; }
  sleep 0.1
done
tenant_b_url="${base_url}"
base_url="${tenant_a_url}"
check tenantA-unknown unknown.example / 404 slate '#0f766e'
check tenantA-connect502 site.example /connect/502 502 slate '#0f766e'
base_url="${tenant_b_url}"
check tenantB-unknown unknown.example / 404 default '#2d8cf0'
if grep -F '#2d8cf0' "${workdir}/tenantA-unknown.body" >/dev/null || grep -F '#0f766e' "${workdir}/tenantB-unknown.body" >/dev/null; then
  echo "not ok - tenant themes leaked across nodes" >&2
  failures=$((failures + 1))
fi

if [ "${failures}" -ne 0 ]; then
  echo "THEME_ERROR_PAGE_OPENRESTY FAIL (${failures})" >&2
  exit 1
fi
echo "THEME_ERROR_PAGE_OPENRESTY PASS"
