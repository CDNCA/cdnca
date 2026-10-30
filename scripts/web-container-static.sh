#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal Docker/Nginx variables.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="$ROOT_DIR/apps/web/Dockerfile"
NGINX_CONFIG="$ROOT_DIR/apps/web/nginx.conf"

checks=0
failures=0

record() {
  local label=$1
  shift
  checks=$((checks + 1))
  if "$@"; then
    printf 'ok - %s\n' "$label"
  else
    printf 'not ok - %s\n' "$label" >&2
    failures=$((failures + 1))
  fi
}

file_exists() {
  [[ -f "$1" ]]
}

contains() {
  grep -Fq -- "$2" "$1"
}

matches() {
  grep -Eq -- "$2" "$1"
}

not_matches() {
  ! grep -Eq -- "$2" "$1"
}

matches_once() {
  local count
  count=$(grep -Ec -- "$2" "$1" || true)
  [[ "$count" -eq 1 ]]
}

record 'Dockerfile exists' file_exists "$DOCKERFILE"
record 'nginx config exists' file_exists "$NGINX_CONFIG"

record 'Node build image is tag and digest pinned' contains "$DOCKERFILE" \
  'FROM public.ecr.aws/docker/library/node:22.19.0-alpine3.22@sha256:d2166de198f26e17e5a442f537754dd616ab069c47cc57b889310a717e0abbf9 AS build'
record 'Nginx runtime image is tag and digest pinned' contains "$DOCKERFILE" \
  'FROM public.ecr.aws/docker/library/nginx:1.29.1-alpine3.22@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8 AS runtime'
record 'pnpm version is exact' contains "$DOCKERFILE" 'corepack prepare pnpm@10.15.0 --activate'
record 'lockfile install is frozen and Web-filtered' contains "$DOCKERFILE" \
  'pnpm install --frozen-lockfile --filter @cdnca/web...'
record 'Turnstile site key is a required build argument' contains "$DOCKERFILE" 'ARG VITE_TURNSTILE_SITE_KEY'
record 'empty Turnstile site key fails before build' contains "$DOCKERFILE" 'test -n "$VITE_TURNSTILE_SITE_KEY"'
record 'Web package build is explicit' contains "$DOCKERFILE" 'pnpm --filter @cdnca/web build'
record 'Turnstile site key is not retained as runtime ENV' not_matches "$DOCKERFILE" \
  '^[[:space:]]*ENV[[:space:]]+VITE_TURNSTILE_SITE_KEY'
record 'no secret-like build arguments are declared' not_matches "$DOCKERFILE" \
  '^[[:space:]]*ARG[[:space:]]+[^#]*(SECRET|PASSWORD|PRIVATE_KEY|ACCESS_TOKEN)'
record 'built Web assets are copied with runtime ownership' contains "$DOCKERFILE" \
  'COPY --from=build --chown=65532:65532 /src/apps/web/dist /usr/share/nginx/html'
record 'runtime uses Helm-compatible non-root identity' contains "$DOCKERFILE" 'USER 65532:65532'
record 'runtime exposes only port 8080' contains "$DOCKERFILE" 'EXPOSE 8080'
record 'runtime bypasses the mutable upstream entrypoint' contains "$DOCKERFILE" \
  'ENTRYPOINT ["nginx", "-g", "daemon off;"]'
record 'runtime does not invoke docker-entrypoint' not_matches "$DOCKERFILE" 'docker-entrypoint'

record 'Nginx listens on IPv4 port 8080' contains "$NGINX_CONFIG" 'listen 8080 default_server;'
record 'Nginx listens on IPv6 port 8080' contains "$NGINX_CONFIG" 'listen [::]:8080 default_server;'
record 'pid is written to Helm writable run volume' contains "$NGINX_CONFIG" 'pid /var/run/nginx.pid;'
record 'client temp data uses Helm writable cache volume' contains "$NGINX_CONFIG" \
  'client_body_temp_path /var/cache/nginx/client_temp;'
record 'proxy temp data uses Helm writable cache volume' contains "$NGINX_CONFIG" \
  'proxy_temp_path /var/cache/nginx/proxy_temp;'
record 'static document root is explicit' contains "$NGINX_CONFIG" 'root /usr/share/nginx/html;'
record 'SPA fallback is enabled' contains "$NGINX_CONFIG" 'try_files $uri $uri/ /index.html;'
record 'missing assets do not fall back to the SPA' contains "$NGINX_CONFIG" 'try_files $uri =404;'
record 'index and non-hashed routes are no-store' contains "$NGINX_CONFIG" 'default "no-store";'
record 'hashed assets receive immutable caching' contains "$NGINX_CONFIG" \
  '"public, max-age=31536000, immutable";'
record 'hashed asset regex is a single quoted Nginx map key' contains "$NGINX_CONFIG" \
  '"~^/(?:dashboard/)?assets/[^/]+-[-_A-Za-z0-9]{8,}\.[^/]+$"'
record 'cache policy is emitted on every response' contains "$NGINX_CONFIG" \
  'add_header Cache-Control $cache_control always;'
record 'server version is hidden' contains "$NGINX_CONFIG" 'server_tokens off;'
record 'content sniffing is disabled' contains "$NGINX_CONFIG" \
  'add_header X-Content-Type-Options "nosniff" always;'
record 'framing is denied' contains "$NGINX_CONFIG" 'add_header X-Frame-Options "DENY" always;'
record 'referrer policy is strict' contains "$NGINX_CONFIG" \
  'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
record 'permissions policy disables unused sensors' contains "$NGINX_CONFIG" \
  'add_header Permissions-Policy "camera=(), geolocation=(), microphone=(), payment=(), usb=()" always;'
record 'CSP is emitted on every response' matches_once "$NGINX_CONFIG" \
  '^[[:space:]]*add_header Content-Security-Policy "[^"]+" always;$'
record 'CSP defaults to self' contains "$NGINX_CONFIG" "default-src 'self'"
# Scripts are trusted by a per-request nonce, never by 'unsafe-inline' (FX55/NF26).
record 'CSP script trust is a per-request nonce with strict-dynamic' contains "$NGINX_CONFIG" \
  "script-src 'self' 'nonce-\$request_id' 'strict-dynamic' \$csp_hosts_script;"
record 'CSP never allows inline script by unsafe-inline' not_matches "$NGINX_CONFIG" \
  "script-src[^;]*'unsafe-inline'"
record 'index.html script tags carry the nonce' contains "$NGINX_CONFIG" \
  "sub_filter '<script ' '<script nonce=\"\$request_id\" ';"
record 'nonce is stamped on every script tag' contains "$NGINX_CONFIG" 'sub_filter_once off;'
record 'nonce rewriting stays limited to HTML (sub_filter default types)' not_matches "$NGINX_CONFIG" 'sub_filter_types'
# Exact CAPTCHA host sets (Turnstile, Tencent CAPTCHA, GeeTest v4 incl. its fallback hosts).
record 'CSP script hosts are exactly the CAPTCHA providers' contains "$NGINX_CONFIG" \
  'default "https://challenges.cloudflare.com https://turing.captcha.qcloud.com https://captcha.gtimg.com https://static.geetest.com https://static.geevisit.com https://gcaptcha4.geetest.com https://gcaptcha4.geevisit.com https://gcaptcha4.gsensebot.com";'
record 'CSP frame hosts are Turnstile and Tencent CAPTCHA' contains "$NGINX_CONFIG" \
  'default "https://challenges.cloudflare.com https://turing.captcha.qcloud.com";'
record 'CSP connect hosts are the CAPTCHA verification APIs' contains "$NGINX_CONFIG" \
  'default "https://challenges.cloudflare.com https://turing.captcha.qcloud.com https://gcaptcha4.geetest.com https://gcaptcha4.geevisit.com https://gcaptcha4.gsensebot.com";'
record 'CSP image hosts are the CAPTCHA image hosts' contains "$NGINX_CONFIG" \
  'default "https://turing.captcha.qcloud.com https://captcha.gtimg.com https://static.geetest.com https://static.geevisit.com";'
record 'CSP directives use the pinned host sets' contains "$NGINX_CONFIG" \
  "img-src 'self' data: blob: \$csp_hosts_img \$global_js_hosts; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-\$request_id' 'strict-dynamic' \$csp_hosts_script; frame-src \$csp_hosts_frame \$plugin_ui_origins; connect-src 'self' \$csp_hosts_connect \$global_js_hosts"
record 'CSP has no wildcard source' not_matches "$NGINX_CONFIG" \
  'Content-Security-Policy[^;]*\*|[[:space:]]\*[[:space:];]'
record 'CSP does not enable unsafe eval' not_matches "$NGINX_CONFIG" "'unsafe-eval'"
record 'access logs omit query strings, cookies, authorization, and referrers' not_matches "$NGINX_CONFIG" \
  '\$(request|request_uri|args|http_cookie|http_authorization|http_referer)([^A-Za-z0-9_]|$)'
record 'runtime has the expected Control API reverse proxy' matches_once "$NGINX_CONFIG" \
  '^[[:space:]]*proxy_pass[[:space:]]+http://control-api:8080;[[:space:]]*$'
record 'runtime proxies only to Control API (API and the CSP host lookup)' matches_once "$NGINX_CONFIG" \
  '^[[:space:]]*proxy_pass[[:space:]]+http://control-api:8080/v1/system-settings/csp-hosts;[[:space:]]*$'
record 'runtime has exactly two reverse proxy directives' bash -c '[[ $(grep -Ec "proxy_pass[[:space:]]" "$1") -eq 2 ]]' _ "$NGINX_CONFIG"
# 全站JS report hosts (system settings) reach only connect-src/img-src, only as https://host lists.
record 'report hosts are read only for the SPA document' contains "$NGINX_CONFIG" 'auth_request /_cdnca/global-js-hosts;'
record 'report host lookup is internal-only' contains "$NGINX_CONFIG" \
  "$(printf 'location = /_cdnca/global-js-hosts {\n            internal;')"
record 'report host lookup is not reachable from outside' contains "$NGINX_CONFIG" \
  "$(printf 'location = /v1/system-settings/csp-hosts {\n            return 404;')"
record 'report hosts must be plain https host sources' contains "$NGINX_CONFIG" \
  '"~^(?<hosts>(?:https://[a-z0-9.-]{1,253})(?: https://[a-z0-9.-]{1,253}){0,19})$" $hosts;'
record 'report hosts are never added to script-src or frame-src' not_matches "$NGINX_CONFIG" \
  '(script-src|frame-src)[^;]*global_js_hosts'
record 'a failed report host lookup serves the strict policy' contains "$NGINX_CONFIG" 'error_page 500 502 503 504 = @spa_strict;'
# PA-19 ui_page plugin origins (enabled plugins only) reach frame-src only, only as https://host lists.
record 'plugin page origins come from the same internal lookup' contains "$NGINX_CONFIG" \
  'auth_request_set $plugin_ui_origins_raw $upstream_http_x_cdnca_plugin_ui_origins;'
record 'plugin page origins must be plain https host sources' contains "$NGINX_CONFIG" \
  '"~^(?<origins>(?:https://[a-z0-9.-]{1,253})(?: https://[a-z0-9.-]{1,253}){0,63})$" $origins;'
record 'plugin page origins are never added to script-src, connect-src or img-src' not_matches "$NGINX_CONFIG" \
  '(script-src|connect-src|img-src|default-src)[^;]*plugin_ui_origins'

if ((failures > 0)); then
  printf 'WEB_CONTAINER_STATIC FAIL (%d/%d assertions failed)\n' "$failures" "$checks" >&2
  exit 1
fi

printf 'WEB_CONTAINER_STATIC PASS (%d assertions)\n' "$checks"
