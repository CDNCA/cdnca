#!/bin/sh
# Runs the OWASP CRS official regression tests (go-ftw + the tests/ directory
# of the pinned CRS source) against the node's own build: the pinned
# OpenResty image + edge/openresty/modsecurity (libmodsecurity, the
# ModSecurity-nginx module, the CRS rules). The WAF is configured the way CRS
# CI configures its modsec3-nginx target (tests/docker-compose.yml): paranoia
# 4, DetectionOnly, info error log, one worker, X-CRS-Test log marker.
#   CRS_GROUPS   space separated rule groups (default: 942 941 932 930 931 944)
#   GO_FTW       go-ftw binary (default ~/.cache/cdnca-modsecurity/ftw/go-ftw, v2.3.0)
#   CRS_OUT      directory for the per-group reports (default: mktemp)
# Body processors, limits and unicode mapping are the node's catalog defaults
# (waf_set:crs_settings: libmodsecurity modsecurity.conf-recommended, PCRE
# match limit 100000).
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
groups="${CRS_GROUPS:-942 941 932 930 931 944}"
ftw="${GO_FTW:-${HOME}/.cache/cdnca-modsecurity/ftw/go-ftw}"
[ -x "${ftw}" ] || { echo "go-ftw not found: ${ftw} (go install github.com/coreruleset/go-ftw/v2@v2.3.0)" >&2; exit 1; }
modsecurity="$(sh "${repo_root}/scripts/security/modsecurity-runtime.sh")"
cache="${MODSECURITY_CACHE:-${HOME}/.cache/cdnca-modsecurity}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-crs-regression.XXXXXX")"
out="${CRS_OUT:-${work}/out}"
container="cdnca-crs-regression-$(basename "${work}")"
port="${CRS_PORT:-18099}"
mkdir -p "${work}/conf" "${work}/logs" "${work}/crs" "${out}"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
# The engine extension carries no rule text: CRS comes from the pinned source
# (the same files the catalog's waf_set:crs_rules carries).
printf '%s  %s\n' a4bb3688ef6205b64471a9ccbf0d7b024eb8edf39b97c6f6c0006e7a948f8550 "${cache}/src/coreruleset-4.30.0-src.tar.gz" | shasum -a 256 -c - >/dev/null
tar -xzf "${cache}/src/coreruleset-4.30.0-src.tar.gz" -C "${work}/crs" coreruleset-4.30.0/tests coreruleset-4.30.0/rules
tests="${work}/crs/coreruleset-4.30.0/tests/regression"

cat >"${work}/conf/modsecurity.conf" <<'EOF'
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile /usr/local/openresty/modsecurity/unicode.mapping 20127
SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRequestBodyJsonDepthLimit 512
SecArgumentsLimit 1000
SecPcreMatchLimit 100000
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
SecAuditEngine Off
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"
SecDefaultAction "phase:5,log,auditlog,pass"
SecAction "id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4300"
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=4,setvar:tx.detection_paranoia_level=4"
SecAction "id:900300,phase:1,pass,t:none,nolog,setvar:tx.arg_length=400,setvar:tx.total_arg_length=6400,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535"
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" "id:1999999,phase:1,pass,t:none,log,msg:'%{MATCHED_VAR}'"
Include /crs-rules/*.conf
EOF
cat >"${work}/conf/nginx.conf" <<'EOF'
load_module /usr/local/openresty/modsecurity/modules/ngx_http_modsecurity_module.so;
worker_processes 1;
error_log /logs/error.log info;
pid /logs/nginx.pid;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path /tmp/body;
  server { listen 127.0.0.1:9001; location / { default_type text/plain; return 200 "ok\n"; } }
  server {
    listen 0.0.0.0:8080 default_server;
    server_name localhost;
    modsecurity on;
    modsecurity_rules_file /conf/modsecurity.conf;
    location / { proxy_pass http://127.0.0.1:9001; }
  }
}
EOF
chmod -R a+rwX "${work}"
docker rm -f "${container}" >/dev/null 2>&1 || true
docker run -d --name "${container}" -p "127.0.0.1:${port}:8080" -v "${work}/conf:/conf:ro" -v "${work}/logs:/logs" \
  -v "${modsecurity}:/usr/local/openresty/modsecurity:ro" -v "${work}/crs/coreruleset-4.30.0/rules:/crs-rules:ro" --entrypoint openresty "${OPENRESTY_IMAGE}" \
  -g 'daemon off;' -p /tmp/ -c /conf/nginx.conf >/dev/null
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:${port}/" && break; sleep 0.2; done
printf 'logfile: %s\ntestoverride:\n  input:\n    dest_addr: 127.0.0.1\n    port: %s\n' "${work}/logs/error.log" "${port}" >"${work}/.ftw.yaml"
: >"${out}/summary.txt"
for group in ${groups}; do
  dir="$(ls -d "${tests}/tests/REQUEST-${group}-"* | head -1)"
  "${ftw}" run --config "${work}/.ftw.yaml" -d "${dir}" --overrides "${tests}/nginx-overrides.yaml" \
    --show-failures-only --max-marker-retries 50 --read-timeout 20s >"${out}/REQUEST-${group}.txt" 2>&1 || true
  total="$(grep -o 'run [0-9]* total' "${out}/REQUEST-${group}.txt" | grep -o '[0-9]*' | head -1)"
  failed="$(grep -c 'failed in' "${out}/REQUEST-${group}.txt" || true)"
  printf 'REQUEST-%s total=%s passed=%s failed=%s\n' "${group}" "${total:-0}" "$(( ${total:-0} - failed ))" "${failed}" >>"${out}/summary.txt"
done
cat "${out}/summary.txt"
echo "reports: ${out}"
