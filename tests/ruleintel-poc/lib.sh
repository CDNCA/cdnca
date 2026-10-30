# Shared helpers of the ADR 0011 RI-01 PoCs (sourced, not executed).
# Each PoC starts exactly one --rm --network none container of the real node
# runtime (OpenResty 1.31.1.1) with the ModSecurity engine extension mounted,
# and removes it on exit; nothing listens outside the container.
#   RULEINTEL_POC_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
#   MODSECURITY_RUNTIME  libmodsecurity 3.0.17 + ModSecurity-nginx 1.0.4
#                        (default: scripts/security/modsecurity-runtime.sh)
#   CRS_SOURCE           coreruleset-4.30.0 source tarball
# Heavy (container) runs go through the machine's queue:
#   sh tests/ruleintel-poc/<name>/run.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
poc_root="${repo_root}/tests/ruleintel-poc"
here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
image="${RULEINTEL_POC_IMAGE:-cdnca-native-runtime:edge-golden}"
work="$(mktemp -d "${TMPDIR:-/tmp}/ruleintel-poc.XXXXXX")"
container="ruleintel-poc-$(basename "${here}")-$$"
failures=0

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf "${work}"
}
trap cleanup EXIT INT TERM

docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
arch="$(docker image inspect "${image}" --format '{{.Architecture}}')"
runtime="${MODSECURITY_RUNTIME:-$(sh "${repo_root}/scripts/security/modsecurity-runtime.sh")}"
[ -f "${runtime}/modules/ngx_http_modsecurity_module.so" ] || { echo "BLOCKED: no ModSecurity runtime at ${runtime}" >&2; exit 69; }
crs_tar="${CRS_SOURCE:-${HOME}/.cache/cdnca-modsecurity/src/coreruleset-4.30.0-src.tar.gz}"

# probe: the ADR 0009 PoC HTTP client (raw HTTP/1.1, summaries)
build_probe() {
  GOWORK=off GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go -C "${repo_root}/tests/dynroute-poc/probe" build -trimpath -o "${work}/probe" .
}

extract_crs() {
  [ -f "${crs_tar}" ] || { echo "BLOCKED: no CRS source ${crs_tar}" >&2; exit 69; }
  mkdir -p "${work}/crs"
  tar xzf "${crs_tar}" -C "${work}/crs" --strip-components=1 coreruleset-4.30.0/rules
}

# start_container: /poc is the work dir (a copy of the PoC directory + generated files)
start_container() {
  cp -R "${here}/." "${work}/"
  chmod -R a+rwX "${work}"
  docker run -d --rm --init --name "${container}" --network none -v "${work}:/poc" \
    -v "${runtime}:/usr/local/openresty/modsecurity:ro" --entrypoint sh "${image}" -c 'sleep 3600' >/dev/null
}

in_c() { docker exec "${container}" sh -c "$1"; }
probe() { docker exec "${container}" /poc/probe "$@"; }
nginx_start() { in_c "mkdir -p /poc/logs && openresty -p /poc/ -c ${1:-nginx.conf}"; sleep 1; }
nginx_stop() { in_c "openresty -p /poc/ -c ${1:-nginx.conf} -s stop" || true; sleep 1; }

# status PORT PATH [probe args...] -> HTTP status of one raw request
status() {
  port="$1"; path="$2"; shift 2
  probe get -url "http://127.0.0.1:${port}${path}" -host a.test -raw "$@" 2>/dev/null | tail -1 | sed -n 's/.*"status":\([0-9]*\).*/\1/p'
}

check() { # name expected actual note
  if [ "$2" = "$3" ]; then
    printf 'PASS %s expected=%s actual=%s  %s\n' "$1" "$2" "$3" "$4"
  else
    printf 'FAIL %s expected=%s actual=%s  %s\n' "$1" "$2" "$3" "$4"
    failures=$((failures + 1))
  fi
}

finish() {
  echo "RESULT $(basename "${here}") failures=${failures}"
  [ "${failures}" -eq 0 ]
}
