# Shared helpers of the ADR 0009 §8.5 PoC scenarios (sourced, not executed).
#   DYNROUTE_POC_IMAGE  real OpenResty runtime (default cdnca-native-runtime:dynroute-poc,
#                       built by run.sh from edge/openresty/native/Dockerfile --target runtime)
# Every scenario starts exactly one container (--rm, --network none) and
# removes it on exit; nothing listens outside the container.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
poc_dir="${repo_root}/tests/dynroute-poc"
image="${DYNROUTE_POC_IMAGE:-cdnca-native-runtime:dynroute-poc}"
work="$(mktemp -d "${TMPDIR:-/tmp}/dynroute-poc.XXXXXX")"
container="dynroute-poc-$(basename "$0" .sh)-$$"
failures=0

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf "${work}"
}
trap cleanup EXIT INT TERM

docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing (run tests/dynroute-poc/run.sh build)" >&2; exit 69; }
arch="$(docker image inspect "${image}" --format '{{.Architecture}}')"

build_probe() {
  GOWORK=off GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go -C "${poc_dir}/probe" build -trimpath -o "${work}/probe" .
}

# start_container [extra docker run args...]: /poc is the work dir.
start_container() {
  chmod -R a+rwX "${work}"
  docker run -d --rm --name "${container}" --network none -v "${work}:/poc" "$@" \
    --entrypoint sh "${image}" -c 'sleep 3600' >/dev/null
}

in_c() { docker exec "${container}" sh -c "$1"; }
probe() { docker exec "${container}" /poc/probe "$@"; }
nginx_start() { in_c "mkdir -p /poc/$1/logs && openresty -p /poc/$1/ -c nginx.conf"; }
nginx_reload() { in_c "openresty -p /poc/$1/ -c nginx.conf -s reload"; sleep 1; }

check() { # name expected actual note
  if [ "$2" = "$3" ]; then
    printf 'PASS %s expected=%s actual=%s  %s\n' "$1" "$2" "$3" "$4"
  else
    printf 'FAIL %s expected=%s actual=%s  %s\n' "$1" "$2" "$3" "$4"
    failures=$((failures + 1))
  fi
}

# json_field LINE KEY: string/number value of a top-level key of one JSON line.
json_field() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\{0,1\}\([^\",}]*\).*/\1/p" | head -1; }

finish() {
  echo "RESULT $(basename "$0" .sh) failures=${failures}"
  [ "${failures}" -eq 0 ]
}
