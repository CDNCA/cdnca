#!/usr/bin/env bash
# Verify that a primary HTTP 200 response with a bad digest falls back to the
# matching artifact/checksum pair instead of accepting or mixing origins.
set -Eeuo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly CONTROL_SCRIPT="${ROOT_DIR}/scripts/install-control.sh"

fail() { printf 'install-control-download-fallback: %s\n' "$*" >&2; exit 1; }
pass() { printf 'install-control-download-fallback: %s\n' "$*"; }

for command in cmp curl file python3 sha256sum; do
  command -v "$command" >/dev/null 2>&1 || fail "${command} is required"
done

readonly TEST_ROOT="$(mktemp -d -t cdnca-install-download-fallback.XXXXXX)"
server_pid=""
cleanup() {
  [ -z "$server_pid" ] || { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; }
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

fixture_dir="${TEST_ROOT}/fixture"
mkdir -p "$fixture_dir"
cp "$(type -P false)" "${fixture_dir}/primary-control-api"
cp "$(type -P true)" "${fixture_dir}/fallback-control-api"
printf '%s\n' 'wrong primary digest' >"${fixture_dir}/primary-body"
printf '%s  control-api\n' "$(sha256sum "${fixture_dir}/primary-body" | awk '{print $1}')" >"${fixture_dir}/primary-SHA256SUMS"
printf '%s  control-api\n' "$(sha256sum "${fixture_dir}/fallback-control-api" | awk '{print $1}')" >"${fixture_dir}/fallback-SHA256SUMS"

request_log="${TEST_ROOT}/requests.log"
port_file="${TEST_ROOT}/port"
python3 - "$fixture_dir" "$request_log" "$port_file" >"${TEST_ROOT}/server.log" 2>&1 <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

root, request_log, port_file = sys.argv[1:]
files = {
    "/primary/control-api": "primary-control-api",
    "/primary/SHA256SUMS": "primary-SHA256SUMS",
    "/fallback/control-api": "fallback-control-api",
    "/fallback/SHA256SUMS": "fallback-SHA256SUMS",
}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open(request_log, "a", encoding="utf-8") as log:
            log.write(self.path + "\n")
        name = files.get(self.path)
        if name is None:
            self.send_error(404)
            return
        body = Path(root, name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
Path(port_file).write_text(str(server.server_address[1]), encoding="ascii")
server.serve_forever()
PY
server_pid=$!

for _ in $(seq 1 100); do
  [ -s "$port_file" ] && break
  sleep 0.05
done
[ -s "$port_file" ] || fail 'fixture server did not publish a port'
port=$(<"$port_file")
[ "$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/primary/control-api")" = 200 ] ||
  fail 'primary fixture did not return HTTP 200'
: >"$request_log"

source_file="${TEST_ROOT}/install-control-functions.sh"
install_root="${TEST_ROOT}/install"
sed -e '/^main "\$@"/d' -e "s|^readonly INSTALL_ROOT=.*|readonly INSTALL_ROOT=\"${install_root}\"|" \
  "$CONTROL_SCRIPT" >"$source_file"
mkdir -p "$install_root"
(
  # shellcheck disable=SC1090
  source "$source_file"
  TEMP_DIR="${TEST_ROOT}/work"
  CONTROL_API_BINARY_URL="http://127.0.0.1:${port}/primary/control-api"
  CONTROL_API_BINARY_FALLBACK_URL="http://127.0.0.1:${port}/fallback/control-api"
  CONTROL_API_SHA256_URL="http://127.0.0.1:${port}/primary/SHA256SUMS"
  CONTROL_API_SHA256_FALLBACK_URL="http://127.0.0.1:${port}/fallback/SHA256SUMS"
  mkdir -p "$TEMP_DIR" "$INSTALL_ROOT"
  download_control_api
)

[ -x "${install_root}/control-api" ] || fail 'control-api was not installed'
cmp -s "${install_root}/control-api" "${fixture_dir}/fallback-control-api" ||
  fail 'installer did not install the verified fallback artifact'
for route in /primary/control-api /primary/SHA256SUMS /fallback/control-api /fallback/SHA256SUMS; do
  grep -Fxq -- "$route" "$request_log" || fail "installer did not request ${route}"
done

pass 'primary HTTP 200 digest mismatch retried the matching fallback artifact/checksum pair'
