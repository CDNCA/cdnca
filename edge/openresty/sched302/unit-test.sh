#!/usr/bin/env bash
# Lua unit tests of cdnca_sched302 against the Go reference
# (libs/edgeconfig/sched302): the landing signature vector and 5000 candidate
# choices, inside the node runtime image's OpenResty (the module needs ngx
# and resty.sha256). Usage: edge/openresty/sched302/unit-test.sh [image]
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../.." && pwd)"
image="${1:-cdnca-native-runtime:edge-golden}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
chmod 755 "${work}"
SCHED302_LUA_VECTORS="${work}/vectors.json" go -C "${repo}/libs/edgeconfig" test ./sched302/ -run TestWriteSched302LuaVectors -count=1 >/dev/null
cat >"${work}/nginx.conf" <<'EOF'
daemon off; master_process off; error_log /dev/stderr warn; pid /tmp/sched302-unit.pid;
events {}
http {
  access_log off;
  lua_package_path "/t/?.lua;;";
  init_worker_by_lua_block {
    ngx.timer.at(0, function()
      rawset(_G, "arg", { [0] = "/t/unit_test.lua", "/v/vectors.json" })
      local exit = os.exit
      os.exit = function(code) io.stderr:write("EXIT ", tostring(code), "\n"); exit(code or 0) end
      rawset(_G, "print", function(...) io.stderr:write(table.concat({ ... }, " "), "\n") end)
      local ok, err = pcall(dofile, "/t/unit_test.lua")
      if not ok then io.stderr:write("ERROR ", tostring(err), "\n"); exit(1) end
      exit(0)
    end)
  }
}
EOF
output="$(docker run --rm --network none -v "${repo}/edge/openresty/sched302:/t:ro" -v "${work}:/v:ro" \
  --entrypoint sh "${image}" -c 'mkdir -p /tmp/logs; timeout 120 /usr/local/openresty/bin/openresty -p /tmp -c /v/nginx.conf 2>&1' || true)"
printf '%s\n' "${output}" | grep -E '^(PASS|FAIL|ERROR|EXIT|  mismatch|all passed|[0-9]+ failed)'
printf '%s\n' "${output}" | grep -q '^all passed$'
