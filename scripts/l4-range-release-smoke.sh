#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

range_guard="${repo_root}/edge/openresty/range/guard.lua"
dockerfile="${repo_root}/edge/openresty/Dockerfile"
config_source="${repo_root}/libs/edgeconfig/config.go"

test -s "${range_guard}"
rg -q --fixed-strings 'COPY --chmod=0444 edge/openresty/range/guard.lua /usr/local/share/cdnca/range/guard.lua' "${dockerfile}"
rg -q --fixed-strings 'require(\"range.guard\")' "${config_source}"
if rg -q --fixed-strings 'range-healthz' "${config_source}"; then
  echo 'Range integration must not add a second production health listener' >&2
  exit 1
fi

if command -v luac >/dev/null 2>&1; then
  luac -p "${range_guard}"
  printf 'lua_syntax=passed\n'
elif command -v lua >/dev/null 2>&1; then
  lua -e 'assert(loadfile(arg[1]))' "${range_guard}"
  printf 'lua_syntax=passed\n'
else
  printf 'lua_syntax=pending_no_interpreter\n'
fi

printf 'range_bundle_static=passed\n'
