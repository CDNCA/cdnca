#!/bin/sh
# Built-image half of tests/edge-openresty-runtime-parity.test.mjs: the node
# container image and the native runtime (edge/openresty/native/Dockerfile
# --target runtime) must carry the same OpenResty (nginx -V, every file under
# /usr/local/openresty) and the same CDNCA Lua files, and the container's
# bundled source verification must list every locked patch.
#   PARITY_IMAGE         container image (default: built with scripts/edge-runtime-build.sh)
#   PARITY_NATIVE_IMAGE  native runtime image (default: built here)
# Images this script builds are removed on exit.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-runtime-parity.XXXXXX")"
suffix="$(basename "${work}" | sed 's/^cdnca-runtime-parity\.//' | tr 'A-Z' 'a-z')"
built=""
cleanup() {
  for image in ${built}; do docker image rm -f "${image}" >/dev/null 2>&1 || true; done
  rm -rf -- "${work}"
}
trap cleanup EXIT INT TERM

image="${PARITY_IMAGE:-}"
if [ -z "${image}" ]; then
  image="cdnca/openresty-runtime:parity-${suffix}"; built="${built} ${image}"
  "${repo_root}/scripts/edge-runtime-build.sh" "${image}" >"${work}/image-build.log" 2>&1 || { cat "${work}/image-build.log" >&2; exit 1; }
fi
native="${PARITY_NATIVE_IMAGE:-}"
if [ -z "${native}" ]; then
  native="cdnca-native-runtime:parity-${suffix}"; built="${built} ${native}"
  docker build --pull=false --provenance=false --target runtime -f "${repo_root}/edge/openresty/native/Dockerfile" \
    -t "${native}" "${repo_root}" >"${work}/native-build.log" 2>&1 || { cat "${work}/native-build.log" >&2; exit 1; }
fi

# Same list for both images; the container adds only resty/ipmatcher.lua (see
# tests/edge-lua-inventory.test.mjs) and its source evidence under runtime/.
inventory='cd / && find usr/local/openresty usr/local/share/cdnca opt/cdnca/l4geo -type f ! -path usr/local/share/cdnca/runtime/\* ! -path usr/local/openresty/site/lualib/resty/ipmatcher.lua -exec sha256sum {} + | sort -k2'
for name in image native; do
  eval "ref=\${${name}}"
  docker run --rm --network none --entrypoint sh "${ref}" -c "${inventory}" >"${work}/${name}.files"
  docker run --rm --network none --entrypoint sh "${ref}" -c '/usr/local/openresty/bin/openresty -V 2>&1' >"${work}/${name}.version"
done

failures=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 $3"; else echo "FAIL $1 expected=$2 actual=$3"; failures=$((failures + 1)); fi; }
lock="${repo_root}/edge/openresty/native/sources.lock.json"
version="$(jq -r .source.version "${lock}")"
check nginx-version "nginx version: openresty/${version}" "$(head -1 "${work}/image.version")"
check nginx-V-identical "$(shasum -a 256 <"${work}/native.version" | cut -c1-64)" "$(shasum -a 256 <"${work}/image.version" | cut -c1-64)"
check ja4-module yes "$(grep -q -- '--add-module=/tmp/openresty-source/bundle/cdnca-ja4' "${work}/image.version" && echo yes || echo no)"
if diff "${work}/native.files" "${work}/image.files" >"${work}/files.diff"; then
  check runtime-and-lua-files "$(wc -l <"${work}/native.files" | tr -d ' ') identical" "$(wc -l <"${work}/image.files" | tr -d ' ') identical"
else
  check runtime-and-lua-files identical "differs:$(grep -c '^[<>]' "${work}/files.diff")"
  sed -n '1,40p' "${work}/files.diff"
fi
lua_count="$(grep -c -E ' (usr/local/share/cdnca|opt/cdnca/l4geo)/' "${work}/image.files" || true)"
lua_expected="$(node --input-type=module -e "import { luaSources } from '${repo_root}/scripts/native-node-runtime-acceptance.mjs'; console.log(Object.keys(luaSources).length)")"
check lua-file-count "${lua_expected}" "${lua_count}"
evidence="$(docker run --rm --network none --entrypoint cat "${image}" /usr/local/share/cdnca/runtime/source-verification.json)"
check source-patches "$(jq '.patches | length' "${lock}")" "$(printf '%s' "${evidence}" | jq .patches)"
check source-sha256 "$(jq -r .source.sha256 "${lock}")" "$(printf '%s' "${evidence}" | jq -r .source_sha256)"
check bundled-lock "$(shasum -a 256 <"${lock}" | cut -c1-64)" \
  "$(docker run --rm --network none --entrypoint cat "${image}" /usr/local/share/cdnca/runtime/sources.lock.json | shasum -a 256 | cut -c1-64)"
[ "${failures}" -eq 0 ] || { echo "runtime parity: ${failures} failure(s)" >&2; exit 1; }
echo "runtime parity: container ${image} == native ${native}"
