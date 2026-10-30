#!/bin/sh
# HTTP policy header variables, allow_duplicate and rule
# conditions (edge/openresty/httppolicy/engine.lua) on the node runtime
# image, one --rm --network none container. policy.json is first checked by
# the agent compiler (canonical form the node receives).
#   CDNCA_HP_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_HP_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
work=$(mktemp -d /tmp/cdnca-hp.XXXXXX)
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/lua/httppolicy"
cp "${repo_root}/edge/openresty/httppolicy/engine.lua" "${work}/lua/httppolicy/engine.lua"
cp "${here}/nginx.conf" "${here}/check.sh" "${work}/"
# the node's object bytes: the agent compiler's canonical site entry
HTTPPOLICY_EXTRAS_OUT="${work}/policy.json" go -C "${repo_root}/agents/edge-agent" test -count=1 \
	-run TestCompileHeaderVariablesAndConditions ./internal/httppolicy/ >/dev/null
chmod -R a+rX "${work}"
docker run --rm --network none -v "${work}:/hp:ro" --entrypoint /bin/sh "${image}" /hp/check.sh
