#!/bin/sh
# Dynamic routing D5b acceptance on a real OpenResty: private bucket origin
# signing from site objects + worker-readable secret objects
# (edge/openresty/dynroute/cdnca_originauth.lua), compared request by request
# with the Go signer. One --rm --network none container.
#   tests/dynroute-originauth/run.sh
#   CDNCA_D5B_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
#   CDNCA_D5B_WRAP   command prefix (the shared machine's queue script)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D5B_IMAGE:-cdnca-native-runtime:edge-golden}
wrap=${CDNCA_D5B_WRAP:-}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
arch=$(docker image inspect "${image}" --format '{{.Architecture}}')
work=$(mktemp -d /tmp/cdnca-d5b-originauth.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/originauth/cmd/cdnca-originauth-dynroute-check
mkdir -p "${work}/lua/dynroute" "${work}/lua/originauth"
for name in cdnca_site.lua cdnca_site_admin.lua cdnca_origin.lua cdnca_origintls.lua cdnca_originauth.lua; do
	cp "${repo_root}/edge/openresty/dynroute/${name}" "${work}/lua/dynroute/"
done
cp "${repo_root}/edge/openresty/originauth/engine.lua" "${repo_root}/edge/openresty/originauth/crypto.lua" "${work}/lua/originauth/"
cp "${here}/nginx.conf" "${here}/fixtures.lua" "${work}/"
chmod -R a+rX "${work}"
# shellcheck disable=SC2086
${wrap} docker run --rm --init --network none --volume "${work}:/t:ro" --entrypoint /t/check "${image}" \
	-lua /t/lua -state /tmp/d5b-auth
