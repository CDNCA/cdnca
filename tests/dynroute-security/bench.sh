#!/bin/sh
# Dynamic routing D7 cost: SITES sites (default 10000) each with its own CC
# policy, ACL + WAF rules, HTTP policy and firewall action, plus as many
# sites without security on a second port; one real OpenResty worker (the
# node runtime image, --rm --network none). Reports the security phases'
# own time per request (cold: first request of each site; warm: random
# sites) and the end-to-end difference between the two ports.
#   tests/dynroute-security/bench.sh
#   SITES=10000 REQUESTS=20000 CDNCA_D7_IMAGE=... CDNCA_D7_WRAP=<queue script>
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D7_IMAGE:-cdnca-native-runtime:edge-golden}
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d7-bench.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/bench" ./internal/siteindex/cmd/cdnca-security-bench
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
# resty.ipmatcher (firewall action engine): native images built from this
# tree ship it in lualib; the vendored copy is put first on the path so an
# image built before that fix measures the same code.
mkdir -p "${work}/lua/resty"
cp "${repo_root}/edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua" "${work}/lua/resty/ipmatcher.lua"
chmod -R a+rX "${work}"
# shellcheck disable=SC2086
${CDNCA_D7_WRAP:-} docker run --rm --init --network none --cpuset-cpus 0 --volume "${work}:/d7:ro" --entrypoint /d7/bench "${image}" \
	-lua /d7/lua -state /tmp/d7bench -sites "${SITES:-10000}" -requests "${REQUESTS:-20000}"
