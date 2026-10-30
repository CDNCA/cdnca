#!/bin/sh
# N16 on the real node runtime: a node configured as install-node.sh writes it
# (dynamic_routing without cache_max_bytes) gets the default cache budget and
# a .svg cache rule answers MISS then HIT (cmd/edge-agent
# TestDynRouteDefaultCacheRealRuntime), one --rm --network none container.
#   CDNCA_D8_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D8_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-n16.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" test -c -trimpath \
	-o "${work}/edge-agent.test" ./cmd/edge-agent
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
chmod -R a+rX "${work}"
# the agent reads the node Lua at its installed path
docker run --rm --init --network none -v "${work}/lua:/usr/local/share/cdnca:ro" -v "${work}:/n16:ro" \
	-e DYNROUTE_CACHE_DEFAULT_OPENRESTY=/usr/local/openresty/bin/openresty \
	--entrypoint /n16/edge-agent.test "${image}" -test.run '^TestDynRouteDefaultCacheRealRuntime$' -test.v
