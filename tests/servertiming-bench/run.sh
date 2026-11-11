#!/bin/sh
# Server-Timing micro benchmark: ns per call of each piece of the
# header_filter Server-Timing slot inside a real OpenResty header_filter, on
# an Authorization bypass (origin fetched, no zone) and a proxy_cache HIT,
# with pcre_jit off (the node skeleton today) and on. Prints the ST lines.
#   CDNCA_ST_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_ST_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
work=$(mktemp -d /tmp/cdnca-st.XXXXXX)
trap 'rm -rf "${work}"' EXIT
for jit in off on; do
	sed "s/__PCRE_JIT__/pcre_jit ${jit};/" "${here}/nginx.conf" >"${work}/nginx-${jit}.conf"
	chmod -R a+rX "${work}"
	echo "== pcre_jit ${jit}"
	docker run --rm --network none -v "${work}:/st/conf:ro" -v "${here}:/st/bench:ro" \
		-v "${repo_root}/edge/openresty/dynroute:/st/dynroute:ro" --entrypoint /usr/local/openresty/nginx/sbin/nginx \
		"${image}" -p /tmp -e stderr -c "/st/conf/nginx-${jit}.conf" 2>&1 | sed -n 's/.*\(ST .*\)/\1/p' | sed 's/ while reading.*//; s/, client:.*//' | grep -E '^ST ' || true
done
