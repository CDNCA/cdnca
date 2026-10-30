#!/bin/sh
# D5a origin selection on the real node runtime (OpenResty 1.31.1.1): each
# part is one --rm --network none container.
#   1. algorithms.lua: the nginx algorithm ports against the v7 golden order
#   2. cdnca-origin-check: connection reuse never across pools/sites, routes,
#      DNS, non-idempotent requests not re-sent, ingress bind; then the
#      selection cost with SCALE sites x POOLS pools (default 10000 x 4)
# The D0 golden scenarios: CDNCA_EDGE_GOLDEN_RENDERER=cdnca-dynroute
#   tests/edge-golden/run.sh check load-balancing,retry-failover,forwarding,l2-fallback
#   CDNCA_D5A_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
#   ONLY=algorithms|check
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D5A_IMAGE:-cdnca-native-runtime:edge-golden}
only=${ONLY:-}
work=$(mktemp -d /tmp/cdnca-d5a.XXXXXX)
trap 'rm -rf "${work}"' EXIT
status=0

if [ -z "${only}" ] || [ "${only}" = algorithms ]; then
	mkdir -p "${work}/alg/logs"
	cat >"${work}/alg/nginx.conf" <<'CONF'
daemon off; master_process off; error_log stderr warn; pid /tmp/d5a.pid;
events {}
http {
  lua_package_path "/t/dynroute/?.lua;;";
  init_worker_by_lua_block {
    ngx.timer.at(0, function()
      local ok, err = pcall(dofile, "/x/algorithms.lua")
      if not ok then ngx.log(ngx.WARN, "RESULT failures=error ", err) end
      os.exit(0)
    end)
  }
  server { listen 127.0.0.1:1; }
}
CONF
	cp "${here}/algorithms.lua" "${here}/route_levels.json" "${work}/alg/"
	chmod -R a+rX "${work}"
	docker run --rm --network none -v "${repo_root}/edge/openresty:/t:ro" -v "${work}/alg:/x" \
		--entrypoint /usr/local/openresty/bin/openresty "${image}" -p /x/ -c nginx.conf 2>&1 |
		grep -Eo "(PASS|FAIL|RESULT) .*" | sed "s/, context: .*//" | tee "${work}/alg.out"
	grep -q '^RESULT failures=0$' "${work}/alg.out" || status=1
	# The container (root) wrote logs/ and nginx temp directories into the bind
	# mount; on Linux they are not ours (no chmod), but their parent is, so they go.
	rm -rf "${work}/alg"
fi

if [ -z "${only}" ] || [ "${only}" = check ]; then
	case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
		arm64|aarch64) go_arch=arm64 ;;
		*) go_arch=amd64 ;;
	esac
	GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
		-o "${work}/check" ./internal/edgegolden/goldendyn/cmd/cdnca-origin-check
	# the node Lua tree as the native Dockerfile installs it
	mkdir -p "${work}/lua"
	grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
		while read -r _ source target; do
			mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
			cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
		done
	chmod -R a+rX "${work}"
	docker run --rm --init --network none -v "${work}:/d5a:ro" --entrypoint /d5a/check "${image}" \
		-lua /d5a/lua -workers "${WORKERS:-1}" -scale "${SCALE:-10000}" -pools "${POOLS:-4}" || status=1
fi
exit "${status}"
