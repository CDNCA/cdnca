#!/bin/sh
# CC / WAF engine regression coverage on dynamic routing, real OpenResty
# (the node runtime image with the ModSecurity extension mounted), one --rm
# --network none container. Replaces the retired v7 scripts
# (scripts/security/rule-enforcement-probe.sh / -bench.sh, cc-browser-e2e.sh;
# dr-d13-c3e): every CC rule group of the signed system catalog solved page
# by page (5秒盾, JS, click, rotate, easy click, easy slider, slider,
# captcha), catalog parameters followed, 宽松 rate limits, self-developed +
# OWASP CRS engines side by side, and the request cost bench.
#
# Chain: control-api TestRuleEnforcementAuditRelease (real compile chain)
# writes a signed site runtime v2 release -> control-api
# cmd/cdnca-site-objects-v2 (the production site object conversion) ->
# agents/edge-agent .../cmd/cdnca-cc-check activates the objects on a
# dynamic routing node and probes it from inside the container.
#
#   tests/dynroute-cc/run.sh                 cc, modes, params, rate, engines
#   ONLY=bench tests/dynroute-cc/run.sh      request cost (no checks)
#   ONLY=cc,rate ...                         some parts
#   BROWSER=1 tests/dynroute-cc/run.sh       headless Chromium solves the pages (browser.mjs)
#   CDNCA_CC_IMAGE        node runtime image (default cdnca-native-runtime:edge-golden)
#   MODSECURITY_RUNTIME   engine extension (default scripts/security/modsecurity-runtime.sh)
#   PLAYWRIGHT_CORE       playwright-core directory (BROWSER=1; default <repo>/node_modules/playwright-core)
#   CHROMIUM              Chromium / chrome-headless-shell executable (BROWSER=1; default the package's own build)
#   CDNCA_CC_WRAP         command prefix for docker (the shared machine's job queue)
#   BENCH_REQUESTS (4000) BENCH_CONCURRENCY (8) BENCH_ROUNDS (3)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_CC_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
runtime=${MODSECURITY_RUNTIME:-$(sh "${repo_root}/scripts/security/modsecurity-runtime.sh")}
[ -f "${runtime}/modules/ngx_http_modsecurity_module.so" ] || { echo "BLOCKED: no ModSecurity runtime at ${runtime}" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-cc.XXXXXX)
container="cdnca-cc-$(basename "${work}" | tr -cd 'a-zA-Z0-9')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf "${work}"; }
trap cleanup EXIT INT TERM
mkdir -p "${work}/release" "${work}/objects" "${work}/lua"
CDNCA_RULE_AUDIT_OUT="${work}/release" go -C "${repo_root}/services/control-api" test ./internal/securitypublication/ \
	-run '^TestRuleEnforcementAuditRelease$' -count=1 >"${work}/release.log" 2>&1 || { cat "${work}/release.log" >&2; exit 1; }
go -C "${repo_root}/services/control-api" run ./cmd/cdnca-site-objects-v2 -bundle "${work}/release/signed-release" \
	-tenant 0a1b9999-0000-4000-8000-000000000002 -out "${work}/objects"
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/edgegolden/goldendyn/cmd/cdnca-cc-check
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
chmod -R a+rX "${work}"
args="-lua /cc/lua -objects /cc/objects -bench-requests ${BENCH_REQUESTS:-4000} -bench-concurrency ${BENCH_CONCURRENCY:-8} -bench-rounds ${BENCH_ROUNDS:-3}"
if [ "${BROWSER:-0}" = 1 ]; then
	playwright=${PLAYWRIGHT_CORE:-${repo_root}/node_modules/playwright-core}
	[ -f "${playwright}/package.json" ] || { echo "BLOCKED: no playwright-core at ${playwright}" >&2; exit 69; }
	port=${CC_BROWSER_PORT:-18093}
	# The browser runs on the host: the node is published on loopback only.
	# shellcheck disable=SC2086
	${CDNCA_CC_WRAP:-} docker run -d --rm --init --name "${container}" -p "127.0.0.1:${port}:8080" -v "${work}:/cc:ro" \
		-v "${runtime}:/usr/local/openresty/modsecurity:ro" --entrypoint /cc/check "${image}" ${args} -only serve >/dev/null
	for _ in $(seq 1 100); do docker logs "${container}" 2>&1 | grep -q READY && break; sleep 0.2; done
	status=0
	node "${here}/browser.mjs" "${playwright}" "http://127.0.0.1:${port}" "${work}/pass.cookie" || status=1
	# The browser's pass cookie from another network (the container's own
	# loopback is not the browser's Docker gateway /24) must be refused.
	other=$(docker exec "${container}" /cc/check -replay /cc/pass.cookie -replay-ua /cc/pass.cookie.ua 2>&1 || true)
	if [ "${other}" = 503 ]; then echo "PASS BROWSER-IP expected=503 actual=${other} 浏览器拿到的 Cookie 换到其它网段（容器内 127.0.0.1）后失效"
	else echo "FAIL BROWSER-IP expected=503 actual=${other} 浏览器拿到的 Cookie 换到其它网段后失效"; status=1; fi
	docker stop -t 5 "${container}" >/dev/null 2>&1 || true
	echo "RESULT browser status=${status}"
	exit "${status}"
fi
# shellcheck disable=SC2086
${CDNCA_CC_WRAP:-} docker run --rm --init --network none --name "${container}" -v "${work}:/cc:ro" \
	-v "${runtime}:/usr/local/openresty/modsecurity:ro" --entrypoint /cc/check "${image}" ${args} -only "${ONLY:-}"
