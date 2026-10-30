#!/bin/sh
# Dynamic routing D13-a acceptance on a real OpenResty: the agent runtime
# (agents/edge-agent/internal/dynroute) drives the node runtime image in one
# --rm --network none container — cold start, incremental activation,
# rollback, certificate rotation and OCSP, cache purge and soft quota,
# managed WAF tiers (and the grey zone repeat threshold per site,
# migration 512 / capability 64: PASS/FAIL waf-repeat-*), per-node L4 forwards (two line groups' nodes in turn,
# each listening only on its group's forward),
# rule pack mounts (sealed pack opened by the node key,
# plans on tmpfs, wrong key refused; official system packs bot-bad-ua and
# cc-404-burst with the site's trusted crawlers), agent and node restart,
# error.log summary.
# SYS_PTRACE: the L4 runtime reads its OpenResty's /proc/<pid>/exe identity
# (scripts/edge-l4-smoke.sh does the same).
#   tests/dynroute-agent/run.sh
#   CDNCA_D13_IMAGE      node runtime image (default cdnca-native-runtime:edge-golden)
#   MODSECURITY_RUNTIME  engine extension directory (default scripts/security/modsecurity-runtime.sh;
#                        "none" skips the managed WAF part)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D13_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
runtime=${MODSECURITY_RUNTIME:-$(sh "${repo_root}/scripts/security/modsecurity-runtime.sh" 2>/dev/null || echo none)}
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d13.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/dynroute/cmd/cdnca-dynroute-agent-check
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
# the L4 runtime's Lua (lua_package_path /opt/cdnca/l4geo) of this checkout:
# an image built before the cdnca rename has it at the old pre-rename path only
mkdir -p "${work}/l4geo"
grep -E '^COPY edge/openresty/[^ ]+ /opt/cdnca/l4geo/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		cp "${repo_root}/${source}" "${work}/l4geo/${target#/opt/cdnca/l4geo/}"
	done
# official system rule packs (license migration 097 sources)
mkdir -p "${work}/official"
cp "${repo_root}"/scripts/security/datasets/rulepacks/system-*.json "${work}/official/"
mkdir -p "${work}/official/imported"
cp "${repo_root}"/scripts/security/datasets/rulepacks/imported/system-*.json "${work}/official/imported/"
chmod -R a+rX "${work}"
waf_volume="" waf_flag=""
if [ "${runtime}" != none ] && [ -f "${runtime}/modules/ngx_http_modsecurity_module.so" ]; then
	waf_volume="-v ${runtime}:/usr/local/openresty/modsecurity:ro"
	waf_flag="-modsecurity /usr/local/openresty/modsecurity"
else
	echo "NOTE: no ModSecurity runtime, managed WAF part skipped" >&2
fi
# shellcheck disable=SC2086
${CDNCA_D13_WRAP:-} docker run --rm --init --network none --cap-add SYS_PTRACE --tmpfs /run/cdnca:mode=0755 ${CDNCA_D13_DOCKER_ARGS:-} -v "${work}:/d13:ro" -v "${work}/l4geo:/opt/cdnca/l4geo:ro" ${waf_volume} \
	--entrypoint /d13/check "${image}" -lua /d13/lua -official /d13/official -workers "${WORKERS:-2}" ${waf_flag}
