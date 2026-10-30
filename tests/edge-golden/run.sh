#!/bin/sh
# Edge behaviour golden (ADR 0009 §5): records what a renderer's real
# OpenResty runtime does for every scenario under cdnca-v7/scenarios, and
# compares a run with the recorded golden. See tests/edge-golden/README.md.
#
#   tests/edge-golden/run.sh record    [scenario,...]   write cdnca-v7/expected/
#   tests/edge-golden/run.sh check     [scenario,...]   run and diff against expected/
#   tests/edge-golden/run.sh selfcheck [scenario,...]   record twice, diff the two runs
#                                                       (reproducible), then check
#
# Environment:
#   CDNCA_EDGE_GOLDEN_IMAGE     node runtime image (default cdnca-native-runtime:edge-golden;
#                               built from edge/openresty/native/Dockerfile --target runtime
#                               when missing)
#   CDNCA_EDGE_GOLDEN_RENDERER  renderer to run (default cdnca-dynroute)
#   CDNCA_EDGE_GOLDEN_MODSECURITY  managed WAF engine extension: "auto" (default,
#                               scripts/security/modsecurity-runtime.sh), a directory, or "none"
#   CDNCA_EDGE_GOLDEN_OUT       where check/selfcheck write observations and reports
#                               (default a temporary directory, printed)
#   CDNCA_EDGE_GOLDEN_WRAP      command prefix for docker (the shared machine's job queue)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
corpus="${here}/cdnca-v7"
image=${CDNCA_EDGE_GOLDEN_IMAGE:-cdnca-native-runtime:edge-golden}
renderer=${CDNCA_EDGE_GOLDEN_RENDERER:-cdnca-dynroute}
wrap=${CDNCA_EDGE_GOLDEN_WRAP:-}
mode=${1:-check}
only=${2:-}
case "${mode}" in record|check|selfcheck) ;; *) echo "usage: $0 record|check|selfcheck [scenario,...]" >&2; exit 2 ;; esac

if ! docker image inspect "${image}" >/dev/null 2>&1; then
	context=$(mktemp -d /tmp/cdnca-edge-golden-context.XXXXXX)
	mkdir -p "${context}/edge"
	cp -a "${repo_root}/edge/openresty" "${context}/edge/"
	${wrap} docker build --target runtime -f "${context}/edge/openresty/native/Dockerfile" -t "${image}" "${context}"
	rm -rf "${context}"
fi
case "$(docker info --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-edge-golden.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/cdnca-edge-golden" ./internal/edgegolden/cmd/cdnca-edge-golden
# The dynamic routing renderers convert the release with the control plane's
# site object v2 conversion (control-api cdnca-site-objects-v2).
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/services/control-api" build -trimpath \
	-o "${work}/cdnca-site-objects-v2" ./cmd/cdnca-site-objects-v2
# The HTTP/3 client (scenarios that require http3): the D9 probe in its own
# module with the HTTP/3 client's pins (tests/dynroute-filters/run.sh).
mkdir -p "${work}/probe-src"
cp "${repo_root}/edge/openresty/http3/client/client.mod" "${work}/probe-src/go.mod"
cp "${repo_root}/edge/openresty/http3/client/client.sum" "${work}/probe-src/go.sum"
cp "${repo_root}/tests/dynroute-filters/probe/main.go" "${work}/probe-src/main.go"
GOWORK=off GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${work}/probe-src" build -trimpath -o "${work}/http3-probe" .
rm -rf "${work}/probe-src"
# The node Lua tree of this checkout, laid out as the image's Dockerfile
# installs it, so a run measures this tree's Lua even on an older image.
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
# The L4 runtime's Lua (lua_package_path /opt/cdnca/l4geo), likewise: an
# image built before the cdnca rename has it at the old pre-rename path only.
mkdir -p "${work}/l4geo"
grep -E '^COPY edge/openresty/[^ ]+ /opt/cdnca/l4geo/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		cp "${repo_root}/${source}" "${work}/l4geo/${target#/opt/cdnca/l4geo/}"
	done
chmod -R a+rX "${work}"

modsecurity=${CDNCA_EDGE_GOLDEN_MODSECURITY:-auto}
modsecurity_args=""
case "${modsecurity}" in
	none) ;;
	auto) modsecurity=$(sh "${repo_root}/scripts/security/modsecurity-runtime.sh" 2>/dev/null || true) ;;
esac
if [ "${modsecurity}" != none ] && [ -f "${modsecurity}/modules/ngx_http_modsecurity_module.so" ]; then
	# The module finds libmodsecurity under its build prefix (edge/openresty/modsecurity/build.sh).
	modsecurity_args="--volume ${modsecurity}:/usr/local/openresty/modsecurity:ro --env CDNCA_EDGE_GOLDEN_MODSECURITY=/usr/local/openresty/modsecurity"
else
	echo "--- no managed WAF engine extension: scenarios that require managed_waf are skipped" >&2
fi

out=${CDNCA_EDGE_GOLDEN_OUT:-$(mktemp -d /tmp/cdnca-edge-golden-out.XXXXXX)}
mkdir -p "${out}"
chmod 777 "${out}"
only_arg=""
[ -n "${only}" ] && only_arg="-only ${only}"
# One CPU: "worker_processes auto" starts one worker, so per-worker state
# (round robin position, connection counts, caches) is the same on every run.
# No network: every origin is in the container. nobody: master and workers
# run as one user, as the native node's workers read the release.
golden() {
	# shellcheck disable=SC2086
	${wrap} docker run --rm --init --network none --cpuset-cpus 0 --user 65534:65534 \
		--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
		--volume "${work}/cdnca-edge-golden:/usr/local/bin/cdnca-edge-golden:ro" \
		--volume "${work}/cdnca-site-objects-v2:/usr/local/bin/cdnca-site-objects-v2:ro" \
		--env CDNCA_EDGE_GOLDEN_SITE_OBJECTS=/usr/local/bin/cdnca-site-objects-v2 \
		--volume "${work}/http3-probe:/usr/local/bin/cdnca-http3-probe:ro" --env CDNCA_EDGE_GOLDEN_HTTP3=/usr/local/bin/cdnca-http3-probe \
		--volume "${work}/lua:/usr/local/share/cdnca:ro" \
		--volume "${corpus}:/golden/corpus:ro" --volume "${out}:/golden/out" \
		${modsecurity_args} --entrypoint /usr/local/bin/cdnca-edge-golden "${image}" "$@" -renderer "${renderer}"
}
docker image inspect "${image}" --format 'image {{.Id}}' >&2
# L4 forwards (scenarios that require l4) run on the node's L4 runtime, which
# runs as root and reads its OpenResty's /proc/<pid>/exe (SYS_PTRACE, as
# scripts/edge-l4-smoke.sh): a second, root container runs only those.
# The first container runs the others (only_arg).
l4_only="" rest_only=""
for path in "${corpus}/scenarios/"*.json; do
	name=$(basename "${path}" .json)
	[ -z "${only}" ] || printf ',%s,' "${only}" | grep -q ",${name}," || continue
	if tr -d ' \n\t' <"${path}" | grep -q '"requires":\[[^]]*"l4"'; then
		l4_only="${l4_only:+${l4_only},}${name}"
	else
		rest_only="${rest_only:+${rest_only},}${name}"
	fi
done
if [ -n "${l4_only}" ]; then
	only_arg="-only ${rest_only}"
fi
golden_l4() {
	# shellcheck disable=SC2086
	${wrap} docker run --rm --init --network none --cpuset-cpus 0 --cap-add SYS_PTRACE \
		--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
		--volume "${work}/cdnca-edge-golden:/usr/local/bin/cdnca-edge-golden:ro" \
		--volume "${work}/cdnca-site-objects-v2:/usr/local/bin/cdnca-site-objects-v2:ro" \
		--env CDNCA_EDGE_GOLDEN_SITE_OBJECTS=/usr/local/bin/cdnca-site-objects-v2 \
		--volume "${work}/lua:/usr/local/share/cdnca:ro" --volume "${work}/l4geo:/opt/cdnca/l4geo:ro" \
		--volume "${corpus}:/golden/corpus:ro" --volume "${out}:/golden/out" \
		--entrypoint /usr/local/bin/cdnca-edge-golden "${image}" "$@" -renderer "${renderer}" -only "${l4_only}"
}

case "${mode}" in
record)
	rm -rf "${out}/expected" && mkdir -p "${out}/expected" && chmod 777 "${out}/expected"
	[ -d "${corpus}/expected" ] && cp "${corpus}/expected/"*.json "${out}/expected/" 2>/dev/null || true
	# The recorder runs as nobody: on Linux the copies are ours, so it could not rewrite them.
	chmod 666 "${out}/expected/"*.json 2>/dev/null || true
	# Scenarios that recorded are kept even when another one failed.
	status=0
	if [ -z "${l4_only}" ] || [ -n "${rest_only}" ]; then
		golden record -scenarios /golden/corpus/scenarios -out /golden/out/expected ${only_arg} || status=$?
	fi
	if [ -n "${l4_only}" ]; then
		golden_l4 record -scenarios /golden/corpus/scenarios -out /golden/out/expected || status=$?
	fi
	mkdir -p "${corpus}/expected"
	cp "${out}/expected/"*.json "${corpus}/expected/" 2>/dev/null || true
	echo "recorded into ${corpus}/expected"
	[ "${status}" -eq 0 ] || exit "${status}"
	;;
check)
	status=0
	if [ -z "${l4_only}" ] || [ -n "${rest_only}" ]; then
		golden check -scenarios /golden/corpus/scenarios -expected /golden/corpus/expected -rules /golden/corpus/compare.json \
			-actual /golden/out/actual -report /golden/out/report.json ${only_arg} || status=$?
	fi
	if [ -n "${l4_only}" ]; then
		echo "--- L4 scenarios (root container): ${l4_only}"
		golden_l4 check -scenarios /golden/corpus/scenarios -expected /golden/corpus/expected -rules /golden/corpus/compare.json \
			-actual /golden/out/actual -report /golden/out/report-l4.json || status=$?
	fi
	[ "${status}" -eq 0 ] || { echo "observations and reports: ${out}" >&2; exit "${status}"; }
	;;
selfcheck)
	for run in first second; do
		mkdir -p "${out}/${run}" && chmod 777 "${out}/${run}"
		golden record -scenarios /golden/corpus/scenarios -out "/golden/out/${run}" ${only_arg}
	done
	echo "--- reproducibility: second run against the first (no rules)"
	golden diff -expected /golden/out/first -actual /golden/out/second -report /golden/out/reproducible.json
	echo "--- the run against the committed golden"
	golden diff -expected /golden/corpus/expected -actual /golden/out/first -rules /golden/corpus/compare.json \
		-report /golden/out/report.json
	;;
esac
echo "observations and reports: ${out}" >&2
