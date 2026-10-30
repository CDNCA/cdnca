#!/bin/sh
# D11 managed WAF (OWASP CRS on libmodsecurity) on dynamic routing, real node
# runtime (OpenResty 1.31.1.1) with the engine extension mounted, one --rm
# --network none container: sites of different CRS profile packs and
# exclusions on one shared server do not leak into each other; request body
# tiers (reject / inspect the first bytes); allow CIDRs; exclusion change on
# the next request without a reload; fail closed; with SCALE the extra time
# per request on SCALE managed WAF sites.
# The D0 golden: CDNCA_EDGE_GOLDEN_RENDERER=cdnca-dynroute tests/edge-golden/run.sh check managed-waf
#   CDNCA_D11_IMAGE        node runtime image (default cdnca-native-runtime:edge-golden)
#   MODSECURITY_RUNTIME    engine extension (default scripts/security/modsecurity-runtime.sh)
#   ONLY=functional|tiers|catalog|apps|adaptive|tuning|tenants|scale|eval|perf|wafadapt|buckets|wafheader|exclprobe|repeat|managedwaflog  SCALE (default 0)  SCALE_TARGETS (exclusions per site, default 0)
#   REQUESTS (default 2000)  ROUNDS (default 3)
#   PERF_SIZES (default 1000; 10000 / 50000 on the evaluation worker)  PERF_REQUESTS (default 10000)
#     ONLY=perf: ADR 0011 §6.5 rule matching p50 / p99 / RSS per generated plan size (PERF line, JSON)
#   CDNCA_D11_WRAP         command prefix for docker (the shared machine's job queue)
#   ONLY=exclprobe (waf-exclcap2): the exclusion cost self test, k and the extra p50 within the budget; per CPU limit
#     CDNCA_D11_DOCKER_ARGS="--cpus 1 --env CDNCA_EXCLPROBE_LOAD=2" (n busy threads as the node's load)
#   CORPUS_SET=std         with ONLY=eval: the public datasets (scripts/security/datasets/README.md)
#     STD_DIR (default ~/.cache/cdnca-waf-datasets/corpus)  STD_SETS  STD_SHARD (i/n)  STD_FAST=1  STD_WORKERS
#   GATE_DIR               with ONLY=eval: quality gate G3 (ADR 0011 RI-11). GATE_DIR/base and GATE_DIR/candidate hold the
#     CRS profile packs (or rule intelligence mark packs: replayed on the rule interpreter, report mode "mark") of each version, GATE_DIR/corpus.jsonl (optional) the extra corpus; the reports go to GATE_DIR/out
#     (report.corpus.jsonl, report.base.json, report.candidate.json)  GATE_WORKERS (default 16)
#     GATE_STD=fast|full  also the waf-comparison datasets of STD_DIR (fast: its --fast subset, the waf-eval-std counting)
#     STD_RULES=1  one request at a time, STDRULE lines (each tier's audited CRS rules and matched variables)
#     STD_PROBE=1  one request at a time to the paranoia 4 log-only probe site only, STDVEC lines (PL4 rule hits + detectors, waf-gap6 learned weights)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D11_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
engine_mount=""
if [ "${ONLY:-}" != perf ]; then
	# ONLY=perf runs the rule interpreter only (no managed WAF engine).
	runtime=${MODSECURITY_RUNTIME:-$(sh "${repo_root}/scripts/security/modsecurity-runtime.sh")}
	[ -f "${runtime}/modules/ngx_http_modsecurity_module.so" ] || { echo "BLOCKED: no ModSecurity runtime at ${runtime}" >&2; exit 69; }
	engine_mount="-v ${runtime}:/usr/local/openresty/modsecurity:ro"
fi
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d11.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/edgegolden/goldendyn/cmd/cdnca-waf-check
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
mkdir -p "${work}/crs-apps"
cp "${repo_root}"/libs/rulepack/testdata/crs-apps/app-*.json "${work}/crs-apps/"
# -only eval: the OWASP CRS regression tests of the pinned source as attack corpus
corpus=""
std_mount="" std_args=""
if [ "${CORPUS_SET:-}" = std ]; then
	std_dir=${STD_DIR:-${HOME}/.cache/cdnca-waf-datasets/corpus}
	[ -d "${std_dir}" ] || { echo "BLOCKED: no std corpora at ${std_dir} (scripts/security/datasets/convert.py)" >&2; exit 69; }
	std_mount="-v ${std_dir}:/std:ro"
	std_args="-corpus-set std -std-sets ${STD_SETS:-wafcomp-mal,wafcomp-legit,gotestwaf,leipzig} -std-shard ${STD_SHARD:-0/1} -std-workers ${STD_WORKERS:-32}"
	[ "${STD_FAST:-0}" = 1 ] && std_args="${std_args} -std-fast"
	[ "${STD_RULES:-0}" = 1 ] && std_args="${std_args} -std-rules"
	[ "${STD_PROBE:-0}" = 1 ] && std_args="${std_args} -std-probe"
fi
case ",${ONLY:-},${CORPUS_SET:-}," in *,std,*) ;; *,eval,*)
	cache="${MODSECURITY_CACHE:-${HOME}/.cache/cdnca-modsecurity}"
	printf '%s  %s\n' a4bb3688ef6205b64471a9ccbf0d7b024eb8edf39b97c6f6c0006e7a948f8550 "${cache}/src/coreruleset-4.30.0-src.tar.gz" | shasum -a 256 -c - >/dev/null
	mkdir -p "${work}/crs" "${work}/crscorpus"
	tar -xzf "${cache}/src/coreruleset-4.30.0-src.tar.gz" -C "${work}/crs" coreruleset-4.30.0/tests/regression/tests coreruleset-4.30.0/rules
	cp "${repo_root}/scripts/security/crscorpus/main.go" "${work}/crscorpus/main.go"
	cp "${repo_root}/scripts/security/crscorpus/corpus.mod" "${work}/crscorpus/go.mod"
	cp "${repo_root}/scripts/security/crscorpus/corpus.sum" "${work}/crscorpus/go.sum"
	GOWORK=off GOFLAGS=-mod=readonly go -C "${work}/crscorpus" run . "${work}/crs/coreruleset-4.30.0/tests/regression/tests" \
		"${work}/crs/coreruleset-4.30.0/rules" >"${work}/crs-corpus.json"
	rm -rf "${work}/crs" "${work}/crscorpus"
	corpus=/d11/crs-corpus.json ;;
esac
gate_mount="" gate_args=""
if [ -n "${GATE_DIR:-}" ]; then
	[ -d "${GATE_DIR}/base" ] && [ -d "${GATE_DIR}/candidate" ] || { echo "BLOCKED: ${GATE_DIR} needs base/ and candidate/" >&2; exit 69; }
	mkdir -p "${GATE_DIR}/out"
	chmod a+rwx "${GATE_DIR}/out"
	gate_mount="-v ${GATE_DIR}:/gate:ro -v ${GATE_DIR}/out:/gate-out"
	gate_args="-gate-base /gate/base -gate-candidate /gate/candidate -report /gate-out/report -gate-workers ${GATE_WORKERS:-16}"
	[ -f "${GATE_DIR}/corpus.jsonl" ] && gate_args="${gate_args} -gate-corpus /gate/corpus.jsonl"
	if [ -n "${GATE_STD:-}" ]; then
		std_dir=${STD_DIR:-${HOME}/.cache/cdnca-waf-datasets/corpus}
		[ -d "${std_dir}" ] || { echo "BLOCKED: no std corpora at ${std_dir} (scripts/security/datasets/convert.py)" >&2; exit 69; }
		gate_mount="${gate_mount} -v ${std_dir}:/std:ro"
		gate_args="${gate_args} -gate-std ${GATE_STD}"
	fi
fi
chmod -R a+rX "${work}"
# The module finds libmodsecurity under its build prefix
# (edge/openresty/modsecurity/build.sh): mount it there.
# shellcheck disable=SC2086
${CDNCA_D11_WRAP:-} docker run --rm --init --network none ${CDNCA_D11_DOCKER_ARGS:-} -v "${work}:/d11:ro" ${std_mount} ${gate_mount} \
	${engine_mount} --env CDNCA_D11_PROBE="${CDNCA_D11_PROBE:-}" --entrypoint /d11/check "${image}" \
	-lua /d11/lua -workers "${WORKERS:-2}" -scale "${SCALE:-0}" -scale-targets "${SCALE_TARGETS:-0}" -requests "${REQUESTS:-2000}" -rounds "${ROUNDS:-3}" -only "${ONLY:-}" -corpus "${corpus}" \
	-perf-sizes "${PERF_SIZES:-1000}" -perf-requests "${PERF_REQUESTS:-10000}" ${std_args} ${gate_args}
