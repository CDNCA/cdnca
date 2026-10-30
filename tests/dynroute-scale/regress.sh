#!/bin/bash
# D13-d full dynamic routing regression: every tests/dynroute-* suite and the
# cdnca-dynroute golden, one after another, each through the shared machine
# queue (CDNCA_D13D_WRAP, default none). Logs go to
# OUT (default /tmp/d13d-regress); a summary line "SUITE <name> rc=<n>
# <seconds>s" per suite is appended to OUT/summary.txt.
#   tests/dynroute-scale/regress.sh                 all suites
#   ONLY="agent golden" tests/dynroute-scale/regress.sh
# dynroute-e2e needs PostgreSQL: a native instance from
# CDNCA_PG_NATIVE (name d13d, port PG_PORT, default 55991)
# is started for it and stopped after.
set -u
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
wrap=${CDNCA_D13D_WRAP:-env}
out=${OUT:-/tmp/d13d-regress}
mkdir -p "${out}"
suites=${ONLY:-"agent index tls origin origintls originauth cache filters telemetry waf sched302 security-fw security-bench poc e2e golden"}
run() { # name command...
	local name=$1 begin rc
	shift
	begin=$(date +%s)
	"${wrap}" "$@" >"${out}/${name}.log" 2>&1
	rc=$?
	echo "SUITE ${name} rc=${rc} $(($(date +%s) - begin))s" | tee -a "${out}/summary.txt"
}
for suite in ${suites}; do
	case "${suite}" in
	security-fw) run "${suite}" sh "${repo_root}/tests/dynroute-security/firewall-action.sh" ;;
	security-bench) run "${suite}" sh "${repo_root}/tests/dynroute-security/bench.sh" ;;
	# the PoC scripts take the node runtime image (built from the same Dockerfile target)
	poc) DYNROUTE_POC_IMAGE=${DYNROUTE_POC_IMAGE:-cdnca-native-runtime:edge-golden} run "${suite}" sh "${repo_root}/tests/dynroute-poc/run.sh" ;;
	e2e)
		url=$("${CDNCA_PG_NATIVE:?set CDNCA_PG_NATIVE for the e2e suite}" start d13d "${PG_PORT:-55991}" | grep -Eo 'postgres://[^ ]+' | tail -1)
		DYNROUTE_E2E_DATABASE_URL=${url} run "${suite}" bash "${repo_root}/tests/dynroute-e2e/run.sh"
		"${CDNCA_PG_NATIVE}" stop d13d >/dev/null 2>&1
		;;
	golden) CDNCA_EDGE_GOLDEN_OUT="${out}/golden" run "${suite}" sh "${repo_root}/tests/edge-golden/run.sh" check ;;
	*) run "${suite}" sh "${repo_root}/tests/dynroute-${suite}/run.sh" ;;
	esac
done
