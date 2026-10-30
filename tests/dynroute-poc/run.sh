#!/bin/sh
# ADR 0009 §8.5 pre-implementation PoC (results: docs/adr/0009-poc-results.md).
#   tests/dynroute-poc/run.sh [build] [shdict quic origintls errorpage modsec]
# "build" (or a missing image) builds the real node runtime from
# edge/openresty/native/Dockerfile --target runtime (OpenResty 1.31.1.1 +
# patches 01-23) as DYNROUTE_POC_IMAGE. Scenarios run one after another, each
# in its own --rm --network none container. On a shared machine set
# DYNROUTE_POC_WRAP to the job-queue wrapper for the build and the runs.
# modsec also needs the ModSecurity runtime for nginx 1.31.1
# (scripts/security/modsecurity-runtime.sh builds it once) and the CRS 4.30.0
# source tarball (CRS_SOURCE).
set -eu
here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "${here}/../.." && pwd)"
image="${DYNROUTE_POC_IMAGE:-cdnca-native-runtime:dynroute-poc}"
wrap="${DYNROUTE_POC_WRAP:-}"
if [ "${1:-}" = build ] || ! docker image inspect "${image}" >/dev/null 2>&1; then
  [ "${1:-}" = build ] && shift
  ${wrap} docker build --target runtime -f "${repo_root}/edge/openresty/native/Dockerfile" -t "${image}" "${repo_root}"
fi
[ "$#" -gt 0 ] || set -- shdict quic origintls errorpage modsec
status=0
for scenario in "$@"; do
  echo "######## ${scenario}"
  DYNROUTE_POC_IMAGE="${image}" ${wrap} sh "${here}/${scenario}.sh" || status=1
done
exit "${status}"
