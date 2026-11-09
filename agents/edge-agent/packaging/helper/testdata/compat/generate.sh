#!/bin/sh
# Regenerates state-<ref>.json: the helper state an OLDER helper leaves behind
# (journal v2/v3 records, current record, transaction staging, receipt key
# files), produced by that release's own helper code. compat_test.go makes the
# current helper take each one over.
#
#   agents/edge-agent/packaging/helper/testdata/compat/generate.sh [REF...]
#
# Default ref: 86c4d871 (the helper on installed nodes; every released helper
# so far has the same tree).
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repo=$(git -C "${here}" rev-parse --show-toplevel)
[ "$#" -gt 0 ] || set -- 86c4d871
for ref in "$@"; do
  tree=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-helper-compat.XXXXXX")
  git -C "${repo}" archive "${ref}" agents/edge-agent libs proto/gen/go | tar -x -C "${tree}"
  cp "${here}/export_state_test.go" "${tree}/agents/edge-agent/packaging/helper/zz_export_state_test.go"
  (cd "${tree}/agents/edge-agent" && GOWORK=off CDNCA_HELPER_COMPAT_OUT="${here}/state-${ref}.json" \
    go test -count=1 -run '^TestExportHelperStateForCompat$' ./packaging/helper/ >/dev/null) || {
    rm -rf -- "${tree}"; printf 'export failed for %s\n' "${ref}" >&2; exit 1; }
  rm -rf -- "${tree}"
  printf 'wrote %s\n' "${here}/state-${ref}.json"
done
