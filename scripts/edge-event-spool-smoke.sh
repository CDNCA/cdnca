#!/bin/sh
set -eu

umask 077
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
tmp_base="${TMPDIR:-/tmp}"
case "${tmp_base}" in
  /*) ;;
  *) echo "TMPDIR must be absolute" >&2; exit 64 ;;
esac
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-event-spool.XXXXXX")"
workdir="$(CDPATH='' cd -- "${workdir}" && pwd -P)"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-event-spool.*|/private"${tmp_base%/}"/cdnca-edge-event-spool.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

chmod 0700 "${workdir}"
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go build -trimpath -o "${workdir}/event-spool-smoke" ./internal/eventspool/cmd/event-spool-smoke
)
"${workdir}/event-spool-smoke" -mode run -root "${workdir}/run"
