#!/bin/sh
# Real environment acceptance of the native node runtime switch
# (node-runtime-upgrade: agents/edge-agent internal/nativeruntime,
# dynroute.UpgradeMaster and l4runtime OpenResty.UpgradeBinary) against the real OpenResty/Lua of a native node
# package, in one privileged disposable debian:12 container (--rm --init;
# nothing is installed, no image is built; systemd never starts and
# systemd-binfmt is masked anyway so it cannot clear Docker Desktop's binfmt
# registrations). The container's own /opt/cdnca-node and /usr/local are the
# node's; never run the test binary on a host.
#
#   scripts/native-runtime-upgrade-acceptance.sh <native package .tar.gz | payload dir>
#
# The input is the node package of a release build (cdnca-edge-agent.tar.gz
# of scripts/native-node-package.mjs) or its exported payload directory
# (runtime/ and lua/, scripts/native-node-export.mjs). The test re-signs that
# payload with a throwaway key into releases that differ only in one Lua
# module and checks:
#   1. new Lua takes effect: A -> B hot upgrades the HTTP master (new master
#      pid, every answer from a worker of it with B's Lua), config.json
#      openresty.version and security_runtime paths/sha point into B;
#   2. old sessions are cut, not waited for (BATCH 77b): after the new master
#      serves, the old one gets QUIT, TERM 10 s later and KILL (with its
#      workers) 5 s after that; a streaming response started on A that would
#      outlast this grace is cut within it, the old HTTP master is gone once
#      the switch returns, and new requests go to B's master;
#   3. the L4 (stream) master, started through l4runtime as the Agent runs
#      it, is hot upgraded the same way (USR2): the TCP session established on
#      A's master is cut within the grace, A's L4 master is gone, the new L4
#      master runs B's binary and takes new sessions;
#   4. sha unchanged skips: a release whose runtime and Lua equal B's (only
#      the Agent differs) is "unchanged": same link, same master;
#   5. precheck failure rolls back: Lua that fails `openresty -t` gives
#      RUNTIME_PRECHECK_FAILED, current and config.json are back on B, which
#      keeps serving from the same master;
#   6. two upgrades in a row both succeed: B -> E and right away E -> F, each
#      with sessions held on the masters it replaces (cut within the grace),
#      no replaced master left running (exactly one HTTP and one L4 master),
#      only the current and the previous release kept; and a master an
#      earlier upgrade left running (USR2 by hand, never retired; nginx
#      ignores USR2 while it runs) is ended first, so F -> G succeeds too.
# Environment: CDNCA_NATIVE_UPGRADE_IMAGE (default debian:12).
set -eu

[ "$#" = 1 ] || { echo "usage: $0 <native package .tar.gz | payload dir>" >&2; exit 64; }
input=$1
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
image="${CDNCA_NATIVE_UPGRADE_IMAGE:-debian:12}"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-native-upgrade.XXXXXX")"
cleanup() {
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-native-upgrade.*) chmod -R u+w -- "${workdir}" 2>/dev/null || true; rm -rf -- "${workdir}" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir "${workdir}/payload"
openresty_version=""
if [ -d "${input}" ]; then
  for part in runtime lua; do
    [ -d "${input}/${part}" ] || { echo "payload ${input} lacks ${part}/" >&2; exit 66; }
    cp -RL "${input}/${part}" "${workdir}/payload/${part}"
  done
elif [ -f "${input}" ]; then
  tar -xzf "${input}" -C "${workdir}/payload" runtime lua release.manifest.json
  openresty_version="$(sed -n 's/.*"openresty_version":"\([0-9.]*\)".*/\1/p' "${workdir}/payload/release.manifest.json")"
  rm -f "${workdir}/payload/release.manifest.json"
else
  echo "no such package or payload: ${input}" >&2; exit 66
fi
[ -f "${workdir}/payload/runtime/openresty/nginx/sbin/nginx" ] || { echo "payload has no runtime/openresty/nginx/sbin/nginx" >&2; exit 66; }

# The native runtime is x86_64 (musl, patchelf'd to /opt/cdnca-node/current).
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go -C "${repo_root}/agents/edge-agent" test -c -trimpath -o "${workdir}/nativeruntime.test" ./internal/nativeruntime
chmod -R a+rX "${workdir}"

docker run --rm --init --privileged --platform linux/amd64 --network none \
  --volume "${workdir}:/acceptance:ro" --workdir /tmp \
  --env CDNCA_NATIVE_RUNTIME_REAL=1 --env CDNCA_NATIVE_PAYLOAD_DIR=/acceptance/payload \
  --env CDNCA_NATIVE_OPENRESTY_VERSION="${openresty_version}" \
  "${image}" sh -ec '
    ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service 2>/dev/null || true
    uname -m
    /acceptance/nativeruntime.test -test.v -test.count=1 -test.timeout=10m -test.run "^TestRealNativeRuntimeUpgrade$"
  '
