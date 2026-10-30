#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-install.XXXXXX")"
cleanup() {
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-install.*) rm -rf -- "${workdir}" ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

"${repo_root}/scripts/edge-runtime-install.sh" --destdir "${workdir}/root"
cmp "${repo_root}/infra/systemd/cdnca-openresty.service" "${workdir}/root/etc/systemd/system/cdnca-openresty.service"
installed_unit="${workdir}/root/etc/systemd/system/cdnca-openresty.service"
grep -Fx 'NoNewPrivileges=yes' "${installed_unit}" >/dev/null
grep -Fx 'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_PERFMON' "${installed_unit}" >/dev/null
grep -Fx 'AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_PERFMON' "${installed_unit}" >/dev/null
if grep -F 'CAP_SYS_ADMIN' "${installed_unit}" >/dev/null; then
  echo "OpenResty unit must not receive CAP_SYS_ADMIN" >&2
  exit 1
fi
cmp "${repo_root}/infra/systemd/cdnca-edge.conf" "${workdir}/root/usr/lib/tmpfiles.d/cdnca-edge.conf"
cmp "${repo_root}/edge/openresty/README.md" "${workdir}/root/usr/share/doc/cdnca-edge/openresty-runtime.md"
test "$(find "${workdir}/root" -type f | wc -l | tr -d ' ')" = "3"
echo "systemd packaging staging verified"
