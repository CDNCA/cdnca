#!/bin/sh
set -eu

usage() {
  echo "usage: $0 --destdir ABSOLUTE_NON_ROOT_PATH" >&2
}

destdir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --destdir)
      [ "$#" -ge 2 ] || { usage; exit 64; }
      destdir="$2"
      shift 2
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done

case "${destdir}" in
  /*) ;;
  *) usage; exit 64 ;;
esac
case "${destdir}" in
  /|*/../*|*/./*)
    echo "--destdir must be a clean non-root path" >&2
    exit 64
    ;;
esac

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
install -d -m 0755 "${destdir}/etc/systemd/system"
install -d -m 0755 "${destdir}/usr/lib/tmpfiles.d"
install -d -m 0755 "${destdir}/usr/share/doc/cdnca-edge"
install -m 0644 "${repo_root}/infra/systemd/cdnca-openresty.service" "${destdir}/etc/systemd/system/cdnca-openresty.service"
install -m 0644 "${repo_root}/infra/systemd/cdnca-edge.conf" "${destdir}/usr/lib/tmpfiles.d/cdnca-edge.conf"
install -m 0644 "${repo_root}/edge/openresty/README.md" "${destdir}/usr/share/doc/cdnca-edge/openresty-runtime.md"

echo "staged systemd packaging under ${destdir}"
