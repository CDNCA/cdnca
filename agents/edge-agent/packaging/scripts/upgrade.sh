#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
bootstrap_transaction_recovery() {
  bootstrap_destdir=
  bootstrap_destdir_seen=false
  bootstrap_value=
  for bootstrap_argument do
    if [ -n "${bootstrap_value}" ]; then
      if [ "${bootstrap_value}" = destdir ]; then
        bootstrap_destdir=${bootstrap_argument}
      fi
      bootstrap_value=
      continue
    fi
    case "${bootstrap_argument}" in
      --destdir) bootstrap_destdir_seen=true; bootstrap_value=destdir ;;
      --artifact|--sbom|--manifest|--signature|--public-key|--service-driver|--health-timeout|--health-stable|--version|--confirm-purge|--native)
        bootstrap_value=other
        ;;
    esac
  done
  if [ "${bootstrap_value}" = destdir ]; then
    printf 'cdnca-edge-agent packaging: DESTDIR must be an absolute clean path\n' >&2
    exit 64
  fi
  bootstrap_root=
  if [ "${bootstrap_destdir_seen}" = true ]; then
    case "${bootstrap_destdir}" in
      /) ;;
      /*)
        case "${bootstrap_destdir}" in
          *//*|*/./*|*/../*|*/.|*/..|*/)
            printf 'cdnca-edge-agent packaging: DESTDIR must be an absolute clean path\n' >&2
            exit 64
            ;;
        esac
        bootstrap_root=${bootstrap_destdir}
        ;;
      *)
        printf 'cdnca-edge-agent packaging: DESTDIR must be an absolute clean path\n' >&2
        exit 64
        ;;
    esac
  fi
  bootstrap_recovery_dir=${bootstrap_root}/var/lib/cdnca-edge-agent-packaging/transaction/recovery
  [ "${script_dir}" != "${bootstrap_recovery_dir}" ] || return 0
  [ -e "${bootstrap_recovery_dir}" ] || [ -L "${bootstrap_recovery_dir}" ] || return 0
  bootstrap_script=${bootstrap_recovery_dir}/${0##*/}
  bootstrap_physical=$(CDPATH='' cd -- "${bootstrap_recovery_dir}" 2>/dev/null && pwd -P) || bootstrap_physical=
  if [ "${bootstrap_physical}" != "${bootstrap_recovery_dir}" ] ||
    [ ! -d "${bootstrap_recovery_dir}" ] || [ -L "${bootstrap_recovery_dir}" ] ||
    [ "$(stat -c '%u:%g:%a' "${bootstrap_recovery_dir}" 2>/dev/null || :)" != 0:0:700 ] ||
    [ ! -f "${bootstrap_script}" ] || [ -L "${bootstrap_script}" ] ||
    [ "$(stat -c '%u:%g:%a:%h' "${bootstrap_script}" 2>/dev/null || :)" != 0:0:555:1 ] ||
    [ ! -f "${bootstrap_recovery_dir}/lib.sh" ] || [ -L "${bootstrap_recovery_dir}/lib.sh" ] ||
    [ "$(stat -c '%u:%g:%a:%h' "${bootstrap_recovery_dir}/lib.sh" 2>/dev/null || :)" != 0:0:555:1 ]; then
    printf 'cdnca-edge-agent packaging: transaction recovery toolset is unsafe\n' >&2
    exit 1
  fi
  CDNCA_PACKAGE_RECOVERY_ONLY=1 "${bootstrap_script}" "$@"
  unset CDNCA_PACKAGE_RECOVERY_ONLY
  exec "${script_dir}/${0##*/}" "$@"
}
bootstrap_transaction_recovery "$@"
exec "${script_dir}/install.sh" --upgrade "$@"
