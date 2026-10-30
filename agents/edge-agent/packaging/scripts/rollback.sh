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
      --artifact|--sbom|--manifest|--signature|--public-key|--service-driver|--health-timeout|--health-stable|--version|--confirm-purge)
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
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "${script_dir}/lib.sh"

usage() {
  printf 'usage: %s --version VERSION [--destdir PATH] [--service-driver PATH] [--health-timeout SECONDS] [--health-stable SECONDS]\n' "$0" >&2
  exit 64
}

DESTDIR=
SERVICE_DRIVER=
target_version=
health_timeout=30
health_stable=5
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version|--destdir|--service-driver|--health-timeout|--health-stable)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        --version) target_version=$2 ;;
        --destdir) set_destdir "$2" ;;
        --service-driver) SERVICE_DRIVER=$2 ;;
        --health-timeout) health_timeout=$2 ;;
        --health-stable) health_stable=$2 ;;
      esac
      shift 2
      ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "rollback must run as root"
validate_version "${target_version}"
validate_uint "${health_timeout}" health-timeout
validate_uint "${health_stable}" health-stable
[ "${health_timeout}" -gt 0 ] || usage_error "health-timeout must be greater than zero"
if [ -n "${SERVICE_DRIVER}" ]; then
  [ -n "${DESTDIR}" ] || usage_error "--service-driver is allowed only with --destdir"
  assert_regular_file "${SERVICE_DRIVER}" "service driver"
  [ -x "${SERVICE_DRIVER}" ] || usage_error "service driver must be executable"
fi
package_recovery_only=false
if package_recovery_only_requested "${script_dir}"; then
  package_recovery_only=true
fi

old_target=
old_version=
rollback_exit() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ -e "${PACKAGE_TRANSACTION:-}" ] || [ -L "${PACKAGE_TRANSACTION:-}" ]; then
    if ! (rollback_package_transaction); then
      printf 'cdnca-edge-agent packaging: automatic rollback recovery failed; the journal was retained\n' >&2
      exit "${status}"
    fi
    clear_package_transaction
    if [ "${TX_SERVICE_STOP_INTENT:-0}" = 1 ] && [ -n "${old_version}" ] && \
      ! wait_for_health "${health_timeout}" "${health_stable}"; then
      printf 'cdnca-edge-agent packaging: rollback recovery selected %s but its health check failed\n' "${old_version}" >&2
    fi
  fi
  release_lock
  exit "${status}"
}

acquire_lock
trap rollback_exit EXIT
trap 'exit 1' HUP INT TERM
if [ "${package_recovery_only}" = true ]; then
  release_lock
  trap - EXIT HUP INT TERM
  exit 0
fi
old_target=$(read_current_target)
old_version=${old_target#versions/}
verify_installed_release "${target_version}"
probe_release_version "$(root_path "/usr/lib/cdnca-edge-agent/versions/${target_version}/edge-agent")" "${target_version}"
if [ "${old_version}" = "${target_version}" ]; then
  release_lock
  trap - EXIT HUP INT TERM
  printf 'cdnca-edge-agent %s is already current\n' "${target_version}"
  exit 0
fi

historical_backup=$(last_upgrade_backup_for "${target_version}" "${old_version}")
config_path=$(root_path /etc/cdnca-edge-agent/config.json)
probe_release_config "$(root_path "/usr/lib/cdnca-edge-agent/versions/${target_version}/edge-agent")" "${config_path}"
begin_package_transaction rollback "${old_target}" "${target_version}"
record_transaction_service_stop
service_action stop
backup_state "${old_version}" "${target_version}" rollback-guard
record_transaction_state_backup "${STATE_BACKUP}"
record_transaction_current_switch
restore_state "${historical_backup}" "pre-rollback-${old_version}"
atomic_switch_current "versions/${target_version}"
service_action restart
wait_for_health "${health_timeout}" "${health_stable}" || die "rollback release did not become healthy"
record_transaction_commit
clear_package_transaction
release_lock
trap - EXIT HUP INT TERM
printf 'rolled back cdnca-edge-agent from %s to %s; replaced state retained at %s\n' "${old_version}" "${target_version}" "$(dirname -- "${RESTORE_DISPLACED}")"
