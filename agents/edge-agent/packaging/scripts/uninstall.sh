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
  printf 'usage: %s [--destdir PATH] [--service-driver PATH] [--purge [--non-interactive --confirm-purge DELETE-EDGE-IDENTITY-AND-STATE]]\n' "$0" >&2
  exit 64
}

DESTDIR=
SERVICE_DRIVER=
purge=false
non_interactive=false
confirmation=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --destdir|--service-driver|--confirm-purge)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        --destdir) set_destdir "$2" ;;
        --service-driver) SERVICE_DRIVER=$2 ;;
        --confirm-purge) confirmation=$2 ;;
      esac
      shift 2
      ;;
    --purge) purge=true; shift ;;
    --non-interactive) non_interactive=true; shift ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "uninstall must run as root"
if [ -n "${SERVICE_DRIVER}" ]; then
  [ -n "${DESTDIR}" ] || usage_error "--service-driver is allowed only with --destdir"
  assert_regular_file "${SERVICE_DRIVER}" "service driver"
  [ -x "${SERVICE_DRIVER}" ] || usage_error "service driver must be executable"
fi
if [ "${purge}" = false ] && { [ "${non_interactive}" = true ] || [ -n "${confirmation}" ]; }; then
  usage_error "purge confirmation options require --purge"
fi
if [ "${purge}" = true ]; then
  if [ "${non_interactive}" = true ]; then
    [ "${confirmation}" = DELETE-EDGE-IDENTITY-AND-STATE ] || die "non-interactive purge requires the exact confirmation guard"
  else
    [ -t 0 ] || die "interactive purge requires a terminal; use the guarded non-interactive form"
    printf 'Type DELETE-EDGE-IDENTITY-AND-STATE to purge node identity and state: ' >&2
    IFS= read -r confirmation
    [ "${confirmation}" = DELETE-EDGE-IDENTITY-AND-STATE ] || die "purge confirmation did not match"
  fi
fi
package_recovery_only=false
if package_recovery_only_requested "${script_dir}"; then
  package_recovery_only=true
fi

remove_tree() {
  candidate=$1
  case "${candidate}" in
    */usr/lib/cdnca-edge-agent|*/usr/libexec/cdnca-edge-agent|*/usr/share/doc/cdnca-edge-agent|\
    */etc/cdnca-edge-agent|*/var/lib/cdnca-edge-agent|*/var/lib/cdnca-edge|\
    */var/lib/cdnca-edge-agent-backups|*/var/lib/cdnca-edge-agent-helper|*/var/log/cdnca-edge-agent|\
    */opt/cdnca-node|*/var/lib/cdnca-node-install|*/var/lib/cdnca-node-monitoring) ;;
    *) die "unsafe uninstall target: ${candidate}" ;;
  esac
  assert_safe_tree "${candidate}"
  if [ -e "${candidate}" ] || [ -L "${candidate}" ]; then
    [ -d "${candidate}" ] && [ ! -L "${candidate}" ] || die "uninstall target is not a trusted directory"
    rm -rf --one-file-system -- "${candidate}"
  fi
}

acquire_lock
trap 'release_lock' EXIT
trap 'exit 1' HUP INT TERM
if [ "${package_recovery_only}" = true ]; then
  release_lock
  trap - EXIT HUP INT TERM
  exit 0
fi
service_action stop >/dev/null 2>&1 || die "failed to stop cdnca-edge-agent; package was not removed"
stop_agent_leftovers || die "failed to stop OpenResty left by cdnca-edge-agent; package was not removed"
service_action disable >/dev/null 2>&1 || die "failed to disable cdnca-edge-agent; package was not removed"
validate_retained_state_layout

remove_tree "$(root_path /usr/lib/cdnca-edge-agent)"
remove_tree "$(root_path /usr/libexec/cdnca-edge-agent)"
remove_tree "$(root_path /usr/share/doc/cdnca-edge-agent)"
for package_file in \
  /usr/lib/systemd/system/cdnca-edge-agent.service \
  /usr/lib/sysusers.d/cdnca-edge-agent.conf \
  /usr/lib/tmpfiles.d/cdnca-edge-agent.conf \
  /etc/logrotate.d/cdnca-edge-agent; do
  target=$(root_path "${package_file}")
  assert_safe_tree "$(dirname -- "${target}")"
  [ ! -L "${target}" ] || die "package metadata target is a symbolic link"
  rm -f -- "${target}"
done

if [ "${purge}" = true ]; then
  # Units a native install (scripts/install-node.sh start_packaging_helper and
  # systemd_compat_apply) adds beside the packaged Agent unit. Left behind they
  # make the next first install refuse the host ("existing service").
  # tests/node-uninstall-units.test.mjs keeps these lists equal to the installer's.
  helper_units='cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket'
  compat_units='cdnca-edge-agent.service cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket'
  if [ -z "${SERVICE_DRIVER}" ] && [ -z "${DESTDIR}" ]; then
    # shellcheck disable=SC2086
    systemctl stop ${helper_units} >/dev/null 2>&1 || true
    systemctl disable cdnca-edge-agent-helper.socket >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    ! systemctl is-active --quiet ${helper_units} || die "failed to stop the packaging helper; state was not purged"
  fi
  for unit in ${helper_units}; do
    target=$(root_path "/usr/lib/systemd/system/${unit}")
    assert_safe_tree "$(dirname -- "${target}")"
    [ ! -L "${target}" ] || die "helper unit target is a symbolic link"
    rm -f -- "${target}"
  done
  for unit in ${compat_units}; do
    dropin_dir=$(root_path "/etc/systemd/system/${unit}.d")
    assert_safe_tree "${dropin_dir}"
    [ ! -L "${dropin_dir}/zz-cdnca-systemd-compat.conf" ] || die "systemd drop-in target is a symbolic link"
    rm -f -- "${dropin_dir}/zz-cdnca-systemd-compat.conf"
    rmdir -- "${dropin_dir}" 2>/dev/null || true
  done
  socket_wants=$(root_path /etc/systemd/system/sockets.target.wants/cdnca-edge-agent-helper.socket)
  assert_safe_tree "$(dirname -- "${socket_wants}")"
  if [ -L "${socket_wants}" ]; then rm -f -- "${socket_wants}"; fi
  # Native release tree, install record and the links into it
  # (install-node.sh activate_native_package); links are removed only while
  # they still point where activation put them.
  for native_link in \
    /usr/local/openresty:/opt/cdnca-node/current/runtime/openresty \
    /usr/local/share/cdnca:/opt/cdnca-node/current/lua/share/cdnca \
    /opt/cdnca/l4geo:/opt/cdnca-node/current/lua/l4geo; do
    target=$(root_path "${native_link%%:*}")
    assert_safe_tree "$(dirname -- "${target}")"
    if [ -L "${target}" ] && [ "$(readlink -- "${target}")" = "${native_link#*:}" ]; then rm -f -- "${target}"; fi
  done
  remove_tree "$(root_path /opt/cdnca-node)"
  remove_tree "$(root_path /var/lib/cdnca-node-install)"
  remove_tree "$(root_path /var/lib/cdnca-node-monitoring)"
  helper_binary=$(root_path /usr/libexec/cdnca-edge-agent-helper)
  assert_safe_tree "${helper_binary}"
  [ ! -L "${helper_binary}" ] || die "packaging helper binary is a symbolic link"
  rm -f -- "${helper_binary}"
  remove_tree "$(root_path /var/lib/cdnca-edge-agent-helper)"
  remove_tree "$(root_path /etc/cdnca-edge-agent)"
  remove_tree "$(root_path /var/lib/cdnca-edge-agent)"
  remove_tree "$(root_path /var/lib/cdnca-edge)"
  remove_tree "$(root_path /var/lib/cdnca-edge-agent-backups)"
  remove_tree "$(root_path /var/log/cdnca-edge-agent)"
  accepted_manifest=$(root_path /var/lib/cdnca-edge-agent-packaging/accepted-manifest)
  assert_safe_tree "${accepted_manifest}"
  [ ! -L "${accepted_manifest}" ] || die "accepted manifest is a symbolic link"
  rm -f -- "${accepted_manifest}"
  runtime_identity_marker=$(root_path "${RUNTIME_IDENTITY_MARKER}")
  assert_safe_tree "${runtime_identity_marker}"
  [ ! -L "${runtime_identity_marker}" ] || die "runtime identity marker is a symbolic link"
  rm -f -- "${runtime_identity_marker}"
fi

service_action daemon-reload >/dev/null 2>&1 || true
[ "${purge}" = false ] || REMOVE_PACKAGE_LOCK=true
release_lock
if [ "${purge}" = true ]; then
  rmdir "$(root_path /var/lib/cdnca-edge-agent-packaging)" || die "package state contains unexpected files"
fi
trap - EXIT HUP INT TERM
if [ "${purge}" = true ]; then
  printf 'purged cdnca-edge-agent package, identity, state, backups, and logs\n'
else
  printf 'uninstalled cdnca-edge-agent package; identity, state, backups, and logs were retained\n'
fi
