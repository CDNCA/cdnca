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
      --artifact|--sbom|--manifest|--signature|--public-key|--service-driver|--health-timeout|--health-stable|--version|--confirm-purge|--runtime-identity|--native)
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
if [ -f "${script_dir}/assets/systemd/cdnca-edge-agent.service" ]; then
  packaging_root=${script_dir}/assets
else
  packaging_root=$(CDPATH='' cd -- "${script_dir}/.." && pwd -P)
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "${script_dir}/lib.sh"

usage() {
  printf 'usage: %s --artifact PATH --sbom PATH --manifest PATH --signature PATH --public-key PATH [--destdir PATH] [--upgrade] [--runtime-identity cdnca-edge|root] [--service-driver PATH] [--health-timeout SECONDS] [--health-stable SECONDS] [--native PATH]\n' "$0" >&2
  exit 64
}

DESTDIR=
SERVICE_DRIVER=
artifact=
sbom=
manifest=
signature=
public_key=
# Native node package (v2 bundle section): kept beside the Agent release as
# native.tar.gz; the Agent verifies and switches /opt/cdnca-node at start.
native_package=
upgrade=false
requested_runtime_identity=
health_timeout=30
health_stable=5
while [ "$#" -gt 0 ]; do
  case "$1" in
    --artifact|--sbom|--manifest|--signature|--public-key|--destdir|--service-driver|--health-timeout|--health-stable|--runtime-identity|--native)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        --native) native_package=$2 ;;
        --runtime-identity) requested_runtime_identity=$2 ;;
        --artifact) artifact=$2 ;;
        --sbom) sbom=$2 ;;
        --manifest) manifest=$2 ;;
        --signature) signature=$2 ;;
        --public-key) public_key=$2 ;;
        --destdir) set_destdir "$2" ;;
        --service-driver) SERVICE_DRIVER=$2 ;;
        --health-timeout) health_timeout=$2 ;;
        --health-stable) health_stable=$2 ;;
      esac
      shift 2
      ;;
    --upgrade) upgrade=true; shift ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "installation must run as root"
validate_uint "${health_timeout}" health-timeout
validate_uint "${health_stable}" health-stable
[ "${health_timeout}" -gt 0 ] || usage_error "health-timeout must be greater than zero"
if [ -n "${SERVICE_DRIVER}" ]; then
  [ -n "${DESTDIR}" ] || usage_error "--service-driver is allowed only with --destdir"
  validate_absolute_path "${SERVICE_DRIVER}" || usage_error "service driver path must be absolute and clean"
  assert_regular_file "${SERVICE_DRIVER}" "service driver"
  [ -x "${SERVICE_DRIVER}" ] || usage_error "service driver must be executable"
fi
package_recovery_only=false
if package_recovery_only_requested "${script_dir}"; then
  package_recovery_only=true
fi
case "${requested_runtime_identity}" in
  ''|cdnca-edge|root) ;;
  *) usage_error "runtime identity must be cdnca-edge or root" ;;
esac
# The marker is authoritative only once a release is current. A fresh install
# takes the requested identity (default cdnca-edge); every later operation
# inherits the recorded one and an explicit request must match it.
load_runtime_identity
recorded_runtime_identity=${PACKAGE_RUNTIME_IDENTITY}
runtime_identity_write=false
if [ "${upgrade}" = true ]; then
  [ -z "${requested_runtime_identity}" ] || usage_error "--runtime-identity is fixed at first install"
elif [ -e "$(root_path /usr/lib/cdnca-edge-agent/current)" ] || [ -L "$(root_path /usr/lib/cdnca-edge-agent/current)" ]; then
  [ -z "${requested_runtime_identity}" ] || [ "${requested_runtime_identity}" = "${recorded_runtime_identity}" ] || \
    die "installed runtime identity ${recorded_runtime_identity} differs from the requested ${requested_runtime_identity}"
else
  PACKAGE_RUNTIME_IDENTITY=${requested_runtime_identity:-cdnca-edge}
  [ "${PACKAGE_RUNTIME_IDENTITY}" = "${recorded_runtime_identity}" ] || runtime_identity_write=true
fi
if [ "${PACKAGE_RUNTIME_IDENTITY}" = root ]; then
  unit_source_relative=systemd/cdnca-edge-agent-root.service
  tmpfiles_source_relative=tmpfiles/cdnca-edge-agent-root.conf
else
  unit_source_relative=systemd/cdnca-edge-agent.service
  tmpfiles_source_relative=tmpfiles/cdnca-edge-agent.conf
fi

# Trust and compatibility checks intentionally precede lock or filesystem writes.
require_supported_host
record_bundle_fingerprints "${artifact}" "${sbom}" "${manifest}" "${signature}" "${public_key}"
if [ -n "${native_package}" ]; then
  verify_native_input "${native_package}"
  NATIVE_PACKAGE_SHA256=$(sha256_file "${native_package}")
fi
verify_bundle "${artifact}" "${sbom}" "${manifest}" "${signature}" "${public_key}"
assert_bundle_fingerprints "${artifact}" "${sbom}" "${manifest}" "${signature}" "${public_key}"
check_release_replay

package_root=$(root_path /usr/lib/cdnca-edge-agent)
current_path=${package_root}/current
config_path=$(root_path /etc/cdnca-edge-agent/config.json)
pinned_key=$(root_path /etc/cdnca-edge-agent/package-signing.pem)
assert_safe_tree "${pinned_key}"
if [ -e "${pinned_key}" ] || [ -L "${pinned_key}" ]; then
  assert_regular_file "${pinned_key}" "pinned package public key"
  cmp -s "${public_key}" "${pinned_key}" || die "package public key differs from the pinned key"
elif [ "${upgrade}" = true ]; then
  die "upgrade requires a pinned package public key"
fi
probe_candidate_version "${artifact}" "${VERIFIED_VERSION}"
if [ "${upgrade}" = true ]; then
  [ -f "${config_path}" ] && [ ! -L "${config_path}" ] || die "upgrade requires an enrolled config.json"
  probe_release_config "${artifact}" "${config_path}"
fi
assert_bundle_fingerprints "${artifact}" "${sbom}" "${manifest}" "${signature}" "${public_key}"
old_target=
old_version=

upgrade_failure() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  cleanup_state_staging
  cleanup_transaction_staging
  transaction_recovered=false
  if [ -e "${PACKAGE_TRANSACTION:-}" ] || [ -L "${PACKAGE_TRANSACTION:-}" ]; then
    if ! (rollback_package_transaction); then
      printf 'cdnca-edge-agent packaging: automatic transaction recovery failed; the journal was retained\n' >&2
      exit "${status}"
    fi
    clear_package_transaction
    transaction_recovered=true
  fi
  layout_recovered=false
  if state_layout_migration_pending; then
    if ! (recover_incomplete_state_layout_migration); then
      printf 'cdnca-edge-agent packaging: automatic state layout recovery failed; the journal was retained\n' >&2
      exit "${status}"
    fi
    layout_recovered=true
  fi
  if [ "${transaction_recovered}" = true ] && [ "${layout_recovered}" = false ] && \
    [ "${TX_SERVICE_STOP_INTENT:-0}" = 1 ] && [ -n "${old_version}" ] && \
    ! wait_for_health "${health_timeout}" "${health_stable}"; then
    printf 'cdnca-edge-agent packaging: automatic rollback selected %s but its health check failed\n' "${old_version}" >&2
  fi
  release_lock
  exit "${status}"
}

acquire_lock
trap upgrade_failure EXIT
trap 'exit 1' HUP INT TERM
if [ "${package_recovery_only}" = true ]; then
  release_lock
  trap - EXIT HUP INT TERM
  exit 0
fi

stage_bundle_inputs "${artifact}" "${sbom}" "${manifest}" "${signature}" "${public_key}"
artifact=${STAGED_ARTIFACT}
sbom=${STAGED_SBOM}
manifest=${STAGED_MANIFEST}
signature=${STAGED_SIGNATURE}
public_key=${STAGED_PUBLIC_KEY}
if [ -n "${native_package}" ]; then
  stage_native_input "${native_package}"
  native_package=${STAGED_NATIVE}
fi
verify_bundle "${artifact}" "${sbom}" "${manifest}" "${signature}" "${public_key}"
check_release_replay
if [ -e "${pinned_key}" ] || [ -L "${pinned_key}" ]; then
  assert_regular_file "${pinned_key}" "pinned package public key"
  cmp -s "${public_key}" "${pinned_key}" || die "package public key differs from the pinned key"
elif [ "${upgrade}" = true ]; then
  die "upgrade requires a pinned package public key"
fi
probe_candidate_version "${artifact}" "${VERIFIED_VERSION}"
if [ "${upgrade}" = true ]; then
  probe_release_config "${artifact}" "${config_path}"
fi

assert_safe_tree "${package_root}"
if [ "${upgrade}" = true ]; then
  old_target=$(read_current_target)
  old_version=${old_target#versions/}
else
  if [ -e "${current_path}" ] || [ -L "${current_path}" ]; then
    old_target=$(read_current_target)
    old_version=${old_target#versions/}
    [ "${old_version}" = "${VERIFIED_VERSION}" ] || die "a different release is installed; use upgrade.sh"
  fi
fi

if [ "${upgrade}" = true ] && state_layout_needs_migration; then
  [ "${PACKAGE_RUNTIME_IDENTITY}" = cdnca-edge ] || die "root runtime identity requires the completed state layout"
  service_action stop
  begin_state_layout_migration "$(root_path /usr/lib/systemd/system/cdnca-edge-agent.service)" \
    "${packaging_root}/systemd/cdnca-edge-agent.service"
  install_atomic_metadata "${packaging_root}/systemd/cdnca-edge-agent.service" \
    "$(root_path /usr/lib/systemd/system/cdnca-edge-agent.service)" 0644
  record_state_layout_unit_installed
  activate_state_layout_migration "${health_timeout}" "${health_stable}"
  commit_state_layout_migration
fi
begin_package_transaction "$(if [ "${upgrade}" = true ]; then printf upgrade; else printf install; fi)" \
  "${old_target}" "${VERIFIED_VERSION}"

metadata_files='systemd/cdnca-edge-agent.service sysusers/cdnca-edge-agent.conf tmpfiles/cdnca-edge-agent.conf logrotate/cdnca-edge-agent config/agent.env config/config.example.json scripts/install.sh scripts/lib.sh scripts/preflight.sh scripts/rollback.sh scripts/uninstall.sh scripts/upgrade.sh README.md'
for relative in ${metadata_files}; do
  source=${packaging_root}/${relative}
  case "${relative}" in
    systemd/cdnca-edge-agent.service) source=${packaging_root}/${unit_source_relative} ;;
    tmpfiles/cdnca-edge-agent.conf) source=${packaging_root}/${tmpfiles_source_relative} ;;
  esac
  case "${relative}" in
    systemd/*) destination=$(root_path "/usr/lib/systemd/system/${relative#systemd/}"); mode=0644 ;;
    sysusers/*) destination=$(root_path "/usr/lib/sysusers.d/${relative#sysusers/}"); mode=0644 ;;
    tmpfiles/*) destination=$(root_path "/usr/lib/tmpfiles.d/${relative#tmpfiles/}"); mode=0644 ;;
    logrotate/*) destination=$(root_path "/etc/logrotate.d/${relative#logrotate/}"); mode=0644 ;;
    config/agent.env) destination=$(root_path /etc/cdnca-edge-agent/agent.env); mode=0600 ;;
    config/*) destination=$(root_path "/usr/share/doc/cdnca-edge-agent/${relative#config/}"); mode=0644 ;;
    scripts/*) destination=$(root_path "/usr/libexec/cdnca-edge-agent/${relative#scripts/}"); source=${script_dir}/${relative#scripts/}; mode=0555 ;;
    README.md) destination=$(root_path /usr/share/doc/cdnca-edge-agent/README.md); mode=0644 ;;
  esac
  assert_safe_tree "$(dirname -- "${destination}")"
  [ ! -L "${destination}" ] || die "package metadata target is a symbolic link"
  if [ "${source}" = "${destination}" ]; then
    continue
  fi
  if [ "${relative}" = config/agent.env ] && { [ -e "${destination}" ] || [ -L "${destination}" ]; }; then
    assert_regular_file "${destination}" "existing environment file"
  else
    install_atomic_metadata "${source}" "${destination}" "${mode}"
  fi
  if [ "${relative}" = systemd/cdnca-edge-agent.service ]; then
    record_state_layout_unit_installed
  fi
done

asset_root=$(root_path /usr/libexec/cdnca-edge-agent/assets)
if [ "${packaging_root}" != "${asset_root}" ]; then
  for relative in \
    systemd/cdnca-edge-agent.service \
    systemd/cdnca-edge-agent-root.service \
    sysusers/cdnca-edge-agent.conf \
    tmpfiles/cdnca-edge-agent.conf \
    tmpfiles/cdnca-edge-agent-root.conf \
    logrotate/cdnca-edge-agent \
    config/agent.env \
    config/config.example.json \
    README.md; do
    asset_parent=$(dirname -- "${relative}")
    if [ "${asset_parent}" = . ]; then
      asset_parent=${asset_root}
    else
      asset_parent=${asset_root}/${asset_parent}
    fi
    assert_safe_tree "${asset_parent}"
    install_atomic_metadata "${packaging_root}/${relative}" "${asset_root}/${relative}" 0644
  done
fi

install_runtime_layout
pin_or_check_public_key "${public_key}"
install_system_account_layout
establish_completed_state_layout
release_path=${package_root}/versions/${VERIFIED_VERSION}
if [ -e "${release_path}" ] || [ -L "${release_path}" ]; then
  record_transaction_release false
else
  record_transaction_release true
fi
install_release "${artifact}" "${sbom}" "${manifest}" "${signature}" "${native_package}"
failpoint_sigkill after-release-install
probe_release_version "${package_root}/versions/${VERIFIED_VERSION}/edge-agent" "${VERIFIED_VERSION}"

if [ "${upgrade}" = false ]; then
  if [ -z "${old_target}" ]; then
    record_transaction_current_switch
    atomic_switch_current "versions/${VERIFIED_VERSION}"
  fi
  service_action daemon-reload
  if [ "${runtime_identity_write}" = true ]; then
    write_runtime_identity "${PACKAGE_RUNTIME_IDENTITY}"
  fi
  record_transaction_commit
  publish_accepted_manifest
  commit_state_layout_migration
  clear_package_transaction
  release_lock
  trap - EXIT HUP INT TERM
  printf 'installed cdnca-edge-agent %s; enroll the node before enabling the service\n' "${VERIFIED_VERSION}"
  exit 0
fi

[ "${old_version}" != "${VERIFIED_VERSION}" ] || {
  verify_installed_release "${VERIFIED_VERSION}"
  service_action daemon-reload
  record_transaction_commit
  publish_accepted_manifest
  commit_state_layout_migration
  clear_package_transaction
  release_lock
  trap - EXIT HUP INT TERM
  printf 'cdnca-edge-agent %s is already current\n' "${VERIFIED_VERSION}"
  exit 0
}

probe_release_config "${package_root}/versions/${VERIFIED_VERSION}/edge-agent" "${config_path}"
record_transaction_service_stop
service_action stop
backup_state "${old_version}" "${VERIFIED_VERSION}" upgrade
record_transaction_state_backup "${STATE_BACKUP}"
record_transaction_current_switch
atomic_switch_current "versions/${VERIFIED_VERSION}"
failpoint_sigkill after-current-switch
service_action daemon-reload
service_action restart
wait_for_health "${health_timeout}" "${health_stable}" || die "new release did not become healthy"
publish_last_upgrade_backup
record_transaction_commit
publish_accepted_manifest
commit_state_layout_migration
clear_package_transaction
release_lock
trap - EXIT HUP INT TERM
printf 'upgraded cdnca-edge-agent from %s to %s; state backup: %s\n' "${old_version}" "${VERIFIED_VERSION}" "${STATE_BACKUP}"
