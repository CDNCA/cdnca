#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "${script_dir}/lib.sh"

# shellcheck disable=SC2034 # Consumed by root_path in lib.sh.
DESTDIR=
if [ "$#" -gt 0 ]; then
  [ "$#" -eq 2 ] && [ "$1" = --destdir ] || usage_error "usage: $0 [--destdir PATH]"
  set_destdir "$2"
fi

config_path=$(root_path "${CDNCA_EDGE_CONFIG:-/etc/cdnca-edge-agent/config.json}")
assert_safe_tree "${config_path}"
assert_regular_file "${config_path}" "configuration"
mode=$(stat -c '%a' "${config_path}" 2>/dev/null || stat -f '%Lp' "${config_path}")
case "${mode}" in
  400|600) ;;
  *) die "configuration must have mode 0400 or 0600" ;;
esac
preflight_ids=$(runtime_ids)
preflight_uid=${preflight_ids%:*}
[ "$(stat -c '%u' "${config_path}" 2>/dev/null || stat -f '%u' "${config_path}")" = "${preflight_uid}" ] || die "configuration must be owned by the service user"

current_target=$(read_current_target)
current_version=${current_target#versions/}
verify_installed_release "${current_version}"
probe_release_config "$(root_path "/usr/lib/cdnca-edge-agent/${current_target}/edge-agent")" "${config_path}"
