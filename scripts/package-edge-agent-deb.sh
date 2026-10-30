#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
BUILDER="${ROOT}/infra/packaging/deb/repository.py"
ASSETS="${ROOT}/agents/edge-agent/packaging"
MAINTAINER="${ROOT}/infra/packaging/deb/maintainer"
readonly SCRIPT_DIR ROOT BUILDER ASSETS MAINTAINER

fail() {
  printf 'reason_code=PKG_BUILD_INVALID %s\n' "$*" >&2
  exit 64
}

architecture=''
version=''
release_sequence=''
source_date_epoch=''
artifact=''
sbom=''
manifest=''
manifest_signature=''
release_public_key=''
rollback_key_version=''
output_dir=''

while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || fail "missing value for $1"
  case "$1" in
    --architecture) [ -z "${architecture}" ] || fail 'duplicate architecture'; architecture=$2 ;;
    --version) [ -z "${version}" ] || fail 'duplicate version'; version=$2 ;;
    --release-sequence) [ -z "${release_sequence}" ] || fail 'duplicate release sequence'; release_sequence=$2 ;;
    --source-date-epoch) [ -z "${source_date_epoch}" ] || fail 'duplicate source date epoch'; source_date_epoch=$2 ;;
    --artifact) [ -z "${artifact}" ] || fail 'duplicate artifact'; artifact=$2 ;;
    --sbom) [ -z "${sbom}" ] || fail 'duplicate SBOM'; sbom=$2 ;;
    --manifest) [ -z "${manifest}" ] || fail 'duplicate manifest'; manifest=$2 ;;
    --manifest-signature) [ -z "${manifest_signature}" ] || fail 'duplicate manifest signature'; manifest_signature=$2 ;;
    --release-public-key) [ -z "${release_public_key}" ] || fail 'duplicate release public key'; release_public_key=$2 ;;
    --rollback-key-version) [ -z "${rollback_key_version}" ] || fail 'duplicate rollback key version'; rollback_key_version=$2 ;;
    --output-dir) [ -z "${output_dir}" ] || fail 'duplicate output directory'; output_dir=$2 ;;
    *) fail "unknown argument $1" ;;
  esac
  shift 2
done

for value in architecture version release_sequence source_date_epoch artifact sbom manifest \
  manifest_signature release_public_key rollback_key_version output_dir; do
  [ -n "${!value}" ] || fail "missing ${value//_/-}"
done
for command in openssl python3; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing command ${command}"
done
[ -f "${BUILDER}" ] && [ ! -L "${BUILDER}" ] || fail 'builder is unavailable'
[ -d "${ASSETS}" ] && [ ! -L "${ASSETS}" ] || fail 'packaging assets are unavailable'
[ -d "${MAINTAINER}" ] && [ ! -L "${MAINTAINER}" ] || fail 'maintainer scripts are unavailable'

exec python3 "${BUILDER}" build-package \
  --architecture "${architecture}" \
  --version "${version}" \
  --release-sequence "${release_sequence}" \
  --source-date-epoch "${source_date_epoch}" \
  --artifact "${artifact}" \
  --sbom "${sbom}" \
  --manifest "${manifest}" \
  --manifest-signature "${manifest_signature}" \
  --release-public-key "${release_public_key}" \
  --rollback-key-version "${rollback_key_version}" \
  --assets "${ASSETS}" \
  --maintainer "${MAINTAINER}" \
  --output-dir "${output_dir}"
