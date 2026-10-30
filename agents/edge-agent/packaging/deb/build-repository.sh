#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGING_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
REPO_ROOT="$(cd -- "${PACKAGING_ROOT}/../../.." && pwd -P)"
PACKAGE_BUILDER="${REPO_ROOT}/scripts/package-edge-agent-deb.sh"
RELEASE_SET_VALIDATOR="${SCRIPT_DIR}/validate-release-set.sh"
readonly SCRIPT_DIR PACKAGING_ROOT REPO_ROOT PACKAGE_BUILDER RELEASE_SET_VALIDATOR

fail() { printf 'edge apt repository build: %s\n' "$1" >&2; exit 1; }
sha256_file() { sha256sum -- "$1" | awk '{print $1}'; }
file_size() { stat -c '%s' -- "$1"; }
require_regular() { [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || fail "unsafe input: $1"; }

config=''
output_dir=''
release_private_key=''
release_public_key=''
apt_homedir=''
apt_key_id=''
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || fail "missing value for $1"
  case "$1" in
    --config) [ -z "${config}" ] || fail 'duplicate config'; config=$2 ;;
    --output-dir) [ -z "${output_dir}" ] || fail 'duplicate output directory'; output_dir=$2 ;;
    --release-private-key) [ -z "${release_private_key}" ] || fail 'duplicate release private key'; release_private_key=$2 ;;
    --release-public-key) [ -z "${release_public_key}" ] || fail 'duplicate release public key'; release_public_key=$2 ;;
    --apt-homedir) [ -z "${apt_homedir}" ] || fail 'duplicate apt homedir'; apt_homedir=$2 ;;
    --apt-key-id) [ -z "${apt_key_id}" ] || fail 'duplicate apt key ID'; apt_key_id=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done

for value in config output_dir release_private_key release_public_key apt_homedir apt_key_id; do
  [ -n "${!value}" ] || fail "missing ${value//_/-}"
done
case "${output_dir}" in /*) ;; *) fail 'output directory must be absolute' ;; esac
[ ! -e "${output_dir}" ] && [ ! -L "${output_dir}" ] || fail 'output already exists'
require_regular "${config}"
require_regular "${release_private_key}"
require_regular "${release_public_key}"
[ -d "${apt_homedir}" ] && [ ! -L "${apt_homedir}" ] || fail 'unsafe apt homedir'
[[ "${apt_key_id}" =~ ^[0-9A-Fa-f]{40}$ ]] || fail 'apt key ID must be a full fingerprint'
apt_key_id=${apt_key_id^^}

for command in awk chmod date dpkg dpkg-deb find gpg gpgv gzip install jq mkdir mktemp mv openssl paste perl rm rmdir sed sha256sum sort stat touch; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing command: ${command}"
done
[ -f "${PACKAGE_BUILDER}" ] && [ ! -L "${PACKAGE_BUILDER}" ] && [ -x "${PACKAGE_BUILDER}" ] ||
  fail 'package builder is unavailable'
[ -f "${RELEASE_SET_VALIDATOR}" ] && [ ! -L "${RELEASE_SET_VALIDATOR}" ] && [ -x "${RELEASE_SET_VALIDATOR}" ] ||
  fail 'release-set validator is unavailable'

jq -e '
  keys == ["component","label","origin","releases","rollback_key_version","schema","source_date_epoch","suite","valid_until_epoch"] and
  .schema == "cdnca.edge.apt-repository/v1" and
  (.suite | test("^[a-z][a-z0-9-]{0,31}$")) and
  (.component | test("^[a-z][a-z0-9-]{0,31}$")) and
  (.origin | type == "string" and length >= 1 and length <= 64 and test("^[A-Za-z0-9 ._-]+$")) and
  (.label | type == "string" and length >= 1 and length <= 64 and test("^[A-Za-z0-9 ._-]+$")) and
  (.source_date_epoch | type) == "number" and
  .source_date_epoch == (.source_date_epoch | floor) and
  .source_date_epoch >= 100000000 and
  (.valid_until_epoch | type) == "number" and
  .valid_until_epoch == (.valid_until_epoch | floor) and
  .valid_until_epoch > 100000000 and
  .valid_until_epoch > .source_date_epoch and
  (.valid_until_epoch - .source_date_epoch) <= 2678400 and
  (.rollback_key_version | type) == "number" and
  .rollback_key_version == (.rollback_key_version | floor) and
  .rollback_key_version >= 1 and .rollback_key_version <= 9223372036854775807 and
  (.releases | type == "array" and length >= 1) and
  all(.releases[];
    keys == ["arch","path","release_sequence"] and
    (.arch == "amd64" or .arch == "arm64") and
    (.path | type == "string" and startswith("/") and length <= 1024 and
      (contains("\n") or contains("\r") or contains("\t")) | not) and
    (.release_sequence | type) == "number" and
    .release_sequence == (.release_sequence | floor) and
    .release_sequence >= 1 and .release_sequence <= 18446744073709551615)
' "${config}" >/dev/null || fail 'invalid repository config'
source_date_epoch=$(jq -er '.source_date_epoch' "${config}")
valid_until_epoch=$(jq -er '.valid_until_epoch' "${config}")
suite=$(jq -er '.suite' "${config}")
component=$(jq -er '.component' "${config}")
origin=$(jq -er '.origin' "${config}")
label=$(jq -er '.label' "${config}")
rollback_key_version=$(jq -er '.rollback_key_version' "${config}")

gpg --batch --homedir "${apt_homedir}" --list-secret-keys "${apt_key_id}" >/dev/null 2>&1 || fail 'apt signing secret key is unavailable'
actual_fingerprint=$(gpg --batch --homedir "${apt_homedir}" --with-colons --fingerprint "${apt_key_id}" |
  awk -F: '$1 == "fpr" {print toupper($10); exit}')
[ "${actual_fingerprint}" = "${apt_key_id}" ] || fail 'apt signing key fingerprint mismatch'

output_parent=${output_dir%/*}
[ "${output_parent}" != "${output_dir}" ] || output_parent=/
[ -d "${output_parent}" ] && [ ! -L "${output_parent}" ] || fail 'unsafe output parent'
work=$(mktemp -d "${output_parent}/.edge-apt-repository.XXXXXX") || fail 'create repository staging'
cleanup() { rm -rf -- "${work}"; }
trap cleanup EXIT
publish=${work}/publish
mkdir -p "${publish}/pool/${component}/c/cdnca-edge-agent" "${publish}/dists/${suite}/${component}"
packages_dir=${work}/packages
mkdir "${packages_dir}"
packages_manifest=${work}/packages.tsv
: >"${packages_manifest}"

while IFS=$'\t' read -r release_sequence arch release_dir; do
  [ -d "${release_dir}" ] && [ ! -L "${release_dir}" ] || fail "unsafe release directory: ${release_dir}"
  artifact=${release_dir}/edge-agent
  sbom=${release_dir}/edge-agent.spdx.json
  provenance=${release_dir}/edge-agent.provenance.json
  require_regular "${artifact}"
  require_regular "${sbom}"
  require_regular "${provenance}"
  [ -x "${artifact}" ] || fail "release artifact is not executable: ${release_dir}"
  version=$(jq -er '.version' "${provenance}")
  jq -e --arg arch "${arch}" --arg artifact_sha "$(sha256_file "${artifact}")" \
    --argjson artifact_size "$(file_size "${artifact}")" --arg sbom_sha "$(sha256_file "${sbom}")" '
    .schema == "cdnca.edge.release-provenance/v1" and .arch == $arch and
    .artifact.path == "edge-agent" and .artifact.sha256 == $artifact_sha and
    .artifact.size == $artifact_size and .sbom.path == "edge-agent.spdx.json" and
    .sbom.sha256 == $sbom_sha and
    (.version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$")) and
    (.source_repository | test("^https://[A-Za-z0-9._/-]+$")) and
    (.source_commit | test("^[0-9a-f]{40}$")) and
    (.created | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  ' "${provenance}" >/dev/null || fail "release provenance mismatch: ${release_dir}"
  machine=62
  [ "${arch}" = arm64 ] && machine=183
  perl -e '
    my ($path,$machine)=@ARGV;
    open my $in, "<:raw", $path or exit 1;
    read($in, my $header, 20) == 20 or exit 1;
    exit 1 unless substr($header,0,7) eq "\x7fELF\x02\x01\x01";
    exit 1 unless unpack("v", substr($header,18,2)) == $machine;
  ' "${artifact}" "${machine}" || fail "release ELF architecture mismatch: ${release_dir}"

  debian_version=$(perl -e '$v=shift; $v =~ s/-/~/; print "$v-1"' "${version}")
  dpkg --validate-version "${debian_version}" >/dev/null 2>&1 || fail "invalid Debian version derived from ${version}"
  if awk -F '\t' -v a="${arch}" -v v="${debian_version}" '$1 == a && $2 == v {found=1} END {exit !found}' "${packages_manifest}"; then
    fail "duplicate package version and architecture: ${debian_version}/${arch}"
  fi

  manifest_dir=${work}/manifest-${arch}-${release_sequence}
  mkdir "${manifest_dir}"
  manifest=${manifest_dir}/manifest
  manifest_signature=${manifest_dir}/manifest.sig
  artifact_sha=$(sha256_file "${artifact}")
  artifact_size=$(file_size "${artifact}")
  sbom_sha=$(sha256_file "${sbom}")
  sbom_size=$(file_size "${sbom}")
  source_repository=$(jq -er '.source_repository' "${provenance}")
  source_commit=$(jq -er '.source_commit' "${provenance}")
  build_time=$(jq -er '.created' "${provenance}")
  printf 'manifest_version=2\nrelease_sequence=%s\nversion=%s\nartifact_path=edge-agent\nartifact_sha256=%s\nartifact_size=%s\nsbom_path=edge-agent.spdx.json\nsbom_sha256=%s\nsbom_size=%s\nos=linux\narch=%s\nsource_repository=%s\nsource_commit=%s\nbuild_time=%s\nminimum_control_protocol=1.0\nminimum_agent_protocol=1.0\n' \
    "${release_sequence}" "${version}" "${artifact_sha}" "${artifact_size}" "${sbom_sha}" "${sbom_size}" \
    "${arch}" "${source_repository}" "${source_commit}" "${build_time}" >"${manifest}"
  openssl pkeyutl -sign -inkey "${release_private_key}" -rawin -in "${manifest}" \
    -out "${manifest_signature}" || fail "sign release manifest: ${version}/${arch}"
  openssl pkeyutl -verify -pubin -inkey "${release_public_key}" -rawin -in "${manifest}" \
    -sigfile "${manifest_signature}" >/dev/null 2>&1 || fail 'release signing key pair mismatch'
  chmod 0444 "${manifest}" "${manifest_signature}"

  "${PACKAGE_BUILDER}" --architecture "${arch}" --version "${version}" \
    --release-sequence "${release_sequence}" --source-date-epoch "${source_date_epoch}" \
    --artifact "${artifact}" --sbom "${sbom}" --manifest "${manifest}" \
    --manifest-signature "${manifest_signature}" --release-public-key "${release_public_key}" \
    --rollback-key-version "${rollback_key_version}" --output-dir "${packages_dir}" >/dev/null ||
    fail "build Debian package: ${version}/${arch}"
  package_name=cdnca-edge-agent_${debian_version}_${arch}.deb
  package_path=${publish}/pool/${component}/c/cdnca-edge-agent/${package_name}
  mv -- "${packages_dir}/${package_name}" "${package_path}" || fail "publish Debian package: ${version}/${arch}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${arch}" "${debian_version}" "${version}" "${release_sequence}" \
    "${package_path#"${publish}"/}" "$(sha256_file "${package_path}")" >>"${packages_manifest}"
done < <(jq -er '.releases[] | [.release_sequence,.arch,.path] | @tsv' "${config}")
"${RELEASE_SET_VALIDATOR}" "${packages_manifest}" >/dev/null || fail 'native release set is incomplete or inconsistent'

for arch in amd64 arm64; do
  binary_dir=${publish}/dists/${suite}/${component}/binary-${arch}
  mkdir -p "${binary_dir}/by-hash/SHA256"
  packages=${binary_dir}/Packages
  : >"${packages}"
  while IFS=$'\t' read -r package_arch debian_version _version _sequence package_relative _package_sha256; do
    [ "${package_arch}" = "${arch}" ] || continue
    package_path=${publish}/${package_relative}
    printf 'Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: %s\nInstalled-Size: %s\nDepends: %s\nDescription: %s\nFilename: %s\nSize: %s\nSHA256: %s\n\n' \
      "$(dpkg-deb -f "${package_path}" Package)" "${debian_version}" "${arch}" \
      "$(dpkg-deb -f "${package_path}" Maintainer)" "$(dpkg-deb -f "${package_path}" Installed-Size)" \
      "$(dpkg-deb -f "${package_path}" Depends)" "$(dpkg-deb -f "${package_path}" Description | sed -n '1p')" \
      "${package_relative}" "$(file_size "${package_path}")" "$(sha256_file "${package_path}")" >>"${packages}"
  done <"${packages_manifest}"
  if [ ! -s "${packages}" ]; then
    rmdir "${binary_dir}/by-hash/SHA256" "${binary_dir}/by-hash" "${binary_dir}"
    continue
  fi
  gzip -n -9 -c "${packages}" >"${packages}.gz"
  for index in "${packages}" "${packages}.gz"; do
    digest=$(sha256_file "${index}")
    install -m 0444 "${index}" "${binary_dir}/by-hash/SHA256/${digest}"
    chmod 0444 "${index}"
  done
done

release_file=${publish}/dists/${suite}/Release
architectures=$(awk -F '\t' '{print $1}' "${packages_manifest}" | LC_ALL=C sort -u | paste -sd ' ' -)
release_date=$(date -u -d "@${source_date_epoch}" -R)
valid_until=$(date -u -d "@${valid_until_epoch}" -R)
{
  printf 'Origin: %s\nLabel: %s\nSuite: %s\nCodename: %s\nDate: %s\nValid-Until: %s\nArchitectures: %s\nComponents: %s\nAcquire-By-Hash: yes\nSHA256:\n' \
    "${origin}" "${label}" "${suite}" "${suite}" "${release_date}" "${valid_until}" "${architectures}" "${component}"
  find "${publish}/dists/${suite}/${component}" -type f ! -path '*/by-hash/*' -print | LC_ALL=C sort |
    while IFS= read -r index; do
      printf ' %s %16s %s\n' "$(sha256_file "${index}")" "$(file_size "${index}")" "${index#"${publish}"/dists/"${suite}"/}"
    done
} >"${release_file}"
chmod 0444 "${release_file}"
gpg --batch --yes --homedir "${apt_homedir}" --local-user "${apt_key_id}" --digest-algo SHA256 \
  --faked-system-time "${source_date_epoch}!" --clearsign -o "${publish}/dists/${suite}/InRelease" "${release_file}" || fail 'sign InRelease'
gpg --batch --yes --homedir "${apt_homedir}" --local-user "${apt_key_id}" --digest-algo SHA256 \
  --faked-system-time "${source_date_epoch}!" --detach-sign -o "${publish}/dists/${suite}/Release.gpg" "${release_file}" || fail 'sign Release.gpg'
gpg --batch --homedir "${apt_homedir}" --export "${apt_key_id}" >"${publish}/cdnca-archive-keyring.gpg"
[ -s "${publish}/cdnca-archive-keyring.gpg" ] || fail 'exported apt keyring is empty'
gpgv --keyring "${publish}/cdnca-archive-keyring.gpg" "${publish}/dists/${suite}/InRelease" >/dev/null 2>&1 || fail 'verify InRelease'
gpgv --keyring "${publish}/cdnca-archive-keyring.gpg" "${publish}/dists/${suite}/Release.gpg" "${release_file}" >/dev/null 2>&1 || fail 'verify Release.gpg'

jq -S -n --arg schema 'cdnca.edge.apt-repository-provenance/v1' --arg suite "${suite}" \
  --arg component "${component}" --arg apt_key_fingerprint "${apt_key_id}" \
  --arg release_sha256 "$(sha256_file "${release_file}")" --argjson source_date_epoch "${source_date_epoch}" \
  --rawfile packages "${packages_manifest}" '
  {apt_key_fingerprint:$apt_key_fingerprint,component:$component,
   packages:($packages | split("\n") | map(select(length>0) | split("\t") |
     {arch:.[0],debian_version:.[1],version:.[2],release_sequence:(.[3]|tonumber),path:.[4],sha256:.[5]})),
   release_sha256:$release_sha256,schema:$schema,source_date_epoch:$source_date_epoch,suite:$suite}
' >"${publish}/repository.provenance.json"
chmod 0444 "${publish}/repository.provenance.json" "${publish}/cdnca-archive-keyring.gpg" \
  "${publish}/dists/${suite}/InRelease" "${publish}/dists/${suite}/Release.gpg"
find "${publish}" -exec touch -h -d "@${source_date_epoch}" {} +
find "${publish}" -type d -exec chmod 0755 {} +
find "${publish}" -type f -exec chmod 0444 {} +
mv -- "${publish}" "${output_dir}" || fail 'publish apt repository'
trap - EXIT
cleanup
