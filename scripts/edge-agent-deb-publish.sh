#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly GATE="${SCRIPT_DIR}/edge-agent-deb-security-gate.sh"
readonly REPOSITORY_BUILDER="${REPO_ROOT}/agents/edge-agent/packaging/deb/build-repository.sh"

fail() { printf 'edge deb publish: %s\n' "$1" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" | awk '{print $1}'; else shasum -a 256 -- "$1" | awk '{print $1}'; fi
}
require_regular() { [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || fail "unsafe input: $1"; }
safe_absolute_path() { [[ "$1" == /* && "$1" != *$'\n'* && "$1" != *$'\r'* && "$1" != *$'\t'* && ! "$1" =~ (^|/)\.\.?(/|$) ]]; }

config=''
output_dir=''
release_private_key=''
release_public_key=''
apt_homedir=''
apt_key_id=''
security_policy=''
security_policy_sha256=''
security_public_key=''
security_public_key_sha256=''
now_epoch=''
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || fail "missing value for $1"
  case "$1" in
    --config) [ -z "${config}" ] || fail 'duplicate config'; config=$2 ;;
    --output-dir) [ -z "${output_dir}" ] || fail 'duplicate output directory'; output_dir=$2 ;;
    --release-private-key) [ -z "${release_private_key}" ] || fail 'duplicate release private key'; release_private_key=$2 ;;
    --release-public-key) [ -z "${release_public_key}" ] || fail 'duplicate release public key'; release_public_key=$2 ;;
    --apt-homedir) [ -z "${apt_homedir}" ] || fail 'duplicate apt homedir'; apt_homedir=$2 ;;
    --apt-key-id) [ -z "${apt_key_id}" ] || fail 'duplicate apt key ID'; apt_key_id=$2 ;;
    --security-policy) [ -z "${security_policy}" ] || fail 'duplicate security policy'; security_policy=$2 ;;
    --security-policy-sha256) [ -z "${security_policy_sha256}" ] || fail 'duplicate security policy digest'; security_policy_sha256=$2 ;;
    --security-public-key) [ -z "${security_public_key}" ] || fail 'duplicate security public key'; security_public_key=$2 ;;
    --security-public-key-sha256) [ -z "${security_public_key_sha256}" ] || fail 'duplicate security public key digest'; security_public_key_sha256=$2 ;;
    --now-epoch) [ -z "${now_epoch}" ] || fail 'duplicate current epoch'; now_epoch=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done
for value in config output_dir release_private_key release_public_key apt_homedir apt_key_id security_policy \
  security_policy_sha256 security_public_key security_public_key_sha256; do
  [ -n "${!value}" ] || fail "missing ${value//_/-}"
done
[ -n "${now_epoch}" ] || now_epoch=$(date +%s)
for path in "${config}" "${output_dir}" "${release_private_key}" "${release_public_key}" \
  "${apt_homedir}" "${security_policy}" "${security_public_key}"; do
  safe_absolute_path "${path}" || fail "input path must be clean and absolute: ${path}"
done
[ ! -e "${output_dir}" ] && [ ! -L "${output_dir}" ] || fail 'output already exists'
for file in "${config}" "${release_private_key}" "${release_public_key}" "${security_policy}" "${security_public_key}" \
  "${GATE}" "${REPOSITORY_BUILDER}"; do
  require_regular "${file}"
done
[ -x "${GATE}" ] && [ -x "${REPOSITORY_BUILDER}" ] || fail 'required production entrypoint is not executable'
[ -d "${apt_homedir}" ] && [ ! -L "${apt_homedir}" ] || fail 'unsafe apt homedir'
for command in awk chmod date find install jq mkdir mktemp mv openssl rm stat; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing command: ${command}"
done
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || fail 'missing SHA-256 command'
jq -e '.schema == "cdnca.edge.apt-repository/v1" and (.releases | type == "array" and length >= 1)' \
  "${config}" >/dev/null || fail 'invalid repository config'

output_parent=${output_dir%/*}
[ "${output_parent}" != "${output_dir}" ] || output_parent=/
[ -d "${output_parent}" ] && [ ! -L "${output_parent}" ] || fail 'unsafe output parent'
work=$(mktemp -d "${output_parent}/.edge-deb-publish.XXXXXX") || fail 'create private publication staging'
cleanup() { rm -rf -- "${work}"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
staged_releases=${work}/releases
mkdir "${staged_releases}"
install -m 0400 "${release_private_key}" "${work}/release-private.pem"
install -m 0444 "${release_public_key}" "${work}/release-public.pem"
install -m 0444 "${security_policy}" "${work}/security-policy.json"
install -m 0444 "${security_public_key}" "${work}/security-public.pem"
install -m 0444 "${config}" "${work}/input-repository.json"
entries=${work}/security-entries.ndjson
: >"${entries}"

index=0
while IFS=$'\t' read -r sequence arch source; do
  safe_absolute_path "${source}" || fail "release path must be clean and absolute: ${source}"
  [ -d "${source}" ] && [ ! -L "${source}" ] || fail "unsafe release directory: ${source}"
  destination=${staged_releases}/${index}
  mkdir "${destination}"
  for name in edge-agent edge-agent.spdx.json edge-agent.provenance.json edge-agent.security.json edge-agent.security.sig; do
    require_regular "${source}/${name}"
    mode=0444
    [ "${name}" = edge-agent ] && mode=0555
    install -m "${mode}" "${source}/${name}" "${destination}/${name}"
  done
  "${GATE}" --release-dir "${destination}" --policy "${work}/security-policy.json" \
    --policy-sha256 "${security_policy_sha256}" --report "${destination}/edge-agent.security.json" \
    --signature "${destination}/edge-agent.security.sig" --public-key "${work}/security-public.pem" \
    --public-key-sha256 "${security_public_key_sha256}" --now-epoch "${now_epoch}" >/dev/null
  version=$(jq -er '.version' "${destination}/edge-agent.provenance.json")
  report_sha=$(sha256_file "${destination}/edge-agent.security.json")
  signature_sha=$(sha256_file "${destination}/edge-agent.security.sig")
  jq -S -c -n --arg arch "${arch}" --argjson release_sequence "${sequence}" \
    --arg report_sha256 "${report_sha}" --arg signature_sha256 "${signature_sha}" --arg version "${version}" \
    '{arch:$arch,release_sequence:$release_sequence,report_sha256:$report_sha256,
      signature_sha256:$signature_sha256,version:$version}' >>"${entries}"
  index=$((index + 1))
done < <(jq -er '.releases[] | [.release_sequence,.arch,.path] | @tsv' "${work}/input-repository.json")
[ "${index}" -gt 0 ] || fail 'repository config contains no releases'

jq --arg releases "${staged_releases}" \
  '.releases |= (to_entries | map(.value.path = ($releases + "/" + (.key | tostring)) | .value))' \
  "${work}/input-repository.json" >"${work}/repository.json"
"${REPOSITORY_BUILDER}" --config "${work}/repository.json" --output-dir "${work}/repository" \
  --release-private-key "${work}/release-private.pem" --release-public-key "${work}/release-public.pem" \
  --apt-homedir "${apt_homedir}" --apt-key-id "${apt_key_id}"

security_dir=${work}/repository/security
mkdir "${security_dir}"
install -m 0444 "${work}/security-policy.json" "${security_dir}/security-policy.json"
install -m 0444 "${work}/security-public.pem" "${security_dir}/security-scanner.pem"
for release in "${staged_releases}"/*; do
  version=$(jq -er '.version' "${release}/edge-agent.provenance.json")
  arch=$(jq -er '.arch' "${release}/edge-agent.provenance.json")
  evidence=${security_dir}/${version}/${arch}
  [ ! -e "${evidence}" ] || fail "duplicate security evidence: ${version}/${arch}"
  mkdir -p "${evidence}"
  install -m 0444 "${release}/edge-agent.security.json" "${evidence}/report.json"
  install -m 0444 "${release}/edge-agent.security.sig" "${evidence}/report.sig"
done
jq -s '.' "${entries}" >"${work}/security-entries.json"
repository_provenance=${work}/repository/repository.provenance.json
require_regular "${repository_provenance}"
jq -S -c -n --arg repository_provenance_sha256 "$(sha256_file "${repository_provenance}")" \
  --arg policy_sha256 "${security_policy_sha256}" --arg security_public_key_sha256 "${security_public_key_sha256}" \
  --argjson evaluated_at_epoch "${now_epoch}" --slurpfile releases "${work}/security-entries.json" '
  {evaluated_at_epoch:$evaluated_at_epoch,policy_sha256:$policy_sha256,
   releases:$releases[0],repository_provenance_sha256:$repository_provenance_sha256,
   schema:"cdnca.edge.security-gate-provenance/v1",security_public_key_sha256:$security_public_key_sha256}
' >"${security_dir}/security-gate.provenance.json"
openssl pkeyutl -sign -inkey "${work}/release-private.pem" -rawin \
  -in "${security_dir}/security-gate.provenance.json" -out "${security_dir}/security-gate.provenance.sig"
openssl pkeyutl -verify -pubin -inkey "${work}/release-public.pem" -rawin \
  -in "${security_dir}/security-gate.provenance.json" -sigfile "${security_dir}/security-gate.provenance.sig" \
  >/dev/null 2>&1 || fail 'security gate provenance signature verification failed'
install -m 0444 "${work}/release-public.pem" "${security_dir}/release-signing.pem"
find "${security_dir}" -type d -exec chmod 0755 {} +
find "${security_dir}" -type f -exec chmod 0444 {} +
mv -- "${work}/repository" "${output_dir}" || fail 'publish apt repository atomically'
trap - EXIT HUP INT TERM
cleanup
printf 'EDGE_AGENT_DEB_PUBLISH PASS releases=%s output=%s\n' "${index}" "${output_dir}"
