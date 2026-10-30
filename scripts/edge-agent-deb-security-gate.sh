#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'edge deb security gate: %s\n' "$1" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{print $1}'
  else
    shasum -a 256 -- "$1" | awk '{print $1}'
  fi
}
file_size() {
  if stat -c '%s' -- "$1" >/dev/null 2>&1; then stat -c '%s' -- "$1"; else stat -f '%z' -- "$1"; fi
}
require_regular() { [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || fail "unsafe input: $1"; }
valid_digest() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
valid_uint() { [[ "$1" =~ ^(0|[1-9][0-9]{0,11})$ ]]; }
safe_absolute_path() { [[ "$1" == /* && "$1" != *$'\n'* && "$1" != *$'\r'* && "$1" != *$'\t'* && ! "$1" =~ (^|/)\.\.?(/|$) ]]; }
semver_at_least() {
  perl -e '
    sub parts { my ($v)=@_; exit 1 unless $v =~ /\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z/; return ($1,$2,$3); }
    my @actual=parts($ARGV[0]); my @minimum=parts($ARGV[1]);
    for my $i (0..2) {
      exit 0 if length($actual[$i]) > length($minimum[$i]);
      exit 1 if length($actual[$i]) < length($minimum[$i]);
      my $order = $actual[$i] cmp $minimum[$i];
      exit 0 if $order > 0; exit 1 if $order < 0;
    }
  ' "$1" "$2"
}

release_dir=''
policy=''
policy_sha256=''
report=''
signature=''
public_key=''
public_key_sha256=''
now_epoch=''
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || fail "missing value for $1"
  case "$1" in
    --release-dir) [ -z "${release_dir}" ] || fail 'duplicate release directory'; release_dir=$2 ;;
    --policy) [ -z "${policy}" ] || fail 'duplicate policy'; policy=$2 ;;
    --policy-sha256) [ -z "${policy_sha256}" ] || fail 'duplicate policy digest'; policy_sha256=$2 ;;
    --report) [ -z "${report}" ] || fail 'duplicate report'; report=$2 ;;
    --signature) [ -z "${signature}" ] || fail 'duplicate signature'; signature=$2 ;;
    --public-key) [ -z "${public_key}" ] || fail 'duplicate public key'; public_key=$2 ;;
    --public-key-sha256) [ -z "${public_key_sha256}" ] || fail 'duplicate public key digest'; public_key_sha256=$2 ;;
    --now-epoch) [ -z "${now_epoch}" ] || fail 'duplicate current epoch'; now_epoch=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done
for value in release_dir policy policy_sha256 report signature public_key public_key_sha256; do
  [ -n "${!value}" ] || fail "missing ${value//_/-}"
done
for path in "${release_dir}" "${policy}" "${report}" "${signature}" "${public_key}"; do
  safe_absolute_path "${path}" || fail "input path must be clean and absolute: ${path}"
done
[ -n "${now_epoch}" ] || now_epoch=$(date +%s)
valid_uint "${now_epoch}" || fail 'current epoch must be a canonical unsigned integer'
valid_digest "${policy_sha256}" || fail 'policy digest must be lowercase SHA-256'
valid_digest "${public_key_sha256}" || fail 'public key digest must be lowercase SHA-256'
[ -d "${release_dir}" ] && [ ! -L "${release_dir}" ] || fail 'unsafe release directory'
for file in "${policy}" "${report}" "${signature}" "${public_key}" \
  "${release_dir}/edge-agent" "${release_dir}/edge-agent.spdx.json" \
  "${release_dir}/edge-agent.provenance.json"; do
  require_regular "${file}"
done
[ -x "${release_dir}/edge-agent" ] || fail 'edge-agent is not executable'
for command in awk date grep jq openssl perl stat; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing command: ${command}"
done
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || fail 'missing SHA-256 command'
[ "$(file_size "${policy}")" -le 1048576 ] || fail 'security policy exceeds size limit'
[ "$(file_size "${report}")" -le 67108864 ] || fail 'security report exceeds size limit'
[ "$(file_size "${signature}")" -eq 64 ] || fail 'security report signature must be a raw Ed25519 signature'
[ "$(file_size "${public_key}")" -le 16384 ] || fail 'security public key exceeds size limit'
[ "$(file_size "${release_dir}/edge-agent")" -ge 1 ] &&
  [ "$(file_size "${release_dir}/edge-agent")" -le 268435456 ] || fail 'edge-agent exceeds size limit'
[ "$(file_size "${release_dir}/edge-agent.spdx.json")" -le 16777216 ] || fail 'SBOM exceeds size limit'
[ "$(file_size "${release_dir}/edge-agent.provenance.json")" -le 1048576 ] || fail 'provenance exceeds size limit'
[ "$(sha256_file "${policy}")" = "${policy_sha256}" ] || fail 'policy digest mismatch'
[ "$(sha256_file "${public_key}")" = "${public_key_sha256}" ] || fail 'public key digest mismatch'
openssl pkey -pubin -in "${public_key}" -text -noout 2>/dev/null | grep -F 'ED25519' >/dev/null ||
  fail 'security report key must be Ed25519'
openssl pkeyutl -verify -pubin -inkey "${public_key}" -rawin -in "${report}" \
  -sigfile "${signature}" >/dev/null 2>&1 || fail 'security report signature is invalid'

jq -e '
  keys == ["allowed_scanner_images","max_database_age_seconds","max_report_age_seconds",
           "minimum_version","required_protocol_regressions","schema"] and
  .schema == "cdnca.edge.security-policy/v1" and
  (.minimum_version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) and
  (.max_database_age_seconds | type == "number" and . == floor and . >= 1 and . <= 604800) and
  (.max_report_age_seconds | type == "number" and . == floor and . >= 1 and . <= 604800) and
  (.allowed_scanner_images | type == "array" and length >= 1 and
    . == (sort | unique) and all(.[]; test("^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$"))) and
  (.required_protocol_regressions | type == "array" and length >= 1 and
    . == (sort | unique) and all(.[]; test("^[a-z][a-z0-9-]{0,63}$")))
' "${policy}" >/dev/null || fail 'security policy is invalid'

jq -e '
  keys == ["advisories","arch","artifact_sha256","database_snapshot_sha256",
           "database_updated_epoch","protocol_regressions","provenance_sha256",
           "sbom_sha256","scanned_at_epoch","scanner_image","schema","source_commit",
           "valid_until_epoch","version"] and
  .schema == "cdnca.edge.security-report/v1" and
  (.arch == "amd64" or .arch == "arm64") and
  (.version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) and
  (.source_commit | test("^[0-9a-f]{40}$")) and
  (.artifact_sha256 | test("^[0-9a-f]{64}$")) and
  (.sbom_sha256 | test("^[0-9a-f]{64}$")) and
  (.provenance_sha256 | test("^[0-9a-f]{64}$")) and
  (.database_snapshot_sha256 | test("^[0-9a-f]{64}$")) and
  (.scanner_image | test("^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$")) and
  all(.database_updated_epoch,.scanned_at_epoch,.valid_until_epoch;
    type == "number" and . == floor and . >= 100000000 and . <= 4102444800) and
  (.protocol_regressions | type == "array" and length >= 1 and
    (map(.name) == (map(.name) | sort | unique)) and
    all(.[]; keys == ["evidence_sha256","name","status"] and .status == "passed" and
      (.name | test("^[a-z][a-z0-9-]{0,63}$")) and
      (.evidence_sha256 | test("^[0-9a-f]{64}$")))) and
  (.advisories | type == "array" and
    (map(.id) == (map(.id) | sort | unique)) and
    all(.[]; keys == ["component","evidence_sha256","fixed_version","id","patch_reference",
                       "regression_test","severity","status","upstream_url"] and
      (.component | test("^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")) and
      (.id | test("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")) and
      (.severity == "low" or .severity == "medium" or .severity == "high" or .severity == "critical") and
      (.status == "patched" or .status == "not_affected") and
      (.fixed_version | type == "string" and length >= 1 and length <= 128) and
      (if .status == "patched" then
         (.patch_reference | test("^([0-9a-f]{40}|https://[^[:space:]]+)$"))
       else .patch_reference == "not-applicable" end) and
      (.regression_test | test("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")) and
      (.upstream_url | test("^https://[^[:space:]]+$")) and
      (.evidence_sha256 | test("^[0-9a-f]{64}$"))))
' "${report}" >/dev/null || fail 'security report is invalid or contains unresolved advisories'

minimum_version=$(jq -er '.minimum_version' "${policy}")
version=$(jq -er '.version' "${report}")
semver_at_least "${version}" "${minimum_version}" || fail "release ${version} is below security minimum ${minimum_version}"
scanner_image=$(jq -er '.scanner_image' "${report}")
jq -e --arg scanner "${scanner_image}" '.allowed_scanner_images | index($scanner) != null' \
  "${policy}" >/dev/null || fail 'scanner image is not allowed by policy'
required_protocols=$(jq -c '.required_protocol_regressions' "${policy}")
actual_protocols=$(jq -c '[.protocol_regressions[].name] | sort | unique' "${report}")
[ "${actual_protocols}" = "${required_protocols}" ] || fail 'required protocol regression evidence is incomplete'

scanned_at=$(jq -er '.scanned_at_epoch' "${report}")
database_updated=$(jq -er '.database_updated_epoch' "${report}")
valid_until=$(jq -er '.valid_until_epoch' "${report}")
max_report_age=$(jq -er '.max_report_age_seconds' "${policy}")
max_database_age=$(jq -er '.max_database_age_seconds' "${policy}")
[ "${scanned_at}" -le "${now_epoch}" ] || fail 'security report is from the future'
[ "${database_updated}" -le "${scanned_at}" ] || fail 'vulnerability database is newer than the scan'
[ "${valid_until}" -ge "${scanned_at}" ] && [ "${valid_until}" -ge "${now_epoch}" ] || fail 'security report is expired'
[ $((now_epoch - scanned_at)) -le "${max_report_age}" ] || fail 'security report is stale'
[ $((now_epoch - database_updated)) -le "${max_database_age}" ] || fail 'vulnerability database is stale'

artifact="${release_dir}/edge-agent"
sbom="${release_dir}/edge-agent.spdx.json"
provenance="${release_dir}/edge-agent.provenance.json"
artifact_sha=$(sha256_file "${artifact}")
sbom_sha=$(sha256_file "${sbom}")
provenance_sha=$(sha256_file "${provenance}")
jq -e --arg version "${version}" --arg artifact_sha "${artifact_sha}" \
  --argjson artifact_size "$(file_size "${artifact}")" --arg sbom_sha "${sbom_sha}" '
  .schema == "cdnca.edge.release-provenance/v1" and .version == $version and
  (.arch == "amd64" or .arch == "arm64") and
  .artifact.path == "edge-agent" and .artifact.sha256 == $artifact_sha and .artifact.size == $artifact_size and
  .sbom.path == "edge-agent.spdx.json" and .sbom.sha256 == $sbom_sha and
  (.source_commit | test("^[0-9a-f]{40}$")) and
  (.builder.image | test("^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$"))
' "${provenance}" >/dev/null || fail 'release provenance does not bind the artifact and SBOM'
jq -e --arg artifact_sha "${artifact_sha}" '
  .spdxVersion == "SPDX-2.3" and .SPDXID == "SPDXRef-DOCUMENT" and
  (.files | any(.fileName == "edge-agent" and
    (.checksums | any(.algorithm == "SHA256" and .checksumValue == $artifact_sha))))
' "${sbom}" >/dev/null || fail 'SBOM does not bind the artifact'

report_arch=$(jq -er '.arch' "${report}")
report_source=$(jq -er '.source_commit' "${report}")
provenance_arch=$(jq -er '.arch' "${provenance}")
provenance_source=$(jq -er '.source_commit' "${provenance}")
[ "$(jq -er '.artifact_sha256' "${report}")" = "${artifact_sha}" ] &&
  [ "$(jq -er '.sbom_sha256' "${report}")" = "${sbom_sha}" ] &&
  [ "$(jq -er '.provenance_sha256' "${report}")" = "${provenance_sha}" ] &&
  [ "${report_arch}" = "${provenance_arch}" ] && [ "${report_source}" = "${provenance_source}" ] ||
  fail 'security report identity does not match release provenance'

printf 'EDGE_AGENT_DEB_SECURITY_GATE PASS version=%s arch=%s\n' "${version}" "${report_arch}"
