#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly GATE="${SCRIPT_DIR}/edge-agent-deb-security-gate.sh"
readonly PUBLISH="${SCRIPT_DIR}/edge-agent-deb-publish.sh"
readonly POLICY="${REPO_ROOT}/infra/apt/security-policy.example.json"

fail() { printf 'edge deb contract test: %s\n' "$1" >&2; exit 1; }
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
sign_report() {
  openssl pkeyutl -sign -inkey "${work}/security-private.pem" -rawin \
    -in "${work}/report.json" -out "${work}/report.sig"
}
run_gate() {
  "${GATE}" --release-dir "${work}/release" --policy "$1" --policy-sha256 "$2" \
    --report "${work}/report.json" --signature "${work}/report.sig" \
    --public-key "${work}/security-public.pem" --public-key-sha256 "${public_key_sha}" \
    --now-epoch "${now_epoch}"
}
expect_fail() {
  local name=$1
  shift
  if "$@" >"${work}/${name}.stdout" 2>"${work}/${name}.stderr"; then
    fail "${name} unexpectedly passed"
  fi
}
write_report() {
  local scanned=$1 database=$2 valid_until=$3 protocols=$4 advisories=$5
  jq -S -c -n --arg arch amd64 --arg artifact_sha "${artifact_sha}" \
    --arg database_sha "$(printf database-v1 | sha256_file /dev/stdin)" \
    --arg provenance_sha "${provenance_sha}" --arg sbom_sha "${sbom_sha}" \
    --arg scanner_image "${scanner_image}" --arg source_commit "${source_commit}" \
    --arg version 1.2.3 --argjson scanned "${scanned}" --argjson database "${database}" \
    --argjson valid_until "${valid_until}" --argjson protocols "${protocols}" \
    --argjson advisories "${advisories}" '
    {advisories:$advisories,arch:$arch,artifact_sha256:$artifact_sha,
     database_snapshot_sha256:$database_sha,database_updated_epoch:$database,
     provenance_sha256:$provenance_sha,protocol_regressions:$protocols,
     sbom_sha256:$sbom_sha,scanned_at_epoch:$scanned,scanner_image:$scanner_image,
     schema:"cdnca.edge.security-report/v1",source_commit:$source_commit,
     valid_until_epoch:$valid_until,version:$version}
  ' >"${work}/report.json"
  sign_report
}

for command in awk jq openssl perl rg stat; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing test dependency: ${command}"
done
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || fail 'missing SHA-256 command'
for file in "${GATE}" "${PUBLISH}" "${POLICY}"; do
  [ -f "${file}" ] && [ ! -L "${file}" ] || fail "missing production contract: ${file#"${REPO_ROOT}/"}"
done
[ -x "${GATE}" ] && [ -x "${PUBLISH}" ] || fail 'production entrypoints are not executable'

bash -n "${GATE}" "${PUBLISH}"
jq -e '
  keys == ["allowed_scanner_images","max_database_age_seconds","max_report_age_seconds",
           "minimum_version","required_protocol_regressions","schema"] and
  .schema == "cdnca.edge.security-policy/v1" and
  (.minimum_version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) and
  (.allowed_scanner_images | length >= 1 and
    all(.[]; test("^.+@sha256:[0-9a-f]{64}$"))) and
  (.required_protocol_regressions == (["cache-refresh","http1","http2","http3","range206","rewrite","websocket"] | sort))
' "${POLICY}" >/dev/null || fail 'example security policy is not strict and canonical'

for forbidden in 'curl | sh' 'wget | sh' 'trusted=yes' 'ufw disable' 'systemctl disable firewalld'; do
  if rg -F "${forbidden}" "${GATE}" "${PUBLISH}" "${REPO_ROOT}/infra/apt" \
    "${REPO_ROOT}/docs/system/installation-and-configuration.md" >/dev/null; then
    fail "forbidden installation pattern: ${forbidden}"
  fi
done
rg -F 'packaging/deb/build-repository.sh' "${PUBLISH}" >/dev/null || fail 'publisher does not call the frozen apt builder'
gate_line=$(rg -n -F '"${GATE}" --release-dir' "${PUBLISH}" | sed -n '1s/:.*//p')
builder_line=$(rg -n -F '"${REPOSITORY_BUILDER}" --config' "${PUBLISH}" | sed -n '1s/:.*//p')
[ -n "${gate_line}" ] && [ -n "${builder_line}" ] && [ "${gate_line}" -lt "${builder_line}" ] ||
  fail 'publisher does not run every security gate before the apt builder'
rg -F 'mktemp -d "${output_parent}/.edge-deb-publish.' "${PUBLISH}" >/dev/null || fail 'publisher lacks private same-filesystem staging'
rg -F 'mv -- "${work}/repository" "${output_dir}"' "${PUBLISH}" >/dev/null || fail 'publisher lacks final atomic rename'
rg -F 'signed-by=/usr/share/keyrings/cdnca-archive-keyring.gpg' "${REPO_ROOT}/infra/apt/README.md" >/dev/null ||
  fail 'apt instructions do not pin the archive keyring'
rg -F 'Debian 12' "${REPO_ROOT}/infra/apt/README.md" >/dev/null || fail 'Debian 12 is undocumented'
rg -F 'Ubuntu 24.04' "${REPO_ROOT}/infra/apt/README.md" >/dev/null || fail 'Ubuntu 24.04 is undocumented'

work=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-edge-security-gate.XXXXXX")
cleanup() { rm -rf -- "${work}"; }
trap cleanup EXIT
mkdir "${work}/release"
printf 'linux-elf-fixture' >"${work}/release/edge-agent"
chmod 0555 "${work}/release/edge-agent"
artifact_sha=$(sha256_file "${work}/release/edge-agent")
source_commit=0123456789abcdef0123456789abcdef01234567
now_epoch=1800000000
scanner_image=$(jq -er '.allowed_scanner_images[0]' "${POLICY}")
jq -S -c -n --arg artifact_sha "${artifact_sha}" '
  {SPDXID:"SPDXRef-DOCUMENT",creationInfo:{created:"2027-01-15T08:00:00Z",creators:["Tool: contract-test"]},
   dataLicense:"CC0-1.0",documentNamespace:("https://cdnca.invalid/spdx/test/"+$artifact_sha),
   files:[{SPDXID:"SPDXRef-File-edge-agent",checksums:[{algorithm:"SHA256",checksumValue:$artifact_sha}],fileName:"edge-agent"}],
   name:"cdnca-edge-agent-1.2.3",spdxVersion:"SPDX-2.3"}
' >"${work}/release/edge-agent.spdx.json"
sbom_sha=$(sha256_file "${work}/release/edge-agent.spdx.json")
jq -S -c -n --arg artifact_sha "${artifact_sha}" --argjson artifact_size "$(file_size "${work}/release/edge-agent")" \
  --arg sbom_sha "${sbom_sha}" --arg source_commit "${source_commit}" '
  {arch:"amd64",artifact:{path:"edge-agent",sha256:$artifact_sha,size:$artifact_size},
   build_id:"contract-test",builder:{image:"docker.io/library/golang@sha256:1111111111111111111111111111111111111111111111111111111111111111",toolchain:"go1.27.3"},
   created:"2027-01-15T08:00:00Z",recipe:{source_date_epoch:1800000000},
   sbom:{path:"edge-agent.spdx.json",sha256:$sbom_sha},schema:"cdnca.edge.release-provenance/v1",
   source_commit:$source_commit,source_repository:"https://example.invalid/cdnca.git",version:"1.2.3"}
' >"${work}/release/edge-agent.provenance.json"
provenance_sha=$(sha256_file "${work}/release/edge-agent.provenance.json")
openssl genpkey -algorithm Ed25519 -out "${work}/security-private.pem" >/dev/null 2>&1
openssl pkey -in "${work}/security-private.pem" -pubout -out "${work}/security-public.pem" >/dev/null 2>&1
public_key_sha=$(sha256_file "${work}/security-public.pem")
policy_sha=$(sha256_file "${POLICY}")
protocols='[{"evidence_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"cache-refresh","status":"passed"},{"evidence_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"http1","status":"passed"},{"evidence_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","name":"http2","status":"passed"},{"evidence_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","name":"http3","status":"passed"},{"evidence_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","name":"range206","status":"passed"},{"evidence_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","name":"rewrite","status":"passed"},{"evidence_sha256":"1111111111111111111111111111111111111111111111111111111111111111","name":"websocket","status":"passed"}]'
write_report "$((now_epoch - 60))" "$((now_epoch - 120))" "$((now_epoch + 600))" "${protocols}" '[]'
run_gate "${POLICY}" "${policy_sha}" >/dev/null || fail 'valid signed security report was rejected'

cp "${work}/release/edge-agent" "${work}/artifact.clean"
chmod 0755 "${work}/release/edge-agent"
printf tamper >>"${work}/release/edge-agent"
expect_fail artifact-drift run_gate "${POLICY}" "${policy_sha}"
cp "${work}/artifact.clean" "${work}/release/edge-agent"
chmod 0555 "${work}/release/edge-agent"

cp "${work}/report.sig" "${work}/report.sig.clean"
printf x >>"${work}/report.sig"
expect_fail signature-tamper run_gate "${POLICY}" "${policy_sha}"
mv "${work}/report.sig.clean" "${work}/report.sig"

missing_http3=$(jq -c 'map(select(.name != "http3"))' <<<"${protocols}")
write_report "$((now_epoch - 60))" "$((now_epoch - 120))" "$((now_epoch + 600))" "${missing_http3}" '[]'
expect_fail missing-protocol run_gate "${POLICY}" "${policy_sha}"

open_advisory='[{"component":"nginx","evidence_sha256":"2222222222222222222222222222222222222222222222222222222222222222","fixed_version":"1.27.5","id":"CVE-2099-0001","patch_reference":"0123456789abcdef0123456789abcdef01234567","regression_test":"http2-boundary","severity":"critical","status":"open","upstream_url":"https://example.invalid/CVE-2099-0001"}]'
write_report "$((now_epoch - 60))" "$((now_epoch - 120))" "$((now_epoch + 600))" "${protocols}" "${open_advisory}"
expect_fail open-advisory run_gate "${POLICY}" "${policy_sha}"

write_report "$((now_epoch - 60))" "$((now_epoch - 200000))" "$((now_epoch + 600))" "${protocols}" '[]'
expect_fail stale-database run_gate "${POLICY}" "${policy_sha}"
expect_fail policy-digest run_gate "${POLICY}" 0000000000000000000000000000000000000000000000000000000000000000

printf 'EDGE_AGENT_DEB_SECURITY_CONTRACT PASS\n'
