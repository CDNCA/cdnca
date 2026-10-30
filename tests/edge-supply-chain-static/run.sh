#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
WORKFLOW="${ROOT}/.github/workflows/edge-supply-chain.yml"
RELEASE_BUILD="${ROOT}/scripts/edge-agent-release-build.sh"
OCI_PUBLISH="${ROOT}/scripts/edge-agent-oci-publish.sh"
SYSTEMD_PUBLISH="${ROOT}/scripts/build-upgrade-e2e-systemd-image.sh"
failures=0

require() {
  local file=$1 pattern=$2 description=$3
  if [[ ! -f ${file} ]] || ! grep -Eq -- "${pattern}" "${file}"; then
    printf 'RED missing %s\n' "${description}" >&2
    failures=$((failures + 1))
  fi
}

reject() {
  local file=$1 pattern=$2 description=$3
  if [[ -f ${file} ]] && grep -Eq -- "${pattern}" "${file}"; then
    printf 'RED rejected %s\n' "${description}" >&2
    failures=$((failures + 1))
  fi
}

require "${RELEASE_BUILD}" '--metadata-file' 'release metadata output option'
require "${RELEASE_BUILD}" 'cdnca\.edge\.release-build-output/v1' 'versioned release metadata schema'
require "${RELEASE_BUILD}" 'edge-agent\.provenance\.json' 'metadata provenance binding'
require "${RELEASE_BUILD}" 'edge-agent\.spdx\.json' 'metadata SPDX binding'
require "${RELEASE_BUILD}" 'mv -- .*metadata' 'atomic release metadata publication'

require "${OCI_PUBLISH}" 'docker buildx build' 'production OCI buildx publication'
require "${OCI_PUBLISH}" '--platform linux/amd64,linux/arm64' 'exact multi-arch OCI platform set'
require "${OCI_PUBLISH}" 'imagetools inspect.*--raw' 'raw OCI index readback'
require "${OCI_PUBLISH}" 'cosign sign ' 'keyless OCI signature'
require "${OCI_PUBLISH}" 'cosign attest.*slsaprovenance' 'SLSA provenance attestation'
require "${OCI_PUBLISH}" 'cosign attest.*spdxjson' 'SPDX attestation'
require "${OCI_PUBLISH}" 'cosign verify.*--certificate-oidc-issuer' 'issuer verification'
require "${OCI_PUBLISH}" 'cosign verify.*--certificate-identity' 'workflow identity verification'
require "${OCI_PUBLISH}" 'linux/amd64.*linux/arm64|linux/arm64.*linux/amd64' 'exact OCI index platform readback'
require "${OCI_PUBLISH}" 'cdnca\.edge\.oci-release-inputs/v1' 'versioned OCI release inputs'
require "${OCI_PUBLISH}" 'EDGE_AGENT_OCI_SUBJECT=' 'systemd consumer environment output'
require "${OCI_PUBLISH}" 'sha256sum.*spdx|sha256_file.*spdx' 'SPDX predicate digest binding'
reject "${OCI_PUBLISH}" 'cosign (sign|attest)[^\n]*--key' 'long-lived cosign signing key'

require "${SYSTEMD_PUBLISH}" 'manifest\.json' 'native raw manifest evidence'
require "${SYSTEMD_PUBLISH}" 'cdnca\.edge\.systemd-release-inputs/v1' 'versioned systemd release inputs'
require "${SYSTEMD_PUBLISH}" 'UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST=' 'amd64 final-acceptance input'
require "${SYSTEMD_PUBLISH}" 'UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST=' 'arm64 final-acceptance input'
require "${SYSTEMD_PUBLISH}" 'UPGRADE_E2E_SYSTEMD_SPDX=' 'SPDX final-acceptance input'

require "${WORKFLOW}" '^  release-build:' 'native release build job'
require "${WORKFLOW}" '^  release-publish:' 'multi-arch release publication job'
require "${WORKFLOW}" 'scripts/edge-agent-oci-publish\.sh' 'production OCI publisher invocation'
require "${WORKFLOW}" 'edge-agent-release-inputs' 'persisted OCI release inputs artifact'
require "${WORKFLOW}" 'edge-systemd-inputs-' 'persisted systemd inputs artifact'
require "${WORKFLOW}" 'COSIGN_EXPECTED_ISSUER: https://token\.actions\.githubusercontent\.com' 'exact GitHub OIDC issuer'
require "${WORKFLOW}" 'COSIGN_EXPECTED_IDENTITY:.*edge-supply-chain\.yml@\$\{\{ github\.ref \}\}' 'exact workflow identity'
reject "${WORKFLOW}" 'uses: [^@[:space:]]+@v[0-9]' 'mutable major-version action reference'

if ((failures != 0)); then
  printf 'EDGE_SUPPLY_CHAIN_STATIC=RED failures=%d\n' "${failures}" >&2
  exit 1
fi

printf 'EDGE_SUPPLY_CHAIN_STATIC=PASS\n'
