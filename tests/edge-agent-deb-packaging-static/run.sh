#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
BUILDER="${ROOT}/scripts/package-edge-agent-deb.sh"
REPOSITORY="${ROOT}/infra/packaging/deb/repository.py"
MAINTAINER="${ROOT}/infra/packaging/deb/maintainer"
RUNBOOK="${ROOT}/docs/runbooks/edge-agent-debian-packaging.md"
TMP_ROOT=${TMPDIR:-/tmp}
TMP_ROOT=${TMP_ROOT%/}
WORK="$(mktemp -d "${TMP_ROOT}/cdnca-ops11-deb.XXXXXX")"

cleanup() {
  rm -rf -- "${WORK}"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'OPS-11 Debian packaging gate failed: %s\n' "$*" >&2
  exit 1
}

for command in bash cmp gpg gpgv gzip node openssl python3 shasum tar; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing command ${command}"
done
command -v shellcheck >/dev/null 2>&1 || fail 'missing command shellcheck'

for file in "${BUILDER}" "${REPOSITORY}" "${MAINTAINER}/preinst" \
  "${MAINTAINER}/postinst" "${MAINTAINER}/prerm" "${MAINTAINER}/postrm" "${RUNBOOK}"; do
  [ -f "${file}" ] && [ ! -L "${file}" ] || fail "missing regular source ${file}"
done

shellcheck "${BUILDER}" "${MAINTAINER}/preinst" "${MAINTAINER}/postinst" \
  "${MAINTAINER}/prerm" "${MAINTAINER}/postrm"
bash -n "${BUILDER}"
PYTHONPYCACHEPREFIX="${WORK}/pycache" python3 -m py_compile "${REPOSITORY}"

mkdir -p "${WORK}/keys" "${WORK}/release/amd64" "${WORK}/release/arm64" \
  "${WORK}/packages-a" "${WORK}/packages-b"
openssl genpkey -algorithm ED25519 -out "${WORK}/keys/release-private.pem" >/dev/null 2>&1
openssl pkey -in "${WORK}/keys/release-private.pem" -pubout -out "${WORK}/keys/release-public.pem" >/dev/null 2>&1

write_release() {
  local arch machine target
  arch=$1
  machine=$2
  target="${WORK}/release/${arch}"
  python3 - "${target}/edge-agent" "${machine}" <<'PY'
import os, struct, sys
path, machine = sys.argv[1], int(sys.argv[2])
header = bytearray(64)
header[:7] = b"\x7fELF\x02\x01\x01"
header[16:18] = struct.pack("<H", 2)
header[18:20] = struct.pack("<H", machine)
with open(path, "wb") as stream:
    stream.write(header)
    stream.write(b"cdnca deterministic package fixture\n")
os.chmod(path, 0o555)
PY
  printf '{"SPDXID":"SPDXRef-DOCUMENT","dataLicense":"CC0-1.0","name":"cdnca-edge-agent","spdxVersion":"SPDX-2.3"}\n' \
    >"${target}/edge-agent.spdx.json"
  local artifact_sha artifact_size sbom_sha sbom_size
  artifact_sha=$(shasum -a 256 "${target}/edge-agent" | awk '{print $1}')
  artifact_size=$(stat -c '%s' "${target}/edge-agent" 2>/dev/null || stat -f '%z' "${target}/edge-agent")
  sbom_sha=$(shasum -a 256 "${target}/edge-agent.spdx.json" | awk '{print $1}')
  sbom_size=$(stat -c '%s' "${target}/edge-agent.spdx.json" 2>/dev/null || stat -f '%z' "${target}/edge-agent.spdx.json")
  printf 'manifest_version=2\nrelease_sequence=42\nversion=1.2.3\nartifact_path=edge-agent\nartifact_sha256=%s\nartifact_size=%s\nsbom_path=edge-agent.spdx.json\nsbom_sha256=%s\nsbom_size=%s\nos=linux\narch=%s\nsource_repository=https://example.invalid/cdnca\nsource_commit=1111111111111111111111111111111111111111\nbuild_time=2026-08-08T00:00:00Z\nminimum_control_protocol=1.0\nminimum_agent_protocol=1.0\n' \
    "${artifact_sha}" "${artifact_size}" "${sbom_sha}" "${sbom_size}" "${arch}" >"${target}/manifest"
  openssl pkeyutl -sign -inkey "${WORK}/keys/release-private.pem" -rawin \
    -in "${target}/manifest" -out "${target}/manifest.sig"
}

write_release amd64 62
write_release arm64 183

build_package() {
  local destination arch
  destination=$1
  arch=$2
  "${BUILDER}" \
    --architecture "${arch}" \
    --version 1.2.3 \
    --release-sequence 42 \
    --source-date-epoch 1786147200 \
    --artifact "${WORK}/release/${arch}/edge-agent" \
    --sbom "${WORK}/release/${arch}/edge-agent.spdx.json" \
    --manifest "${WORK}/release/${arch}/manifest" \
    --manifest-signature "${WORK}/release/${arch}/manifest.sig" \
    --release-public-key "${WORK}/keys/release-public.pem" \
    --rollback-key-version 1 \
    --output-dir "${destination}"
}

for arch in amd64 arm64; do
  build_package "${WORK}/packages-a" "${arch}"
  build_package "${WORK}/packages-b" "${arch}"
  package="cdnca-edge-agent_1.2.3-1_${arch}.deb"
  cmp "${WORK}/packages-a/${package}" "${WORK}/packages-b/${package}" ||
    fail "${arch} package is not reproducible"
  python3 "${REPOSITORY}" inspect-package \
    --package "${WORK}/packages-a/${package}" \
    --expect-architecture "${arch}" \
    --expect-version 1.2.3-1 \
    --require-lifecycle preinst,postinst,prerm,postrm \
    --require-path usr/lib/systemd/system/cdnca-edge-agent.service \
    --require-path usr/libexec/cdnca-edge-agent/install.sh \
    --require-path usr/lib/cdnca-edge-agent/deb-bundles/1.2.3/manifest
done

for fragment in \
  PKG_HOST_UNSUPPORTED PKG_DOWNGRADE_REFUSED PKG_ROLLBACK_AUTH_INVALID \
  PKG_ROLLBACK_AUTH_EXPIRED PKG_ROLLBACK_AUTH_REPLAY PKG_PREFLIGHT_FAILED; do
  grep -Fq "${fragment}" "${MAINTAINER}/preinst" || fail "preinst lacks ${fragment}"
done
for fragment in \
  systemd-sysusers systemd-tmpfiles 'systemctl enable --now' 'systemctl try-restart' \
  PKG_ENROLLMENT_REQUIRED PKG_SERVICE_READY PKG_INSTALL_ROLLED_BACK receipt; do
  grep -Fq "${fragment}" "${MAINTAINER}/postinst" || fail "postinst lacks ${fragment}"
done
grep -Fq 'Default removal retains identity, configuration, state, backups, and logs' \
  "${MAINTAINER}/postrm" || fail 'postrm lacks retention contract'
grep -Fq 'openssl pkeyutl -verify' "${MAINTAINER}/preinst" || fail 'downgrade authorization is not signed'

GPG_HOME="${WORK}/gpg"
mkdir -m 0700 "${GPG_HOME}"
gpg --batch --homedir "${GPG_HOME}" --passphrase '' --quick-generate-key \
  'CDNCA OPS11 Test <ops11@example.invalid>' ed25519 sign 1d >/dev/null 2>&1
FINGERPRINT=$(gpg --batch --homedir "${GPG_HOME}" --with-colons --fingerprint |
  awk -F: '$1 == "fpr" {print toupper($10); exit}')
[ "${#FINGERPRINT}" -eq 40 ] || fail 'test signing fingerprint is invalid'
NOW=1786147200
VALID_UNTIL=$((NOW + 604800))
python3 "${REPOSITORY}" publish \
  --packages-dir "${WORK}/packages-a" \
  --output-dir "${WORK}/repository" \
  --suite stable --component main --origin CDNCA --label 'CDNCA Edge' \
  --source-date-epoch "${NOW}" --valid-until-epoch "${VALID_UNTIL}" \
  --gpg-home "${GPG_HOME}" --fingerprint "${FINGERPRINT}" --key-version 1 \
  --policy-output "${WORK}/trusted-policy.json"

python3 "${REPOSITORY}" verify \
  --repository "${WORK}/repository" \
  --policy "${WORK}/trusted-policy.json" \
  --trusted-keyring "${WORK}/repository/cdnca-archive-keyring.gpg" \
  --now-epoch "$((NOW + 60))"

for arch in amd64 arm64; do
  packages="${WORK}/repository/dists/stable/main/binary-${arch}/Packages"
  digest=$(shasum -a 256 "${packages}" | awk '{print $1}')
  cmp "${packages}" "${WORK}/repository/dists/stable/main/binary-${arch}/by-hash/SHA256/${digest}" ||
    fail "${arch} Packages by-hash mismatch"
done
[ -s "${WORK}/repository/dists/stable/InRelease" ] || fail 'missing InRelease'
[ -s "${WORK}/repository/dists/stable/Release.gpg" ] || fail 'missing Release.gpg'

if grep -R -E -- 'BEGIN .*PRIVATE KEY|curl[^#|]*\|[[:space:]]*(ba)?sh|wget[^#|]*\|[[:space:]]*(ba)?sh' \
  "${ROOT}/infra/packaging/deb" "${BUILDER}" "${RUNBOOK}" >/dev/null; then
  fail 'private key material or remote pipe-to-shell found'
fi

printf 'EDGE_AGENT_DEB_PACKAGING_STATIC PASS\n'
