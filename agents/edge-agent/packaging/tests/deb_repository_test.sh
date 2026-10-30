#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGING_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly SCRIPT_DIR PACKAGING_ROOT
readonly REPOSITORY_BUILDER="${PACKAGING_ROOT}/deb/build-repository.sh"
readonly PACKAGE_BUILDER="${PACKAGING_ROOT}/../../../scripts/package-edge-agent-deb.sh"
readonly RELEASE_SET_VALIDATOR="${PACKAGING_ROOT}/deb/validate-release-set.sh"
readonly DEB_PREINST="${PACKAGING_ROOT}/../../../infra/packaging/deb/maintainer/preinst"
readonly SUITE=stable COMPONENT=main
readonly VERSION_ONE=1.0.0 VERSION_TWO=1.1.0 VERSION_BAD=1.2.0

fail() { printf 'edge apt repository test: %s\n' "$1" >&2; exit 1; }
sha256_file() { sha256sum -- "$1" | awk '{print $1}'; }
file_size() { stat -c '%s' -- "$1"; }

write_release() {
  local output=$1 arch=$2 version=$3 healthy=$4 sequence=$5
  local artifact sbom provenance artifact_sha sbom_sha created
  mkdir -p "${output}"
  artifact=${output}/edge-agent
  sbom=${output}/edge-agent.spdx.json
  provenance=${output}/edge-agent.provenance.json
  env CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -buildvcs=false \
    -ldflags "-buildid= -s -w -X main.agentVersion=${version} -X main.healthy=${healthy}" \
    -o "${artifact}" "${fixture_source}"
  chmod 0555 "${artifact}"
  artifact_sha=$(sha256_file "${artifact}")
  created=$(date -u -d "@${source_epoch}" '+%Y-%m-%dT%H:%M:%SZ')
  jq -S -c -n --arg created "${created}" --arg version "${version}" --arg artifact "${artifact_sha}" '
    {SPDXID:"SPDXRef-DOCUMENT",creationInfo:{created:$created,creators:["Tool: cdnca-edge-deb-test"]},
     dataLicense:"CC0-1.0",documentNamespace:("https://cdnca.invalid/spdx/deb-test/"+$artifact),
     files:[{SPDXID:"SPDXRef-File-edge-agent",checksums:[{algorithm:"SHA256",checksumValue:$artifact}],fileName:"edge-agent"}],
     name:("cdnca-edge-agent-"+$version),spdxVersion:"SPDX-2.3"}
  ' >"${sbom}"
  sbom_sha=$(sha256_file "${sbom}")
  jq -S -c -n --arg arch "${arch}" --arg artifact_sha "${artifact_sha}" \
    --argjson artifact_size "$(file_size "${artifact}")" --arg created "${created}" \
    --arg sbom_sha "${sbom_sha}" --arg version "${version}" '
    {arch:$arch,artifact:{path:"edge-agent",sha256:$artifact_sha,size:$artifact_size},
     build_id:("deb-test-"+$version+"-"+$arch),builder:{image:"test.invalid/fixture@sha256:0000000000000000000000000000000000000000000000000000000000000000",toolchain:"go-test"},
     created:$created,recipe:{source_date_epoch:0},sbom:{path:"edge-agent.spdx.json",sha256:$sbom_sha},
     schema:"cdnca.edge.release-provenance/v1",source_commit:"0123456789abcdef0123456789abcdef01234567",
     source_repository:"https://example.invalid/cdnca.git",version:$version}
  ' >"${provenance}"
  chmod 0444 "${sbom}" "${provenance}"
  printf '%s\t%s\t%s\n' "${sequence}" "${arch}" "${output}" >>"${release_rows}"
}

build_repository() {
  local output=$1 work apt_home apt_fingerprint config key_epoch valid_until
  local arch version health sequence release_dir package packages digest
  for command in date dpkg-deb gpg gpgv go jq openssl sha256sum stat; do
    command -v "${command}" >/dev/null 2>&1 || fail "missing build command: ${command}"
  done
  [ -f "${REPOSITORY_BUILDER}" ] && [ ! -L "${REPOSITORY_BUILDER}" ] || fail 'missing repository builder'
  case "${output}" in /*) ;; *) fail 'build output must be absolute' ;; esac
  [ ! -e "${output}" ] && [ ! -L "${output}" ] || fail 'build output already exists'
  work=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-edge-deb-test.XXXXXX")
  trap 'rm -rf -- "${work}"' EXIT
  fixture_source=${work}/fixture.go
  release_rows=${work}/releases.tsv
  source_epoch=$(date +%s)
  readonly fixture_source release_rows source_epoch
  : >"${release_rows}"
  cat >"${fixture_source}" <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var agentVersion = "development"
var healthy = "false"

func main() {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--version" {
		fmt.Printf("{\"event\":\"version\",\"agent_version\":%q}\n", agentVersion)
		return
	}
	if len(args) == 1 && args[0] == "--health" {
		if healthy == "true" {
			fmt.Println("healthy")
			return
		}
		os.Exit(1)
	}
	if len(args) == 3 && args[0] == "--check-config" && args[1] == "-config" {
		body, err := os.ReadFile(args[2])
		if err == nil && json.Valid(body) {
			return
		}
		os.Exit(1)
	}
	if len(args) == 2 && args[0] == "-config" {
		body, err := os.ReadFile(args[1])
		if err != nil || !json.Valid(body) || healthy != "true" {
			os.Exit(1)
		}
		stopped := make(chan os.Signal, 1)
		signal.Notify(stopped, syscall.SIGINT, syscall.SIGTERM)
		<-stopped
		signal.Stop(stopped)
		return
	}
	os.Exit(64)
}
GO
  for arch in amd64 arm64; do
    for release in "1:${VERSION_ONE}:true" "2:${VERSION_TWO}:true" "3:${VERSION_BAD}:false"; do
      sequence=${release%%:*}
      version=${release#*:}; version=${version%%:*}
      health=${release##*:}
      release_dir=${work}/release-${version}-${arch}
      write_release "${release_dir}" "${arch}" "${version}" "${health}" "${sequence}"
    done
  done
  openssl genpkey -algorithm Ed25519 -out "${work}/release-private.pem" >/dev/null 2>&1
  openssl pkey -in "${work}/release-private.pem" -pubout -out "${work}/release-public.pem" >/dev/null 2>&1
  chmod 0400 "${work}/release-private.pem"
  chmod 0444 "${work}/release-public.pem"

  apt_home=${work}/apt-gnupg
  mkdir -m 0700 "${apt_home}"
  key_epoch=$((source_epoch - 3600))
  gpg --batch --homedir "${apt_home}" --pinentry-mode loopback --passphrase '' \
    --faked-system-time "${key_epoch}!" --quick-gen-key 'CDNCA Edge Repository Test <edge-test@cdnca.invalid>' ed25519 sign 0 >/dev/null 2>&1
  apt_fingerprint=$(gpg --batch --homedir "${apt_home}" --with-colons --fingerprint |
    awk -F: '$1 == "fpr" {print toupper($10); exit}')
  [[ "${apt_fingerprint}" =~ ^[0-9A-F]{40}$ ]] || fail 'generate apt signing key'
  valid_until=$((source_epoch + 604800))
  config=${work}/repository.json
  jq -S -n --arg suite "${SUITE}" --arg component "${COMPONENT}" \
    --argjson source_date_epoch "${source_epoch}" --argjson valid_until_epoch "${valid_until}" \
    --rawfile releases "${release_rows}" '
    {component:$component,label:"CDNCA Edge",origin:"CDNCA",releases:($releases | split("\n") |
       map(select(length > 0) | split("\t") | {release_sequence:(.[0]|tonumber),arch:.[1],path:.[2]})),
     rollback_key_version:1,schema:"cdnca.edge.apt-repository/v1",source_date_epoch:$source_date_epoch,suite:$suite,
     valid_until_epoch:$valid_until_epoch}
  ' >"${config}"
  "${REPOSITORY_BUILDER}" --config "${config}" --output-dir "${output}" \
    --release-private-key "${work}/release-private.pem" --release-public-key "${work}/release-public.pem" \
    --apt-homedir "${apt_home}" --apt-key-id "${apt_fingerprint}"

  gpgv --keyring "${output}/cdnca-archive-keyring.gpg" "${output}/dists/${SUITE}/InRelease" >/dev/null 2>&1 ||
    fail 'verify built InRelease'
  gpgv --keyring "${output}/cdnca-archive-keyring.gpg" "${output}/dists/${SUITE}/Release.gpg" \
    "${output}/dists/${SUITE}/Release" >/dev/null 2>&1 || fail 'verify built Release.gpg'
  [ -z "$(find "${output}" -type d ! -perm 0755 -print -quit)" ] || fail 'repository directory mode'
  [ -z "$(find "${output}" -type f ! -perm 0444 -print -quit)" ] || fail 'repository file mode'
  for arch in amd64 arm64; do
    packages=${output}/dists/${SUITE}/${COMPONENT}/binary-${arch}/Packages
    [ -s "${packages}" ] || fail "missing ${arch} Packages"
    digest=$(sha256_file "${packages}")
    cmp -s "${packages}" "${output}/dists/${SUITE}/${COMPONENT}/binary-${arch}/by-hash/SHA256/${digest}" ||
      fail "${arch} by-hash Packages mismatch"
    for version in "${VERSION_ONE}" "${VERSION_TWO}" "${VERSION_BAD}"; do
      package=${output}/pool/${COMPONENT}/c/cdnca-edge-agent/cdnca-edge-agent_${version}-1_${arch}.deb
      [ "$(dpkg-deb -f "${package}" Package)" = cdnca-edge-agent ] || fail "${version}/${arch} package name"
      [ "$(dpkg-deb -f "${package}" Architecture)" = "${arch}" ] || fail "${version}/${arch} package architecture"
      dpkg-deb --fsys-tarfile "${package}" | tar -tf - | sed 's#^\./##' | grep -Fx 'usr/libexec/cdnca-edge-agent/upgrade.sh' >/dev/null ||
        fail "${version}/${arch} package upgrade asset"
      dpkg-deb --fsys-tarfile "${package}" | tar -tf - | sed 's#^\./##' | grep -Fx 'usr/lib/systemd/system/cdnca-edge-agent.service' >/dev/null ||
        fail "${version}/${arch} package systemd unit"
      for lifecycle in preinst postinst prerm postrm; do
        dpkg-deb --ctrl-tarfile "${package}" | tar -tf - | sed 's#^\./##' | grep -Fx "${lifecycle}" >/dev/null ||
          fail "${version}/${arch} package ${lifecycle} lifecycle"
      done
    done
  done
  jq -e '.schema == "cdnca.edge.apt-repository-provenance/v1" and (.packages | length) == 6 and
    all(.packages[]; (.sha256 | test("^[0-9a-f]{64}$")))' \
    "${output}/repository.provenance.json" >/dev/null || fail 'repository provenance'
  trap - EXIT
  rm -rf -- "${work}"
  printf 'EDGE_AGENT_APT_REPOSITORY_BUILD PASS\n'
}

install_fake_systemctl() {
  [ -x /usr/bin/systemctl ] || fail 'systemctl dependency is unavailable'
  mv /usr/bin/systemctl /usr/bin/systemctl.cdnca-real
  cat >/usr/bin/systemctl <<'SH'
#!/bin/sh
set -eu
state=/run/cdnca-edge-agent-test-active
case "${1:-}" in
  # Host preflight reads the real systemd version (lib.sh require_supported_host).
  --version) exec /usr/bin/systemctl.cdnca-real --version ;;
  daemon-reload) exit 0 ;;
  stop|disable) rm -f -- "${state}"; exit 0 ;;
  enable) : >"${state}"; exit 0 ;;
  # postinst try-restarts an active service when reinstalling the current release.
  try-restart|restart)
    [ "${1}" = restart ] || [ -f "${state}" ] || exit 0
    if /usr/lib/cdnca-edge-agent/current/edge-agent --health >/dev/null 2>&1; then
      : >"${state}"
    else
      rm -f -- "${state}"
    fi
    exit 0
    ;;
  is-active)
    [ "${2:-}" = --quiet ] && [ "${3:-}" = cdnca-edge-agent.service ] || exit 64
    [ -f "${state}" ] || exit 3
    /usr/lib/cdnca-edge-agent/current/edge-agent --health >/dev/null 2>&1 || exit 3
    exit 0
    ;;
  *) exit 64 ;;
esac
SH
  chmod 0755 /usr/bin/systemctl
}

assert_current() {
  local version=$1
  [ "$(readlink /usr/lib/cdnca-edge-agent/current)" = "versions/${version}" ] || fail "current release is not ${version}"
  /usr/lib/cdnca-edge-agent/current/edge-agent --version | grep -F "\"agent_version\":\"${version}\"" >/dev/null ||
    fail "current binary identity is not ${version}"
}

verify_distribution() {
  local repository=$1 distro=$2 arch=$3 actual_id actual_version bad_status package_status accepted
  for command in apt-get dpkg-query gpgv jq readlink sha256sum; do
    command -v "${command}" >/dev/null 2>&1 || fail "missing verify command: ${command}"
  done
  [ "$(id -u)" -eq 0 ] || fail 'distribution verification must run as root'
  [ -d "${repository}" ] && [ ! -L "${repository}" ] || fail 'unsafe repository path'
  [ "$(dpkg --print-architecture)" = "${arch}" ] || fail 'container architecture mismatch'
  actual_id=$(sed -n 's/^ID=//p' /etc/os-release | sed 's/^"//;s/"$//' | sed -n '1p')
  actual_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | sed 's/^"//;s/"$//' | sed -n '1p')
  case "${distro}:${actual_id}:${actual_version}" in
    debian12:debian:12|ubuntu2404:ubuntu:24.04) ;;
    *) fail "unexpected distribution ${actual_id}/${actual_version}" ;;
  esac
  gpgv --keyring "${repository}/cdnca-archive-keyring.gpg" "${repository}/dists/${SUITE}/InRelease" >/dev/null 2>&1 ||
    fail 'distribution InRelease verification'
  printf 'deb [signed-by=%s/cdnca-archive-keyring.gpg] file:%s %s %s\n' \
    "${repository}" "${repository}" "${SUITE}" "${COMPONENT}" >/etc/apt/sources.list.d/cdnca-edge.list
  apt-get update -o Acquire::Languages=none -qq
  apt-cache policy cdnca-edge-agent | grep -F "${VERSION_ONE}-1" >/dev/null || fail 'apt did not acquire repository packages'
  install_fake_systemctl
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "cdnca-edge-agent=${VERSION_ONE}-1" >/dev/null
  [ "$(dpkg-query -W -f='${Architecture}' cdnca-edge-agent)" = "${arch}" ] || fail 'installed package architecture'
  [ "$(dpkg-query -W -f='${db:Status-Status}' cdnca-edge-agent)" = installed ] || fail 'first package is not installed'
  assert_current "${VERSION_ONE}"

  printf '%s\n' '{"repository_test":true}' >/etc/cdnca-edge-agent/config.json
  chown cdnca-edge:cdnca-edge /etc/cdnca-edge-agent/config.json
  chmod 0600 /etc/cdnca-edge-agent/config.json
  printf '%s\n' state-v1 >/var/lib/cdnca-edge-agent-backups/active-state/state.txt
  chown cdnca-edge:cdnca-edge /var/lib/cdnca-edge-agent-backups/active-state/state.txt
  chmod 0600 /var/lib/cdnca-edge-agent-backups/active-state/state.txt
  systemctl restart cdnca-edge-agent.service
  systemctl is-active --quiet cdnca-edge-agent.service || fail 'v1 service is not active'

  CDNCA_EDGE_DEB_HEALTH_TIMEOUT=3 CDNCA_EDGE_DEB_HEALTH_STABLE=0 DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq "cdnca-edge-agent=${VERSION_TWO}-1" >/dev/null
  assert_current "${VERSION_TWO}"
  [ "$(dpkg-query -W -f='${db:Status-Status}' cdnca-edge-agent)" = installed ] || fail 'v2 package is not installed'
  systemctl is-active --quiet cdnca-edge-agent.service || fail 'v2 service is not active'
  printf '%s\n' state-v2 >/var/lib/cdnca-edge-agent-backups/active-state/state.txt
  chown cdnca-edge:cdnca-edge /var/lib/cdnca-edge-agent-backups/active-state/state.txt
  chmod 0600 /var/lib/cdnca-edge-agent-backups/active-state/state.txt

  set +e
  CDNCA_EDGE_DEB_HEALTH_TIMEOUT=2 CDNCA_EDGE_DEB_HEALTH_STABLE=0 DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq "cdnca-edge-agent=${VERSION_BAD}-1" >/dev/null 2>&1
  bad_status=$?
  set -e
  [ "${bad_status}" -ne 0 ] || fail 'unhealthy package upgrade unexpectedly passed'
  assert_current "${VERSION_TWO}"
  [ "$(cat /var/lib/cdnca-edge-agent-backups/active-state/state.txt)" = state-v2 ] || fail 'failed upgrade did not restore v2 state'
  systemctl is-active --quiet cdnca-edge-agent.service || fail 'failed upgrade did not restore the v2 service'
  accepted=/var/lib/cdnca-edge-agent-packaging/accepted-manifest
  grep -Fx 'release_sequence=2' "${accepted}" >/dev/null || fail 'failed upgrade advanced accepted sequence'
  grep -Fx "version=${VERSION_TWO}" "${accepted}" >/dev/null || fail 'failed upgrade changed accepted version'
  package_status=$(dpkg-query -W -f='${db:Status-Status}' cdnca-edge-agent)
  [ "${package_status}" != installed ] || fail 'failed package upgrade is incorrectly configured'

  CDNCA_EDGE_DEB_HEALTH_TIMEOUT=2 CDNCA_EDGE_DEB_HEALTH_STABLE=0 DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq --allow-downgrades "cdnca-edge-agent=${VERSION_TWO}-1" >/dev/null
  [ "$(dpkg-query -W -f='${db:Status-Status}' cdnca-edge-agent)" = installed ] || fail 'dpkg state did not recover to v2'
  assert_current "${VERSION_TWO}"
  /usr/libexec/cdnca-edge-agent/rollback.sh --version "${VERSION_ONE}" --health-timeout 2 --health-stable 0 >/dev/null
  assert_current "${VERSION_ONE}"
  [ "$(cat /var/lib/cdnca-edge-agent-backups/active-state/state.txt)" = state-v1 ] || fail 'explicit rollback did not restore v1 state'
  systemctl is-active --quiet cdnca-edge-agent.service || fail 'explicit rollback service is not active'
  grep -Fx 'release_sequence=2' "${accepted}" >/dev/null || fail 'explicit rollback weakened accepted replay floor'
  printf 'EDGE_AGENT_APT_DISTRIBUTION_%s_%s PASS\n' "${distro}" "${arch}"
}

verify_static_contract() {
  [ -f "${REPOSITORY_BUILDER}" ] && [ ! -L "${REPOSITORY_BUILDER}" ] || fail 'missing repository builder'
  [ -f "${PACKAGE_BUILDER}" ] && [ ! -L "${PACKAGE_BUILDER}" ] || fail 'missing package builder'
  [ -f "${RELEASE_SET_VALIDATOR}" ] && [ ! -L "${RELEASE_SET_VALIDATOR}" ] || fail 'missing release-set validator'
  [ -f "${DEB_PREINST}" ] && [ ! -L "${DEB_PREINST}" ] || fail 'missing Debian preinst'
  bash -n "${REPOSITORY_BUILDER}" "${PACKAGE_BUILDER}" "${RELEASE_SET_VALIDATOR}" "${DEB_PREINST}" "$0"
  grep -F "PACKAGE_BUILDER=\"\${REPO_ROOT}/scripts/package-edge-agent-deb.sh\"" \
    "${REPOSITORY_BUILDER}" >/dev/null || fail 'repository does not use the canonical package builder'
  grep -F "\"\${PACKAGE_BUILDER}\" --architecture" "${REPOSITORY_BUILDER}" >/dev/null ||
    fail 'repository does not invoke the canonical package builder'
  grep -F -- "--rollback-key-version \"\${rollback_key_version}\"" "${REPOSITORY_BUILDER}" >/dev/null ||
    fail 'repository does not bind the rollback trust key version'
  if grep -F 'dpkg-deb --root-owner-group' "${REPOSITORY_BUILDER}" >/dev/null; then
    fail 'repository still contains a second Debian package implementation'
  fi
  # shellcheck disable=SC2016 # Assert literal production variable references.
  grep -F '"${RELEASE_SET_VALIDATOR}" "${packages_manifest}"' "${REPOSITORY_BUILDER}" >/dev/null ||
    fail 'repository does not validate the complete native release set'

  matrix=$(mktemp "${TMPDIR:-/tmp}/cdnca-edge-release-set.XXXXXX")
  cleanup_matrix() { rm -f -- "${matrix}"; }
  trap cleanup_matrix EXIT
  printf 'amd64\t1.0.0-1\t1.0.0\t10\tpool/amd64.deb\t%s\narm64\t1.0.0-1\t1.0.0\t10\tpool/arm64.deb\t%s\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' >"${matrix}"
  "${RELEASE_SET_VALIDATOR}" "${matrix}" >/dev/null || fail 'complete amd64/arm64 release set was rejected'
  sed -n '1p' "${matrix}" >"${matrix}.invalid"
  if "${RELEASE_SET_VALIDATOR}" "${matrix}.invalid" >/dev/null 2>&1; then
    fail 'single-architecture release set was accepted'
  fi
  sed '2s/\t10\t/\t11\t/' "${matrix}" >"${matrix}.invalid"
  if "${RELEASE_SET_VALIDATOR}" "${matrix}.invalid" >/dev/null 2>&1; then
    fail 'cross-architecture release sequence split was accepted'
  fi
  cp "${matrix}" "${matrix}.invalid"
  printf 'amd64\t1.1.0-1\t1.1.0\t10\tpool/other-amd64.deb\t%s\narm64\t1.1.0-1\t1.1.0\t10\tpool/other-arm64.deb\t%s\n' \
    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' >>"${matrix}.invalid"
  if "${RELEASE_SET_VALIDATOR}" "${matrix}.invalid" >/dev/null 2>&1; then
    fail 'one release sequence was accepted for two versions'
  fi
  rm -f -- "${matrix}.invalid"
  trap - EXIT
  cleanup_matrix

  grep -F 'debian:12) minimum_systemd_version=252' "${DEB_PREINST}" >/dev/null ||
    fail 'Debian 12 systemd floor is not explicit in preinst'
  grep -F 'ubuntu:24.04) minimum_systemd_version=255' "${DEB_PREINST}" >/dev/null ||
    fail 'Ubuntu 24.04 systemd floor is not explicit in preinst'
  # shellcheck disable=SC2016 # Assert literal production variable references.
  grep -F '"${systemd_version}" -ge "${minimum_systemd_version}"' "${DEB_PREINST}" >/dev/null ||
    fail 'preinst does not enforce the distribution-specific systemd floor'
  printf 'EDGE_AGENT_APT_REPOSITORY_STATIC PASS\n'
}

case "${1:-}" in
  static)
    [ "$#" -eq 1 ] || fail 'usage: deb_repository_test.sh static'
    verify_static_contract
    ;;
  build)
    [ "$#" -eq 2 ] || fail 'usage: deb_repository_test.sh build OUTPUT'
    build_repository "$2"
    ;;
  verify)
    [ "$#" -eq 4 ] || fail 'usage: deb_repository_test.sh verify REPOSITORY DISTRO ARCH'
    verify_distribution "$2" "$3" "$4"
    ;;
  *) fail 'usage: deb_repository_test.sh static | build OUTPUT | verify REPOSITORY DISTRO ARCH' ;;
esac
