#!/usr/bin/env bash
set -Eeuo pipefail

fail() { printf 'EDGE_RUNTIME_SECURITY_RELEASE_STATIC FAIL: %s\n' "$1" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" | awk '{print $1}'; else shasum -a 256 -- "$1" | awk '{print $1}'; fi
}

[ "${EDGE_RUNTIME_SECURITY_RELEASE_STATIC_ONLY:-}" = "1" ] || fail 'runtime wave is not authorized; set EDGE_RUNTIME_SECURITY_RELEASE_STATIC_ONLY=1'
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH='' cd -- "${script_dir}/../.." && pwd -P)
lock=${repo_root}/edge/openresty/security-release/runtime-lock.json
snapshot=${repo_root}/edge/openresty/security-release/advisory-snapshot.json
runtime_env=${repo_root}/edge/openresty/runtime.env
policy=${repo_root}/agents/edge-agent/internal/securityrelease/policy.go
for file in "${lock}" "${snapshot}" "${runtime_env}" "${policy}"; do
  [ -f "${file}" ] && [ ! -L "${file}" ] || fail "missing or unsafe input ${file}"
done
for command in awk jq sed; do command -v "${command}" >/dev/null 2>&1 || fail "missing command ${command}"; done
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || fail 'missing SHA-256 command'

snapshot_sha=$(sha256_file "${snapshot}")
jq -e --arg snapshot_sha "${snapshot_sha}" '
  keys == ["advisory_snapshot","block_reason","release_eligible","schema","source"] and
  .schema == "cdnca.edge.openresty.runtime-lock/v1" and .release_eligible == false and
  .block_reason == "security_hotfix_advisory_open" and
  .advisory_snapshot.path == "edge/openresty/security-release/advisory-snapshot.json" and
  .advisory_snapshot.sha256 == $snapshot_sha and
  (.source.openresty_version | test("^[0-9]+(\\.[0-9]+){3}$")) and
  (.source.image_digest | test("^sha256:[0-9a-f]{64}$")) and
  (.source.tarball_sha256 | test("^[0-9a-f]{64}$"))
' "${lock}" >/dev/null || fail 'runtime lock is invalid'

jq -e '
  keys == ["advisories","observed_at","runtime","schema","source"] and
  .schema == "cdnca.edge.openresty.advisory-snapshot/v1" and
  .source == "https://nginx.org/en/security_advisories.html" and
  .runtime.openresty_version == "1.27.1.2" and .runtime.nginx_version == "1.27.1" and
  (.advisories | length >= 5) and
  (all(.advisories[];
    (.id | test("^CVE-[0-9]{4}-[0-9]+$")) and .status == "affected" and
    (.fixed_version | length > 0) and (.upstream_url | startswith("https://")) and
    (.required_regression | test("^[a-z][a-z0-9-]+$")))) and
  ([.advisories[].id] | index("CVE-2025-23419") != null) and
  ([.advisories[].id] | index("CVE-2026-42533") != null) and
  ([.advisories[].id] | index("CVE-2026-40460") != null)
' "${snapshot}" >/dev/null || fail 'advisory snapshot is incomplete'

env_version=$(sed -n 's/^OPENRESTY_VERSION=//p' "${runtime_env}")
env_image=$(sed -n 's/^OPENRESTY_IMAGE=//p' "${runtime_env}")
env_tar_sha=$(sed -n 's/^OPENRESTY_TARBALL_SHA256=//p' "${runtime_env}")
[ "$(jq -r '.source.openresty_version' "${lock}")" = "${env_version}" ] || fail 'OpenResty version drift'
[ "$(jq -r '.source.image_digest' "${lock}")" = "${env_image#*@}" ] || fail 'OpenResty image digest drift'
[ "$(jq -r '.source.tarball_sha256' "${lock}")" = "${env_tar_sha}" ] || fail 'OpenResty tarball digest drift'

printf 'EDGE_RUNTIME_SECURITY_RELEASE_STATIC PASS release_eligible=false reason=security_hotfix_advisory_open\n'
