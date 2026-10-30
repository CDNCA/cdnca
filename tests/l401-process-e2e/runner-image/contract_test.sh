#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract assertions intentionally match literal source.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly DOCKERFILE="${SCRIPT_DIR}/Dockerfile"
readonly BUILD="${SCRIPT_DIR}/build.sh"
readonly LOCK="${SCRIPT_DIR}/inputs.lock.json"

fail() {
  printf 'L401_RUNNER_IMAGE_CONTRACT FAIL check=%s\n' "$1" >&2
  exit 1
}

require_literal() {
  local file=$1 literal=$2 check=$3
  grep -Fq -- "${literal}" "${file}" || fail "${check}"
}

for file in "${DOCKERFILE}" "${BUILD}" "${LOCK}"; do
  [ -f "${file}" ] && [ ! -L "${file}" ] || fail 'authoritative-input-file'
done

require_literal "${BUILD}" "for command in awk bash docker find grep jq mktemp sha256sum sort; do" host-command-preflight

go_image="$(jq -er '.go_image' "${LOCK}")"
snapshot="$(jq -er '.debian_snapshot' "${LOCK}")"
platform="$(jq -er '.platform' "${LOCK}")"
source_date_epoch="$(jq -er '.source_date_epoch' "${LOCK}")"
apt_packages="$(jq -er '.apt_packages | join(" ")' "${LOCK}")"
[[ ${go_image} =~ @sha256:[0-9a-f]{64}$ ]] || fail 'go-digest'
# OpenResty is the node runtime of edge/openresty/runtime.env, not a second pin.
jq -e '(has("openresty_image") | not) and (has("openresty_version") | not)' "${LOCK}" >/dev/null ||
  fail 'openresty-pin-in-lock'
[[ ${snapshot} =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail 'snapshot-lock'
[ "${platform}" = 'linux/amd64' ] || fail 'platform-lock'

require_literal "${DOCKERFILE}" "ARG GO_IMAGE=${go_image}" fixed-go-default
grep -Fxq 'ARG OPENRESTY_IMAGE' "${DOCKERFILE}" || fail 'openresty-image-without-default'
grep -Fxq 'ARG OPENRESTY_VERSION' "${DOCKERFILE}" || fail 'openresty-version-without-default'
require_literal "${BUILD}" 'readonly RUNTIME_ENV="${SCRIPT_DIR}/../../../edge/openresty/runtime.env"' openresty-runtime-env
require_literal "${BUILD}" "openresty_image=\"\$(sed -n 's/^OPENRESTY_IMAGE=//p' \"\${RUNTIME_ENV}\")\"" openresty-image-from-runtime-env
require_literal "${BUILD}" "openresty_version=\"\$(sed -n 's/^OPENRESTY_VERSION=//p' \"\${RUNTIME_ENV}\")\"" openresty-version-from-runtime-env
require_literal "${BUILD}" '--build-arg "OPENRESTY_IMAGE=${openresty_image}"' openresty-image-build-arg
require_literal "${BUILD}" '--build-arg "OPENRESTY_VERSION=${openresty_version}"' openresty-version-build-arg
require_literal "${DOCKERFILE}" "ARG DEBIAN_SNAPSHOT=${snapshot}" fixed-snapshot-default
require_literal "${DOCKERFILE}" "ARG SOURCE_DATE_EPOCH=${source_date_epoch}" fixed-source-date-epoch
require_literal "${DOCKERFILE}" "ARG APT_PACKAGES=\"${apt_packages}\"" fixed-package-set
require_literal "${DOCKERFILE}" 'https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/' snapshot-https
require_literal "${DOCKERFILE}" 'signed-by=/usr/share/keyrings/debian-archive-keyring.gpg' release-signature
require_literal "${DOCKERFILE}" 'io.cdnca.l401.runner.provenance-input-sha256=' provenance-label
require_literal "${DOCKERFILE}" 'ARG BUILDX_BUILDER=' builder-arg
require_literal "${DOCKERFILE}" 'ARG BUILDX_BUILDER_PLATFORMS=' builder-platforms-arg
require_literal "${DOCKERFILE}" 'io.cdnca.l401.runner.buildx-builder=' builder-label
require_literal "${DOCKERFILE}" 'io.cdnca.l401.runner.buildx-builder-platforms=' builder-platforms-label
require_literal "${BUILD}" '--output "type=docker,dest=${OUTPUT_DIR}/runner-image.tar,rewrite-timestamp=true"' reproducible-archive
require_literal "${BUILD}" '--platform "${platform}"' fixed-platform
require_literal "${BUILD}" 'readonly BUILDX_BUILDER="${L401_BUILDX_BUILDER:-}"' explicit-builder-input
require_literal "${BUILD}" 'docker buildx inspect --bootstrap "${BUILDX_BUILDER}"' builder-capability-preflight
require_literal "${BUILD}" 'buildx_builder_platforms' builder-platform-provenance
require_literal "${BUILD}" 'docker load --input "${OUTPUT_DIR}/runner-image.tar"' local-load
require_literal "${BUILD}" 'L401_RUNNER_IMAGE=%s' local-content-reference
require_literal "${BUILD}" 'L401_RUNNER_PROVENANCE_INPUT_SHA256=%s' provenance-reference
require_literal "${BUILD}" 'debian-packages.tsv' package-inventory
require_literal "${BUILD}" 'provenance-inputs.json.sha256' provenance-checksum
require_literal "${BUILD}" 'sha256sum runner-image.tar >runner-image.tar.sha256' portable-archive-checksum

if grep -Eq '(^|[^[:alnum:]])latest([^[:alnum:]]|$)' "${DOCKERFILE}" "${BUILD}" "${LOCK}"; then
  fail 'floating-latest-tag'
fi
if grep -Fq 'http://snapshot.debian.org' "${DOCKERFILE}"; then
  fail 'insecure-snapshot-transport'
fi
if grep -Eq '(trusted=yes|AllowUnauthenticated|allow-unauthenticated)' "${DOCKERFILE}"; then
  fail 'disabled-package-authentication'
fi
if grep -Eq 'docker[[:space:]]+(login|push)' "${BUILD}"; then
  fail 'registry-dependency'
fi

printf 'L401_RUNNER_IMAGE_CONTRACT PASS\n'
