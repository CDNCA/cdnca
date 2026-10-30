#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
. "${repo_root}/edge/openresty/runtime.env"

image="${1:-cdnca/openresty-runtime:${OPENRESTY_VERSION}}"
case "${image}" in
  *[!A-Za-z0-9._:/@-]*)
    echo "unsafe image reference: ${image}" >&2
    exit 64
    ;;
esac

if [ "${CDNCA_EDGE_NO_CACHE:-0}" = "1" ]; then
  set -- --no-cache
else
  set --
fi

entrypoint_path="${repo_root}/edge/openresty/entrypoint.sh"
entrypoint_base64="$(base64 <"${entrypoint_path}" | tr -d '\n')"
entrypoint_sha256="$(shasum -a 256 "${entrypoint_path}" | awk '{print $1}')"

docker build \
  "$@" \
  --pull=false \
  --provenance=false \
  --build-arg "OPENRESTY_IMAGE=${OPENRESTY_IMAGE}" \
  --build-arg "OPENRESTY_BUILD_IMAGE=${OPENRESTY_BUILD_IMAGE}" \
	  --build-arg "OPENRESTY_VERSION=${OPENRESTY_VERSION}" \
	  --build-arg "OPENRESTY_SOURCE_DIGEST=${OPENRESTY_SOURCE_DIGEST}" \
	  --build-arg "OPENRESTY_TARBALL_URL=${OPENRESTY_TARBALL_URL}" \
	  --build-arg "OPENRESTY_TARBALL_SHA256=${OPENRESTY_TARBALL_SHA256}" \
  --build-arg "SOURCE_DATE_EPOCH=${OPENRESTY_SOURCE_DATE_EPOCH}" \
  --build-arg "ENTRYPOINT_BASE64=${entrypoint_base64}" \
  --build-arg "ENTRYPOINT_SHA256=${entrypoint_sha256}" \
  --label "org.opencontainers.image.revision=${CDNCA_EDGE_REVISION:-uncommitted}" \
  --file "${repo_root}/edge/openresty/Dockerfile" \
  --tag "${image}" \
  "${repo_root}"

docker image inspect "${image}" --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "org.opencontainers.image.base.digest"}}'
