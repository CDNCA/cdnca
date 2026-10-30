#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-repro.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-repro\.//')"
builder="cdnca-edge-repro-${suffix}"

cleanup() {
  docker buildx rm "${builder}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-repro.*) rm -rf -- "${workdir}" ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

if ! base_repo_digests="$(docker image inspect "${OPENRESTY_IMAGE}" --format '{{json .RepoDigests}}' 2>/dev/null)"; then
  echo "fixed OpenResty image is not present in the local Docker store: ${OPENRESTY_IMAGE}" >&2
  exit 1
fi
printf '%s' "${base_repo_digests}" | jq -e --arg expected "${OPENRESTY_IMAGE}" 'index($expected) != null' >/dev/null || {
  echo "local OpenResty image does not carry the required repo digest: ${OPENRESTY_IMAGE}" >&2
  exit 1
}
mkdir "${workdir}/base-layout"
docker image save --output "${workdir}/base.tar" "${OPENRESTY_IMAGE}"
tar -xf "${workdir}/base.tar" -C "${workdir}/base-layout"
jq -e --arg digest "${OPENRESTY_SOURCE_DIGEST}" \
  '.manifests | any(.digest == $digest)' \
  "${workdir}/base-layout/index.json" >/dev/null || {
  echo "local OCI layout does not contain the fixed base manifest: ${OPENRESTY_SOURCE_DIGEST}" >&2
  exit 1
}
test -f "${workdir}/base-layout/blobs/sha256/${OPENRESTY_SOURCE_DIGEST#sha256:}"

docker buildx create \
  --name "${builder}" \
  --driver docker-container \
  --driver-opt "image=${BUILDKIT_IMAGE}" >/dev/null
docker buildx inspect --bootstrap "${builder}" >/dev/null

entrypoint_base64="$(base64 <"${repo_root}/edge/openresty/entrypoint.sh" | tr -d '\n')"
entrypoint_sha256="$(shasum -a 256 "${repo_root}/edge/openresty/entrypoint.sh" | awk '{print $1}')"

build_oci() {
  name="$1"
  if ! docker buildx build \
    --builder "${builder}" \
    --no-cache \
    --pull=false \
    --provenance=false \
    --build-context "cdnca-openresty-base=oci-layout://${workdir}/base-layout@${OPENRESTY_SOURCE_DIGEST}" \
    --build-arg "OPENRESTY_IMAGE=cdnca-openresty-base" \
    --build-arg "OPENRESTY_VERSION=${OPENRESTY_VERSION}" \
    --build-arg "OPENRESTY_SOURCE_DIGEST=${OPENRESTY_SOURCE_DIGEST}" \
    --build-arg "SOURCE_DATE_EPOCH=${OPENRESTY_SOURCE_DATE_EPOCH}" \
    --build-arg "ENTRYPOINT_BASE64=${entrypoint_base64}" \
    --build-arg "ENTRYPOINT_SHA256=${entrypoint_sha256}" \
    --label "org.opencontainers.image.revision=uncommitted" \
    --tag cdnca/openresty-runtime:repro \
    --metadata-file "${workdir}/${name}.json" \
    --output "type=oci,dest=${workdir}/${name}.tar,rewrite-timestamp=true,compression=gzip,compression-level=9,force-compression=true" \
    --file "${repo_root}/edge/openresty/Dockerfile" \
    "${repo_root}" >"${workdir}/${name}.log" 2>&1; then
    cat "${workdir}/${name}.log" >&2
    exit 1
  fi
}

build_oci first
build_oci second

first_digest="$(jq -er '."containerimage.digest"' "${workdir}/first.json")"
second_digest="$(jq -er '."containerimage.digest"' "${workdir}/second.json")"
if [ "${first_digest}" != "${second_digest}" ]; then
  echo "OCI manifest digests differ: ${first_digest} != ${second_digest}" >&2
  echo "first index:" >&2
  tar -xOf "${workdir}/first.tar" index.json >&2
  echo "second index:" >&2
  tar -xOf "${workdir}/second.tar" index.json >&2
  exit 1
fi

first_tar_sha256="$(shasum -a 256 "${workdir}/first.tar" | awk '{print $1}')"
second_tar_sha256="$(shasum -a 256 "${workdir}/second.tar" | awk '{print $1}')"
printf 'buildkit_image=%s\nbase_source=local-docker-cache\nbase_manifest_digest=%s\noci_manifest_digest=%s\nfirst_tar_sha256=%s\nsecond_tar_sha256=%s\ntar_bytes_match=%s\n' \
  "${BUILDKIT_IMAGE}" "${OPENRESTY_SOURCE_DIGEST}" "${first_digest}" "${first_tar_sha256}" "${second_tar_sha256}" \
  "$(test "${first_tar_sha256}" = "${second_tar_sha256}" && echo true || echo false)"
