#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly DOCKERFILE="${SCRIPT_DIR}/Dockerfile"
readonly INPUT_LOCK="${SCRIPT_DIR}/inputs.lock.json"
# The runner's OpenResty is the node runtime pinned in edge/openresty/runtime.env.
readonly RUNTIME_ENV="${SCRIPT_DIR}/../../../edge/openresty/runtime.env"
readonly BUILDX_BUILDER="${L401_BUILDX_BUILDER:-}"

fail() {
  printf 'L401_RUNNER_IMAGE_BUILD FAIL stage=%s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing-command-$1"
}

[ "$#" -eq 1 ] || fail 'usage-build-sh-output-directory'
for command in awk bash docker find grep jq mktemp sha256sum sort; do
  require_command "${command}"
done
[ -n "${BUILDX_BUILDER}" ] || fail 'missing-buildx-builder'
docker info >/dev/null 2>&1 || fail 'docker-daemon'
docker buildx version >/dev/null 2>&1 || fail 'docker-buildx'
builder_inspect="$(docker buildx inspect --bootstrap "${BUILDX_BUILDER}" 2>&1)" || fail 'buildx-builder-inspect'
builder_platforms="$(awk -F': ' '$1 == "Platforms" {print $2; exit}' <<<"${builder_inspect}")"
[ -n "${builder_platforms}" ] || fail 'buildx-builder-platforms'
grep -Eq '(^|[[:space:],])linux/amd64([[:space:],(+]|$)' <<<"${builder_platforms}" ||
  fail 'buildx-builder-missing-linux-amd64'
readonly builder_platforms

OUTPUT_DIR="$1"
mkdir -p -- "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd -- "${OUTPUT_DIR}" && pwd -P)"
readonly OUTPUT_DIR
[ -z "$(find "${OUTPUT_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail 'output-directory-not-empty'

jq -e '
  .schema == "cdnca.l401.runner-inputs.v1" and
  (.platform == "linux/amd64") and
  (.source_date_epoch | type == "number") and
  (.debian_snapshot | test("^[0-9]{8}T[0-9]{6}Z$")) and
  (.go_image | test("@sha256:[0-9a-f]{64}$")) and
  (has("openresty_image") | not) and (has("openresty_version") | not) and
  (.apt_packages | length > 0 and all(test("^[a-z0-9][a-z0-9+.-]*$")))
' "${INPUT_LOCK}" >/dev/null || fail 'input-lock-schema'

go_image="$(jq -er '.go_image' "${INPUT_LOCK}")"
platform="$(jq -er '.platform' "${INPUT_LOCK}")"
[ -f "${RUNTIME_ENV}" ] || fail 'runtime-env'
openresty_image="$(sed -n 's/^OPENRESTY_IMAGE=//p' "${RUNTIME_ENV}")"
openresty_version="$(sed -n 's/^OPENRESTY_VERSION=//p' "${RUNTIME_ENV}")"
[[ ${openresty_image} =~ ^openresty/openresty@sha256:[0-9a-f]{64}$ ]] || fail 'runtime-env-openresty-image'
[[ ${openresty_version} =~ ^[0-9]+(\.[0-9]+){3}$ ]] || fail 'runtime-env-openresty-version'
debian_snapshot="$(jq -er '.debian_snapshot' "${INPUT_LOCK}")"
source_date_epoch="$(jq -er '.source_date_epoch' "${INPUT_LOCK}")"
apt_packages="$(jq -er '.apt_packages | join(" ")' "${INPUT_LOCK}")"
readonly go_image platform openresty_image openresty_version debian_snapshot source_date_epoch apt_packages

dockerfile_sha256="$(sha256sum "${DOCKERFILE}" | awk '{print $1}')"
input_lock_sha256="$(sha256sum "${INPUT_LOCK}" | awk '{print $1}')"
build_script_sha256="$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')"
jq -nS \
  --arg buildx_builder "${BUILDX_BUILDER}" \
  --arg buildx_builder_platforms "${builder_platforms}" \
  --arg schema 'cdnca.l401.runner-provenance-inputs.v1' \
  --arg dockerfile_sha256 "${dockerfile_sha256}" \
  --arg input_lock_sha256 "${input_lock_sha256}" \
  --arg build_script_sha256 "${build_script_sha256}" \
  --arg platform "${platform}" \
  --arg go_image "${go_image}" \
  --arg openresty_image "${openresty_image}" \
  --arg openresty_version "${openresty_version}" \
  --arg debian_snapshot "${debian_snapshot}" \
  --arg source_date_epoch "${source_date_epoch}" \
  --arg apt_packages "${apt_packages}" \
  '{schema:$schema,platform:$platform,buildx_builder:$buildx_builder,buildx_builder_platforms:$buildx_builder_platforms,
    dockerfile_sha256:$dockerfile_sha256,input_lock_sha256:$input_lock_sha256,
    build_script_sha256:$build_script_sha256,go_image:$go_image,openresty_image:$openresty_image,
    openresty_version:$openresty_version,debian_snapshot:$debian_snapshot,
    source_date_epoch:($source_date_epoch | tonumber),apt_packages:($apt_packages | split(" "))}' \
  >"${OUTPUT_DIR}/provenance-inputs.json"
provenance_input_sha256="$(sha256sum "${OUTPUT_DIR}/provenance-inputs.json" | awk '{print $1}')"
readonly provenance_input_sha256

staging_ref="cdnca-l401-runner:contract-v1-${provenance_input_sha256:0:16}"
readonly staging_ref
SOURCE_DATE_EPOCH="${source_date_epoch}" docker buildx build \
  --builder "${BUILDX_BUILDER}" \
  --file "${DOCKERFILE}" \
  --platform "${platform}" \
  --tag "${staging_ref}" \
  --build-arg "GO_IMAGE=${go_image}" \
  --build-arg "OPENRESTY_IMAGE=${openresty_image}" \
  --build-arg "OPENRESTY_VERSION=${openresty_version}" \
  --build-arg "DEBIAN_SNAPSHOT=${debian_snapshot}" \
  --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
  --build-arg "BUILDX_BUILDER=${BUILDX_BUILDER}" \
  --build-arg "BUILDX_BUILDER_PLATFORMS=${builder_platforms}" \
  --build-arg "APT_PACKAGES=${apt_packages}" \
  --build-arg "PROVENANCE_INPUT_SHA256=${provenance_input_sha256}" \
  --metadata-file "${OUTPUT_DIR}/build-metadata.json" \
  --output "type=docker,dest=${OUTPUT_DIR}/runner-image.tar,rewrite-timestamp=true" \
  "${SCRIPT_DIR}" || fail 'buildx-build'

(cd -- "${OUTPUT_DIR}" && sha256sum runner-image.tar >runner-image.tar.sha256)
docker load --input "${OUTPUT_DIR}/runner-image.tar" >/dev/null || fail 'docker-load'
image_id="$(docker image inspect --format '{{.Id}}' "${staging_ref}")" || fail 'loaded-image-inspect'
[[ ${image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'loaded-image-content-id'

labels="$(docker image inspect --format '{{json .Config.Labels}}' "${image_id}")" || \
  fail 'loaded-image-label-inspect'
jq -e \
  --arg go_image "${go_image}" \
  --arg openresty_image "${openresty_image}" \
  --arg openresty_version "${openresty_version}" \
  --arg snapshot "${debian_snapshot}" \
  --arg builder "${BUILDX_BUILDER}" \
  --arg builder_platforms "${builder_platforms}" \
  --arg provenance "${provenance_input_sha256}" \
  '.["io.cdnca.l401.runner.contract"] == "v1" and
   .["io.cdnca.l401.runner.go-image"] == $go_image and
   .["io.cdnca.l401.runner.openresty-image"] == $openresty_image and
   .["io.cdnca.l401.runner.openresty-version"] == $openresty_version and
   .["io.cdnca.l401.runner.debian-snapshot"] == $snapshot and
   .["io.cdnca.l401.runner.buildx-builder"] == $builder and
   .["io.cdnca.l401.runner.buildx-builder-platforms"] == $builder_platforms and
   .["io.cdnca.l401.runner.provenance-input-sha256"] == $provenance' \
  <<<"${labels}" >/dev/null || fail 'loaded-image-labels'

docker run --rm --pull=never --entrypoint /usr/bin/dpkg-query "${image_id}" \
  -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' | LC_ALL=C sort \
  >"${OUTPUT_DIR}/debian-packages.tsv" || fail 'package-inventory'
{
  printf 'L401_RUNNER_IMAGE=%s\n' "${image_id}"
  printf 'L401_RUNNER_PROVENANCE_INPUT_SHA256=%s\n' "${provenance_input_sha256}"
} >"${OUTPUT_DIR}/runner.env"
printf '%s  provenance-inputs.json\n' "${provenance_input_sha256}" \
  >"${OUTPUT_DIR}/provenance-inputs.json.sha256"

printf 'L401_RUNNER_IMAGE_BUILD PASS image=%s archive=%s provenance=%s\n' \
  "${image_id}" "${OUTPUT_DIR}/runner-image.tar" "${provenance_input_sha256}"
