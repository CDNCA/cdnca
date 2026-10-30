#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly CONTRACT="${REPO_ROOT}/agents/edge-agent/packaging/build/contract.json"
readonly RECIPE="${REPO_ROOT}/agents/edge-agent/packaging/build/recipe.sh"

fail() { printf 'edge release build: %s\n' "$1" >&2; exit 1; }
sha256_file() { shasum -a 256 -- "$1" | awk '{print $1}'; }
edge_release_file_size() {
  local size
  # GNU stat may print filesystem data before rejecting the BSD size probe.
  if ! size=$(stat -f '%z' "$1" 2>/dev/null); then
    size=$(stat -c '%s' "$1") || fail 'cannot read release file size'
  fi
  [[ "$size" =~ ^(0|[1-9][0-9]*)$ ]] || fail 'invalid release file size'
  printf '%s\n' "$size"
}

output_dir=''
arch=''
metadata_file=''
forwarded=()
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || fail "missing value for $1"
  case "$1" in
    --output-dir) [ -z "${output_dir}" ] || fail 'duplicate output directory'; output_dir=$2 ;;
    --arch) [ -z "${arch}" ] || fail 'duplicate architecture'; arch=$2 ;;
    --metadata-file) [ -z "${metadata_file}" ] || fail 'duplicate metadata file'; metadata_file=$2 ;;
    --version|--build-id|--source-repository|--source-commit|--source-date-epoch) forwarded+=("$1" "$2") ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done
case "${output_dir}" in /*) ;; *) fail 'output directory must be absolute' ;; esac
case "${arch}" in amd64|arm64) ;; *) fail 'architecture must be amd64 or arm64' ;; esac
[ ! -e "${output_dir}" ] || fail 'output already exists'
if [ -n "${metadata_file}" ]; then
  [ "${metadata_file}" = "${output_dir}/release-inputs.json" ] || fail 'metadata file must be OUTPUT_DIR/release-inputs.json'
fi
for command in docker find jq mktemp mv shasum sort stat; do command -v "${command}" >/dev/null 2>&1 || fail "missing command: ${command}"; done
[ -f "${CONTRACT}" ] && [ ! -L "${CONTRACT}" ] || fail 'missing build contract'
[ -f "${RECIPE}" ] && [ ! -L "${RECIPE}" ] || fail 'missing build recipe'
builder=$(jq -er '.builder.image' "${CONTRACT}")
[[ "${builder}" =~ ^docker\.io/library/golang:1\.27\.3-bookworm@sha256:[0-9a-f]{64}$ ]] || fail 'builder is not digest pinned'
roots=()
while IFS= read -r root; do
  roots+=("${root}")
done < <(jq -er '.source_roots[]' "${CONTRACT}")

work=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-edge-release-wrapper.XXXXXX")
trap 'rm -rf -- "${work}"' EXIT
source_manifest="${work}/source.sha256"
c_manifest="${work}/c.sha256"
: >"${source_manifest}"
for root in "${roots[@]}"; do
  [ -d "${REPO_ROOT}/${root}" ] && [ ! -L "${REPO_ROOT}/${root}" ] || fail "unsafe source root: ${root}"
  if find "${REPO_ROOT}/${root}" \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
    fail "unsafe source member: ${root}"
  fi
  while IFS= read -r -d '' source; do
    relative=${source#"${REPO_ROOT}/"}
    printf '%s  %s\n' "$(sha256_file "${source}")" "${relative}" >>"${source_manifest}"
  done < <(find "${REPO_ROOT}/${root}" -type f -print0)
done
LC_ALL=C sort -u -o "${source_manifest}" "${source_manifest}"
awk '$2 ~ /^agents\/edge-agent\//' "${source_manifest}" >"${c_manifest}"

output_parent=${output_dir%/*}
[ -n "${output_parent}" ] || output_parent=/
[ -d "${output_parent}" ] && [ ! -L "${output_parent}" ] || fail 'unsafe output parent'
publish_work=$(mktemp -d "${output_parent}/.edge-release-wrapper.XXXXXX")
cleanup_publish() { rm -rf -- "${publish_work}"; }
trap 'cleanup_publish; rm -rf -- "${work}"' EXIT
publish_base=${publish_work##*/}
publish_dir=${publish_work}/release
docker run --rm --user "$(id -u):$(id -g)" \
  --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=1g \
  -e HOME=/tmp/home -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod-cache \
  -v "${REPO_ROOT}:/workspace:ro" -v "${work}:/input:ro" -v "${output_parent}:/output:rw" \
  "${builder}" /workspace/agents/edge-agent/packaging/build/recipe.sh \
  --source-root /workspace --source-manifest /input/source.sha256 --c-manifest /input/c.sha256 \
  --contract /workspace/agents/edge-agent/packaging/build/contract.json \
  --output-dir "/output/${publish_base}/release" --arch "${arch}" "${forwarded[@]}"

if [ -n "${metadata_file}" ]; then
  artifact_sha=$(sha256_file "${publish_dir}/edge-agent")
  artifact_size=$(edge_release_file_size "${publish_dir}/edge-agent")
  provenance_sha=$(sha256_file "${publish_dir}/edge-agent.provenance.json")
  provenance_size=$(edge_release_file_size "${publish_dir}/edge-agent.provenance.json")
  spdx_sha=$(sha256_file "${publish_dir}/edge-agent.spdx.json")
  spdx_size=$(edge_release_file_size "${publish_dir}/edge-agent.spdx.json")
  metadata_staging=${publish_dir}/.release-inputs.json
  metadata_destination=${publish_dir}/release-inputs.json
  jq -S -n \
    --arg arch "${arch}" --arg artifact_sha256 "${artifact_sha}" --argjson artifact_size "${artifact_size}" \
    --arg provenance_sha256 "${provenance_sha}" --argjson provenance_size "${provenance_size}" \
    --arg spdx_sha256 "${spdx_sha}" --argjson spdx_size "${spdx_size}" \
    --arg source_manifest_sha256 "$(sha256_file "${source_manifest}")" '
    {architecture:$arch,
     files:{
       "edge-agent":{sha256:$artifact_sha256,size:$artifact_size},
       "edge-agent.provenance.json":{sha256:$provenance_sha256,size:$provenance_size},
       "edge-agent.spdx.json":{sha256:$spdx_sha256,size:$spdx_size}},
     schema:"cdnca.edge.release-build-output/v1",
     source_manifest_sha256:$source_manifest_sha256}
  ' >"${metadata_staging}"
  chmod 0444 "${metadata_staging}"
  mv -- "${metadata_staging}" "${metadata_destination}"
fi

mv -- "${publish_dir}" "${output_dir}"
cleanup_publish
trap 'rm -rf -- "${work}"' EXIT
