#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'edge agent OCI publish: %s\n' "$1" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" | awk '{print $1}'; else shasum -a 256 -- "$1" | awk '{print $1}'; fi
}
file_size() { stat -f '%z' "$1" 2>/dev/null || stat -c '%s' "$1"; }
require_regular() { [[ -f $1 && ! -L $1 && -r $1 ]] || fail "unsafe input: $1"; }
require_digest_subject() { [[ $1 =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]] || fail "invalid digest subject: $1"; }
safe_absolute_path() { [[ $1 == /* && $1 != *$'\n'* && $1 != *$'\r'* && $1 != *$'\t'* && ! $1 =~ (^|/)\.\.?(/|$) ]]; }

amd64_dir=''
arm64_dir=''
repository=''
tag=''
source_repository=''
source_commit=''
source_date_epoch=''
build_id=''
output_dir=''
cosign_issuer=''
cosign_identity=''
while (($# > 0)); do
  (($# >= 2)) || fail "missing value for $1"
  case $1 in
    --amd64-dir) [[ -z ${amd64_dir} ]] || fail 'duplicate amd64 directory'; amd64_dir=$2 ;;
    --arm64-dir) [[ -z ${arm64_dir} ]] || fail 'duplicate arm64 directory'; arm64_dir=$2 ;;
    --repository) [[ -z ${repository} ]] || fail 'duplicate repository'; repository=$2 ;;
    --tag) [[ -z ${tag} ]] || fail 'duplicate tag'; tag=$2 ;;
    --source-repository) [[ -z ${source_repository} ]] || fail 'duplicate source repository'; source_repository=$2 ;;
    --source-commit) [[ -z ${source_commit} ]] || fail 'duplicate source commit'; source_commit=$2 ;;
    --source-date-epoch) [[ -z ${source_date_epoch} ]] || fail 'duplicate source epoch'; source_date_epoch=$2 ;;
    --build-id) [[ -z ${build_id} ]] || fail 'duplicate build ID'; build_id=$2 ;;
    --output-dir) [[ -z ${output_dir} ]] || fail 'duplicate output directory'; output_dir=$2 ;;
    --cosign-issuer) [[ -z ${cosign_issuer} ]] || fail 'duplicate cosign issuer'; cosign_issuer=$2 ;;
    --cosign-identity) [[ -z ${cosign_identity} ]] || fail 'duplicate cosign identity'; cosign_identity=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done
for value in amd64_dir arm64_dir repository tag source_repository source_commit source_date_epoch build_id output_dir cosign_issuer cosign_identity; do
  [[ -n ${!value} ]] || fail "missing ${value//_/-}"
done
for path in "${amd64_dir}" "${arm64_dir}" "${output_dir}"; do safe_absolute_path "${path}" || fail "path must be clean and absolute: ${path}"; done
[[ -d ${amd64_dir} && ! -L ${amd64_dir} ]] || fail 'unsafe amd64 directory'
[[ -d ${arm64_dir} && ! -L ${arm64_dir} ]] || fail 'unsafe arm64 directory'
[[ ! -e ${output_dir} && ! -L ${output_dir} ]] || fail 'output already exists'
[[ ${repository} =~ ^[a-z0-9][a-z0-9._/-]*$ ]] || fail 'invalid OCI repository'
[[ ${tag} =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || fail 'invalid OCI tag'
[[ ${source_repository} =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'invalid source repository'
[[ ${source_commit} =~ ^[0-9a-f]{40}$ ]] || fail 'source commit must be a full SHA'
[[ ${source_date_epoch} =~ ^[1-9][0-9]{8,11}$ ]] || fail 'invalid source epoch'
[[ ${build_id} =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || fail 'invalid build ID'
[[ ${cosign_issuer} == https://token.actions.githubusercontent.com ]] || fail 'unexpected cosign issuer'
[[ ${cosign_identity} == https://github.com/*/.github/workflows/edge-supply-chain.yml@refs/* ]] || fail 'unexpected cosign identity'
for command in awk base64 cat cosign date docker find install jq mkdir mktemp mv rm stat; do command -v "${command}" >/dev/null 2>&1 || fail "missing command: ${command}"; done
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || fail 'missing SHA-256 command'

version=''
for arch in amd64 arm64; do
  directory_var=${arch}_dir
  directory=${!directory_var}
  for name in edge-agent edge-agent.provenance.json edge-agent.spdx.json release-inputs.json; do require_regular "${directory}/${name}"; done
  [[ -x ${directory}/edge-agent ]] || fail "${arch} artifact is not executable"
  jq -e --arg arch "${arch}" --arg source "${source_commit}" --arg repository "${source_repository}" '
    .schema == "cdnca.edge.release-provenance/v1" and .arch == $arch and
    .source_commit == $source and .source_repository == $repository
  ' "${directory}/edge-agent.provenance.json" >/dev/null || fail "${arch} provenance identity mismatch"
  release_version=$(jq -er '.version' "${directory}/edge-agent.provenance.json")
  if [[ -z ${version} ]]; then version=${release_version}; else [[ ${release_version} == "${version}" ]] || fail 'release versions differ'; fi
  jq -e --arg arch "${arch}" --arg artifact "$(sha256_file "${directory}/edge-agent")" \
    --arg provenance "$(sha256_file "${directory}/edge-agent.provenance.json")" \
    --arg spdx "$(sha256_file "${directory}/edge-agent.spdx.json")" '
    .schema == "cdnca.edge.release-build-output/v1" and .architecture == $arch and
    .files["edge-agent"].sha256 == $artifact and
    .files["edge-agent.provenance.json"].sha256 == $provenance and
    .files["edge-agent.spdx.json"].sha256 == $spdx
  ' "${directory}/release-inputs.json" >/dev/null || fail "${arch} release metadata drift"
done

output_parent=${output_dir%/*}
[[ -n ${output_parent} ]] || output_parent=/
[[ -d ${output_parent} && ! -L ${output_parent} ]] || fail 'unsafe output parent'
work=$(mktemp -d "${output_parent}/.edge-agent-oci.XXXXXX")
cleanup() { rm -rf -- "${work}"; }
trap cleanup EXIT HUP INT TERM
context=${work}/context
publish=${work}/publish
mkdir -p "${context}/amd64" "${context}/arm64" "${publish}"
for arch in amd64 arm64; do
  directory_var=${arch}_dir
  directory=${!directory_var}
  install -m 0555 "${directory}/edge-agent" "${context}/${arch}/edge-agent"
  install -m 0444 "${directory}/edge-agent.provenance.json" "${context}/${arch}/edge-agent.provenance.json"
  install -m 0444 "${directory}/edge-agent.spdx.json" "${context}/${arch}/edge-agent.spdx.json"
done
cat >"${context}/Dockerfile" <<'DOCKERFILE'
FROM scratch
ARG TARGETARCH
ARG SOURCE_COMMIT
ARG SOURCE_DATE_EPOCH
ARG SOURCE_REPOSITORY
ARG VERSION
COPY --chmod=0555 ${TARGETARCH}/edge-agent /usr/bin/cdnca-edge-agent
COPY --chmod=0444 ${TARGETARCH}/edge-agent.provenance.json /usr/share/cdnca/edge-agent.provenance.json
COPY --chmod=0444 ${TARGETARCH}/edge-agent.spdx.json /usr/share/cdnca/edge-agent.spdx.json
LABEL org.opencontainers.image.created.epoch="${SOURCE_DATE_EPOCH}" \
      org.opencontainers.image.revision="${SOURCE_COMMIT}" \
      org.opencontainers.image.source="${SOURCE_REPOSITORY}" \
      org.opencontainers.image.version="${VERSION}"
ENTRYPOINT ["/usr/bin/cdnca-edge-agent"]
DOCKERFILE

image_tag=${repository}:${tag}
metadata=${work}/build-metadata.json
docker buildx build --platform linux/amd64,linux/arm64 --push --provenance=false --sbom=false \
  --metadata-file "${metadata}" --tag "${image_tag}" \
  --build-arg "SOURCE_COMMIT=${source_commit}" --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
  --build-arg "SOURCE_REPOSITORY=${source_repository}" --build-arg "VERSION=${version}" "${context}" >&2
digest=$(jq -er '."containerimage.digest"' "${metadata}")
[[ ${digest} =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'build metadata has no image digest'
subject=${repository}@${digest}
require_digest_subject "${subject}"
docker buildx imagetools inspect "${subject}" --raw >"${publish}/index.json"
[[ $(sha256_file "${publish}/index.json") == "${digest#sha256:}" ]] || fail 'OCI index digest readback mismatch'
jq -e '
  .schemaVersion == 2 and (.manifests | type == "array" and length == 2) and
  ([.manifests[] | .platform.os + "/" + .platform.architecture] | sort) == ["linux/amd64","linux/arm64"]
' "${publish}/index.json" >/dev/null || fail 'OCI index platform set is not exact'
amd64_digest=$(jq -er '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest' "${publish}/index.json")
arm64_digest=$(jq -er '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "arm64") | .digest' "${publish}/index.json")
for arch in amd64 arm64; do
  digest_var=${arch}_digest
  native_digest=${!digest_var}
  [[ ${native_digest} =~ ^sha256:[0-9a-f]{64}$ ]] || fail "invalid ${arch} manifest digest"
  docker buildx imagetools inspect "${repository}@${native_digest}" --raw >"${publish}/manifest-${arch}.json"
  [[ $(sha256_file "${publish}/manifest-${arch}.json") == "${native_digest#sha256:}" ]] || fail "${arch} manifest digest readback mismatch"
  jq -e '.schemaVersion == 2 and (.config.digest | test("^sha256:[0-9a-f]{64}$")) and (.layers | length >= 1)' \
    "${publish}/manifest-${arch}.json" >/dev/null || fail "${arch} image manifest is incomplete"
done

created=$(date -u -r "${source_date_epoch}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d "@${source_date_epoch}" '+%Y-%m-%dT%H:%M:%SZ')
jq -S -n --arg build_id "${build_id}" --arg builder "${cosign_identity}" --arg created "${created}" \
  --arg source_commit "${source_commit}" --arg source_repository "${source_repository}" --arg version "${version}" \
  --arg amd64 "$(sha256_file "${amd64_dir}/edge-agent")" --arg arm64 "$(sha256_file "${arm64_dir}/edge-agent")" '
  {buildType:"https://cdnca.example/slsa/edge-agent-oci@v1",builder:{id:$builder},
   invocation:{configSource:{digest:{sha1:$source_commit},entryPoint:"scripts/edge-agent-oci-publish.sh",uri:$source_repository},
     environment:{platforms:["linux/amd64","linux/arm64"]},parameters:{version:$version}},
   materials:[{digest:{sha1:$source_commit},uri:$source_repository},
     {digest:{sha256:$amd64},uri:"pkg:generic/cdnca-edge-agent?arch=amd64"},
     {digest:{sha256:$arm64},uri:"pkg:generic/cdnca-edge-agent?arch=arm64"}],
   metadata:{buildFinishedOn:$created,buildInvocationId:$build_id,buildStartedOn:$created,
     completeness:{environment:true,materials:true,parameters:true},reproducible:true}}
' >"${publish}/slsa-provenance.json"
jq -S -n --arg created "${created}" --arg digest "${digest#sha256:}" --arg version "${version}" \
  --arg amd64 "$(sha256_file "${amd64_dir}/edge-agent")" --arg arm64 "$(sha256_file "${arm64_dir}/edge-agent")" '
  {SPDXID:"SPDXRef-DOCUMENT",creationInfo:{created:$created,creators:["Tool: cdnca-edge-agent-oci-publish-v1"]},
   dataLicense:"CC0-1.0",documentNamespace:("https://cdnca.invalid/spdx/edge-agent-oci/"+$digest),
   files:[
     {SPDXID:"SPDXRef-File-amd64",checksums:[{algorithm:"SHA256",checksumValue:$amd64}],fileName:"linux/amd64/edge-agent"},
     {SPDXID:"SPDXRef-File-arm64",checksums:[{algorithm:"SHA256",checksumValue:$arm64}],fileName:"linux/arm64/edge-agent"}],
   name:("cdnca-edge-agent-oci-"+$version),
   packages:[
     {SPDXID:"SPDXRef-Package-amd64",downloadLocation:"NOASSERTION",filesAnalyzed:true,name:"cdnca-edge-agent-amd64",versionInfo:$version},
     {SPDXID:"SPDXRef-Package-arm64",downloadLocation:"NOASSERTION",filesAnalyzed:true,name:"cdnca-edge-agent-arm64",versionInfo:$version}],
   relationships:[
     {spdxElementId:"SPDXRef-DOCUMENT",relationshipType:"DESCRIBES",relatedSpdxElement:"SPDXRef-Package-amd64"},
     {spdxElementId:"SPDXRef-DOCUMENT",relationshipType:"DESCRIBES",relatedSpdxElement:"SPDXRef-Package-arm64"},
     {spdxElementId:"SPDXRef-Package-amd64",relationshipType:"CONTAINS",relatedSpdxElement:"SPDXRef-File-amd64"},
     {spdxElementId:"SPDXRef-Package-arm64",relationshipType:"CONTAINS",relatedSpdxElement:"SPDXRef-File-arm64"}],
   spdxVersion:"SPDX-2.3"}
' >"${publish}/spdx.json"

cosign sign --yes "${subject}" >"${publish}/signature.json"
cosign attest --yes --type slsaprovenance --predicate "${publish}/slsa-provenance.json" "${subject}" >"${publish}/slsa-upload.json"
cosign attest --yes --type spdxjson --predicate "${publish}/spdx.json" "${subject}" >"${publish}/spdx-upload.json"
cosign verify --certificate-oidc-issuer "${cosign_issuer}" --certificate-identity "${cosign_identity}" \
  "${subject}" >"${publish}/signature-verify.json"
cosign verify-attestation --type slsaprovenance --certificate-oidc-issuer "${cosign_issuer}" \
  --certificate-identity "${cosign_identity}" "${subject}" >"${publish}/slsa-verify.json"
cosign verify-attestation --type spdxjson --certificate-oidc-issuer "${cosign_issuer}" \
  --certificate-identity "${cosign_identity}" "${subject}" >"${publish}/spdx-verify.json"
for pair in "slsa-verify.json:slsa-provenance.json:https://slsa.dev/provenance/v0.2" \
  "spdx-verify.json:spdx.json:https://spdx.dev/Document"; do
  verified=${pair%%:*}; rest=${pair#*:}; predicate=${rest%%:*}; predicate_type=${rest#*:}
  expected=$(jq -S -c . "${publish}/${predicate}" | sha256_file /dev/stdin)
  jq -e -s --arg digest "${digest#sha256:}" --arg predicate_type "${predicate_type}" --arg repository "${repository}" '
    length >= 1 and all(.[].payload | @base64d | fromjson;
      .predicateType == $predicate_type and (.subject | length) == 1 and
      .subject[0].name == $repository and .subject[0].digest.sha256 == $digest)
  ' "${publish}/${verified}" >/dev/null || fail "${predicate_type} statement does not bind the OCI subject"
  while IFS= read -r payload; do
    actual=$(printf '%s' "${payload}" | base64 --decode | jq -S -c .predicate | sha256_file /dev/stdin)
    [[ ${actual} == "${expected}" ]] || fail "${predicate_type} verified predicate drift"
  done < <(jq -r '.payload' "${publish}/${verified}")
done

jq -S -n --arg subject "${subject}" --arg repository "${repository}" --arg digest "${digest}" \
  --arg amd64_subject "${repository}@${amd64_digest}" --arg arm64_subject "${repository}@${arm64_digest}" \
  --arg identity "${cosign_identity}" --arg issuer "${cosign_issuer}" --arg version "${version}" \
  --arg slsa_sha256 "$(sha256_file "${publish}/slsa-provenance.json")" \
  --arg spdx_sha256 "$(sha256_file "${publish}/spdx.json")" '
  {attestations:{slsa:{path:"slsa-provenance.json",sha256:$slsa_sha256},spdx:{path:"spdx.json",sha256:$spdx_sha256}},
   cosign:{identity:$identity,issuer:$issuer},digest:$digest,platforms:{
     amd64:{manifest:"manifest-amd64.json",subject:$amd64_subject},
     arm64:{manifest:"manifest-arm64.json",subject:$arm64_subject}},
   repository:$repository,schema:"cdnca.edge.oci-release-inputs/v1",subject:$subject,version:$version}
' >"${publish}/release-inputs.json"
cat >"${publish}/release-inputs.env" <<EOF
EDGE_AGENT_OCI_SUBJECT=${subject}
EDGE_AGENT_OCI_AMD64_SUBJECT=${repository}@${amd64_digest}
EDGE_AGENT_OCI_ARM64_SUBJECT=${repository}@${arm64_digest}
EDGE_AGENT_OCI_COSIGN_ISSUER=${cosign_issuer}
EDGE_AGENT_OCI_COSIGN_IDENTITY=${cosign_identity}
EDGE_AGENT_OCI_SLSA=slsa-provenance.json
EDGE_AGENT_OCI_SLSA_SHA256=$(sha256_file "${publish}/slsa-provenance.json")
EDGE_AGENT_OCI_SPDX=spdx.json
EDGE_AGENT_OCI_SPDX_SHA256=$(sha256_file "${publish}/spdx.json")
EOF
find "${publish}" -type f -exec chmod 0444 {} +
mv -- "${publish}" "${output_dir}"
trap - EXIT HUP INT TERM
cleanup
printf '%s\n' "${subject}"
