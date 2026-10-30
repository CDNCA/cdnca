#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${repo_root}/tests/edge-linux/Dockerfile"
image_lock="${repo_root}/tests/edge-linux/images.env"
runtime_lock="${repo_root}/edge/openresty/runtime.env"
workflow="${repo_root}/.github/workflows/edge-supply-chain.yml"
contract_failures=0
implementation_source=

contract_require() {
  group=$1 pattern=$2 file=$3
  if [[ ! -f ${file} ]] || ! grep -Eq -- "${pattern}" "${file}"; then
    printf 'RED[%s] missing %s in %s\n' "${group}" "${pattern}" "${file#"${repo_root}/"}" >&2
    contract_failures=$((contract_failures + 1))
  fi
}

contract_reject() {
  group=$1 pattern=$2 file=$3
  if [[ -f ${file} ]] && grep -Eq -- "${pattern}" "${file}"; then
    printf 'RED[%s] rejected %s in %s\n' "${group}" "${pattern}" "${file#"${repo_root}/"}" >&2
    contract_failures=$((contract_failures + 1))
  fi
}

implementation_require() {
  group=$1 pattern=$2
  if ! grep -Eq -- "${pattern}" <<<"${implementation_source}"; then
    printf 'RED[%s] implementation missing %s\n' "${group}" "${pattern}" >&2
    contract_failures=$((contract_failures + 1))
  fi
}

implementation_reject() {
  group=$1 pattern=$2
  if grep -Eq -- "${pattern}" <<<"${implementation_source}"; then
    printf 'RED[%s] implementation rejected %s\n' "${group}" "${pattern}" >&2
    contract_failures=$((contract_failures + 1))
  fi
}

verify_contract() {
  implementation_source=$(sed -n '/^# BEGIN IMPLEMENTATION$/,$p' "${BASH_SOURCE[0]}")
  contract_reject input-lock '^# syntax=' "${dockerfile}"
  contract_require input-lock '^DOCKERFILE_FRONTEND=buildkit-builtin$' "${image_lock}"
  contract_require input-lock '^DOCKERFILE_FRONTEND_SHA256=sha256:[0-9a-f]{64}$' "${image_lock}"
  contract_require input-lock '^BUILDKIT_PROVENANCE_BUILD_TYPE=https://mobyproject\.org/buildkit@v1$' "${image_lock}"
  contract_require input-lock '^[A-Z0-9_]+_IMAGE=[^[:space:]@]+@sha256:[0-9a-f]{64}$' "${image_lock}"
  contract_reject input-lock 'setup-qemu|tonistiigi/binfmt|QEMU_IMAGE' "${workflow}"
  contract_require input-lock 'runner: ubuntu-24\.04$' "${workflow}"
  contract_require input-lock 'runner: ubuntu-24\.04-arm$' "${workflow}"
  contract_require input-lock '^APT_SNAPSHOT=[0-9]{8}T[0-9]{6}Z$' "${image_lock}"
  contract_require input-lock '^APT_PACKAGES_SHA256=sha256:[0-9a-f]{64}$' "${image_lock}"
  contract_require input-lock '^REQUIRED_RUNTIME_PACKAGES_SHA256=sha256:[0-9a-f]{64}$' "${image_lock}"
  contract_require input-lock 'uses: [^@[:space:]]+@[0-9a-f]{40}' "${workflow}"
  contract_reject input-lock 'uses: [^@[:space:]]+@v[0-9]' "${workflow}"

  contract_require runtime '^FROM .* AS toolchain$' "${dockerfile}"
  contract_require runtime '^FROM .* AS runtime$' "${dockerfile}"
  contract_require runtime 'jq' "${dockerfile}"
  contract_require runtime 'cdnca-edge-agent-helper\.socket' "${dockerfile}"
  contract_require runtime 'packaging/scripts/install\.sh' "${dockerfile}"
  contract_require runtime 'OPENRESTY_SOURCE_DIGEST' "${dockerfile}"
  contract_require runtime 'runtime-packages\.tsv' "${dockerfile}"
  contract_require runtime 'runtime-files\.tsv' "${dockerfile}"
  contract_require runtime 'runtime-inventory\.sha256' "${dockerfile}"
  contract_require runtime 'io\.cdnca\.runtime\.inventory\.digest\.amd64' "${dockerfile}"
  contract_require runtime 'io\.cdnca\.runtime\.inventory\.digest\.arm64' "${dockerfile}"
  if sed -n '/ AS runtime$/,$p' "${dockerfile}" | grep -Eq 'apt-get install[^;]*patchelf'; then
    printf 'RED[runtime] final image installs patchelf\n' >&2
    contract_failures=$((contract_failures + 1))
  fi

  implementation_require publication 'docker buildx build'
  implementation_require publication --metadata-file
  implementation_require publication 'linux/amd64'
  implementation_require publication 'linux/arm64'
  implementation_require publication 'RepoDigests'
  implementation_require publication 'imagetools inspect.*--raw'
  implementation_require publication 'tag mutation'
  implementation_require publication 'runtime-inventory\.sha256'
  implementation_require publication 'runtime-packages\.tsv'
  implementation_require publication 'runtime-files\.tsv'

  implementation_require attestation 'cosign sign '
  implementation_require attestation 'buildx\.build\.provenance'
  implementation_require attestation 'BUILDX_METADATA_PROVENANCE=max'
  implementation_require attestation 'cosign attest.*slsaprovenance'
  implementation_require attestation 'cosign attest.*spdxjson'
  implementation_require attestation --certificate-oidc-issuer
  implementation_require attestation --certificate-identity
  implementation_require attestation 'predicateType'
  implementation_require attestation 'packages'
  implementation_require attestation 'files'
  implementation_require attestation 'relationships'
  implementation_require attestation 'verify_predicate_hash'
  implementation_require attestation 'BUILDER_NODES'
  implementation_require attestation 'SOURCE_CONTEXT'
  # shellcheck disable=SC2016
  implementation_reject attestation '--file "\$\{dockerfile\}"'
  # shellcheck disable=SC2016
  implementation_require attestation '--file tests/edge-linux/Dockerfile "\$\{SOURCE_CONTEXT\}"'
  implementation_require attestation '\.invocation\.configSource\.entryPoint == "tests/edge-linux/Dockerfile"'
  # shellcheck disable=SC2016
  implementation_require attestation '\.builder\.id == \$expected_builder_id'
  implementation_require attestation '\.materials \| length == 3'
  # shellcheck disable=SC2016
  implementation_require attestation 'digest\.sha1 == \$revision'
  implementation_reject attestation 'builder\.id.*length > 0'
  implementation_reject attestation --provenance=false
  contract_require attestation 'id: buildx' "${workflow}"
  contract_require attestation 'steps\.buildx\.outputs\.name' "${workflow}"
  contract_require attestation 'steps\.buildx\.outputs\.nodes' "${workflow}"
  contract_require attestation 'EXPECTED_BUILD_TYPE: https://mobyproject\.org/buildkit@v1' "${workflow}"
  contract_require attestation 'SOURCE_CONTEXT: https://github\.com/\$\{\{ github\.repository \}\}\.git#\$\{\{ github\.sha \}\}' "${workflow}"

  implementation_require stdout '^verify_upgrade_e2e_image_publication\(\)'
  implementation_require stdout "printf '%s\\\\n' .*subject"

  if ((contract_failures != 0)); then
    printf 'UPGRADE_SYSTEMD_SUPPLY_CHAIN_CONTRACT=RED failures=%d\n' "${contract_failures}" >&2
    return 1
  fi
  printf 'UPGRADE_SYSTEMD_SUPPLY_CHAIN_CONTRACT=PASS\n' >&2
}

if [[ ${1:-} == --contract-test ]]; then
  verify_contract
  exit
fi

# BEGIN IMPLEMENTATION

fail() { printf 'upgrade systemd image: %s\n' "$1" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }
require_digest_ref() { [[ $1 =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]] || fail "unlocked image reference: $1"; }

builder_id_from_nodes() {
  jq -er '
    if type == "array" and length == 1 and
      (.[0].name | type == "string" and length > 0) and
      (.[0].buildkit | test("^v[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$"))
    then "https://github.com/moby/buildkit@" + .[0].buildkit
    else error("unexpected setup-buildx nodes output") end
  ' <<<"$1"
}

verify_upgrade_e2e_image_input_lock() {
  # shellcheck disable=SC1090,SC1091
  source "${image_lock}"
  # shellcheck disable=SC1090,SC1091
  source "${runtime_lock}"

  require_digest_ref "${DEBIAN_12_IMAGE}"
  require_digest_ref "${UBUNTU_24_IMAGE}"
  require_digest_ref "${BUILDKIT_IMAGE}"
  require_digest_ref "${OPENRESTY_IMAGE}"
  [[ ${DOCKERFILE_FRONTEND} == buildkit-builtin ]] || fail 'unexpected Dockerfile frontend'
  [[ ${DOCKERFILE_FRONTEND_SHA256} == "${BUILDKIT_IMAGE##*@}" ]] || fail 'frontend and BuildKit digests differ'
  [[ ${BUILDKIT_PROVENANCE_BUILD_TYPE} == https://mobyproject.org/buildkit@v1 ]] || fail 'unexpected BuildKit provenance buildType'
  [[ ${EXPECTED_BUILD_TYPE} == "${BUILDKIT_PROVENANCE_BUILD_TYPE}" ]] || fail 'workflow buildType differs from the locked value'
  [[ ${OPENRESTY_SOURCE_DIGEST} == "${OPENRESTY_IMAGE##*@}" ]] || fail 'OpenResty digest mismatch'
  [[ ${APT_SNAPSHOT} =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail 'invalid APT snapshot'
  [[ sha256:$(printf '%s' "${APT_PACKAGES}" | sha256sum | awk '{print $1}') == "${APT_PACKAGES_SHA256}" ]] || fail 'APT package lock mismatch'
  [[ sha256:$(printf '%s' "${TOOLCHAIN_PACKAGES}" | sha256sum | awk '{print $1}') == "${TOOLCHAIN_PACKAGES_SHA256}" ]] || fail 'toolchain package lock mismatch'
  [[ sha256:$(printf '%s' "${REQUIRED_RUNTIME_PACKAGES}" | sha256sum | awk '{print $1}') == "${REQUIRED_RUNTIME_PACKAGES_SHA256}" ]] || fail 'required runtime package lock mismatch'
  [[ ${COSIGN_VERSION} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'cosign version is not exact'
  [[ ${SOURCE_REVISION} =~ ^[0-9a-f]{40}$ ]] || fail 'source revision must be a full commit SHA'
  [[ ${SOURCE_CONTEXT} == https://github.com/*.git#"${SOURCE_REVISION}" ]] || fail 'Git source context is not bound to SOURCE_REVISION'
  SOURCE_URI=${SOURCE_CONTEXT%#*}
  [[ ${SOURCE_URI} =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git$ ]] || fail 'unsafe Git source URI'
  [[ ${SOURCE_DATE_EPOCH} =~ ^[1-9][0-9]{8,11}$ ]] || fail 'invalid SOURCE_DATE_EPOCH'
  [[ ${IMAGE_REPOSITORY} =~ ^[a-z0-9][a-z0-9._/-]*$ ]] || fail 'unsafe image repository'
  [[ ${IMAGE_TAG} =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$ ]] || fail 'unsafe image tag'
  [[ ${BUILDER_NAME} =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$ ]] || fail 'unsafe builder name'
  EXPECTED_BUILDER_ID=$(builder_id_from_nodes "${BUILDER_NODES}")
  case ${DISTRO} in
    debian12) DISTRO_IMAGE=${DEBIAN_12_IMAGE} ;;
    ubuntu24) DISTRO_IMAGE=${UBUNTU_24_IMAGE} ;;
    *) fail "unsupported distro: ${DISTRO}" ;;
  esac
  export APT_PACKAGES APT_PACKAGES_SHA256 APT_SNAPSHOT BUILDKIT_IMAGE BUILDKIT_PROVENANCE_BUILD_TYPE DISTRO_IMAGE
  export EXPECTED_BUILDER_ID SOURCE_CONTEXT SOURCE_URI
  export OPENRESTY_IMAGE OPENRESTY_SOURCE_DIGEST OPENRESTY_VERSION
  export REQUIRED_RUNTIME_PACKAGES REQUIRED_RUNTIME_PACKAGES_SHA256 TOOLCHAIN_PACKAGES TOOLCHAIN_PACKAGES_SHA256
}

resolve_tag_digest() {
  docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}' 2>/dev/null
}

verify_statement() {
  file=$1 predicate_type=$2 subject_name=$3 subject_hex=$4
  jq -e -s --arg predicate_type "${predicate_type}" --arg subject_name "${subject_name}" --arg subject_hex "${subject_hex}" '
    length >= 1 and all(.[].payload | @base64d | fromjson;
      .predicateType == $predicate_type and (.subject | length) == 1 and
      .subject[0].name == $subject_name and .subject[0].digest.sha256 == $subject_hex)
  ' "${file}" >/dev/null
}

verify_predicate_hash() {
  verified=$1 predicate=$2
  expected=$(jq -S -c . "${predicate}" | sha256sum | awk '{print $1}')
  jq -e -s --arg expected "${expected}" '
    length >= 1 and all(.[].payload | @base64d | fromjson | .predicate;
      ((. | tojson | fromjson) | @json) as $canonical |
      $canonical | length > 0)
  ' "${verified}" >/dev/null
  while IFS= read -r payload; do
    actual=$(printf '%s' "${payload}" | base64 --decode | jq -S -c .predicate | sha256sum | awk '{print $1}')
    [[ ${actual} == "${expected}" ]] || fail 'verified attestation predicate differs from the published predicate'
  done < <(jq -r '.payload' "${verified}")
}

export_runtime_inventory() {
  platform=$1 destination=$2
  mkdir -p "${destination}"
  docker buildx build --builder "${BUILDER_NAME}" --platform "${platform}" --target inventory-export \
    --output "type=local,dest=${destination}" \
    --build-arg "DISTRO_IMAGE=${DISTRO_IMAGE}" --build-arg "OPENRESTY_IMAGE=${OPENRESTY_IMAGE}" \
    --build-arg "OPENRESTY_VERSION=${OPENRESTY_VERSION}" --build-arg "OPENRESTY_SOURCE_DIGEST=${OPENRESTY_SOURCE_DIGEST}" \
    --build-arg "APT_SNAPSHOT=${APT_SNAPSHOT}" --build-arg "APT_PACKAGES=${APT_PACKAGES}" \
    --build-arg "APT_PACKAGES_SHA256=${APT_PACKAGES_SHA256}" --build-arg "TOOLCHAIN_PACKAGES=${TOOLCHAIN_PACKAGES}" \
    --build-arg "TOOLCHAIN_PACKAGES_SHA256=${TOOLCHAIN_PACKAGES_SHA256}" --build-arg "REQUIRED_RUNTIME_PACKAGES=${REQUIRED_RUNTIME_PACKAGES}" \
    --build-arg "REQUIRED_RUNTIME_PACKAGES_SHA256=${REQUIRED_RUNTIME_PACKAGES_SHA256}" --build-arg "SOURCE_REVISION=${SOURCE_REVISION}" \
    --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" --build-arg "EXPECTED_BUILDER_ID=${EXPECTED_BUILDER_ID}" \
    --file tests/edge-linux/Dockerfile "${SOURCE_CONTEXT}" 1>&2
  for file in runtime-packages.tsv runtime-files.tsv runtime-inventory.sha256; do
    [[ -s ${destination}/${file} ]] || fail "${platform} did not export ${file}"
  done
  actual=$( { printf 'cdnca.runtime-inventory/v1\n'; cat "${destination}/runtime-packages.tsv" "${destination}/runtime-files.tsv"; } | sha256sum | awk '{print "sha256:" $1}')
  expected=$(<"${destination}/runtime-inventory.sha256")
  [[ ${actual} == "${expected}" && ${expected} =~ ^sha256:[0-9a-f]{64}$ ]] || fail "${platform} inventory digest mismatch"
  [[ $(wc -l <"${destination}/runtime-packages.tsv") -gt 10 ]] || fail "${platform} package inventory is incomplete"
  [[ $(wc -l <"${destination}/runtime-files.tsv") -gt 100 ]] || fail "${platform} file inventory is incomplete"
  grep -Eq $'^systemd\\t' "${destination}/runtime-packages.tsv" || fail "${platform} inventory omits systemd"
  grep -Eq $'\\t/usr/local/openresty/' "${destination}/runtime-files.tsv" || fail "${platform} inventory omits OpenResty"
  grep -Eq $'\\t/opt/cdnca-musl/' "${destination}/runtime-files.tsv" || fail "${platform} inventory omits musl"
  grep -Eq $'\\t/opt/cdnca-upgrade-e2e/packaging/' "${destination}/runtime-files.tsv" || fail "${platform} inventory omits packaging"
  grep -Eq $'\\t/etc/os-release\\t' "${destination}/runtime-files.tsv" || fail "${platform} inventory omits base files"
}

build_spdx_predicate() {
  output=$1 amd64_dir=$2 arm64_dir=$3 subject_hex=$4
  for arch in amd64 arm64; do
    dir_var=${arch}_dir
    dir=${!dir_var}
    jq -Rn --arg arch "${arch}" '[inputs | select(length > 0) | split("\t") | {name:.[0],version:.[1]}] |
      to_entries | map({SPDXID:("SPDXRef-Package-"+$arch+"-"+(.key|tostring)),name:.value.name,
        versionInfo:.value.version,downloadLocation:"NOASSERTION",filesAnalyzed:false,primaryPackagePurpose:"LIBRARY"})' \
      <"${dir}/runtime-packages.tsv" >"${dir}/packages.json"
    jq -Rn --arg arch "${arch}" '[inputs | select(length > 0) | split("\t") | {kind:.[0],sha256:.[1],path:.[2],target:.[3]}] |
      to_entries | map({SPDXID:("SPDXRef-File-"+$arch+"-"+(.key|tostring)),fileName:.value.path,
        checksums:[{algorithm:"SHA256",checksumValue:.value.sha256}],fileTypes:[(if .value.kind == "L" then "OTHER" else "BINARY" end)],
        comment:(if .value.kind == "L" then "symlink="+.value.target else "regular-file" end)})' \
      <"${dir}/runtime-files.tsv" >"${dir}/files.json"
  done
  created=$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')
  jq -S -n --arg created "${created}" --arg digest "${subject_hex}" --arg distro "${DISTRO}" \
    --arg amd64_inventory "$(<"${amd64_dir}/runtime-inventory.sha256")" \
    --arg arm64_inventory "$(<"${arm64_dir}/runtime-inventory.sha256")" \
    --arg openresty "${OPENRESTY_SOURCE_DIGEST}" \
    --slurpfile amd64_packages "${amd64_dir}/packages.json" --slurpfile arm64_packages "${arm64_dir}/packages.json" \
    --slurpfile amd64_files "${amd64_dir}/files.json" --slurpfile arm64_files "${arm64_dir}/files.json" '
    ($amd64_packages[0] + $arm64_packages[0]) as $packages |
    ($amd64_files[0] + $arm64_files[0]) as $files |
    {SPDXID:"SPDXRef-DOCUMENT",spdxVersion:"SPDX-2.3",dataLicense:"CC0-1.0",
     name:("cdnca-upgrade-e2e-systemd-"+$distro),documentNamespace:("https://cdnca.invalid/spdx/upgrade-e2e/"+$digest),
     creationInfo:{created:$created,creators:["Tool: cdnca-edge-supply-chain-v1"]},packages:$packages,files:$files,
     relationships:(([$packages[].SPDXID | {spdxElementId:"SPDXRef-DOCUMENT",relationshipType:"DESCRIBES",relatedSpdxElement:.}]) +
       ([$files[].SPDXID | {spdxElementId:"SPDXRef-DOCUMENT",relationshipType:"CONTAINS",relatedSpdxElement:.}])),
     annotations:[{annotationType:"OTHER",annotator:"Tool: cdnca-edge-supply-chain-v1",annotationDate:$created,
       comment:("subject=sha256:"+$digest+" amd64="+$amd64_inventory+" arm64="+$arm64_inventory+" openresty="+$openresty)}]}
  ' >"${output}"
  jq -e '.packages | length > 0' "${output}" >/dev/null
  jq -e '.files | length > 0' "${output}" >/dev/null
  jq -e '(.relationships | length) == ((.packages | length) + (.files | length))' "${output}" >/dev/null
}

verify_runtime() {
  platform=$1 subject=$2 expected_inventory=$3
  arch=${platform#linux/}
  container="cdnca-upgrade-e2e-${DISTRO}-${arch}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
  created_containers+=("${container}")
  docker pull --platform "${platform}" "${subject}" 1>&2
  docker image inspect "${subject}" --format '{{json .RepoDigests}}' |
    jq -e --arg subject "${subject}" 'index($subject) != null' >/dev/null || fail "missing ${platform} RepoDigests"
  [[ $(docker image inspect "${subject}" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}') == "${SOURCE_REVISION}" ]] || fail "${platform} source revision label mismatch"
  [[ $(docker image inspect "${subject}" --format '{{index .Config.Labels "org.opencontainers.image.created.epoch"}}') == "${SOURCE_DATE_EPOCH}" ]] || fail "${platform} source epoch label mismatch"
  [[ $(docker image inspect "${subject}" --format '{{index .Config.Labels "org.opencontainers.image.base.digest"}}') == "${OPENRESTY_SOURCE_DIGEST}" ]] || fail "${platform} OpenResty digest label mismatch"
  inventory_label="io.cdnca.runtime.inventory.digest.${arch}"
  [[ $(docker image inspect "${subject}" --format "{{index .Config.Labels \"${inventory_label}\"}}") == "${expected_inventory}" ]] || fail "${platform} inventory label mismatch"
  docker run --detach --name "${container}" --platform "${platform}" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "${subject}" 1>&2
  for _ in $(seq 1 100); do
    state=$(docker exec "${container}" systemctl is-system-running 2>/dev/null || true)
    [[ ${state} == running || ${state} == degraded ]] && break
    sleep 0.1
  done
  [[ ${state:-unknown} == running || ${state:-unknown} == degraded ]] || fail "${platform} systemd did not become ready"
  docker exec "${container}" systemctl start cdnca-edge-agent-helper.socket
  docker exec "${container}" systemctl is-active --quiet cdnca-edge-agent-helper.socket
  docker exec "${container}" bash -n /opt/cdnca-upgrade-e2e/packaging/scripts/install.sh
  [[ $(docker exec "${container}" cat /usr/share/cdnca/runtime-inventory.sha256) == "${expected_inventory}" ]] || fail "${platform} runtime inventory changed"
  docker exec "${container}" jq -e -n --arg digest "${OPENRESTY_SOURCE_DIGEST}" '$digest | test("^sha256:[0-9a-f]{64}$")' >/dev/null
  actual_version=$(docker exec "${container}" /usr/local/openresty/bin/openresty -V 2>&1 | sed -n 's/^nginx version: openresty\///p')
  [[ ${actual_version} == "${OPENRESTY_VERSION}" ]] || fail "${platform} OpenResty version mismatch"
  if docker exec "${container}" sh -c 'command -v patchelf' >/dev/null 2>&1; then fail "${platform} final runtime contains patchelf"; fi
  docker rm --force "${container}" >/dev/null
}

verify_pull() {
  platform=$1 subject=$2
  docker pull --platform "${platform}" "${subject}" 1>&2
  docker image inspect "${subject}" --format '{{json .RepoDigests}}' |
    jq -e --arg subject "${subject}" 'index($subject) != null' >/dev/null || fail "missing ${platform} RepoDigests"
}

validate_provenance() {
  provenance=$1 platform=$2 expected_inventory=$3 expected_builder_id=${4:-${EXPECTED_BUILDER_ID}}
  jq -e --arg apt_packages "${APT_PACKAGES_SHA256}" --arg apt_snapshot "${APT_SNAPSHOT}" \
    --arg base "${DISTRO_IMAGE##*@sha256:}" --arg distro_image "${DISTRO_IMAGE}" --arg expected_builder_id "${expected_builder_id}" \
    --arg build_type "${EXPECTED_BUILD_TYPE}" --arg buildkit "${BUILDKIT_IMAGE}" \
    --arg expected_inventory "${expected_inventory}" --arg openresty "${OPENRESTY_SOURCE_DIGEST}" --arg openresty_image "${OPENRESTY_IMAGE}" \
    --arg openresty_hex "${OPENRESTY_SOURCE_DIGEST#sha256:}" --arg platform "${platform}" \
    --arg required_packages "${REQUIRED_RUNTIME_PACKAGES_SHA256}" --arg toolchain_packages "${TOOLCHAIN_PACKAGES_SHA256}" \
    --arg revision "${SOURCE_REVISION}" --arg source_uri "${SOURCE_URI}" --arg epoch "${SOURCE_DATE_EPOCH}" '
    .buildType == $build_type and .builder.id == $expected_builder_id and
    .invocation.configSource.entryPoint == "tests/edge-linux/Dockerfile" and
    .invocation.parameters.frontend == "dockerfile.v0" and .invocation.environment.platform == $platform and
    (.invocation.parameters.args as $args |
      $args["build-arg:APT_PACKAGES_SHA256"] == $apt_packages and $args["build-arg:APT_SNAPSHOT"] == $apt_snapshot and
      $args["build-arg:EXPECTED_BUILDER_ID"] == $expected_builder_id and $args["build-arg:BUILDKIT_IMAGE"] == $buildkit and
      $args["build-arg:DISTRO_IMAGE"] == $distro_image and
      $args["build-arg:REQUIRED_RUNTIME_PACKAGES_SHA256"] == $required_packages and
      $args["build-arg:TOOLCHAIN_PACKAGES_SHA256"] == $toolchain_packages and
      (($args["build-arg:EXPECTED_RUNTIME_INVENTORY_SHA256_AMD64"] == $expected_inventory) or
       ($args["build-arg:EXPECTED_RUNTIME_INVENTORY_SHA256_ARM64"] == $expected_inventory)) and
      $args["build-arg:OPENRESTY_IMAGE"] == $openresty_image and $args["build-arg:OPENRESTY_SOURCE_DIGEST"] == $openresty and
      $args["build-arg:SOURCE_REVISION"] == $revision and
      $args["build-arg:SOURCE_DATE_EPOCH"] == $epoch) and
    (.materials | length == 3) and
    ([.materials[] | select((.digest | keys) == ["sha256"] and .digest.sha256 == $base)] | length == 1) and
    ([.materials[] | select((.digest | keys) == ["sha256"] and .digest.sha256 == $openresty_hex)] | length == 1) and
    ([.materials[] | select((.digest | keys) == ["sha1"] and .digest.sha1 == $revision and .uri == $source_uri)] | length == 1) and
    all(.materials[];
      (((.digest | keys) == ["sha256"]) and (.digest.sha256 == $base or .digest.sha256 == $openresty_hex)) or
      (((.digest | keys) == ["sha1"]) and .digest.sha1 == $revision and .uri == $source_uri))
  ' "${provenance}" >/dev/null || fail "${platform} actual BuildKit provenance is not bound to all locked materials"
}

verify_predicate_set() {
  verified=$1 first=$2 second=$3 directory=$4
  jq -S -c . "${first}" | sha256sum | awk '{print $1}' >"${directory}/expected-predicates"
  jq -S -c . "${second}" | sha256sum | awk '{print $1}' >>"${directory}/expected-predicates"
  : >"${directory}/actual-predicates"
  while IFS= read -r payload; do
    printf '%s' "${payload}" | base64 --decode | jq -S -c .predicate | sha256sum | awk '{print $1}' >>"${directory}/actual-predicates"
  done < <(jq -r '.payload' "${verified}")
  LC_ALL=C sort -u -o "${directory}/expected-predicates" "${directory}/expected-predicates"
  LC_ALL=C sort -u -o "${directory}/actual-predicates" "${directory}/actual-predicates"
  cmp -s "${directory}/expected-predicates" "${directory}/actual-predicates" || fail 'verified provenance predicates differ from native builder outputs'
}

build_arch_publication() {
  ARCH=$1
  case ${ARCH} in amd64|arm64) ;; *) fail "unsupported architecture: ${ARCH}" ;; esac
  platform="linux/${ARCH}"
  case "$(uname -m)" in x86_64) native_arch=amd64 ;; aarch64|arm64) native_arch=arm64 ;; *) fail 'unsupported native runner architecture' ;; esac
  [[ ${native_arch} == "${ARCH}" ]] || fail "native runner architecture ${native_arch} cannot build ${ARCH}"
  created_containers=()
  cleanup_arch() {
    local container
    for container in "${created_containers[@]:-}"; do [[ -n ${container} ]] && docker rm --force "${container}" >/dev/null 2>&1 || true; done
  }
  trap cleanup_arch EXIT HUP INT TERM
  arch_dir="${EVIDENCE_DIR}/${ARCH}"
  [[ ! -e ${arch_dir} ]] || fail "evidence path already exists: ${arch_dir}"
  mkdir -p "${arch_dir}"
  inventory_dir="${arch_dir}/inventory"
  export_runtime_inventory "${platform}" "${inventory_dir}"
  inventory=$(<"${inventory_dir}/runtime-inventory.sha256")
  expected_amd64=UNBOUND
  expected_arm64=UNBOUND
  if [[ ${ARCH} == amd64 ]]; then expected_amd64=${inventory}; else expected_arm64=${inventory}; fi
  tag="${IMAGE_REPOSITORY}:${IMAGE_TAG}-${ARCH}"
  metadata="${arch_dir}/metadata.json"
  BUILDX_METADATA_PROVENANCE=max docker buildx build --builder "${BUILDER_NAME}" --platform "${platform}" --target runtime --push \
    --provenance=mode=max --sbom=false --metadata-file "${metadata}" --tag "${tag}" \
    --build-arg "DISTRO_IMAGE=${DISTRO_IMAGE}" --build-arg "OPENRESTY_IMAGE=${OPENRESTY_IMAGE}" \
    --build-arg "OPENRESTY_VERSION=${OPENRESTY_VERSION}" --build-arg "OPENRESTY_SOURCE_DIGEST=${OPENRESTY_SOURCE_DIGEST}" \
    --build-arg "APT_SNAPSHOT=${APT_SNAPSHOT}" --build-arg "APT_PACKAGES=${APT_PACKAGES}" \
    --build-arg "APT_PACKAGES_SHA256=${APT_PACKAGES_SHA256}" --build-arg "TOOLCHAIN_PACKAGES=${TOOLCHAIN_PACKAGES}" \
    --build-arg "TOOLCHAIN_PACKAGES_SHA256=${TOOLCHAIN_PACKAGES_SHA256}" --build-arg "REQUIRED_RUNTIME_PACKAGES=${REQUIRED_RUNTIME_PACKAGES}" \
    --build-arg "REQUIRED_RUNTIME_PACKAGES_SHA256=${REQUIRED_RUNTIME_PACKAGES_SHA256}" --build-arg "SOURCE_REVISION=${SOURCE_REVISION}" \
    --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" --build-arg "EXPECTED_BUILDER_ID=${EXPECTED_BUILDER_ID}" \
    --build-arg "BUILDKIT_IMAGE=${BUILDKIT_IMAGE}" --build-arg "EXPECTED_RUNTIME_INVENTORY_SHA256_AMD64=${expected_amd64}" \
    --build-arg "EXPECTED_RUNTIME_INVENTORY_SHA256_ARM64=${expected_arm64}" --file tests/edge-linux/Dockerfile "${SOURCE_CONTEXT}" 1>&2
  pushed_digest=$(jq -er '."containerimage.digest"' "${metadata}")
  [[ ${pushed_digest} =~ ^sha256:[0-9a-f]{64}$ ]] || fail "${platform} metadata has no exact RepoDigest"
  pushed_subject="${IMAGE_REPOSITORY}@${pushed_digest}"
  [[ $(resolve_tag_digest "${tag}") == "${pushed_digest}" ]] || fail "${platform} tag mutation detected"
  docker buildx imagetools inspect "${pushed_subject}" --raw >"${arch_dir}/pushed-manifest.json"
  if jq -e '.manifests | type == "array"' "${arch_dir}/pushed-manifest.json" >/dev/null 2>&1; then
    digest=$(jq -er --arg arch "${ARCH}" '
      [.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch)] as $runnable |
      if ($runnable | length) == 1 then $runnable[0].digest else error("native runnable manifest is not unique") end
    ' "${arch_dir}/pushed-manifest.json")
  else
    digest=${pushed_digest}
  fi
  [[ ${digest} =~ ^sha256:[0-9a-f]{64}$ ]] || fail "${platform} has no exact native manifest digest"
  subject="${IMAGE_REPOSITORY}@${digest}"
  jq -e '."buildx.build.provenance" | type == "object"' "${metadata}" >/dev/null || fail "${platform} metadata omits actual provenance"
  jq -S '."buildx.build.provenance"' "${metadata}" >"${arch_dir}/provenance.json"
  validate_provenance "${arch_dir}/provenance.json" "${platform}" "${inventory}"
  printf '%s' "${BUILDER_NODES}" >"${arch_dir}/builder-nodes.json"
  verify_runtime "${platform}" "${subject}" "${inventory}"
  docker buildx imagetools inspect "${subject}" --raw >"${arch_dir}/manifest.json"
  [[ $(sha256sum "${arch_dir}/manifest.json" | awk '{print $1}') == "${digest#sha256:}" ]] || fail "${platform} manifest digest readback mismatch"
  jq -e '.schemaVersion == 2 and (.config.digest | test("^sha256:[0-9a-f]{64}$")) and (.layers | length >= 1)' \
    "${arch_dir}/manifest.json" >/dev/null || fail "${platform} native image manifest is incomplete"
  printf '%s\n' "${pushed_subject}" >"${arch_dir}/pushed-subject.txt"
  printf '%s\n' "${subject}" >"${arch_dir}/subject.txt"
  printf '%s\n' "${subject}"
  cleanup_arch
  trap - EXIT HUP INT TERM
}

persist_systemd_release_inputs() {
  local final_dir=${EVIDENCE_DIR}/final staging=${EVIDENCE_DIR}/.final-inputs.$$
  [[ ! -e ${final_dir} && ! -L ${final_dir} ]] || fail 'systemd final evidence already exists'
  mkdir "${staging}"
  install -m 0444 "${workdir}/manifest.json" "${staging}/manifest.json"
  install -m 0444 "${workdir}/spdx.json" "${staging}/spdx.json"
  install -m 0444 "${workdir}/signature-verify.json" "${staging}/signature-verify.json"
  install -m 0444 "${workdir}/provenance-verify.json" "${staging}/provenance-verify.json"
  install -m 0444 "${workdir}/spdx-verify.json" "${staging}/spdx-verify.json"
  for arch in amd64 arm64; do
    for file in "${EVIDENCE_DIR}/${arch}/manifest.json" "${EVIDENCE_DIR}/${arch}/provenance.json" \
      "${EVIDENCE_DIR}/${arch}/inventory/runtime-inventory.sha256"; do
      [[ -s ${file} ]] || fail "missing final systemd evidence: ${file}"
    done
  done
  local amd64_manifest_sha256 arm64_manifest_sha256 amd64_inventory_sha256 arm64_inventory_sha256
  local amd64_provenance_sha256 arm64_provenance_sha256 spdx_sha256
  amd64_manifest_sha256=$(sha256sum "${EVIDENCE_DIR}/amd64/manifest.json" | awk '{print $1}')
  arm64_manifest_sha256=$(sha256sum "${EVIDENCE_DIR}/arm64/manifest.json" | awk '{print $1}')
  amd64_inventory_sha256=$(sha256sum "${EVIDENCE_DIR}/amd64/inventory/runtime-inventory.sha256" | awk '{print $1}')
  arm64_inventory_sha256=$(sha256sum "${EVIDENCE_DIR}/arm64/inventory/runtime-inventory.sha256" | awk '{print $1}')
  amd64_provenance_sha256=$(sha256sum "${EVIDENCE_DIR}/amd64/provenance.json" | awk '{print $1}')
  arm64_provenance_sha256=$(sha256sum "${EVIDENCE_DIR}/arm64/provenance.json" | awk '{print $1}')
  spdx_sha256=$(sha256sum "${workdir}/spdx.json" | awk '{print $1}')
  jq -S -n --arg subject "${subject}" --arg repository "${IMAGE_REPOSITORY}" --arg digest "${digest}" \
    --arg amd64_subject "${amd64_subject}" --arg arm64_subject "${arm64_subject}" \
    --arg identity "${COSIGN_EXPECTED_IDENTITY}" --arg issuer "${COSIGN_EXPECTED_ISSUER}" \
    --arg amd64_manifest_sha256 "${amd64_manifest_sha256}" --arg arm64_manifest_sha256 "${arm64_manifest_sha256}" \
    --arg amd64_inventory_sha256 "${amd64_inventory_sha256}" --arg arm64_inventory_sha256 "${arm64_inventory_sha256}" \
    --arg amd64_provenance_sha256 "${amd64_provenance_sha256}" --arg arm64_provenance_sha256 "${arm64_provenance_sha256}" \
    --arg spdx_sha256 "${spdx_sha256}" '
    {cosign:{identity:$identity,issuer:$issuer},digest:$digest,
     evidence:{amd64_inventory:{path:"../amd64/inventory/runtime-inventory.sha256",sha256:$amd64_inventory_sha256},
       amd64_manifest:{path:"../amd64/manifest.json",sha256:$amd64_manifest_sha256},
       amd64_provenance:{path:"../amd64/provenance.json",sha256:$amd64_provenance_sha256},
       arm64_inventory:{path:"../arm64/inventory/runtime-inventory.sha256",sha256:$arm64_inventory_sha256},
       arm64_manifest:{path:"../arm64/manifest.json",sha256:$arm64_manifest_sha256},
       arm64_provenance:{path:"../arm64/provenance.json",sha256:$arm64_provenance_sha256}},
     platforms:{amd64:{manifest:"../amd64/manifest.json",subject:$amd64_subject},
       arm64:{manifest:"../arm64/manifest.json",subject:$arm64_subject}},
     repository:$repository,schema:"cdnca.edge.systemd-release-inputs/v1",spdx:{path:"spdx.json",sha256:$spdx_sha256},subject:$subject}
  ' >"${staging}/release-inputs.json"
  cat >"${staging}/release-inputs.env" <<EOF
SYSTEMD_INPUT_DIR=\$(CDPATH='' cd -- \"\$(dirname -- \"\${BASH_SOURCE[0]}\")\" && pwd -P)
export UPGRADE_E2E_SYSTEMD_IMAGE=${subject}
export UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT=${amd64_subject}
export UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT=${arm64_subject}
export UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST=\"\${SYSTEMD_INPUT_DIR}/../amd64/manifest.json\"
export UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST_SHA256=${amd64_manifest_sha256}
export UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST=\"\${SYSTEMD_INPUT_DIR}/../arm64/manifest.json\"
export UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST_SHA256=${arm64_manifest_sha256}
export UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY=\"\${SYSTEMD_INPUT_DIR}/../amd64/inventory/runtime-inventory.sha256\"
export UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY_SHA256=${amd64_inventory_sha256}
export UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY=\"\${SYSTEMD_INPUT_DIR}/../arm64/inventory/runtime-inventory.sha256\"
export UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY_SHA256=${arm64_inventory_sha256}
export UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE=\"\${SYSTEMD_INPUT_DIR}/../amd64/provenance.json\"
export UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE_SHA256=${amd64_provenance_sha256}
export UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE=\"\${SYSTEMD_INPUT_DIR}/../arm64/provenance.json\"
export UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE_SHA256=${arm64_provenance_sha256}
export UPGRADE_E2E_SYSTEMD_SPDX=\"\${SYSTEMD_INPUT_DIR}/spdx.json\"
export UPGRADE_E2E_SYSTEMD_SPDX_SHA256=${spdx_sha256}
export UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER=${COSIGN_EXPECTED_ISSUER}
export UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY=${COSIGN_EXPECTED_IDENTITY}
EOF
  chmod 0444 "${staging}/release-inputs.json" "${staging}/release-inputs.env"
  mv -- "${staging}" "${final_dir}"
}

verify_upgrade_e2e_image_publication() {
  workdir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-upgrade-systemd.XXXXXX")
  created_containers=()
  cleanup() {
    local container
    for container in "${created_containers[@]:-}"; do [[ -n ${container} ]] && docker rm --force "${container}" >/dev/null 2>&1 || true; done
    case ${workdir} in
      "${TMPDIR:-/tmp}"/cdnca-upgrade-systemd.*) rm -rf -- "${workdir}" ;;
      *) printf 'refusing to remove unexpected workdir: %s\n' "${workdir}" >&2 ;;
    esac
  }
  trap cleanup EXIT HUP INT TERM

  tag="${IMAGE_REPOSITORY}:${IMAGE_TAG}"
  amd64_dir="${EVIDENCE_DIR}/amd64"
  arm64_dir="${EVIDENCE_DIR}/arm64"
  amd64_inventory_dir="${amd64_dir}/inventory"
  arm64_inventory_dir="${arm64_dir}/inventory"
  for file in "${amd64_dir}/subject.txt" "${amd64_dir}/provenance.json" "${amd64_dir}/builder-nodes.json" \
    "${arm64_dir}/subject.txt" "${arm64_dir}/provenance.json" "${arm64_dir}/builder-nodes.json"; do
    [[ -s ${file} ]] || fail "missing native build evidence: ${file}"
  done
  amd64_inventory=$(<"${amd64_inventory_dir}/runtime-inventory.sha256")
  arm64_inventory=$(<"${arm64_inventory_dir}/runtime-inventory.sha256")
  amd64_subject=$(<"${amd64_dir}/subject.txt")
  arm64_subject=$(<"${arm64_dir}/subject.txt")
  [[ ${amd64_subject} == "${IMAGE_REPOSITORY}"@sha256:* && ${amd64_subject#*@} =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'invalid amd64 subject'
  [[ ${arm64_subject} == "${IMAGE_REPOSITORY}"@sha256:* && ${arm64_subject#*@} =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'invalid arm64 subject'
  validate_provenance "${amd64_dir}/provenance.json" linux/amd64 "${amd64_inventory}" "$(builder_id_from_nodes "$(<"${amd64_dir}/builder-nodes.json")")"
  validate_provenance "${arm64_dir}/provenance.json" linux/arm64 "${arm64_inventory}" "$(builder_id_from_nodes "$(<"${arm64_dir}/builder-nodes.json")")"
  docker buildx imagetools create --tag "${tag}" "${amd64_subject}" "${arm64_subject}" 1>&2
  digest=$(resolve_tag_digest "${tag}")
  [[ ${digest} =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'merged tag has no exact RepoDigest'
  subject="${IMAGE_REPOSITORY}@${digest}"
  [[ $(resolve_tag_digest "${tag}") == "${digest}" ]] || fail 'tag mutation detected immediately after push'
  docker buildx imagetools inspect "${subject}" --raw >"${workdir}/manifest.json"
  raw_hash=$(sha256sum "${workdir}/manifest.json" | awk '{print $1}')
  [[ ${digest} == "sha256:${raw_hash}" ]] || fail 'raw manifest hash differs from RepoDigest'
  jq -e '(.manifests | length) == 2 and
    ([.manifests[] | select(.platform.os == "linux") | .platform.os + "/" + .platform.architecture] | sort) == ["linux/amd64","linux/arm64"]' \
    "${workdir}/manifest.json" >/dev/null || fail 'published runnable platform set is not exact'
  verify_pull linux/amd64 "${subject}"
  verify_pull linux/arm64 "${subject}"

  subject_hex=${digest#sha256:}
  provenance_amd64="${amd64_dir}/provenance.json"
  provenance_arm64="${arm64_dir}/provenance.json"
  build_spdx_predicate "${workdir}/spdx.json" "${amd64_inventory_dir}" "${arm64_inventory_dir}" "${subject_hex}"

  cosign sign --yes "${subject}" >"${workdir}/signature.json"
  cosign attest --yes --type slsaprovenance --predicate "${provenance_amd64}" "${subject}" >"${workdir}/provenance-amd64-upload.json"
  cosign attest --yes --type slsaprovenance --predicate "${provenance_arm64}" "${subject}" >"${workdir}/provenance-arm64-upload.json"
  cosign attest --yes --type spdxjson --predicate "${workdir}/spdx.json" "${subject}" >"${workdir}/spdx-upload.json"
  cosign verify --certificate-oidc-issuer "${COSIGN_EXPECTED_ISSUER}" --certificate-identity "${COSIGN_EXPECTED_IDENTITY}" "${subject}" >"${workdir}/signature-verify.json"
  cosign verify-attestation --type slsaprovenance --certificate-oidc-issuer "${COSIGN_EXPECTED_ISSUER}" --certificate-identity "${COSIGN_EXPECTED_IDENTITY}" "${subject}" >"${workdir}/provenance-verify.json"
  cosign verify-attestation --type spdxjson --certificate-oidc-issuer "${COSIGN_EXPECTED_ISSUER}" --certificate-identity "${COSIGN_EXPECTED_IDENTITY}" "${subject}" >"${workdir}/spdx-verify.json"
  verify_statement "${workdir}/provenance-verify.json" 'https://slsa.dev/provenance/v0.2' "${IMAGE_REPOSITORY}" "${subject_hex}"
  verify_statement "${workdir}/spdx-verify.json" 'https://spdx.dev/Document' "${IMAGE_REPOSITORY}" "${subject_hex}"
  verify_predicate_set "${workdir}/provenance-verify.json" "${provenance_amd64}" "${provenance_arm64}" "${workdir}"
  verify_predicate_hash "${workdir}/spdx-verify.json" "${workdir}/spdx.json"
  jq -e -s --arg amd64 "${amd64_inventory}" --arg arm64 "${arm64_inventory}" --arg digest "${subject_hex}" '
    all(.[].payload | @base64d | fromjson | .predicate;
      (.packages | length) > 0 and (.files | length) > 0 and (.relationships | length) == ((.packages | length) + (.files | length)) and
      (.documentNamespace | endswith($digest)) and (.annotations[0].comment | contains("amd64="+$amd64) and contains("arm64="+$arm64)))
  ' "${workdir}/spdx-verify.json" >/dev/null || fail 'verified SPDX content is incomplete'
  [[ $(resolve_tag_digest "${tag}") == "${digest}" ]] || fail 'tag mutation detected after verification'
  persist_systemd_release_inputs
  printf '%s\n' "${subject}"
  cleanup
  trap - EXIT HUP INT TERM
}

mode=${1:-}
case ${mode} in
  --build-arch)
    [[ $# == 3 ]] || fail 'usage: build-upgrade-e2e-systemd-image.sh --build-arch debian12|ubuntu24 amd64|arm64'
    DISTRO=$2
    ARCH=$3
    for command in docker grep jq sed sha256sum; do require_command "${command}"; done
    for name in IMAGE_REPOSITORY IMAGE_TAG BUILDER_NAME BUILDER_NODES EXPECTED_BUILD_TYPE SOURCE_CONTEXT SOURCE_REVISION SOURCE_DATE_EPOCH EVIDENCE_DIR; do
      [[ -n ${!name:-} ]] || fail "missing environment: ${name}"
    done
    [[ ${EVIDENCE_DIR} == /* ]] || fail 'EVIDENCE_DIR must be absolute'
    verify_upgrade_e2e_image_input_lock
    build_arch_publication "${ARCH}"
    ;;
  --merge)
    [[ $# == 2 ]] || fail 'usage: build-upgrade-e2e-systemd-image.sh --merge debian12|ubuntu24'
    DISTRO=$2
    for command in base64 cmp cosign date docker grep install jq sed sha256sum; do require_command "${command}"; done
    for name in IMAGE_REPOSITORY IMAGE_TAG BUILDER_NAME BUILDER_NODES EXPECTED_BUILD_TYPE SOURCE_CONTEXT SOURCE_REVISION SOURCE_DATE_EPOCH EVIDENCE_DIR COSIGN_EXPECTED_ISSUER COSIGN_EXPECTED_IDENTITY; do
      [[ -n ${!name:-} ]] || fail "missing environment: ${name}"
    done
    [[ ${EVIDENCE_DIR} == /* ]] || fail 'EVIDENCE_DIR must be absolute'
    [[ ${COSIGN_EXPECTED_ISSUER} == https://token.actions.githubusercontent.com ]] || fail 'unexpected OIDC issuer'
    [[ ${COSIGN_EXPECTED_IDENTITY} == https://github.com/*/.github/workflows/edge-supply-chain.yml@refs/* ]] || fail 'unexpected workflow identity'
    verify_upgrade_e2e_image_input_lock
    cosign version 2>&1 | grep -F "GitVersion:    v${COSIGN_VERSION}" >/dev/null || fail 'cosign version mismatch'
    verify_upgrade_e2e_image_publication
    ;;
  *) fail 'usage: build-upgrade-e2e-systemd-image.sh --build-arch DISTRO ARCH | --merge DISTRO' ;;
esac
