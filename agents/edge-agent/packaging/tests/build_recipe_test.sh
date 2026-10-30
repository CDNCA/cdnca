#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly CONTRACT="${REPO_ROOT}/agents/edge-agent/packaging/build/contract.json"
readonly RECIPE="${REPO_ROOT}/agents/edge-agent/packaging/build/recipe.sh"
readonly WRAPPER="${REPO_ROOT}/scripts/edge-agent-release-build.sh"
readonly PACKAGE_SMOKE="${REPO_ROOT}/scripts/edge-agent-package-smoke.sh"
readonly E2E="${REPO_ROOT}/tests/upgrade-process-e2e/run.sh"
readonly E2E_README="${REPO_ROOT}/tests/upgrade-process-e2e/README.md"
readonly CI="${REPO_ROOT}/.github/workflows/ci.yml"

fail() {
  printf 'edge release build recipe test: %s\n' "$1" >&2
  exit 1
}

sha256_file() {
  shasum -a 256 -- "$1" | awk '{print $1}'
}

write_manifest() {
  local root=$1 output=$2 relative_root source relative
  shift 2
  : >"${output}"
  for relative_root in "$@"; do
    [ -d "${root}/${relative_root}" ] && [ ! -L "${root}/${relative_root}" ] || return 1
    if find "${root}/${relative_root}" \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
      return 1
    fi
    while IFS= read -r -d '' source; do
      relative=${source#"${root}/"}
      printf '%s  %s\n' "$(sha256_file "${source}")" "${relative}" >>"${output}"
    done < <(find "${root}/${relative_root}" -type f -print0)
  done
  LC_ALL=C sort -u -o "${output}" "${output}"
}

expect_failure_without_publish() {
  local label=$1 output=$2
  shift 2
  if "$@" >/dev/null 2>&1; then
    fail "${label} unexpectedly passed"
  fi
  [ ! -e "${output}" ] || fail "${label} published output"
}

check_ci_contract() {
  local shell_job
  shell_job=$(sed -n '/^  shell:/,/^  plugin-example:/p' "${CI}") || return 1
  grep -Fx '      - uses: actions/setup-go@v5' <<<"${shell_job}" >/dev/null || return 1
  # The GitHub expression must remain literal.
  # shellcheck disable=SC2016
  grep -Fx '          go-version: ${{ env.GO_VERSION }}' <<<"${shell_job}" >/dev/null || return 1
  grep -Fx '      - uses: docker/setup-qemu-action@v3' <<<"${shell_job}" >/dev/null || return 1
  grep -Fx '          platforms: arm64' <<<"${shell_job}" >/dev/null || return 1
  grep -Fx '        run: scripts/edge-agent-package-smoke.sh all' <<<"${shell_job}" >/dev/null || return 1
}

real_wrapper_smoke() {
  local command smoke_root output binary version build_id source_repository source_commit source_epoch
  local version_json go_build_id metadata arch native_arch machine
  for command in docker go jq mktemp; do
    command -v "${command}" >/dev/null 2>&1 || fail "missing real smoke command ${command}"
  done
  version=${EDGE_RELEASE_SMOKE_VERSION:-0.0.0-ci}
  build_id=${EDGE_RELEASE_SMOKE_BUILD_ID:-ci-wrapper-smoke}
  source_repository=${EDGE_RELEASE_SMOKE_SOURCE_REPOSITORY:-}
  source_commit=${EDGE_RELEASE_SMOKE_SOURCE_COMMIT:-}
  source_epoch=${EDGE_RELEASE_SMOKE_SOURCE_DATE_EPOCH:-}
  [ -n "${source_repository}" ] && [ -n "${source_commit}" ] && [ -n "${source_epoch}" ] ||
    fail 'missing real smoke provenance'
  smoke_root=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-edge-real-build.XXXXXX")
  trap 'rm -rf -- "${smoke_root}"' EXIT
  case "$(uname -m)" in
    x86_64|amd64) native_arch=amd64 ;;
    aarch64|arm64) native_arch=arm64 ;;
    *) fail 'unsupported real smoke host architecture' ;;
  esac
  for arch in amd64 arm64; do
    output="${smoke_root}/release-${arch}"
    "${WRAPPER}" --output-dir "${output}" --arch "${arch}" --version "${version}" --build-id "${build_id}-${arch}" \
      --source-repository "${source_repository}" --source-commit "${source_commit}" --source-date-epoch "${source_epoch}"
    binary="${output}/edge-agent"
    [ -x "${binary}" ] || fail "real smoke ${arch} executable missing"
    machine=62
    [ "${arch}" = arm64 ] && machine=183
    perl -e '
      my ($path,$machine)=@ARGV;
      open my $in, "<:raw", $path or exit 1;
      read($in, my $header, 20) == 20 or exit 1;
      exit 1 unless substr($header,0,7) eq "\x7fELF\x02\x01\x01";
      exit 1 unless unpack("v", substr($header,18,2)) == $machine;
    ' "${binary}" "${machine}" || fail "real smoke ${arch} ELF identity"
    go_build_id=$(go tool buildid "${binary}") || fail "read real smoke ${arch} Go build ID"
    [ -z "${go_build_id}" ] || fail "real smoke ${arch} Go build ID is not empty"
    metadata=$(go version -m "${binary}") || fail "read real smoke ${arch} Go metadata"
    grep -F 'go1.27.3' <<<"${metadata}" >/dev/null || fail "real smoke ${arch} toolchain metadata"
    grep -F $'build\tGOOS=linux' <<<"${metadata}" >/dev/null || fail "real smoke ${arch} GOOS metadata"
    grep -F $'build\tGOARCH='"${arch}" <<<"${metadata}" >/dev/null || fail "real smoke ${arch} GOARCH metadata"
    jq -e --arg version "${version}" --arg build_id "${build_id}-${arch}" --arg arch "${arch}" '
      .version == $version and .build_id == $build_id and .arch == $arch and
      .builder.toolchain == "go1.27.3" and (.builder.image | contains("@sha256:"))
    ' "${output}/edge-agent.provenance.json" >/dev/null || fail "real smoke ${arch} provenance identity"
    if [ "$(uname -s)" = Linux ] && [ "${arch}" = "${native_arch}" ]; then
      version_json=$("${binary}" -version 2>&1) || fail "real smoke ${arch} version command"
      jq -e --arg version "${version}" --arg build_id "${build_id}-${arch}" '
        .event == "version" and .agent_version == $version and .agent_version != "development" and
        .build_id == $build_id and (.build_id | length > 0)
      ' <<<"${version_json}" >/dev/null || fail "real smoke ${arch} version identity"
    fi
  done
  rm -rf -- "${smoke_root}"
  trap - EXIT
  printf 'EDGE_AGENT_RELEASE_BUILD_REAL_WRAPPER PASS\n'
}

if [ "${1:-}" = --ci-contract-only ]; then
  [ "$#" -eq 1 ] || fail 'unexpected CI contract arguments'
  check_ci_contract || fail 'CI real wrapper smoke contract'
  printf 'EDGE_AGENT_RELEASE_BUILD_CI_CONTRACT PASS\n'
  exit 0
fi
if [ "${1:-}" = --real-wrapper-smoke ]; then
  [ "$#" -eq 1 ] || fail 'unexpected real wrapper smoke arguments'
  real_wrapper_smoke
  exit 0
fi
[ "$#" -eq 0 ] || fail 'unexpected arguments'

for command in awk chmod cmp find grep jq mkdir mktemp od perl sed shasum sort tr wc; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing command ${command}"
done
for path in "${CONTRACT}" "${RECIPE}" "${WRAPPER}"; do
  [ -f "${path}" ] && [ ! -L "${path}" ] || fail "missing ${path#"${REPO_ROOT}/"}"
done

jq -e '
  keys == ["architectures","builder","recipe","schema","source_roots"] and
  .schema == "cdnca.edge.release-build/v1" and
  .builder.toolchain == "go1.27.3" and
  (.builder.image | test("^docker\\.io/library/golang:1\\.27\\.3-bookworm@sha256:[0-9a-f]{64}$")) and
  .source_roots == ["agents/edge-agent","libs/edgeconfig","libs/entitlement","libs/rulepack","proto/gen/go"] and
  .architectures == {"amd64":{"elf_machine":62,"goarch":"amd64"},"arm64":{"elf_machine":183,"goarch":"arm64"}} and
  .recipe.command == "./cmd/edge-agent" and
  .recipe.go_flags == ["-buildvcs=false","-mod=readonly","-trimpath"] and
  .recipe.ldflags == ["-buildid=","-s","-w","-X main.agentVersion=${VERSION}","-X main.buildID=${BUILD_ID}"] and
  .recipe.output_files == ["edge-agent","edge-agent.provenance.json","edge-agent.spdx.json"]
' "${CONTRACT}" >/dev/null || fail 'versioned builder contract'

workdir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-edge-build-test.XXXXXX")
trap 'rm -rf -- "${workdir}"' EXIT
case "$(uname -m)" in
  x86_64|amd64) fixture_arch=arm64; fixture_machine=183 ;;
  aarch64|arm64) fixture_arch=amd64; fixture_machine=62 ;;
  *) fail 'unsupported test host architecture' ;;
esac
fixture="${workdir}/source"
mkdir -p "${fixture}/agents/edge-agent/cmd/edge-agent" \
  "${fixture}/agents/edge-agent/packaging/build" "${fixture}/libs/edgeconfig" \
  "${fixture}/libs/entitlement" "${fixture}/libs/rulepack" "${fixture}/proto/gen/go"
printf 'package main\nfunc main() {}\n' >"${fixture}/agents/edge-agent/cmd/edge-agent/main.go"
printf 'module example.invalid/edge-agent\ngo 1.27.0\n' >"${fixture}/agents/edge-agent/go.mod"
printf 'module example.invalid/edgeconfig\ngo 1.27.0\n' >"${fixture}/libs/edgeconfig/go.mod"
printf 'module example.invalid/entitlement\ngo 1.27.0\n' >"${fixture}/libs/entitlement/go.mod"
printf 'module example.invalid/rulepack\ngo 1.27.0\n' >"${fixture}/libs/rulepack/go.mod"
printf 'module example.invalid/proto\ngo 1.27.0\n' >"${fixture}/proto/gen/go/go.mod"
cp "${CONTRACT}" "${fixture}/agents/edge-agent/packaging/build/contract.json"
cp "${RECIPE}" "${fixture}/agents/edge-agent/packaging/build/recipe.sh"

source_manifest="${workdir}/source.sha256"
c_manifest="${workdir}/c.sha256"
write_manifest "${fixture}" "${source_manifest}" agents/edge-agent libs/edgeconfig libs/entitlement libs/rulepack proto/gen/go || fail 'source manifest fixture'
awk '$2 ~ /^agents\/edge-agent\//' "${source_manifest}" >"${c_manifest}"

fake_go="${workdir}/go"
cat >"${fake_go}" <<'FAKE_GO'
#!/usr/bin/env bash
set -Eeuo pipefail
if [ "${1:-}" = version ] && [ "${2:-}" != -m ]; then
  printf 'go version go1.27.3 linux/amd64\n'
  exit 0
fi
if [ "${1:-}" = version ] && [ "${2:-}" = -m ]; then
  binary=$3
  arch=$(perl -0777 -ne 'print $1 if /goarch=([^\n]+)/' "${binary}")
  printf '%s: go1.27.3\n' "${binary}"
  printf '\tbuild\tCGO_ENABLED=0\n\tbuild\tGOARCH=%s\n\tbuild\tGOOS=linux\n' "${arch}"
  exit 0
fi
[ "${1:-}" = build ] || exit 2
output=''
ldflags=''
shift
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    -ldflags) ldflags=$2; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "${output}" ] && [ -n "${ldflags}" ] || exit 2
required_go=$(awk '$1 == "go" {print $2}' go.mod)
if [ "${required_go}" = 1.28.0 ]; then
  [ "${GOTOOLCHAIN:-auto}" != local ] || exit 2
else
  [ "${GOTOOLCHAIN:-}" = local ] || exit 2
fi
version=$(printf '%s\n' "${ldflags}" | sed -n 's/.*main\.agentVersion=\([^ ]*\).*/\1/p')
build_id=$(printf '%s\n' "${ldflags}" | sed -n 's/.*main\.buildID=\([^ ]*\).*/\1/p')
machine=62
[ "${GOARCH}" = arm64 ] && machine=183
perl -e '
  my ($path,$machine,$version,$build,$arch,$epoch,$mode)=@ARGV;
  open my $out, ">:raw", $path or die $!;
  print {$out} "\x7fELF", pack("C*",2,1,1,0), "\0" x 8;
  print {$out} pack("v",2), pack("v",$machine), pack("V",1), "\0" x 40;
  if ($mode eq "missing") {
    print {$out} "goarch=$arch\nepoch=$epoch\n";
  } elsif ($mode eq "duplicate") {
    print {$out} "agent_version=$version\nbuild_id=$build\nbuild_id=$build\ngoarch=$arch\nepoch=$epoch\n";
  } elsif ($mode eq "default") {
    print {$out} "agent_version=development\nbuild_id=\ngoarch=$arch\nepoch=$epoch\n";
  } else {
    print {$out} "agent_version=$version\nbuild_id=$build\ngoarch=$arch\nepoch=$epoch\n";
  }
  close $out or die $!;
' "${output}" "${machine}" "${version}" "${build_id}" "${GOARCH}" "${SOURCE_DATE_EPOCH}" "${EDGE_RELEASE_FAKE_BINARY_MODE:-valid}"
chmod 0755 "${output}"
FAKE_GO
chmod 0755 "${fake_go}"

common=(
  --source-root "${fixture}"
  --source-manifest "${source_manifest}"
  --c-manifest "${c_manifest}"
  --contract "${fixture}/agents/edge-agent/packaging/build/contract.json"
  --version 1.2.3
  --build-id edge-1.2.3-build.7
  --source-repository https://example.invalid/cdnca.git
  --source-commit 0123456789abcdef0123456789abcdef01234567
  --source-date-epoch 1782864000
  --arch "${fixture_arch}"
)

string_number_contract="${workdir}/string-number-contract.json"
jq '.architectures.amd64.elf_machine = "62"' "${CONTRACT}" >"${string_number_contract}"
string_number=("${common[@]}")
string_number[7]="${string_number_contract}"
expect_failure_without_publish string-number-contract "${workdir}/string-number" \
  env EDGE_RELEASE_GO="${fake_go}" "${RECIPE}" "${string_number[@]}" --output-dir "${workdir}/string-number"

expect_failure_without_publish development-version "${workdir}/development" \
  env EDGE_RELEASE_GO="${fake_go}" "${RECIPE}" "${common[@]/1.2.3/development}" --output-dir "${workdir}/development"
for mode in missing duplicate default; do
  expect_failure_without_publish "${mode}-binary-metadata" "${workdir}/${mode}-binary-metadata" \
    env EDGE_RELEASE_GO="${fake_go}" EDGE_RELEASE_FAKE_BINARY_MODE="${mode}" \
    "${RECIPE}" "${common[@]}" --output-dir "${workdir}/${mode}-binary-metadata"
done
invalid=("${common[@]}")
invalid[9]='1.2'
expect_failure_without_publish invalid-semver "${workdir}/invalid" \
  env EDGE_RELEASE_GO="${fake_go}" "${RECIPE}" "${invalid[@]}" --output-dir "${workdir}/invalid"

sed 's/^go 1\.27\.0$/go 1.28.0/' "${fixture}/agents/edge-agent/go.mod" >"${workdir}/other-go.mod"
mv "${workdir}/other-go.mod" "${fixture}/agents/edge-agent/go.mod"
other_source_manifest="${workdir}/other-source.sha256"
other_c_manifest="${workdir}/other-c.sha256"
write_manifest "${fixture}" "${other_source_manifest}" agents/edge-agent libs/edgeconfig libs/entitlement libs/rulepack proto/gen/go || fail 'other toolchain source manifest'
awk '$2 ~ /^agents\/edge-agent\//' "${other_source_manifest}" >"${other_c_manifest}"
other_toolchain=("${common[@]}")
other_toolchain[3]="${other_source_manifest}"
other_toolchain[5]="${other_c_manifest}"
expect_failure_without_publish other-toolchain-source "${workdir}/other-toolchain" \
  env EDGE_RELEASE_GO="${fake_go}" "${RECIPE}" "${other_toolchain[@]}" --output-dir "${workdir}/other-toolchain"
sed 's/^go 1\.28\.0$/go 1.27.0/' "${fixture}/agents/edge-agent/go.mod" >"${workdir}/restored-go.mod"
mv "${workdir}/restored-go.mod" "${fixture}/agents/edge-agent/go.mod"

bad_source="${workdir}/bad-source.sha256"
cp "${source_manifest}" "${bad_source}"
sed '1s/^[0-9a-f]\{64\}/0000000000000000000000000000000000000000000000000000000000000000/' \
  "${bad_source}" >"${bad_source}.new"
mv "${bad_source}.new" "${bad_source}"
expect_failure_without_publish source-digest-drift "${workdir}/source-drift" \
  env EDGE_RELEASE_GO="${fake_go}" "${RECIPE}" "${common[@]}" --source-manifest "${bad_source}" --output-dir "${workdir}/source-drift"

bad_c="${workdir}/bad-c.sha256"
grep -v 'packaging/build/contract.json$' "${c_manifest}" >"${bad_c}"
expect_failure_without_publish c-manifest-drift "${workdir}/c-drift" \
  env EDGE_RELEASE_GO="${fake_go}" "${RECIPE}" "${common[@]}" --c-manifest "${bad_c}" --output-dir "${workdir}/c-drift"

ln -s main.go "${fixture}/agents/edge-agent/cmd/edge-agent/linked.go"
expect_failure_without_publish source-symlink "${workdir}/symlink" \
  env EDGE_RELEASE_GO="${fake_go}" "${RECIPE}" "${common[@]}" --output-dir "${workdir}/symlink"
rm "${fixture}/agents/edge-agent/cmd/edge-agent/linked.go"

for run in one two; do
  env EDGE_RELEASE_GO="${fake_go}" "${RECIPE}" "${common[@]}" --output-dir "${workdir}/${run}"
done
for name in edge-agent edge-agent.provenance.json edge-agent.spdx.json; do
  cmp -s "${workdir}/one/${name}" "${workdir}/two/${name}" || fail "non-deterministic ${name}"
done

[ "$(od -An -t u1 -j 18 -N 2 "${workdir}/one/edge-agent" | tr -d ' ')" = "${fixture_machine}0" ] || fail "${fixture_arch} ELF machine"
metadata=$(EDGE_RELEASE_GO="${fake_go}" "${fake_go}" version -m "${workdir}/one/edge-agent")
grep -F 'go1.27.3' <<<"${metadata}" >/dev/null || fail 'embedded toolchain metadata'
grep -F $'build\tCGO_ENABLED=0' <<<"${metadata}" >/dev/null || fail 'embedded CGO metadata'
grep -F $'build\tGOARCH='"${fixture_arch}" <<<"${metadata}" >/dev/null || fail 'embedded architecture metadata'
! grep -F -- '-ldflags' <<<"${metadata}" >/dev/null || fail 'fake metadata invented linker flags'
perl -0777 -e '
  my ($path, $version, $build_id) = @ARGV;
  open my $input, "<:raw", $path or exit 1;
  my $raw = do { local $/; <$input> };
  close $input or exit 1;
  exit 1 unless index($raw, $version) >= 0;
  my $count = 0;
  my $position = -1;
  ++$count while ($position = index($raw, $build_id, $position + 1)) >= 0;
  exit 1 unless $count == 1;
' "${workdir}/one/edge-agent" 1.2.3 edge-1.2.3-build.7 || fail 'embedded binary identity'
jq -e --arg artifact "$(sha256_file "${workdir}/one/edge-agent")" '
  .spdxVersion == "SPDX-2.3" and .dataLicense == "CC0-1.0" and .SPDXID == "SPDXRef-DOCUMENT" and
  .creationInfo.created == "2026-07-01T00:00:00Z" and
  .files == [{"SPDXID":"SPDXRef-File-edge-agent","checksums":[{"algorithm":"SHA256","checksumValue":$artifact}],"fileName":"edge-agent"}]
' "${workdir}/one/edge-agent.spdx.json" >/dev/null || fail 'SPDX 2.3 output'
jq -e --arg source "$(sha256_file "${source_manifest}")" --arg c "$(sha256_file "${c_manifest}")" --arg arch "${fixture_arch}" '
  .schema == "cdnca.edge.release-provenance/v1" and .version == "1.2.3" and
  .build_id == "edge-1.2.3-build.7" and .arch == $arch and
  .source_manifest_sha256 == $source and .c_manifest_sha256 == $c and
  .builder.toolchain == "go1.27.3" and (.builder.image | contains("@sha256:"))
' "${workdir}/one/edge-agent.provenance.json" >/dev/null || fail 'provenance output'

grep -F 'packaging/build/recipe.sh' "${WRAPPER}" >/dev/null || fail 'wrapper does not use recipe'
grep -F 'packaging/build/recipe.sh' "${E2E}" >/dev/null || fail 'E2E does not use recipe'
grep -F 'upgrade_e2e_bundle_executable_identity' "${E2E}" >/dev/null || fail 'bundle executable binding'
! grep -F 'docker ' "${RECIPE}" >/dev/null || fail 'inner recipe starts Docker'
! grep -Eq '(^|[^A-Za-z0-9_])jq([^A-Za-z0-9_]|$)' "${RECIPE}" || fail 'inner recipe requires jq'
grep -F 'build_recipe_test.sh' "${PACKAGE_SMOKE}" >/dev/null || fail 'package smoke recipe contract'
check_ci_contract || fail 'CI real wrapper smoke contract'
# Both grep failures must remain visible under pipefail.
# shellcheck disable=SC2126
external_keys=$(grep -Eo '[A-Z][A-Z0-9_]{2,}' "${E2E_README}" | sort -u |
  grep -E '^(UPGRADE_E2E|CONTROL_|LICENSE_|ENTITLEMENT_)' | grep -v '^UPGRADE_E2E_STATIC_ONLY$' | wc -l | tr -d ' ')
[ "${external_keys}" = 78 ] || fail "external key count ${external_keys}"

printf 'EDGE_AGENT_RELEASE_BUILD_RECIPE PASS\n'
