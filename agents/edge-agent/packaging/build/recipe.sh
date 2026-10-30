#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() {
  printf 'edge release recipe: %s\n' "$1" >&2
  exit 1
}

sha256_file() {
  shasum -a 256 -- "$1" | awk '{print $1}'
}

require_regular() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || fail "unsafe input: $1"
}

valid_semver() {
  perl -e '
    my $v = shift;
    exit 1 unless $v =~ /\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\z/;
    if (defined $4) { for (split /\./, $4) { exit 1 if /\A[0-9]+\z/ && length($_) > 1 && /^0/; } }
  ' "$1"
}

verify_manifest_format() {
  require_regular "$1"
  LC_ALL=C sort -c -u "$1" >/dev/null 2>&1 || return 1
  perl -ne '
    chomp;
    exit 1 unless /\A[0-9a-f]{64}  ([A-Za-z0-9][A-Za-z0-9._\/-]*)\z/;
    my $path = $1;
    exit 1 if index($path, "//") >= 0 || $path =~ m{(?:\A|/)\.\.?(?:/|\z)};
    END {exit 1 unless $. > 0}
  ' "$1"
}

write_inventory() {
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
      printf '%s  %s\n' "$(sha256_file "${source}")" "${relative}" >>"${output}" || return 1
    done < <(find "${root}/${relative_root}" -type f -print0)
  done
  LC_ALL=C sort -u -o "${output}" "${output}"
}

read_contract() {
  perl -MJSON::PP -0777 -e '
    my ($path, $arch) = @ARGV;
    open my $input, "<:raw", $path or exit 1;
    my $raw = do { local $/; <$input> };
    close $input or exit 1;
    my $contract = eval { JSON::PP->new->utf8(1)->decode($raw) };
    exit 1 if $@ || ref($contract) ne "HASH";
    my $image = eval { $contract->{builder}{image} };
    exit 1 unless defined($image) && !ref($image) &&
      $image =~ /\Adocker\.io\/library\/golang:1\.27\.3-bookworm\@sha256:[0-9a-f]{64}\z/;
    my $expected = {
      architectures => {
        amd64 => {elf_machine => 62, goarch => "amd64"},
        arm64 => {elf_machine => 183, goarch => "arm64"},
      },
      builder => {image => $image, toolchain => "go1.27.3"},
      recipe => {
        command => "./cmd/edge-agent",
        go_flags => ["-buildvcs=false", "-mod=readonly", "-trimpath"],
        ldflags => ["-buildid=", "-s", "-w", q{-X main.agentVersion=${VERSION}}, q{-X main.buildID=${BUILD_ID}}],
        output_files => ["edge-agent", "edge-agent.provenance.json", "edge-agent.spdx.json"],
      },
      schema => "cdnca.edge.release-build/v1",
      # 与 agents/edge-agent/go.mod 的本仓 replace 依赖一一对应。
      source_roots => ["agents/edge-agent", "libs/edgeconfig", "libs/entitlement", "libs/rulepack", "proto/gen/go"],
    };
    my $json = JSON::PP->new->canonical(1);
    exit 1 unless $json->encode($contract) eq $json->encode($expected);
    my $architecture = $contract->{architectures}{$arch};
    exit 1 unless ref($architecture) eq "HASH";
    print "builder_image\t$image\n";
    print "toolchain\t$contract->{builder}{toolchain}\n";
    print "goarch\t$architecture->{goarch}\n";
    print "elf_machine\t$architecture->{elf_machine}\n";
    print "source_root\t$_\n" for @{$contract->{source_roots}};
  ' "$1" "$2"
}

write_sbom() {
  perl -MJSON::PP -e '
    my ($output, $created, $namespace, $version, $artifact) = @ARGV;
    my $document = {
      SPDXID => "SPDXRef-DOCUMENT",
      creationInfo => {created => $created, creators => ["Tool: cdnca-edge-release-build-v1"]},
      dataLicense => "CC0-1.0",
      documentNamespace => $namespace,
      files => [{
        SPDXID => "SPDXRef-File-edge-agent",
        checksums => [{algorithm => "SHA256", checksumValue => $artifact}],
        fileName => "edge-agent",
      }],
      name => "cdnca-edge-agent-$version",
      spdxVersion => "SPDX-2.3",
    };
    open my $stream, ">:raw", $output or exit 1;
    print {$stream} JSON::PP->new->canonical(1)->utf8(1)->encode($document), "\n" or exit 1;
    close $stream or exit 1;
  ' "$1" "$2" "$3" "$4" "$5"
}

write_provenance() {
  perl -MJSON::PP -e '
    my ($output, $arch, $artifact, $artifact_size, $build_id, $builder_image, $c_sha, $created,
      $epoch, $source_commit, $source_repository, $source_sha, $sbom, $toolchain, $version) = @ARGV;
    exit 1 unless $artifact_size =~ /\A[1-9][0-9]*\z/ && $epoch =~ /\A[1-9][0-9]*\z/;
    my $document = {
      arch => $arch,
      artifact => {path => "edge-agent", sha256 => $artifact, size => 0 + $artifact_size},
      build_id => $build_id,
      builder => {image => $builder_image, toolchain => $toolchain},
      c_manifest_sha256 => $c_sha,
      created => $created,
      recipe => {
        go_flags => ["-buildvcs=false", "-mod=readonly", "-trimpath"],
        ldflags => ["-buildid=", "-s", "-w", q{-X main.agentVersion=${VERSION}}, q{-X main.buildID=${BUILD_ID}}],
        source_date_epoch => 0 + $epoch,
      },
      sbom => {path => "edge-agent.spdx.json", sha256 => $sbom},
      schema => "cdnca.edge.release-provenance/v1",
      source_commit => $source_commit,
      source_manifest_sha256 => $source_sha,
      source_repository => $source_repository,
      version => $version,
    };
    open my $stream, ">:raw", $output or exit 1;
    print {$stream} JSON::PP->new->canonical(1)->utf8(1)->encode($document), "\n" or exit 1;
    close $stream or exit 1;
  ' "$@"
}

verify_injected_metadata() {
  perl -e '
    my ($path, $version, $build_id) = @ARGV;
    my $size = -s $path;
    exit 1 unless defined($size) && $size > 0 && $size <= 268435456;
    my @needles = ($version, $build_id);
    exit 1 unless length($needles[0]) && length($needles[1]);
    my @counts = (0, 0);
    my @last_start = (-1, -1);
    my $overlap = length($version) > length($build_id) ? length($version) - 1 : length($build_id) - 1;
    open my $input, "<:raw", $path or exit 1;
    my ($carry, $offset) = ("", 0);
    while (1) {
      my $read = read($input, my $chunk, 1048576);
      exit 1 unless defined $read;
      last if $read == 0;
      my $data = $carry . $chunk;
      my $base = $offset - length($carry);
      for my $index (0 .. $#needles) {
        my $position = -1;
        while (($position = index($data, $needles[$index], $position + 1)) >= 0) {
          my $absolute = $base + $position;
          next if $absolute <= $last_start[$index];
          ++$counts[$index];
          $last_start[$index] = $absolute;
        }
      }
      $offset += $read;
      $carry = $overlap && length($data) > $overlap ? substr($data, -$overlap) : $data;
    }
    close $input or exit 1;
    exit 1 unless $counts[0] >= 1 && $counts[1] == 1;
  ' "$1" "$2" "$3"
}

verify_version_output() {
  perl -MJSON::PP -0777 -e '
    my ($version, $build_id) = @ARGV;
    my $raw = <STDIN>;
    my $document = eval { JSON::PP->new->utf8(1)->decode($raw) };
    exit 1 if $@ || ref($document) ne "HASH";
    exit 1 unless join("\0", sort keys %{$document}) eq
      join("\0", sort qw(agent_version build_id event level msg time));
    for my $key (qw(agent_version build_id event level msg time)) {
      exit 1 if !defined($document->{$key}) || ref($document->{$key});
    }
    exit 1 unless $document->{agent_version} eq $version &&
      $document->{build_id} eq $build_id && $document->{event} eq "version" &&
      $document->{level} eq "INFO" && $document->{msg} eq "edge agent version" &&
      length($document->{time});
  ' "$1" "$2"
}

source_root=''
source_manifest=''
c_manifest=''
contract=''
output_dir=''
version=''
build_id=''
source_repository=''
source_commit=''
source_date_epoch=''
arch=''
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || fail "missing value for $1"
  case "$1" in
    --source-root) [ -z "${source_root}" ] || fail 'duplicate source root'; source_root=$2 ;;
    --source-manifest) [ -z "${source_manifest}" ] || fail 'duplicate source manifest'; source_manifest=$2 ;;
    --c-manifest) [ -z "${c_manifest}" ] || fail 'duplicate C manifest'; c_manifest=$2 ;;
    --contract) [ -z "${contract}" ] || fail 'duplicate contract'; contract=$2 ;;
    --output-dir) [ -z "${output_dir}" ] || fail 'duplicate output directory'; output_dir=$2 ;;
    --version) [ -z "${version}" ] || fail 'duplicate version'; version=$2 ;;
    --build-id) [ -z "${build_id}" ] || fail 'duplicate build ID'; build_id=$2 ;;
    --source-repository) [ -z "${source_repository}" ] || fail 'duplicate source repository'; source_repository=$2 ;;
    --source-commit) [ -z "${source_commit}" ] || fail 'duplicate source commit'; source_commit=$2 ;;
    --source-date-epoch) [ -z "${source_date_epoch}" ] || fail 'duplicate source epoch'; source_date_epoch=$2 ;;
    --arch) [ -z "${arch}" ] || fail 'duplicate architecture'; arch=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done

for value in source_root source_manifest c_manifest contract output_dir version build_id source_repository source_commit source_date_epoch arch; do
  [ -n "${!value}" ] || fail "missing ${value//_/-}"
done
case "${source_root}" in /*) ;; *) fail 'source root must be absolute' ;; esac
case "${output_dir}" in /*) ;; *) fail 'output directory must be absolute' ;; esac
[ -d "${source_root}" ] && [ ! -L "${source_root}" ] || fail 'unsafe source root'
[ ! -e "${output_dir}" ] && [ ! -L "${output_dir}" ] || fail 'output already exists'
valid_semver "${version}" || fail 'version must be canonical SemVer'
[[ "${build_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || fail 'invalid build ID'
[[ "${source_repository}" =~ ^https://[A-Za-z0-9._/-]+$ ]] || fail 'invalid source repository'
[[ "${source_commit}" =~ ^[0-9a-f]{40}$ ]] || fail 'invalid source commit'
[[ "${source_date_epoch}" =~ ^[1-9][0-9]{8,11}$ ]] || fail 'invalid source epoch'
case "${arch}" in amd64|arm64) ;; *) fail 'unsupported architecture' ;; esac

for command in awk cmp find grep mktemp mv perl shasum sort uname; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing command: ${command}"
done
require_regular "${contract}"
verify_manifest_format "${source_manifest}" || fail 'invalid source manifest'
verify_manifest_format "${c_manifest}" || fail 'invalid C manifest'
contract_values=$(read_contract "${contract}" "${arch}") || fail 'unsupported build contract'
builder_image=''
toolchain=''
goarch=''
elf_machine=''
source_roots=()
while IFS=$'\t' read -r key value; do
  case "${key}" in
    builder_image) builder_image=${value} ;;
    toolchain) toolchain=${value} ;;
    goarch) goarch=${value} ;;
    elf_machine) elf_machine=${value} ;;
    source_root) source_roots+=("${value}") ;;
    *) fail 'unsupported build contract output' ;;
  esac
done <<<"${contract_values}"
[ -n "${builder_image}" ] && [ -n "${toolchain}" ] && [ -n "${goarch}" ] && [ -n "${elf_machine}" ] &&
  [ "${#source_roots[@]}" -eq 5 ] || fail 'incomplete build contract'

output_parent=${output_dir%/*}
[ "${output_parent}" != "${output_dir}" ] || output_parent=/
[ -d "${output_parent}" ] && [ ! -L "${output_parent}" ] || fail 'unsafe output parent'
work=$(mktemp -d "${output_parent}/.edge-release-build.XXXXXX") || fail 'create build staging'
cleanup() { rm -rf -- "${work}"; }
trap cleanup EXIT
actual_manifest="${work}/source.sha256"
actual_c="${work}/c.sha256"
write_inventory "${source_root}" "${actual_manifest}" "${source_roots[@]}" || fail 'unsafe source tree'
cmp -s "${source_manifest}" "${actual_manifest}" || fail 'source manifest drift'
awk '$2 ~ /^agents\/edge-agent\//' "${actual_manifest}" >"${actual_c}"
cmp -s "${c_manifest}" "${actual_c}" || fail 'C manifest drift'

go_binary=${EDGE_RELEASE_GO:-go}
command -v "${go_binary}" >/dev/null 2>&1 || fail 'Go builder is unavailable'
"${go_binary}" version | grep -Eq "^go version ${toolchain} " || fail 'Go toolchain mismatch'
publish="${work}/publish"
mkdir "${publish}" || fail 'create publish staging'
binary="${publish}/edge-agent"
ldflags="-buildid= -s -w -X main.agentVersion=${version} -X main.buildID=${build_id}"
(
  cd -- "${source_root}/agents/edge-agent"
  env -u GOENV -u GOFLAGS \
    LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="${source_date_epoch}" GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${goarch}" \
    "${go_binary}" build -buildvcs=false -mod=readonly -trimpath -ldflags "${ldflags}" -o "${binary}" ./cmd/edge-agent
) || fail 'Go build failed'

perl -e '
  my ($path,$machine)=@ARGV;
  open my $in, "<:raw", $path or exit 1;
  read($in, my $header, 20) == 20 or exit 1;
  exit 1 unless substr($header,0,7) eq "\x7fELF\x02\x01\x01";
  exit 1 unless unpack("v", substr($header,18,2)) == $machine;
' "${binary}" "${elf_machine}" || fail 'binary is not the expected Linux ELF'
metadata=$("${go_binary}" version -m "${binary}") || fail 'read Go build metadata'
grep -F "go1.27.3" <<<"${metadata}" >/dev/null || fail 'binary toolchain mismatch'
grep -F $'build\tCGO_ENABLED=0' <<<"${metadata}" >/dev/null || fail 'binary CGO metadata mismatch'
grep -F $'build\tGOARCH='"${goarch}" <<<"${metadata}" >/dev/null || fail 'binary architecture metadata mismatch'
verify_injected_metadata "${binary}" "${version}" "${build_id}" || fail 'binary injected metadata mismatch'
case "$(uname -m)" in
  x86_64|amd64) native_goarch=amd64 ;;
  aarch64|arm64) native_goarch=arm64 ;;
  *) native_goarch='' ;;
esac
if [ "${goarch}" = "${native_goarch}" ]; then
  version_output=$("${binary}" --version 2>&1) || fail 'binary version command failed'
  verify_version_output "${version}" "${build_id}" <<<"${version_output}" || fail 'binary version output mismatch'
fi

artifact_sha=$(sha256_file "${binary}")
artifact_size=$(wc -c <"${binary}" | tr -d ' ')
source_sha=$(sha256_file "${source_manifest}")
c_sha=$(sha256_file "${c_manifest}")
created=$(perl -MPOSIX=strftime -e 'print strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(shift))' "${source_date_epoch}")
namespace="https://cdnca.invalid/spdx/edge-agent/${source_sha}/${version}/${arch}"
sbom="${publish}/edge-agent.spdx.json"
write_sbom "${sbom}" "${created}" "${namespace}" "${version}" "${artifact_sha}" || fail 'write SPDX SBOM'
sbom_sha=$(sha256_file "${sbom}")
provenance="${publish}/edge-agent.provenance.json"
write_provenance "${provenance}" "${arch}" "${artifact_sha}" "${artifact_size}" "${build_id}" \
  "${builder_image}" "${c_sha}" "${created}" "${source_date_epoch}" "${source_commit}" \
  "${source_repository}" "${source_sha}" "${sbom_sha}" "${toolchain}" "${version}" || fail 'write provenance'
chmod 0555 "${binary}"
chmod 0444 "${sbom}" "${provenance}"
mv -- "${publish}" "${output_dir}" || fail 'publish release output'
trap - EXIT
cleanup
