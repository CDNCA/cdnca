#!/bin/sh

SUPPORTED_CONTROL_PROTOCOL=1.0
SUPPORTED_AGENT_PROTOCOL=1.0
COMPAT_CONTROL_PROTOCOL_TOO_OLD='reason_code=COMPAT_CONTROL_PROTOCOL_TOO_OLD'
COMPAT_AGENT_PROTOCOL_TOO_OLD='reason_code=COMPAT_AGENT_PROTOCOL_TOO_OLD'
COMPAT_RELEASE_SEQUENCE_REPLAY='reason_code=COMPAT_RELEASE_SEQUENCE_REPLAY'
COMPAT_RELEASE_SEQUENCE_CONFLICT='reason_code=COMPAT_RELEASE_SEQUENCE_CONFLICT'

die() {
  printf 'cdnca-edge-agent packaging: %s\n' "$*" >&2
  exit 1
}

die_reason() {
  reason_code=$1
  shift
  case "${reason_code}" in
    ''|*[!A-Z0-9_]*) die "internal reason code is invalid" ;;
  esac
  printf 'cdnca-edge-agent packaging: reason_code=%s: %s\n' "${reason_code}" "$*" >&2
  exit 1
}

usage_error() {
  printf 'cdnca-edge-agent packaging: %s\n' "$*" >&2
  exit 64
}

validate_absolute_path() {
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *//*|*/./*|*/../*|*/.|*/..|*/) [ "$1" = / ] || return 1 ;;
  esac
}

set_destdir() {
  validate_absolute_path "$1" || usage_error "DESTDIR must be an absolute clean path"
  case "$1" in
    /) DESTDIR= ;;
    *) DESTDIR=$1 ;;
  esac
}

package_recovery_only_requested() {
  recovery_only_script_dir=$1
  case "${CDNCA_PACKAGE_RECOVERY_ONLY:-0}" in
    0) return 1 ;;
    1) ;;
    *) die "invalid internal package recovery mode" ;;
  esac
  recovery_only_dir=$(root_path /var/lib/cdnca-edge-agent-packaging/transaction/recovery)
  [ "${recovery_only_script_dir}" = "${recovery_only_dir}" ] || die "internal package recovery mode is unavailable"
  assert_safe_tree "${recovery_only_dir}"
  [ -d "${recovery_only_dir}" ] && [ ! -L "${recovery_only_dir}" ] || \
    die "transaction recovery toolset is unavailable"
  [ "$(stat -c '%u:%g:%a' "${recovery_only_dir}")" = 0:0:700 ] || \
    die "transaction recovery toolset ownership or mode is unsafe"
}

root_path() {
  printf '%s%s\n' "${DESTDIR}" "$1"
}

assert_regular_file() {
  [ -f "$1" ] && [ ! -L "$1" ] || die "$2 must be a non-symlink regular file"
}

assert_safe_tree() {
  validate_absolute_path "$1" || die "unsafe path: $1"
  path_part=${1#/}
  checked=
  while [ -n "${path_part}" ]; do
    component=${path_part%%/*}
    if [ "${component}" = "${path_part}" ]; then
      path_part=
    else
      path_part=${path_part#*/}
    fi
    checked=${checked}/${component}
    [ ! -L "${checked}" ] || die "symbolic-link path component rejected: ${checked}"
  done
}

validate_version() {
  [ -n "$1" ] && [ "${#1}" -le 128 ] || usage_error "invalid version"
  case "$1" in
    [A-Za-z0-9]* ) ;;
    *) usage_error "version must start with an ASCII letter or digit" ;;
  esac
  case "$1" in
    *[!A-Za-z0-9._-]*) usage_error "version contains unsupported characters" ;;
  esac
}

validate_uint() {
  case "$1" in
    ''|*[!0-9]*) usage_error "$2 must be a non-negative integer" ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "sha256sum or shasum is required"
  fi
}

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf '%s\n' amd64 ;;
    aarch64|arm64) printf '%s\n' arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

require_supported_host() {
  [ "$(uname -s)" = Linux ] || die_reason HOST_NOT_LINUX "only Linux artifacts are supported"
  [ -r /etc/os-release ] || die_reason HOST_OS_RELEASE_UNAVAILABLE "/etc/os-release is unavailable"
  distro_id=$(sed -n 's/^ID=//p' /etc/os-release | sed 's/^"//;s/"$//' | sed -n '1p')
  distro_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | sed 's/^"//;s/"$//' | sed -n '1p')
  for host_command in $(required_host_commands); do
    command -v "${host_command}" >/dev/null 2>&1 ||
      die_reason HOST_DEPENDENCY_MISSING "required command is unavailable: ${host_command}"
  done
  systemd_version=$(systemctl --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
  [ -n "${systemd_version}" ] || die_reason HOST_SYSTEMD_VERSION_UNAVAILABLE "cannot determine systemd version"
  if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
    cgroup_mode=unified
  else
    cgroup_mode=legacy
  fi
  validate_supported_host_facts "${distro_id}" "${distro_version}" "$(uname -r)" "${systemd_version}" "${cgroup_mode}"
}

ED25519_TOOL_PATH=/usr/libexec/cdnca-ed25519

# Trusted like /usr/bin/openssl: a root-owned, non-writable regular file in a
# root-owned system directory (outside every helper ReadWritePaths entry).
ed25519_tool_trusted() {
  [ -f "${ED25519_TOOL_PATH}" ] && [ ! -L "${ED25519_TOOL_PATH}" ] || return 1
  [ "$(stat -c '%u:%a:%h' "${ED25519_TOOL_PATH}" 2>/dev/null)" = 0:555:1 ] || return 1
  [ "$(stat -c '%u' /usr/libexec 2>/dev/null)" = 0 ] && [ ! -L /usr/libexec ] || return 1
  [ $(( 0$(stat -c '%a' /usr/libexec) & 022 )) -eq 0 ]
}

required_host_commands() {
  for host_command in \
    awk basename cmp cp date dirname env find flock getent id install jq ln mkdir mktemp mv \
    od perl readlink rm sed setpriv sha256sum sort stat sync systemctl \
    systemd-sysusers systemd-tmpfiles tr uname wc; do
    printf '%s\n' "${host_command}"
  done
}

validate_supported_host_facts() {
  host_distro_id=$1
  host_distro_version=$2
  host_kernel_release=$3
  host_systemd_version=$4
  host_cgroup_mode=$5

  # Same tiers as scripts/lib/install-preflight.sh (docs/install/os-support-matrix.md).
  # RHEL-family VERSION_ID carries the point release (9.4); only the major counts.
  case "${host_distro_id}" in
    rocky|almalinux|rhel) host_distro_version=${host_distro_version%%.*} ;;
  esac
  case "${host_distro_id}:${host_distro_version}" in
    debian:12) minimum_systemd_version=252 ;;
    ubuntu:24.04) minimum_systemd_version=255 ;;
    ubuntu:22.04) minimum_systemd_version=249 ;;
    ubuntu:20.04) minimum_systemd_version=245 ;;
    ubuntu:18.04) minimum_systemd_version=237 ;;
    debian:10) minimum_systemd_version=241 ;;
    debian:11) minimum_systemd_version=247 ;;
    debian:13) minimum_systemd_version=257 ;;
    rocky:8|almalinux:8|rhel:8) minimum_systemd_version=239 ;;
    rocky:9|almalinux:9|rhel:9) minimum_systemd_version=252 ;;
    rocky:10|almalinux:10|rhel:10) minimum_systemd_version=257 ;;
    *)
      die_reason HOST_UNSUPPORTED_DISTRIBUTION \
        "unsupported distribution: ${host_distro_id:-unknown} ${host_distro_version:-unknown}"
      ;;
  esac

  host_kernel_version=${host_kernel_release%%-*}
  host_kernel_major=${host_kernel_version%%.*}
  host_kernel_remainder=${host_kernel_version#*.}
  [ "${host_kernel_remainder}" != "${host_kernel_version}" ] ||
    die_reason HOST_KERNEL_VERSION_INVALID "kernel release is invalid: ${host_kernel_release}"
  host_kernel_minor=${host_kernel_remainder%%.*}
  case "${host_kernel_major}" in
    ''|*[!0-9]*)
      die_reason HOST_KERNEL_VERSION_INVALID "kernel release is invalid: ${host_kernel_release}"
      ;;
  esac
  case "${host_kernel_minor}" in
    ''|*[!0-9]*)
      die_reason HOST_KERNEL_VERSION_INVALID "kernel release is invalid: ${host_kernel_release}"
      ;;
  esac
  # The Agent signals OpenResty only through pidfd_open/pidfd_send_signal
  # (Linux 5.3+): there is no PID-reuse-prone kill(2) fallback. Older kernels
  # pass only when they carry a pidfd backport, proven by a live probe.
  if [ "${host_kernel_major}" -lt 5 ] ||
    { [ "${host_kernel_major}" -eq 5 ] && [ "${host_kernel_minor}" -lt 3 ]; }; then
    host_pidfd_supported ||
      die_reason HOST_KERNEL_TOO_OLD "Linux kernel 5.3 or newer (pidfd_open) is required"
  fi

  case "${host_systemd_version}" in
    ''|*[!0-9]*) die_reason HOST_SYSTEMD_VERSION_UNAVAILABLE "systemd version is invalid" ;;
  esac
  [ "${host_systemd_version}" -ge "${minimum_systemd_version}" ] ||
    die_reason HOST_SYSTEMD_TOO_OLD \
      "${host_distro_id} ${host_distro_version} requires systemd ${minimum_systemd_version} or newer"
  # cgroup v1 (legacy/hybrid) is accepted: the Agent reads either hierarchy's
  # systemd line in /proc/<pid>/cgroup; the installer preflight warns instead.
  case "${host_cgroup_mode}" in
    unified|legacy) ;;
    *) die_reason HOST_CGROUP_MODE_UNKNOWN "cgroup mode is invalid" ;;
  esac
}

# pidfd_open(getpid(), 0) through the host perl (already a packaging
# dependency). ENOSYS means the kernel lacks pidfd; any fd or other errno
# (for example EPERM under a seccomp filter) means the syscall exists.
host_pidfd_supported() {
  command -v perl >/dev/null 2>&1 || return 1
  perl -e 'require POSIX; my $fd = syscall(434, $$, 0); exit(($fd < 0 && $! == POSIX::ENOSYS()) ? 1 : 0)' 2>/dev/null
}

manifest_value() {
  manifest_path=$1
  manifest_line=$2
  manifest_key=$3
  value=$(sed -n "${manifest_line}p" "${manifest_path}")
  case "${value}" in
    "${manifest_key}="*) printf '%s\n' "${value#*=}" ;;
    *) die "manifest line ${manifest_line} must be ${manifest_key}=..." ;;
  esac
}

validate_canonical_uint() {
  number=$1
  label=$2
  validate_uint "${number}" "${label}"
  [ "${#number}" -le 18 ] || die "${label} is too large"
  case "${number}" in
    0*) [ "${number}" = 0 ] || die "${label} is not canonical" ;;
  esac
}

validate_sha256() {
  [ "${#1}" -eq 64 ] || die "$2 SHA-256 is invalid"
  case "$1" in
    *[!0-9a-f]*) die "$2 SHA-256 is invalid" ;;
  esac
}

validate_protocol() {
  protocol=$1
  label=$2
  case "${protocol}" in
    *.*) ;;
    *) die "${label} protocol must use MAJOR.MINOR" ;;
  esac
  case "${protocol#*.}" in
    *.*) die "${label} protocol must use MAJOR.MINOR" ;;
  esac
  protocol_major=${protocol%%.*}
  protocol_minor=${protocol#*.}
  validate_canonical_uint "${protocol_major}" "${label} protocol major"
  validate_canonical_uint "${protocol_minor}" "${label} protocol minor"
  [ "${protocol_major}" -gt 0 ] || die "${label} protocol major must be positive"
}

protocol_at_least() {
  supported=$1
  required=$2
  supported_major=${supported%%.*}
  supported_minor=${supported#*.}
  required_major=${required%%.*}
  required_minor=${required#*.}
  [ "${supported_major}" -gt "${required_major}" ] || {
    [ "${supported_major}" -eq "${required_major}" ] && [ "${supported_minor}" -ge "${required_minor}" ]
  }
}

file_size() {
  stat -c '%s' "$1" || die "cannot read file size: $1"
}

durable_sync() {
  sync -f "$1" || die "cannot durably sync: $1"
}

consume_failpoint() {
  [ -n "${DESTDIR}" ] || return 1
  [ "${CDNCA_PACKAGE_FAILPOINT:-}" = "$1" ] || return 1
  unset CDNCA_PACKAGE_FAILPOINT
}

failpoint_die() {
  consume_failpoint "$1" || return 0
  die "injected failure before $1"
}

failpoint_interrupt() {
  consume_failpoint "$1" || return 0
  kill -TERM "$$"
  die "injected interrupt before $1"
}

failpoint_sigkill() {
  consume_failpoint "$1" || return 0
  kill -KILL "$$"
}

verify_elf_artifact() {
  artifact_path=$1
  artifact_arch=$2
  elf_magic=$(od -An -tx1 -N4 "${artifact_path}" | tr -d ' \n')
  [ "${elf_magic}" = 7f454c46 ] || die "artifact is not an ELF executable"
  elf_class=$(od -An -tu1 -j4 -N1 "${artifact_path}" | tr -d ' ')
  elf_data=$(od -An -tu1 -j5 -N1 "${artifact_path}" | tr -d ' ')
  elf_type=$(od -An -tx1 -j16 -N2 "${artifact_path}" | tr -d ' \n')
  elf_machine=$(od -An -tx1 -j18 -N2 "${artifact_path}" | tr -d ' \n')
  [ "${elf_class}" = 2 ] && [ "${elf_data}" = 1 ] || die "artifact must be a 64-bit little-endian ELF"
  case "${elf_type}" in
    0200|0300) ;;
    *) die "artifact ELF type is not executable" ;;
  esac
  case "${artifact_arch}:${elf_machine}" in
    amd64:3e00|arm64:b700) ;;
    *) die "artifact ELF machine differs from manifest architecture" ;;
  esac
}

verify_spdx_sbom() {
  command -v jq >/dev/null 2>&1 || die "jq is required for SPDX SBOM validation"
  jq -e '
    type == "object" and
    .spdxVersion == "SPDX-2.3" and
    .dataLicense == "CC0-1.0" and
    .SPDXID == "SPDXRef-DOCUMENT" and
    ((.name | type) == "string" and (.name | length) > 0) and
    ((.documentNamespace | type) == "string" and
      ((.documentNamespace | startswith("https://")) or
       (.documentNamespace | startswith("http://")))) and
    ((.creationInfo | type) == "object") and
    ((.creationInfo.created | type) == "string" and
      (.creationInfo.created | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))) and
    ((.creationInfo.creators | type) == "array" and
      (.creationInfo.creators | length) > 0 and
      all(.creationInfo.creators[]; type == "string" and length > 0))
  ' "$1" >/dev/null || die "SBOM is not a valid minimal SPDX 2.3 document"
}

agent_ids() {
  if [ -n "${DESTDIR}" ]; then
    passwd_file=$(root_path /etc/passwd)
    assert_safe_tree "${passwd_file}"
    assert_regular_file "${passwd_file}" "staged passwd database"
    agent_uid=$(awk -F: '$1 == "cdnca-edge" { print $3; exit }' "${passwd_file}")
    agent_gid=$(awk -F: '$1 == "cdnca-edge" { print $4; exit }' "${passwd_file}")
  else
    agent_uid=$(id -u cdnca-edge 2>/dev/null) || die "cdnca-edge user is unavailable"
    agent_gid=$(id -g cdnca-edge 2>/dev/null) || die "cdnca-edge group is unavailable"
  fi
  validate_uint "${agent_uid}" "cdnca-edge uid"
  validate_uint "${agent_gid}" "cdnca-edge gid"
  [ "${agent_uid}" -gt 0 ] && [ "${agent_gid}" -gt 0 ] || die "cdnca-edge must be unprivileged"
  printf '%s:%s\n' "${agent_uid}" "${agent_gid}"
}

# The packaged Agent runs either as the unprivileged cdnca-edge account (the
# default deb layout) or as root (native nodes, whose OpenResty worker
# management requires root). A fresh root install records the choice in a
# root-owned marker that only root can create; an absent marker is cdnca-edge.
RUNTIME_IDENTITY_MARKER=/var/lib/cdnca-edge-agent-packaging/runtime-identity

load_runtime_identity() {
  marker=$(root_path "${RUNTIME_IDENTITY_MARKER}")
  assert_safe_tree "${marker}"
  if [ ! -e "${marker}" ] && [ ! -L "${marker}" ]; then
    PACKAGE_RUNTIME_IDENTITY=cdnca-edge
    return
  fi
  assert_regular_file "${marker}" "runtime identity marker"
  [ "$(stat -c '%u:%g:%a:%h:%s' "${marker}")" = 0:0:600:1:4 ] || \
    die "runtime identity marker ownership, mode, or size is unsafe"
  [ "$(cat "${marker}")" = root ] || die "runtime identity marker is invalid"
  PACKAGE_RUNTIME_IDENTITY=root
}

write_runtime_identity() {
  requested=$1
  marker=$(root_path "${RUNTIME_IDENTITY_MARKER}")
  marker_parent=$(dirname -- "${marker}")
  assert_safe_tree "${marker}"
  case "${requested}" in
    cdnca-edge)
      if [ -e "${marker}" ] || [ -L "${marker}" ]; then
        assert_regular_file "${marker}" "runtime identity marker"
        rm -f -- "${marker}"
        durable_sync "${marker_parent}"
      fi
      ;;
    root)
      install -d -m 0700 "${marker_parent}"
      marker_temporary=${marker_parent}/.runtime-identity.$$
      [ ! -e "${marker_temporary}" ] && [ ! -L "${marker_temporary}" ] || die "runtime identity staging exists"
      printf 'root' >"${marker_temporary}"
      chmod 0600 "${marker_temporary}"
      durable_sync "${marker_temporary}"
      mv -Tf "${marker_temporary}" "${marker}"
      durable_sync "${marker_parent}"
      ;;
    *) die "unsupported runtime identity" ;;
  esac
  load_runtime_identity
  [ "${PACKAGE_RUNTIME_IDENTITY}" = "${requested}" ] || die "runtime identity marker was not recorded"
}

require_runtime_identity() {
  [ -n "${PACKAGE_RUNTIME_IDENTITY:-}" ] || load_runtime_identity
}

runtime_ids() {
  require_runtime_identity
  case "${PACKAGE_RUNTIME_IDENTITY}" in
    root) printf '0:0\n' ;;
    cdnca-edge) agent_ids ;;
    *) die "runtime identity is invalid" ;;
  esac
}

run_root_probe() {
  [ "$(id -u)" -eq 0 ] || die "root-mode configuration probes require root"
  command -v setpriv >/dev/null 2>&1 || die "setpriv is required for release probes"
  setpriv --clear-groups --no-new-privs -- env -i \
    PATH=/usr/bin:/bin \
    CDNCA_PROBE_EXPECT_UID=0 \
    CDNCA_PROBE_EXPECT_GID=0 \
    "$@" 9>&-
}

run_restricted_probe() {
  probe_uid=$1
  probe_gid=$2
  shift 2
  validate_uint "${probe_uid}" "probe uid"
  validate_uint "${probe_gid}" "probe gid"
  [ "${probe_uid}" -gt 0 ] && [ "${probe_gid}" -gt 0 ] || die "release probes must be unprivileged"
  command -v setpriv >/dev/null 2>&1 || die "setpriv is required for unprivileged release probes"
  if [ "$(id -u)" -eq "${probe_uid}" ]; then
    [ "$(id -g)" -eq "${probe_gid}" ] && [ "$(id -G)" = "${probe_gid}" ] || die "probe caller has unexpected groups"
    setpriv --no-new-privs -- env -i \
      PATH=/usr/bin:/bin \
      CDNCA_PROBE_EXPECT_UID="${probe_uid}" \
      CDNCA_PROBE_EXPECT_GID="${probe_gid}" \
      "$@" 9>&-
  else
    [ "$(id -u)" -eq 0 ] || die "release probes require root or cdnca-edge"
    setpriv \
      --reuid "${probe_uid}" \
      --regid "${probe_gid}" \
      --clear-groups \
      --no-new-privs \
      -- env -i \
      PATH=/usr/bin:/bin \
      CDNCA_PROBE_EXPECT_UID="${probe_uid}" \
      CDNCA_PROBE_EXPECT_GID="${probe_gid}" \
      "$@" 9>&-
  fi
}

run_agent_probe() {
  probe_ids=$(agent_ids)
  run_restricted_probe "${probe_ids%:*}" "${probe_ids#*:}" "$@"
}

probe_candidate_version() {
  candidate_artifact=$1
  expected_version=$2
  version_output=$(run_restricted_probe 65534 65534 "${candidate_artifact}" --version 2>&1) || die "candidate artifact version probe failed as an unprivileged identity"
  printf '%s\n' "${version_output}" | grep -F "\"agent_version\":\"${expected_version}\"" >/dev/null || die "candidate artifact version differs from manifest"
}

probe_release_version() {
  probe_artifact=$1
  expected_version=$2
  version_output=$(run_agent_probe "${probe_artifact}" --version 2>&1) || die "signed artifact version probe failed as cdnca-edge"
  printf '%s\n' "${version_output}" | grep -F "\"agent_version\":\"${expected_version}\"" >/dev/null || die "artifact version differs from manifest"
}

# The configuration probe runs as the identity the service runs as, because
# only that identity can read the owner-only configuration. In root mode the
# service itself executes the same signature-verified release as root.
probe_release_config() {
  probe_artifact=$1
  probe_config=$2
  require_runtime_identity
  case "${PACKAGE_RUNTIME_IDENTITY}" in
    root)
      run_root_probe "${probe_artifact}" --check-config -config "${probe_config}" >/dev/null 2>&1 || \
        die "release rejected the installed configuration as root"
      ;;
    cdnca-edge)
      run_agent_probe "${probe_artifact}" --check-config -config "${probe_config}" >/dev/null 2>&1 || \
        die "release rejected the installed configuration as cdnca-edge"
      ;;
    *) die "runtime identity is invalid" ;;
  esac
}

verify_input_file() {
  input_path=$1
  label=$2
  maximum_size=$3
  validate_absolute_path "${input_path}" || usage_error "bundle paths must be absolute and clean"
  assert_safe_tree "${input_path}"
  assert_regular_file "${input_path}" "${label}"
  [ "$(stat -c '%h' "${input_path}")" -eq 1 ] || die "${label} must not be a hard link"
  input_mode=$(stat -c '%a' "${input_path}")
  [ $((0${input_mode} & 07022)) -eq 0 ] || die "${label} has unsafe permissions"
  input_size=$(file_size "${input_path}")
  [ "${input_size}" -gt 0 ] && [ "${input_size}" -le "${maximum_size}" ] || die "${label} size is outside the allowed range"
}

verify_bundle() {
  artifact=$1
  sbom=$2
  manifest=$3
  signature=$4
  public_key=$5

  verify_input_file "${artifact}" artifact 268435456
  verify_input_file "${sbom}" SBOM 16777216
  verify_input_file "${manifest}" manifest 16384
  verify_input_file "${signature}" signature 64
  verify_input_file "${public_key}" "public key" 4096
  [ "$(file_size "${signature}")" -eq 64 ] || die "Ed25519 signature must contain exactly 64 bytes"
  [ -x "${artifact}" ] || die "artifact must be executable"
  # Native nodes carry the static Ed25519 tool installed (and pinned) by
  # install-node.sh in a root-only system path; docs/install/ed25519-tool-security.md.
  # Only hosts installed without it (Debian package path) fall back to OpenSSL 3.
  if ed25519_tool_trusted; then
    "${ED25519_TOOL_PATH}" check-public "${public_key}" >/dev/null 2>&1 || die "public key is not Ed25519"
    "${ED25519_TOOL_PATH}" verify "${public_key}" "${manifest}" "${signature}" >/dev/null 2>&1 ||
      die "manifest signature verification failed"
  else
    command -v openssl >/dev/null 2>&1 || die "openssl is required"
    openssl pkey -pubin -in "${public_key}" -text_pub -noout 2>/dev/null | grep -q '^ED25519 Public-Key:' || die "public key is not Ed25519"
    openssl pkeyutl -verify -pubin -inkey "${public_key}" -rawin \
      -in "${manifest}" -sigfile "${signature}" >/dev/null 2>&1 || die "manifest signature verification failed"
  fi

  [ "$(wc -l <"${manifest}" | tr -d ' ')" = 16 ] || die "manifest must contain exactly 16 newline-terminated canonical lines"
  release_manifest_version=$(manifest_value "${manifest}" 1 manifest_version)
  release_sequence=$(manifest_value "${manifest}" 2 release_sequence)
  release_version=$(manifest_value "${manifest}" 3 version)
  manifest_artifact_path=$(manifest_value "${manifest}" 4 artifact_path)
  manifest_artifact_sha256=$(manifest_value "${manifest}" 5 artifact_sha256)
  manifest_artifact_size=$(manifest_value "${manifest}" 6 artifact_size)
  manifest_sbom_path=$(manifest_value "${manifest}" 7 sbom_path)
  manifest_sbom_sha256=$(manifest_value "${manifest}" 8 sbom_sha256)
  manifest_sbom_size=$(manifest_value "${manifest}" 9 sbom_size)
  manifest_os=$(manifest_value "${manifest}" 10 os)
  manifest_arch=$(manifest_value "${manifest}" 11 arch)
  source_repository=$(manifest_value "${manifest}" 12 source_repository)
  source_commit=$(manifest_value "${manifest}" 13 source_commit)
  build_time=$(manifest_value "${manifest}" 14 build_time)
  minimum_control_protocol=$(manifest_value "${manifest}" 15 minimum_control_protocol)
  minimum_agent_protocol=$(manifest_value "${manifest}" 16 minimum_agent_protocol)

  [ "${release_manifest_version}" = 2 ] || die "unsupported or downgraded manifest version"
  validate_canonical_uint "${release_sequence}" release_sequence
  [ "${release_sequence}" -gt 0 ] || die "release_sequence must be positive"
  validate_version "${release_version}"
  [ "${manifest_artifact_path}" = edge-agent ] || die "artifact_path is not canonical"
  [ "${manifest_sbom_path}" = edge-agent.spdx.json ] || die "sbom_path is not canonical"
  [ "$(basename -- "${artifact}")" = "${manifest_artifact_path}" ] || die "artifact filename differs from manifest"
  [ "$(basename -- "${sbom}")" = "${manifest_sbom_path}" ] || die "SBOM filename differs from manifest"
  validate_sha256 "${manifest_artifact_sha256}" artifact
  validate_sha256 "${manifest_sbom_sha256}" SBOM
  validate_canonical_uint "${manifest_artifact_size}" artifact_size
  validate_canonical_uint "${manifest_sbom_size}" sbom_size
  [ "${manifest_artifact_size}" -gt 0 ] && [ "${manifest_artifact_size}" -le 268435456 ] || die "artifact_size is outside the allowed range"
  [ "${manifest_sbom_size}" -gt 0 ] && [ "${manifest_sbom_size}" -le 16777216 ] || die "sbom_size is outside the allowed range"
  [ "${manifest_os}" = linux ] || die "manifest operating system is not linux"
  [ "$(uname -s)" = Linux ] || die "artifact operating system does not match this host"
  [ "${manifest_arch}" = "$(host_arch)" ] || die "artifact architecture does not match this host"
  verify_elf_artifact "${artifact}" "${manifest_arch}"
  [ -n "${source_repository}" ] && [ "${#source_repository}" -le 256 ] || die "source_repository is invalid"
  case "${source_repository}" in
    https://?*|ssh://?*) ;;
    *) die "source_repository must be an https or ssh URI" ;;
  esac
  case "${source_repository}" in
    *[!A-Za-z0-9:/._@-]*) die "source_repository contains unsupported characters" ;;
  esac
  case "${#source_commit}" in
    40|64) ;;
    *) die "source_commit must contain 40 or 64 lowercase hexadecimal characters" ;;
  esac
  case "${source_commit}" in
    *[!0-9a-f]*) die "source_commit is invalid" ;;
  esac
  [ "${#build_time}" -eq 20 ] && [ "$(date -u -d "${build_time}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)" = "${build_time}" ] || die "build_time must be canonical UTC RFC3339"
  validate_protocol "${minimum_control_protocol}" minimum-control
  validate_protocol "${minimum_agent_protocol}" minimum-agent
  protocol_at_least "${SUPPORTED_CONTROL_PROTOCOL}" "${minimum_control_protocol}" ||
    die_reason "${COMPAT_CONTROL_PROTOCOL_TOO_OLD#reason_code=}" \
      "control protocol ${SUPPORTED_CONTROL_PROTOCOL} does not satisfy the release minimum"
  protocol_at_least "${SUPPORTED_AGENT_PROTOCOL}" "${minimum_agent_protocol}" ||
    die_reason "${COMPAT_AGENT_PROTOCOL_TOO_OLD#reason_code=}" \
      "agent protocol ${SUPPORTED_AGENT_PROTOCOL} does not satisfy the release minimum"
  [ "$(file_size "${artifact}")" = "${manifest_artifact_size}" ] || die "artifact size differs from manifest"
  [ "$(file_size "${sbom}")" = "${manifest_sbom_size}" ] || die "SBOM size differs from manifest"
  [ "$(sha256_file "${artifact}")" = "${manifest_artifact_sha256}" ] || die "artifact SHA-256 verification failed"
  [ "$(sha256_file "${sbom}")" = "${manifest_sbom_sha256}" ] || die "SBOM SHA-256 verification failed"
  verify_spdx_sbom "${sbom}"
  VERIFIED_VERSION=${release_version}
  VERIFIED_SEQUENCE=${release_sequence}
  VERIFIED_MANIFEST=${manifest}
}

record_bundle_fingerprints() {
  BUNDLE_ARTIFACT_SHA256=$(sha256_file "$1")
  BUNDLE_SBOM_SHA256=$(sha256_file "$2")
  BUNDLE_MANIFEST_SHA256=$(sha256_file "$3")
  BUNDLE_SIGNATURE_SHA256=$(sha256_file "$4")
  BUNDLE_PUBLIC_KEY_SHA256=$(sha256_file "$5")
}

assert_bundle_fingerprints() {
  [ "$(sha256_file "$1")" = "${BUNDLE_ARTIFACT_SHA256}" ] || die "artifact changed during validation"
  [ "$(sha256_file "$2")" = "${BUNDLE_SBOM_SHA256}" ] || die "SBOM changed during validation"
  [ "$(sha256_file "$3")" = "${BUNDLE_MANIFEST_SHA256}" ] || die "manifest changed during validation"
  [ "$(sha256_file "$4")" = "${BUNDLE_SIGNATURE_SHA256}" ] || die "signature changed during validation"
  [ "$(sha256_file "$5")" = "${BUNDLE_PUBLIC_KEY_SHA256}" ] || die "public key changed during validation"
}

cleanup_bundle_staging() {
  staging_path=${1:-${PACKAGE_BUNDLE_STAGING:-}}
  [ -n "${staging_path}" ] || return 0
  staging_parent=$(root_path /usr/lib/cdnca-edge-agent)
  case "${staging_path}" in
    "${staging_parent}"/.input-bundle-*) ;;
    *) die "unsafe bundle staging cleanup path" ;;
  esac
  if [ -e "${staging_path}" ] || [ -L "${staging_path}" ]; then
    [ -d "${staging_path}" ] && [ ! -L "${staging_path}" ] || die "bundle staging path became unsafe"
    rm -rf -- "${staging_path}"
  fi
  rmdir "${staging_parent}" >/dev/null 2>&1 || true
  if [ "${staging_path}" = "${PACKAGE_BUNDLE_STAGING:-}" ]; then
    PACKAGE_BUNDLE_STAGING=
  fi
}

stage_bundle_inputs() {
  source_artifact=$1
  source_sbom=$2
  source_manifest=$3
  source_signature=$4
  source_public_key=$5

  if [ -n "${CDNCA_PACKAGE_TEST_AFTER_LOCK_HOOK:-}" ]; then
    [ -n "${DESTDIR}" ] || die "the after-lock hook is available only with DESTDIR"
    validate_absolute_path "${CDNCA_PACKAGE_TEST_AFTER_LOCK_HOOK}" || die "after-lock hook path is unsafe"
    verify_input_file "${CDNCA_PACKAGE_TEST_AFTER_LOCK_HOOK}" "after-lock hook" 1048576
    [ -x "${CDNCA_PACKAGE_TEST_AFTER_LOCK_HOOK}" ] || die "after-lock hook is not executable"
    "${CDNCA_PACKAGE_TEST_AFTER_LOCK_HOOK}"
  fi

  staging_parent=$(root_path /usr/lib/cdnca-edge-agent)
  PACKAGE_BUNDLE_STAGING=${staging_parent}/.input-bundle-$$
  assert_safe_tree "${staging_parent}"
  assert_safe_tree "${PACKAGE_BUNDLE_STAGING}"
  install -d -m 0755 "${staging_parent}"
  [ ! -e "${PACKAGE_BUNDLE_STAGING}" ] && [ ! -L "${PACKAGE_BUNDLE_STAGING}" ] || die "bundle staging path exists"
  install -d -m 0755 "${PACKAGE_BUNDLE_STAGING}"
  install -m 0555 "${source_artifact}" "${PACKAGE_BUNDLE_STAGING}/edge-agent"
  install -m 0444 "${source_sbom}" "${PACKAGE_BUNDLE_STAGING}/edge-agent.spdx.json"
  install -m 0444 "${source_manifest}" "${PACKAGE_BUNDLE_STAGING}/manifest"
  install -m 0444 "${source_signature}" "${PACKAGE_BUNDLE_STAGING}/manifest.sig"
  install -m 0444 "${source_public_key}" "${PACKAGE_BUNDLE_STAGING}/public-key.pem"
  chmod 0555 "${PACKAGE_BUNDLE_STAGING}"
  durable_sync "${PACKAGE_BUNDLE_STAGING}"

  [ "$(stat -c '%u:%g:%a' "${PACKAGE_BUNDLE_STAGING}")" = 0:0:555 ] || die "bundle staging ownership or mode is unsafe"
  for staged_input in \
    "${PACKAGE_BUNDLE_STAGING}/edge-agent" \
    "${PACKAGE_BUNDLE_STAGING}/edge-agent.spdx.json" \
    "${PACKAGE_BUNDLE_STAGING}/manifest" \
    "${PACKAGE_BUNDLE_STAGING}/manifest.sig" \
    "${PACKAGE_BUNDLE_STAGING}/public-key.pem"; do
    [ "$(stat -c '%u:%g' "${staged_input}")" = 0:0 ] || die "bundle staging input is not owned by root"
  done

  STAGED_ARTIFACT=${PACKAGE_BUNDLE_STAGING}/edge-agent
  STAGED_SBOM=${PACKAGE_BUNDLE_STAGING}/edge-agent.spdx.json
  STAGED_MANIFEST=${PACKAGE_BUNDLE_STAGING}/manifest
  STAGED_SIGNATURE=${PACKAGE_BUNDLE_STAGING}/manifest.sig
  STAGED_PUBLIC_KEY=${PACKAGE_BUNDLE_STAGING}/public-key.pem
  assert_bundle_fingerprints \
    "${STAGED_ARTIFACT}" "${STAGED_SBOM}" "${STAGED_MANIFEST}" \
    "${STAGED_SIGNATURE}" "${STAGED_PUBLIC_KEY}"
}

# The native node package of a v2 bundle. Its signature is the native release
# signature (artifact trust); the Agent checks it before it switches
# /opt/cdnca-node. Here only its framing and that it does not change.
verify_native_input() {
  verify_input_file "$1" "native package" 209715200
  [ "$(od -An -tx1 -N2 "$1" | tr -d ' \n')" = 1f8b ] || die "native package is not gzip"
}

stage_native_input() {
  [ -n "${PACKAGE_BUNDLE_STAGING:-}" ] || die "bundle staging is missing"
  chmod 0755 "${PACKAGE_BUNDLE_STAGING}"
  install -m 0444 "$1" "${PACKAGE_BUNDLE_STAGING}/native.tar.gz"
  chmod 0555 "${PACKAGE_BUNDLE_STAGING}"
  durable_sync "${PACKAGE_BUNDLE_STAGING}"
  STAGED_NATIVE=${PACKAGE_BUNDLE_STAGING}/native.tar.gz
  [ "$(stat -c '%u:%g' "${STAGED_NATIVE}")" = 0:0 ] || die "bundle staging input is not owned by root"
  [ "$(sha256_file "${STAGED_NATIVE}")" = "${NATIVE_PACKAGE_SHA256}" ] || die "native package changed during validation"
}

check_release_replay() {
  accepted=$(root_path /var/lib/cdnca-edge-agent-packaging/accepted-manifest)
  assert_safe_tree "${accepted}"
  if [ -e "${accepted}" ] || [ -L "${accepted}" ]; then
    verify_input_file "${accepted}" "accepted manifest" 16384
    [ "$(stat -c '%u' "${accepted}")" -eq 0 ] || die "accepted manifest must be owned by root"
    [ "$(wc -l <"${accepted}" | tr -d ' ')" = 16 ] || die "accepted manifest is not canonical"
    [ "$(manifest_value "${accepted}" 1 manifest_version)" = 2 ] || die "accepted manifest version is invalid"
    accepted_sequence=$(manifest_value "${accepted}" 2 release_sequence)
    validate_canonical_uint "${accepted_sequence}" accepted-release_sequence
    [ "${VERIFIED_SEQUENCE}" -ge "${accepted_sequence}" ] ||
      die_reason "${COMPAT_RELEASE_SEQUENCE_REPLAY#reason_code=}" \
        "release manifest replay or downgrade rejected"
    if [ "${VERIFIED_SEQUENCE}" -eq "${accepted_sequence}" ]; then
      cmp -s "${VERIFIED_MANIFEST}" "${accepted}" ||
        die_reason "${COMPAT_RELEASE_SEQUENCE_CONFLICT#reason_code=}" \
          "release sequence was already accepted with different content"
    fi
  fi
}

publish_accepted_manifest() {
  accepted_root=$(root_path /var/lib/cdnca-edge-agent-packaging)
  accepted=${accepted_root}/accepted-manifest
  temporary=${accepted_root}/.accepted-manifest.$$
  previous=${accepted_root}/.accepted-manifest-previous.$$
  install -m 0600 "${VERIFIED_MANIFEST}" "${temporary}"
  durable_sync "${temporary}"
  if [ -e "${accepted}" ] || [ -L "${accepted}" ]; then
    assert_regular_file "${accepted}" "accepted manifest"
    install -m 0600 "${accepted}" "${previous}"
    durable_sync "${previous}"
  fi
  durable_sync "${accepted_root}"
  if consume_failpoint accepted-manifest-commit; then
    rm -f -- "${temporary}" "${previous}"
    durable_sync "${accepted_root}"
    die "injected failure before accepted-manifest-commit"
  fi
  mv -Tf "${temporary}" "${accepted}"
  if ! sync -f "${accepted_root}"; then
    if [ -f "${previous}" ] && [ ! -L "${previous}" ]; then
      mv -Tf "${previous}" "${accepted}" >/dev/null 2>&1 || true
    else
      rm -f -- "${accepted}" >/dev/null 2>&1 || true
    fi
    sync -f "${accepted_root}" >/dev/null 2>&1 || true
    die "cannot durably commit accepted manifest"
  fi
  rm -f -- "${previous}"
  sync -f "${accepted_root}" >/dev/null 2>&1 || printf 'cdnca-edge-agent packaging: warning: accepted manifest cleanup was not durably synced\n' >&2
}

pin_or_check_public_key() {
  source_key=$1
  pinned_key=$(root_path /etc/cdnca-edge-agent/package-signing.pem)
  assert_safe_tree "${pinned_key}"
  if [ -e "${pinned_key}" ] || [ -L "${pinned_key}" ]; then
    assert_regular_file "${pinned_key}" "pinned package public key"
    cmp -s "${source_key}" "${pinned_key}" || die "package public key differs from the pinned key"
  else
    require_runtime_identity
    if [ "${PACKAGE_RUNTIME_IDENTITY}" = root ]; then
      install -d -m 0700 "$(dirname -- "${pinned_key}")"
    else
      install -d -m 0750 "$(dirname -- "${pinned_key}")"
    fi
    install -m 0444 "${source_key}" "${pinned_key}"
    durable_sync "${pinned_key}"
    durable_sync "$(dirname -- "${pinned_key}")"
  fi
}

read_current_target() {
  current=$(root_path /usr/lib/cdnca-edge-agent/current)
  [ -L "${current}" ] || die "current release link is missing"
  target=$(readlink "${current}") || die "cannot read current release link"
  case "${target}" in
    versions/*) ;;
    *) die "current release link target is unsafe" ;;
  esac
  version=${target#versions/}
  validate_version "${version}"
  [ "${target}" = "versions/${version}" ] || die "current release link target is unsafe"
  printf '%s\n' "${target}"
}

atomic_switch_current() {
  target=$1
  case "${target}" in
    versions/*) ;;
    *) die "release link target is unsafe" ;;
  esac
  current=$(root_path /usr/lib/cdnca-edge-agent/current)
  temporary=$(root_path "/usr/lib/cdnca-edge-agent/.current.$$")
  current_parent=$(dirname -- "${current}")
  [ ! -e "${temporary}" ] && [ ! -L "${temporary}" ] || die "temporary current link exists"
  ln -s "${target}" "${temporary}"
  durable_sync "${current_parent}"
  if consume_failpoint current-commit; then
    rm -f -- "${temporary}"
    durable_sync "${current_parent}"
    die "injected failure before current-commit"
  fi
  mv -Tf "${temporary}" "${current}"
  durable_sync "${current_parent}"
}

verify_installed_release() {
  release_version=$1
  release=$(root_path "/usr/lib/cdnca-edge-agent/versions/${release_version}")
  key=$(root_path /etc/cdnca-edge-agent/package-signing.pem)
  assert_safe_tree "${release}"
  [ -d "${release}" ] && [ ! -L "${release}" ] || die "release ${release_version} is not installed"
  verify_bundle "${release}/edge-agent" "${release}/edge-agent.spdx.json" "${release}/manifest" "${release}/manifest.sig" "${key}"
  [ "${VERIFIED_VERSION}" = "${release_version}" ] || die "installed release directory and manifest differ"
}

install_release() {
  artifact=$1
  sbom=$2
  manifest=$3
  signature=$4
  native=${5:-}
  release_root=$(root_path "/usr/lib/cdnca-edge-agent/versions/${VERIFIED_VERSION}")
  versions_root=$(dirname -- "${release_root}")
  assert_safe_tree "${versions_root}"
  assert_safe_tree "${release_root}"
  install -d -m 0755 "${versions_root}"
  if [ -e "${release_root}" ] || [ -L "${release_root}" ]; then
    cmp -s "${manifest}" "${release_root}/manifest" || die "release version already exists with different manifest"
    verify_installed_release "${VERIFIED_VERSION}"
    return
  fi
  staging=${versions_root}/.staging-${VERIFIED_VERSION}-$$
  install -d -m 0755 "${staging}"
  install -m 0555 "${artifact}" "${staging}/edge-agent"
  install -m 0444 "${sbom}" "${staging}/edge-agent.spdx.json"
  install -m 0444 "${manifest}" "${staging}/manifest"
  install -m 0444 "${signature}" "${staging}/manifest.sig"
  if [ -n "${native}" ]; then
    install -m 0444 "${native}" "${staging}/native.tar.gz"
    [ "$(sha256_file "${staging}/native.tar.gz")" = "${NATIVE_PACKAGE_SHA256}" ] || die "native package changed during installation"
  fi
  durable_sync "${staging}"
  mv "${staging}" "${release_root}"
  durable_sync "${versions_root}"
  verify_installed_release "${VERIFIED_VERSION}"
}

process_start_ticks() {
  process_pid=$1
  validate_uint "${process_pid}" "process pid"
  [ -r "/proc/${process_pid}/stat" ] || return 1
  process_stat=$(sed 's/^.*) //' "/proc/${process_pid}/stat") || return 1
  process_ticks=$(printf '%s\n' "${process_stat}" | awk '{print $20}')
  validate_uint "${process_ticks}" "process start ticks"
  printf '%s\n' "${process_ticks}"
}

PACKAGE_METADATA_ENTRIES='sysusers:/usr/lib/sysusers.d/cdnca-edge-agent.conf:0644
tmpfiles:/usr/lib/tmpfiles.d/cdnca-edge-agent.conf:0644
logrotate:/etc/logrotate.d/cdnca-edge-agent:0644
agent-env:/etc/cdnca-edge-agent/agent.env:0600
config-example:/usr/share/doc/cdnca-edge-agent/config.example.json:0644
readme:/usr/share/doc/cdnca-edge-agent/README.md:0644
script-install:/usr/libexec/cdnca-edge-agent/install.sh:0555
script-lib:/usr/libexec/cdnca-edge-agent/lib.sh:0555
script-preflight:/usr/libexec/cdnca-edge-agent/preflight.sh:0555
script-rollback:/usr/libexec/cdnca-edge-agent/rollback.sh:0555
script-uninstall:/usr/libexec/cdnca-edge-agent/uninstall.sh:0555
script-upgrade:/usr/libexec/cdnca-edge-agent/upgrade.sh:0555
asset-systemd:/usr/libexec/cdnca-edge-agent/assets/systemd/cdnca-edge-agent.service:0644
asset-systemd-root:/usr/libexec/cdnca-edge-agent/assets/systemd/cdnca-edge-agent-root.service:0644
asset-sysusers:/usr/libexec/cdnca-edge-agent/assets/sysusers/cdnca-edge-agent.conf:0644
asset-tmpfiles:/usr/libexec/cdnca-edge-agent/assets/tmpfiles/cdnca-edge-agent.conf:0644
asset-tmpfiles-root:/usr/libexec/cdnca-edge-agent/assets/tmpfiles/cdnca-edge-agent-root.conf:0644
asset-logrotate:/usr/libexec/cdnca-edge-agent/assets/logrotate/cdnca-edge-agent:0644
asset-agent-env:/usr/libexec/cdnca-edge-agent/assets/config/agent.env:0644
asset-config-example:/usr/libexec/cdnca-edge-agent/assets/config/config.example.json:0644
asset-readme:/usr/libexec/cdnca-edge-agent/assets/README.md:0644'

install_atomic_metadata() {
  metadata_source=$1
  metadata_destination=$2
  metadata_mode=$3
  metadata_parent=$(dirname -- "${metadata_destination}")
  metadata_name=$(basename -- "${metadata_destination}")
  metadata_temporary=${metadata_parent}/.${metadata_name}.package-install-$$
  assert_safe_tree "${metadata_parent}"
  install -d -m 0755 "${metadata_parent}"
  [ ! -L "${metadata_destination}" ] || die "package metadata target is a symbolic link"
  [ ! -e "${metadata_temporary}" ] && [ ! -L "${metadata_temporary}" ] || \
    die "package metadata staging path exists"
  install -m "${metadata_mode}" "${metadata_source}" "${metadata_temporary}"
  [ "$(stat -c '%u:%g:%a:%h' "${metadata_temporary}")" = "0:0:${metadata_mode#0}:1" ] || \
    die "package metadata staging ownership, mode, or link count is unsafe"
  durable_sync "${metadata_temporary}"
  case "${metadata_destination}" in
    */usr/libexec/cdnca-edge-agent/lib.sh) failpoint_sigkill metadata-lib-before-commit ;;
  esac
  mv -Tf "${metadata_temporary}" "${metadata_destination}"
  durable_sync "${metadata_parent}"
}

cleanup_metadata_install_staging() {
  metadata_pid=$1
  validate_uint "${metadata_pid}" "metadata staging pid"
  for metadata_entry in \
    systemd-unit:/usr/lib/systemd/system/cdnca-edge-agent.service:0644 \
    ${PACKAGE_METADATA_ENTRIES}; do
    metadata_detail=${metadata_entry#*:}
    metadata_path=${metadata_detail%:*}
    metadata_destination=$(root_path "${metadata_path}")
    metadata_parent=$(dirname -- "${metadata_destination}")
    metadata_name=$(basename -- "${metadata_destination}")
    metadata_temporary=${metadata_parent}/.${metadata_name}.package-install-${metadata_pid}
    if [ -e "${metadata_temporary}" ] || [ -L "${metadata_temporary}" ]; then
      assert_regular_file "${metadata_temporary}" "package metadata staging"
      [ "$(stat -c '%u:%g:%h' "${metadata_temporary}")" = 0:0:1 ] || \
        die "package metadata staging ownership or link count is unsafe"
      metadata_writable=$(find "${metadata_temporary}" -maxdepth 0 -perm /0022 -print -quit)
      [ -z "${metadata_writable}" ] || die "package metadata staging is group/world writable"
      rm -f -- "${metadata_temporary}"
      durable_sync "${metadata_parent}"
    fi
  done
}

snapshot_transaction_metadata() {
  transaction_dir=$1
  snapshot_dir=${transaction_dir}/metadata
  install -d -m 0700 "${snapshot_dir}"
  for metadata_entry in ${PACKAGE_METADATA_ENTRIES}; do
    metadata_id=${metadata_entry%%:*}
    metadata_detail=${metadata_entry#*:}
    metadata_path=${metadata_detail%:*}
    metadata_mode=${metadata_entry##*:}
    installed_metadata=$(root_path "${metadata_path}")
    if [ -e "${installed_metadata}" ] || [ -L "${installed_metadata}" ]; then
      assert_regular_file "${installed_metadata}" "installed package metadata"
      [ "$(stat -c '%u:%a:%h' "${installed_metadata}")" = "0:${metadata_mode#0}:1" ] || \
        die "installed package metadata ownership, mode, or link count is unsafe: ${metadata_path}"
      install -m 0600 "${installed_metadata}" "${snapshot_dir}/${metadata_id}"
      durable_sync "${snapshot_dir}/${metadata_id}"
    fi
  done
  durable_sync "${snapshot_dir}"
}

verify_transaction_metadata() {
  transaction_dir=$1
  snapshot_dir=${transaction_dir}/metadata
  [ -d "${snapshot_dir}" ] && [ ! -L "${snapshot_dir}" ] || die "transaction metadata snapshot is unsafe"
  [ "$(stat -c '%u:%a' "${snapshot_dir}")" = 0:700 ] || die "transaction metadata snapshot ownership or mode is unsafe"
  unsafe_snapshot=$(find "${snapshot_dir}" -mindepth 1 -maxdepth 1 \
    \( ! -type f -o -links +1 -o ! -uid 0 -o ! -perm 0600 \) -print -quit)
  [ -z "${unsafe_snapshot}" ] || die "transaction metadata snapshot contains an unsafe entry"
  for metadata_entry in ${PACKAGE_METADATA_ENTRIES}; do
    metadata_id=${metadata_entry%%:*}
    if [ -e "${snapshot_dir}/${metadata_id}" ] || [ -L "${snapshot_dir}/${metadata_id}" ]; then
      assert_regular_file "${snapshot_dir}/${metadata_id}" "transaction package metadata"
    fi
  done
}

snapshot_transaction_recovery() {
  transaction_dir=$1
  [ -n "${TX_OLD_TARGET}" ] || return 0
  recovery_dir=${transaction_dir}/recovery
  recovery_packaging_root=${packaging_root:-${script_dir}/assets}
  install -d -m 0700 "${recovery_dir}" "${recovery_dir}/assets"
  for recovery_script in install.sh lib.sh preflight.sh rollback.sh uninstall.sh upgrade.sh; do
    recovery_source=${script_dir}/${recovery_script}
    assert_regular_file "${recovery_source}" "installed recovery script"
    [ "$(stat -c '%h' "${recovery_source}")" = 1 ] || die "recovery script is hard-linked"
    [ -z "$(find "${recovery_source}" -maxdepth 0 -perm /0022 -print -quit)" ] || \
      die "recovery script is group/world writable"
    install -m 0555 "${recovery_source}" "${recovery_dir}/${recovery_script}"
    durable_sync "${recovery_dir}/${recovery_script}"
  done
  for recovery_asset in \
    systemd/cdnca-edge-agent.service \
    sysusers/cdnca-edge-agent.conf \
    tmpfiles/cdnca-edge-agent.conf \
    logrotate/cdnca-edge-agent \
    config/agent.env \
    config/config.example.json \
    README.md; do
    recovery_source=${recovery_packaging_root}/${recovery_asset}
    recovery_destination=${recovery_dir}/assets/${recovery_asset}
    assert_regular_file "${recovery_source}" "installed recovery asset"
    [ "$(stat -c '%h' "${recovery_source}")" = 1 ] || die "recovery asset is hard-linked"
    [ -z "$(find "${recovery_source}" -maxdepth 0 -perm /0022 -print -quit)" ] || \
      die "recovery asset is group/world writable"
    install -d -m 0700 "$(dirname -- "${recovery_destination}")"
    install -m 0644 "${recovery_source}" "${recovery_destination}"
    durable_sync "${recovery_destination}"
    durable_sync "$(dirname -- "${recovery_destination}")"
  done
  durable_sync "${recovery_dir}"
}

verify_transaction_recovery() {
  transaction_dir=$1
  recovery_dir=${transaction_dir}/recovery
  if [ -z "${TX_OLD_TARGET}" ]; then
    [ ! -e "${recovery_dir}" ] && [ ! -L "${recovery_dir}" ] || die "unexpected transaction recovery toolset"
    return
  fi
  [ -d "${recovery_dir}" ] && [ ! -L "${recovery_dir}" ] || die "transaction recovery toolset is unavailable"
  [ "$(stat -c '%u:%g:%a' "${recovery_dir}")" = 0:0:700 ] || die "transaction recovery toolset ownership or mode is unsafe"
  unsafe_recovery=$(find "${recovery_dir}" \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit)
  [ -z "${unsafe_recovery}" ] || die "transaction recovery toolset contains an unsafe entry"
  linked_recovery=$(find "${recovery_dir}" -type f -links +1 -print -quit)
  [ -z "${linked_recovery}" ] || die "transaction recovery toolset contains a hard-linked file"
  foreign_recovery=$(find "${recovery_dir}" \( ! -uid 0 -o ! -gid 0 \) -print -quit)
  [ -z "${foreign_recovery}" ] || die "transaction recovery toolset is not owned by root"
  writable_recovery=$(find "${recovery_dir}" -perm /0022 -print -quit)
  [ -z "${writable_recovery}" ] || die "transaction recovery toolset is group/world writable"
  for recovery_script in install.sh lib.sh preflight.sh rollback.sh uninstall.sh upgrade.sh; do
    assert_regular_file "${recovery_dir}/${recovery_script}" "transaction recovery script"
    [ "$(stat -c '%a' "${recovery_dir}/${recovery_script}")" = 555 ] || die "transaction recovery script mode is unsafe"
  done
  for recovery_asset in \
    systemd/cdnca-edge-agent.service \
    sysusers/cdnca-edge-agent.conf \
    tmpfiles/cdnca-edge-agent.conf \
    logrotate/cdnca-edge-agent \
    config/agent.env \
    config/config.example.json \
    README.md; do
    assert_regular_file "${recovery_dir}/assets/${recovery_asset}" "transaction recovery asset"
    [ "$(stat -c '%a' "${recovery_dir}/assets/${recovery_asset}")" = 644 ] || die "transaction recovery asset mode is unsafe"
  done
}

write_package_transaction() {
  transaction_dir=$1
  transaction_journal=${transaction_dir}/journal
  transaction_temporary=${transaction_dir}/.journal.$$
  printf 'transaction_version=2\noperation=%s\nold_target=%s\nnew_version=%s\nstate_backup=%s\nunit_existed=%s\nkey_existed=%s\nlast_upgrade_target=%s\nrelease_was_new=%s\ncurrent_switch_intent=%s\nservice_stop_intent=%s\ncommit_intent=%s\nstate_restore_staging=%s\n' \
    "${TX_OPERATION}" "${TX_OLD_TARGET}" "${TX_NEW_VERSION}" \
    "${TX_STATE_BACKUP}" "${TX_UNIT_EXISTED}" "${TX_KEY_EXISTED}" \
    "${TX_LAST_UPGRADE_TARGET}" "${TX_RELEASE_WAS_NEW}" \
    "${TX_CURRENT_SWITCH_INTENT}" "${TX_SERVICE_STOP_INTENT}" \
    "${TX_COMMIT_INTENT}" "${TX_STATE_RESTORE_STAGING}" >"${transaction_temporary}"
  chmod 0600 "${transaction_temporary}"
  durable_sync "${transaction_temporary}"
  mv -Tf "${transaction_temporary}" "${transaction_journal}"
  durable_sync "${transaction_dir}"
}

load_package_transaction() {
  transaction_dir=$1
  [ -d "${transaction_dir}" ] && [ ! -L "${transaction_dir}" ] || die "package transaction is unsafe"
  [ "$(stat -c '%u:%a' "${transaction_dir}")" = 0:700 ] || die "package transaction ownership or mode is unsafe"
  transaction_journal=${transaction_dir}/journal
  verify_input_file "${transaction_journal}" "package transaction journal" 16384
  [ "$(stat -c '%u:%a' "${transaction_journal}")" = 0:600 ] || die "package transaction journal ownership or mode is unsafe"
  transaction_version=$(manifest_value "${transaction_journal}" 1 transaction_version)
  case "${transaction_version}" in
    2) transaction_lines=13 ;;
    1) die "legacy v1 transaction lacks a complete metadata snapshot; journal retained for manual recovery" ;;
    *) die "package transaction version is unsupported" ;;
  esac
  [ "$(wc -l <"${transaction_journal}" | tr -d ' ')" = "${transaction_lines}" ] || die "package transaction journal is not canonical"
  TX_OPERATION=$(manifest_value "${transaction_journal}" 2 operation)
  TX_OLD_TARGET=$(manifest_value "${transaction_journal}" 3 old_target)
  TX_NEW_VERSION=$(manifest_value "${transaction_journal}" 4 new_version)
  TX_STATE_BACKUP=$(manifest_value "${transaction_journal}" 5 state_backup)
  TX_UNIT_EXISTED=$(manifest_value "${transaction_journal}" 6 unit_existed)
  TX_KEY_EXISTED=$(manifest_value "${transaction_journal}" 7 key_existed)
  TX_LAST_UPGRADE_TARGET=$(manifest_value "${transaction_journal}" 8 last_upgrade_target)
  TX_RELEASE_WAS_NEW=$(manifest_value "${transaction_journal}" 9 release_was_new)
  TX_CURRENT_SWITCH_INTENT=$(manifest_value "${transaction_journal}" 10 current_switch_intent)
  TX_SERVICE_STOP_INTENT=$(manifest_value "${transaction_journal}" 11 service_stop_intent)
  TX_COMMIT_INTENT=$(manifest_value "${transaction_journal}" 12 commit_intent)
  TX_STATE_RESTORE_STAGING=$(manifest_value "${transaction_journal}" 13 state_restore_staging)

  case "${TX_OPERATION}" in install|upgrade|rollback) ;; *) die "package transaction operation is invalid" ;; esac
  validate_version "${TX_NEW_VERSION}"
  if [ -n "${TX_OLD_TARGET}" ]; then
    case "${TX_OLD_TARGET}" in versions/*) ;; *) die "package transaction old target is unsafe" ;; esac
    old_transaction_version=${TX_OLD_TARGET#versions/}
    validate_version "${old_transaction_version}"
    [ "${TX_OLD_TARGET}" = "versions/${old_transaction_version}" ] || die "package transaction old target is unsafe"
  fi
  if [ -n "${TX_STATE_BACKUP}" ]; then
    transaction_backup_root=$(root_path /var/lib/cdnca-edge-agent-backups)
    case "${TX_STATE_BACKUP}" in "${transaction_backup_root}"/*) ;; *) die "package transaction state backup is unsafe" ;; esac
  fi
  if [ -n "${TX_STATE_RESTORE_STAGING}" ]; then
    validate_restore_staging_path "${TX_STATE_RESTORE_STAGING}"
  fi
  case "${TX_LAST_UPGRADE_TARGET}" in ''|*/*|.|..) [ -z "${TX_LAST_UPGRADE_TARGET}" ] || die "package transaction recovery target is unsafe" ;; esac
  for transaction_flag in \
    "${TX_UNIT_EXISTED}" "${TX_KEY_EXISTED}" "${TX_RELEASE_WAS_NEW}" \
    "${TX_CURRENT_SWITCH_INTENT}" "${TX_SERVICE_STOP_INTENT}" "${TX_COMMIT_INTENT}"; do
    case "${transaction_flag}" in 0|1) ;; *) die "package transaction flag is invalid" ;; esac
  done
  verify_input_file "${transaction_dir}/new-manifest" "transaction manifest" 16384
  [ "$(stat -c '%u:%a' "${transaction_dir}/new-manifest")" = 0:600 ] || die "transaction manifest ownership or mode is unsafe"
  if [ "${TX_UNIT_EXISTED}" = 1 ]; then
    verify_input_file "${transaction_dir}/systemd-unit" "transaction systemd unit" 1048576
    [ "$(stat -c '%u:%a' "${transaction_dir}/systemd-unit")" = 0:600 ] || die "transaction systemd unit ownership or mode is unsafe"
  else
    [ ! -e "${transaction_dir}/systemd-unit" ] && [ ! -L "${transaction_dir}/systemd-unit" ] || die "unexpected transaction systemd unit snapshot"
  fi
  verify_transaction_metadata "${transaction_dir}"
  verify_transaction_recovery "${transaction_dir}"
}

begin_package_transaction() {
  operation=$1
  previous_target=$2
  next_version=$3
  transaction_parent=$(dirname -- "${PACKAGE_TRANSACTION}")
  transaction_staging=${transaction_parent}/.transaction.$$
  PACKAGE_TRANSACTION_STAGING=${transaction_staging}
  [ ! -e "${PACKAGE_TRANSACTION}" ] && [ ! -L "${PACKAGE_TRANSACTION}" ] || die "an incomplete package transaction was not recovered"
  [ ! -e "${transaction_staging}" ] && [ ! -L "${transaction_staging}" ] || die "package transaction staging path exists"
  install -d -m 0700 "${transaction_staging}"

  TX_OPERATION=${operation}
  TX_OLD_TARGET=${previous_target}
  TX_NEW_VERSION=${next_version}
  TX_STATE_BACKUP=
  TX_RELEASE_WAS_NEW=0
  TX_CURRENT_SWITCH_INTENT=0
  TX_SERVICE_STOP_INTENT=0
  TX_COMMIT_INTENT=0
  TX_STATE_RESTORE_STAGING=
  installed_unit=$(root_path /usr/lib/systemd/system/cdnca-edge-agent.service)
  if [ -e "${installed_unit}" ] || [ -L "${installed_unit}" ]; then
    assert_regular_file "${installed_unit}" "installed systemd unit"
    [ "$(stat -c '%u:%g:%a:%h' "${installed_unit}")" = 0:0:644:1 ] || \
      die "installed systemd unit ownership, mode, or link count is unsafe"
    install -m 0600 "${installed_unit}" "${transaction_staging}/systemd-unit"
    durable_sync "${transaction_staging}/systemd-unit"
    TX_UNIT_EXISTED=1
  else
    TX_UNIT_EXISTED=0
  fi
  snapshot_transaction_metadata "${transaction_staging}"
  snapshot_transaction_recovery "${transaction_staging}"
  pinned_key=$(root_path /etc/cdnca-edge-agent/package-signing.pem)
  if [ -e "${pinned_key}" ] || [ -L "${pinned_key}" ]; then
    assert_regular_file "${pinned_key}" "pinned package public key"
    TX_KEY_EXISTED=1
  else
    TX_KEY_EXISTED=0
  fi
  last_upgrade_link=$(root_path /var/lib/cdnca-edge-agent-backups/last-upgrade)
  if [ -L "${last_upgrade_link}" ]; then
    TX_LAST_UPGRADE_TARGET=$(readlink "${last_upgrade_link}") || die "cannot read last-upgrade recovery point"
    case "${TX_LAST_UPGRADE_TARGET}" in */*|.|..) die "last-upgrade recovery point is unsafe" ;; esac
  elif [ -e "${last_upgrade_link}" ]; then
    die "last-upgrade recovery point is not a symbolic link"
  else
    TX_LAST_UPGRADE_TARGET=
  fi
  install -m 0600 "${VERIFIED_MANIFEST}" "${transaction_staging}/new-manifest"
  durable_sync "${transaction_staging}/new-manifest"
  write_package_transaction "${transaction_staging}"
  durable_sync "${transaction_parent}"
  failpoint_sigkill transaction-before-publish
  mv "${transaction_staging}" "${PACKAGE_TRANSACTION}"
  PACKAGE_TRANSACTION_STAGING=
  durable_sync "${transaction_parent}"
}

persist_package_transaction() {
  [ -d "${PACKAGE_TRANSACTION}" ] && [ ! -L "${PACKAGE_TRANSACTION}" ] || die "package transaction is unavailable"
  write_package_transaction "${PACKAGE_TRANSACTION}"
}

record_transaction_release() {
  case "$1" in true) TX_RELEASE_WAS_NEW=1 ;; false) TX_RELEASE_WAS_NEW=0 ;; *) die "invalid release transaction state" ;; esac
  persist_package_transaction
}

record_transaction_state_backup() {
  TX_STATE_BACKUP=$1
  persist_package_transaction
}

record_transaction_service_stop() {
  TX_SERVICE_STOP_INTENT=1
  persist_package_transaction
}

record_transaction_current_switch() {
  TX_CURRENT_SWITCH_INTENT=1
  persist_package_transaction
}

record_transaction_commit() {
  TX_COMMIT_INTENT=1
  persist_package_transaction
}

record_transaction_restore_staging() {
  TX_STATE_RESTORE_STAGING=$1
  persist_package_transaction
}

restore_transaction_unit() {
  transaction_dir=$1
  installed_unit=$(root_path /usr/lib/systemd/system/cdnca-edge-agent.service)
  unit_parent=$(dirname -- "${installed_unit}")
  assert_safe_tree "${unit_parent}"
  install -d -m 0755 "${unit_parent}"
  [ ! -L "${installed_unit}" ] || die "installed systemd unit became a symbolic link"
  if [ "${TX_UNIT_EXISTED}" = 1 ]; then
    unit_temporary=${unit_parent}/.cdnca-edge-agent.service.restore.$$
    install -m 0644 "${transaction_dir}/systemd-unit" "${unit_temporary}"
    durable_sync "${unit_temporary}"
    durable_sync "${unit_parent}"
    mv -Tf "${unit_temporary}" "${installed_unit}"
  else
    rm -f -- "${installed_unit}"
  fi
  durable_sync "${unit_parent}"
}

restore_transaction_metadata() {
  transaction_dir=$1
  [ -d "${transaction_dir}/metadata" ] || return 0
  for metadata_entry in ${PACKAGE_METADATA_ENTRIES}; do
    metadata_id=${metadata_entry%%:*}
    metadata_detail=${metadata_entry#*:}
    metadata_path=${metadata_detail%:*}
    metadata_mode=${metadata_entry##*:}
    snapshot=${transaction_dir}/metadata/${metadata_id}
    destination=$(root_path "${metadata_path}")
    destination_parent=$(dirname -- "${destination}")
    assert_safe_tree "${destination_parent}"
    if [ ! -d "${destination_parent}" ]; then
      install -d -m 0755 "${destination_parent}"
    fi
    [ ! -L "${destination}" ] || die "package metadata became a symbolic link during recovery"
    if [ -f "${snapshot}" ] && [ ! -L "${snapshot}" ]; then
      temporary=${destination_parent}/.${metadata_id}.restore.$$
      install -m "${metadata_mode}" "${snapshot}" "${temporary}"
      durable_sync "${temporary}"
      mv -Tf "${temporary}" "${destination}"
    else
      rm -f -- "${destination}"
    fi
    durable_sync "${destination_parent}"
  done
}

restore_transaction_current() {
  [ "${TX_CURRENT_SWITCH_INTENT}" = 1 ] || return 0
  if [ -n "${TX_OLD_TARGET}" ]; then
    atomic_switch_current "${TX_OLD_TARGET}"
  else
    current=$(root_path /usr/lib/cdnca-edge-agent/current)
    if [ -L "${current}" ]; then
      [ "$(readlink "${current}")" = "versions/${TX_NEW_VERSION}" ] || die "current release changed during transaction recovery"
      rm -f -- "${current}"
      durable_sync "$(dirname -- "${current}")"
    elif [ -e "${current}" ]; then
      die "current release path is unsafe during transaction recovery"
    fi
  fi
}

restore_transaction_last_upgrade() {
  backup_root=$(root_path /var/lib/cdnca-edge-agent-backups)
  link=${backup_root}/last-upgrade
  if [ -n "${TX_LAST_UPGRADE_TARGET}" ]; then
    [ -d "${backup_root}/${TX_LAST_UPGRADE_TARGET}" ] && [ ! -L "${backup_root}/${TX_LAST_UPGRADE_TARGET}" ] || die "previous last-upgrade backup is unavailable"
    temporary=${backup_root}/.last-upgrade-transaction-restore.$$
    ln -s "${TX_LAST_UPGRADE_TARGET}" "${temporary}"
    durable_sync "${backup_root}"
    mv -Tf "${temporary}" "${link}"
    durable_sync "${backup_root}"
  elif [ -d "${backup_root}" ]; then
    [ ! -e "${link}" ] || [ -L "${link}" ] || die "last-upgrade path became unsafe"
    rm -f -- "${link}"
    durable_sync "${backup_root}"
  fi
}

remove_transaction_release() {
  [ "${TX_RELEASE_WAS_NEW}" = 1 ] || return 0
  release=$(root_path "/usr/lib/cdnca-edge-agent/versions/${TX_NEW_VERSION}")
  versions_root=$(dirname -- "${release}")
  case "${release}" in */usr/lib/cdnca-edge-agent/versions/*) ;; *) die "unsafe transaction release cleanup path" ;; esac
  if [ -e "${release}" ] || [ -L "${release}" ]; then
    [ -d "${release}" ] && [ ! -L "${release}" ] || die "transaction release path became unsafe"
    rm -rf -- "${release}"
    durable_sync "${versions_root}"
  fi
}

package_transaction_committed() {
  [ "${TX_COMMIT_INTENT}" = 1 ] || return 1
  current=$(root_path /usr/lib/cdnca-edge-agent/current)
  [ -L "${current}" ] || return 1
  if [ "${TX_OPERATION}" = rollback ]; then
    [ "$(readlink "${current}")" = "versions/${TX_NEW_VERSION}" ]
    return
  fi
  accepted=$(root_path /var/lib/cdnca-edge-agent-packaging/accepted-manifest)
  [ -f "${accepted}" ] && [ ! -L "${accepted}" ] || return 1
  cmp -s "${PACKAGE_TRANSACTION}/new-manifest" "${accepted}" || return 1
  [ "$(readlink "${current}")" = "versions/${TX_NEW_VERSION}" ]
}

rollback_package_transaction() {
  load_package_transaction "${PACKAGE_TRANSACTION}"
  cleanup_transaction_restore_staging
  restore_transaction_unit "${PACKAGE_TRANSACTION}"
  restore_transaction_metadata "${PACKAGE_TRANSACTION}"
  restore_transaction_current
  if [ "${TX_CURRENT_SWITCH_INTENT}" = 1 ] && [ -n "${TX_STATE_BACKUP}" ]; then
    restore_state "${TX_STATE_BACKUP}" "recovered-${TX_NEW_VERSION}"
  fi
  restore_transaction_last_upgrade
  if [ "${TX_KEY_EXISTED}" = 0 ]; then
    pinned_key=$(root_path /etc/cdnca-edge-agent/package-signing.pem)
    [ ! -L "${pinned_key}" ] || die "pinned package public key became unsafe"
    rm -f -- "${pinned_key}"
    [ ! -d "$(dirname -- "${pinned_key}")" ] || durable_sync "$(dirname -- "${pinned_key}")"
  fi
  remove_transaction_release
  service_action daemon-reload
  if [ "${TX_SERVICE_STOP_INTENT}" = 1 ] && [ -n "${TX_OLD_TARGET}" ] && \
    ! state_layout_migration_pending; then
    service_action restart
  fi
}

clear_package_transaction() {
  [ -n "${PACKAGE_TRANSACTION:-}" ] || return 0
  transaction_parent=$(dirname -- "${PACKAGE_TRANSACTION}")
  case "${PACKAGE_TRANSACTION}" in */var/lib/cdnca-edge-agent-packaging/transaction) ;; *) die "unsafe package transaction cleanup path" ;; esac
  if [ -e "${PACKAGE_TRANSACTION}" ] || [ -L "${PACKAGE_TRANSACTION}" ]; then
    [ -d "${PACKAGE_TRANSACTION}" ] && [ ! -L "${PACKAGE_TRANSACTION}" ] || die "package transaction became unsafe"
    rm -rf -- "${PACKAGE_TRANSACTION}"
    durable_sync "${transaction_parent}"
  fi
}

recover_incomplete_package_transaction() {
  [ -e "${PACKAGE_TRANSACTION}" ] || [ -L "${PACKAGE_TRANSACTION}" ] || return 0
  load_package_transaction "${PACKAGE_TRANSACTION}"
  if ! package_transaction_committed; then
    rollback_package_transaction
  fi
  clear_package_transaction
}

cleanup_transaction_staging() {
  [ -n "${PACKAGE_TRANSACTION_STAGING:-}" ] || return 0
  transaction_parent=$(dirname -- "${PACKAGE_TRANSACTION}")
  case "${PACKAGE_TRANSACTION_STAGING}" in "${transaction_parent}"/.transaction.*) ;; *) die "unsafe transaction staging cleanup path" ;; esac
  if [ -e "${PACKAGE_TRANSACTION_STAGING}" ] || [ -L "${PACKAGE_TRANSACTION_STAGING}" ]; then
    [ -d "${PACKAGE_TRANSACTION_STAGING}" ] && [ ! -L "${PACKAGE_TRANSACTION_STAGING}" ] || die "transaction staging path became unsafe"
    rm -rf -- "${PACKAGE_TRANSACTION_STAGING}"
  fi
  PACKAGE_TRANSACTION_STAGING=
}

cleanup_transaction_staging_for_pid() {
  transaction_pid=$1
  validate_uint "${transaction_pid}" "transaction staging pid"
  transaction_parent=$(dirname -- "${PACKAGE_TRANSACTION}")
  transaction_staging=${transaction_parent}/.transaction.${transaction_pid}
  if [ -e "${transaction_staging}" ] || [ -L "${transaction_staging}" ]; then
    [ -d "${transaction_staging}" ] && [ ! -L "${transaction_staging}" ] || \
      die "stale transaction staging became unsafe"
    [ "$(stat -c '%u:%g:%a' "${transaction_staging}")" = 0:0:700 ] || \
      die "stale transaction staging ownership or mode is unsafe"
    rm -rf -- "${transaction_staging}"
    durable_sync "${transaction_parent}"
  fi
}

validate_restore_staging_path() {
  restore_staging=$1
  restore_parent=$(root_path /var/lib/cdnca-edge-agent-backups)
  case "${restore_staging}" in
    "${restore_parent}"/.restore-*) ;;
    *) die "unsafe state restore staging path" ;;
  esac
  restore_pid=${restore_staging#"${restore_parent}"/.restore-}
  case "${restore_pid}" in ''|*[!0-9]*) die "unsafe state restore staging pid" ;; esac
  [ "${restore_staging}" = "${restore_parent}/.restore-${restore_pid}" ] || \
    die "unsafe state restore staging path"
}

cleanup_transaction_restore_staging() {
  [ -n "${TX_STATE_RESTORE_STAGING:-}" ] || return 0
  validate_restore_staging_path "${TX_STATE_RESTORE_STAGING}"
  restore_parent=$(dirname -- "${TX_STATE_RESTORE_STAGING}")
  if [ -e "${TX_STATE_RESTORE_STAGING}" ] || [ -L "${TX_STATE_RESTORE_STAGING}" ]; then
    [ -d "${TX_STATE_RESTORE_STAGING}" ] && [ ! -L "${TX_STATE_RESTORE_STAGING}" ] || \
      die "journal-bound state restore staging became unsafe"
    [ "$(stat -c '%u:%g:%a' "${TX_STATE_RESTORE_STAGING}")" = 0:0:700 ] || \
      die "journal-bound state restore staging ownership or mode is unsafe"
    rm -rf -- "${TX_STATE_RESTORE_STAGING}"
    durable_sync "${restore_parent}"
  fi
  record_transaction_restore_staging ''
}

cleanup_all_restore_staging() {
  restore_parent=$(root_path /var/lib/cdnca-edge-agent-backups)
  [ -d "${restore_parent}" ] || return 0
  first_restore=$(find "${restore_parent}" -mindepth 1 -maxdepth 1 \
    -name '.restore-*' -print -quit)
  [ -n "${first_restore}" ] || return 0
  restore_ids=$(runtime_ids)
  restore_uid=${restore_ids%:*}
  restore_gid=${restore_ids#*:}
  find "${restore_parent}" -mindepth 1 -maxdepth 1 \
    -name '.restore-*' -exec sh -eu -c '
      expected_uid=$1
      expected_gid=$2
      shift 2
      for candidate do
        name=${candidate##*/}
        suffix=${name#.restore-}
        case "${suffix}" in ""|*[!0-9]*) continue ;; esac
        [ "${name}" = ".restore-${suffix}" ] || continue
        [ -d "${candidate}" ] && [ ! -L "${candidate}" ] || exit 1
        [ "$(stat -c "%a" "${candidate}")" = 700 ] || exit 1
        owner=$(stat -c "%u:%g" "${candidate}")
        case "${owner}" in
          0:0) ;;
          "${expected_uid}:${expected_gid}")
            unsafe=$(find "${candidate}" \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit)
            [ -z "${unsafe}" ] || exit 1
            linked=$(find "${candidate}" -type f -links +1 -print -quit)
            [ -z "${linked}" ] || exit 1
            writable=$(find "${candidate}" -perm /0022 -print -quit)
            [ -z "${writable}" ] || exit 1
            foreign=$(find "${candidate}" \( ! -uid "${expected_uid}" -o ! -gid "${expected_gid}" \) -print -quit)
            [ -z "${foreign}" ] || exit 1
            ;;
          *) exit 1 ;;
        esac
        rm -rf -- "${candidate}"
      done
    ' sh "${restore_uid}" "${restore_gid}" {} + || die "unsafe orphaned state restore staging"
  durable_sync "${restore_parent}"
}

acquire_lock() {
  command -v flock >/dev/null 2>&1 || die "flock is required"
  lock_parent=$(root_path /var/lib/cdnca-edge-agent-packaging)
  assert_safe_tree "${lock_parent}"
  install -d -m 0700 "${lock_parent}"
  PACKAGE_LOCK=${lock_parent}/transaction.lock
  PACKAGE_OWNER=${lock_parent}/transaction.owner
  PACKAGE_TRANSACTION=${lock_parent}/transaction

  if [ -d "${PACKAGE_LOCK}" ] && [ ! -L "${PACKAGE_LOCK}" ]; then
    legacy_owner=${PACKAGE_LOCK}/owner
    assert_regular_file "${legacy_owner}" "legacy package lock owner"
    legacy_pid=$(manifest_value "${legacy_owner}" 1 pid)
    validate_uint "${legacy_pid}" "legacy package lock pid"
    [ ! -r "/proc/${legacy_pid}/stat" ] || die "another package operation is active"
    rm -f -- "${legacy_owner}"
    rmdir "${PACKAGE_LOCK}" || die "legacy package lock contains unexpected files"
  elif [ -e "${PACKAGE_LOCK}" ] || [ -L "${PACKAGE_LOCK}" ]; then
    assert_regular_file "${PACKAGE_LOCK}" "package lock"
  fi
  if [ ! -e "${PACKAGE_LOCK}" ]; then
    : >"${PACKAGE_LOCK}"
    chmod 0600 "${PACKAGE_LOCK}"
  fi
  assert_regular_file "${PACKAGE_LOCK}" "package lock"
  [ "$(stat -c '%u:%a:%h' "${PACKAGE_LOCK}")" = 0:600:1 ] || die "package lock ownership, mode, or link count is unsafe"
  exec 9>>"${PACKAGE_LOCK}"
  flock -n 9 || die "another package operation is active"
  PACKAGE_LOCK_HELD=true

  stale_pid=
  if [ -e "${PACKAGE_OWNER}" ] || [ -L "${PACKAGE_OWNER}" ]; then
    verify_input_file "${PACKAGE_OWNER}" "package lock owner" 4096
    [ "$(stat -c '%u:%a' "${PACKAGE_OWNER}")" = 0:600 ] || die "package lock owner ownership or mode is unsafe"
    [ "$(wc -l <"${PACKAGE_OWNER}" | tr -d ' ')" = 2 ] || die "package lock owner is not canonical"
    stale_pid=$(manifest_value "${PACKAGE_OWNER}" 1 pid)
    stale_ticks=$(manifest_value "${PACKAGE_OWNER}" 2 start_ticks)
    validate_uint "${stale_pid}" "stale package owner pid"
    validate_uint "${stale_ticks}" "stale package owner start ticks"
  fi
  owner_temporary=${lock_parent}/.transaction.owner.$$
  printf 'pid=%s\nstart_ticks=%s\n' "$$" "$(process_start_ticks "$$")" >"${owner_temporary}"
  chmod 0600 "${owner_temporary}"
  durable_sync "${owner_temporary}"
  mv -Tf "${owner_temporary}" "${PACKAGE_OWNER}"
  durable_sync "${lock_parent}"

  if ! (recover_incomplete_package_transaction); then
    rm -f -- "${PACKAGE_OWNER}"
    flock -u 9
    exec 9>&-
    PACKAGE_LOCK_HELD=false
    die "incomplete package transaction recovery failed"
  fi
  if ! (recover_incomplete_state_layout_migration); then
    rm -f -- "${PACKAGE_OWNER}"
    flock -u 9
    exec 9>&-
    PACKAGE_LOCK_HELD=false
    die "incomplete state layout migration recovery failed"
  fi
  cleanup_all_restore_staging
  if [ -n "${stale_pid}" ]; then
    cleanup_transaction_staging_for_pid "${stale_pid}"
    cleanup_metadata_install_staging "${stale_pid}"
    cleanup_bundle_staging "$(root_path "/usr/lib/cdnca-edge-agent/.input-bundle-${stale_pid}")"
    cleanup_state_layout_migration_staging "${stale_pid}"
  fi
}

release_lock() {
  [ "${PACKAGE_LOCK_HELD:-false}" = true ] || return 0
  [ ! -e "${PACKAGE_TRANSACTION}" ] && [ ! -L "${PACKAGE_TRANSACTION}" ] || die "cannot release lock with an incomplete package transaction"
  cleanup_transaction_staging
  cleanup_metadata_install_staging "$$"
  cleanup_bundle_staging
  rm -f -- "${PACKAGE_OWNER}"
  durable_sync "$(dirname -- "${PACKAGE_LOCK}")"
  if [ "${REMOVE_PACKAGE_LOCK:-false}" = true ]; then
    rm -f -- "${PACKAGE_LOCK}"
    durable_sync "$(dirname -- "${PACKAGE_LOCK}")"
  fi
  flock -u 9
  exec 9>&-
  PACKAGE_LOCK_HELD=false
}

service_action() {
  action=$1
  if [ -n "${SERVICE_DRIVER:-}" ]; then
    "${SERVICE_DRIVER}" "${action}"
    return
  fi
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
  case "${action}" in
    daemon-reload) systemctl daemon-reload ;;
    restart|stop|disable|enable) systemctl "${action}" cdnca-edge-agent.service ;;
    is-active) systemctl is-active --quiet cdnca-edge-agent.service ;;
    *) die "unsupported service action: ${action}" ;;
  esac
}

# The Agent unit uses KillMode=process so Agent restarts and upgrades keep
# the OpenResty masters it started (L4 sessions stay up; the next Agent adopts
# them). After the unit is stopped for good everything left in its cgroup was
# started by the Agent; stop it so uninstall leaves no runtime behind.
stop_agent_leftovers() {
  [ -z "${SERVICE_DRIVER:-}" ] && [ -z "${DESTDIR}" ] || return 0
  for leftover_procs in \
    /sys/fs/cgroup/system.slice/cdnca-edge-agent.service/cgroup.procs \
    /sys/fs/cgroup/systemd/system.slice/cdnca-edge-agent.service/cgroup.procs; do
    [ -f "${leftover_procs}" ] || continue
    stop_cgroup_leftovers "${leftover_procs}" 10 || return 1
  done
}

# stop_cgroup_leftovers PROCS_FILE TIMEOUT_SECONDS: TERM every listed process
# (nginx fast shutdown), wait, then KILL whatever is still listed.
stop_cgroup_leftovers() {
  leftover_file=$1
  leftover_timeout=$2
  leftover_pids=$(cat -- "${leftover_file}" 2>/dev/null || true)
  [ -n "${leftover_pids}" ] || return 0
  for leftover_pid in ${leftover_pids}; do
    kill -TERM "${leftover_pid}" 2>/dev/null || true
  done
  leftover_waited=0
  while [ "${leftover_waited}" -lt "${leftover_timeout}" ]; do
    leftover_alive=
    for leftover_pid in $(cat -- "${leftover_file}" 2>/dev/null || true); do
      if kill -0 "${leftover_pid}" 2>/dev/null; then
        leftover_alive=${leftover_pid}
        break
      fi
    done
    [ -n "${leftover_alive}" ] || return 0
    sleep 1
    leftover_waited=$((leftover_waited + 1))
  done
  for leftover_pid in $(cat -- "${leftover_file}" 2>/dev/null || true); do
    kill -KILL "${leftover_pid}" 2>/dev/null || true
  done
  sleep 1
  for leftover_pid in $(cat -- "${leftover_file}" 2>/dev/null || true); do
    if kill -0 "${leftover_pid}" 2>/dev/null; then
      return 1
    fi
  done
  return 0
}

wait_for_health() {
  timeout=$1
  stable=$2
  started=$(date +%s)
  active_since=
  while :; do
    now=$(date +%s)
    if service_action is-active >/dev/null 2>&1; then
      [ -n "${active_since}" ] || active_since=${now}
      [ $((now - active_since)) -ge "${stable}" ] && return 0
    else
      active_since=
    fi
    [ $((now - started)) -lt "${timeout}" ] || return 1
    sleep 1
  done
}

validate_state_tree() {
  state_tree=$1
  state_label=$2
  [ -d "${state_tree}" ] && [ ! -L "${state_tree}" ] || die "${state_label} must be a non-symlink directory"
  state_device=$(stat -c '%d' "${state_tree}")
  foreign_state_device=$(find "${state_tree}" -printf '%D %p\n' | awk -v expected="${state_device}" '$1 != expected { sub(/^[^ ]+ /, ""); print; exit }')
  [ -z "${foreign_state_device}" ] || die "${state_label} crosses a filesystem boundary"
  unsafe_state_path=$(find "${state_tree}" \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit)
  [ -z "${unsafe_state_path}" ] || die "${state_label} contains a symbolic link or special file"
  linked_state_path=$(find "${state_tree}" -type f -links +1 -print -quit)
  [ -z "${linked_state_path}" ] || die "${state_label} contains a hard-linked file"
  writable_state_path=$(find "${state_tree}" -perm /0022 -print -quit)
  [ -z "${writable_state_path}" ] || die "${state_label} contains group/world-writable state"
  privileged_state_path=$(find "${state_tree}" -perm /7000 -print -quit)
  [ -z "${privileged_state_path}" ] || die "${state_label} contains setuid, setgid, or sticky state"
  state_ids=$(runtime_ids)
  state_uid=${state_ids%:*}
  state_gid=${state_ids#*:}
  if [ "${state_uid}" -eq 0 ]; then
    # A root Agent may legitimately leave entries owned by the OpenResty
    # worker it manages (nginx chowns temporary paths). Ownership grants no
    # authority over a root producer; only the tree root must be root-owned.
    [ "$(stat -c '%u:%g' "${state_tree}")" = 0:0 ] || die "${state_label} root must be owned by root"
  else
    foreign_state_path=$(find "${state_tree}" \( ! -uid "${state_uid}" -o ! -gid "${state_gid}" \) -print -quit)
    [ -z "${foreign_state_path}" ] || die "${state_label} contains state not owned by cdnca-edge"
  fi
  [ "$(stat -c '%a' "${state_tree}")" = 700 ] || die "${state_label} root mode must be 0700"
}

state_tree_sha256() {
  digest_root=$1
  validate_state_tree "${digest_root}" "state digest source"
  perl -Mstrict -Mwarnings -MFile::Find -MDigest::SHA -e '
    my $root = shift;
    my @paths;
    find({ no_chdir => 1, wanted => sub {
      my $path = $File::Find::name;
      return if $path eq $root;
      my $relative = substr($path, length($root) + 1);
      push @paths, $relative;
    }}, $root);
    my $hash = Digest::SHA->new(256);
    for my $relative (sort { $a cmp $b } @paths) {
      my $path = "$root/$relative";
      my @stat = lstat($path);
      die "cannot stat state tree\n" unless @stat;
      my $kind = -d _ ? "d" : -f _ ? "f" : die "unsafe state tree entry\n";
      for my $field ($relative, $kind, sprintf("%o", $stat[2] & 07777),
          $stat[4], $stat[5], $stat[7]) {
        $field = "$field";
        $hash->add(pack("N", length($field)), $field);
      }
      next if $kind eq "d";
      open my $file, "<:raw", $path or die "cannot open state file\n";
      my $buffer;
      while (read($file, $buffer, 65536)) { $hash->add($buffer); }
      close $file or die "cannot close state file\n";
    }
    print $hash->hexdigest, "\n";
  ' "${digest_root}" || die "cannot hash state tree"
}

state_layout_paths() {
  STATE_LAYOUT_LEGACY=$(root_path /var/lib/cdnca-edge-agent)
  STATE_LAYOUT_ROOT=$(root_path /var/lib/cdnca-edge-agent-backups)
  STATE_LAYOUT_ACTIVE=${STATE_LAYOUT_ROOT}/active-state
  STATE_LAYOUT_MIGRATION=$(root_path /var/lib/cdnca-edge-agent-packaging/layout-migration)
}

state_layout_migration_pending() {
  state_layout_paths
  [ -e "${STATE_LAYOUT_MIGRATION}" ] || [ -L "${STATE_LAYOUT_MIGRATION}" ]
}

validate_empty_state_mountpoint() {
  state_layout_paths
  [ -d "${STATE_LAYOUT_LEGACY}" ] && [ ! -L "${STATE_LAYOUT_LEGACY}" ] || \
    die "state bind mountpoint must be a non-symlink directory"
  [ "$(stat -c '%u:%g:%a' "${STATE_LAYOUT_LEGACY}")" = 0:0:700 ] || \
    die "state bind mountpoint ownership or mode is unsafe"
  [ -z "$(find "${STATE_LAYOUT_LEGACY}" -mindepth 1 -print -quit)" ] || \
    die "state bind mountpoint contains retained state"
}

cleanup_empty_state_mountpoint() {
  state_layout_paths
  [ -d "${STATE_LAYOUT_LEGACY}" ] && [ ! -L "${STATE_LAYOUT_LEGACY}" ] || \
    die "state bind mountpoint must be a non-symlink directory"
  mount_ids=$(runtime_ids)
  mountpoint_policy=$(stat -c '%u:%g:%a' "${STATE_LAYOUT_LEGACY}")
  case "${mountpoint_policy}" in
    0:0:700|"${mount_ids%:*}:${mount_ids#*:}:700") ;;
    *) die "state bind mountpoint ownership or mode is unsafe" ;;
  esac
  for mount_child in gateway-journal deployments; do
    candidate=${STATE_LAYOUT_LEGACY}/${mount_child}
    if [ -e "${candidate}" ] || [ -L "${candidate}" ]; then
      [ -d "${candidate}" ] && [ ! -L "${candidate}" ] || die "state bind mountpoint contains an unsafe entry"
      [ "$(stat -c '%u:%g:%a' "${candidate}")" = "${mount_ids%:*}:${mount_ids#*:}:700" ] || \
        die "state bind mountpoint child policy is unsafe"
      [ -z "$(find "${candidate}" -mindepth 1 -print -quit)" ] || \
        die "state bind mountpoint contains retained state"
      rmdir "${candidate}" || die "cannot clean state bind mountpoint"
    fi
  done
  [ -z "$(find "${STATE_LAYOUT_LEGACY}" -mindepth 1 -print -quit)" ] || \
    die "state bind mountpoint contains retained state"
  chown 0:0 "${STATE_LAYOUT_LEGACY}"
  chmod 0700 "${STATE_LAYOUT_LEGACY}"
  durable_sync "$(dirname -- "${STATE_LAYOUT_LEGACY}")"
  validate_empty_state_mountpoint
}

create_state_mountpoint() {
  state_layout_paths
  [ ! -e "${STATE_LAYOUT_LEGACY}" ] && [ ! -L "${STATE_LAYOUT_LEGACY}" ] || \
    die "state bind mountpoint already exists"
  install -d -m 0700 "${STATE_LAYOUT_LEGACY}"
  chown 0:0 "${STATE_LAYOUT_LEGACY}"
  durable_sync "$(dirname -- "${STATE_LAYOUT_LEGACY}")"
  cleanup_empty_state_mountpoint
}

validate_completed_state_layout() {
  state_layout_paths
  assert_safe_tree "${STATE_LAYOUT_ROOT}"
  [ -d "${STATE_LAYOUT_ROOT}" ] && [ ! -L "${STATE_LAYOUT_ROOT}" ] || die "state mount root is unavailable"
  [ "$(stat -c '%u:%g:%a' "${STATE_LAYOUT_ROOT}")" = 0:0:700 ] || \
    die "state mount root ownership or mode is unsafe"
  validate_state_tree "${STATE_LAYOUT_ACTIVE}" "canonical active state"
  validate_empty_state_mountpoint
}

establish_completed_state_layout() {
  state_layout_paths
  assert_safe_tree "${STATE_LAYOUT_ROOT}"
  install -d -m 0700 "${STATE_LAYOUT_ROOT}"
  [ "$(stat -c '%u:%g:%a' "${STATE_LAYOUT_ROOT}")" = 0:0:700 ] || \
    die "state mount root ownership or mode is unsafe"
  if [ -e "${STATE_LAYOUT_ACTIVE}" ] || [ -L "${STATE_LAYOUT_ACTIVE}" ]; then
    validate_completed_state_layout
    return
  fi
  validate_state_tree "${STATE_LAYOUT_LEGACY}" "fresh agent state"
  mv "${STATE_LAYOUT_LEGACY}" "${STATE_LAYOUT_ACTIVE}" || die "cannot establish canonical active state"
  durable_sync "$(dirname -- "${STATE_LAYOUT_LEGACY}")"
  durable_sync "${STATE_LAYOUT_ROOT}"
  create_state_mountpoint
  validate_completed_state_layout
}

state_layout_needs_migration() {
  state_layout_paths
  if [ -e "${STATE_LAYOUT_ACTIVE}" ] || [ -L "${STATE_LAYOUT_ACTIVE}" ]; then
    validate_completed_state_layout
    return 1
  fi
  validate_state_tree "${STATE_LAYOUT_LEGACY}" "legacy agent state"
  return 0
}

write_state_layout_migration() {
  migration_dir=$1
  migration_journal=${migration_dir}/journal
  migration_temporary=${migration_dir}/.journal.$$
  printf 'migration_version=1\nphase=%s\nlegacy_device=%s\nlegacy_inode=%s\nlegacy_tree_sha256=%s\nold_unit_sha256=%s\nnew_unit_sha256=%s\nlegacy_mode_uid_gid=%s\n' \
    "${LM_PHASE}" "${LM_LEGACY_DEVICE}" "${LM_LEGACY_INODE}" \
    "${LM_LEGACY_TREE_SHA256}" "${LM_OLD_UNIT_SHA256}" \
    "${LM_NEW_UNIT_SHA256}" "${LM_LEGACY_MODE_UID_GID}" >"${migration_temporary}"
  chmod 0600 "${migration_temporary}"
  durable_sync "${migration_temporary}"
  mv -Tf "${migration_temporary}" "${migration_journal}"
  durable_sync "${migration_dir}"
}

load_state_layout_migration() {
  migration_dir=$1
  [ -d "${migration_dir}" ] && [ ! -L "${migration_dir}" ] || die "state layout migration is unsafe"
  [ "$(stat -c '%u:%g:%a' "${migration_dir}")" = 0:0:700 ] || \
    die "state layout migration ownership or mode is unsafe"
  migration_journal=${migration_dir}/journal
  verify_input_file "${migration_journal}" "state layout migration journal" 16384
  [ "$(stat -c '%u:%g:%a:%h' "${migration_journal}")" = 0:0:600:1 ] || \
    die "state layout migration journal policy is unsafe"
  [ "$(wc -l <"${migration_journal}" | tr -d ' ')" = 8 ] || die "state layout migration journal is not canonical"
  [ "$(manifest_value "${migration_journal}" 1 migration_version)" = 1 ] || \
    die "state layout migration version is unsupported"
  LM_PHASE=$(manifest_value "${migration_journal}" 2 phase)
  LM_LEGACY_DEVICE=$(manifest_value "${migration_journal}" 3 legacy_device)
  LM_LEGACY_INODE=$(manifest_value "${migration_journal}" 4 legacy_inode)
  LM_LEGACY_TREE_SHA256=$(manifest_value "${migration_journal}" 5 legacy_tree_sha256)
  LM_OLD_UNIT_SHA256=$(manifest_value "${migration_journal}" 6 old_unit_sha256)
  LM_NEW_UNIT_SHA256=$(manifest_value "${migration_journal}" 7 new_unit_sha256)
  LM_LEGACY_MODE_UID_GID=$(manifest_value "${migration_journal}" 8 legacy_mode_uid_gid)
  case "${LM_PHASE}" in prepared|unit_installed|state_move_intent|activated|revert_intent) ;; *) die "state layout migration phase is invalid" ;; esac
  validate_uint "${LM_LEGACY_DEVICE}" "legacy state device"
  validate_uint "${LM_LEGACY_INODE}" "legacy state inode"
  [ "${LM_LEGACY_INODE}" -gt 0 ] || die "legacy state inode is invalid"
  validate_sha256 "${LM_LEGACY_TREE_SHA256}" "legacy state tree"
  validate_sha256 "${LM_OLD_UNIT_SHA256}" "old systemd unit"
  validate_sha256 "${LM_NEW_UNIT_SHA256}" "new systemd unit"
  lm_mode=${LM_LEGACY_MODE_UID_GID%%:*}
  lm_ids=${LM_LEGACY_MODE_UID_GID#*:}
  [ "${lm_ids}" != "${LM_LEGACY_MODE_UID_GID}" ] || die "legacy state ownership facts are invalid"
  lm_uid=${lm_ids%%:*}
  lm_gid=${lm_ids#*:}
  [ "${lm_gid}" != "${lm_ids}" ] || die "legacy state ownership facts are invalid"
  [ "${lm_mode}" = 700 ] || die "legacy state mode fact is invalid"
  validate_uint "${lm_uid}" "legacy state uid"
  validate_uint "${lm_gid}" "legacy state gid"
  [ "${LM_LEGACY_MODE_UID_GID}" = "700:${lm_uid}:${lm_gid}" ] || die "legacy state ownership facts are not canonical"
  migration_old_unit=${migration_dir}/old-unit
  verify_input_file "${migration_old_unit}" "old systemd unit snapshot" 1048576
  [ "$(stat -c '%u:%g:%a:%h' "${migration_old_unit}")" = 0:0:600:1 ] || \
    die "old systemd unit snapshot policy is unsafe"
  [ "$(sha256_file "${migration_old_unit}")" = "${LM_OLD_UNIT_SHA256}" ] || \
    die "old systemd unit snapshot digest differs"
}

begin_state_layout_migration() {
  old_unit=$1
  new_unit=$2
  state_layout_paths
  [ ! -e "${STATE_LAYOUT_MIGRATION}" ] && [ ! -L "${STATE_LAYOUT_MIGRATION}" ] || \
    die "state layout migration already exists"
  validate_state_tree "${STATE_LAYOUT_LEGACY}" "legacy agent state"
  [ ! -e "${STATE_LAYOUT_ACTIVE}" ] && [ ! -L "${STATE_LAYOUT_ACTIVE}" ] || \
    die "canonical active state already exists"
  assert_safe_tree "${STATE_LAYOUT_ROOT}"
  install -d -m 0700 "${STATE_LAYOUT_ROOT}"
  [ "$(stat -c '%u:%g:%a' "${STATE_LAYOUT_ROOT}")" = 0:0:700 ] || \
    die "state mount root ownership or mode is unsafe"
  verify_input_file "${old_unit}" "old systemd unit snapshot" 1048576
  verify_input_file "${new_unit}" "new systemd unit" 1048576
  grep -Fx 'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind' \
    "${new_unit}" >/dev/null || die "new systemd unit lacks the fixed state bind"
  if grep -F 'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:' "${old_unit}" >/dev/null; then
    die "bind-aware unit cannot be paired with legacy state"
  fi
  migration_parent=$(dirname -- "${STATE_LAYOUT_MIGRATION}")
  migration_staging=${migration_parent}/.layout-migration.$$
  [ ! -e "${migration_staging}" ] && [ ! -L "${migration_staging}" ] || \
    die "state layout migration staging exists"
  install -d -m 0700 "${migration_staging}"
  install -m 0600 "${old_unit}" "${migration_staging}/old-unit"
  durable_sync "${migration_staging}/old-unit"
  LM_PHASE=prepared
  LM_LEGACY_DEVICE=$(stat -c '%d' "${STATE_LAYOUT_LEGACY}")
  LM_LEGACY_INODE=$(stat -c '%i' "${STATE_LAYOUT_LEGACY}")
  LM_LEGACY_TREE_SHA256=$(state_tree_sha256 "${STATE_LAYOUT_LEGACY}")
  LM_OLD_UNIT_SHA256=$(sha256_file "${old_unit}")
  LM_NEW_UNIT_SHA256=$(sha256_file "${new_unit}")
  LM_LEGACY_MODE_UID_GID=$(stat -c '%a:%u:%g' "${STATE_LAYOUT_LEGACY}")
  write_state_layout_migration "${migration_staging}"
  durable_sync "${migration_parent}"
  mv "${migration_staging}" "${STATE_LAYOUT_MIGRATION}"
  durable_sync "${migration_parent}"
  failpoint_sigkill layout-after-prepared
}

cleanup_state_layout_migration_staging() {
  migration_pid=$1
  validate_uint "${migration_pid}" "state layout migration staging pid"
  migration_parent=$(root_path /var/lib/cdnca-edge-agent-packaging)
  migration_staging=${migration_parent}/.layout-migration.${migration_pid}
  if [ -e "${migration_staging}" ] || [ -L "${migration_staging}" ]; then
    [ -d "${migration_staging}" ] && [ ! -L "${migration_staging}" ] || \
      die "state layout migration staging is unsafe"
    [ "$(stat -c '%u:%g:%a' "${migration_staging}")" = 0:0:700 ] || \
      die "state layout migration staging policy is unsafe"
    migration_unsafe=$(find "${migration_staging}" \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit)
    [ -z "${migration_unsafe}" ] || die "state layout migration staging contains an unsafe entry"
    rm -rf -- "${migration_staging}"
    durable_sync "${migration_parent}"
  fi
}

record_state_layout_unit_installed() {
  state_layout_migration_pending || return 0
  state_layout_paths
  load_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  [ "${LM_PHASE}" = prepared ] || die "state layout migration did not expect a unit install"
  installed_unit=$(root_path /usr/lib/systemd/system/cdnca-edge-agent.service)
  [ "$(sha256_file "${installed_unit}")" = "${LM_NEW_UNIT_SHA256}" ] || die "installed bind-aware unit digest differs"
  LM_PHASE=unit_installed
  write_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  failpoint_sigkill layout-after-unit-installed
}

recorded_layout_location() {
  require_exact=$1
  state_layout_paths
  recorded_count=0
  LAYOUT_RECORDED_LOCATION=
  for recorded_candidate in "${STATE_LAYOUT_LEGACY}" "${STATE_LAYOUT_ACTIVE}"; do
    if [ -d "${recorded_candidate}" ] && [ ! -L "${recorded_candidate}" ] && \
      [ "$(stat -c '%d:%i' "${recorded_candidate}")" = "${LM_LEGACY_DEVICE}:${LM_LEGACY_INODE}" ]; then
      validate_state_tree "${recorded_candidate}" "recorded agent state"
      [ "$(stat -c '%a:%u:%g' "${recorded_candidate}")" = "${LM_LEGACY_MODE_UID_GID}" ] || \
        die "recorded agent state ownership facts differ"
      if [ "${require_exact}" = true ]; then
        [ "$(state_tree_sha256 "${recorded_candidate}")" = "${LM_LEGACY_TREE_SHA256}" ] || \
          die "recorded agent state tree differs"
      fi
      recorded_count=$((recorded_count + 1))
      LAYOUT_RECORDED_LOCATION=${recorded_candidate}
    fi
  done
  [ "${recorded_count}" -eq 1 ] || die "recorded agent state location is ambiguous or unavailable"
}

activate_state_layout_migration() {
  health_timeout=$1
  health_stable=$2
  state_layout_paths
  load_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  [ "${LM_PHASE}" = unit_installed ] || die "state layout migration is not ready for activation"
  recorded_layout_location true
  [ "${LAYOUT_RECORDED_LOCATION}" = "${STATE_LAYOUT_LEGACY}" ] || die "legacy state moved before durable intent"
  [ ! -e "${STATE_LAYOUT_ACTIVE}" ] && [ ! -L "${STATE_LAYOUT_ACTIVE}" ] || die "canonical active state already exists"
  LM_PHASE=state_move_intent
  write_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  failpoint_sigkill layout-after-state-move-intent
  mv "${STATE_LAYOUT_LEGACY}" "${STATE_LAYOUT_ACTIVE}" || die "cannot move legacy state to canonical active state"
  durable_sync "$(dirname -- "${STATE_LAYOUT_LEGACY}")"
  durable_sync "${STATE_LAYOUT_ROOT}"
  failpoint_sigkill layout-after-state-move
  create_state_mountpoint
  service_action daemon-reload
  service_action restart
  wait_for_health "${health_timeout}" "${health_stable}" || die "legacy release did not become healthy through the state bind"
  recorded_layout_location false
  [ "${LAYOUT_RECORDED_LOCATION}" = "${STATE_LAYOUT_ACTIVE}" ] || die "activated state is not canonical"
  LM_PHASE=activated
  write_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  failpoint_sigkill layout-after-activated
}

restore_state_layout_unit() {
  state_layout_paths
  installed_unit=$(root_path /usr/lib/systemd/system/cdnca-edge-agent.service)
  install_atomic_metadata "${STATE_LAYOUT_MIGRATION}/old-unit" "${installed_unit}" 0644
  [ "$(sha256_file "${installed_unit}")" = "${LM_OLD_UNIT_SHA256}" ] || die "old systemd unit restore differs"
}

clear_state_layout_migration() {
  state_layout_paths
  [ -e "${STATE_LAYOUT_MIGRATION}" ] || [ -L "${STATE_LAYOUT_MIGRATION}" ] || return 0
  load_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  migration_parent=$(dirname -- "${STATE_LAYOUT_MIGRATION}")
  rm -rf -- "${STATE_LAYOUT_MIGRATION}"
  durable_sync "${migration_parent}"
}

commit_state_layout_migration() {
  state_layout_migration_pending || return 0
  state_layout_paths
  load_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  [ "${LM_PHASE}" = activated ] || die "state layout migration cannot be committed from its current phase"
  recorded_layout_location false
  [ "${LAYOUT_RECORDED_LOCATION}" = "${STATE_LAYOUT_ACTIVE}" ] || die "committed state is not canonical"
  installed_unit=$(root_path /usr/lib/systemd/system/cdnca-edge-agent.service)
  [ "$(sha256_file "${installed_unit}")" = "${LM_NEW_UNIT_SHA256}" ] || die "committed bind-aware unit digest differs"
  validate_completed_state_layout
  clear_state_layout_migration
}

recover_incomplete_state_layout_migration() {
  state_layout_migration_pending || return 0
  state_layout_paths
  load_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  case "${LM_PHASE}" in
    prepared|unit_installed|state_move_intent) recorded_layout_location true ;;
    activated|revert_intent) recorded_layout_location false ;;
  esac
  service_action stop
  LM_PHASE=revert_intent
  write_state_layout_migration "${STATE_LAYOUT_MIGRATION}"
  failpoint_sigkill layout-after-revert-intent
  if [ "${LAYOUT_RECORDED_LOCATION}" = "${STATE_LAYOUT_ACTIVE}" ]; then
    if [ -e "${STATE_LAYOUT_LEGACY}" ] || [ -L "${STATE_LAYOUT_LEGACY}" ]; then
      cleanup_empty_state_mountpoint
      rmdir "${STATE_LAYOUT_LEGACY}" || die "cannot remove state bind mountpoint during recovery"
    fi
    mv "${STATE_LAYOUT_ACTIVE}" "${STATE_LAYOUT_LEGACY}" || die "cannot restore legacy state layout"
    durable_sync "${STATE_LAYOUT_ROOT}"
    durable_sync "$(dirname -- "${STATE_LAYOUT_LEGACY}")"
  else
    [ ! -e "${STATE_LAYOUT_ACTIVE}" ] && [ ! -L "${STATE_LAYOUT_ACTIVE}" ] || \
      die "unexpected canonical state conflicts with recovery"
  fi
  validate_state_tree "${STATE_LAYOUT_LEGACY}" "recovered legacy agent state"
  restore_state_layout_unit
  service_action daemon-reload
  service_action restart
  wait_for_health 30 0 || die "recovered legacy release did not become healthy"
  clear_state_layout_migration
}

validate_retained_state_layout() {
  state_layout_paths
  if [ -e "${STATE_LAYOUT_ACTIVE}" ] || [ -L "${STATE_LAYOUT_ACTIVE}" ]; then
    validate_completed_state_layout
  else
    validate_state_tree "${STATE_LAYOUT_LEGACY}" "retained legacy agent state"
  fi
}

atomic_exchange_paths() {
  exchange_left=$1
  exchange_right=$2
  [ "$(stat -c '%d' "${exchange_left}")" = "$(stat -c '%d' "${exchange_right}")" ] || return 1
  case "$(host_arch)" in
    amd64) renameat2_number=316 ;;
    arm64) renameat2_number=276 ;;
  esac
  perl -we '
    my ($number, $left, $right) = @ARGV;
    syscall($number, -100, $left, -100, $right, 2) == 0
      or die "renameat2 exchange failed: $!\n";
  ' "${renameat2_number}" "${exchange_left}" "${exchange_right}"
}

cleanup_state_staging() {
  for staging_path in "${STATE_COPY_STAGING:-}" "${STATE_RESTORE_STAGING:-}"; do
    [ -n "${staging_path}" ] || continue
    case "${staging_path}" in
      */var/lib/cdnca-edge-agent-backups/.staging-*|*/var/lib/cdnca-edge-agent-backups/.restore-*) ;;
      *) die "unsafe state staging cleanup path" ;;
    esac
    if [ -e "${staging_path}" ] || [ -L "${staging_path}" ]; then
      [ -d "${staging_path}" ] && [ ! -L "${staging_path}" ] || die "state staging path became unsafe"
      rm -rf -- "${staging_path}"
    fi
  done
  STATE_COPY_STAGING=
  STATE_RESTORE_STAGING=
}

backup_state() {
  from_version=$1
  to_version=$2
  purpose=$3
  state=$(root_path /var/lib/cdnca-edge-agent-backups/active-state)
  backup_root=$(root_path /var/lib/cdnca-edge-agent-backups)
  assert_safe_tree "${state}"
  assert_safe_tree "${backup_root}"
  [ -d "${state}" ] && [ ! -L "${state}" ] || die "agent state directory is unavailable"
  validate_state_tree "${state}" "agent state"
  install -d -m 0700 "${backup_root}"
  stamp=$(date -u '+%Y%m%dT%H%M%SZ')
  STATE_BACKUP=${backup_root}/${stamp}-$$-${purpose}
  STATE_COPY_STAGING=${backup_root}/.staging-${stamp}-$$-${purpose}
  install -d -m 0700 "${STATE_COPY_STAGING}"
  if ! cp -a "${state}" "${STATE_COPY_STAGING}/state"; then
    cleanup_state_staging
    die "cannot copy agent state backup"
  fi
  validate_state_tree "${STATE_COPY_STAGING}/state" "staged state backup"
  printf 'from_version=%s\nto_version=%s\npurpose=%s\n' "${from_version}" "${to_version}" "${purpose}" >"${STATE_COPY_STAGING}/metadata"
  chmod 0600 "${STATE_COPY_STAGING}/metadata"
  durable_sync "${STATE_COPY_STAGING}"
  mv "${STATE_COPY_STAGING}" "${STATE_BACKUP}"
  STATE_COPY_STAGING=
  durable_sync "${backup_root}"
}

publish_last_upgrade_backup() {
  backup_root=$(root_path /var/lib/cdnca-edge-agent-backups)
  target=${STATE_BACKUP#"${backup_root}/"}
  link=${backup_root}/last-upgrade
  if [ -L "${link}" ]; then
    last_upgrade_previous=$(readlink "${link}") || die "cannot read previous last-upgrade link"
    case "${last_upgrade_previous}" in
      */*|.|..) die "previous last-upgrade link is unsafe" ;;
    esac
  elif [ -e "${link}" ]; then
    die "last-upgrade path is not a symbolic link"
  fi
  temporary=${backup_root}/.last-upgrade.$$
  ln -s "${target}" "${temporary}"
  durable_sync "${backup_root}"
  mv -Tf "${temporary}" "${link}"
  durable_sync "${backup_root}"
}

last_upgrade_backup_for() {
  from_version=$1
  to_version=$2
  backup_root=$(root_path /var/lib/cdnca-edge-agent-backups)
  assert_safe_tree "${backup_root}"
  link=${backup_root}/last-upgrade
  [ -L "${link}" ] || die "no successful-upgrade state backup is available"
  target=$(readlink "${link}")
  case "${target}" in
    */*|.|..) die "last-upgrade backup link is unsafe" ;;
  esac
  selected=${backup_root}/${target}
  assert_safe_tree "${selected}"
  assert_regular_file "${selected}/metadata" "state backup metadata"
  grep -Fx "from_version=${from_version}" "${selected}/metadata" >/dev/null || die "last state backup does not match rollback target"
  grep -Fx "to_version=${to_version}" "${selected}/metadata" >/dev/null || die "last state backup does not match current release"
  [ -d "${selected}/state" ] && [ ! -L "${selected}/state" ] || die "state backup is unavailable"
  validate_state_tree "${selected}/state" "selected state backup"
  printf '%s\n' "${selected}"
}

restore_state() {
  backup=$1
  label=$2
  state=$(root_path /var/lib/cdnca-edge-agent-backups/active-state)
  backup_root=$(root_path /var/lib/cdnca-edge-agent-backups)
  assert_safe_tree "${state}"
  assert_safe_tree "${backup_root}"
  [ -d "${state}" ] && [ ! -L "${state}" ] || die "current agent state must be a non-symlink directory"
  validate_state_tree "${backup}/state" "state restore source"
  state_parent=$(dirname -- "${state}")
  STATE_RESTORE_STAGING=${backup_root}/.restore-$$
  validate_restore_staging_path "${STATE_RESTORE_STAGING}"
  [ ! -e "${STATE_RESTORE_STAGING}" ] && [ ! -L "${STATE_RESTORE_STAGING}" ] || die "state restore staging path exists"
  install -d -m 0700 "${STATE_RESTORE_STAGING}"
  [ "$(stat -c '%u:%g:%a' "${STATE_RESTORE_STAGING}")" = 0:0:700 ] || die "state restore staging ownership or mode is unsafe"
  record_transaction_restore_staging "${STATE_RESTORE_STAGING}"
  if consume_failpoint state-copy; then
    : >"${STATE_RESTORE_STAGING}/partial-copy"
    die "injected state copy failure"
  fi
  cp -a "${backup}/state" "${STATE_RESTORE_STAGING}/state" || die "cannot stage restored state"
  validate_state_tree "${STATE_RESTORE_STAGING}/state" "staged restored state"
  durable_sync "${STATE_RESTORE_STAGING}"
  failpoint_sigkill state-restore-after-staging
  displaced=${backup_root}/$(date -u '+%Y%m%dT%H%M%SZ')-$$-${label}
  install -d -m 0700 "${displaced}"
  durable_sync "${backup_root}"
  failpoint_interrupt state-restore-interrupt
  trap '' HUP INT TERM
  if ! atomic_exchange_paths "${state}" "${STATE_RESTORE_STAGING}/state"; then
    trap 'exit 1' HUP INT TERM
    cleanup_state_staging
    die "cannot atomically exchange restored state"
  fi
  if ! sync -f "${state_parent}" || ! sync -f "${backup_root}"; then
    atomic_exchange_paths "${state}" "${STATE_RESTORE_STAGING}/state" >/dev/null 2>&1 || true
    sync -f "${state_parent}" >/dev/null 2>&1 || true
    sync -f "${backup_root}" >/dev/null 2>&1 || true
    trap 'exit 1' HUP INT TERM
    cleanup_state_staging
    die "cannot durably commit restored state"
  fi
  trap 'exit 1' HUP INT TERM
  # shellcheck disable=SC2034 # Reported by rollback.sh after a successful restore.
  if mv "${STATE_RESTORE_STAGING}/state" "${displaced}/replaced-state"; then
    RESTORE_DISPLACED=${displaced}/replaced-state
    rmdir "${STATE_RESTORE_STAGING}" || die "cannot remove committed state restore staging"
    STATE_RESTORE_STAGING=
    record_transaction_restore_staging ''
    durable_sync "${backup_root}"
  else
    RESTORE_DISPLACED=${STATE_RESTORE_STAGING}/state
    STATE_RESTORE_STAGING=
    record_transaction_restore_staging ''
    printf 'cdnca-edge-agent packaging: restored state committed; replaced state remains at %s\n' "${RESTORE_DISPLACED}" >&2
  fi
}

install_runtime_layout() {
  require_runtime_identity
  state_layout_paths
  assert_safe_tree "${STATE_LAYOUT_ROOT}"
  install -d -m 0700 "${STATE_LAYOUT_ROOT}"
  if [ -e "${STATE_LAYOUT_ACTIVE}" ] || [ -L "${STATE_LAYOUT_ACTIVE}" ]; then
    validate_completed_state_layout
    runtime_state=${STATE_LAYOUT_ACTIVE}
  else
    runtime_state=${STATE_LAYOUT_LEGACY}
    if [ -e "${runtime_state}" ] || [ -L "${runtime_state}" ]; then
      validate_state_tree "${runtime_state}" "fresh agent state"
    fi
  fi
  if [ "${PACKAGE_RUNTIME_IDENTITY}" = root ]; then
    # Root mode: enrollment creates identity/ itself and refuses an existing
    # one; the deployment root's mode belongs to the Agent's native worker
    # access (root:cdnca-runtime 0710) and must never be reset here.
    for path in /etc/cdnca-edge-agent/tls /etc/cdnca-edge-agent/trust /var/log/cdnca-edge-agent; do
      rooted_path=$(root_path "${path}")
      assert_safe_tree "${rooted_path}"
      install -d -m 0700 "${rooted_path}"
    done
    rooted_path=$(root_path /var/lib/cdnca-edge)
    assert_safe_tree "${rooted_path}"
    [ -e "${rooted_path}" ] || [ -L "${rooted_path}" ] || install -d -m 0700 "${rooted_path}"
    [ -d "${rooted_path}" ] && [ ! -L "${rooted_path}" ] || die "deployment root must be a non-symlink directory"
  else
    for path in \
      /etc/cdnca-edge-agent/identity \
      /etc/cdnca-edge-agent/tls \
      /etc/cdnca-edge-agent/trust \
      /var/lib/cdnca-edge \
      /var/log/cdnca-edge-agent; do
      rooted_path=$(root_path "${path}")
      assert_safe_tree "${rooted_path}"
      install -d -m 0700 "${rooted_path}"
    done
  fi
  for state_child in gateway-journal deployments; do
    assert_safe_tree "${runtime_state}/${state_child}"
    install -d -m 0700 "${runtime_state}/${state_child}"
  done
  if [ "${PACKAGE_RUNTIME_IDENTITY}" = root ]; then
    chmod 0700 "$(root_path /etc/cdnca-edge-agent)" "$(root_path /var/log/cdnca-edge-agent)"
  else
    chmod 0750 "$(root_path /etc/cdnca-edge-agent)" "$(root_path /var/log/cdnca-edge-agent)"
  fi
}

verify_existing_system_account_layout() {
  if [ -n "${DESTDIR}" ]; then
    passwd_database=$(root_path /etc/passwd)
    group_database=$(root_path /etc/group)
    assert_safe_tree "${passwd_database}"
    assert_safe_tree "${group_database}"
    assert_regular_file "${passwd_database}" "staged passwd database"
    assert_regular_file "${group_database}" "staged group database"
    account_record=$(awk -F: '$1 == "cdnca-edge" { print }' "${passwd_database}")
    group_record=$(awk -F: '$1 == "cdnca-edge" { print }' "${group_database}")
  else
    command -v getent >/dev/null 2>&1 || die "getent is required to verify the existing service identity"
    account_record=$(getent passwd cdnca-edge) || die "cdnca-edge user is unavailable for upgrade"
    group_record=$(getent group cdnca-edge) || die "cdnca-edge group is unavailable for upgrade"
  fi
  identity_ids=$(printf '%s\n' "${account_record}" | awk -F: '
    NR == 1 && NF == 7 && $1 == "cdnca-edge" &&
      $3 ~ /^[0-9]+$/ && $3 + 0 > 0 && $4 ~ /^[0-9]+$/ && $4 + 0 > 0 &&
      $6 == "/var/lib/cdnca-edge-agent" && $7 == "/usr/sbin/nologin" {
        valid = 1
        print $3 ":" $4
      }
    END { exit !(valid && NR == 1) }
  ') || die "cdnca-edge passwd identity differs from the packaging contract"
  printf '%s\n' "${group_record}" | awk -F: -v expected_gid="${identity_ids#*:}" '
    NR == 1 && NF == 4 && $1 == "cdnca-edge" && $3 == expected_gid { valid = 1 }
    END { exit !(valid && NR == 1) }
  ' >/dev/null || die "cdnca-edge primary group differs from the packaging contract"
  [ "$(agent_ids)" = "${identity_ids}" ] || die "resolved cdnca-edge identity differs from passwd and group"
}

install_system_account_layout() {
  if [ "${upgrade:-false}" = true ]; then
    verify_existing_system_account_layout
  elif [ -n "${DESTDIR}" ]; then
    systemd-sysusers --root="${DESTDIR}" >/dev/null
  else
    systemd-sysusers cdnca-edge-agent.conf >/dev/null
  fi
  if [ -n "${DESTDIR}" ]; then
    systemd-tmpfiles --root="${DESTDIR}" --create cdnca-edge-agent.conf >/dev/null
  else
    systemd-tmpfiles --create cdnca-edge-agent.conf >/dev/null
  fi
  if [ "${upgrade:-false}" = false ] && [ -z "${old_target:-}" ]; then
    state_layout_paths
    if [ -e "${STATE_LAYOUT_ACTIVE}" ] || [ -L "${STATE_LAYOUT_ACTIVE}" ]; then
      # Default uninstall retains canonical state; a reinstall reuses it only
      # when it still satisfies the completed layout and runtime ownership.
      validate_completed_state_layout
      return
    fi
    state_ids=$(runtime_ids)
    for state_path in "${STATE_LAYOUT_LEGACY}" "${STATE_LAYOUT_LEGACY}/gateway-journal" "${STATE_LAYOUT_LEGACY}/deployments"; do
      [ -d "${state_path}" ] && [ ! -L "${state_path}" ] || die "fresh runtime state path is unsafe"
      chown "${state_ids%:*}:${state_ids#*:}" "${state_path}"
      chmod 0700 "${state_path}"
    done
  fi
}
