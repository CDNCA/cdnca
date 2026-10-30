#!/bin/sh
set -eu

packaging_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
repo_root=$(CDPATH='' cd -- "${packaging_root}/../../.." && pwd -P)
task_prefix=cdnca_ops0611_packaging
protocol_hash=fbd782ae8365028f100ad0d04dd21da175827bb14a1b10cb40f9aace5a5be050
mode=${1:-all}

case "${mode}" in
  all|static|go|systemd-verify|runtime) ;;
  *) printf 'usage: %s [all|static|go|systemd-verify|runtime]\n' "$0" >&2; exit 64 ;;
esac

fail() {
  printf 'edge-agent helper smoke failed: %s\n' "$*" >&2
  exit 1
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

assert_line() {
  expected=$1
  file=$2
  grep -F -x -- "${expected}" "${file}" >/dev/null || fail "${file} is missing: ${expected}"
}

assert_absent_text() {
  forbidden=$1
  file=$2
  if grep -F -- "${forbidden}" "${file}" >/dev/null; then
    fail "${file} contains forbidden text: ${forbidden}"
  fi
}

assert_absent_line() {
  forbidden=$1
  file=$2
  if grep -F -x -- "${forbidden}" "${file}" >/dev/null; then
    fail "${file} contains forbidden line: ${forbidden}"
  fi
}

make_workdir() {
  tmp_base=${TMPDIR:-/tmp}
  work_base=${tmp_base%/}
  workdir=$(mktemp -d "${work_base}/${task_prefix}.helper.XXXXXX")
}

cleanup() {
  cleanup_status=$?
  if [ "${cleanup_status}" -ne 0 ] && [ "${CDNCA_OPS0611_ISOLATED:-}" = 1 ] && command -v systemctl >/dev/null 2>&1; then
    for failed_unit in \
      cdnca-edge-agent-helper.service \
      cdnca-edge-agent-helper.socket \
      cdnca-edge-agent.service; do
      systemctl status --no-pager --full "${failed_unit}" >&2 || true
      journalctl -u "${failed_unit}" --no-pager -n 200 >&2 || true
    done
  fi
  for owned_pid in \
    "${probe_pid:-}" "${agent_client_pid:-}" "${cancel_client_pid:-}" \
    "${cancel_namespace_pid:-}" "${delay_client_pid:-}" \
    "${failure_pid_3:-}" "${failure_pid_4:-}" \
    "${sigkill_client_pid:-}" "${sigkill_namespace_pid:-}"; do
    [ -n "${owned_pid}" ] || continue
    kill "${owned_pid}" >/dev/null 2>&1 || true
    wait "${owned_pid}" 2>/dev/null || true
  done
  if [ "${upgrade_replaced:-false}" = true ] && [ -f "${upgrade_backup:-}" ] && [ -n "${upgrade_script:-}" ]; then
    install -o root -g root -m 0555 "${upgrade_backup}" "${upgrade_script}" >/dev/null 2>&1 || true
  fi
  if [ -n "${upgrade_passthrough:-}" ]; then
    rm -f -- "${upgrade_passthrough}" >/dev/null 2>&1 || true
  fi
  if [ "${runtime_units_started:-false}" = true ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket cdnca-edge-agent.service >/dev/null 2>&1 || true
  fi
  if [ "${CDNCA_OPS0611_ISOLATED:-}" = 1 ]; then
    if [ "${migration_gate_created:-false}" = true ]; then
      rm -f -- /var/lib/cdnca-edge-agent-packaging/layout-migration
    fi
    rm -f -- \
      /run/cdnca-ops0611-concurrent-handoffs \
      /run/cdnca-ops0611-cancel-handoff \
      /run/cdnca-ops0611-inspect-cancel \
      /run/cdnca-ops0611-nsenter-ready \
      /run/cdnca-ops0611-sigkill-before-handoff \
      /run/cdnca-ops0611-sigkill-after-handoff \
      /run/cdnca-ops0611-sigkill-inspect \
      /run/cdnca-ops0611-sigkill-nsenter-ready \
      /run/cdnca-ops0611-probe-started \
      /run/cdnca-ops0611-probe-stop
  fi
  if [ -n "${workdir:-}" ]; then
    case "${workdir}" in
      "${work_base-}"/${task_prefix}.helper.*) rm -rf -- "${workdir}" ;;
      *) printf 'refusing to clean unexpected helper smoke path: %s\n' "${workdir}" >&2 ;;
    esac
  fi
  return "${cleanup_status}"
}
trap cleanup EXIT HUP INT TERM

append_section() {
  section=$1
  perl -e 'use strict; use warnings; my $size = -s $ARGV[0]; print pack("Q>", $size);' "${section}" >>"${bundle}"
  cat "${section}" >>"${bundle}"
}

validate_fixture_bundle() {
  candidate=$1
  perl -e '
    use strict;
    use warnings;
    my $path = shift;
    open my $fh, "<:raw", $path or exit 2;
    local $/;
    my $data = <$fh>;
    my $magic = "cdnca-edge-release-bundle/v1\0";
    exit 3 unless substr($data, 0, length($magic), "") eq $magic;
    my @limits = (16384, 64, 16777216, 268435456);
    for my $index (0 .. 3) {
      exit 4 if length($data) < 8;
      my $length = unpack("Q>", substr($data, 0, 8, ""));
      exit 5 if $length < 1 || $length > $limits[$index];
      exit 6 if $index == 1 && $length != 64;
      exit 7 if length($data) < $length;
      substr($data, 0, $length, "");
    }
    exit 8 if length($data) != 0;
  ' "${candidate}"
}

run_static() {
  protocol=${packaging_root}/helper/PROTOCOL.md
  service=${packaging_root}/systemd/cdnca-edge-agent-helper.service
  edge_service=${packaging_root}/systemd/cdnca-edge-agent.service
  socket=${packaging_root}/systemd/cdnca-edge-agent-helper.socket
  tmpfiles=${packaging_root}/tmpfiles/cdnca-edge-agent.conf
  [ "$(hash_file "${protocol}")" = "${protocol_hash}" ] || fail "frozen PROTOCOL.md hash differs"

  command -v go >/dev/null 2>&1 || fail "go is required for syntax-aware test contract validation"
  make_workdir
  go_test_ast_checker=${workdir}/assert-go-tests.go
  cat >"${go_test_ast_checker}" <<'EOF'
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var expected = []string{
	"TestServiceV2PrepareInspectActivateResponseLossAndReplay",
	"TestServiceV2InspectInstallingIsPure",
	"TestServiceV2AbortPreparedPersistsTombstoneAndReplays",
	"TestServicePrepareAbortedTransactionRejectsSamePayloadReplay",
	"TestServiceAbortPreparedCleansStagingAfterDurableTombstone",
	"TestServiceAbortPreparedCleanupFailureKeepsTombstoneAndRetries",
	"TestServiceAbortPreparedInspectWaitsForCleanupAfterTombstone",
	"TestServiceAbortPreparedRequiresParentSyncAfterDirectoryAlreadyMissing",
	"TestServiceAbortPreparedCannotRaceActivationAcrossInstances",
	"TestServiceV2AbortPreparedRejectsInstallingAndActive",
	"TestServiceV2SIGKILLWindowsFailClosedAndDoNotRepeatRunner",
	"TestLinuxClientRejectsResponseProtocolDowngrade",
}

type declaration struct {
	path string
	fn   *ast.FuncDecl
}

func exactTestSignature(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Type.TypeParams != nil || fn.Type.Results != nil || fn.Body == nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	parameter := fn.Type.Params.List[0]
	if len(parameter.Names) != 1 || parameter.Names[0].Name != "t" {
		return false
	}
	star, ok := parameter.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := star.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "T" {
		return false
	}
	packageName, ok := selector.X.(*ast.Ident)
	return ok && packageName.Name == "testing"
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: assert-go-tests <root>")
		os.Exit(2)
	}
	wanted := make(map[string]bool, len(expected))
	found := make(map[string][]declaration, len(expected))
	for _, name := range expected {
		wanted[name] = true
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(os.Args[1], func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, item := range file.Decls {
			fn, ok := item.(*ast.FuncDecl)
			if ok && wanted[fn.Name.Name] {
				found[fn.Name.Name] = append(found[fn.Name.Name], declaration{path: path, fn: fn})
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, name := range expected {
		declarations := found[name]
		if len(declarations) != 1 || !exactTestSignature(declarations[0].fn) {
			fmt.Fprintf(os.Stderr, "%s has %d exact top-level declarations\n", name, len(declarations))
			os.Exit(1)
		}
	}
}
EOF
  go run "${go_test_ast_checker}" "${packaging_root}/helper" || \
    fail "v2 helper regression test declarations are invalid"

  for contract in \
    '"protocol_version":2,"operation":"prepare_install"' \
    '"protocol_version":2,"operation":"inspect_transaction"' \
    '"protocol_version":2,"operation":"activate_install"' \
    '"protocol_version":2,"operation":"abort_prepared"' \
    "Transaction status phases are exactly \`unknown\`, \`prepared\`, \`aborted\`," \
    "\`aborted\` tombstone before removing the staged transaction directory" \
    "The \`aborted\` tombstone is terminal" \
    'abort replay returns the same journal-derived status' \
    "persists \`installing\` before invoking packaging" \
    "Exact target facts are signed and persisted as \`active\` without"; do
    grep -F -- "${contract}" "${protocol}" >/dev/null || fail "v2 protocol contract is missing: ${contract}"
  done
  for line in \
    'UMask=0077' \
    'ConditionFileIsExecutable=/usr/libexec/cdnca-edge-agent-helper' \
    'ConditionPathIsDirectory=/var/lib/cdnca-edge-agent-backups/active-state' \
    'ConditionPathExists=!/var/lib/cdnca-edge-agent-packaging/layout-migration' \
    'ExecStart=/usr/libexec/cdnca-edge-agent-helper serve' \
    'NoNewPrivileges=yes' \
    'PrivateNetwork=yes' \
    'ProtectSystem=strict' \
    'StateDirectory=cdnca-edge-agent-helper cdnca-edge-agent-backups' \
    'ReadOnlyPaths=/etc/cdnca-edge-agent/package-signing.pem' \
    'ReadWritePaths=/var/lib/cdnca-edge-agent-helper' \
    'ReadWritePaths=/var/lib/cdnca-edge-agent-backups' \
    'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID' \
    'RestrictAddressFamilies=AF_UNIX'; do
    assert_line "${line}" "${service}"
  done
  # An explicit root user makes systemd drop CAP_SETUID (see the unit).
  assert_absent_line 'User=root' "${service}"
  assert_absent_line 'Group=root' "${service}"
  assert_absent_text 'EnvironmentFile=' "${service}"
  assert_absent_text 'ExecStartPre=' "${service}"
  assert_absent_text 'ExecStart=/bin/' "${service}"
  assert_absent_line 'ReadWritePaths=/' "${service}"
  assert_absent_line 'ReadWritePaths=/var/lib' "${service}"
  assert_absent_line 'ReadWritePaths=/var/lib/cdnca-edge-agent' "${service}"
  assert_absent_text 'CAP_SYS_ADMIN' "${service}"
  assert_absent_text 'AmbientCapabilities=CAP_' "${service}"
  assert_absent_line 'FlushPending=yes' "${socket}"

  sigkill_body=$(sed -n '/^  sigkill_helper_cgroup() {$/,/^  }$/p' "$0")
  sigkill_stop_line=$(printf '%s\n' "${sigkill_body}" | grep -n -F 'systemctl stop cdnca-edge-agent-helper.service' | sed -n '1s/:.*//p')
  sigkill_poll_line=$(printf '%s\n' "${sigkill_body}" | grep -n -F "while [ \"\${sigkill_attempt}\" -lt 100 ]; do" | sed -n '1s/:.*//p')
  [ -n "${sigkill_stop_line}" ] && [ -n "${sigkill_poll_line}" ] && [ "${sigkill_stop_line}" -lt "${sigkill_poll_line}" ] || \
    fail "SIGKILL fixture does not suppress automatic restart before polling"
  for property in ActiveState SubState MainPID NRestarts; do
    printf '%s\n' "${sigkill_body}" | grep -F "${property}" >/dev/null || \
      fail "SIGKILL fixture does not verify ${property} quiescence"
  done

  cancellation_body=$(sed -n '/^  cancelling_upgrade=/,/^  upgrade_passthrough=/p' "$0")
  for contract in \
    '.ok == false and .error_code == "ERR_DEADLINE" and .receipt == null' \
    '.phase == "installing" and .transaction_id == "txn-runtime-cancel-5"' \
    'cancelled install Query recovery receipt differs'; do
    printf '%s\n' "${cancellation_body}" | grep -F "${contract}" >/dev/null || \
      fail "cancellation fixture does not preserve recovery contract: ${contract}"
  done

  for line in \
    'User=cdnca-edge' \
    'Group=cdnca-edge' \
    "ExecStart=/usr/lib/cdnca-edge-agent/current/edge-agent -config \${CDNCA_EDGE_CONFIG}" \
    'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind' \
    'ReadWritePaths=/var/lib/cdnca-edge /var/log/cdnca-edge-agent -/etc/cdnca-edge-agent/identity -/etc/cdnca-edge-agent/identity'; do
    assert_line "${line}" "${edge_service}"
  done
  assert_absent_line 'ReadWritePaths=/var/lib' "${edge_service}"
  assert_absent_text 'ReadWritePaths=/var/lib/cdnca-edge-agent ' "${edge_service}"
  assert_absent_line 'ReadWritePaths=/var/lib/cdnca-edge-agent-backups' "${edge_service}"
  assert_absent_text 'CAP_SYS_ADMIN' "${edge_service}"

  assert_line 'd /var/lib/cdnca-edge-agent-backups 0700 root root -' "${tmpfiles}"
  for line in \
    'd /var/lib/cdnca-edge-agent 0700 root root -' \
    'd /var/lib/cdnca-edge-agent/gateway-journal 0700 cdnca-edge cdnca-edge -' \
    'd /var/lib/cdnca-edge-agent/deployments 0700 cdnca-edge cdnca-edge -'; do
    assert_absent_line "${line}" "${tmpfiles}"
  done
  assert_absent_text '/var/lib/cdnca-edge-agent-backups/active-state' "${tmpfiles}"

  for line in \
    'ListenSequentialPacket=/run/cdnca-edge-agent/helper.sock' \
    'SocketUser=cdnca-edge' \
    'SocketGroup=cdnca-edge' \
    'SocketMode=0600' \
    'DirectoryMode=0711' \
    'Accept=no' \
    'Backlog=16'; do
    assert_line "${line}" "${socket}"
  done

  command -v perl >/dev/null 2>&1 || fail "perl is required for canonical bundle fixture"
  fixture=${workdir}/fixture
  mkdir "${fixture}"
  printf 'manifest_version=2\n' >"${fixture}/manifest"
  perl -e 'print pack("C*", (0x5a) x 64)' >"${fixture}/manifest.sig"
  printf '{"spdxVersion":"SPDX-2.3"}' >"${fixture}/edge-agent.spdx.json"
  printf '\177ELF\001\002\003\004' >"${fixture}/edge-agent"
  bundle=${workdir}/release.bundle
  printf 'cdnca-edge-release-bundle/v1\000' >"${bundle}"
  append_section "${fixture}/manifest"
  append_section "${fixture}/manifest.sig"
  append_section "${fixture}/edge-agent.spdx.json"
  append_section "${fixture}/edge-agent"
  [ "$(stat -c '%s' "${bundle}" 2>/dev/null || stat -f '%z' "${bundle}")" = 179 ] || fail "golden bundle size differs"
  [ "$(hash_file "${bundle}")" = '60dc410c77a1b71b3e877e3bdb0bf0a3cd48a0bcb028fa56636912dee7ae13b2' ] || fail "golden bundle digest differs"
  validate_fixture_bundle "${bundle}" || fail "canonical binary bundle rejected"
  cp "${bundle}" "${workdir}/trailing.bundle"
  printf 'x' >>"${workdir}/trailing.bundle"
  if validate_fixture_bundle "${workdir}/trailing.bundle"; then
    fail "bundle fixture accepted a trailing byte"
  fi
  rm -rf -- "${workdir}"
  workdir=
  printf 'edge-agent helper static contract checks passed\n'
}

run_go() {
  command -v go >/dev/null 2>&1 || fail "go is required"
  (
    cd "${repo_root}/agents/edge-agent"
    go test ./packaging/helper/... ./internal/updater/...
  )
  printf 'edge-agent helper focused Go tests passed\n'
}

run_systemd_verify() {
  [ "$(uname -s)" = Linux ] || fail "systemd verification requires Linux"
  command -v systemd-analyze >/dev/null 2>&1 || fail "systemd-analyze is required"
  [ "$(id -u)" -eq 0 ] || fail "systemd verification must run as root in an isolated test environment"
  [ -e /.dockerenv ] || [ "${CDNCA_OPS0611_ISOLATED:-}" = 1 ] || fail "refusing to create verification fixtures outside an isolated environment"

  helper_fixture=/usr/libexec/cdnca-edge-agent-helper
  helper_fixture_created=false
  if [ ! -e "${helper_fixture}" ]; then
    printf '#!/bin/sh\nexit 0\n' >"${helper_fixture}"
    chmod 0755 "${helper_fixture}"
    helper_fixture_created=true
  fi
  edge_fixture=/usr/lib/cdnca-edge-agent/current/edge-agent
  edge_fixture_created=false
  if [ ! -e "${edge_fixture}" ]; then
    install -d -m 0755 "$(dirname -- "${edge_fixture}")"
    printf '#!/bin/sh\nexit 0\n' >"${edge_fixture}"
    chmod 0755 "${edge_fixture}"
    edge_fixture_created=true
  fi
  preflight_fixture=/usr/libexec/cdnca-edge-agent/preflight.sh
  preflight_fixture_created=false
  if [ ! -e "${preflight_fixture}" ]; then
    install -d -m 0755 "$(dirname -- "${preflight_fixture}")"
    printf '#!/bin/sh\nexit 0\n' >"${preflight_fixture}"
    chmod 0755 "${preflight_fixture}"
    preflight_fixture_created=true
  fi
  openresty_fixture=/usr/lib/systemd/system/cdnca-openresty.service
  openresty_fixture_created=false
  if [ ! -e "${openresty_fixture}" ]; then
    printf '[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n' >"${openresty_fixture}"
    openresty_fixture_created=true
  fi
  verify_output=
  if ! verify_output=$(systemd-analyze verify \
    "${packaging_root}/systemd/cdnca-edge-agent.service" \
    "${packaging_root}/systemd/cdnca-edge-agent-helper.socket" \
    "${packaging_root}/systemd/cdnca-edge-agent-helper.service" 2>&1); then
    [ "${helper_fixture_created}" = false ] || rm -f -- "${helper_fixture}"
    if [ "${edge_fixture_created}" = true ]; then
      rm -f -- "${edge_fixture}"
      rmdir "$(dirname -- "${edge_fixture}")" "$(dirname -- "$(dirname -- "${edge_fixture}")")" 2>/dev/null || true
    fi
    if [ "${preflight_fixture_created}" = true ]; then
      rm -f -- "${preflight_fixture}"
      rmdir "$(dirname -- "${preflight_fixture}")" 2>/dev/null || true
    fi
    [ "${openresty_fixture_created}" = false ] || rm -f -- "${openresty_fixture}"
    printf '%s\n' "${verify_output}" >&2
    fail "systemd-analyze verify failed"
  fi
  [ "${helper_fixture_created}" = false ] || rm -f -- "${helper_fixture}"
  if [ "${edge_fixture_created}" = true ]; then
    rm -f -- "${edge_fixture}"
    rmdir "$(dirname -- "${edge_fixture}")" "$(dirname -- "$(dirname -- "${edge_fixture}")")" 2>/dev/null || true
  fi
  if [ "${preflight_fixture_created}" = true ]; then
    rm -f -- "${preflight_fixture}"
    rmdir "$(dirname -- "${preflight_fixture}")" 2>/dev/null || true
  fi
  [ "${openresty_fixture_created}" = false ] || rm -f -- "${openresty_fixture}"
  printf '%s\n' "$(systemd-analyze --version | sed -n '1p')"
  printf 'edge-agent helper systemd verification passed\n'
}

run_runtime() {
  helper_source=${repo_root}/agents/edge-agent/packaging/helper/cmd/cdnca-edge-agent-helper/main.go
  [ -f "${helper_source}" ] || fail "helper CLI source is not available; runtime acceptance is blocked"
  [ "$(uname -s)" = Linux ] || fail "runtime mode requires Linux"
  [ "$(id -u)" -eq 0 ] || fail "runtime mode requires root inside an isolated systemd environment"
  [ -e /.dockerenv ] && [ "${CDNCA_OPS0611_ISOLATED:-}" = 1 ] || fail "runtime mode is restricted to its isolated container"
  [ -x /task/cdnca-edge-agent-helper ] || fail "cross-built helper binary is missing"
  [ "$(ps -p 1 -o comm= | tr -d ' ')" = systemd ] || fail "systemd is not PID 1"
  for command in cc dd find jq nsenter openssl perl python3 setpriv systemctl; do
    command -v "${command}" >/dev/null 2>&1 || fail "runtime dependency is missing: ${command}"
  done
  run_systemd_verify

  make_workdir
  chmod 0711 "${workdir}"
  runtime_arch=$(uname -m)
  case "${runtime_arch}" in
    x86_64|amd64) runtime_arch=amd64 ;;
    aarch64|arm64) runtime_arch=arm64 ;;
    *) fail "unsupported runtime architecture: ${runtime_arch}" ;;
  esac
  agent_gid=$(getent group cdnca-edge 2>/dev/null | awk -F: '{print $3}' || :)
  if [ -z "${agent_gid}" ]; then
    install -m 0644 "${packaging_root}/sysusers/cdnca-edge-agent.conf" /usr/lib/sysusers.d/cdnca-edge-agent.conf
    systemd-sysusers /usr/lib/sysusers.d/cdnca-edge-agent.conf
    agent_gid=$(getent group cdnca-edge | awk -F: '{print $3}')
  fi
  agent_uid=$(id -u cdnca-edge)

  release_private=${workdir}/release-private.pem
  release_public=${workdir}/release-public.pem
  openssl genpkey -algorithm ED25519 -out "${release_private}"
  openssl pkey -in "${release_private}" -pubout -out "${release_public}"

  make_runtime_agent() {
    agent_path=$1
    agent_version=$2
    source_path=${agent_path}.c
    cat >"${source_path}" <<EOF
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int probe_identity(void) {
  const char *uid_text = getenv("CDNCA_PROBE_EXPECT_UID");
  const char *gid_text = getenv("CDNCA_PROBE_EXPECT_GID");
  if (uid_text == NULL || gid_text == NULL) return 90;
  if (getuid() != (uid_t)strtoul(uid_text, NULL, 10) ||
      getgid() != (gid_t)strtoul(gid_text, NULL, 10)) return 91;
  return 0;
}

static int probe_handoff(const char *artifact_path) {
  const char *names[] = {"manifest", "manifest.sig", "edge-agent.spdx.json", "edge-agent"};
  char directory[4096];
  char path[4096];
  char *slash;
  size_t index;
  if (getuid() != 65534 || getgid() != 65534) return 0;
  if (snprintf(directory, sizeof(directory), "%s", artifact_path) >= (int)sizeof(directory)) return 96;
  slash = strrchr(directory, '/');
  if (slash == NULL) return 97;
  *slash = '\0';
  for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
    int descriptor;
    if (snprintf(path, sizeof(path), "%s/%s", directory, names[index]) >= (int)sizeof(path)) return 98;
    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return 99;
    close(descriptor);
    descriptor = open(path, O_WRONLY | O_CLOEXEC);
    if (descriptor >= 0) {
      close(descriptor);
      return 100;
    }
  }
  return 0;
}

static int serve(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int enabled = 1;
  struct sockaddr_in address;
  if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) return 92;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(18091);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(fd, 16) != 0) return 93;
  for (;;) {
    int client = accept(fd, NULL, NULL);
    if (client < 0) {
      if (errno == EINTR) continue;
      return 94;
    }
    if (write(client, "${agent_version}\n", sizeof("${agent_version}\n") - 1) !=
        (ssize_t)(sizeof("${agent_version}\n") - 1)) {
      close(client);
      return 101;
    }
    close(client);
  }
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    int identity = probe_identity();
    if (identity != 0) return identity;
    identity = probe_handoff(argv[0]);
    if (identity != 0) return identity;
    puts("{\"agent_version\":\"${agent_version}\",\"build_id\":\"ops0611\"}");
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "--check-config") == 0 && strcmp(argv[2], "-config") == 0) {
    int identity = probe_identity();
    if (identity != 0) return identity;
    return access(argv[3], R_OK) == 0 ? 0 : 95;
  }
  if (argc == 3 && strcmp(argv[1], "-config") == 0 && access(argv[2], R_OK) == 0) return serve();
  return 2;
}
EOF
    cc -O2 -Wall -Wextra -Werror -o "${agent_path}" "${source_path}"
    rm -f -- "${source_path}"
  }

  make_runtime_release() {
    release_dir=$1
    release_version=$2
    release_sequence=$3
    mkdir "${release_dir}"
    make_runtime_agent "${release_dir}/edge-agent" "${release_version}"
    printf '{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"edge-agent-%s","documentNamespace":"https://example.invalid/spdx/%s","creationInfo":{"created":"2026-07-28T00:00:00Z","creators":["Tool: cdnca-ops0611-runtime"]}}\n' \
      "${release_version}" "${release_version}" >"${release_dir}/edge-agent.spdx.json"
    executable_digest=$(hash_file "${release_dir}/edge-agent")
    executable_size=$(stat -c '%s' "${release_dir}/edge-agent")
    sbom_digest=$(hash_file "${release_dir}/edge-agent.spdx.json")
    sbom_size=$(stat -c '%s' "${release_dir}/edge-agent.spdx.json")
    printf 'manifest_version=2\nrelease_sequence=%s\nversion=%s\nartifact_path=edge-agent\nartifact_sha256=%s\nartifact_size=%s\nsbom_path=edge-agent.spdx.json\nsbom_sha256=%s\nsbom_size=%s\nos=linux\narch=%s\nsource_repository=https://example.invalid/cdnca.git\nsource_commit=0123456789abcdef0123456789abcdef01234567\nbuild_time=2026-07-28T00:00:00Z\nminimum_control_protocol=1.0\nminimum_agent_protocol=1.0\n' \
      "${release_sequence}" "${release_version}" "${executable_digest}" "${executable_size}" \
      "${sbom_digest}" "${sbom_size}" "${runtime_arch}" >"${release_dir}/manifest"
    openssl pkeyutl -sign -inkey "${release_private}" -rawin -in "${release_dir}/manifest" -out "${release_dir}/manifest.sig"
    bundle=${release_dir}/release.bundle
    printf 'cdnca-edge-release-bundle/v1\000' >"${bundle}"
    append_section "${release_dir}/manifest"
    append_section "${release_dir}/manifest.sig"
    append_section "${release_dir}/edge-agent.spdx.json"
    append_section "${release_dir}/edge-agent"
    validate_fixture_bundle "${bundle}" || fail "runtime canonical bundle is invalid"
  }

  assert_canonical_state_layout() {
    layout_phase=$1
    common_facts=$(stat -c '%u:%g:%a' /var/lib/cdnca-edge-agent-backups)
    active_facts=$(stat -c '%u:%g:%a' /var/lib/cdnca-edge-agent-backups/active-state)
    mountpoint_facts=$(stat -c '%u:%g:%a' /var/lib/cdnca-edge-agent)
    [ "${common_facts}" = 0:0:700 ] || fail "${layout_phase}: common state root policy differs: ${common_facts}"
    [ "${active_facts}" = "${agent_uid}:${agent_gid}:700" ] || \
      fail "${layout_phase}: canonical active state policy differs: ${active_facts}"
    [ "${mountpoint_facts}" = 0:0:700 ] || \
      fail "${layout_phase}: legacy mountpoint policy differs: ${mountpoint_facts}"
    [ -z "$(find /var/lib/cdnca-edge-agent -mindepth 1 -print -quit)" ] || \
      fail "${layout_phase}: host legacy mountpoint retained state"
    for layout_child in gateway-journal deployments; do
      [ "$(stat -c '%u:%g:%a' "/var/lib/cdnca-edge-agent-backups/active-state/${layout_child}")" = "${agent_uid}:${agent_gid}:700" ] || \
        fail "${layout_phase}: ${layout_child} policy differs"
    done
    [ ! -e /var/lib/cdnca-edge-agent-packaging/layout-migration ] || \
      fail "${layout_phase}: migration journal was retained"
  }

  assert_agent_state_bind() {
    bind_phase=$1
    bind_pid=$(systemctl show -p MainPID --value cdnca-edge-agent.service)
    [ "${bind_pid}" -gt 1 ] || fail "${bind_phase}: Agent MainPID is unavailable"
    bind_source=
    bind_attempt=0
    while [ "${bind_attempt}" -lt 100 ]; do
      bind_source=$(nsenter -t "${bind_pid}" -m -- \
        findmnt -n --mountpoint /var/lib/cdnca-edge-agent -o SOURCE 2>/dev/null) && break
      bind_source=
      sleep 0.05
      bind_attempt=$((bind_attempt + 1))
    done
    [ -n "${bind_source}" ] || fail "${bind_phase}: Agent state bind is unavailable"
    case "${bind_source}" in
      *'[/var/lib/cdnca-edge-agent-backups/active-state]') ;;
      *) fail "${bind_phase}: Agent state bind source differs: ${bind_source}" ;;
    esac
    bind_marker=bind-write-${bind_phase}
    printf '%s\n' "${bind_marker}" | nsenter -t "${bind_pid}" -m -- \
      setpriv --reuid="${agent_uid}" --regid="${agent_gid}" --clear-groups --no-new-privs -- \
      tee /var/lib/cdnca-edge-agent/gateway-journal/bind-write >/dev/null
    [ "$(cat /var/lib/cdnca-edge-agent-backups/active-state/gateway-journal/bind-write)" = "${bind_marker}" ] || \
      fail "${bind_phase}: Agent write did not reach canonical active state"
  }

  snapshot_tree() {
    snapshot_root=$1
    snapshot_output=$2
    (
      cd "${snapshot_root}" || exit 1
      find . -xdev -printf '%P|%y|%m|%U|%G|%s|%l\n' | LC_ALL=C sort
      find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
    ) >"${snapshot_output}"
  }

  assert_helper_condition_blocked() {
    condition_phase=$1
    condition_state=$2
    condition_before=${workdir}/${condition_phase}.state.before
    condition_after=${workdir}/${condition_phase}.state.after
    snapshot_tree "${condition_state}" "${condition_before}"
    agent_unit_before=$(hash_file /usr/lib/systemd/system/cdnca-edge-agent.service)
    helper_unit_before=$(hash_file /usr/lib/systemd/system/cdnca-edge-agent-helper.service)

    systemctl reset-failed cdnca-edge-agent-helper.service >/dev/null 2>&1 || true
    systemctl start cdnca-edge-agent-helper.service >/dev/null 2>&1 || true
    [ "$(systemctl show -p ConditionResult --value cdnca-edge-agent-helper.service)" = no ] || \
      fail "${condition_phase}: helper condition did not fail closed"
    [ "$(systemctl show -p ActiveState --value cdnca-edge-agent-helper.service)" = inactive ] || \
      fail "${condition_phase}: helper became active"
    [ "$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)" = 0 ] || \
      fail "${condition_phase}: helper process was created"
    [ ! -e /var/lib/cdnca-edge-agent-helper/receipt-key.json ] || \
      fail "${condition_phase}: helper private key was generated"
    [ ! -e /etc/cdnca-edge-agent/helper-receipt-public.json ] || \
      fail "${condition_phase}: helper public pin was generated"
    condition_journal=$(find /var/lib/cdnca-edge-agent-helper -maxdepth 1 -name 'journal-*.json' -print -quit 2>/dev/null || :)
    [ -z "${condition_journal}" ] || fail "${condition_phase}: helper journal was generated"

    snapshot_tree "${condition_state}" "${condition_after}"
    cmp -s "${condition_before}" "${condition_after}" || fail "${condition_phase}: Agent state changed"
    [ "$(hash_file /usr/lib/systemd/system/cdnca-edge-agent.service)" = "${agent_unit_before}" ] || \
      fail "${condition_phase}: Agent unit changed"
    [ "$(hash_file /usr/lib/systemd/system/cdnca-edge-agent-helper.service)" = "${helper_unit_before}" ] || \
      fail "${condition_phase}: helper unit changed"
    systemctl stop cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket >/dev/null 2>&1 || true
  }

  sigkill_helper_cgroup() {
    sigkill_phase=$1
    sigkill_control_group=$(systemctl show -p ControlGroup --value cdnca-edge-agent-helper.service)
    case "${sigkill_control_group}" in
      */system.slice/cdnca-edge-agent-helper.service) ;;
      *) fail "${sigkill_phase}: helper control group differs: ${sigkill_control_group}" ;;
    esac
    sigkill_cgroup_procs=/sys/fs/cgroup${sigkill_control_group}/cgroup.procs
    [ -r "${sigkill_cgroup_procs}" ] || fail "${sigkill_phase}: helper cgroup process list is unavailable"
    sigkill_pids=$(tr '\n' ' ' <"${sigkill_cgroup_procs}")
    sigkill_main_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
    case " ${sigkill_pids} " in
      *" ${sigkill_main_pid} "*) ;;
      *) fail "${sigkill_phase}: helper MainPID is absent from its cgroup" ;;
    esac
    sigkill_pid_count=$(printf '%s\n' "${sigkill_pids}" | wc -w | tr -d ' ')
    [ "${sigkill_pid_count}" -ge 2 ] || fail "${sigkill_phase}: helper cgroup has no packaging child"

    systemctl kill --kill-whom=all --signal=SIGKILL cdnca-edge-agent-helper.service \
      >"${workdir}/${sigkill_phase}.systemctl-kill.log" 2>&1 || true
    systemctl stop cdnca-edge-agent-helper.service >/dev/null 2>&1 || true
    sigkill_attempt=0
    while [ "${sigkill_attempt}" -lt 100 ]; do
      sigkill_exec_code=$(systemctl show -p ExecMainCode --value cdnca-edge-agent-helper.service)
      sigkill_exec_status=$(systemctl show -p ExecMainStatus --value cdnca-edge-agent-helper.service)
      [ "${sigkill_exec_code}:${sigkill_exec_status}" = 2:9 ] && break
      sleep 0.05
      sigkill_attempt=$((sigkill_attempt + 1))
    done
    if [ "${sigkill_exec_code}:${sigkill_exec_status}" != 2:9 ]; then
      cat "${workdir}/${sigkill_phase}.systemctl-kill.log" >&2
      fail "${sigkill_phase}: systemd did not record helper SIGKILL"
    fi
    for sigkill_pid in ${sigkill_pids}; do
      sigkill_attempt=0
      while kill -0 "${sigkill_pid}" 2>/dev/null && [ "${sigkill_attempt}" -lt 100 ]; do
        sleep 0.05
        sigkill_attempt=$((sigkill_attempt + 1))
      done
      kill -0 "${sigkill_pid}" 2>/dev/null && fail "${sigkill_phase}: helper cgroup PID survived SIGKILL: ${sigkill_pid}"
    done
    sigkill_attempt=0
    while [ "${sigkill_attempt}" -lt 100 ]; do
      sigkill_active=$(systemctl show -p ActiveState --value cdnca-edge-agent-helper.service)
      sigkill_sub=$(systemctl show -p SubState --value cdnca-edge-agent-helper.service)
      sigkill_current_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
      if [ "${sigkill_active}:${sigkill_sub}:${sigkill_current_pid}" = inactive:dead:0 ]; then
        break
      fi
      sleep 0.05
      sigkill_attempt=$((sigkill_attempt + 1))
    done
    [ "${sigkill_active}:${sigkill_sub}:${sigkill_current_pid}" = inactive:dead:0 ] || \
      fail "${sigkill_phase}: helper service did not become quiescent after SIGKILL"
    sigkill_restarts=$(systemctl show -p NRestarts --value cdnca-edge-agent-helper.service)
    sleep 3
    [ "$(systemctl show -p ActiveState --value cdnca-edge-agent-helper.service)" = inactive ] && \
      [ "$(systemctl show -p SubState --value cdnca-edge-agent-helper.service)" = dead ] && \
      [ "$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)" = 0 ] && \
      [ "$(systemctl show -p NRestarts --value cdnca-edge-agent-helper.service)" = "${sigkill_restarts}" ] || \
      fail "${sigkill_phase}: helper automatic restart was not suppressed"
  }

  start_helper_stable() {
    systemctl reset-failed cdnca-edge-agent-helper.service
    systemctl start cdnca-edge-agent-helper.service
    helper_start_attempt=0
    helper_start_pid=0
    while [ "${helper_start_attempt}" -lt 100 ]; do
      helper_start_active=$(systemctl show -p ActiveState --value cdnca-edge-agent-helper.service)
      helper_start_sub=$(systemctl show -p SubState --value cdnca-edge-agent-helper.service)
      helper_start_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
      if [ "${helper_start_active}:${helper_start_sub}" = active:running ] && [ "${helper_start_pid}" -gt 1 ]; then
        break
      fi
      sleep 0.05
      helper_start_attempt=$((helper_start_attempt + 1))
    done
    [ "${helper_start_active}:${helper_start_sub}" = active:running ] && [ "${helper_start_pid}" -gt 1 ] || \
      fail "helper did not reach active/running after SIGKILL"
    sleep 0.1
    [ "$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)" = "${helper_start_pid}" ] || \
      fail "helper MainPID changed before recovery Query"
  }

  release_v1=${workdir}/v1
  release_v2=${workdir}/v2
  release_v3=${workdir}/v3
  release_v4=${workdir}/v4
  release_v5=${workdir}/v5
  release_v6=${workdir}/v6
  make_runtime_release "${release_v1}" 1.0.0 1
  make_runtime_release "${release_v2}" 1.1.0 2
  make_runtime_release "${release_v3}" 1.2.0 3
  make_runtime_release "${release_v4}" 1.3.0 4
  make_runtime_release "${release_v5}" 1.4.0 5
  make_runtime_release "${release_v6}" 1.5.0 6

  "${packaging_root}/scripts/install.sh" \
    --artifact "${release_v1}/edge-agent" \
    --sbom "${release_v1}/edge-agent.spdx.json" \
    --manifest "${release_v1}/manifest" \
    --signature "${release_v1}/manifest.sig" \
    --public-key "${release_public}"
  baseline_release_snapshot=${workdir}/baseline-release.sha256
  for baseline_file in edge-agent edge-agent.spdx.json manifest manifest.sig; do
    printf '%s  %s\n' "$(hash_file "/usr/lib/cdnca-edge-agent/versions/1.0.0/${baseline_file}")" "${baseline_file}" >>"${baseline_release_snapshot}"
  done
  install -o cdnca-edge -g cdnca-edge -m 0600 "${packaging_root}/config/config.example.json" /etc/cdnca-edge-agent/config.json
  baseline_config_digest=$(hash_file /etc/cdnca-edge-agent/config.json)
  install -o root -g root -m 0755 /task/cdnca-edge-agent-helper /usr/libexec/cdnca-edge-agent-helper
  install -o root -g root -m 0644 "${packaging_root}/systemd/cdnca-edge-agent-helper.service" /usr/lib/systemd/system/cdnca-edge-agent-helper.service
  install -o root -g root -m 0644 "${packaging_root}/systemd/cdnca-edge-agent-helper.socket" /usr/lib/systemd/system/cdnca-edge-agent-helper.socket
  upgrade_script=/usr/libexec/cdnca-edge-agent/upgrade.sh
  upgrade_backup=${workdir}/upgrade.sh.production
  install -o root -g root -m 0555 "${upgrade_script}" "${upgrade_backup}"
  for candidate_bundle in \
    "${release_v2}/release.bundle" \
    "${release_v3}/release.bundle" \
    "${release_v4}/release.bundle" \
    "${release_v5}/release.bundle" \
    "${release_v6}/release.bundle"; do
    chown "${agent_uid}:${agent_gid}" "${candidate_bundle}"
    chmod 0400 "${candidate_bundle}"
  done
  bundle_digest=$(hash_file "${release_v2}/release.bundle")
  bundle_size=$(stat -c '%s' "${release_v2}/release.bundle")
  bundle_v1_digest=$(hash_file "${release_v1}/release.bundle")
  manifest_v1_digest=$(hash_file "${release_v1}/manifest")
  bundle_v3_digest=$(hash_file "${release_v3}/release.bundle")
  bundle_v3_size=$(stat -c '%s' "${release_v3}/release.bundle")
  bundle_v4_digest=$(hash_file "${release_v4}/release.bundle")
  bundle_v4_size=$(stat -c '%s' "${release_v4}/release.bundle")
  inner_v3_digest=$(hash_file "${release_v3}/edge-agent")
  inner_v4_digest=$(hash_file "${release_v4}/edge-agent")
  bundle_v5_digest=$(hash_file "${release_v5}/release.bundle")
  bundle_v5_size=$(stat -c '%s' "${release_v5}/release.bundle")
  bundle_v6_digest=$(hash_file "${release_v6}/release.bundle")
  bundle_v6_size=$(stat -c '%s' "${release_v6}/release.bundle")

  runtime_units_started=true
  systemctl daemon-reload
  assert_canonical_state_layout fresh-install
  systemctl start cdnca-edge-agent.service
  systemctl is-active --quiet cdnca-edge-agent.service || fail "baseline agent is not active"
  assert_agent_state_bind fresh-install
  [ "$(getent passwd cdnca-edge | awk -F: '{print $6}')" = /var/lib/cdnca-edge-agent ] || fail "service account home changed"
  agent_pid=$(systemctl show -p MainPID --value cdnca-edge-agent.service)
  agent_arguments=$(tr '\000' '\n' <"/proc/${agent_pid}/cmdline")
  expected_agent_arguments=$(printf '%s\n%s\n%s' \
    /usr/lib/cdnca-edge-agent/current/edge-agent -config /etc/cdnca-edge-agent/config.json)
  [ "${agent_arguments}" = "${expected_agent_arguments}" ] || fail "fresh Agent arguments changed"

  systemctl stop cdnca-edge-agent.service
  legacy_unit=${workdir}/legacy-edge-agent.service
  sed '/^BindPaths=\/var\/lib\/cdnca-edge-agent-backups\/active-state:/d' \
    /usr/lib/systemd/system/cdnca-edge-agent.service >"${legacy_unit}"
  install -o root -g root -m 0644 "${legacy_unit}" /usr/lib/systemd/system/cdnca-edge-agent.service
  rmdir /var/lib/cdnca-edge-agent
  mv /var/lib/cdnca-edge-agent-backups/active-state /var/lib/cdnca-edge-agent
  sync -f /var/lib/cdnca-edge-agent-backups
  sync -f /var/lib
  systemctl daemon-reload
  systemctl start cdnca-edge-agent.service
  systemctl is-active --quiet cdnca-edge-agent.service || fail "legacy baseline agent is not active"
  [ -f /var/lib/cdnca-edge-agent/gateway-journal/bind-write ] || fail "legacy conversion lost Agent state"
  assert_absent_text 'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:' /usr/lib/systemd/system/cdnca-edge-agent.service
  assert_helper_condition_blocked legacy-layout /var/lib/cdnca-edge-agent

  /usr/libexec/cdnca-edge-agent/upgrade.sh \
    --artifact "${release_v1}/edge-agent" \
    --sbom "${release_v1}/edge-agent.spdx.json" \
    --manifest "${release_v1}/manifest" \
    --signature "${release_v1}/manifest.sig" \
    --public-key "${release_public}" \
    --health-timeout 15 \
    --health-stable 1
  assert_canonical_state_layout legacy-migration
  assert_agent_state_bind legacy-migration
  assert_line 'BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind' \
    /usr/lib/systemd/system/cdnca-edge-agent.service
  [ "$(hash_file /etc/cdnca-edge-agent/config.json)" = "${baseline_config_digest}" ] || fail "legacy migration changed config bytes"
  while read -r expected_digest baseline_file; do
    [ "$(hash_file "/usr/lib/cdnca-edge-agent/versions/1.0.0/${baseline_file}")" = "${expected_digest}" ] || \
      fail "legacy migration changed old release bytes: ${baseline_file}"
  done <"${baseline_release_snapshot}"
  [ -f /var/lib/cdnca-edge-agent-backups/active-state/gateway-journal/bind-write ] || fail "legacy migration lost gateway journal state"
  [ -d /var/lib/cdnca-edge-agent-backups/active-state/deployments ] || fail "legacy migration lost deployments state"

  completed_state_before=${workdir}/completed.state.before
  completed_state_after=${workdir}/completed.state.after
  snapshot_tree /var/lib/cdnca-edge-agent-backups/active-state "${completed_state_before}"
  mountpoint_before=$(stat -c '%d:%i:%u:%g:%a' /var/lib/cdnca-edge-agent)
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/cdnca-edge-agent.conf
  snapshot_tree /var/lib/cdnca-edge-agent-backups/active-state "${completed_state_after}"
  cmp -s "${completed_state_before}" "${completed_state_after}" || fail "tmpfiles rerun changed canonical active state"
  [ "$(stat -c '%d:%i:%u:%g:%a' /var/lib/cdnca-edge-agent)" = "${mountpoint_before}" ] || \
    fail "tmpfiles rerun changed the completed bind mountpoint"
  assert_canonical_state_layout tmpfiles-rerun

  install -d -o root -g root -m 0700 /var/lib/cdnca-edge-agent-packaging
  : >/var/lib/cdnca-edge-agent-packaging/layout-migration
  chmod 0600 /var/lib/cdnca-edge-agent-packaging/layout-migration
  migration_gate_created=true
  assert_helper_condition_blocked migration-pending /var/lib/cdnca-edge-agent-backups/active-state
  rm -f -- /var/lib/cdnca-edge-agent-packaging/layout-migration
  migration_gate_created=false

  systemctl enable --now cdnca-edge-agent-helper.socket
  socket_facts=$(stat -c '%U:%G:%a:%F' /run/cdnca-edge-agent/helper.sock)
  [ "${socket_facts}" = 'cdnca-edge:cdnca-edge:600:socket' ] || fail "socket facts differ: ${socket_facts}"
  directory_mode=$(stat -c '%a' /run/cdnca-edge-agent)
  [ "${directory_mode}" = 711 ] || fail "socket directory mode differs: ${directory_mode}"

  client=${workdir}/client.py
  cat >"${client}" <<'PYTHON'
import array
import json
import os
import os
import socket
import sys
import time

SOCKET = "/run/cdnca-edge-agent/helper.sock"

def packet(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def exchange(raw, artifact=None, lose=False, extra=False, writable=False, ready_marker=None):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(310)
    connection.connect(SOCKET)
    descriptors = []
    ancillary = []
    if artifact is not None:
        descriptors.append(os.open(artifact, os.O_RDWR if writable else os.O_RDONLY))
        if extra:
            descriptors.append(os.open(artifact, os.O_RDONLY))
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))]
    if ready_marker is not None:
        open(ready_marker, "w", encoding="ascii").close()
        time.sleep(1)
    try:
        connection.sendmsg([raw], ancillary)
        connection.shutdown(socket.SHUT_WR)
        if lose:
            return None
        response = connection.recv(32768)
        return json.loads(response)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        connection.close()

def exchange_read_only(raw):
    delay = 0.05
    for attempt in range(6):
        try:
            return exchange(raw)
        except (ConnectionResetError, BrokenPipeError):
            if attempt == 5:
                raise
            time.sleep(delay)
            delay *= 2

command = sys.argv[1]
if command == "current":
    request = {"protocol_version": 1, "operation": "current"}
    print(json.dumps(exchange_read_only(packet(request)), separators=(",", ":")))
elif command == "install":
    current = json.load(open(sys.argv[2], encoding="utf-8"))["receipt"]
    request = {
        "protocol_version": 1, "operation": "install", "transaction_id": sys.argv[4],
        "release_sequence": int(sys.argv[5]), "current_version": current["current_version"],
        "target_version": sys.argv[6],
        "platform": "linux", "architecture": os.environ["RUNTIME_ARCH"],
        "artifact_sha256": sys.argv[7], "artifact_size": int(sys.argv[8]),
        "audit_basename": "release.bundle", "current_receipt": current,
    }
    raw = packet(request)
    if sys.argv[10] != "-":
        open(sys.argv[10], "wb").write(raw)
    delivery = sys.argv[9]
    ready_marker = sys.argv[11] if delivery == "delay" else None
    response = exchange(raw, sys.argv[3], delivery == "lose", delivery == "extra", delivery == "writable", ready_marker)
    if response is not None:
        print(json.dumps(response, separators=(",", ":")))
elif command == "query":
    request = {"protocol_version": 1, "operation": "query", "transaction_id": sys.argv[2]}
    print(json.dumps(exchange_read_only(packet(request)), separators=(",", ":")))
elif command == "rollback":
    previous = json.load(open(sys.argv[2], encoding="utf-8"))["receipt"]
    active = json.load(open(sys.argv[3], encoding="utf-8"))["receipt"]
    request = {
        "protocol_version": 1, "operation": "rollback", "transaction_id": "txn-runtime-2",
        "release_sequence": 2, "artifact_sha256": os.environ["BUNDLE_DIGEST"],
        "expected_current_version": "1.1.0", "rollback_version": "1.0.0",
        "active_receipt": active, "previous_receipt": previous,
    }
    print(json.dumps(exchange(packet(request)), separators=(",", ":")))
elif command == "hold":
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.connect(SOCKET)
    try:
        time.sleep(30)
    finally:
        connection.close()
else:
    raise SystemExit(64)
PYTHON
  chown "${agent_uid}:${agent_gid}" "${client}"
  chmod 0555 "${client}"
  client_state=${workdir}/client-state
  mkdir "${client_state}"
  chown "${agent_uid}:${agent_gid}" "${client_state}"
  client_command="setpriv --reuid=${agent_uid} --regid=${agent_gid} --clear-groups --no-new-privs -- env -i PATH=/usr/bin:/bin RUNTIME_ARCH=${runtime_arch} BUNDLE_DIGEST=${bundle_digest} BUNDLE_SIZE=${bundle_size} python3 ${client}"

  verifier=${workdir}/verify-receipt.py
  cat >"${verifier}" <<'PYTHON'
import base64
import json
import os
import subprocess
import sys

response_path, pin_path, output_directory, label = sys.argv[1:]
response = json.load(open(response_path, encoding="utf-8"))
pin = json.load(open(pin_path, encoding="utf-8"))
receipt = response["receipt"]
if not response.get("ok") or receipt["signature"]["key_id"] != pin["key_id"]:
    raise SystemExit("receipt public pin mismatch")

def raw_base64(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)

public_key = raw_base64(pin["public_key"])
signature = raw_base64(receipt["signature"]["value"])
if len(public_key) != 32 or len(signature) != 64:
    raise SystemExit("receipt key or signature length differs")

signable = {
    "schema_version": receipt["schema_version"],
    "installer_transaction_id": receipt["installer_transaction_id"],
    "release_sequence": receipt["release_sequence"],
    "artifact_sha256": receipt["artifact_sha256"],
    "current_version": receipt["current_version"],
}
if receipt.get("previous_version"):
    signable["previous_version"] = receipt["previous_version"]
signable["status"] = receipt["status"]
signable["issued_at"] = receipt["issued_at"]
signable["key_id"] = receipt["signature"]["key_id"]

prefix = os.path.join(output_directory, label)
open(prefix + ".signing", "wb").write(json.dumps(signable, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
open(prefix + ".sig", "wb").write(signature)
open(prefix + ".der", "wb").write(bytes.fromhex("302a300506032b6570032100") + public_key)
subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", prefix + ".der", "-out", prefix + ".pem"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", prefix + ".pem", "-rawin", "-in", prefix + ".signing", "-sigfile", prefix + ".sig"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
PYTHON
  chown "${agent_uid}:${agent_gid}" "${verifier}"
  chmod 0500 "${verifier}"

  verify_receipt() {
    response_path=$1
    label=$2
    setpriv --reuid="${agent_uid}" --regid="${agent_gid}" --clear-groups --no-new-privs -- \
      env -i PATH=/usr/bin:/bin python3 "${verifier}" "${response_path}" \
      /etc/cdnca-edge-agent/helper-receipt-public.json "${client_state}" "${label}"
  }

  assert_private_tmp_clean() {
    target_pid=$1
    phase=$2
    leftovers=$(nsenter -t "${target_pid}" -m -- find /tmp -maxdepth 1 -type d -name 'cdnca-edge-agent-helper-*' -print)
    [ -z "${leftovers}" ] || fail "PrivateTmp handoff remained after ${phase}: ${leftovers}"
  }

  current_transaction_id() {
    manifest_digest=$1
    current_version=$2
    current_sequence=$3
    current_digest=$(printf '%s\000%s\000%s' "${manifest_digest}" "${current_version}" "${current_sequence}" | sha256sum | awk '{print $1}')
    printf 'current-%s\n' "$(printf '%s' "${current_digest}" | cut -c 1-32)"
  }

  # A fresh client process is used for each step, exercising Agent restart/reconnect semantics.
  sh -c "${client_command} current" >"${client_state}/current.json"
  expected_current_v1_seq1=$(current_transaction_id "${manifest_v1_digest}" 1.0.0 1)
  jq -e --arg tx "${expected_current_v1_seq1}" --arg digest "${bundle_v1_digest}" \
    '.ok == true and .receipt.installer_transaction_id == $tx and .receipt.release_sequence == 1 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.0.0" and .receipt.previous_version == null and .receipt.status == "active"' \
    "${client_state}/current.json" >/dev/null || fail "baseline Current response differs"
  verify_receipt "${client_state}/current.json" current
  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  [ "${helper_pid}" -gt 1 ] || fail "helper MainPID is unavailable for mount-boundary inspection"
  if nsenter -t "${helper_pid}" -m -- touch /var/lib/cdnca-edge-agent/helper-must-not-write 2>/dev/null; then
    rm -f -- /var/lib/cdnca-edge-agent/helper-must-not-write
    fail "helper mount namespace can write the legacy Agent state view"
  fi
  if nsenter -t "${helper_pid}" -m -- touch /var/lib/helper-must-not-write 2>/dev/null; then
    rm -f -- /var/lib/helper-must-not-write
    fail "helper mount namespace has broad /var/lib write access"
  fi
  nsenter -t "${helper_pid}" -m -- sh -c \
    'touch /var/lib/cdnca-edge-agent-backups/.helper-write-check && rm -f /var/lib/cdnca-edge-agent-backups/.helper-write-check'
  helper_cap_bnd=$(awk '/^CapBnd:/ { print $2 }' "/proc/${helper_pid}/status")
  python3 - "${helper_cap_bnd}" <<'PYTHON'
import sys
if int(sys.argv[1], 16) & (1 << 21):
    raise SystemExit("helper retains CAP_SYS_ADMIN")
PYTHON

  wrong_gid=65534
  [ "${agent_gid}" != "${wrong_gid}" ] || wrong_gid=65533
  setpriv --reuid="${agent_uid}" --regid="${wrong_gid}" --clear-groups --no-new-privs -- \
    env -i PATH=/usr/bin:/bin RUNTIME_ARCH="${runtime_arch}" python3 "${client}" current \
    >"${client_state}/wrong-gid.json"
  jq -e '.ok == false and .error_code == "ERR_UNAUTHORIZED"' "${client_state}/wrong-gid.json" >/dev/null || fail "wrong peer GID was not rejected"
  if setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs -- \
    env -i PATH=/usr/bin:/bin RUNTIME_ARCH="${runtime_arch}" python3 "${client}" current \
    >"${client_state}/wrong-uid.json" 2>"${client_state}/wrong-uid.log"; then
    fail "wrong peer UID connected to the 0600 helper socket"
  fi

  probe=${workdir}/probe.py
  cat >"${probe}" <<'PYTHON'
import os
import socket
import sys
import time
while True:
    started = time.monotonic_ns() // 1_000_000
    ok = 0
    try:
        connection = socket.create_connection(("127.0.0.1", 18091), 0.2)
        ok = 1 if connection.recv(64) else 0
        connection.close()
    except OSError:
        pass
    finished = time.monotonic_ns() // 1_000_000
    if ok or os.path.exists("/run/cdnca-ops0611-probe-started"):
        open("/run/cdnca-ops0611-probe-started", "a").close()
        print(f"{started} {finished} {ok}", flush=True)
        if ok and os.path.exists("/run/cdnca-ops0611-probe-stop"):
            break
    time.sleep(0.02)
PYTHON
  rm -f -- /run/cdnca-ops0611-probe-started /run/cdnca-ops0611-probe-stop
  python3 "${probe}" >"${workdir}/traffic.log" 2>&1 &
  probe_pid=$!
  probe_attempt=0
  while [ ! -s "${workdir}/traffic.log" ] && [ "${probe_attempt}" -lt 100 ]; do
    sleep 0.1
    probe_attempt=$((probe_attempt + 1))
  done
  [ -s "${workdir}/traffic.log" ] || fail "traffic probe did not record an initial success"
  [ "$(awk 'NR == 1 { print $3 }' "${workdir}/traffic.log")" = 1 ] || fail "traffic probe first sample was not successful"

  sigkill_before_upgrade=${workdir}/upgrade-sigkill-before.sh
  cat >"${sigkill_before_upgrade}" <<'SH'
#!/bin/sh
set -eu
[ "$#" -eq 10 ] && [ "$1" = --artifact ] && [ "$3" = --sbom ] && \
  [ "$5" = --manifest ] && [ "$7" = --signature ] && [ "$9" = --public-key ] || exit 90
case "$2" in
  /tmp/cdnca-edge-agent-helper-*/handoff/edge-agent) ;;
  *) exit 91 ;;
esac
printf '%s\n' "${2%/edge-agent}" >/run/cdnca-ops0611-sigkill-before-handoff
sleep 300
SH
  chmod 0555 "${sigkill_before_upgrade}"
  rm -f -- /run/cdnca-ops0611-sigkill-before-handoff \
    /run/cdnca-ops0611-sigkill-inspect /run/cdnca-ops0611-sigkill-nsenter-ready
  install -o root -g root -m 0555 "${sigkill_before_upgrade}" "${upgrade_script}"
  upgrade_replaced=true
  sh -c "${client_command} install ${client_state}/current.json ${release_v2}/release.bundle txn-runtime-2 2 1.1.0 ${bundle_digest} ${bundle_size} respond ${client_state}/install.packet" \
    >"${client_state}/sigkill-before.json" 2>"${client_state}/sigkill-before.log" &
  sigkill_client_pid=$!
  sigkill_attempt=0
  while [ ! -s /run/cdnca-ops0611-sigkill-before-handoff ] && [ "${sigkill_attempt}" -lt 100 ]; do
    sleep 0.1
    sigkill_attempt=$((sigkill_attempt + 1))
  done
  [ -s /run/cdnca-ops0611-sigkill-before-handoff ] || fail "pre-activation SIGKILL fixture did not observe a handoff"
  jq -e '.phase == "installing" and .transaction_id == "txn-runtime-2"' \
    /var/lib/cdnca-edge-agent-helper/journal-txn-runtime-2.json >/dev/null || \
    fail "pre-activation SIGKILL journal was not installing"
  [ "$(readlink /usr/lib/cdnca-edge-agent/current)" = versions/1.0.0 ] || \
    fail "pre-activation SIGKILL fixture activated the candidate"
  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  sigkill_namespace_result=${workdir}/sigkill-before-namespace-leftovers
  nsenter -t "${helper_pid}" -m -- sh -c \
    'touch /run/cdnca-ops0611-sigkill-nsenter-ready; while [ ! -e /run/cdnca-ops0611-sigkill-inspect ]; do sleep 0.05; done; find /tmp -maxdepth 1 -type d -name "cdnca-edge-agent-helper-*" -print' \
    >"${sigkill_namespace_result}" &
  sigkill_namespace_pid=$!
  sigkill_attempt=0
  while [ ! -e /run/cdnca-ops0611-sigkill-nsenter-ready ] && [ "${sigkill_attempt}" -lt 100 ]; do
    kill -0 "${sigkill_namespace_pid}" 2>/dev/null || fail "pre-activation PrivateTmp observer exited before ready"
    sleep 0.1
    sigkill_attempt=$((sigkill_attempt + 1))
  done
  [ -e /run/cdnca-ops0611-sigkill-nsenter-ready ] || fail "pre-activation PrivateTmp observer did not become ready"
  sigkill_helper_cgroup sigkill-before
  if wait "${sigkill_client_pid}"; then
    fail "pre-activation SIGKILL unexpectedly returned a response"
  fi
  sigkill_client_pid=
  touch /run/cdnca-ops0611-sigkill-inspect
  wait "${sigkill_namespace_pid}"
  sigkill_namespace_pid=
  [ ! -s "${sigkill_namespace_result}" ] || fail "pre-activation SIGKILL retained a PrivateTmp handoff"
  install -o root -g root -m 0555 "${upgrade_backup}" "${upgrade_script}"
  upgrade_replaced=false
  start_helper_stable
  sh -c "${client_command} query txn-runtime-2" >"${client_state}/active.json"
  if ! jq -e --arg digest "${bundle_digest}" \
    '.ok == true and .receipt.installer_transaction_id == "txn-runtime-2" and .receipt.release_sequence == 2 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.1.0" and .receipt.previous_version == "1.0.0" and .receipt.status == "active"' \
    "${client_state}/active.json" >/dev/null; then
    cat "${client_state}/active.json" >&2
    fail "pre-activation SIGKILL Query did not recover active receipt"
  fi
  verify_receipt "${client_state}/active.json" query-active
  assert_canonical_state_layout helper-install
  assert_agent_state_bind helper-install
  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  assert_private_tmp_clean "${helper_pid}" sigkill-before-recovery
  rm -f -- /run/cdnca-ops0611-sigkill-before-handoff \
    /run/cdnca-ops0611-sigkill-inspect /run/cdnca-ops0611-sigkill-nsenter-ready

  tampered_bundle=${workdir}/same-size-tampered.bundle
  cp "${release_v3}/release.bundle" "${tampered_bundle}"
  chown "${agent_uid}:${agent_gid}" "${tampered_bundle}"
  chmod 0600 "${tampered_bundle}"
  printf 'X' | dd of="${tampered_bundle}" bs=1 seek=0 conv=notrunc status=none
  chmod 0400 "${tampered_bundle}"
  [ "$(stat -c '%s' "${tampered_bundle}")" = "${bundle_v3_size}" ] || fail "tampered bundle size changed"
  [ "$(hash_file "${tampered_bundle}")" != "${bundle_v3_digest}" ] || fail "tampered bundle digest did not change"
  sh -c "${client_command} install ${client_state}/active.json ${tampered_bundle} txn-runtime-tamper 3 1.2.0 ${bundle_v3_digest} ${bundle_v3_size} respond -" \
    >"${client_state}/tamper.json"
  jq -e '.ok == false and .error_code == "ERR_ARTIFACT_MISMATCH"' "${client_state}/tamper.json" >/dev/null || fail "same-size artifact tamper was not rejected"

  sh -c "${client_command} install ${client_state}/active.json ${release_v3}/release.bundle txn-runtime-extra-fd 3 1.2.0 ${bundle_v3_digest} ${bundle_v3_size} extra -" \
    >"${client_state}/extra-fd.json"
  jq -e '.ok == false and .error_code == "ERR_FD_UNSAFE"' "${client_state}/extra-fd.json" >/dev/null || fail "extra SCM_RIGHTS descriptor was not rejected"

  writable_bundle=${workdir}/writable.bundle
  cp "${release_v3}/release.bundle" "${writable_bundle}"
  chown "${agent_uid}:${agent_gid}" "${writable_bundle}"
  chmod 0600 "${writable_bundle}"
  sh -c "${client_command} install ${client_state}/active.json ${writable_bundle} txn-runtime-writable-fd 3 1.2.0 ${bundle_v3_digest} ${bundle_v3_size} writable -" \
    >"${client_state}/writable-fd.json"
  jq -e '.ok == false and .error_code == "ERR_FD_UNSAFE"' "${client_state}/writable-fd.json" >/dev/null || fail "writable artifact descriptor was not rejected"

  opened_bundle=${workdir}/opened-then-tampered.bundle
  opened_marker=${client_state}/artifact-opened
  cp "${release_v3}/release.bundle" "${opened_bundle}"
  chown "${agent_uid}:${agent_gid}" "${opened_bundle}"
  chmod 0400 "${opened_bundle}"
  rm -f -- "${opened_marker}"
  sh -c "${client_command} install ${client_state}/active.json ${opened_bundle} txn-runtime-open-tamper 3 1.2.0 ${bundle_v3_digest} ${bundle_v3_size} delay - ${opened_marker}" \
    >"${client_state}/opened-tamper.json" &
  delay_client_pid=$!
  open_attempt=0
  while [ ! -e "${opened_marker}" ] && [ "${open_attempt}" -lt 100 ]; do
    sleep 0.05
    open_attempt=$((open_attempt + 1))
  done
  [ -e "${opened_marker}" ] || fail "Agent did not open artifact before TOCTOU mutation"
  chmod 0600 "${opened_bundle}"
  printf 'X' | dd of="${opened_bundle}" bs=1 seek=0 conv=notrunc status=none
  chmod 0400 "${opened_bundle}"
  wait "${delay_client_pid}"
  delay_client_pid=
  jq -e '.ok == false and .error_code == "ERR_ARTIFACT_MISMATCH"' "${client_state}/opened-tamper.json" >/dev/null || fail "opened artifact byte tamper was not rejected"
  sh -c "${client_command} install ${client_state}/current.json ${release_v2}/release.bundle txn-runtime-2 2 1.1.0 ${bundle_digest} ${bundle_size} respond ${client_state}/replay.packet" >"${client_state}/replay.json"
  cmp -s "${client_state}/active.json" "${client_state}/replay.json" || fail "same-payload install replay was not idempotent"
  cmp -s "${client_state}/install.packet" "${client_state}/replay.packet" || fail "install replay packet bytes differ"
  verify_receipt "${client_state}/replay.json" install-replay

  systemctl restart cdnca-edge-agent-helper.service
  sh -c "${client_command} query txn-runtime-2" >"${client_state}/restart-query.json"
  cmp -s "${client_state}/active.json" "${client_state}/restart-query.json" || fail "helper restart changed persisted Query receipt"
  verify_receipt "${client_state}/restart-query.json" restart-query

  query_pids=
  query_index=0
  while [ "${query_index}" -lt 12 ]; do
    sh -c "${client_command} query txn-runtime-2" >"${client_state}/concurrent-query-${query_index}.json" &
    query_pids="${query_pids} $!"
    query_index=$((query_index + 1))
  done
  for query_pid in ${query_pids}; do
    wait "${query_pid}"
  done
  query_index=0
  while [ "${query_index}" -lt 12 ]; do
    cmp -s "${client_state}/active.json" "${client_state}/concurrent-query-${query_index}.json" || fail "concurrent Query ${query_index} differed"
    query_index=$((query_index + 1))
  done

  query_samples=${workdir}/query-ms
  : >"${query_samples}"
  query_index=0
  while [ "${query_index}" -lt 100 ]; do
    query_started=$(date +%s%N)
    sh -c "${client_command} query txn-runtime-2" >/dev/null
    query_finished=$(date +%s%N)
    printf '%s\n' "$(((query_finished - query_started) / 1000000))" >>"${query_samples}"
    query_index=$((query_index + 1))
  done
  query_p95=$(sort -n "${query_samples}" | sed -n '95p')
  replay_index=0
  install_started=$(date +%s%N)
  while [ "${replay_index}" -lt 10 ]; do
    sh -c "${client_command} install ${client_state}/current.json ${release_v2}/release.bundle txn-runtime-2 2 1.1.0 ${bundle_digest} ${bundle_size} respond ${client_state}/replay.packet" >/dev/null
    replay_index=$((replay_index + 1))
  done
  install_finished=$(date +%s%N)

  sh -c "${client_command} rollback ${client_state}/current.json ${client_state}/active.json" >"${client_state}/rolled-back.json"
  if ! jq -e --arg digest "${bundle_digest}" \
    '.ok == true and .receipt.installer_transaction_id == "txn-runtime-2" and .receipt.release_sequence == 2 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.0.0" and .receipt.previous_version == "1.1.0" and .receipt.status == "rolled_back"' \
    "${client_state}/rolled-back.json" >/dev/null; then
    cat "${client_state}/rolled-back.json" >&2
    fail "Rollback receipt differs"
  fi
  verify_receipt "${client_state}/rolled-back.json" rollback
  sh -c "${client_command} current" >"${client_state}/restored-current.json"
  expected_current_v1_seq2=$(current_transaction_id "${manifest_v1_digest}" 1.0.0 2)
  jq -e --arg tx "${expected_current_v1_seq2}" --arg digest "${bundle_v1_digest}" \
    '.ok == true and .receipt.installer_transaction_id == $tx and .receipt.release_sequence == 2 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.0.0" and .receipt.previous_version == "1.1.0" and .receipt.status == "active"' \
    "${client_state}/restored-current.json" >/dev/null || fail "Current did not preserve release high-water mark after rollback"
  verify_receipt "${client_state}/restored-current.json" restored-current
  assert_canonical_state_layout helper-rollback
  assert_agent_state_bind helper-rollback

  failing_upgrade=${workdir}/upgrade-failure.sh
  cat >"${failing_upgrade}" <<'SH'
#!/bin/sh
set -eu
[ "$#" -eq 10 ] && [ "$1" = --artifact ] && [ "$3" = --sbom ] && \
  [ "$5" = --manifest ] && [ "$7" = --signature ] && [ "$9" = --public-key ] || exit 90
case "$2" in
  /tmp/cdnca-edge-agent-helper-*/handoff/edge-agent) ;;
  *) exit 91 ;;
esac
printf '%s %s\n' "${2%/edge-agent}" "$(sha256sum "$2" | awk '{print $1}')" >>/run/cdnca-ops0611-concurrent-handoffs
sleep 5
exit 1
SH
  chmod 0555 "${failing_upgrade}"
  rm -f -- /run/cdnca-ops0611-concurrent-handoffs
  install -o root -g root -m 0555 "${failing_upgrade}" "${upgrade_script}"
  upgrade_replaced=true

  sh -c "${client_command} install ${client_state}/restored-current.json ${release_v3}/release.bundle txn-runtime-failure-3 3 1.2.0 ${bundle_v3_digest} ${bundle_v3_size} respond -" \
    >"${client_state}/failure-3.json" &
  failure_pid_3=$!
  concurrent_attempt=0
  while [ ! -s /run/cdnca-ops0611-concurrent-handoffs ] && [ "${concurrent_attempt}" -lt 100 ]; do
    sleep 0.05
    concurrent_attempt=$((concurrent_attempt + 1))
  done
  [ -s /run/cdnca-ops0611-concurrent-handoffs ] || fail "first concurrent handoff was not observed"
  [ "$(sed -n '1s/^.* //p' /run/cdnca-ops0611-concurrent-handoffs)" = "${inner_v3_digest}" ] || \
    fail "first concurrent handoff did not bind txn-runtime-failure-3 to v3"
  sh -c "${client_command} install ${client_state}/restored-current.json ${release_v4}/release.bundle txn-runtime-failure-4 4 1.3.0 ${bundle_v4_digest} ${bundle_v4_size} respond -" \
    >"${client_state}/failure-4.json" &
  failure_pid_4=$!
  wait "${failure_pid_3}"
  wait "${failure_pid_4}"
  failure_pid_3=
  failure_pid_4=
  jq -e --arg digest "${bundle_v3_digest}" \
    '.ok == true and .receipt.installer_transaction_id == "txn-runtime-failure-3" and .receipt.release_sequence == 3 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.0.0" and .receipt.previous_version == "1.2.0" and .receipt.status == "rolled_back"' \
    "${client_state}/failure-3.json" >/dev/null || fail "first concurrent install rollback receipt differs"
  jq -e '.ok == false and .error_code == "ERR_TRANSACTION_CONFLICT"' \
    "${client_state}/failure-4.json" >/dev/null || fail "stale concurrent install was not rejected"
  [ "$(wc -l </run/cdnca-ops0611-concurrent-handoffs | tr -d ' ')" = 1 ] || \
    fail "stale concurrent install entered packaging"

  sh -c "${client_command} current" >"${client_state}/current-after-failure-3.json"
  sh -c "${client_command} install ${client_state}/current-after-failure-3.json ${release_v4}/release.bundle txn-runtime-failure-4 4 1.3.0 ${bundle_v4_digest} ${bundle_v4_size} respond -" \
    >"${client_state}/failure-4-retry.json"
  jq -e --arg digest "${bundle_v4_digest}" \
    '.ok == true and .receipt.installer_transaction_id == "txn-runtime-failure-4" and .receipt.release_sequence == 4 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.0.0" and .receipt.previous_version == "1.3.0" and .receipt.status == "rolled_back"' \
    "${client_state}/failure-4-retry.json" >/dev/null || fail "refreshed concurrent install rollback receipt differs"
  [ "$(sort -u /run/cdnca-ops0611-concurrent-handoffs | wc -l | tr -d ' ')" = 2 ] || fail "concurrent install attempts reused a handoff"
  [ "$(sed -n '2s/^.* //p' /run/cdnca-ops0611-concurrent-handoffs)" = "${inner_v4_digest}" ] || \
    fail "second concurrent handoff did not bind txn-runtime-failure-4 to v4"
  observed_inner_digests=$(awk '{print $2}' /run/cdnca-ops0611-concurrent-handoffs | sort -u)
  expected_inner_digests=$(printf '%s\n%s\n' "${inner_v3_digest}" "${inner_v4_digest}" | sort -u)
  [ "${observed_inner_digests}" = "${expected_inner_digests}" ] || fail "concurrent handoff content crossed transactions"
  jq -e --arg outer "${bundle_v3_digest}" --arg inner "${inner_v3_digest}" \
    '.transaction_id == "txn-runtime-failure-3" and .release_sequence == 3 and .outer_artifact_sha256 == $outer and .executable_sha256 == $inner and .target_version == "1.2.0"' \
    /var/lib/cdnca-edge-agent-helper/journal-txn-runtime-failure-3.json >/dev/null || fail "v3 failure journal facts differ"
  jq -e --arg outer "${bundle_v4_digest}" --arg inner "${inner_v4_digest}" \
    '.transaction_id == "txn-runtime-failure-4" and .release_sequence == 4 and .outer_artifact_sha256 == $outer and .executable_sha256 == $inner and .target_version == "1.3.0"' \
    /var/lib/cdnca-edge-agent-helper/journal-txn-runtime-failure-4.json >/dev/null || fail "v4 failure journal facts differ"
  sh -c "${client_command} current" >"${client_state}/current-after-failure-4.json"
  while IFS=' ' read -r handoff_path handoff_digest; do
    case "${handoff_path}" in
      /tmp/cdnca-edge-agent-helper-*/handoff) ;;
      *) fail "concurrent handoff path escaped fixed PrivateTmp prefix" ;;
    esac
    [ -n "${handoff_digest}" ] || fail "concurrent handoff digest is missing"
    [ ! -e "${handoff_path}" ] || fail "failed install handoff remained: ${handoff_path}"
  done </run/cdnca-ops0611-concurrent-handoffs
  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  assert_private_tmp_clean "${helper_pid}" failure

  cancelling_upgrade=${workdir}/upgrade-cancel.sh
  cat >"${cancelling_upgrade}" <<'SH'
#!/bin/sh
set -eu
[ "$#" -eq 10 ] && [ "$1" = --artifact ] && [ "$3" = --sbom ] && \
  [ "$5" = --manifest ] && [ "$7" = --signature ] && [ "$9" = --public-key ] || exit 90
case "$2" in
  /tmp/cdnca-edge-agent-helper-*/handoff/edge-agent) ;;
  *) exit 91 ;;
esac
printf '%s\n' "${2%/edge-agent}" >/run/cdnca-ops0611-cancel-handoff
sleep 300
SH
  chmod 0555 "${cancelling_upgrade}"
  rm -f -- /run/cdnca-ops0611-cancel-handoff /run/cdnca-ops0611-inspect-cancel /run/cdnca-ops0611-nsenter-ready
  install -o root -g root -m 0555 "${cancelling_upgrade}" "${upgrade_script}"
  sh -c "${client_command} install ${client_state}/current-after-failure-4.json ${release_v5}/release.bundle txn-runtime-cancel-5 5 1.4.0 ${bundle_v5_digest} ${bundle_v5_size} respond -" \
    >"${client_state}/cancel.json" 2>"${client_state}/cancel.log" &
  cancel_client_pid=$!
  cancel_attempt=0
  while [ ! -s /run/cdnca-ops0611-cancel-handoff ] && [ "${cancel_attempt}" -lt 100 ]; do
    sleep 0.1
    cancel_attempt=$((cancel_attempt + 1))
  done
  [ -s /run/cdnca-ops0611-cancel-handoff ] || fail "cancel fixture did not observe a handoff"
  cancel_handoff=$(cat /run/cdnca-ops0611-cancel-handoff)
  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  nsenter -t "${helper_pid}" -m -- test -d "${cancel_handoff}" || fail "cancel handoff was not in helper PrivateTmp"
  cancel_namespace_result=${workdir}/cancel-namespace-leftovers
  nsenter -t "${helper_pid}" -m -- sh -c \
    'touch /run/cdnca-ops0611-nsenter-ready; while [ ! -e /run/cdnca-ops0611-inspect-cancel ]; do sleep 0.05; done; find /tmp -maxdepth 1 -type d -name "cdnca-edge-agent-helper-*" -print' \
    >"${cancel_namespace_result}" &
  cancel_namespace_pid=$!
  cancel_attempt=0
  while [ ! -e /run/cdnca-ops0611-nsenter-ready ] && [ "${cancel_attempt}" -lt 100 ]; do
    kill -0 "${cancel_namespace_pid}" 2>/dev/null || fail "PrivateTmp namespace observer exited before ready"
    sleep 0.1
    cancel_attempt=$((cancel_attempt + 1))
  done
  [ -e /run/cdnca-ops0611-nsenter-ready ] || fail "PrivateTmp namespace observer did not become ready"
  systemctl stop cdnca-edge-agent-helper.service
  wait "${cancel_client_pid}" || fail "cancelled install did not return a deadline response"
  cancel_client_pid=
  jq -e \
    '.ok == false and .error_code == "ERR_DEADLINE" and .receipt == null' \
    "${client_state}/cancel.json" >/dev/null || fail "cancelled install deadline response differs"
  jq -e '.phase == "installing" and .transaction_id == "txn-runtime-cancel-5" and .active_receipt == null and .rollback_receipt == null' \
    /var/lib/cdnca-edge-agent-helper/journal-txn-runtime-cancel-5.json >/dev/null || \
    fail "cancelled install wrote a terminal journal state"
  touch /run/cdnca-ops0611-inspect-cancel
  wait "${cancel_namespace_pid}"
  cancel_namespace_pid=
  [ ! -s "${cancel_namespace_result}" ] || fail "cancelled handoff remained in retained PrivateTmp namespace"
  install -o root -g root -m 0555 "${upgrade_backup}" "${upgrade_script}"
  upgrade_replaced=false
  start_helper_stable
  sh -c "${client_command} query txn-runtime-cancel-5" >"${client_state}/cancel-query.json"
  jq -e --arg digest "${bundle_v5_digest}" \
    '.ok == true and .receipt.installer_transaction_id == "txn-runtime-cancel-5" and .receipt.release_sequence == 5 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.4.0" and .receipt.previous_version == "1.0.0" and .receipt.status == "active"' \
    "${client_state}/cancel-query.json" >/dev/null || fail "cancelled install Query recovery receipt differs"
  verify_receipt "${client_state}/cancel-query.json" cancellation-query
  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  assert_private_tmp_clean "${helper_pid}" cancellation
  rm -f -- /run/cdnca-ops0611-concurrent-handoffs /run/cdnca-ops0611-cancel-handoff /run/cdnca-ops0611-inspect-cancel

  sh -c "${client_command} current" >"${client_state}/current-after-cancel.json"
  jq -e --arg digest "${bundle_v5_digest}" \
    '.ok == true and .receipt.installer_transaction_id == "txn-runtime-cancel-5" and .receipt.release_sequence == 5 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.4.0" and .receipt.previous_version == "1.0.0" and .receipt.status == "active"' \
    "${client_state}/current-after-cancel.json" >/dev/null || fail "Current after cancellation differs"
  verify_receipt "${client_state}/current-after-cancel.json" current-after-cancel

  upgrade_passthrough=/usr/libexec/cdnca-edge-agent/upgrade.sh.ops0611-production
  install -o root -g root -m 0555 "${upgrade_backup}" "${upgrade_passthrough}"
  sigkill_after_upgrade=${workdir}/upgrade-sigkill-after.sh
  cat >"${sigkill_after_upgrade}" <<'SH'
#!/bin/sh
set -eu
/usr/libexec/cdnca-edge-agent/upgrade.sh.ops0611-production "$@"
printf '%s\n' "${2%/edge-agent}" >/run/cdnca-ops0611-sigkill-after-handoff
sleep 300
SH
  chmod 0555 "${sigkill_after_upgrade}"
  rm -f -- /run/cdnca-ops0611-sigkill-after-handoff \
    /run/cdnca-ops0611-sigkill-inspect /run/cdnca-ops0611-sigkill-nsenter-ready
  install -o root -g root -m 0555 "${sigkill_after_upgrade}" "${upgrade_script}"
  upgrade_replaced=true
  sh -c "${client_command} install ${client_state}/current-after-cancel.json ${release_v6}/release.bundle txn-runtime-sigkill-after-6 6 1.5.0 ${bundle_v6_digest} ${bundle_v6_size} respond -" \
    >"${client_state}/sigkill-after.json" 2>"${client_state}/sigkill-after.log" &
  sigkill_client_pid=$!
  sigkill_attempt=0
  while [ ! -s /run/cdnca-ops0611-sigkill-after-handoff ] && [ "${sigkill_attempt}" -lt 600 ]; do
    sleep 0.1
    sigkill_attempt=$((sigkill_attempt + 1))
  done
  [ -s /run/cdnca-ops0611-sigkill-after-handoff ] || fail "post-activation SIGKILL fixture did not observe an activated handoff"
  jq -e '.phase == "installing" and .transaction_id == "txn-runtime-sigkill-after-6"' \
    /var/lib/cdnca-edge-agent-helper/journal-txn-runtime-sigkill-after-6.json >/dev/null || \
    fail "post-activation SIGKILL journal was not installing"
  [ "$(readlink /usr/lib/cdnca-edge-agent/current)" = versions/1.5.0 ] || \
    fail "post-activation SIGKILL fixture did not activate the candidate"
  systemctl is-active --quiet cdnca-edge-agent.service || fail "post-activation candidate Agent was not active"
  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  sigkill_namespace_result=${workdir}/sigkill-after-namespace-leftovers
  nsenter -t "${helper_pid}" -m -- sh -c \
    'touch /run/cdnca-ops0611-sigkill-nsenter-ready; while [ ! -e /run/cdnca-ops0611-sigkill-inspect ]; do sleep 0.05; done; find /tmp -maxdepth 1 -type d -name "cdnca-edge-agent-helper-*" -print' \
    >"${sigkill_namespace_result}" &
  sigkill_namespace_pid=$!
  sigkill_attempt=0
  while [ ! -e /run/cdnca-ops0611-sigkill-nsenter-ready ] && [ "${sigkill_attempt}" -lt 100 ]; do
    kill -0 "${sigkill_namespace_pid}" 2>/dev/null || fail "post-activation PrivateTmp observer exited before ready"
    sleep 0.1
    sigkill_attempt=$((sigkill_attempt + 1))
  done
  [ -e /run/cdnca-ops0611-sigkill-nsenter-ready ] || fail "post-activation PrivateTmp observer did not become ready"
  sigkill_helper_cgroup sigkill-after
  if wait "${sigkill_client_pid}"; then
    fail "post-activation SIGKILL unexpectedly returned a response"
  fi
  sigkill_client_pid=
  touch /run/cdnca-ops0611-sigkill-inspect
  wait "${sigkill_namespace_pid}"
  sigkill_namespace_pid=
  [ ! -s "${sigkill_namespace_result}" ] || fail "post-activation SIGKILL retained a PrivateTmp handoff"
  install -o root -g root -m 0555 "${upgrade_backup}" "${upgrade_script}"
  upgrade_replaced=false
  rm -f -- "${upgrade_passthrough}"
  upgrade_passthrough=
  start_helper_stable
  sh -c "${client_command} query txn-runtime-sigkill-after-6" >"${client_state}/sigkill-after-query.json"
  jq -e --arg digest "${bundle_v6_digest}" \
    '.ok == true and .receipt.installer_transaction_id == "txn-runtime-sigkill-after-6" and .receipt.release_sequence == 6 and .receipt.artifact_sha256 == $digest and .receipt.current_version == "1.5.0" and .receipt.previous_version == "1.4.0" and .receipt.status == "active"' \
    "${client_state}/sigkill-after-query.json" >/dev/null || fail "post-activation SIGKILL Query receipt differs"
  verify_receipt "${client_state}/sigkill-after-query.json" sigkill-after-query
  jq -e --arg digest "${bundle_v6_digest}" \
    '.phase == "active" and .active_receipt.artifact_sha256 == $digest and .active_receipt.status == "active"' \
    /var/lib/cdnca-edge-agent-helper/journal-txn-runtime-sigkill-after-6.json >/dev/null || \
    fail "post-activation SIGKILL journal did not persist the active receipt"
  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  assert_private_tmp_clean "${helper_pid}" sigkill-after-recovery
  assert_canonical_state_layout sigkill-after-recovery
  assert_agent_state_bind sigkill-after-recovery
  rm -f -- /run/cdnca-ops0611-sigkill-after-handoff \
    /run/cdnca-ops0611-sigkill-inspect /run/cdnca-ops0611-sigkill-nsenter-ready

  touch /run/cdnca-ops0611-probe-stop
  probe_attempt=0
  while kill -0 "${probe_pid}" 2>/dev/null && [ "${probe_attempt}" -lt 100 ]; do
    sleep 0.1
    probe_attempt=$((probe_attempt + 1))
  done
  if kill -0 "${probe_pid}" 2>/dev/null; then
    fail "traffic probe did not observe a final success boundary"
  fi
  wait "${probe_pid}"
  probe_pid=
  [ "$(awk 'END { print $3 }' "${workdir}/traffic.log")" = 1 ] || fail "traffic probe final sample was not successful"
  traffic_successes=$(awk '$3 == 1 { count++ } END { print count + 0 }' "${workdir}/traffic.log")
  [ "${traffic_successes}" -ge 2 ] || fail "traffic probe did not record two successful boundaries"
  max_traffic_gap_ms=$(awk '$3 == 1 { if (seen && $2 - previous > maximum) maximum = $2 - previous; previous = $2; seen = 1 } END { printf "%.0f\n", maximum }' "${workdir}/traffic.log")
  traffic_gap_limit_ms=15000
  [ "${max_traffic_gap_ms}" -le "${traffic_gap_limit_ms}" ] || \
    fail "traffic probe exceeded ${traffic_gap_limit_ms}ms bound: ${max_traffic_gap_ms}ms between successes"

  helper_pid=$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  private_value=$(jq -r '.private_key' /var/lib/cdnca-edge-agent-helper/receipt-key.json)
  if setpriv --reuid="${agent_uid}" --regid="${agent_gid}" --clear-groups -- test -r /var/lib/cdnca-edge-agent-helper/receipt-key.json; then
    fail "Agent identity can read helper private key"
  fi
  tr '\000' '\n' <"/proc/${helper_pid}/environ" | grep -F "${private_value}" >/dev/null && fail "private key leaked into helper environment"
  tr '\000' '\n' <"/proc/${helper_pid}/cmdline" | grep -F "${private_value}" >/dev/null && fail "private key leaked into helper arguments"
  if find "/proc/${helper_pid}/fd" -maxdepth 1 -type l -lname '*receipt-key.json*' -print -quit | grep . >/dev/null; then
    fail "helper retained private key file descriptor"
  fi
  journalctl -u cdnca-edge-agent-helper.service --no-pager | grep -F "${private_value}" >/dev/null && fail "private key leaked into helper journal"

  agent_pid=$(systemctl show -p MainPID --value cdnca-edge-agent.service)
  [ "${agent_pid}" -gt 1 ] || fail "Agent MainPID is unavailable for key exposure inspection"
  tr '\000' '\n' <"/proc/${agent_pid}/environ" | grep -F "${private_value}" >/dev/null && fail "private key leaked into Agent environment"
  tr '\000' '\n' <"/proc/${agent_pid}/cmdline" | grep -F "${private_value}" >/dev/null && fail "private key leaked into Agent arguments"
  if find "/proc/${agent_pid}/fd" -maxdepth 1 -type l -lname '*receipt-key.json*' -print -quit | grep . >/dev/null; then
    fail "Agent retained helper private key file descriptor"
  fi
  journalctl -u cdnca-edge-agent.service --no-pager | grep -F "${private_value}" >/dev/null && fail "private key leaked into Agent journal"

  setpriv --reuid="${agent_uid}" --regid="${agent_gid}" --clear-groups --no-new-privs -- \
    env -i PATH=/usr/bin:/bin RUNTIME_ARCH="${runtime_arch}" python3 "${client}" hold \
    >"${client_state}/hold-client.log" 2>&1 &
  agent_client_pid=$!
  sleep 1
  kill -0 "${agent_client_pid}" 2>/dev/null || fail "hold client exited before key exposure inspection"
  tr '\000' '\n' <"/proc/${agent_client_pid}/environ" | grep -F "${private_value}" >/dev/null && fail "private key leaked into Agent client environment"
  tr '\000' '\n' <"/proc/${agent_client_pid}/cmdline" | grep -F "${private_value}" >/dev/null && fail "private key leaked into Agent client arguments"
  if find "/proc/${agent_client_pid}/fd" -maxdepth 1 -type l -lname '*receipt-key.json*' -print -quit | grep . >/dev/null; then
    fail "Agent client retained helper private key file descriptor"
  fi
  grep -F "${private_value}" "${client_state}/hold-client.log" >/dev/null && fail "private key leaked into Agent client log"
  kill "${agent_client_pid}" >/dev/null 2>&1 || true
  wait "${agent_client_pid}" 2>/dev/null || true
  agent_client_pid=

  helper_rss=$(ps -o rss= -p "${helper_pid}" | tr -d ' ')
  helper_cpu=$(ps -o %cpu= -p "${helper_pid}" | tr -d ' ')

  assert_socket_policy_rejected() {
    policy_case=$1
    systemctl start cdnca-edge-agent-helper.service >/dev/null 2>&1 || true
    policy_attempt=0
    policy_rejected=false
    while [ "${policy_attempt}" -lt 100 ]; do
      service_active=$(systemctl show -p ActiveState --value cdnca-edge-agent-helper.service)
      service_substate=$(systemctl show -p SubState --value cdnca-edge-agent-helper.service)
      service_status=$(systemctl show -p ExecMainStatus --value cdnca-edge-agent-helper.service)
      service_result=$(systemctl show -p Result --value cdnca-edge-agent-helper.service)
      if [ "${service_status}" != 0 ] && [ "${service_result}" = exit-code ]; then
        case "${service_active}:${service_substate}" in
          active:running) ;;
          *) policy_rejected=true; break ;;
        esac
      fi
      sleep 0.1
      policy_attempt=$((policy_attempt + 1))
    done
    systemctl stop cdnca-edge-agent-helper.service >/dev/null 2>&1 || true
    [ "${policy_rejected}" = true ] || fail "helper did not reject ${policy_case} socket policy"
  }

  systemctl stop cdnca-edge-agent-helper.service
  chmod 0660 /run/cdnca-edge-agent/helper.sock
  assert_socket_policy_rejected 'wrong-mode'
  chmod 0600 /run/cdnca-edge-agent/helper.sock
  systemctl reset-failed cdnca-edge-agent-helper.service
  systemctl start cdnca-edge-agent-helper.service
  systemctl stop cdnca-edge-agent-helper.service
  chown root:root /run/cdnca-edge-agent/helper.sock
  assert_socket_policy_rejected 'wrong-owner'
  chown "${agent_uid}:${agent_gid}" /run/cdnca-edge-agent/helper.sock
  systemctl reset-failed cdnca-edge-agent-helper.service
  systemctl start cdnca-edge-agent-helper.service
  socket_facts=$(stat -c '%U:%G:%a:%F' /run/cdnca-edge-agent/helper.sock)
  [ "${socket_facts}" = 'cdnca-edge:cdnca-edge:600:socket' ] || fail "restored socket facts differ: ${socket_facts}"

  same_tx_install_replay_ms=$(((install_finished - install_started) / 1000000))
  printf 'runtime evidence: query_p95_ms=%s same_tx_install_replay_10_ms=%s helper_rss_kib=%s helper_cpu_percent=%s max_traffic_gap_ms=%s\n' \
    "${query_p95}" "${same_tx_install_replay_ms}" "${helper_rss}" "${helper_cpu}" "${max_traffic_gap_ms}"

  systemctl stop cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket cdnca-edge-agent.service
  rm -rf -- "${workdir}"
  workdir=
  printf 'edge-agent helper isolated systemd runtime passed\n'
}

case "${mode}" in
  static) run_static ;;
  go) run_go ;;
  systemd-verify) run_systemd_verify ;;
  runtime) run_runtime ;;
  all) run_static; run_go ;;
esac
