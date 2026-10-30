package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
)

func TestNodeInstallerEnablesMonitoringWithoutActivatingPolicy(t *testing.T) {
	root, install := nodeInstallerMonitoringConfig(t)
	if output, err := install(); err != nil {
		t.Fatalf("generate installed config: %v\n%s", err, output)
	}
	config, _, err := loadConfig(filepath.Join(root, "etc/cdnca-edge-agent/config.json"))
	if err != nil {
		t.Fatal(err)
	}
	upgrade := config.Upgrade
	if !upgrade.Enabled || upgrade.InstallationID != "00000000-0000-4000-8000-0000000000aa" ||
		upgrade.Root != filepath.Join(root, "var/lib/cdnca-edge-agent/upgrades") ||
		upgrade.ControlExecutionTrustFile != filepath.Join(root, "etc/cdnca-edge-agent/trust/control-execution.json") ||
		upgrade.EdgeExecutionTrustFile != filepath.Join(root, "etc/cdnca-edge-agent/trust/edge-execution.json") ||
		upgrade.InstallerReceiptTrustFile != filepath.Join(root, "etc/cdnca-edge-agent/trust/installer-receipt.json") ||
		upgrade.DownloadRootCAFile != filepath.Join(root, "etc/cdnca-edge-agent/tls/upgrade-download-ca.pem") ||
		upgrade.DownloadHost != "auth.example.com" || upgrade.DownloadPort != 443 || len(upgrade.DownloadAddresses) != 2 ||
		upgrade.Timeout != "10m" || upgrade.MaxArtifactBytes != 285229182 || upgrade.DiskReserveBytes != 536870912 {
		t.Fatalf("installer upgrade settings = %+v", upgrade)
	}
	if err := upgrade.validate(config); err != nil {
		t.Fatalf("installed upgrade section is invalid: %v", err)
	}
	// The OWASP CRS engine extension is written explicitly: enabled, inside
	// the deployment root, downloaded over the upgrade channel above.
	if engine := config.WAFEngine; engine.Disabled || engine.Timeout != "2m" ||
		engine.Root != filepath.Join(config.DeploymentRoot, "extensions", "waf-crs") || engine.validate(config) != nil {
		t.Fatalf("installer waf_engine settings = %+v", engine)
	}
	// XDP is detected by the Agent at every start; the installer only
	// records an explicit --disable-xdp.
	if config.XDP.Disabled || config.XDP.Interfaces != nil {
		t.Fatalf("installer xdp settings = %+v", config.XDP)
	}
	// Dynamic routing is the only node runtime; its workers run as the
	// native worker account.
	if routing := config.DynamicRouting; !routing.Enabled || routing.WorkerGroup != "cdnca-runtime" ||
		routing.StateRoot != "" || routing.SharedRoot != "" {
		t.Fatalf("installer dynamic_routing settings = %+v", routing)
	}
	want := nodeMonitoringSettings{Enabled: true, StateDir: filepath.Join(root, "var/lib/cdnca-node-monitoring"), DefaultPort: 80}
	if config.NodeMonitoring != want {
		t.Fatalf("installer monitoring settings = %+v, want %+v", config.NodeMonitoring, want)
	}
	info, err := os.Stat(want.StateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("monitoring directory must be private: %v, %v", info, err)
	}
	// The packaged root unit keeps /var writable (ProtectSystem=full), which is
	// where the monitoring state directory lives on a real host.
	unit, err := os.ReadFile("../../packaging/systemd/cdnca-edge-agent-root.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "\nProtectSystem=full\n") || strings.Contains(string(unit), "ProtectSystem=strict") ||
		!strings.HasPrefix(filepath.ToSlash(strings.TrimPrefix(want.StateDir, root)), "/var/lib/") {
		t.Fatal("packaged Agent unit does not permit its monitoring state directory")
	}
	bridge, runtime, err := assembleNodeMonitoring(config.NodeMonitoring, config.Identity.NodeID)
	if err != nil || bridge == nil || runtime == nil {
		t.Fatalf("assemble installed monitoring: %v", err)
	}
	if _, err := runtime.RunOnce(t.Context()); !errors.Is(err, nodemonitoring.ErrNoActiveConfig) {
		t.Fatalf("fresh installed runtime must have no activated policy: %v", err)
	}

	// Observe real TCP calls on a private ephemeral port, not the host's port 80.
	// All other settings and persisted paths are the exact installer output.
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	observed := config.NodeMonitoring
	observed.DefaultPort = uint16(listener.Addr().(*net.TCPAddr).Port)
	bridge, runtime, err = assembleNodeMonitoring(observed, config.Identity.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := bridge.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unconfigured bridge must wait, not terminate or activate: %v", err)
	}
	if err := listener.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if connection != nil {
		_ = connection.Close()
		t.Fatal("unconfigured monitoring runtime probed a local port")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("probe observation failed: %v", err)
	}
	if runtime.Status() != (nodemonitoring.Status{}) || len(bridge.Pending()) != 0 {
		t.Fatal("unconfigured runtime activated state or queued a report")
	}
	for _, directory := range []string{"runtime", "node-monitoring-carrier"} {
		entries, err := os.ReadDir(filepath.Join(want.StateDir, directory))
		if err != nil || len(entries) != 0 {
			t.Fatalf("installer must not create a monitoring revision or report: %s: %v, %v", directory, entries, err)
		}
	}
}

// The installer writes waf_engine for every signed package it installs: the
// baseline is 1.0.35, so there is no older Agent whose strict decoding would
// refuse the section (an older package fails --check-config and the install
// stops). Its values equal the defaults assembleWAFEngine applies.
func TestNodeInstallerWritesWAFEngine(t *testing.T) {
	for _, version := range []string{"1.0.33", "1.0.35", "1.1.0"} {
		t.Run(version, func(t *testing.T) {
			root, install := nodeInstallerConfigForAgent(t, version)
			if output, err := install(); err != nil {
				t.Fatalf("generate installed config: %v\n%s", err, output)
			}
			path := filepath.Join(root, "etc/cdnca-edge-agent/config.json")
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(content, &fields); err != nil {
				t.Fatal(err)
			}
			if _, got := fields["waf_engine"]; !got {
				t.Fatal("waf_engine not written")
			}
			// Node plugins were removed (ADR 0007 §4.6); the installer no longer writes the section.
			if _, got := fields["node_plugins"]; got {
				t.Fatal("node_plugins must not be written")
			}
			config, _, err := loadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			// External probing is on by default (probe only); joining the
			// node market stays an explicit operator choice.
			if !config.MarketProbe.Enabled || config.MarketProbe.JoinMarket || config.MarketProbe.Benchmark ||
				!config.DynamicRouting.Enabled {
				t.Fatalf("installed runtimes: %+v %+v", config.MarketProbe, config.DynamicRouting)
			}
			// A leftover node_plugins section is an unknown field: strict decoding refuses it.
			fields["node_plugins"] = json.RawMessage(`{"enabled":true,"state_dir":"/var/lib/cdnca-node-plugins"}`)
			leftover, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, leftover, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadConfig(path); err == nil {
				t.Fatal("config with node_plugins must be rejected")
			}
			// security_runtime native: the signed release's real asset paths
			// and the signed digests, no ready marker; the formal loader
			// above verified them (check-config at install time).
			security := config.SecurityRuntime
			securityRoot := filepath.Join(root, "release/lua/share/cdnca/security")
			if !security.Enabled || security.Mode != securityRuntimeModeNative || security.ReadyFile != "" ||
				security.WAF.Path != filepath.Join(securityRoot, "cdnca_waf.lua") ||
				security.CC.Path != filepath.Join(securityRoot, "cc.lua") ||
				security.Adaptive.Path != filepath.Join(securityRoot, "cc_adaptive.lua") {
				t.Fatalf("security_runtime = %+v", security)
			}
			if status, err := validateSecurityRuntime(security); err != nil || status != (securityRuntimeStatus{}) {
				t.Fatalf("installed native security_runtime = %+v, %v", status, err)
			}
			if want := (wafEngineSettings{Root: filepath.Join(config.DeploymentRoot, "extensions", "waf-crs"), Timeout: "2m"}); config.WAFEngine != want {
				t.Fatalf("waf_engine = %+v, want %+v", config.WAFEngine, want)
			}
		})
	}
}

// Upgrade is written enabled only when every runtime prerequisite exists; a
// missing or writable trust file fails the install before any config exists.
func TestNodeInstallerRefusesUpgradeWithoutTrustPrerequisites(t *testing.T) {
	for _, name := range []string{"trust/installer-receipt.json", "trust/control-execution.json", "tls/upgrade-download-ca.pem"} {
		for _, mutation := range []string{"missing", "writable"} {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				root, install := nodeInstallerMonitoringConfig(t)
				path := filepath.Join(root, "etc/cdnca-edge-agent", name)
				var err error
				if mutation == "missing" {
					err = os.Remove(path)
				} else {
					err = os.Chmod(path, 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
				output, err := install()
				if err == nil || !strings.Contains(string(output), "node upgrade cannot be enabled") {
					t.Fatalf("installer accepted %s %s: %v\n%s", mutation, name, err, output)
				}
				if _, err := os.Stat(filepath.Join(root, "etc/cdnca-edge-agent/config.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("config was written without upgrade prerequisites: %v", err)
				}
			})
		}
	}
}

func TestLocalNodeProbeExecutesHTTPAndPingProtocols(t *testing.T) {
	probe := localNodeProbe{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	port := uint16(server.Listener.Addr().(*net.TCPAddr).Port)
	if err := probe.ProbeProtocol(t.Context(), "http", port, time.Second); err != nil {
		t.Fatalf("HTTP probe = %v", err)
	}
	if err := probe.ProbeProtocol(t.Context(), "tcp", port, time.Second); err != nil {
		t.Fatalf("TCP compatibility probe = %v", err)
	}
	if err := probe.ProbeProtocol(t.Context(), "ping", port, time.Second); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") || strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Skipf("ICMP is unavailable to this non-root test process: %v", err)
		}
		t.Fatalf("Ping probe = %v", err)
	}
}

// The packaged non-root unit has no CAP_NET_RAW: Ping must still work through
// the unprivileged ICMP datagram socket. Each socket kind is reported so a
// container run shows which one the unit's capabilities allow.
func TestPingProbeFallsBackToUnprivilegedICMP(t *testing.T) {
	for _, network := range pingNetworks {
		t.Logf("%s: %v", network, probePingOn(t.Context(), network, time.Second))
	}
	if err := probePingOn(t.Context(), "udp4", time.Second); err != nil {
		if os.Getenv("CDNCA_REQUIRE_UNPRIVILEGED_PING") != "" {
			t.Fatalf("unprivileged ICMP = %v", err)
		}
		t.Skipf("unprivileged ICMP is disabled on this host (net.ipv4.ping_group_range): %v", err)
	}
	if err := probePing(t.Context(), time.Second); err != nil {
		t.Fatalf("probePing must succeed when unprivileged ICMP works: %v", err)
	}
}

func TestNodeInstallerMonitoringConfigRejectsUnsafePaths(t *testing.T) {
	root, install := nodeInstallerMonitoringConfig(t)
	if output, err := install(); err != nil {
		t.Fatalf("generate installed config: %v\n%s", err, output)
	}
	path := filepath.Join(root, "etc/cdnca-edge-agent/config.json")
	config, _, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !config.NodeMonitoring.Enabled {
		t.Fatal("installer did not enable monitoring")
	}
	link := filepath.Join(root, "monitoring-link")
	if err := os.Symlink(config.NodeMonitoring.StateDir, link); err != nil {
		t.Fatal(err)
	}
	for name, stateDir := range map[string]string{
		"relative": "monitoring", "root": "/", "unclean": root + "/../monitoring",
		"deployment": config.DeploymentRoot, "deployment child": filepath.Join(config.DeploymentRoot, "monitoring"),
		"journal": config.JournalDir, "certificate": config.CertificateRuntime.StateRoot,
		"symlink": link, "symlink ancestor": filepath.Join(link, "child"),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			candidate.NodeMonitoring.StateDir = stateDir
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "node_monitoring") {
				t.Fatalf("formal loader must reject the monitoring path: %v", err)
			}
		})
	}
}

func TestNodeInstallerMonitoringDirectoryRejectsExistingState(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "directory"
		if symlink {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			root, install := nodeInstallerMonitoringConfig(t)
			state := filepath.Join(root, "var/lib/cdnca-node-monitoring")
			target := state
			if symlink {
				target = filepath.Join(root, "existing-state")
			}
			if err := os.Mkdir(target, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "keep"), []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if symlink {
				if err := os.Symlink(target, state); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := install(); err == nil {
				t.Fatal("installer reused monitoring state created after blank-host preflight")
			}
			info, err := os.Stat(target)
			if err != nil || info.Mode().Perm() != 0o750 {
				t.Fatalf("existing monitoring target was changed: %v, %v", info, err)
			}
			if content, err := os.ReadFile(filepath.Join(target, "keep")); err != nil || string(content) != "unchanged" {
				t.Fatalf("existing monitoring data was changed: %v", err)
			}
		})
	}
}

func nodeInstallerMonitoringConfig(t *testing.T) (string, func() ([]byte, error)) {
	t.Helper()
	return nodeInstallerConfigForAgent(t, "1.0.35")
}

// nodeInstallerConfigForAgent runs write_config as if the signed node package
// carried agentVersion (NATIVE_VERSION comes from the verified manifest).
func nodeInstallerConfigForAgent(t *testing.T, agentVersion string) (string, func() ([]byte, error)) {
	t.Helper()
	root := secureConfigTempDir(t)
	content, err := os.ReadFile("../../../../scripts/install-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.TrimSuffix(string(content), "\nmain \"$@\"\n")
	if script == string(content) {
		t.Fatal("installer entrypoint was not isolated")
	}
	var replacements []string
	for _, prefix := range []string{"/usr/lib/cdnca-edge-agent", "/usr/local", "/etc", "/opt", "/var/lib", "/var/log", "/run", "/usr/sbin/nginx"} {
		replacements = append(replacements, prefix, filepath.Join(root, prefix[1:]))
	}
	script = strings.NewReplacer(replacements...).Replace(script)
	if goruntime.GOOS == "linux" {
		// Preserve the native profile's fixed ABI paths, while redirecting writes.
		// loadConfig reads identity but does not start OpenResty or the daemon.
		for from, to := range map[string]string{
			`--arg deployment "$STATE_ROOT"`:                                             `--arg deployment "/var/lib/cdnca-edge"`,
			`binary: "` + filepath.Join(root, "usr/local/openresty/bin/openresty") + `"`: `binary: "/usr/local/openresty/bin/openresty"`,
		} {
			if strings.Count(script, from) != 1 {
				t.Fatal("native profile isolation no longer matches the installer")
			}
			script = strings.Replace(script, from, to, 1)
		}
	} else {
		// macOS /var is a symlink, deliberately refused by the native profile.
		// This portable branch verifies monitoring only; Linux tests retain it.
		t.Log("non-Linux: isolated monitoring profile; native profile requires Linux rerun")
		script = strings.Replace(script, `systemd_service: "cdnca-openresty-native.service"`, `systemd_service: ""`, 1)
	}
	for _, directory := range []string{"etc/cdnca-edge-agent/trust", "etc/cdnca-edge-agent/tls", "etc/systemd/system",
		"usr/lib/cdnca-edge-agent/current", "release/evidence", "var/lib"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeIdentityFixture(t, filepath.Join(root, "etc/cdnca-edge-agent"))
	// Only the shell's check-config invocation is stubbed. The tests above use
	// the formal Go loader and monitoring assembler with the generated file.
	// write_config enables upgrades only once every trust prerequisite exists.
	for _, name := range []string{"trust/control-execution.json", "trust/edge-execution.json",
		"trust/installer-receipt.json", "tls/upgrade-download-ca.pem"} {
		if err := os.WriteFile(filepath.Join(root, "etc/cdnca-edge-agent", name), []byte("fixture"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/cdnca-edge-agent/current/edge-agent"),
		[]byte("#!/bin/sh\n[ \"$#\" -eq 3 ] && [ \"$1\" = --config ] && [ \"$3\" = --check-config ]\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The signed package's WAF/CC assets under the release (no symlink
	// ancestor); their digests reach write_config as NATIVE_SECURITY_ASSETS.
	securityAssets := map[string]string{}
	if err := os.MkdirAll(filepath.Join(root, "release/lua/share/cdnca/security"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]string{"waf": "cdnca_waf", "cc": "cc", "adaptive": "cc_adaptive"} {
		content := []byte("return {" + name + "=true}\n")
		if err := os.WriteFile(filepath.Join(root, "release/lua/share/cdnca/security", file+".lua"), content, 0o444); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		securityAssets[name] = hex.EncodeToString(digest[:])
	}
	securityAssetsJSON, err := json.Marshal(securityAssets)
	if err != nil {
		t.Fatal(err)
	}
	return root, func() ([]byte, error) {
		// 脚本经 stdin 传入：install-node.sh 全文超过 Linux 单参数上限 128KiB（bash -c 会 E2BIG）。
		command := exec.CommandContext(t.Context(), "bash", "-s", "--", root, agentVersion)
		command.Stdin = strings.NewReader(script + `
ARTIFACT_TRUST_FILE="$TRUST_DIR/artifacts.json"
GATEWAY_ROOT_CA_FILE="$TLS_DIR/gateway-ca.pem"
GATEWAY_ADDRESS=gateway.example:19444
GATEWAY_SERVER_NAME=gateway.example
OPENRESTY_VERSION=1.31.1.1
UPGRADE_INSTALLATION_ID=00000000-0000-4000-8000-0000000000aa
UPGRADE_DOWNLOAD_HOST=auth.example.com
UPGRADE_DOWNLOAD_PORT=443
UPGRADE_DOWNLOAD_ADDRESSES='["203.0.113.7","2001:db8::7"]'
NATIVE_RELEASE="$1/release"
NATIVE_VERSION="$2"
NATIVE_SECURITY_ASSETS='` + string(securityAssetsJSON) + `'
write_config
`)
		return command.CombinedOutput()
	}
}
