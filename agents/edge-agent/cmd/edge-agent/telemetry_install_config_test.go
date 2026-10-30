package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// An installed node reports access and security logs: the installer writes
// telemetry enabled with the default spool, and the dynamic routing skeleton
// (which writes the node-level logs only with telemetry on) follows it.
func TestNodeInstallerEnablesTelemetry(t *testing.T) {
	root, install := nodeInstallerMonitoringConfig(t)
	if output, err := install(); err != nil {
		t.Fatalf("generate installed config: %v\n%s", err, output)
	}
	path := filepath.Join(root, "etc/cdnca-edge-agent/config.json")
	config, timeouts, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	defaults := defaultFileConfig().Telemetry
	want := defaults
	want.Enabled = true
	want.SpoolRoot = filepath.Join(root, strings.TrimPrefix(defaults.SpoolRoot, "/"))
	if config.Telemetry != want {
		t.Fatalf("installer telemetry = %+v, want %+v", config.Telemetry, want)
	}
	// The real Agent binary's --check-config accepts the generated file (the
	// installer fixture stubs that call).
	binary := filepath.Join(t.TempDir(), "edge-agent")
	if output, err := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build edge-agent: %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(t.Context(), binary, "--config", path, "--check-config").CombinedOutput(); err != nil ||
		!strings.Contains(string(output), "configuration_valid") {
		t.Fatalf("edge-agent --check-config: %v\n%s", err, output)
	}
	if timeouts.TelemetrySoftAgeLimit <= 0 || timeouts.TelemetryHardAgeLimit <= timeouts.TelemetrySoftAgeLimit {
		t.Fatalf("installed telemetry timeouts = %+v", timeouts)
	}
	// The spool lives under the Agent's state bind (/var/lib/cdnca-edge-agent),
	// writable under the packaged unit and separate from every other root.
	if !strings.HasPrefix(defaults.SpoolRoot, "/var/lib/cdnca-edge-agent/") {
		t.Fatalf("default spool root %q is outside the Agent state bind", defaults.SpoolRoot)
	}
	unit, err := os.ReadFile("../../packaging/systemd/cdnca-edge-agent-root.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "BindPaths=/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind") {
		t.Fatal("packaged Agent unit no longer binds the state root that holds the spool")
	}
}

// The example configuration documents the same default.
func TestConfigExampleEnablesTelemetry(t *testing.T) {
	content, err := os.ReadFile("../../packaging/config/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var fields struct {
		Telemetry *telemetrySettings `json:"telemetry"`
	}
	if err := json.Unmarshal(content, &fields); err != nil {
		t.Fatal(err)
	}
	if fields.Telemetry == nil || !fields.Telemetry.Enabled || fields.Telemetry.SpoolRoot != defaultFileConfig().Telemetry.SpoolRoot {
		t.Fatalf("example telemetry = %+v", fields.Telemetry)
	}
}
