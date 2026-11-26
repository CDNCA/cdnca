package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/http3runtime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const fakeH3ProbeVersion = `{"schema":"cdnca.h3probe/v1","go":"go1.24.5","quic_go":"v0.54.0"}`

// writeFakeH3Probe writes an executable that answers `version` like the
// packaged h3probe (edge/openresty/http3/client) and nothing else.
func writeFakeH3Probe(t *testing.T, directory, output string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, "h3probe")
	script := "#!/bin/sh\n[ \"$1\" = version ] && [ $# -eq 1 ] || exit 2\nprintf '%s\\n' '" + output + "'\n"
	if err := os.WriteFile(path, []byte(script), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func http3RuntimeTestConfig(probe string) fileConfig {
	return fileConfig{OpenResty: openRestySettings{Binary: "/usr/local/openresty/bin/openresty",
		Version: http3runtime.RuntimeVersionOpenResty, HTTP3Probe: probe}}
}

// An h3probe on PATH is never picked up: production nodes have no such PATH
// entry, so the probe is the configured absolute path or HTTP/3 is not
// declared, with the reason, instead of silently falling back.
func TestHTTP3RuntimeIgnoresPATHAndRequiresConfiguredProbe(t *testing.T) {
	onPath := t.TempDir()
	writeFakeH3Probe(t, onPath, fakeH3ProbeVersion, 0o755)
	t.Setenv("PATH", onPath)
	readiness := checkHTTP3Readiness(http3RuntimeTestConfig(""))
	if readiness.Ready || !strings.Contains(readiness.Reason, "openresty.http3_probe is not configured") {
		t.Fatalf("unconfigured probe = %+v", readiness)
	}
}

func TestHTTP3RuntimeProbeFailuresAreExplicit(t *testing.T) {
	for _, item := range []struct {
		name, output, reason string
		mode                 os.FileMode
		missing              bool
	}{
		{name: "missing", missing: true, reason: "not found"},
		{name: "not executable", output: fakeH3ProbeVersion, mode: 0o644, reason: "not executable"},
		{name: "wrong schema", output: `{"schema":"other","go":"go1.24.5","quic_go":"v0.54.0"}`, mode: 0o755, reason: "self-test"},
		{name: "no quic-go", output: `{"schema":"cdnca.h3probe/v1","go":"go1.24.5","quic_go":""}`, mode: 0o755, reason: "self-test"},
		{name: "garbage", output: `nope`, mode: 0o755, reason: "self-test"},
	} {
		t.Run(item.name, func(t *testing.T) {
			directory := t.TempDir()
			probe := filepath.Join(directory, "h3probe")
			if !item.missing {
				probe = writeFakeH3Probe(t, directory, item.output, item.mode)
			}
			readiness := checkHTTP3Readiness(http3RuntimeTestConfig(probe))
			if readiness.Ready || !strings.Contains(readiness.Reason, probe) || !strings.Contains(readiness.Reason, item.reason) {
				t.Fatalf("probe %s = %+v", item.name, readiness)
			}
		})
	}
}

func TestHTTP3RuntimeVersionMismatchIsExplicit(t *testing.T) {
	config := http3RuntimeTestConfig(writeFakeH3Probe(t, t.TempDir(), fakeH3ProbeVersion, 0o755))
	config.OpenResty.Version = "1.27.1.2"
	readiness := checkHTTP3Readiness(config)
	if readiness.Ready || !strings.Contains(readiness.Reason, "1.27.1.2") ||
		!strings.Contains(readiness.Reason, http3runtime.RuntimeVersionOpenResty) {
		t.Fatalf("version mismatch = %+v", readiness)
	}
}

func TestHTTP3RuntimeReadyWithConfiguredProbe(t *testing.T) {
	probe := writeFakeH3Probe(t, t.TempDir(), fakeH3ProbeVersion, 0o555)
	readiness := checkHTTP3Readiness(http3RuntimeTestConfig(probe))
	if !readiness.Ready || readiness.Probe != probe || readiness.Reason != "" {
		t.Fatalf("configured probe = %+v", readiness)
	}
}

// The reason travels with every terminal deployment status (node status on
// the control plane), and the same text is the local log line.
func TestHTTP3RuntimeCheckAndLogCarryTheReason(t *testing.T) {
	reason := "h3probe /opt/x/h3probe not found"
	checks := http3RuntimeChecks(http3RuntimeReadiness{Reason: reason})()
	if len(checks) != 1 || checks[0].Name != "edge_http3_runtime" || checks[0].Succeeded ||
		!strings.Contains(checks[0].Summary, "HTTP_3 not declared") || !strings.Contains(checks[0].Summary, reason) ||
		checks[0].LatencyDuration == nil {
		t.Fatalf("unavailable check = %+v", checks)
	}
	ready := http3RuntimeChecks(http3RuntimeReadiness{Ready: true, Probe: "/opt/x/h3probe"})()
	if len(ready) != 1 || !ready[0].Succeeded || !strings.Contains(ready[0].Summary, "/opt/x/h3probe") {
		t.Fatalf("ready check = %+v", ready)
	}
	var log strings.Builder
	logHTTP3Readiness(&log, http3RuntimeReadiness{Reason: reason})
	if !strings.Contains(log.String(), "HTTP/3 unavailable, HTTP_3 not declared: "+reason) {
		t.Fatalf("log = %q", log.String())
	}
	combined := combineDeploymentChecks(
		func() []*agentv1.CheckResult { return []*agentv1.CheckResult{{Name: "edge_waf_crs_engine"}} },
		http3RuntimeChecks(http3RuntimeReadiness{Reason: reason}),
	)()
	if len(combined) != 2 || combined[0].Name != "edge_waf_crs_engine" || combined[1].Name != "edge_http3_runtime" {
		t.Fatalf("combined checks = %+v", combined)
	}
}

func TestHTTP3ProbeConfigMustBeAbsoluteClean(t *testing.T) {
	for _, value := range []string{"h3probe", "/opt/cdnca-node/current/runtime/bin/../bin/h3probe", "/opt/x/h3probe\n"} {
		config := validFileConfig()
		config.OpenResty.HTTP3Probe = value
		if _, err := config.validate(); err == nil || !strings.Contains(err.Error(), "openresty.http3_probe") {
			t.Fatalf("http3_probe %q accepted: %v", value, err)
		}
	}
	config := validFileConfig()
	config.OpenResty.HTTP3Probe = "/opt/cdnca-node/current/runtime/bin/h3probe"
	if _, err := config.validate(); err != nil {
		t.Fatalf("installer probe path rejected: %v", err)
	}
	var settings openRestySettings
	if err := json.Unmarshal([]byte(`{"http3_probe":"/opt/cdnca-node/current/runtime/bin/h3probe"}`), &settings); err != nil ||
		settings.HTTP3Probe != "/opt/cdnca-node/current/runtime/bin/h3probe" {
		t.Fatalf("decode http3_probe = %+v, %v", settings, err)
	}
}
