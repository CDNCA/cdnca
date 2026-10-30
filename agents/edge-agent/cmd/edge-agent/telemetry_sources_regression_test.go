package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestTelemetrySourceRunnerRemovesSourcesOutsideActiveManifest(t *testing.T) {
	root := telemetrySecureRoot(t)
	spoolRoot := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spoolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	spoolRoot, err := filepath.EvalSymlinks(spoolRoot)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := eventspool.New(eventspool.Config{
		Root: spoolRoot, MaxEventBytes: 64 << 10, MaxSegmentBytes: 1 << 20,
		SoftLimitBytes: 8 << 20, HardLimitBytes: 16 << 20, MaxTenantBytes: 12 << 20,
		MaxBatchEvents: 100, PressureMode: eventspool.PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := newTelemetrySourceRunner(telemetrySourceConfig{
		DeploymentRoot: root, SpoolRoot: spoolRoot, EnrollmentNodeID: telemetryTestNodeID,
		PollInterval: time.Millisecond, MaxLineBytes: 64 << 10, MaxBatchEvents: 100,
		MaxQuarantineBytes: 1 << 20,
	}, spool)
	if err != nil {
		t.Fatal(err)
	}
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}

	v1 := telemetryBundle(t, root, "cfg-v1")
	v1Release := filepath.Join(root, "releases", v1.ManifestSHA256)
	writeTelemetryRelease(t, v1Release, v1)
	if err := prechecker.Precheck(context.Background(), "cfg-v1", v1Release); err != nil {
		t.Fatal(err)
	}
	replaceTelemetryCurrent(t, root, v1.ManifestSHA256)
	if err := runner.syncOnce(context.Background()); err != nil {
		t.Fatalf("initial source sync error = %v", err)
	}
	v1Manifest, err := parseTelemetryBundleManifest(v1)
	if err != nil {
		t.Fatal(err)
	}
	assertTelemetrySourceSet(t, runner, v1Manifest, true)

	v2 := telemetryBundle(t, root, "cfg-v2")
	v2Release := filepath.Join(root, "releases", v2.ManifestSHA256)
	writeTelemetryRelease(t, v2Release, v2)
	if err := prechecker.Precheck(context.Background(), "cfg-v2", v2Release); err != nil {
		t.Fatal(err)
	}
	replaceTelemetryCurrent(t, root, v2.ManifestSHA256)
	if err := runner.syncOnce(context.Background()); err != nil {
		t.Fatalf("replacement source sync error = %v", err)
	}
	v2Manifest, err := parseTelemetryBundleManifest(v2)
	if err != nil {
		t.Fatal(err)
	}
	assertTelemetrySourceSet(t, runner, v1Manifest, false)
	assertTelemetrySourceSet(t, runner, v2Manifest, true)

	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := runner.syncOnce(context.Background()); err != nil {
		t.Fatalf("inactive source sync error = %v", err)
	}
	if len(runner.sources) != 0 || len(runner.tailers) != 0 {
		t.Fatalf("inactive manifest retained telemetry sources: sources=%d tailers=%d", len(runner.sources), len(runner.tailers))
	}
	content, err := os.ReadFile(filepath.Join(spoolRoot, "state", telemetrySourceRegistryName))
	if err != nil {
		t.Fatal(err)
	}
	var registry telemetrySourceRegistry
	if err := json.Unmarshal(content, &registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.Sources) != 0 {
		t.Fatalf("inactive source registry retained %d entries", len(registry.Sources))
	}
}

func replaceTelemetryCurrent(t *testing.T, root, digest string) {
	t.Helper()
	current := filepath.Join(root, "current")
	if err := os.Remove(current); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", digest), current); err != nil {
		t.Fatal(err)
	}
}

func parseTelemetryBundleManifest(bundle edgeconfig.Bundle) (edgeconfig.TelemetryIdentityManifest, error) {
	return edgeconfig.ParseTelemetryIdentityManifest(bundle.Files[edgeconfig.TelemetryIdentityManifestPath])
}

func assertTelemetrySourceSet(t *testing.T, runner *telemetrySourceRunner, manifest edgeconfig.TelemetryIdentityManifest, want bool) {
	t.Helper()
	for _, site := range manifest.Sites {
		for _, path := range []string{site.AccessLogPath, site.SecurityLogPath} {
			_, sourcePresent := runner.sources[path]
			_, tailerPresent := runner.tailers[path]
			if sourcePresent != want || tailerPresent != want {
				t.Fatalf("source %q presence = source:%v tailer:%v, want %v", path, sourcePresent, tailerPresent, want)
			}
		}
	}
}
