package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// A multi-tenant node's composed release carries each scope's signed
// telemetry identity (composedTelemetryIdentityDir): the
// precheck prepares every scope's log sources, and the runner, reading the
// composed release, registers them under each scope's own config version.
func TestComposedSiteTelemetryIsPreparedAndCollectedPerScope(t *testing.T) {
	root := telemetrySecureRoot(t)
	versions := map[string]string{
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
	}
	composedRoot := filepath.Join(filepath.Dir(root), "site-runtime")
	digest := strings.Repeat("c", 64)
	release := filepath.Join(composedRoot, "composed-releases", digest)
	identities := filepath.Join(release, filepath.FromSlash(composedTelemetryIdentityDir))
	if err := os.MkdirAll(identities, 0o700); err != nil {
		t.Fatal(err)
	}
	for scopeID, versionID := range versions {
		identity := telemetryBundle(t, root, versionID).Files[edgeconfig.TelemetryIdentityManifestPath]
		if err := os.WriteFile(filepath.Join(release, filepath.FromSlash(composedTelemetryIdentityDir+"/"+scopeID+".json")),
			identity, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("composed-releases", digest), filepath.Join(composedRoot, "composed-current")); err != nil {
		t.Fatal(err)
	}
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "composed-0123456789abcdef01234567", release); err != nil {
		t.Fatalf("prepare composed site telemetry: %v", err)
	}
	sources := map[string]string{}
	for _, versionID := range versions {
		directory := filepath.Join(root, "shared", "telemetry", versionID, telemetryTestSiteID, "18081")
		for _, name := range []string{"access.jsonl", "security.jsonl"} {
			path := filepath.Join(directory, name)
			if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("composed source %s was not prepared: %v", path, err)
			}
			sources[path] = versionID
		}
	}

	spoolRoot := telemetrySecureRoot(t)
	spool, err := eventspool.New(eventspool.Config{Root: spoolRoot, MaxEventBytes: 64 << 10, MaxSegmentBytes: 1 << 20,
		SoftLimitBytes: 8 << 20, HardLimitBytes: 16 << 20, MaxTenantBytes: 12 << 20, MaxBatchEvents: 100,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := newTelemetrySourceRunner(telemetrySourceConfig{DeploymentRoot: root, SpoolRoot: spoolRoot,
		ComposedCurrent:  filepath.Join(composedRoot, "composed-current"),
		EnrollmentNodeID: telemetryTestNodeID, PollInterval: time.Second, MaxLineBytes: 4096, MaxBatchEvents: 10,
		MaxQuarantineBytes: 64 << 10}, spool)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.observeActive(); err != nil {
		t.Fatal(err)
	}
	if len(runner.sources) != len(sources) {
		t.Fatalf("composed site sources = %+v, want %d", runner.sources, len(sources))
	}
	for path, versionID := range sources {
		registered, ok := runner.sources[path]
		if !ok || registered.Identity.ConfigVersionID != versionID || registered.Identity.SiteID != telemetryTestSiteID ||
			registered.Identity.TenantID != telemetryTestTenantID || registered.Identity.ListenPort != 18081 {
			t.Fatalf("source %s missing or misattributed: %+v", path, registered)
		}
	}
}

// Only <scope id>.json regular files are identities; anything else in the
// directory refuses the release instead of being collected or ignored.
func TestComposedSiteTelemetryRejectsForeignIdentityFiles(t *testing.T) {
	root := telemetrySecureRoot(t)
	release := filepath.Join(filepath.Dir(root), "composed-release")
	identities := filepath.Join(release, filepath.FromSlash(composedTelemetryIdentityDir))
	if err := os.MkdirAll(identities, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := telemetryBundle(t, root, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2").Files[edgeconfig.TelemetryIdentityManifestPath]
	for _, name := range []string{"not-a-scope.json", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAA1.json"} {
		path := filepath.Join(identities, name)
		if err := os.WriteFile(path, identity, 0o440); err != nil {
			t.Fatal(err)
		}
		if _, err := readComposedTelemetryManifests(release); err == nil {
			t.Fatalf("identity file %q was accepted", name)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if manifests, err := readComposedTelemetryManifests(filepath.Join(root, "missing")); err != nil || len(manifests) != 0 {
		t.Fatalf("release without identities = %v, %v", manifests, err)
	}
}
