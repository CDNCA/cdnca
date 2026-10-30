package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const obs06ActiveCaptureDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestOBS06SignedCaptureFiltersMapExactlyToTailer(t *testing.T) {
	policy := edgeconfig.TelemetrySiteCapturePolicy{
		SiteID:                     telemetryTestSiteID,
		Domain:                     "capture.example.test",
		ListenPort:                 443,
		Enabled:                    true,
		Methods:                    []string{"GET", "POST"},
		URIPrefixes:                []string{"/api", "/checkout"},
		RequestHeaderAllowlist:     []string{"Authorization"},
		ResponseHeaderAllowlist:    []string{"Set-Cookie"},
		RequestBodyFieldAllowlist:  []string{"password"},
		ResponseBodyFieldAllowlist: []string{},
		MaxValueBytes:              4096,
		MaxBodyBytes:               65536,
		MaxEventBytes:              1048576,
	}
	got, err := eventspoolCapturePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	want := eventspool.CapturePolicy{
		Enabled:             true,
		Methods:             []string{"GET", "POST"},
		URIPrefixes:         []string{"/api", "/checkout"},
		RequestHeaders:      []string{"Authorization"},
		ResponseHeaders:     []string{"Set-Cookie"},
		RequestBodyFields:   []string{"password"},
		ResponseBodyFields:  []string{},
		MaxHeaderValueBytes: 4096,
		MaxBodyBytes:        65536,
		MaxEventBytes:       1048576,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapped=%+v want=%+v", got, want)
	}
}

func TestOBS06ActiveCaptureIdentityPersistsAsTelemetryLKG(t *testing.T) {
	root := telemetrySecureRoot(t)
	spoolRoot := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spoolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	spoolRoot, err := filepath.EvalSymlinks(spoolRoot)
	if err != nil {
		t.Fatal(err)
	}
	bundle := telemetryReleaseBundle(t, root, "cfg-obs06", 7, "", telemetryListener{domain: "capture.example.test", port: 18081,
		capture: edgeconfig.TelemetryCapturePolicy{SchemaVersion: 1, Revision: 7, EvidenceDigest: obs06ActiveCaptureDigest,
			Enabled: true, RequestHeaderAllowlist: []string{"Authorization"}}})
	release := filepath.Join(root, "releases", bundle.ManifestSHA256)
	writeTelemetryRelease(t, release, bundle)
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "cfg-obs06", release); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", bundle.ManifestSHA256), filepath.Join(root, "current")); err != nil {
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
	config := telemetrySourceConfig{
		DeploymentRoot: root, SpoolRoot: spoolRoot, EnrollmentNodeID: telemetryTestNodeID,
		PollInterval: time.Millisecond, MaxLineBytes: 64 << 10, MaxBatchEvents: 100,
		MaxQuarantineBytes: 1 << 20,
	}
	runner, err := newTelemetrySourceRunner(config, spool)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, registration := range runner.sources {
		if registration.Identity.CapturePolicyRevision != 7 ||
			registration.Identity.CapturePolicyDigest != obs06ActiveCaptureDigest {
			t.Fatalf("active capture identity = %+v", registration.Identity)
		}
	}
	content, err := os.ReadFile(filepath.Join(spoolRoot, "state", telemetrySourceRegistryName))
	if err != nil {
		t.Fatal(err)
	}
	var persisted telemetrySourceRegistry
	if err := json.Unmarshal(content, &persisted); err != nil || len(persisted.Sources) != 2 {
		t.Fatalf("persisted capture LKG = %+v, %v", persisted, err)
	}
	reloaded, err := newTelemetrySourceRunner(config, spool)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.sources) != 2 {
		t.Fatalf("reloaded capture LKG sources = %d", len(reloaded.sources))
	}
	for _, registration := range reloaded.sources {
		if registration.Identity.CapturePolicyRevision != 7 ||
			registration.Identity.CapturePolicyDigest != obs06ActiveCaptureDigest {
			t.Fatalf("reloaded capture LKG identity = %+v", registration.Identity)
		}
	}
}
