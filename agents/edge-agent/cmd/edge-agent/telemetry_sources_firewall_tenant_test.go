package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/google/uuid"
)

// firewallHitEnvelope is a kernel hit as firewall/hitlog.go parseKernelHit
// builds it: the command's tenant (the configuration scope, access_scopes.id)
// and the firewall's own runtime version.
func firewallHitEnvelope(scopeID, siteID string, occurredAt time.Time) eventspool.Envelope {
	return eventspool.Envelope{
		SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventSecurity, EventID: uuid.NewString(), OccurredAt: occurredAt,
		TenantID: scopeID, SiteID: siteID, NodeID: telemetryTestNodeID, ConfigVersionID: "runtime-" + uuid.NewString(),
		Host: "-", Path: "/", ClientIP: "198.51.100.8", Method: "NETWORK", ListenPort: 443,
		DestinationPort: 443, Protocol: "tcp", RequestClass: "network", SecurityType: "global_firewall",
		Action: "block", Severity: "medium", RuleID: uuid.NewString(),
	}
}

// A global firewall hit reaches the spool under its site's telemetry
// identity (tenants.id and the published config version), which is what the
// gateway authorizes; a hit of a site without one never enters the spool,
// where it would hold back every later event.
func TestFirewallHitsArePublishedUnderTheSitesTelemetryIdentity(t *testing.T) {
	root := telemetrySecureRoot(t)
	spoolRoot := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spoolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	spoolRoot, err := filepath.EvalSymlinks(spoolRoot)
	if err != nil {
		t.Fatal(err)
	}
	bundle := telemetryBundle(t, root, "cfg-v1")
	release := filepath.Join(root, "releases", bundle.ManifestSHA256)
	writeTelemetryRelease(t, release, bundle)
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "cfg-v1", release); err != nil {
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
	scopeID := "22222222-2222-4222-8222-222222222222" // distinct from telemetryTestTenantID
	now := time.Now().UTC().Truncate(time.Millisecond)
	source := &retryFirewallHitSource{batches: [][]eventspool.Envelope{{
		firewallHitEnvelope(scopeID, telemetryTestSiteID, now),
		firewallHitEnvelope(scopeID, uuid.NewString(), now), // site without telemetry identity
	}}}
	runner, err := newTelemetrySourceRunner(telemetrySourceConfig{
		DeploymentRoot: root, SpoolRoot: spoolRoot, EnrollmentNodeID: telemetryTestNodeID,
		PollInterval: time.Millisecond, MaxLineBytes: 64 << 10, MaxBatchEvents: 100,
		MaxQuarantineBytes: 1 << 20,
	}, spool)
	if err != nil {
		t.Fatal(err)
	}
	runner.firewallHits = source
	if err := runner.syncOnce(context.Background()); err != nil {
		t.Fatalf("sync error = %v", err)
	}

	publisher := &capturePublication{}
	result, err := spool.Flush(context.Background(), publisher, 100)
	if err != nil || result.Published != 1 || len(publisher.publications) != 1 {
		t.Fatalf("Flush() = %+v, publications=%d, error=%v", result, len(publisher.publications), err)
	}
	var publication struct {
		Type     string `json:"type"`
		TenantID string `json:"tenant_id"`
		Events   []struct {
			TenantID      string `json:"tenant_id"`
			SiteID        string `json:"site_id"`
			ConfigVersion string `json:"config_version_id"`
			EventType     string `json:"event_type"`
		} `json:"events"`
	}
	if err := json.Unmarshal(publisher.publications[0].Payload, &publication); err != nil {
		t.Fatal(err)
	}
	if publication.Type != "security.v2" || publication.TenantID != telemetryTestTenantID || len(publication.Events) != 1 ||
		publication.Events[0].TenantID != telemetryTestTenantID || publication.Events[0].SiteID != telemetryTestSiteID ||
		publication.Events[0].ConfigVersion != "cfg-v1" || publication.Events[0].EventType != "global_firewall" {
		t.Fatalf("firewall hit publication = %s", publisher.publications[0].Payload)
	}
}
