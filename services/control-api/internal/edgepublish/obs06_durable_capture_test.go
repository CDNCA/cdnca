package edgepublish

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecapture"
	"github.com/google/uuid"
)

func TestOBS06DurableCaptureIdentityEntersImmutableBundles(t *testing.T) {
	scopeID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	tenantID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	siteID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	configID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	document := sitecapture.PolicyDocument{
		Enabled: true, Methods: []string{"GET"}, URIPrefixes: []string{"/api"},
		RequestHeaderAllowlist: []string{"Authorization"}, MaxValueBytes: 4096,
		MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	fact, err := decodeSiteCapturePolicyFact(siteID, 7, raw, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if fact.revision != 7 || fact.evidenceDigest != hex.EncodeToString(digest[:]) {
		t.Fatalf("durable fact identity = %+v", fact)
	}

	runtime := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: scopeID.String(), SourceRevision: 12,
		ConfigVersionID: configID.String(), Sites: []siteRuntimeV2Site{{
			ID: siteID.String(), Domains: []string{"capture.example.test"},
			Listeners: []siteRuntimeV2Listener{{Port: 443}},
		}},
	}
	stateRoot := filepath.Join(t.TempDir(), "edge")
	manifestBytes, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7183"), configID, 12, runtime,
		nil, map[uuid.UUID]*siteCapturePolicyFact{siteID: fact}, noAccessLogFields, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.CapturePolicy.Sites) != 1 || manifest.CapturePolicy.Sites[0].Revision != 7 ||
		manifest.CapturePolicy.Sites[0].EvidenceDigest != hex.EncodeToString(digest[:]) ||
		manifest.TenantID != tenantID.String() || manifest.Sites[0].SiteID != siteID.String() {
		t.Fatalf("site-runtime v2 telemetry identity = %+v", manifest)
	}

	wire, err := marshalSiteRuntimeV2Bundle([]byte(`{"schema":"test"}`), nil, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := edgeconfig.UnmarshalBundle(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := bundle.Files[edgeconfig.TelemetryIdentityManifestPath]; string(got) != string(manifestBytes) {
		t.Fatalf("immutable bundle lost telemetry policy identity: %q", got)
	}
}

func TestOBS06DurableCaptureFactRejectsDigestMismatch(t *testing.T) {
	siteID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	raw := []byte(`{"enabled":false,"methods":[],"uri_prefixes":[],"request_header_allowlist":[],"response_header_allowlist":[],"request_body_field_allowlist":[],"response_body_field_allowlist":[],"max_value_bytes":4096,"max_body_bytes":65536,"max_event_bytes":1048576}`)
	digest := sha256.Sum256(raw)
	digest[0] ^= 0xff
	if _, err := decodeSiteCapturePolicyFact(siteID, 1, raw, digest[:]); err == nil {
		t.Fatal("durable capture fact accepted a mismatched evidence digest")
	}
}
