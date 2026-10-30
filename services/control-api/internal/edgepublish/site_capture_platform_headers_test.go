package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecapture"
	"github.com/google/uuid"
)

// noAccessLogFields records no optional header (the manifest is the site's
// own capture policy alone).
var noAccessLogFields = edgeconfig.AccessLogFields{Fields: []string{}}

// fix-logfields: the platform's access log header fields enter every site's
// capture allowlists, whether or not the site has a capture policy.
func TestTelemetryManifestAddsPlatformAccessLogHeaders(t *testing.T) {
	scopeID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	tenantID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	configID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	plainID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	ownID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	own := sitecapture.PolicyDocument{
		Enabled: true, Methods: []string{"GET"}, URIPrefixes: []string{"/api"},
		RequestHeaderAllowlist: []string{"X-Trace"}, MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20,
	}
	raw, err := json.Marshal(own)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	fact, err := decodeSiteCapturePolicyFact(ownID, 3, raw, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	runtime := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: scopeID.String(), SourceRevision: 9, ConfigVersionID: configID.String(),
		Sites: []siteRuntimeV2Site{
			{ID: plainID.String(), Domains: []string{"plain.example.test"}, Listeners: []siteRuntimeV2Listener{{Port: 80}}},
			{ID: ownID.String(), Domains: []string{"own.example.test"}, Listeners: []siteRuntimeV2Listener{{Port: 80}}},
		},
	}
	stateRoot := filepath.Join(t.TempDir(), "edge")
	content, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7183"),
		configID, 9, runtime, nil, map[uuid.UUID]*siteCapturePolicyFact{ownID: fact}, edgeconfig.EffectiveAccessLogFields(nil), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(content)
	if err != nil {
		t.Fatal(err)
	}
	policies := map[string]edgeconfig.TelemetrySiteCapturePolicy{}
	for _, policy := range manifest.CapturePolicy.Sites {
		policies[policy.SiteID] = policy
	}
	plain := policies[plainID.String()]
	if !plain.Enabled || plain.Revision != 0 || plain.EvidenceDigest != "" || len(plain.Methods) != 0 || len(plain.URIPrefixes) != 0 ||
		!slices.Equal(plain.RequestHeaderAllowlist, []string{"Referer", "User-Agent"}) ||
		!slices.Equal(plain.ResponseHeaderAllowlist, []string{"Content-Type"}) {
		t.Fatalf("a site without a capture policy = %+v", plain)
	}
	mine := policies[ownID.String()]
	if !mine.Enabled || mine.Revision != 3 || !slices.Equal(mine.Methods, []string{"GET"}) ||
		!slices.Equal(mine.URIPrefixes, []string{"/api"}) ||
		!slices.Equal(mine.RequestHeaderAllowlist, []string{"Referer", "User-Agent", "X-Trace"}) ||
		!slices.Equal(mine.ResponseHeaderAllowlist, []string{"Content-Type"}) {
		t.Fatalf("a site with its own capture policy = %+v", mine)
	}

	// No header selected: the sites keep exactly their own policies.
	content, err = buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7183"),
		configID, 9, runtime, nil, map[uuid.UUID]*siteCapturePolicyFact{ownID: fact}, noAccessLogFields, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if manifest, err = edgeconfig.ParseTelemetryIdentityManifest(content); err != nil {
		t.Fatal(err)
	}
	for _, policy := range manifest.CapturePolicy.Sites {
		if policy.SiteID == plainID.String() && policy.Enabled {
			t.Fatalf("no header field: the plain site captures %+v", policy)
		}
	}
}
