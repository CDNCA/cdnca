package edgeconfig

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Site runtime v8 (site objects) has no 1000-listener scope limit: the
// telemetry identity manifest of a 5000-site scope (7500 listeners, several
// MiB) must parse.
func TestTelemetryIdentityManifestAcceptsLargeScopes(t *testing.T) {
	const (
		tenantID  = "7e000000-0000-4000-8000-000000000001"
		configID  = "c0000000-0000-4000-8000-000000000001"
		stateRoot = "/var/lib/cdnca-edge"
	)
	manifest := TelemetryIdentityManifest{SchemaVersion: 1, ConfigVersionID: configID, ConfigRevision: 1, TenantID: tenantID,
		CapturePolicy: TelemetryCapturePolicyManifest{SchemaVersion: 1}, SourceCapabilities: TelemetrySourceCapabilities{SchemaVersion: 1}}
	for _, port := range []uint16{80, 443} {
		for index := 0; index < 5000; index++ {
			if port == 443 && index%2 == 1 {
				continue
			}
			siteID := fmt.Sprintf("%08x-0000-4000-8000-%012x", index+1, index+1)
			domain := fmt.Sprintf("s%05d.example.com", index)
			access, security := TelemetryLogPaths(stateRoot, configID, siteID, port)
			manifest.Sites = append(manifest.Sites, TelemetrySiteIdentity{SiteID: siteID, Domain: domain, ListenPort: port,
				NamespaceID: CacheSiteNamespaceID(tenantID, siteID), AccessLogPath: access, SecurityLogPath: security})
			manifest.CapturePolicy.Sites = append(manifest.CapturePolicy.Sites, TelemetrySiteCapturePolicy{SiteID: siteID,
				Domain: domain, ListenPort: port, Methods: []string{}, URIPrefixes: []string{}, RequestHeaderAllowlist: []string{},
				ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{}})
		}
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) <= 1<<20 {
		t.Fatalf("fixture is only %d bytes", len(content))
	}
	parsed, err := ParseTelemetryIdentityManifest(append(content, '\n'))
	if err != nil || len(parsed.Sites) != 7500 {
		t.Fatalf("%d listeners: %v", len(parsed.Sites), err)
	}
}
