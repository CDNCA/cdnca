package edgepublish

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

// SecurityReleaseSite is one site of a security smoke release: a plain HTTP
// listener carrying the listener security control-api compiled for it.
type SecurityReleaseSite struct {
	ID       string
	Domain   string
	Port     int
	Origin   string
	OriginAt int
	Security *edgeconfig.ListenerSecurity
}

// WriteSecurityRelease writes, for the security smokes, the signed site
// runtime release control-api publishes for sites (document, telemetry
// identity, CRS files of their managed WAF) as release files under output
// (signed-release/), plus the deployment root the node renders against
// (/runtime, as scripts/security run it). cmd/site-runtime-release
// (agents/edge-agent) compiles it into the release OpenResty runs.
func WriteSecurityRelease(t *testing.T, output, scopeID, versionID string, sites []SecurityReleaseSite,
	rules *edgeconfig.CRSRuleText, profiles securitypolicy.CRSProfiles) {
	t.Helper()
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: scopeID, ConfigVersionID: versionID, SourceRevision: 1,
		// The baseline compileSiteRuntimeV2Source starts from.
		RequiredCapabilities: []siteRuntimeV2Capability{{Name: "http1", APIVersion: 1}, {Name: "ipv4", APIVersion: 1},
			{Name: "site_runtime", APIVersion: edgeconfig.MinSiteRuntimeVersion}, {Name: "websocket", APIVersion: 1}},
	}
	trueValue, falseValue := true, false
	for _, site := range sites {
		document.Sites = append(document.Sites, siteRuntimeV2Site{
			ID: site.ID, Revision: 1, Domains: []string{site.Domain}, DefaultPoolID: "primary",
			WebSocket: &falseValue, Range: &trueValue,
			Listeners: []siteRuntimeV2Listener{{ID: "public-" + strconv.Itoa(site.Port), AddressFamily: "ipv4",
				Port: int64(site.Port), Protocols: []string{"http1"}, Security: site.Security}},
			OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin", Algorithm: "round_robin",
				Origins: []siteRuntimeV2Origin{{ID: "origin", Tier: "origin", Scheme: "http", Host: site.Origin,
					Port: int64(site.OriginAt), Weight: 1}},
				Retry: siteRuntimeV2RetryPolicy{Methods: []string{"GET", "HEAD"}, BodylessOnly: &trueValue, ResponseNotStarted: &trueValue,
					RetryOn:     []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
					MaxAttempts: 1, ConnectTimeoutMS: 250, ReadTimeoutMS: 2000, TotalBudgetMS: 2250}}},
			L2: siteRuntimeV2L2Policy{Enabled: &falseValue, ProbeIntervalMS: 10000, FailureThreshold: 3,
				RecoveryThreshold: 3, SingleHalfOpenProbe: &trueValue, MaxHops: 1},
		})
	}
	setSiteRuntimeV2SecurityCapabilities(&document)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatalf("site runtime document: %v", err)
	}
	var crs map[string][]byte
	if rules != nil {
		crs, err = siteRuntimeV2CRSFiles(canonical, rules, profiles, nil)
		if err != nil {
			t.Fatalf("CRS files: %v", err)
		}
	}
	telemetry, err := securityReleaseTelemetry(document, "/runtime")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := buildSiteRuntimeV2Bundle(canonical, nil, nil, nil, nil, crs, telemetry)
	if err != nil {
		t.Fatalf("site runtime bundle: %v", err)
	}
	for name, content := range bundle.Files {
		path := filepath.Join(output, "signed-release", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// securityReleaseTelemetry is the signed telemetry identity of every listener
// (deploymentRoot: the node's deployment root as the smoke runs it).
func securityReleaseTelemetry(document siteRuntimeV2Document, deploymentRoot string) ([]byte, error) {
	manifest := edgeconfig.TelemetryIdentityManifest{
		SchemaVersion: 1, ConfigVersionID: document.ConfigVersionID, ConfigRevision: uint64(document.SourceRevision),
		TenantID:           document.ConfigurationScopeID,
		CapturePolicy:      edgeconfig.TelemetryCapturePolicyManifest{SchemaVersion: 1},
		SourceCapabilities: edgeconfig.TelemetrySourceCapabilities{SchemaVersion: 1},
	}
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			port := uint16(listener.Port)
			access, security := edgeconfig.TelemetryLogPaths(deploymentRoot, document.ConfigVersionID, site.ID, port)
			manifest.Sites = append(manifest.Sites, edgeconfig.TelemetrySiteIdentity{SiteID: site.ID, Domain: site.Domains[0],
				ListenPort: port, NamespaceID: edgeconfig.CacheSiteNamespaceID(manifest.TenantID, site.ID),
				AccessLogPath: access, SecurityLogPath: security})
			manifest.CapturePolicy.Sites = append(manifest.CapturePolicy.Sites, edgeconfig.TelemetrySiteCapturePolicy{
				SiteID: site.ID, Domain: site.Domains[0], ListenPort: port, Methods: []string{}, URIPrefixes: []string{},
				RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{},
				ResponseBodyFieldAllowlist: []string{}, MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20})
		}
	}
	sortTelemetrySites(&manifest)
	content, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	content = append(content, '\n')
	if _, err := edgeconfig.ParseTelemetryIdentityManifest(content); err != nil {
		return nil, err
	}
	return content, nil
}

// sortTelemetrySites orders listeners by (port, domain) as the manifest requires.
func sortTelemetrySites(manifest *edgeconfig.TelemetryIdentityManifest) {
	for i := 1; i < len(manifest.Sites); i++ {
		for j := i; j > 0; j-- {
			left, right := manifest.Sites[j-1], manifest.Sites[j]
			if left.ListenPort < right.ListenPort || left.ListenPort == right.ListenPort && left.Domain < right.Domain {
				break
			}
			manifest.Sites[j-1], manifest.Sites[j] = right, left
			manifest.CapturePolicy.Sites[j-1], manifest.CapturePolicy.Sites[j] = manifest.CapturePolicy.Sites[j], manifest.CapturePolicy.Sites[j-1]
		}
	}
}
