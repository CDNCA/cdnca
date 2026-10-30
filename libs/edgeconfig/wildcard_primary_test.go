package edgeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// A site's primary domain may be a wildcard ("*.x.example"): every registry
// keyed on the site's domain keys it on that form, while values compared with
// a request's host stay exact names.

func TestNormalizeSiteDomainName(t *testing.T) {
	for input, want := range map[string]string{
		"*.X.Example.": "*.x.example", "x.example": "x.example", " *.a.b.example ": "*.a.b.example",
	} {
		if got, err := normalizeSiteDomainName(input); err != nil || got != want {
			t.Fatalf("normalizeSiteDomainName(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	long := "*." + strings.Repeat("a", 62) + "." + strings.Repeat("b", 62) + "." + strings.Repeat("c", 62) + "." + strings.Repeat("d", 63)
	if len(long) != 254 {
		t.Fatalf("fixture length %d", len(long))
	}
	for _, input := range []string{"*", "*.", "*.com", "**.x.example", "*x.example", "a.*.x.example", "*.*.x.example", "x", long} {
		if got, err := normalizeSiteDomainName(input); err == nil {
			t.Fatalf("normalizeSiteDomainName(%q) = %q, want error", input, got)
		}
	}
}

func wildcardSecurityListener(t *testing.T, domain string) SecurityListener {
	t.Helper()
	siteID := "11111111-1111-4111-8111-111111111111"
	policy := CCV2Policy{
		SchemaVersion: CCV2SchemaVersion, TenantScopeID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", SiteID: siteID,
		PolicyID: "44444444-4444-4444-8444-444444444444", PolicyVersion: 1,
		BindingID: "33333333-3333-4333-8333-333333333333", BindingRevision: 1,
		PublicationID: "55555555-5555-4555-8555-555555555555", Enabled: true,
		TrustedProxies: []string{}, Allowlist: []string{},
		Rules: []CCV2Rule{{RuleID: "66666666-6666-4666-8666-666666666666", Priority: 10, Flow: CCV2FlowStop,
			Match:     CCV2Match{Path: &CCV2PathMatch{Kind: CCV2PathPrefix, Value: "/limited"}},
			Dimension: CCV2DimensionClientIP,
			Limit:     CCV2Limit{Algorithm: CCV2AlgorithmFixedWindow, Requests: 2, WindowSeconds: 60},
			Action:    CCV2Action{Kind: CCV2ActionTemporaryBan, BanSeconds: 120}}},
	}
	canonical, err := CanonicalCCV2Policy(policy)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	return SecurityListener{SiteID: siteID, Domain: domain, Port: 8080, Protocol: ProtocolHTTP, Security: ListenerSecurity{
		CC: &CCV2SiteBinding{SourceSHA256: strings.Repeat("a", 64), CompiledSHA256: hex.EncodeToString(digest[:]), Policy: policy},
		Policies: []SecurityPolicy{{Kind: SecurityWAF, PolicyID: "22222222-2222-4222-8222-222222222222",
			PolicyVersion: 3, BindingRevision: 1, RuntimeSHA256: strings.Repeat("b", 64), Enabled: true,
			DefaultAction: WAFAllow, Rules: []WAFRule{{RuleID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
				Match:  WAFMatch{Port: 8080, Header: &WAFHeaderMatch{Name: "x-bad", Kind: WAFHeaderExact, Value: "1"}},
				Action: WAFBlock, Control: WAFStop}}}},
	}}
}

func TestRenderSecurityFragmentsKeysWildcardPrimary(t *testing.T) {
	fragments, err := RenderSecurityFragments("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "018f47a2-5b9c-7d31-8a60-104c9c0b7102",
		[]SecurityListener{wildcardSecurityListener(t, "*.x.example")})
	if err != nil {
		t.Fatalf("RenderSecurityFragments(wildcard primary) error = %v", err)
	}
	if fragments.CCV2Registry == nil || len(fragments.CCV2Registry.Entries) != 1 || fragments.CCV2Registry.Entries[0].Hostname != "*.x.example" {
		t.Fatalf("CC v2 registry = %+v", fragments.CCV2Registry)
	}
	encoded, err := CanonicalCCV2Registry(*fragments.CCV2Registry)
	if err != nil || !strings.Contains(string(encoded), `"hostname":"*.x.example"`) {
		t.Fatalf("canonical registry = %s, %v", encoded, err)
	}
	for _, domain := range []string{"*.com", "*.X.example", "a.*.x.example"} {
		if _, err := RenderSecurityFragments("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "018f47a2-5b9c-7d31-8a60-104c9c0b7102",
			[]SecurityListener{wildcardSecurityListener(t, domain)}); err == nil {
			t.Fatalf("RenderSecurityFragments(%q) accepted a non-canonical site domain", domain)
		}
	}
	// A CC host condition may name the wildcard domain the server serves (the
	// engine matches it as server_name does); a non-canonical one is refused.
	if err := validateCCV2Match(CCV2Match{Host: "*.x.example"}); err != nil {
		t.Fatalf("CC v2 match host refused the wildcard site domain: %v", err)
	}
	for _, host := range []string{"*.com", "*.X.example", "a.*.x.example"} {
		if err := validateCCV2Match(CCV2Match{Host: host}); err == nil {
			t.Fatalf("CC v2 match host accepted %q", host)
		}
	}
}

func TestTelemetryIdentityManifestAcceptsWildcardPrimary(t *testing.T) {
	tenantID, siteID, version := "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"
	manifest := TelemetryIdentityManifest{
		SchemaVersion: 1, ConfigVersionID: version, ConfigRevision: 3, TenantID: tenantID,
		Sites: []TelemetrySiteIdentity{{SiteID: siteID, Domain: "*.x.example", ListenPort: 80,
			NamespaceID: CacheSiteNamespaceID(tenantID, siteID), AccessLogPath: "/var/lib/edge/a/access.jsonl",
			SecurityLogPath: "/var/lib/edge/a/security.jsonl"}},
		CapturePolicy: TelemetryCapturePolicyManifest{SchemaVersion: 1, Sites: []TelemetrySiteCapturePolicy{{
			SiteID: siteID, Domain: "*.x.example", ListenPort: 80, Methods: []string{}, URIPrefixes: []string{},
			RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{},
			ResponseBodyFieldAllowlist: []string{}, MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20}}},
		SourceCapabilities: TelemetrySourceCapabilities{SchemaVersion: 1},
	}
	content, _ := json.Marshal(manifest)
	if parsed, err := ParseTelemetryIdentityManifest(content); err != nil || parsed.Sites[0].Domain != "*.x.example" {
		t.Fatalf("ParseTelemetryIdentityManifest(wildcard primary) = %+v, %v", parsed, err)
	}
}
