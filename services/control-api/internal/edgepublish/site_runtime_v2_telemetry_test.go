package edgepublish

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// The v2 document lists a site's primary domain first, the domain the legacy
// renderer keys the site's telemetry on.
func TestSiteRuntimeV2DomainsPutPrimaryFirst(t *testing.T) {
	for name, test := range map[string]struct {
		fact siteFact
		want []string
	}{
		"primary sorted later": {fact: siteFact{domain: "www.example.test", domains: []string{"a.example.test", "www.example.test", "z.example.test"}},
			want: []string{"www.example.test", "a.example.test", "z.example.test"}},
		"primary already first": {fact: siteFact{domain: "a.example.test", domains: []string{"a.example.test", "b.example.test"}},
			want: []string{"a.example.test", "b.example.test"}},
		"primary not live": {fact: siteFact{domain: "gone.example.test", domains: []string{"a.example.test", "b.example.test"}},
			want: []string{"a.example.test", "b.example.test"}},
		"no domain facts": {fact: siteFact{domain: "only.example.test"}, want: []string{"only.example.test"}},
	} {
		t.Run(name, func(t *testing.T) {
			before := append([]string(nil), test.fact.domains...)
			if got := siteRuntimeV2Domains(test.fact); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("domains = %v, want %v", got, test.want)
			}
			if !reflect.DeepEqual(test.fact.domains, before) && before != nil {
				t.Fatal("siteRuntimeV2Domains mutated the fact")
			}
		})
	}
}

// A v2 site with several domains gets one telemetry entry per listener under
// its first (primary) domain; before, the manifest refused every
// multi-domain site and the whole v2 publication failed.
func TestSiteRuntimeV2TelemetryManifestKeysEveryListenerOnPrimaryDomain(t *testing.T) {
	scopeID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7c01")
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7c02")
	configID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7c03")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7c04")
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: scopeID.String(), SourceRevision: 3, ConfigVersionID: configID.String(),
		Sites: []siteRuntimeV2Site{{
			ID: siteID.String(), Domains: []string{"www.example.test", "a.example.test"},
			Listeners: []siteRuntimeV2Listener{{Port: 80}, {Port: 443}},
		}},
	}
	content, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7c05"),
		configID, 3, document, nil, nil, noAccessLogFields, filepath.Join(t.TempDir(), "edge"))
	if err != nil {
		t.Fatalf("multi-domain site: %v", err)
	}
	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Sites) != 2 || manifest.Sites[0].ListenPort != 80 || manifest.Sites[1].ListenPort != 443 {
		t.Fatalf("telemetry listeners = %+v", manifest.Sites)
	}
	for _, site := range manifest.Sites {
		if site.Domain != "www.example.test" {
			t.Fatalf("telemetry domain = %q, want the primary", site.Domain)
		}
	}
}
