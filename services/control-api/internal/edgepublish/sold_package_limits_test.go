package edgepublish

import (
	"encoding/json"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"slices"
	"testing"
)

func TestSoldPackageLimitsPreserveMissingAndGateExplicitCapabilities(t *testing.T) {
	missing, err := decodeSoldPackageLimits([]byte(`{}`))
	if err != nil || missing.WAF != nil || missing.WebSocket != nil {
		t.Fatalf("legacy changed: %+v %v", missing, err)
	}
	limits, err := decodeSoldPackageLimits([]byte(`{"connections":20,"websocket":false,"http3":false,"custom_cc":false,"waf":false}`))
	if err != nil {
		t.Fatal(err)
	}
	limits.subscriptionID = uuid.New()
	bindings := []securityBindingFact{{policy: securitypolicy.Policy{Kind: securitypolicy.KindCC}}, {policy: securitypolicy.Policy{Kind: securitypolicy.KindWAF}}, {policy: securitypolicy.Policy{Kind: securitypolicy.KindACL}}}
	filtered := soldPackageSecurityBindings(bindings, limits)
	if len(filtered) != 1 || filtered[0].policy.Kind != securitypolicy.KindACL || len(bindings) != 3 {
		t.Fatal("capability filter lost ACL or mutated source")
	}
	var document siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(document.Sites[0].ID)
	applySoldPackageRuntimeV2Limits(&document, map[uuid.UUID]soldPackageLimits{id: limits})
	if *document.Sites[0].WebSocket || slices.Contains(document.Sites[0].Listeners[0].Protocols, "http3") || document.Sites[0].PackageLimits.Connections != 20 {
		t.Fatal("gated capabilities survived")
	}
	raw, _ := json.Marshal(document)
	_, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Package limits need no more than the 1.0.35 baseline (site_runtime v6).
	for _, capability := range capabilities {
		if capability.Name.String() == "CAPABILITY_NAME_SITE_RUNTIME" && capability.ApiVersion != edgeconfig.MinSiteRuntimeVersion {
			t.Fatalf("site_runtime = %d, want the baseline %d", capability.ApiVersion, edgeconfig.MinSiteRuntimeVersion)
		}
	}
}

func TestSoldPackageLimitsRejectMalformedExplicitValues(t *testing.T) {
	for _, raw := range []string{`null`, `{"connections":null}`, `{"connections":65536}`, `{"websocket":null}`, `{"waf":"false"}`} {
		if _, err := decodeSoldPackageLimits([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

// ge-analytics: a sold package's bandwidth is a node limit, not only an alert.
func TestSoldPackageBandwidthBecomesNodeLimit(t *testing.T) {
	for raw, want := range map[string]*edgeconfig.PackageConnectionLimit{
		`{"bandwidth_bps":100000000}`:                 {Connections: -1, BandwidthBPS: 100_000_000},
		`{"bandwidth_bps":-1,"connections":-1}`:       nil,
		`{"bandwidth_bps":0}`:                         nil,
		`{"bandwidth_bps":80000000,"connections":20}`: {Connections: 20, BandwidthBPS: 80_000_000},
		`{"connections":20}`:                          {Connections: 20},
	} {
		limits, err := decodeSoldPackageLimits([]byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		limits.subscriptionID = uuid.New()
		var document siteRuntimeV2Document
		if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
			t.Fatal(err)
		}
		applySoldPackageRuntimeV2Limits(&document, map[uuid.UUID]soldPackageLimits{uuid.MustParse(document.Sites[0].ID): limits})
		got := document.Sites[0].PackageLimits
		if want == nil {
			if got != nil {
				t.Fatalf("%s: unlimited package got a node limit %+v", raw, got)
			}
			continue
		}
		if got == nil || got.Connections != want.Connections || got.BandwidthBPS != want.BandwidthBPS ||
			got.SubscriptionID != limits.subscriptionID.String() {
			t.Fatalf("%s: limit = %+v, want %+v", raw, got, want)
		}
		encoded, _ := json.Marshal(document)
		if _, _, _, _, err := compileSiteRuntimeV2Document(encoded); err != nil {
			t.Fatalf("%s: compile: %v", raw, err)
		}
	}
	for _, raw := range []string{`{"bandwidth_bps":null}`, `{"bandwidth_bps":-2}`, `{"bandwidth_bps":1000000000000000001}`} {
		if _, err := decodeSoldPackageLimits([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
