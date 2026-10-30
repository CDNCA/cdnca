package nodeidentity

import (
	"testing"

	"github.com/google/uuid"
)

// G8-a 缺陷 3：v2 快照带站点全部域名，遥测绑定与实时名册曾要求每站 1 个域名，
// 多域名站点的节点遥测被整份拒绝。名册每个监听一条，代表域名取第一个域名，
// 与主控 buildSiteRuntimeV2TelemetryManifest 下发的清单一致。
func TestTelemetrySiteRuntimeV2AcceptsMultiDomainSite(t *testing.T) {
	document := siteRuntimeV2Fixture(t)
	scopeID := uuid.MustParse(document["configuration_scope_id"].(string))
	configID := uuid.MustParse(document["config_version_id"].(string))
	tenantID := uuid.MustParse(document["streams"].(map[string]any)["tenant_id"].(string))
	site := document["sites"].([]any)[0].(map[string]any)
	siteID := uuid.MustParse(site["id"].(string))
	site["domains"] = []any{"route.example.test", "static.route.example.test", "www.route.example.test"}

	raw, digest := encodeSnapshot(t, document)
	bindings, listeners, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{siteID: uuid.MustParse("99999999-9999-4999-8999-999999999999")}, recorded: true})
	if err != nil {
		t.Fatalf("multi-domain site runtime v2 snapshot: %v", err)
	}
	if len(bindings) != 3 || len(listeners) != 2 { // the site and the fixture's two forwards
		t.Fatalf("bindings = %#v, listeners = %#v", bindings, listeners)
	}
	for _, listener := range listeners {
		if listener.SiteID != siteID.String() || listener.Domain != "route.example.test" {
			t.Fatalf("listener = %#v, want the site's first domain", listener)
		}
	}
	site["domains"] = []any{}
	raw, digest = encodeSnapshot(t, document)
	if _, _, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID, telemetrySiteSubscriptions{}); err == nil {
		t.Fatal("site without domains accepted")
	}
}

// A v2 site serving several domains (the control plane lists the primary
// first) binds like any other: before g11-v2a the reader refused it, and a
// single-scope node with such a site lost its whole telemetry session.
func TestTelemetrySiteRuntimeV2BindsMultiDomainSiteUnderItsPrimaryDomain(t *testing.T) {
	document := siteRuntimeV2Fixture(t)
	scopeID := uuid.MustParse(document["configuration_scope_id"].(string))
	configID := uuid.MustParse(document["config_version_id"].(string))
	tenantID := uuid.MustParse(document["streams"].(map[string]any)["tenant_id"].(string))
	site := document["sites"].([]any)[0].(map[string]any)
	siteID := uuid.MustParse(site["id"].(string))
	site["domains"] = []any{"route.example.test", "alias.example.test"}
	subscriptionID := uuid.MustParse("99999999-9999-4999-8999-999999999999")

	raw, digest := encodeSnapshot(t, document)
	bindings, listeners, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{siteID: subscriptionID}, recorded: true})
	if err != nil {
		t.Fatalf("multi-domain site runtime v2 snapshot: %v", err)
	}
	if len(bindings) != 3 || bindings[0].SiteID != siteID || bindings[0].PackageSubscriptionID != subscriptionID {
		t.Fatalf("bindings = %#v", bindings)
	}
	if len(listeners) != 2 {
		t.Fatalf("listeners = %#v", listeners)
	}
	for _, listener := range listeners {
		if listener.Domain != "route.example.test" {
			t.Fatalf("listener domain = %q, want the primary", listener.Domain)
		}
	}
}
