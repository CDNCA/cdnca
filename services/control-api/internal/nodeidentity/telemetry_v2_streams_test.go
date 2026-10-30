package nodeidentity

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// v12 起转发自己是遥测分区（信封 site_id = 转发 ID）。授权快照给每条
// 转发一条绑定，带本版本发布时它的套餐（运行时 package_subscription_id）；没有套餐的为空。
// 网关按这条绑定核对四层事实上的套餐。
func TestTelemetrySiteRuntimeV2BindsForwardsWithTheirPackage(t *testing.T) {
	document := siteRuntimeV2Fixture(t)
	scopeID := uuid.MustParse(document["configuration_scope_id"].(string))
	configID := uuid.MustParse(document["config_version_id"].(string))
	tenantID := uuid.MustParse(document["streams"].(map[string]any)["tenant_id"].(string))
	siteID := uuid.MustParse(document["sites"].([]any)[0].(map[string]any)["id"].(string))
	streams := document["streams"].(map[string]any)["streams_v2"].([]any)
	packaged := streams[0].(map[string]any)
	packagedID := uuid.MustParse(packaged["stream_id"].(string))
	unpackagedID := uuid.MustParse(streams[1].(map[string]any)["stream_id"].(string))
	subscriptionID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	packaged["package_subscription_id"] = subscriptionID.String()

	raw, digest := encodeSnapshot(t, document)
	bindings, _, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{siteID: uuid.Nil}, recorded: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]TelemetrySiteScope{}
	for _, binding := range bindings {
		got[binding.SiteID] = binding
	}
	want := TelemetrySiteScope{SiteID: packagedID, TenantID: tenantID, ConfigurationScopeID: scopeID,
		ConfigVersionID: configID, PackageSubscriptionID: subscriptionID}
	if len(bindings) != 3 || got[packagedID] != want {
		t.Fatalf("packaged forward binding = %#v (all %#v)", got[packagedID], bindings)
	}
	if binding, ok := got[unpackagedID]; !ok || binding.PackageSubscriptionID != uuid.Nil {
		t.Fatalf("forward without a package = %#v ok=%v", binding, ok)
	}

	// 转发 ID 与网站 ID 撞车：拒绝（同一遥测分区不能有两份身份）。
	packaged["stream_id"] = siteID.String()
	packaged["geo"].(map[string]any)["stream_id"] = siteID.String()
	raw, digest = encodeSnapshot(t, document)
	if _, _, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{siteID: uuid.Nil}, recorded: true}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("stream sharing a site ID err = %v", err)
	}
}
