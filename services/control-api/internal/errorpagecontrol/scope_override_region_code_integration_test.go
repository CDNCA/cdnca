//go:build integration

package errorpagecontrol

import (
	"testing"
)

// fz-x12（待出包前全量跑）: a region override names the region by its
// catalog name, which is often Chinese (华东); the snapshot carries the
// region's catalog code instead (region-<display_id>), the code the node
// learns from its key document, so the override reaches the node instead
// of being dropped for not being lower-case ASCII.
//
//	TEST_DATABASE_URL=... TEST_DATABASE_TEMPLATE=... go -C services/control-api test -tags integration -count=1 \
//	  -run TestScopeOverrideChineseRegionPublishesItsCodePostgreSQL ./internal/errorpagecontrol/
func TestScopeOverrideChineseRegionPublishesItsCodePostgreSQL(t *testing.T) {
	fixture := openScopeOverrideDatabase(t)
	identities := seedScopeOverrideIdentities(t, fixture.pool)
	service := newScopeOverrideTestService(t, fixture.pool)
	// the node's region joins the catalog (sync_node_region_catalog_223)
	seedScopeOverrideNode(t, fixture.pool, identities.platform, 71, "华东", "192.0.2.71")
	var code string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT code FROM region_catalog
		WHERE platform_scope_id=$1 AND name='华东'`, identities.platform.ScopeID).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if code == "" || code == "华东" {
		t.Fatalf("华东 code = %q", code)
	}
	body := []byte(`<!doctype html><html><body>华东 node ip page</body></html>`)
	asset := readyAsset(t, service, identities.platform, identities.platformScope, "override-region-code", body, "text/html")
	if _, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideRegion, Region: "华东",
		Items:         []ScopeOverrideBinding{{Key: SlotNodeIPAccess, AssetID: asset.ID}, {Key: SlotHTTP502, AssetID: asset.ID}},
		WriteMetadata: writeMetadata("override-region-code-create"),
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.PublicationSnapshot(t.Context(), identities.platform)
	if err != nil {
		t.Fatal(err)
	}
	var regions []string
	for _, slot := range snapshot.Policy.Slots {
		if slot.Region != "" {
			regions = append(regions, slot.Key+"="+slot.Region)
		}
	}
	if len(regions) != 2 || regions[0] != SlotHTTP502+"="+code || regions[1] != SlotNodeIPAccess+"="+code {
		t.Fatalf("region slots = %v, want both under %s", regions, code)
	}
}
