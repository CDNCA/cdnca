//go:build integration

package errorpagecontrol

import (
	"strconv"
	"testing"
)

// errpage-5 / errpage-ovr（待出包前全量跑）: an area / node override of a slot the node
// gives itself is pinned into the publication snapshot (snapshotOverrideSlots,
// with its region / node_id selector) and every create / update / delete
// queues the slot republication (publishSlotsTx); deleting it drops it from
// the next snapshot. An override of a site page slot (http_502) is
// delivered too (errpage-ovr): pinned as an edge_connect 502 slot with its
// selector, which edgepublish turns into site page variants.
//
//	TEST_DATABASE_URL=... go -C services/control-api test -tags integration -count=1 \
//	  -run TestScopeOverrideChangesPublishSlotsPostgreSQL ./internal/errorpagecontrol/
func TestScopeOverrideChangesPublishSlotsPostgreSQL(t *testing.T) {
	fixture := openScopeOverrideDatabase(t)
	identities := seedScopeOverrideIdentities(t, fixture.pool)
	service := newScopeOverrideTestService(t, fixture.pool)
	republisher := &countingSlotRepublisher{}
	if err := service.WithSlotRepublisher(republisher); err != nil {
		t.Fatal(err)
	}
	nodeID := seedScopeOverrideNode(t, fixture.pool, identities.platform, 61, "cn-east", "192.0.2.61")
	regionBody := []byte(`<!doctype html><html><body>region node ip page</body></html>`)
	nodeBody := []byte(`<!doctype html><html><body>node node ip page</body></html>`)
	regionAsset := readyAsset(t, service, identities.platform, identities.platformScope, "override-publish-region", regionBody, "text/html")
	nodeAsset := readyAsset(t, service, identities.platform, identities.platformScope, "override-publish-node", nodeBody, "text/html")

	overrideSlots := func(step string) []SnapshotSlot {
		t.Helper()
		snapshot, err := service.PublicationSnapshot(t.Context(), identities.platform)
		if err != nil {
			t.Fatalf("%s snapshot: %v", step, err)
		}
		var slots []SnapshotSlot
		for _, slot := range snapshot.Policy.Slots {
			if slot.Region != "" || slot.NodeID != "" {
				slots = append(slots, slot)
			}
		}
		return slots
	}
	calls := func(step string, want int) {
		t.Helper()
		if republisher.calls != want {
			t.Fatalf("%s: republication queued %d times, want %d", step, republisher.calls, want)
		}
	}

	region, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideRegion, Region: "cn-east",
		Items: []ScopeOverrideBinding{{Key: SlotNodeIPAccess, AssetID: regionAsset.ID},
			{Key: SlotHTTP502, AssetID: regionAsset.ID}},
		WriteMetadata: writeMetadata("override-publish-region-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	calls("region create", 1)
	slots := overrideSlots("region create")
	// ordered by slot key: http_502 before node_ip_access
	if len(slots) != 2 || slots[0].Key != SlotHTTP502 || slots[0].Category != CategoryEdgeConnect || slots[0].Status != 502 ||
		slots[0].Region != "cn-east" || slots[0].NodeID != "" || slots[0].Resource.SHA256 != regionAsset.SHA256 ||
		slots[1].Key != SlotNodeIPAccess || slots[1].Region != "cn-east" || slots[1].NodeID != "" ||
		slots[1].Category != slotOwnPages[SlotNodeIPAccess].Category || slots[1].Status != 403 ||
		slots[1].Resource.SHA256 != regionAsset.SHA256 {
		t.Fatalf("region create slots=%#v (http_502 must be delivered)", slots)
	}

	node, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideNode, NodeDisplayID: 61,
		Items:         []ScopeOverrideBinding{{Key: SlotNodeIPAccess, AssetID: nodeAsset.ID}},
		WriteMetadata: writeMetadata("override-publish-node-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	calls("node create", 2)
	slots = overrideSlots("node create")
	// ordered by slot key, node ID ("" first), region
	if len(slots) != 3 || slots[0].Key != SlotHTTP502 || slots[1].Key != SlotNodeIPAccess || slots[1].Region != "cn-east" ||
		slots[2].NodeID != nodeID.String() || slots[2].Resource.SHA256 != nodeAsset.SHA256 {
		t.Fatalf("node create slots=%#v", slots)
	}

	regionDisplayID, err := strconv.ParseInt(region.Value.DisplayID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateScopeOverride(t.Context(), identities.platform, UpdateScopeOverrideRequest{
		DisplayID: regionDisplayID, ExpectedRevision: 1,
		Items:         []ScopeOverrideBinding{{Key: SlotNodeIPAccess, AssetID: nodeAsset.ID}},
		WriteMetadata: writeMetadata("override-publish-region-update"),
	}); err != nil {
		t.Fatal(err)
	}
	calls("region update", 3)
	slots = overrideSlots("region update")
	// the update drops http_502 from the region override
	if len(slots) != 2 || slots[0].Key != SlotNodeIPAccess || slots[0].Region != "cn-east" || slots[0].Resource.SHA256 != nodeAsset.SHA256 {
		t.Fatalf("region update slots=%#v", slots)
	}

	nodeDisplayID, err := strconv.ParseInt(node.Value.DisplayID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeleteScopeOverride(t.Context(), identities.platform, DeleteScopeOverrideRequest{
		DisplayID: nodeDisplayID, ExpectedRevision: 1, WriteMetadata: writeMetadata("override-publish-node-delete"),
	}); err != nil {
		t.Fatal(err)
	}
	calls("node delete", 4)
	if slots = overrideSlots("node delete"); len(slots) != 1 || slots[0].Region != "cn-east" {
		t.Fatalf("node delete slots=%#v", slots)
	}
	if _, err := service.DeleteScopeOverride(t.Context(), identities.platform, DeleteScopeOverrideRequest{
		DisplayID: regionDisplayID, ExpectedRevision: 2, WriteMetadata: writeMetadata("override-publish-region-delete"),
	}); err != nil {
		t.Fatal(err)
	}
	calls("region delete", 5)
	if slots = overrideSlots("region delete"); len(slots) != 0 {
		t.Fatalf("region delete slots=%#v", slots)
	}
	// a retired node's override is not delivered
	if _, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideNode, NodeDisplayID: 61,
		// blacklist 不在可覆盖槽位（ErrorPageScopeOverrideSlotKeys / 迁移 220 约束）里，用 node_ip_access
		Items:         []ScopeOverrideBinding{{Key: SlotNodeIPAccess, AssetID: nodeAsset.ID}},
		WriteMetadata: writeMetadata("override-publish-node-restore"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE nodes SET admin_state='retired' WHERE id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	// 快照是最近一次已存的发布；直接改库退役节点不产生新发布，绑定一个全局槽位触发下一次固化。
	if _, err := service.BindSlot(t.Context(), identities.platform, BindSlotRequest{
		Key: SlotHTTP502, AssetID: regionAsset.ID, WriteMetadata: writeMetadata("override-publish-after-retire"),
	}); err != nil {
		t.Fatal(err)
	}
	if slots = overrideSlots("retired node"); len(slots) != 0 {
		t.Fatalf("retired node slots=%#v", slots)
	}
}
