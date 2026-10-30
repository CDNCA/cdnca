package systemconfig

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Saving the ddos_protection category stores the canonical
// value, needs no entitlement (nil expansion authorizer) and writes the
// create_draft audit event naming the category.
func TestDDoSProtectionCategorySaveIsCanonicalAndAudited(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	activateInitialSystemConfiguration(t, fixture)
	manager, err := NewCategoryManager(fixture.service, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryDDoSProtection, ExpectedHeadRevision: 1,
		Change: CategoryChange{DDoSProtection: &edgeconfig.DDoSProtection{MaxConnectionsPerIP: 200, NewConnectionsPerSecond: 50,
			RateBanSeconds: 600, AllowNetworks: []string{"192.0.2.9", "192.0.2.0/24"}, CCKernelBan: edgeconfig.CCKernelBanSitePorts}},
		IdempotencyKey: "ddos-save", RequestID: "ddos-save",
	})
	if err != nil {
		t.Fatal(err)
	}
	value, ok := result.Value.(edgeconfig.DDoSProtection)
	if !ok || value.MaxConnectionsPerIP != 200 || len(value.AllowNetworks) != 2 || value.AllowNetworks[0] != "192.0.2.0/24" {
		t.Fatalf("saved value = %#v", result.Value)
	}
	var action, payload string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT action,payload::text FROM audit_events WHERE request_id='ddos-save'`).
		Scan(&action, &payload); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil || action != operationCreateDraft || decoded["category"] != CategoryDDoSProtection {
		t.Fatalf("audit = %s %s (%v)", action, payload, err)
	}
	read, err := manager.GetActiveCategory(t.Context(), fixture.platform, CategoryDDoSProtection)
	if err != nil || read.HeadRevision != result.Revision {
		t.Fatalf("read back = %+v, %v", read, err)
	}
}
