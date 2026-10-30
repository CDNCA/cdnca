//go:build integration

package systemconfig

import (
	"errors"
	"reflect"
	"testing"
)

// The categories share one revision stream: activating from one page makes
// every pending category effective, so the caller must confirm the set.
func TestCategoryActivationRequiresConfirmedPendingCategories(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	activateInitialSystemConfiguration(t, fixture)
	manager, err := NewCategoryManager(fixture.service, allowExpansion{})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := fixture.service.GetRevision(t.Context(), fixture.platform, 1)
	if err != nil {
		t.Fatal(err)
	}

	monitoring := effectiveNodeMonitoring(initial.Configuration.NodeMonitoring)
	monitoring.ProbeIntervalMS += 1000
	if _, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryNodeMonitoring, ExpectedHeadRevision: 1, Change: CategoryChange{NodeMonitoring: &monitoring},
		IdempotencyKey: "pending-monitor-save", RequestID: "pending-monitor-save",
	}); err != nil {
		t.Fatal(err)
	}
	ddos := EffectiveDDoSProtection(initial.Configuration.DDoSProtection)
	ddos.MaxConnectionsPerIP = 321
	draft, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryDDoSProtection, ExpectedHeadRevision: 2, Change: CategoryChange{DDoSProtection: &ddos},
		IdempotencyKey: "pending-ddos-save", RequestID: "pending-ddos-save",
	})
	if err != nil {
		t.Fatal(err)
	}
	both := []string{CategoryNodeMonitoring, CategoryDDoSProtection}
	if !reflect.DeepEqual(draft.PendingCategories, both) {
		t.Fatalf("save pending = %v, want %v", draft.PendingCategories, both)
	}
	read, err := manager.GetActiveCategory(t.Context(), fixture.platform, CategoryNginx)
	if err != nil || !reflect.DeepEqual(read.PendingCategories, both) {
		t.Fatalf("read pending = %v err=%v", read.PendingCategories, err)
	}

	onlyDDoS := []string{CategoryDDoSProtection}
	if _, err := manager.PreflightRevision(t.Context(), fixture.platform, PreflightRevisionRequest{
		Revision: draft.Revision, SnapshotSHA256: draft.SnapshotSHA256, ExpectedPendingCategories: &onlyDDoS,
		IdempotencyKey: "pending-preflight-stale", RequestID: "pending-preflight-stale",
	}); !errors.Is(err, ErrPendingCategoriesChanged) {
		t.Fatalf("stale preflight err = %v", err)
	}
	reordered := []string{CategoryDDoSProtection, CategoryNodeMonitoring}
	if _, err := manager.PreflightRevision(t.Context(), fixture.platform, PreflightRevisionRequest{
		Revision: draft.Revision, SnapshotSHA256: draft.SnapshotSHA256, ExpectedPendingCategories: &reordered,
		IdempotencyKey: "pending-preflight", RequestID: "pending-preflight",
	}); err != nil {
		t.Fatal(err)
	}

	activate := func(key string, expected *[]string) error {
		_, err := manager.ActivateRevision(t.Context(), fixture.platform, ActivateRequest{
			Revision: draft.Revision, ExpectedActiveRevision: 1, ExpectedPendingCategories: expected,
			IdempotencyKey: key, RequestID: key,
		})
		return err
	}
	if err := activate("pending-activate-missing", nil); !errors.Is(err, ErrPendingCategoriesChanged) {
		t.Fatalf("activation without expected err = %v", err)
	}
	if err := activate("pending-activate-stale", &onlyDDoS); !errors.Is(err, ErrPendingCategoriesChanged) {
		t.Fatalf("activation with stale expected err = %v", err)
	}
	if active, err := fixture.service.GetActive(t.Context(), fixture.platform); err != nil || active.Revision != 1 {
		t.Fatalf("rejected activation changed active: %#v err=%v", active, err)
	}
	if err := activate("pending-activate", &both); err != nil {
		t.Fatal(err)
	}
	for category, want := range map[string]any{CategoryNodeMonitoring: monitoring, CategoryDDoSProtection: ddos} {
		document, err := manager.GetActiveCategory(t.Context(), fixture.platform, category)
		if err != nil || document.ActiveRevision != draft.Revision || !reflect.DeepEqual(document.Value, want) ||
			len(document.PendingCategories) != 0 {
			t.Fatalf("%s after activation = %#v err=%v", category, document, err)
		}
	}

	// A head that changes only the current category needs no confirmation.
	ddos.MaxConnectionsPerIP = 654
	single, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryDDoSProtection, ExpectedHeadRevision: draft.Revision,
		Change:         CategoryChange{DDoSProtection: &ddos},
		IdempotencyKey: "pending-single-save", RequestID: "pending-single-save",
	})
	if err != nil || !reflect.DeepEqual(single.PendingCategories, onlyDDoS) {
		t.Fatalf("single pending = %v err=%v", single.PendingCategories, err)
	}
	if _, err := manager.PreflightRevision(t.Context(), fixture.platform, PreflightRevisionRequest{
		Revision: single.Revision, SnapshotSHA256: single.SnapshotSHA256,
		IdempotencyKey: "pending-single-preflight", RequestID: "pending-single-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ActivateRevision(t.Context(), fixture.platform, ActivateRequest{
		Revision: single.Revision, ExpectedActiveRevision: draft.Revision,
		IdempotencyKey: "pending-single-activate", RequestID: "pending-single-activate",
	}); err != nil {
		t.Fatalf("single-category activation without expected: %v", err)
	}
}
