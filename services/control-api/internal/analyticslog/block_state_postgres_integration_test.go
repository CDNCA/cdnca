//go:build integration

package analyticslog

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

func TestBlockHistoryFormalSchema(t *testing.T) {
	// The store reads tables written by current code: start from the release
	// head (template clone, or a full replay with MigratedPool's own timeout).
	// A one-minute context here used to cover the replay and timed out under
	// load (apply migration 284: context deadline exceeded).
	pool := databasetest.MigratedPool(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	now := time.Date(2026, 10, 9, 6, 0, 0, 0, time.UTC)
	store, err := NewPostgresBlockStateStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	siteID, policyID, tenantScopeID := uuid.New(), uuid.New(), uuid.New()
	from, to := now.Add(-time.Hour), now
	for _, test := range []struct {
		name    string
		scopeID uuid.UUID
		request BlockListRequest
	}{
		{name: "fresh platform", request: BlockListRequest{Limit: 10}},
		{name: "tenant scope", scopeID: tenantScopeID, request: BlockListRequest{Limit: 10}},
		{name: "all filters", scopeID: tenantScopeID, request: BlockListRequest{
			Limit: 10, Offset: 1, SiteID: &siteID, PolicyID: &policyID,
			CIDR: "192.0.2.1/32", OccurredFrom: &from, OccurredTo: &to,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			page, err := store.ListHistory(ctx, test.scopeID, test.request)
			if err != nil {
				t.Fatalf("history against formal migrations: %v", err)
			}
			if page.Items == nil || len(page.Items) != 0 || page.TotalCount != 0 || !page.SnapshotAt.Equal(now) {
				t.Fatalf("empty history = %+v", page)
			}
		})
	}
}
