//go:build integration

package marketsubscribehttp

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// listingTestPool needs migration 429 (MARKET_BUYER_TEST_DATABASE_URL).
func listingTestPool(t *testing.T) *PostgresListingStore {
	t.Helper()
	pool := buyerTestPool(t)
	var ok bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('market_listing_batch_items') IS NOT NULL`).Scan(&ok); err != nil || !ok {
		t.Skip("database is not migrated through 429")
	}
	return NewPostgresListingStore(pool)
}

func TestPostgresListingTemplates(t *testing.T) {
	store := listingTestPool(t)
	ctx := t.Context()
	platform, user := platformScope(t, store.pool), uuid.New()
	name := "ml11b-" + uuid.NewString()[:8]
	saved, err := store.PutTemplate(ctx, platform, user, ListingTemplate{Name: name, Body: json.RawMessage(`{"price":100}`)})
	if err != nil || saved.Revision != 1 {
		t.Fatalf("create %+v %v", saved, err)
	}
	if _, err := store.PutTemplate(ctx, platform, user, ListingTemplate{Name: name, Body: json.RawMessage(`{}`)}); !errors.Is(err, ErrListingConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	updated, err := store.PutTemplate(ctx, platform, user, ListingTemplate{ID: saved.ID, Name: name, Body: json.RawMessage(`{"price":120}`), Revision: 1})
	if err != nil || updated.Revision != 2 {
		t.Fatalf("update %+v %v", updated, err)
	}
	if _, err := store.PutTemplate(ctx, platform, user, ListingTemplate{ID: saved.ID, Name: name, Body: json.RawMessage(`{}`), Revision: 1}); !errors.Is(err, ErrListingConflict) {
		t.Fatalf("stale: %v", err)
	}
	if _, err := store.PutTemplate(ctx, platform, user, ListingTemplate{ID: uuid.New(), Name: "x", Body: json.RawMessage(`{}`), Revision: 1}); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("missing: %v", err)
	}
	items, err := store.Templates(ctx, platform)
	found := false
	for _, item := range items {
		found = found || item.ID == saved.ID && string(item.Body) == `{"price": 120}`
	}
	if err != nil || !found {
		t.Fatalf("list %+v %v", items, err)
	}
	if err := store.DeleteTemplate(ctx, platform, saved.ID, 1); !errors.Is(err, ErrListingConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err := store.DeleteTemplate(ctx, platform, saved.ID, 2); err != nil {
		t.Fatal(err)
	}
	// Templates belong to the platform scope.
	if _, err := store.PutTemplate(ctx, tenantScope(t, store.pool), user, ListingTemplate{Name: name, Body: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("tenant scope template accepted")
	}
}

func TestPostgresListingBatchItemLease(t *testing.T) {
	store := listingTestPool(t)
	ctx := t.Context()
	platform, user := platformScope(t, store.pool), uuid.New()
	sum := sha256.Sum256([]byte(uuid.NewString()))
	digest := sum[:]

	// Concurrent submissions of one item: exactly one gets the lease.
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed, busy := 0, 0
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.ClaimItem(ctx, platform, user, digest, time.Minute)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				claimed++
			case errors.Is(err, ErrItemBusy):
				busy++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if claimed != 1 || busy != 3 {
		t.Fatalf("claimed %d busy %d", claimed, busy)
	}
	group, offer := uuid.New(), uuid.New()
	// Recording the group keeps the lease; releasing hands the item on.
	if err := store.SaveItem(ctx, platform, digest, BatchItem{GroupID: &group}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimItem(ctx, platform, user, digest, time.Minute); !errors.Is(err, ErrItemBusy) {
		t.Fatalf("lease after group: %v", err)
	}
	if err := store.ReleaseItem(ctx, platform, digest); err != nil {
		t.Fatal(err)
	}
	item, err := store.ClaimItem(ctx, platform, user, digest, time.Minute)
	if err != nil || item.GroupID == nil || *item.GroupID != group || item.OfferID != nil {
		t.Fatalf("retry claim %+v %v", item, err)
	}
	if err := store.SaveItem(ctx, platform, digest, BatchItem{GroupID: &group, OfferID: &offer}); err != nil {
		t.Fatal(err)
	}
	// Done: every later claim returns the offer, no lease needed.
	for range 2 {
		item, err := store.ClaimItem(ctx, platform, user, digest, time.Minute)
		if err != nil || item.OfferID == nil || *item.OfferID != offer {
			t.Fatalf("done claim %+v %v", item, err)
		}
	}
	if err := store.ReleaseItem(ctx, platform, digest); err != nil {
		t.Fatal(err)
	}
	if item, _ := store.ClaimItem(ctx, platform, user, digest, time.Minute); item.OfferID == nil {
		t.Fatal("release cleared a finished item")
	}
}
