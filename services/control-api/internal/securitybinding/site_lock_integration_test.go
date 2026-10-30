package securitybinding

import (
	"context"
	"errors"
	"testing"
	"time"
)

// FX31: a tenant cannot publish a security binding to a site locked by a
// platform administrator; unlocking restores publication.
func TestPublishRejectsLockedSiteForTenant(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, 5*time.Minute)
	setLocked := func(locked bool) {
		t.Helper()
		query := `UPDATE sites SET lock_reason=NULL,locked_at=NULL,locked_by_user_id=NULL WHERE id=$1`
		if locked {
			query = `UPDATE sites SET lock_reason='audit',locked_at=now(),locked_by_user_id=owner_user_id WHERE id=$1`
		}
		if _, err := fixture.pool.Exec(context.Background(), query, fixture.tenantA.siteID); err != nil {
			t.Fatal(err)
		}
	}
	setLocked(true)
	request := publishRequest(fixture.tenantA, "locked-v1", 1, 0, 0)
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), request); !errors.Is(err, ErrSiteLocked) {
		t.Fatalf("locked publish = %v, want ErrSiteLocked", err)
	}
	assertCounts(t, fixture.pool, 0, 0, 0, 0)
	setLocked(false)
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), request); err != nil {
		t.Fatalf("unlocked publish = %v", err)
	}
}
