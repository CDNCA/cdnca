//go:build integration

package cachecontrol

import (
	"context"
	"errors"
	"testing"
	"time"
)

// FX31: a tenant cannot change the cache policy of a site locked by a
// platform administrator; unlocking restores it.
func TestPublishPolicyRejectsLockedSiteForTenant(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "policy-locked", 1)
	if _, err := pool.Exec(context.Background(), `UPDATE sites SET lock_reason='audit',locked_at=$2,locked_by_user_id=$3,
		revision=revision+1 WHERE id=$1`, fixture.siteID, cacheTestNow, fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	request := PublishPolicyRequest{
		SiteID: fixture.siteID, ExpectedRevision: 0, Document: validPolicyV2Document(60, 30),
		IdempotencyKey: "policy-locked", RequestID: "policy-locked-request",
	}
	if _, err := store.PublishPolicy(context.Background(), fixture.actor, request); !errors.Is(err, ErrSiteLocked) {
		t.Fatalf("locked publish = %v, want ErrSiteLocked", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sites SET lock_reason=NULL,locked_at=NULL,locked_by_user_id=NULL,
		revision=revision+1 WHERE id=$1`, fixture.siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishPolicy(context.Background(), fixture.actor, request); err != nil {
		t.Fatalf("unlocked publish = %v", err)
	}
}
