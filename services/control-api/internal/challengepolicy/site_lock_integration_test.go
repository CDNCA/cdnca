package challengepolicy

import (
	"context"
	"errors"
	"testing"
)

// FX31: a tenant cannot create or change a challenge policy of a locked site;
// unlocking restores writes.
func TestChallengePolicyRejectsLockedSiteForTenant(t *testing.T) {
	fixture := newFixture(t, allowGate())
	created, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("lock-before"),
	})
	if err != nil {
		t.Fatal(err)
	}
	lock := func(locked bool) {
		t.Helper()
		query := `UPDATE sites SET lock_reason=NULL,locked_at=NULL,locked_by_user_id=NULL WHERE id=$1`
		if locked {
			query = `UPDATE sites SET lock_reason='audit',locked_at=now(),locked_by_user_id=owner_user_id WHERE id=$1`
		}
		if _, err := fixture.pool.Exec(context.Background(), query, fixture.siteA); err != nil {
			t.Fatal(err)
		}
	}
	lock(true)
	if _, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("lock-create"),
	}); !errors.Is(err, ErrSiteLocked) {
		t.Fatalf("locked create = %v, want ErrSiteLocked", err)
	}
	if _, err := fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: created.Policy.Revision,
		Config: validConfig(ModeClick), WriteMetadata: metadata("lock-update"),
	}); !errors.Is(err, ErrSiteLocked) {
		t.Fatalf("locked update = %v, want ErrSiteLocked", err)
	}
	lock(false)
	if _, err := fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: created.Policy.Revision,
		Config: validConfig(ModeClick), WriteMetadata: metadata("unlock-update"),
	}); err != nil {
		t.Fatalf("unlocked update = %v", err)
	}
}
