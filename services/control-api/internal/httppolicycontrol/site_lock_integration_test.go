package httppolicycontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// FX31: a tenant cannot create or change the HTTP policy of a locked site;
// unlocking restores writes.
func TestHTTPPolicyRejectsLockedSiteForTenant(t *testing.T) {
	fixture := newIntegrationFixture(t, allowTestGate())
	existing := createServicePolicy(t, fixture, fixture.siteA, "lock-before")
	setSiteLocked(t, fixture, fixture.siteA, true)

	if _, err := fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: existing.ID, ExpectedRevision: existing.Revision,
		Config: validTestConfig(), WriteMetadata: testMetadata("lock-update"),
	}); !errors.Is(err, ErrSiteLocked) {
		t.Fatalf("locked update = %v, want ErrSiteLocked", err)
	}
	if _, err := fixture.service.Delete(context.Background(), fixture.ownerA, DeleteRequest{
		TargetScopeID: fixture.tenantA, ID: existing.ID, ExpectedRevision: existing.Revision,
		WriteMetadata: testMetadata("lock-delete"),
	}); !errors.Is(err, ErrSiteLocked) {
		t.Fatalf("locked delete = %v, want ErrSiteLocked", err)
	}

	setSiteLocked(t, fixture, fixture.siteA, false)
	if _, err := fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: existing.ID, ExpectedRevision: existing.Revision,
		Config: validTestConfig(), WriteMetadata: testMetadata("unlock-update"),
	}); err != nil {
		t.Fatalf("unlocked update = %v", err)
	}
}

func setSiteLocked(t *testing.T, fixture *integrationFixture, siteID uuid.UUID, locked bool) {
	t.Helper()
	query := `UPDATE sites SET lock_reason=NULL,locked_at=NULL,locked_by_user_id=NULL WHERE id=$1`
	args := []any{siteID}
	if locked {
		query = `UPDATE sites SET lock_reason='audit',locked_at=now(),locked_by_user_id=owner_user_id WHERE id=$1`
	}
	if _, err := fixture.pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}
