package originauthcontrol

import (
	"errors"
	"testing"
)

// FX31: a tenant cannot create or change origin auth rules of a site locked by
// a platform administrator; platform actors keep access and unlocking restores
// tenant writes.
func TestRuleWritesRejectLockedSiteForTenant(t *testing.T) {
	fixture := newOriginAuthFixture(t)
	service := fixtureService(t, fixture, "new", nil, nil)
	credential := createCredential(t, service, fixture.owner, "lock", "lock-credential")
	created, err := service.CreateRule(t.Context(), fixture.owner, CreateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, SiteID: fixture.siteA, SourcePosition: 1,
		Config: s3RuleConfig(credential.ID, 1), Enabled: false, WriteMetadata: metadata("lock-rule"),
	})
	if err != nil {
		t.Fatal(err)
	}
	setLocked := func(locked bool) {
		t.Helper()
		query := `UPDATE sites SET lock_reason=NULL,locked_at=NULL,locked_by_user_id=NULL WHERE id=$1`
		if locked {
			query = `UPDATE sites SET lock_reason='audit',locked_at=now(),locked_by_user_id=owner_user_id WHERE id=$1`
		}
		if _, err := fixture.pool.Exec(t.Context(), query, fixture.siteA); err != nil {
			t.Fatal(err)
		}
	}
	setLocked(true)
	if _, err := service.CreateRule(t.Context(), fixture.owner, CreateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, SiteID: fixture.siteA, SourcePosition: 1,
		Config: s3RuleConfig(credential.ID, 1), Enabled: false, WriteMetadata: metadata("locked-create"),
	}); !errors.Is(err, ErrSiteLocked) {
		t.Fatalf("locked create = %v, want ErrSiteLocked", err)
	}
	if _, err := service.DeleteRule(t.Context(), fixture.owner, RuleMutationRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: created.Rule.ID, ExpectedRevision: created.Rule.Revision,
		WriteMetadata: metadata("locked-delete"),
	}); !errors.Is(err, ErrSiteLocked) {
		t.Fatalf("locked delete = %v, want ErrSiteLocked", err)
	}
	config := created.Rule.RuleConfig
	config.SignatureTTLSeconds = 301
	platformUpdate, err := service.UpdateRule(t.Context(), fixture.platform, UpdateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: created.Rule.ID, ExpectedRevision: created.Rule.Revision,
		Config: config, WriteMetadata: metadata("platform-update"),
	})
	if err != nil {
		t.Fatalf("platform update on locked site = %v", err)
	}
	setLocked(false)
	if _, err := service.DeleteRule(t.Context(), fixture.owner, RuleMutationRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: created.Rule.ID, ExpectedRevision: platformUpdate.Rule.Revision,
		WriteMetadata: metadata("unlocked-delete"),
	}); err != nil {
		t.Fatalf("unlocked delete = %v", err)
	}
}
