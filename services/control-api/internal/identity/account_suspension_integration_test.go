//go:build integration

package identity_test

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type siteState struct {
	enabled bool
	status  string
}

func readSiteState(t *testing.T, fixture managedUserAuthorityFixture, siteID uuid.UUID) siteState {
	t.Helper()
	var state siteState
	if err := fixture.pool.QueryRow(t.Context(), `SELECT enabled,status FROM sites WHERE id=$1`, siteID).Scan(&state.enabled, &state.status); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestAccountSuspensionStopsAndRestoresOnlyHeldSites(t *testing.T) {
	for _, suspend := range []struct {
		name, stop, restore, reason string
	}{
		{"user", `UPDATE users SET status='disabled' WHERE id=$1 AND $2::uuid IS NOT NULL`,
			`UPDATE users SET status='active' WHERE id=$1 AND $2::uuid IS NOT NULL`, "user_disabled"},
		{"membership", `UPDATE memberships SET status='suspended' WHERE user_id=$1 AND scope_id=$2`,
			`UPDATE memberships SET status='active' WHERE user_id=$1 AND scope_id=$2`, "membership_suspended"},
		{"tenant", `UPDATE tenants SET status='suspended' WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$2) AND $1::uuid IS NOT NULL`,
			`UPDATE tenants SET status='active' WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$2) AND $1::uuid IS NOT NULL`, "tenant_suspended"},
	} {
		t.Run(suspend.name, func(t *testing.T) {
			fixture := seedManagedUserAuthorityFixture(t, "identity.users.manage")
			ctx := t.Context()
			store := identity.NewStore(fixture.pool)
			serving := insertSecondaryVerificationSite(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID, "susp-"+suspend.name+".example.com", true, "", uuid.Nil)
			stoppedByTenant := insertSecondaryVerificationSite(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID, "susp-off-"+suspend.name+".example.com", false, "", uuid.Nil)
			republisher := &secondaryVerificationRepublisherStub{}
			// An active owner: nothing to do.
			if pass, err := store.EnforceAccountSuspensions(ctx, republisher, 10); err != nil || pass.Held+pass.Released != 0 {
				t.Fatalf("idle pass: %+v %v", pass, err)
			}
			if _, err := fixture.pool.Exec(ctx, suspend.stop, fixture.targetUserID, fixture.targetScopeID); err != nil {
				t.Fatal(err)
			}
			pass, err := store.EnforceAccountSuspensions(ctx, republisher, 10)
			if err != nil || pass.Held != 1 {
				t.Fatalf("hold pass: %+v %v", pass, err)
			}
			if state := readSiteState(t, fixture, serving); state.enabled || state.status != "disabled" {
				t.Fatalf("serving site not stopped: %+v", state)
			}
			if len(republisher.calls) != 1 || !republisher.sawCommittedChange || republisher.calls[0].Operation != identity.AccountSuspensionOperationDisable {
				t.Fatalf("republish on hold: %+v", republisher.calls)
			}
			var reason string
			if err := fixture.pool.QueryRow(ctx, `SELECT reason FROM account_suspension_site_holds WHERE site_id=$1 AND released_at IS NULL`, serving).Scan(&reason); err != nil || reason != suspend.reason {
				t.Fatalf("hold reason=%q err=%v", reason, err)
			}
			// A second pass is idempotent.
			if pass, err := store.EnforceAccountSuspensions(ctx, republisher, 10); err != nil || pass.Held+pass.Released != 0 {
				t.Fatalf("repeat pass: %+v %v", pass, err)
			}
			if _, err := fixture.pool.Exec(ctx, suspend.restore, fixture.targetUserID, fixture.targetScopeID); err != nil {
				t.Fatal(err)
			}
			if pass, err := store.EnforceAccountSuspensions(ctx, republisher, 10); err != nil || pass.Released != 1 {
				t.Fatalf("release pass: %+v %v", pass, err)
			}
			if state := readSiteState(t, fixture, serving); !state.enabled || state.status != "active" {
				t.Fatalf("held site not restored: %+v", state)
			}
			// The site the tenant had stopped itself stays stopped.
			if state := readSiteState(t, fixture, stoppedByTenant); state.enabled {
				t.Fatalf("tenant-disabled site re-enabled: %+v", state)
			}
			if len(republisher.calls) != 2 || republisher.calls[1].Operation != identity.AccountSuspensionOperationEnable {
				t.Fatalf("republish on release: %+v", republisher.calls)
			}
			var audited int
			if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action IN ('site.account_suspension.stop','site.account_suspension.restore')
				AND payload->>'trigger'='account_suspension'`, serving.String()).Scan(&audited); err != nil || audited != 2 {
				t.Fatalf("site audit events=%d err=%v", audited, err)
			}
		})
	}
}

func TestAccountSuspensionKeepsAdministratorChangeAfterHold(t *testing.T) {
	fixture := seedManagedUserAuthorityFixture(t, "identity.users.manage")
	ctx := t.Context()
	store := identity.NewStore(fixture.pool)
	site := insertSecondaryVerificationSite(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID, "susp-admin.example.com", true, "", uuid.Nil)
	republisher := &secondaryVerificationRepublisherStub{}
	if _, err := fixture.pool.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, fixture.targetUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnforceAccountSuspensions(ctx, republisher, 10); err != nil {
		t.Fatal(err)
	}
	// Meanwhile the site was moved to traffic_exceeded by enforcement.
	if _, err := fixture.pool.Exec(ctx, `UPDATE sites SET status='traffic_exceeded',enabled=true WHERE id=$1`, site); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE users SET status='active' WHERE id=$1`, fixture.targetUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnforceAccountSuspensions(ctx, republisher, 10); err != nil {
		t.Fatal(err)
	}
	if state := readSiteState(t, fixture, site); state.status != "traffic_exceeded" {
		t.Fatalf("release overwrote a later change: %+v", state)
	}
	var open int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM account_suspension_site_holds WHERE site_id=$1 AND released_at IS NULL`, site).Scan(&open); err != nil || open != 0 {
		t.Fatalf("hold left open: %d %v", open, err)
	}
}

// The real system republication channel accepts the new trigger (migration
// constraints and edgepublish validation agree).
func TestAccountSuspensionRepublishesThroughSystemChannel(t *testing.T) {
	fixture := seedManagedUserAuthorityFixture(t, "identity.users.manage")
	ctx := t.Context()
	insertSecondaryVerificationSite(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID, "susp-real.example.com", true, "", uuid.Nil)
	if _, err := fixture.pool.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, fixture.targetUserID); err != nil {
		t.Fatal(err)
	}
	pass, err := identity.NewStore(fixture.pool).EnforceAccountSuspensions(ctx, edgeautopublish.AccountSuspensionRepublisher{}, 10)
	if err != nil || pass.Held != 1 {
		t.Fatalf("hold: %+v %v", pass, err)
	}
	var triggers []string
	if err := fixture.pool.QueryRow(ctx, `SELECT triggers FROM edge_system_republication_heads WHERE scope_id=$1`, fixture.targetScopeID).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if len(triggers) != 1 || triggers[0] != "account_suspension" {
		t.Fatalf("triggers=%v", triggers)
	}
}
