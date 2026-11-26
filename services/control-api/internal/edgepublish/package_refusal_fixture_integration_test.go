//go:build integration

package edgepublish

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AddSiteOnOwnPackage creates a site of the scope on a package subscription of
// its own (the fixture's sites share one).
func (scope *SystemRepublishScope) AddSiteOnOwnPackage(t *testing.T, domain string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	fixture := scope.fixture
	siteID := fixture.createSite(t, domain, 18082, false).Site.ID
	subscriptionID := seedPublishPackage(t, fixture.pool, fixture.scopeID, fixture.userID,
		fixture.platformScopeID, fixture.platformUserID)
	scope.RebindSite(t, siteID, subscriptionID)
	return siteID, subscriptionID
}

// RebindSite moves a site to another package subscription of the scope (the
// fixture bypasses the site triggers, as a package change projection does).
func (scope *SystemRepublishScope) RebindSite(t *testing.T, siteID, subscriptionID uuid.UUID) {
	t.Helper()
	scope.replicaExec(t, `UPDATE sites SET package_subscription_id=$2,
		package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=$1`, siteID, subscriptionID)
}

// SetPackageState writes a subscription's lifecycle and suspension (the
// fixture bypasses the subscription triggers).
func (scope *SystemRepublishScope) SetPackageState(t *testing.T, subscriptionID uuid.UUID, lifecycle string, suspended bool) {
	t.Helper()
	scope.replicaExec(t, `UPDATE package_subscriptions SET lifecycle_status=$2,
		cancelled_at=CASE WHEN $2='cancelled' THEN COALESCE(cancelled_at,updated_at) END,
		suspended_at=CASE WHEN $3 THEN COALESCE(suspended_at,updated_at) END,
		suspend_reason=CASE WHEN $3 THEN 'fixture' END WHERE id=$1`, subscriptionID, lifecycle, suspended)
}

// RevokeEntitlement revokes every entitlement version of a subscription (the
// fixture bypasses the entitlement triggers).
func (scope *SystemRepublishScope) RevokeEntitlement(t *testing.T, subscriptionID uuid.UUID) {
	t.Helper()
	scope.replicaExec(t, `UPDATE package_subscription_entitlement_versions SET entitlement_status='revoked'
		WHERE subscription_id=$1`, subscriptionID)
}

func (scope *SystemRepublishScope) replicaExec(t *testing.T, statement string, args ...any) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), statement, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
