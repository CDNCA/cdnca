//go:build integration

package edgepublish

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Package expiry fixtures (errpage-5, 待出包前全量跑) for
// package_expiry_integration_test.go (edgepublish_test).

// BindSiteToSubscription puts siteID on the scope's package subscription.
// A site on a subscription must name its owner (113
// sites_package_subscription_owner_113_fk); opening a package records it
// (packagesubscription.Store open), the shared fixture seeds the
// subscription directly, so the owner projection is recorded here.
func (scope *SystemRepublishScope) BindSiteToSubscription(t *testing.T, siteID uuid.UUID) {
	t.Helper()
	scope.Exec(t, `INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,
		owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',clock_timestamp())
		ON CONFLICT DO NOTHING`, scope.SubscriptionID, scope.ScopeID, scope.UserID)
	scope.Exec(t, `UPDATE sites SET package_subscription_id=$2,
		package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=$1`, siteID, scope.SubscriptionID)
}

// EndSubscription moves the subscription's term end into the past (the term
// elapsed: the renewal guard only refuses shortening by a write, so the
// fixture writes it as a replica). The end is before publishTestClock, the
// publisher's fixed clock, which is never after the database clock the
// watcher reads: in a full package run the database clock is minutes past
// publishTestClock, so an end relative to it would not yet be over for the
// publisher.
func (scope *SystemRepublishScope) EndSubscription(t *testing.T) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET starts_at=clock_timestamp()-interval '2 days',
			ends_at=$2::timestamptz-interval '1 minute' WHERE id=$1`, scope.SubscriptionID, publishTestClock)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// RenewSubscription extends the term to a day from now, as a fulfillment does.
func (scope *SystemRepublishScope) RenewSubscription(t *testing.T) {
	t.Helper()
	// the revision fact (deferred constraint trigger) as renew does in
	// packagetrafficenforcement's fixture
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var revision int64
		if err := tx.QueryRow(t.Context(), `UPDATE package_subscriptions SET ends_at=clock_timestamp()+interval '1 day',
			revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision`, scope.SubscriptionID).
			Scan(&revision); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_versions(subscription_id,revision,operation,snapshot,
			created_by_user_id,created_at) VALUES($1,$2,'renew','{}',$3,clock_timestamp())`, scope.SubscriptionID, revision, scope.UserID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// SetExpiryClose writes the platform's 套餐到期后关闭网站 setting.
func (scope *SystemRepublishScope) SetExpiryClose(t *testing.T, enabled bool) {
	t.Helper()
	scope.Exec(t, `INSERT INTO platform_system_settings(platform_scope_id,revision,settings,updated_at)
		VALUES($1,1,jsonb_build_object('expiry_close',$2::boolean),clock_timestamp())
		ON CONFLICT (platform_scope_id) DO UPDATE SET revision=platform_system_settings.revision+1,
		settings=platform_system_settings.settings||jsonb_build_object('expiry_close',$2::boolean),updated_at=clock_timestamp()`,
		scope.fixture.platformScopeID, enabled)
}

// DeclareErrorPageSlots records a new session of nodeID that also declares
// ERROR_PAGE_SLOTS v1 (a package expired site requires it).
func (scope *SystemRepublishScope) DeclareErrorPageSlots(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, "1.0.35-slots", append(systemRepublishFeatures(6),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ERROR_PAGE_SLOTS, ApiVersion: siteobject.ErrorPageSlotsAPIVersion}))
}

// PublishedPackageExpiry is, per site ID, the package_expired mark of the
// latest publication's v2 document, and whether it requires error_page_slots.
func (scope *SystemRepublishScope) PublishedPackageExpiry(t *testing.T) (map[uuid.UUID]bool, bool) {
	t.Helper()
	var document siteRuntimeV2Document
	if err := json.Unmarshal(scope.LatestPublication(t).Snapshot, &document); err != nil {
		t.Fatal(err)
	}
	marks := make(map[uuid.UUID]bool, len(document.Sites))
	for _, site := range document.Sites {
		marks[uuid.MustParse(site.ID)] = site.PackageExpired
	}
	required := false
	for _, capability := range document.RequiredCapabilities {
		if capability.Name == siteobject.ErrorPageSlotsCapability && capability.APIVersion == siteobject.ErrorPageSlotsAPIVersion {
			required = true
		}
	}
	return marks, required
}
