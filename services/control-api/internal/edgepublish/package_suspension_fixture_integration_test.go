//go:build integration

package edgepublish

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Package subscription suspension fixtures (bb03, migration 555) for
// package_suspension_integration_test.go (edgepublish_test).

// SetSubscriptionSuspended writes a suspend/unsuspend version and the row
// change as packagesubscription.Store.Suspend does, then runs republish in the
// same transaction with the scope revision read before the change.
func (scope *SystemRepublishScope) SetSubscriptionSuspended(t *testing.T, subscriptionID uuid.UUID, suspend bool,
	republish func(tx pgx.Tx, fromRevision int64) error,
) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var from int64
		if err := tx.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
			scope.ScopeID).Scan(&from); err != nil {
			return err
		}
		operation, at, reason := "unsuspend", any(nil), any(nil)
		if suspend {
			operation, reason = "suspend", "bb03-test"
		}
		var now string
		if err := tx.QueryRow(t.Context(), `SELECT clock_timestamp()::text`).Scan(&now); err != nil {
			return err
		}
		if suspend {
			at = now
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_versions(subscription_id,revision,operation,snapshot,
			created_by_user_id,created_at) SELECT id,revision+1,$2,'{}'::jsonb,$3,$4::timestamptz FROM package_subscriptions WHERE id=$1`,
			subscriptionID, operation, scope.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET suspended_at=$2::timestamptz,suspend_reason=$3,
			revision=revision+1,updated_by_user_id=$4,updated_at=$5::timestamptz WHERE id=$1`,
			subscriptionID, at, reason, scope.UserID, now); err != nil {
			return err
		}
		return republish(tx, from)
	}); err != nil {
		t.Fatal(err)
	}
}

// PublishedSiteIDs are the sites the scope's latest publication carries.
func (scope *SystemRepublishScope) PublishedSiteIDs(t *testing.T) map[uuid.UUID]bool {
	t.Helper()
	var document siteRuntimeV2Document
	if err := json.Unmarshal(scope.LatestPublication(t).Snapshot, &document); err != nil {
		t.Fatal(err)
	}
	ids := make(map[uuid.UUID]bool, len(document.Sites))
	for _, site := range document.Sites {
		ids[uuid.MustParse(site.ID)] = true
	}
	return ids
}

// AddSubscription opens a second package subscription for the scope's owner
// (same product), so one subscription can be suspended alone.
func (scope *SystemRepublishScope) AddSubscription(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	scope.Exec(t, `INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,
		site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,custom_cycle_days,
		tcp_factor_numerator,tcp_factor_denominator,lifecycle_status,created_by_user_id,updated_by_user_id,created_at,updated_at)
		SELECT $1,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,
		  traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,
		  tcp_factor_denominator,'active',created_by_user_id,created_by_user_id,created_at,created_at
		FROM package_subscriptions WHERE id=$2`, id, scope.SubscriptionID)
	scope.Exec(t, `INSERT INTO package_subscription_versions(subscription_id,revision,operation,snapshot,created_by_user_id,created_at)
		SELECT id,1,'open','{}'::jsonb,created_by_user_id,created_at FROM package_subscriptions WHERE id=$1`, id)
	scope.Exec(t, `INSERT INTO package_subscription_entitlement_versions(subscription_id,revision,tenant_scope_id,effective_at,
		product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,
		custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
		entitlement_status,operation,created_by_user_id,created_at)
		SELECT $1,1,tenant_scope_id,effective_at,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,
		  traffic_limit_bytes,timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,package_period,
		  period_price_minor,currency,entitlement_status,'manual_open',created_by_user_id,created_at
		FROM package_subscription_entitlement_versions WHERE subscription_id=$2 ORDER BY revision LIMIT 1`, id, scope.SubscriptionID)
	scope.Exec(t, `INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,
		owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',clock_timestamp())
		ON CONFLICT DO NOTHING`, id, scope.ScopeID, scope.UserID)
	return id
}

// BindSiteTo puts siteID on subscriptionID.
func (scope *SystemRepublishScope) BindSiteTo(t *testing.T, siteID, subscriptionID uuid.UUID) {
	t.Helper()
	scope.Exec(t, `INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,
		owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',clock_timestamp())
		ON CONFLICT DO NOTHING`, subscriptionID, scope.ScopeID, scope.UserID)
	scope.Exec(t, `UPDATE sites SET package_subscription_id=$2,
		package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=$1`, siteID, subscriptionID)
}
