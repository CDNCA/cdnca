//go:build integration

package edgepublish

import (
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// the compiler reads the site's
// subscription at the entitlement in effect (701), not the purchased product
// snapshot the subscription row keeps (261): package limits and capability
// gates, and the package line group the site's nodes come from.
func TestCompileReadsSubscriptionCurrentEntitlement(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	nodeB := scope.AddNode(t, 12)
	groupB := scope.AddStreamLineGroup(t, "198.51.100.91", nodeB)
	// The site follows its package's line group (none of its own).
	scope.Exec(t, `UPDATE sites SET node_group_id=NULL WHERE id=$1`, scope.SiteID)

	read := func() (soldPackageLimits, []uuid.UUID) {
		t.Helper()
		var limits soldPackageLimits
		var nodes []uuid.UUID
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			all, err := loadSoldPackageLimits(t.Context(), tx, scope.ScopeID)
			if err != nil {
				return err
			}
			limits = all[scope.SiteID]
			nodes, _, err = systemTargetNodes(t.Context(), tx, scope.ScopeID, nil, true)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return limits, nodes
	}
	before, beforeNodes := read()
	if slices.Contains(beforeNodes, nodeB) {
		t.Fatalf("node of product B's line group targeted before the change: %v", beforeNodes)
	}
	if before.BandwidthBPS != nil && *before.BandwidthBPS == 8_000_000 {
		t.Fatal("fixture product already has product B's bandwidth")
	}

	// Product B in effect now: a new entitlement version, the row untouched.
	scope.Exec(t, `INSERT INTO package_subscription_entitlement_versions(
		subscription_id,revision,supersedes_subscription_id,supersedes_revision,tenant_scope_id,effective_at,effective_until,
		product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,
		custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
		entitlement_status,source_order_id,operation,created_by_user_id,created_at)
		SELECT subscription_id,revision+1,subscription_id,revision,tenant_scope_id,clock_timestamp(),NULL,
		  product_id,product_revision,
		  jsonb_set(jsonb_set(product_snapshot,'{spec,limits}',
		    COALESCE(product_snapshot#>'{spec,limits}','{}'::jsonb)||'{"bandwidth_bps":8000000,"monthly_traffic_bytes":10737418,"domains":1,"waf":true,"custom_cc":true}'::jsonb),
		    '{spec,node_group_id}',to_jsonb($2::text)),
		  1,1,node_limit,10737418,timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,
		  package_period,period_price_minor,currency,'active',NULL,'admin_edit',created_by_user_id,clock_timestamp()
		FROM package_subscription_entitlement_versions WHERE subscription_id=$1 ORDER BY revision DESC LIMIT 1`,
		scope.SubscriptionID, groupB)
	after, afterNodes := read()
	if after.BandwidthBPS == nil || *after.BandwidthBPS != 8_000_000 || after.WAF == nil || !*after.WAF ||
		after.CustomCC == nil || !*after.CustomCC || after.subscriptionID != scope.SubscriptionID {
		t.Fatalf("compiled limits after the change = %+v", after)
	}
	if !slices.Contains(afterNodes, nodeB) {
		t.Fatalf("product B's line group node %s not targeted: %v", nodeB, afterNodes)
	}
	var purchased string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT COALESCE(product_snapshot#>>'{spec,node_group_id}','')
		FROM package_subscriptions WHERE id=$1`, scope.SubscriptionID).Scan(&purchased); err != nil || purchased == groupB.String() {
		t.Fatalf("purchased snapshot rewritten: %q %v", purchased, err)
	}
}

// A security activation of a site whose subscription is suspended says so
// (package_subscription_suspended), not that the publication lost the site.
func TestSiteOutOfPublicationNamesSuspension(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	check := func() error {
		t.Helper()
		var result error
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			result = siteOutOfPublicationError(t.Context(), tx, scope.ScopeID, scope.SiteID)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	noop := func(pgx.Tx, int64) error { return nil }
	if err := check(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("live subscription: %v, want ErrNotFound", err)
	}
	scope.SetSubscriptionSuspended(t, scope.SubscriptionID, true, noop)
	if err := check(); !errors.Is(err, ErrPackageSubscriptionSuspended) {
		t.Fatalf("suspended subscription: %v, want ErrPackageSubscriptionSuspended", err)
	}
	// Another tenant's suspended site is not this scope's.
	other := scope.SecondScope(t)
	var result error
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		result = siteOutOfPublicationError(t.Context(), tx, other.ScopeID, scope.SiteID)
		return nil
	}); err != nil || !errors.Is(result, ErrNotFound) {
		t.Fatalf("cross-scope lookup: %v %v", result, err)
	}
	scope.SetSubscriptionSuspended(t, scope.SubscriptionID, false, noop)
	if err := check(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resumed subscription: %v, want ErrNotFound", err)
	}
}
