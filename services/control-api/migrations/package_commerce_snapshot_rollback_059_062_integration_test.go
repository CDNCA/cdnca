//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// packageSnapshot059062Fixture is one tenant subscription seeded in SQL on
// the schema the migration under test stops at (moved from the package
// commerce HTTP layer, whose runtime reads today's schema).
type packageSnapshot059062Fixture struct {
	scopeID, userID, productID, subscriptionID uuid.UUID
	now                                        time.Time
}

func seedPackageSnapshot059062(t *testing.T, pool *pgxpool.Pool) packageSnapshot059062Fixture {
	t.Helper()
	fixture := packageSnapshot059062Fixture{
		scopeID: uuid.New(), userID: uuid.New(), productID: uuid.New(), subscriptionID: uuid.New(),
		now: time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC),
	}
	tenantID := uuid.New()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{tenantID, "snapshot " + suffix}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`,
			[]any{fixture.userID, "snap" + suffix, "snapshot " + suffix}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.userID}},
		{`INSERT INTO package_products(id,name,spec,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,'{}'::jsonb,$3,$3,$4,$4)`, []any{fixture.productID, "snapshot " + suffix, fixture.userID, fixture.now}},
		{`INSERT INTO package_product_versions(product_id,revision,name,enabled,sort_order,spec,created_by_user_id,created_at)
			VALUES($1,1,$2,true,100,'{}'::jsonb,$3,$4)`, []any{fixture.productID, "snapshot " + suffix, fixture.userID, fixture.now}},
		{`INSERT INTO package_subscriptions(
			id,tenant_scope_id,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,
			timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,
			created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,$2,$3::uuid,1,jsonb_build_object('id',$3::uuid::text,'revision',1,'name',$4::text,'spec','{}'::jsonb),
			1,1,1,1,$5,$6,'UTC','monthly',1,1,$7,$7,$5,$5)`,
			[]any{fixture.subscriptionID, fixture.scopeID, fixture.productID, "snapshot " + suffix,
				fixture.now, fixture.now.Add(30 * 24 * time.Hour), fixture.userID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed %q: %v", strings.Fields(statement.query)[2], err)
		}
	}
	return fixture
}

// insertEntitlement059 appends one migration-backfill entitlement fact at
// revision (the chain head is revision-1).
func (fixture packageSnapshot059062Fixture) insertEntitlement059(t *testing.T, pool *pgxpool.Pool, revision int64) {
	t.Helper()
	var supersedes any
	var supersedesRevision any
	if revision > 1 {
		supersedes, supersedesRevision = fixture.subscriptionID, revision-1
	}
	at := fixture.now.Add(time.Duration(revision) * time.Minute)
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_subscription_entitlement_versions(
		subscription_id,revision,supersedes_subscription_id,supersedes_revision,tenant_scope_id,
		effective_at,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,
		traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,
		currency,entitlement_status,operation,created_by_user_id,created_at
	) SELECT id,$2,$3,$4,tenant_scope_id,$5,product_id,product_revision,product_snapshot,
		site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,
		tcp_factor_numerator,tcp_factor_denominator,'CNY','active','migration_backfill',$6,$5
	FROM package_subscriptions WHERE id=$1`,
		fixture.subscriptionID, revision, supersedes, supersedesRevision, at, fixture.userID); err != nil {
		t.Fatalf("insert entitlement revision %d: %v", revision, err)
	}
}

// TestPackageCommerceSnapshot059RollbackPolicy: 059 rolls back while no
// entitlement fact exists, backfills existing facts at sequence zero, assigns
// server sequences afterwards and refuses down once facts exist.
func TestPackageCommerceSnapshot059RollbackPolicy(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 59)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "down", 59); err != nil {
		t.Fatalf("empty 059 down: %v", err)
	}
	fixture := seedPackageSnapshot059062(t, pool)
	fixture.insertEntitlement059(t, pool, 1)
	if err := migrateVersionIsolated(ctx, pool, "up", 59); err != nil {
		t.Fatalf("059 apply over existing facts: %v", err)
	}
	var legacySequence int64
	if err := pool.QueryRow(ctx, `SELECT commit_sequence FROM package_subscription_entitlement_versions
		WHERE subscription_id=$1 AND revision=1`, fixture.subscriptionID).Scan(&legacySequence); err != nil || legacySequence != 0 {
		t.Fatalf("059 did not preserve the existing fact at baseline sequence zero: sequence=%d err=%v", legacySequence, err)
	}
	fixture.insertEntitlement059(t, pool, 2)
	if err := migrateVersionIsolated(ctx, pool, "down", 59); err == nil {
		t.Fatal("059 down succeeded with package entitlement facts")
	}
	var sequence int64
	if err := pool.QueryRow(ctx, `SELECT commit_sequence FROM package_subscription_entitlement_versions
		WHERE subscription_id=$1 AND revision=2`, fixture.subscriptionID).Scan(&sequence); err != nil || sequence < 1 {
		t.Fatalf("059 failed rollback did not preserve fact and commit sequence: sequence=%d err=%v", sequence, err)
	}
}

// TestPackageCommerceStateSnapshot062RollbackPolicy: 062 rolls back and
// reapplies while empty, backfills an existing subscription at sequence zero,
// captures later state changes append-only and refuses down once facts exist.
func TestPackageCommerceStateSnapshot062RollbackPolicy(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 62)
	ctx := t.Context()
	for _, step := range []string{"down", "up", "down"} {
		if err := migrateVersionIsolated(ctx, pool, step, 62); err != nil {
			t.Fatalf("empty 062 %s: %v", step, err)
		}
	}
	fixture := seedPackageSnapshot059062(t, pool)
	if err := migrateVersionIsolated(ctx, pool, "up", 62); err != nil {
		t.Fatalf("062 apply over existing subscription: %v", err)
	}
	var backfillRevision, backfillSequence int64
	var backfillStatus string
	if err := pool.QueryRow(ctx, `SELECT revision,lifecycle_status,commit_sequence
		FROM package_subscription_state_versions WHERE subscription_id=$1`, fixture.subscriptionID).Scan(
		&backfillRevision, &backfillStatus, &backfillSequence,
	); err != nil || backfillRevision != 1 || backfillStatus != "active" || backfillSequence != 0 {
		t.Fatalf("062 backfill=(revision=%d status=%q sequence=%d err=%v)",
			backfillRevision, backfillStatus, backfillSequence, err)
	}

	// A cancel is the one state change with no order behind it (051).
	cancelledAt := fixture.now.Add(time.Hour)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `INSERT INTO package_subscription_versions(
		subscription_id,revision,operation,snapshot,created_by_user_id,created_at)
		VALUES($1,2,'cancel','{}'::jsonb,$2,$3)`, fixture.subscriptionID, fixture.userID, cancelledAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE package_subscriptions SET revision=2,lifecycle_status='cancelled',
		cancelled_at=$2,updated_at=$2,updated_by_user_id=$3 WHERE id=$1`,
		fixture.subscriptionID, cancelledAt, fixture.userID); err != nil {
		t.Fatalf("062 cancel: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("062 cancel commit: %v", err)
	}
	var capturedSequence int64
	if err := pool.QueryRow(ctx, `SELECT commit_sequence FROM package_subscription_state_versions
		WHERE subscription_id=$1 AND revision=2`, fixture.subscriptionID).Scan(&capturedSequence); err != nil || capturedSequence < 1 {
		t.Fatalf("062 captured sequence=%d err=%v", capturedSequence, err)
	}
	for _, mutation := range []struct {
		name      string
		statement string
		args      []any
	}{
		{"update", `UPDATE package_subscription_state_versions SET updated_at=updated_at WHERE subscription_id=$1`, []any{fixture.subscriptionID}},
		{"delete", `DELETE FROM package_subscription_state_versions WHERE subscription_id=$1`, []any{fixture.subscriptionID}},
		{"truncate", `TRUNCATE package_subscription_state_versions`, nil},
		{"client sequence", `
			INSERT INTO package_subscription_state_versions (
				subscription_id,revision,tenant_scope_id,owner_user_id,lifecycle_status,
				starts_at,ends_at,cancelled_at,created_at,updated_at,commit_sequence
			)
			SELECT id,revision,tenant_scope_id,created_by_user_id,lifecycle_status,
			       starts_at,ends_at,cancelled_at,created_at,updated_at,999
			FROM package_subscriptions WHERE id=$1`, []any{fixture.subscriptionID}},
	} {
		if _, err := pool.Exec(ctx, mutation.statement, mutation.args...); err == nil {
			t.Fatalf("062 state fact %s succeeded", mutation.name)
		}
	}
	if err := migrateVersionIsolated(ctx, pool, "down", 62); err == nil {
		t.Fatal("062 down succeeded with subscription state facts")
	}
	var facts int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM package_subscription_state_versions
		WHERE subscription_id=$1`, fixture.subscriptionID).Scan(&facts); err != nil || facts != 2 {
		t.Fatalf("062 failed down did not preserve facts: count=%d err=%v", facts, err)
	}
}
