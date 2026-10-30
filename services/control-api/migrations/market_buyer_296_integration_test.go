//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestMarketBuyerMigration checks that 296 grants the new marketplace codes to
// platform system roles, keeps advisory acknowledgements durable and refuses
// to roll back once acknowledgements exist.
func TestMarketBuyerMigration(t *testing.T) {
	const version = 296
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var codes int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions WHERE name IN
		('marketplace.browse','marketplace.purchase','marketplace.sell')`).Scan(&codes); err != nil || codes != 3 {
		t.Fatalf("permissions = %d, %v", codes, err)
	}
	var tenantGrants int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id=rp.role_id
		JOIN access_scopes s ON s.id=r.scope_id WHERE rp.permission_name LIKE 'marketplace.%' AND s.kind<>'platform'`).
		Scan(&tenantGrants); err != nil || tenantGrants != 0 {
		t.Fatalf("tenant roles got marketplace codes: %d, %v", tenantGrants, err)
	}

	scope := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')
		ON CONFLICT DO NOTHING`, scope); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	advisory := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO plugin_security_advisories(id,plugin_id,affected_versions,severity,action,title,
		status,published_at,received_at,updated_at) VALUES($1,'acme.waf','<1.4.2','high','disable','t','published',now(),now(),now())`,
		advisory); err != nil {
		t.Fatal(err)
	}
	user := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO plugin_security_advisory_acks(advisory_id,scope_id,acknowledged_by,disposition,acknowledged_at)
		VALUES($1,$2,$3,'disabled',now())`, advisory, scope, user); err != nil {
		t.Fatal(err)
	}
	var pgErr *pgconn.PgError
	if _, err := pool.Exec(ctx, `UPDATE plugin_security_advisory_acks SET disposition='upgraded' WHERE advisory_id=$1`,
		advisory); !errors.As(err, &pgErr) || pgErr.Code != "P2961" {
		t.Fatalf("ack rewrite err=%v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM plugin_security_advisory_acks WHERE advisory_id=$1`, advisory); !errors.As(err, &pgErr) ||
		pgErr.Code != "P2961" {
		t.Fatalf("ack delete err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE plugin_security_advisory_acks SET reported_at=now() WHERE advisory_id=$1`, advisory); err != nil {
		t.Fatalf("reported_at once: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE plugin_security_advisory_acks SET reported_at=now() WHERE advisory_id=$1`,
		advisory); !errors.As(err, &pgErr) || pgErr.Code != "P2961" {
		t.Fatalf("reported_at twice err=%v", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P2963" {
		t.Fatalf("down with buyer facts err=%v", err)
	}
}
