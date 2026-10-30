//go:build integration

package migrations_test

import "testing"

// TestDomainOwnershipPermanentMigration rolls 322 up, down and up on a 321
// schema with a verified proof: down restores a recheck date, up drops it.
func TestDomainOwnershipPermanentMigration(t *testing.T) {
	const version = 322
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, statement := range []string{
		`INSERT INTO users(id,username,display_name,password_hash)
			VALUES('00000000-0000-4000-8000-000000000316','own-316','own-316','x')`,
		`INSERT INTO tenants(id,display_name) VALUES('00000000-0000-4000-8000-000000003161','own-316')`,
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES('00000000-0000-4000-8000-000000003162','tenant',
			'00000000-0000-4000-8000-000000003161')`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO domain_ownerships(id,scope_id,apex,method,token,status,verified_at,
		last_checked_at,next_check_at,created_by_user_id,created_at,updated_at)
		VALUES(gen_random_uuid(),'00000000-0000-4000-8000-000000003162','permanent.test','dns_txt',repeat('c',48),
		'verified',now(),now(),now(),'00000000-0000-4000-8000-000000000316',now(),now())`); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
		AND table_name='domain_ownerships' AND column_name IN ('next_check_at','consecutive_failures')`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("recheck columns = %d (%v)", columns, err)
	}
	var kept string
	if err := pool.QueryRow(ctx, `SELECT status FROM domain_ownerships WHERE apex='permanent.test'`).Scan(&kept); err != nil || kept != "verified" {
		t.Fatalf("proof after round trip = %q (%v)", kept, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE domain_ownerships SET verified_at=NULL WHERE apex='permanent.test'`); err == nil {
		t.Fatal("verified proof without verified_at accepted")
	}
}
