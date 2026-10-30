//go:build integration

package migrations_test

import "testing"

// TestTenantMemberHandover409: up, down, up; the column defaults to false;
// down is refused while a user still has to change the password.
func TestTenantMemberHandover409(t *testing.T) {
	const version = 409
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES(gen_random_uuid(),'m409','M','x')`); err != nil {
		t.Fatal(err)
	}
	var required bool
	if err := pool.QueryRow(ctx, `SELECT password_change_required FROM users WHERE username='m409'`).Scan(&required); err != nil || required {
		t.Fatalf("default=%v %v", required, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET password_change_required=true WHERE username='m409'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("down discarded a pending password change")
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET password_change_required=false WHERE username='m409'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
}
