//go:build integration

package migrations_test

import "testing"

// TestSecurityBanNetworks545: up admits masked networks of IPv4 /8../32 and
// IPv6 /32../128 (single addresses still); down refuses while a network row
// exists and restores the single address check once none is left.
func TestSecurityBanNetworks545(t *testing.T) {
	const version = 545
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	mustExec(t, pool, `ALTER TABLE security_ban_entries DISABLE TRIGGER ALL`)
	insert := `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,banned_at,banned_until)
		VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),$1,'manual',now(),now()+interval '1 hour')`
	if _, err := pool.Exec(ctx, insert, "198.51.100.0/24"); sqlState(err) != "23514" {
		t.Fatalf("network before 545: %v, want 23514", err)
	}
	mustExec(t, pool, insert, "198.51.100.1")
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	for _, good := range []string{"198.51.100.0/24", "10.0.0.0/8", "198.51.100.2", "2001:db8::/32", "2001:db8:1::/48", "2001:db8::2"} {
		mustExec(t, pool, insert, good)
	}
	for _, bad := range []string{"198.51.100.7/24", "10.0.0.0/7", "2001:db8::/31", "2001:db8::1/64"} {
		if _, err := pool.Exec(ctx, insert, bad); sqlState(err) != "23514" {
			t.Fatalf("%s: %v, want 23514", bad, err)
		}
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P5452" {
		t.Fatalf("down with network bans: %v, want P5452", err)
	}
	mustExec(t, pool, `DELETE FROM security_ban_entries WHERE masklen(client_ip) <> CASE WHEN family(client_ip)=4 THEN 32 ELSE 128 END`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if _, err := pool.Exec(ctx, insert, "198.51.100.0/24"); sqlState(err) != "23514" {
		t.Fatalf("network after down: %v, want 23514", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again %d: %v", version, err)
	}
}
