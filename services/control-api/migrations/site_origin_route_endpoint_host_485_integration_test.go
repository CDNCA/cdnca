//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestSiteOriginRouteEndpointHost485 (Codex A15/ORIGIN-DB-01): at 484 the
// endpoint host is inet and a DNS origin fails with 22P02 (the production
// PUT 500); 485 stores canonical text, keeps existing IP rows (as their bare
// address) and the 109 exclusions, and refuses to roll back over DNS rows.
func TestSiteOriginRouteEndpointHost485(t *testing.T) {
	const version = 485
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	siteID := uuid.New()
	code := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return ""
	}
	// FKs are triggers: replica role lets the endpoint rows stand alone, CHECKs still apply.
	insert := func(endpointID, host string, position int) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_route_endpoints
			(site_id,pool_id,endpoint_id,position,host,port,weight) VALUES ($1,'default',$2,$3,$4,443,10)`,
			siteID, endpointID, position, host); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	if err := insert("dns", "origin.example.test", 0); code(err) != "22P02" {
		t.Fatalf("484 DNS endpoint error = %v, want 22P02 (the reported 500)", err)
	}
	for index, host := range []string{"192.0.2.10", "2001:db8::10"} {
		if err := insert("ip-"+string(rune('a'+index)), host, index); err != nil {
			t.Fatalf("484 IP endpoint %s: %v", host, err)
		}
	}

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	// pgx caches the INSERT's parameter types per connection (inet before 485).
	pool.Reset()
	var dataType string
	if err := pool.QueryRow(ctx, `SELECT data_type FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='site_origin_route_endpoints' AND column_name='host'`).Scan(&dataType); err != nil {
		t.Fatal(err)
	}
	if dataType != "text" {
		t.Fatalf("host column type = %s, want text", dataType)
	}
	rows, err := pool.Query(ctx, `SELECT host FROM site_origin_route_endpoints WHERE site_id=$1 ORDER BY position`, siteID)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, host)
	}
	rows.Close()
	if len(kept) != 2 || kept[0] != "192.0.2.10" || kept[1] != "2001:db8::10" {
		t.Fatalf("existing IP endpoints after 485 = %v, want bare addresses", kept)
	}

	for position, host := range []string{"origin.example.test", "a-1.b2.example.com", "198.51.100.7", "2001:db8::7"} {
		if err := insert("ok-"+string(rune('a'+position)), host, 10+position); err != nil {
			t.Errorf("valid host %q rejected: %v", host, err)
		}
	}
	for position, host := range []string{
		"0.0.0.0", "::", "255.255.255.255", "169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1", "::ffff:192.0.2.1",
		"192.0.2.0/24", "2001:0db8::1", "Origin.Example.Test", " origin.example.test", "origin", "localhost",
		"origin.123", "-a.example.test", "a..example.test", "1.in-addr.arpa", "a_b.example.test", "",
	} {
		if err := insert("bad-"+string(rune('a'+position)), host, 20+position); code(err) != "23514" {
			t.Errorf("invalid host %q error = %v, want 23514", host, err)
		}
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); code(err) != "P4852" {
		t.Fatalf("down over DNS endpoints error = %v, want P4852", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM site_origin_route_endpoints
		WHERE site_id=$1 AND NOT pg_input_is_valid(host, 'inet')`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down over IP-only endpoints: %v", err)
	}
	var ipRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_origin_route_endpoints
		WHERE site_id=$1 AND host IN ('192.0.2.10'::inet,'2001:db8::10'::inet)`, siteID).Scan(&ipRows); err != nil {
		t.Fatal(err)
	}
	if ipRows != 2 {
		t.Fatalf("IP endpoints after down = %d, want 2", ipRows)
	}
}
