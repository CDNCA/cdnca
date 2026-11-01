//go:build integration

package migrations_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestURLAuthLegacyMarker602 rolls 602 up, down and up over stored rows
// carrying both old markers, a NULL marker included: each step rewrites the
// rows one-to-one, and the check accepts only the values of that step.
func TestURLAuthLegacyMarker602(t *testing.T) {
	// Keep equal to the 602 contract's version.
	const version = 602
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'602 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'urlauth-602','URL auth 602','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	// UNIQUE (scope_id, site_id) allows one policy per site: one site per marker row.
	sites := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for i, id := range sites {
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
				created_by_user_id,updated_by_user_id) VALUES($1,$2,$3,$4,$5,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$4,$4)`,
				id, scopeID, i+1, userID, fmt.Sprintf("urlauth602-%d.example.test", i+1)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, id); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, id)
			return err
		}); err != nil {
			t.Fatalf("seed site %d: %v", i+1, err)
		}
	}
	insert := func(site uuid.UUID, marker *string) (uuid.UUID, error) {
		id := uuid.New()
		_, err := pool.Exec(ctx, `INSERT INTO url_auth_policies(id,scope_id,tenant_id,owner_user_id,site_id,name,algorithm,
			migration_marker,signature_parameter,expiration_parameter,key_id_parameter,max_clock_skew_seconds,
			max_validity_seconds,max_signature_uses,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,'hmac-sha256',$7,'sign','expires','kid',30,3600,0,$4,$4,now(),now())`,
			id, scopeID, tenantID, userID, site, "p-"+id.String()[:8], marker)
		return id, err
	}
	str := func(s string) *string { return &s }
	rowA, err := insert(sites[0], str("cdnfly_type_a_md5"))
	if err != nil {
		t.Fatalf("seed a: %v", err)
	}
	rowB, err := insert(sites[1], str("cdnfly_type_b_md5"))
	if err != nil {
		t.Fatalf("seed b: %v", err)
	}
	rowNone, err := insert(sites[2], nil)
	if err != nil {
		t.Fatalf("seed null: %v", err)
	}
	marker := func(id uuid.UUID) *string {
		t.Helper()
		var got *string
		if err := pool.QueryRow(ctx, `SELECT migration_marker FROM url_auth_policies WHERE id=$1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	// accepts reports whether the current check allows value, without keeping the row change.
	accepts := func(value string) bool {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `UPDATE url_auth_policies SET migration_marker=$2 WHERE id=$1`, rowNone, value)
		if err != nil && sqlState(err) != "23514" {
			t.Fatalf("probe %s: %v", value, err)
		}
		return err == nil
	}
	expect := func(step, a, b, prefix string) {
		t.Helper()
		if got := marker(rowA); got == nil || *got != a {
			t.Fatalf("%s: row a = %v, want %s", step, got, a)
		}
		if got := marker(rowB); got == nil || *got != b {
			t.Fatalf("%s: row b = %v, want %s", step, got, b)
		}
		if got := marker(rowNone); got != nil {
			t.Fatalf("%s: null row = %v, want NULL", step, *got)
		}
		old := map[string]string{"legacy": "cdnfly", "cdnfly": "legacy"}[prefix]
		if !accepts(prefix+"_type_a_md5") || !accepts(prefix+"_type_b_md5") || accepts(old+"_type_a_md5") || accepts(old+"_type_b_md5") {
			t.Fatalf("%s: check does not accept exactly %s_type_*_md5", step, prefix)
		}
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		if step == "up" {
			expect(step, "legacy_type_a_md5", "legacy_type_b_md5", "legacy")
		} else {
			expect(step, "cdnfly_type_a_md5", "cdnfly_type_b_md5", "cdnfly")
		}
	}
}
