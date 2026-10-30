//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSiteTLSProfile387: the TLS profile columns and CHECKs (contiguous
// protocol ranges, legacy versions only with the legacy preset, a client CA
// exactly with client verification), the system SSL default without
// "custom", and down refusing a profile 386 cannot hold.
func TestSiteTLSProfile387(t *testing.T) {
	const version = 387
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'387 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'tls-387','TLS 387','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,http_ports,https_ports,
			origins,origin_hosts,created_by_user_id,updated_by_user_id) VALUES($1,$2,1,$3,'tls387.example.com',ARRAY['80'],
			ARRAY['443'],ARRAY['origin.example.com:80'],ARRAY['origin.example.com'],$3,$3)`, siteID, scopeID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.com',80)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var preset, auth string
	var stapling bool
	if err := pool.QueryRow(ctx, `SELECT tls_cipher_preset,tls_ocsp_stapling,tls_client_auth FROM sites WHERE id=$1`,
		siteID).Scan(&preset, &stapling, &auth); err != nil || preset != "modern" || stapling || auth != "off" {
		t.Fatalf("defaults %q %v %q (%v)", preset, stapling, auth, err)
	}
	const ca = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	update := `UPDATE sites SET tls_protocols=$2,tls_cipher_preset=$3,tls_client_auth=$4,tls_client_ca_pem=$5 WHERE id=$1`
	for _, good := range []struct {
		protocols    []string
		preset, auth string
		ca           any
	}{
		{[]string{"TLSv1.3"}, "modern", "off", nil},
		{[]string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}, "legacy", "off", nil},
		{[]string{"TLSv1.2", "TLSv1.3"}, "compatible", "required", ca},
		{[]string{"TLSv1.2", "TLSv1.3"}, "legacy", "optional", ca},
	} {
		mustExec(t, pool, update, siteID, good.protocols, good.preset, good.auth, good.ca)
	}
	for _, bad := range []struct {
		protocols    []string
		preset, auth string
		ca           any
	}{
		{[]string{"TLSv1", "TLSv1.3"}, "legacy", "off", nil},                  // a gap
		{[]string{"SSLv3", "TLSv1.2", "TLSv1.3"}, "legacy", "off", nil},       // SSL
		{[]string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}, "compatible", "off", nil}, // legacy version, wider preset
		{[]string{"TLSv1.2", "TLSv1.3"}, "custom", "off", nil},
		{[]string{"TLSv1.2", "TLSv1.3"}, "modern", "required", nil},
		{[]string{"TLSv1.2", "TLSv1.3"}, "modern", "off", ca},
		{[]string{"TLSv1.2", "TLSv1.3"}, "modern", "optional", "not a certificate"},
	} {
		if _, err := pool.Exec(ctx, update, siteID, bad.protocols, bad.preset, bad.auth, bad.ca); sqlState(err) != "23514" {
			t.Fatalf("%+v: %v, want 23514", bad, err)
		}
	}
	var accepts, refusesCustom bool
	if err := pool.QueryRow(ctx, `SELECT system_configuration_v2_default_ssl($1::jsonb),
		NOT system_configuration_v2_default_ssl($2::jsonb)`,
		`{"mode":"recommended","protocols":["TLSv1.2","TLSv1.3"],"cipher_suites":"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305","prefer_server_ciphers":false}`,
		`{"mode":"custom","protocols":["TLSv1.3"],"cipher_suites":"TLS_AES_128_GCM_SHA256","prefer_server_ciphers":false}`,
	).Scan(&accepts, &refusesCustom); err != nil || !accepts || !refusesCustom {
		t.Fatalf("default SSL validation: recommended %v, custom refused %v (%v)", accepts, refusesCustom, err)
	}
	// The site still holds a profile 386 cannot hold.
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3872" {
		t.Fatalf("down with a TLS profile: %v, want P3872", err)
	}
	mustExec(t, pool, update, siteID, []string{"TLSv1.2", "TLSv1.3"}, "modern", "off", nil)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
}
