//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// 673: 672 -> 673 -> 672 -> 673. Up lets the page secrets envelope fingerprint the evidence
// issuer's server private key and hold up to 32768 bytes; down refuses (P6732) while the key is saved or the
// envelope is larger than the earlier 16384.
func TestSystemSettingsKYCIssuerKey673UpDownUp(t *testing.T) {
	const version = 673
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	const platform = "67300000-0000-4000-8000-000000000001"
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	insert := func(fingerprints string, ciphertextBytes int) error {
		_, err := pool.Exec(ctx, `INSERT INTO platform_system_user_settings
			(platform_scope_id,revision,settings,updated_at,secrets_key_id,secrets_ciphertext,secrets_fingerprints)
			VALUES($1,1,'{}',now(),'k1',decode(repeat('00',$3::int),'hex'),$2::jsonb)`, platform, fingerprints, ciphertextBytes)
		return err
	}
	clearRow := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `DELETE FROM platform_system_user_settings`); err != nil {
			t.Fatal(err)
		}
	}
	const issuerKey = `{"kyc_issuer_server_private_key":"0123456789abcdef"}`
	if err := insert(issuerKey, 29); err == nil {
		t.Fatal("672 accepted an issuer private key fingerprint")
	}
	if err := insert(`{"kyc_api_key":"0123456789abcdef"}`, 16385); err == nil {
		t.Fatal("672 accepted an envelope over 16384 bytes")
	}
	for _, direction := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, direction, version); err != nil {
			t.Fatalf("%s %d: %v", direction, version, err)
		}
	}
	if err := insert(`{"kyc_issuer_server_private_key":"0123456789abcdef","kyc_object_session_token":"0123456789abcdef"}`, 32768); err != nil {
		t.Fatalf("673 refused the issuer private key fingerprint: %v", err)
	}
	clearRow()
	for name, tc := range map[string]struct {
		fingerprints string
		bytes        int
	}{
		"unknown secret":     {`{"smtp_password":"0123456789abcdef"}`, 29},
		"envelope too long":  {`{"kyc_api_key":"0123456789abcdef"}`, 32769},
		"envelope too short": {`{"kyc_api_key":"0123456789abcdef"}`, 28},
	} {
		if err := insert(tc.fingerprints, tc.bytes); err == nil {
			t.Fatalf("673 accepted %s", name)
		}
	}
	for name, tc := range map[string]struct {
		fingerprints string
		bytes        int
	}{
		"saved issuer key": {issuerKey, 29},
		"large envelope":   {`{"kyc_api_key":"0123456789abcdef"}`, 16385},
	} {
		if err := insert(tc.fingerprints, tc.bytes); err != nil {
			t.Fatal(err)
		}
		err := migrateVersionIsolated(ctx, pool, "down", version)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P6732" {
			t.Fatalf("673 down with %s: %v", name, err)
		}
		clearRow()
	}
	if err := insert(`{"kyc_object_access_key_id":"0123456789abcdef"}`, 16384); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("673 down with only 671 secrets: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("673 up again: %v", err)
	}
}
