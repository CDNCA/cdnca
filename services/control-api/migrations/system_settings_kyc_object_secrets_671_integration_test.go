//go:build integration

package migrations_test

import "testing"

// 671: 670 -> 671 -> 670 -> 671. Up lets the page secrets envelope fingerprint the three KYC
// object store keys; down refuses (P6712) while one of them is saved.
func TestSystemSettingsKYCObjectSecrets671UpDownUp(t *testing.T) {
	const version = 671
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	const platform = "67100000-0000-4000-8000-000000000001"
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	insert := func(fingerprints string) error {
		_, err := pool.Exec(ctx, `INSERT INTO platform_system_user_settings
			(platform_scope_id,revision,settings,updated_at,secrets_key_id,secrets_ciphertext,secrets_fingerprints)
			VALUES($1,1,'{}',now(),'k1',decode(repeat('00',29),'hex'),$2::jsonb)`, platform, fingerprints)
		return err
	}
	clearRow := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `DELETE FROM platform_system_user_settings`); err != nil {
			t.Fatal(err)
		}
	}
	const objectKey = `{"kyc_object_secret_access_key":"0123456789abcdef"}`
	if err := insert(objectKey); err == nil {
		t.Fatal("670 accepted a KYC object store secret fingerprint")
	}
	for _, direction := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, direction, version); err != nil {
			t.Fatalf("%s %d: %v", direction, version, err)
		}
	}
	if err := insert(`{"kyc_object_access_key_id":"0123456789abcdef","kyc_object_session_token":"0123456789abcdef","kyc_api_key":"0123456789abcdef"}`); err != nil {
		t.Fatalf("671 refused KYC object store fingerprints: %v", err)
	}
	clearRow()
	if err := insert(`{"smtp_password":"0123456789abcdef"}`); err == nil {
		t.Fatal("671 accepted an unknown secret fingerprint")
	}
	if err := insert(objectKey); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("671 down dropped a saved KYC object store secret")
	}
	clearRow()
	if err := insert(`{"kyc_api_key":"0123456789abcdef"}`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("671 down with only 668 secrets: %v", err)
	}
}
