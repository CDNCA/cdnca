//go:build integration

package migrations_test

import "testing"

// TestIPIntelUpdates367: the catalog gains local rows (ipintel/local only,
// feature-gated, no delivery); settings enable only with a sealed secret;
// the platform owner gets the permission; down refuses once a local library
// exists and restores delivery_id NOT NULL otherwise.
func TestIPIntelUpdates367(t *testing.T) {
	const version = 367
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	local := func(id, feature string, resident bool) error {
		_, err := pool.Exec(ctx, `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,
			requires_feature,resident,encryption,status,origin,first_seen_at,updated_at)
			VALUES($1,'ipintel','v1',1,repeat('a',64),10,'m',$2,$3,'none','active','local',now(),now())`, id, feature, resident)
		return err
	}
	for name, err := range map[string]error{
		"other id":   local("ipintel/base", "module.ipintel.dnspup", false),
		"no feature": local("ipintel/local", "", false),
		"resident":   local("ipintel/local", "module.ipintel.dnspup", true),
	} {
		if sqlState(err) != "23514" {
			t.Fatalf("%s: %v, want 23514", name, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,
		resident,encryption,status,first_seen_at,updated_at) VALUES('ipintel/base','ipintel','v1',1,repeat('a',64),10,'m',true,'none',
		'active',now(),now())`); sqlState(err) != "23514" {
		t.Fatalf("catalog row without delivery: %v, want 23514", err)
	}
	for name, statement := range map[string]string{
		"enable without secret":      `UPDATE ip_intel_update_settings SET enabled=true,url='https://x',api_key='k'`,
		"fingerprint without secret": `UPDATE ip_intel_update_settings SET secret_fingerprint='0123456789abcdef'`,
		"interval too short":         `UPDATE ip_intel_update_settings SET interval_minutes=10`,
		"anchor out of range":        `UPDATE ip_intel_update_settings SET anchor_minute=1440`,
	} {
		if _, err := pool.Exec(ctx, statement); sqlState(err) != "23514" {
			t.Fatalf("%s: %v, want 23514", name, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_permissions grant_row JOIN roles role ON role.id=grant_row.role_id
		WHERE role.name='platform_owner' AND grant_row.permission_name='system.ip_intel_updates.manage')`).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	var owners int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE name='platform_owner' AND system_role`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners > 0 && !granted {
		t.Fatal("platform owner lacks system.ip_intel_updates.manage")
	}
	if err := local("ipintel/local", "module.ipintel.dnspup", false); err != nil {
		t.Fatalf("local library: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3672" {
		t.Fatalf("down with a local library: %v, want P3672", err)
	}
	mustExec(t, pool, `DELETE FROM artifact_catalog_entries WHERE origin='local'`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,
		resident,encryption,status,first_seen_at,updated_at) VALUES('ipintel/base','ipintel','v1',1,repeat('a',64),10,'m',true,'none',
		'active',now(),now())`); sqlState(err) != "23502" {
		t.Fatalf("366 delivery_id NOT NULL: %v, want 23502", err)
	}
}
