//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// TestMigrateImport446: up/down/up; the order archive is read-only, a
// migrate_import_credit ledger row needs an approved balance credit, and the
// down refuses while legacy password hashes are stored.
func TestMigrateImport446(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_migrate_import.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("migrate import migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash)
		VALUES('00000000-0000-4000-8000-000000004321','mi446user','MI 446','unused')`)
	mustExec(t, pool, `INSERT INTO migrate_import_order_archive(id,user_id,job_id,source_system,source_instance,
		source_order_id,order_type,amount_minor,paid_minor,status,archived_at)
		VALUES(gen_random_uuid(),'00000000-0000-4000-8000-000000004321',gen_random_uuid(),'cdnfly-v6','cdn.test','9','recharge',100,100,'paid',now())`)
	if _, err := pool.Exec(ctx, `UPDATE migrate_import_order_archive SET paid_minor=0`); sqlState(err) != "P4462" {
		t.Fatalf("archive update: %v, want P4462", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM migrate_import_order_archive`); sqlState(err) != "P4462" {
		t.Fatalf("archive delete: %v, want P4462", err)
	}
	// A balanced migrate_import_credit without an approved credit row is
	// rejected at commit.
	mustExec(t, pool, `INSERT INTO tenants(id,display_name,created_at,updated_at)
		VALUES('00000000-0000-4000-8000-00000000432a','MI 446',now(),now())`)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES('00000000-0000-4000-8000-00000000432b','tenant','00000000-0000-4000-8000-00000000432a')`)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) SELECT '00000000-0000-4000-8000-00000000432c','platform'
		WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO billing_accounts(id,scope_id,kind,currency,balance_minor,revision,created_at,updated_at)
			VALUES('00000000-0000-4000-8000-00000000432b','00000000-0000-4000-8000-00000000432b','tenant_liability','CNY',100,2,now(),now())`,
		`INSERT INTO billing_accounts(id,scope_id,kind,currency,balance_minor,revision,created_at,updated_at)
			SELECT '00000000-0000-4000-8000-00000000432e',id,'platform_clearing','CNY',-100,2,now(),now()
			FROM access_scopes WHERE kind='platform'`,
		`INSERT INTO billing_transactions(id,target_scope_id,operation,direction,amount_minor,currency,reason,created_by_user_id,created_at)
			VALUES('00000000-0000-4000-8000-00000000432f','00000000-0000-4000-8000-00000000432b','migrate_import_credit','credit',100,'CNY','x',
			'00000000-0000-4000-8000-000000004321',now())`,
		`INSERT INTO billing_postings(id,transaction_id,account_id,side,amount_minor,balance_after_minor,created_at) VALUES
			(gen_random_uuid(),'00000000-0000-4000-8000-00000000432f','00000000-0000-4000-8000-00000000432b','credit',100,100,now()),
			(gen_random_uuid(),'00000000-0000-4000-8000-00000000432f','00000000-0000-4000-8000-00000000432e','debit',100,-100,now())`,
	} {
		if _, err = tx.Exec(ctx, statement); err != nil {
			break
		}
	}
	if err == nil {
		err = tx.Commit(ctx)
	} else {
		_ = tx.Rollback(ctx)
	}
	if sqlState(err) != "P4463" {
		t.Fatalf("orphan credit: %v, want P4463", err)
	}
	mustExec(t, pool, `INSERT INTO migrate_import_legacy_passwords(user_id,scheme,key_id,ciphertext,source_system,
		job_id,expires_at,created_at) VALUES('00000000-0000-4000-8000-000000004321','md5_hex','k1',
		'\x000102030405060708090a0b0c0d0e0f','goedge',gen_random_uuid(),now()+interval '1 day',now())`)
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) SELECT id,'00000000-0000-4000-8000-000000004321'
		FROM access_scopes WHERE kind='platform'`); sqlState(err) != "P4465" {
		t.Fatalf("legacy user joins platform: %v, want P4465", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4464" {
		t.Fatalf("down with legacy hashes: %v, want P4464", err)
	}
	// Deleting the user cascades through the read-only archive.
	mustExec(t, pool, `DELETE FROM users WHERE id='00000000-0000-4000-8000-000000004321'`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
