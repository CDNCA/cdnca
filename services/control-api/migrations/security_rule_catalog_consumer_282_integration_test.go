//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSecurityRuleCatalogConsumerMigration282(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 281)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "up", 282); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", 282); err != nil {
		t.Fatalf("rollback without local choices: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 282); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	var pgError *pgconn.PgError
	if _, err := pool.Exec(ctx, `INSERT INTO security_system_rules(system_key,kind,name,sort,hidden,revision,body,status,
		delivery_id,first_seen_at,updated_at) VALUES('cc_rule:1','cc_rule_group','JS验证',3,false,1,'{}','active',$1,now(),now())`,
		uuid.New()); !errors.As(err, &pgError) || pgError.Code != "P2821" {
		t.Fatalf("unsigned system rule insert error = %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('cdnca.security_rule_catalog_apply','on',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security_system_rules(system_key,kind,name,sort,hidden,revision,body,status,
		delivery_id,first_seen_at,updated_at) VALUES('cc_rule:1','cc_rule_group','JS验证',3,false,1,'{}','active',$1,now(),now())`,
		uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO security_system_rule_tenant_states(scope_id,system_key,enabled,revision,
		updated_by_user_id,updated_at) VALUES($1,'cc_rule:1',false,1,$2,$3)`, uuid.New(), uuid.New(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", 282); !errors.As(err, &pgError) || pgError.Code != "P2823" {
		t.Fatalf("rollback with tenant choices error = %v", err)
	}
}
