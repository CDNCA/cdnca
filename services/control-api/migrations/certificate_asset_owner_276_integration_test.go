//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCertificateAssetOwnerMigration276(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 275)
	scope, tenant, actor, owner, legacyID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Certificate owner migration');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,'owner-276-actor','Actor','unused'),($4,'owner-276-user','Owner','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3),($2,$4);
		INSERT INTO certificate_assets(tenant_scope_id,id,name,source,created_by_scope_id,created_by_user_id,updated_by_scope_id,updated_by_user_id,created_at,updated_at)
		VALUES($2,$5,'Legacy certificate','uploaded',$2,$3,$2,$3,now(),now())`, pgx.QueryExecModeSimpleProtocol, tenant, scope, actor, owner, legacyID); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 276); err != nil {
		t.Fatal(err)
	}
	var recorded *uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT owner_user_id FROM certificate_assets WHERE id=$1`, legacyID).Scan(&recorded); err != nil || recorded != nil {
		t.Fatalf("legacy owner was inferred: %v %v", recorded, err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 276); err != nil {
		t.Fatalf("nullable-only rollback: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 276); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	assetID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO certificate_assets(tenant_scope_id,id,name,source,created_by_scope_id,created_by_user_id,updated_by_scope_id,updated_by_user_id,owner_user_id,created_at,updated_at)
		VALUES($1,$2,'Recorded certificate','uploaded',$1,$3,$1,$3,$4,now(),now())`, scope, assetID, actor, owner); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `UPDATE certificate_assets SET owner_user_id=$2,revision=revision+1 WHERE id=$1`, assetID, actor)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "P2761" {
		t.Fatalf("owner mutation must fail with P2761: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM memberships WHERE scope_id=$1 AND user_id=$2`, scope, owner); err != nil {
		t.Fatalf("historical ownership imposed a membership FK: %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT owner_user_id FROM certificate_assets WHERE id=$1`, assetID).Scan(&recorded); err != nil || recorded == nil || *recorded != owner {
		t.Fatalf("member removal lost recorded owner: %v %v", recorded, err)
	}
	err = migrateVersionIsolated(t.Context(), pool, "down", 276)
	if !errors.As(err, &pgError) || pgError.Code != "P2762" {
		t.Fatalf("recorded owner rollback must fail with P2762: %v", err)
	}
	var head int
	if err := pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != 276 {
		t.Fatalf("rollback failure changed head: %d %v", head, err)
	}
}
