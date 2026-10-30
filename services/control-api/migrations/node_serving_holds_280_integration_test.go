//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNodeServingHoldsMigration280(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 279)
	ctx := t.Context()
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'serving-owner','Serving owner','test-only')`, []any{userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'n1','active',$3,1)`, []any{nodeID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 280); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", 280); err != nil {
		t.Fatalf("rollback without holds: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 280); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	var pgError *pgconn.PgError
	insert := `INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,changed_at,updated_at)
		VALUES($1,'availability_monitor',true,'probe_unhealthy',$2,now(),now(),now())`
	if _, err := pool.Exec(ctx, insert, nodeID, 2); !errors.As(err, &pgError) || pgError.Code != "P2802" {
		t.Fatalf("hold must start at revision 1: %v", err)
	}
	if _, err := pool.Exec(ctx, insert, nodeID, 1); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct{ query, code string }{
		{`UPDATE node_serving_holds SET held=false,held_since=NULL WHERE node_id=$1`, "P2802"},
		{`UPDATE node_serving_holds SET held=false,revision=2 WHERE node_id=$1`, "23514"},
		{`UPDATE node_serving_holds SET revision=3 WHERE node_id=$1`, "P2802"},
		{`DELETE FROM node_serving_holds WHERE node_id=$1`, "P2801"},
	} {
		if _, err := pool.Exec(ctx, invalid.query, nodeID); !errors.As(err, &pgError) || pgError.Code != invalid.code {
			t.Fatalf("%s: %v", invalid.query, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE node_serving_holds SET protected_groups=1,updated_at=now() WHERE node_id=$1`, nodeID); !errors.As(err, &pgError) || pgError.Code != "P2802" {
		t.Fatalf("becoming protected without a revision accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_serving_holds SET protected_groups=1,revision=2,updated_at=now() WHERE node_id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_serving_holds SET protected_groups=2,updated_at=now() WHERE node_id=$1`, nodeID); err != nil {
		t.Fatalf("protected count refresh without transition: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_serving_events(id,node_id,source,event,reason_code,hold_revision,occurred_at)
		VALUES($1,$2,'availability_monitor','held','probe_unhealthy',1,now())`, uuid.New(), nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_serving_events SET reason_code='x'`); !errors.As(err, &pgError) || pgError.Code != "P2801" {
		t.Fatalf("event mutation accepted: %v", err)
	}
	err := migrateVersionIsolated(ctx, pool, "down", 280)
	if !errors.As(err, &pgError) || pgError.Code != "P2803" {
		t.Fatalf("rollback with an active hold must fail with P2803: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_serving_holds SET held=false,held_since=NULL,protected_groups=0,revision=3,
		reason_code='probe_recovered',changed_at=now(),updated_at=now() WHERE node_id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", 280); err != nil {
		t.Fatalf("rollback after release: %v", err)
	}
}
