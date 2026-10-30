//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNodePurgeMigration284 covers the purge contract of migration 284:
// a node delete cascades through node-owned rows, protection triggers still
// reject UPDATE and any DELETE that is not that cascade, the live line group
// reference stays restricted, and 284 rolls back and re-applies cleanly.
func TestNodePurgeMigration284(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 283)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "up", 284); err != nil {
		t.Fatal(err)
	}
	scopeID, userID := uuid.New(), uuid.New()
	purged, kept := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'purge-owner','Purge owner','test-only')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	for index, id := range []uuid.UUID{purged, kept} {
		mustExec(t, pool, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,$5)`,
			id, scopeID, "purge-"+id.String()[:8], userID, index+1)
		mustExec(t, pool, `INSERT INTO node_serving_events(id,node_id,source,event,reason_code,hold_revision,detail,occurred_at)
			VALUES($1,$2,'availability_monitor','held','probe_failed',1,'{}',now())`, uuid.New(), id)
	}
	groupID := seedNodePurgeLineGroup(t, pool, scopeID, userID, purged)

	// Direct deletes and updates stay rejected, with or without the marker.
	for _, statement := range []string{
		`DELETE FROM node_serving_events WHERE node_id=$1`,
		`DELETE FROM node_identity_state WHERE node_id=$1`,
		`UPDATE node_serving_events SET reason_code='tampered' WHERE node_id=$1`,
	} {
		for _, marker := range []bool{false, true} {
			if err := purgeTx(ctx, pool, purged, marker, statement); err == nil {
				t.Fatalf("%s (marker=%v) was accepted", statement, marker)
			}
		}
	}
	// A purge marker for another node does not unlock this node's cascade.
	if err := purgeTx(ctx, pool, kept, true, `DELETE FROM nodes WHERE id='`+purged.String()+`'`); err == nil {
		t.Fatal("cascade with a marker for another node was accepted")
	}
	// The current revision of a live line group still lists the node.
	if err := purgeTx(ctx, pool, purged, true, `DELETE FROM nodes WHERE id=$1`); err == nil ||
		!strings.Contains(err.Error(), "current revision of a line group") {
		t.Fatalf("delete of a node in a live line group = %v", err)
	}
	mustExec(t, pool, `UPDATE node_line_groups SET deleted_at=now(),deleted_by_user_id=$2,updated_by_user_id=$2,updated_at=now() WHERE id=$1`,
		groupID, userID)
	if err := purgeTx(ctx, pool, purged, true, `DELETE FROM nodes WHERE id=$1`); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if left := nodeOwnedRows(t, pool, purged); left != "" {
		t.Fatalf("rows left after purge: %s", left)
	}
	var keptRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_serving_events WHERE node_id=$1`, kept).Scan(&keptRows); err != nil || keptRows != 1 {
		t.Fatalf("other node rows = %d, %v", keptRows, err)
	}
	// Without the marker a node delete is refused by the restored guards.
	if err := purgeTx(ctx, pool, kept, false, `DELETE FROM nodes WHERE id=$1`); err == nil {
		t.Fatal("node delete without the purge marker was accepted")
	}

	if err := migrateVersionIsolated(ctx, pool, "down", 284); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var restricted bool
	if err := pool.QueryRow(ctx, `SELECT confdeltype='r' FROM pg_constraint WHERE conname='node_serving_events_node_id_fkey'
		AND conrelid=(current_schema()||'.node_serving_events')::regclass`).Scan(&restricted); err != nil || !restricted {
		t.Fatalf("rollback restored RESTRICT = %v, %v", restricted, err)
	}
	if err := purgeTx(ctx, pool, kept, true, `DELETE FROM nodes WHERE id=$1`); err == nil {
		t.Fatal("node delete after rollback was accepted")
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 284); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if err := purgeTx(ctx, pool, kept, true, `DELETE FROM nodes WHERE id=$1`); err != nil {
		t.Fatalf("purge after re-apply: %v", err)
	}
	if left := nodeOwnedRows(t, pool, kept); left != "" {
		t.Fatalf("rows left after second purge: %s", left)
	}
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// purgeTx runs statement ($1 = node) in a transaction that optionally carries
// the cdnca.node_purge marker for node, and commits it.
func purgeTx(ctx context.Context, pool *pgxpool.Pool, node uuid.UUID, marker bool, statement string) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if marker {
			if _, err := tx.Exec(ctx, `SELECT set_config('cdnca.node_purge', $1, true)`, node.String()); err != nil {
				return err
			}
		}
		var args []any
		if strings.Contains(statement, "$1") {
			args = append(args, node)
		}
		_, err := tx.Exec(ctx, statement, args...)
		return err
	})
}

// nodeOwnedRows lists every table that references nodes (directly or through
// node-owned rows) and still holds a row for node.
func nodeOwnedRows(t *testing.T, pool *pgxpool.Pool, node uuid.UUID) string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		WITH RECURSIVE closure(relation) AS (
			SELECT conrelid FROM pg_constraint WHERE contype='f' AND confrelid=(current_schema()||'.nodes')::regclass
			UNION
			SELECT c.conrelid FROM pg_constraint c JOIN closure ON c.confrelid=closure.relation WHERE c.contype='f'
		)
		SELECT relation::regclass::text, attribute.attname FROM closure
		JOIN pg_attribute attribute ON attribute.attrelid=closure.relation
		WHERE attribute.attname IN ('node_id','target_node_id') AND NOT attribute.attisdropped`)
	if err != nil {
		t.Fatal(err)
	}
	type column struct{ table, name string }
	columns, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (column, error) {
		var item column
		return item, row.Scan(&item.table, &item.name)
	})
	if err != nil || len(columns) < 55 {
		t.Fatalf("node-owned columns = %d, %v", len(columns), err)
	}
	var left []string
	for _, item := range columns {
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{item.table}.Sanitize()+
			` WHERE `+pgx.Identifier{item.name}.Sanitize()+`=$1`, node).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			left = append(left, item.table)
		}
	}
	var nodes int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM nodes WHERE id=$1`, node).Scan(&nodes); err != nil || nodes != 0 {
		left = append(left, "nodes")
	}
	return strings.Join(left, ",")
}

// seedNodePurgeLineGroup seals revision 1 of a line group whose only
// endpoint (with its health row) points at node.
func seedNodePurgeLineGroup(t *testing.T, pool *pgxpool.Pool, scopeID, userID, node uuid.UUID) uuid.UUID {
	t.Helper()
	groupID := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			 VALUES($1,$2,'purge-guard',1,$3,$3,now(),now())`, []any{groupID, scopeID, userID}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,
			 probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,
			 configuration_digest,created_by_user_id,created_at)
			 VALUES($1,$2,1,'purge-guard','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$3,$4,now())`,
				[]any{groupID, scopeID, make([]byte, 32), userID}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,
			 region,carrier,priority,weight,enabled) VALUES($1,$2,$3,$4,1,'192.0.2.10',4,80,'','',0,1,true)`,
				[]any{uuid.New(), node, scopeID, groupID}},
			{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
			 consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			 SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now() FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2`,
				[]any{scopeID, groupID}},
			{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`,
				[]any{scopeID, groupID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed line group: %v", err)
	}
	return groupID
}
