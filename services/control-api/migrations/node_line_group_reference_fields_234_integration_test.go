//go:build integration

package migrations_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var nodeLineGroupMigration234Time = time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)

func TestNodeLineGroupReferenceFields234RepresentableUpDownUp(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 233)
	scopeID, userID, groupID := seedNodeLineGroupMigration233(t, pool, "tenant", "reference-roundtrip")
	seedNodeLineGroupMigration234Receipt(t, pool, scopeID, userID, groupID)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 234); err != nil {
		t.Fatalf("233 -> 234: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 234)
	assertNodeLineGroupMigration234Columns(t, pool, true)
	assertNodeLineGroupMigration234Defaults(t, pool, scopeID, groupID)
	assertNodeLineGroupMigration234ReceiptFields(t, pool, scopeID, userID, true)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 234); err != nil {
		t.Fatalf("234 -> 233: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 233)
	assertNodeLineGroupMigration234Columns(t, pool, false)
	assertNodeLineGroupMigration234ReceiptFields(t, pool, scopeID, userID, false)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 234); err != nil {
		t.Fatalf("233 -> 234 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 234)
	assertNodeLineGroupMigration234Defaults(t, pool, scopeID, groupID)
	assertNodeLineGroupMigration234ReceiptFields(t, pool, scopeID, userID, true)
}

func TestNodeLineGroupReferenceFields234ReferenceGuardsAndRollbackFence(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 233)
	scopeID, userID, targetID := seedNodeLineGroupMigration233(t, pool, "tenant", "reference-target")
	if err := migrateVersionIsolated(t.Context(), pool, "up", 234); err != nil {
		t.Fatal(err)
	}

	primaryID := uuid.New()
	if err := insertNodeLineGroupMigration234(t, pool, scopeID, userID, primaryID,
		"Reference primary", "", "v4-reference-primary", &targetID, "interval"); err != nil {
		t.Fatalf("insert valid reference: %v", err)
	}

	otherScopeID, _, otherTargetID := seedNodeLineGroupMigration233(t, pool, "tenant", "reference-other-scope")
	if otherScopeID == scopeID {
		t.Fatal("cross-scope fixture reused the source scope")
	}
	assertNodeLineGroupMigration234Code(t, insertNodeLineGroupMigration234(t, pool, scopeID, userID,
		uuid.New(), "Cross scope", "", "v4-reference-cross-scope", &otherTargetID, "primary_offline"), "P2342")
	assertNodeLineGroupMigration234Code(t, insertNodeLineGroupMigration234(t, pool, scopeID, userID,
		uuid.New(), "Region mismatch", "华东", "v4-reference-region", &targetID, "primary_offline"), "P2342")

	nestedID := uuid.New()
	if err := insertNodeLineGroupMigration234(t, pool, scopeID, userID, nestedID,
		"Nested target", "", "v4-reference-nested", &targetID, "primary_offline"); err != nil {
		t.Fatalf("insert first-level reference: %v", err)
	}
	assertNodeLineGroupMigration234Code(t, insertNodeLineGroupMigration234(t, pool, scopeID, userID,
		uuid.New(), "Nested consumer", "", "v4-reference-nested-consumer", &nestedID, "primary_offline"), "P2342")

	selfID := uuid.New()
	assertNodeLineGroupMigration234Code(t, insertNodeLineGroupMigration234(t, pool, scopeID, userID,
		selfID, "Self reference", "", "v4-reference-self", &selfID, "primary_offline"), "P2342")

	deletedAt := nodeLineGroupMigration234Time.Add(time.Minute)
	_, err := pool.Exec(t.Context(), `UPDATE node_line_groups
		SET deleted_at=$4,deleted_by_user_id=$3,updated_by_user_id=$3,updated_at=$4
		WHERE tenant_scope_id=$1 AND id=$2`, scopeID, targetID, userID, deletedAt)
	assertNodeLineGroupMigration234Code(t, err, "P2342")

	assertNodeLineGroupMigration234Code(t, migrateVersionIsolated(t.Context(), pool, "down", 234), "P2341")
	assertPackageCommerceRBAC079Ledger(t, pool, 234)
	assertNodeLineGroupMigration234Columns(t, pool, true)
}

func seedNodeLineGroupMigration234Receipt(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, userID, groupID uuid.UUID,
) {
	t.Helper()
	writeID := uuid.New()
	createdAt := nodeLineGroupMigration234Time.Add(-time.Minute)
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_scheduling_write_requests(
		id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,target_group_id,created_at)
		VALUES($1,$2,$3,'node_scheduling.group.create','migration-234-receipt',$4,$5,$6)`,
		writeID, scopeID, userID, make([]byte, 32), groupID, createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_scheduling_write_requests
		SET response_body=jsonb_build_object('group',jsonb_build_object(
			'id',$2::text,'revision',1,'region','','resolved_value','migration-233-tenant','note','','sort_order',100
		),'replayed',false),completed_at=$3 WHERE id=$1`,
		writeID, groupID, nodeLineGroupMigration234Time); err != nil {
		t.Fatal(err)
	}
}

func insertNodeLineGroupMigration234(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, userID, groupID uuid.UUID,
	name, region, ipv4ResolvedValue string,
	l2ConfigID *uuid.UUID,
	failoverMode string,
) error {
	t.Helper()
	resolvedValue := "lg-" + strings.ReplaceAll(groupID.String(), "-", "")
	return pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_groups(
			id,tenant_scope_id,name,region,resolved_value,ipv4_resolved_value,l2_config_id,failover_mode,
			note,sort_order,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,'',100,1,$9,$9,$10,$10)`,
			groupID, scopeID, name, region, resolvedValue, ipv4ResolvedValue, l2ConfigID,
			failoverMode, userID, nodeLineGroupMigration234Time); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_group_revisions(
			line_group_id,tenant_scope_id,revision,name,region,resolved_value,ipv4_resolved_value,
			l2_config_id,failover_mode,note,sort_order,probe_interval_ms,probe_timeout_ms,
			failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,
			endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,'',100,10000,3000,3,3,0,0,0,$9,$10,$11)`,
			groupID, scopeID, name, region, resolvedValue, ipv4ResolvedValue, l2ConfigID,
			failoverMode, make([]byte, 32), userID, nodeLineGroupMigration234Time); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=$4
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`,
			scopeID, groupID, int64(1), nodeLineGroupMigration234Time)
		return err
	})
}

func assertNodeLineGroupMigration234Columns(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND
		      table_name IN ('node_line_groups','node_line_group_revisions') AND
		      column_name IN ('ipv4_resolved_value','l2_config_id','failover_mode')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if got := count == 6; got != want {
		t.Fatalf("migration 234 columns present=%v, want %v (count=%d)", got, want, count)
	}
}

func assertNodeLineGroupMigration234Defaults(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, groupID uuid.UUID,
) {
	t.Helper()
	wantIPv4 := "v4-" + strings.ReplaceAll(groupID.String(), "-", "")
	var currentIPv4, revisionIPv4, currentFailover, revisionFailover string
	var currentL2, revisionL2 *uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT current_group.ipv4_resolved_value,
		current_group.l2_config_id,current_group.failover_mode,revision.ipv4_resolved_value,
		revision.l2_config_id,revision.failover_mode
		FROM node_line_groups current_group
		JOIN node_line_group_revisions revision ON revision.tenant_scope_id=current_group.tenant_scope_id
		 AND revision.line_group_id=current_group.id AND revision.revision=current_group.current_revision
		WHERE current_group.tenant_scope_id=$1 AND current_group.id=$2`, scopeID, groupID).Scan(
		&currentIPv4, &currentL2, &currentFailover, &revisionIPv4, &revisionL2, &revisionFailover); err != nil {
		t.Fatal(err)
	}
	if currentIPv4 != wantIPv4 || revisionIPv4 != wantIPv4 || currentL2 != nil || revisionL2 != nil ||
		currentFailover != "primary_offline" || revisionFailover != "primary_offline" {
		t.Fatalf("migration 234 defaults current=(%q,%v,%q) revision=(%q,%v,%q)",
			currentIPv4, currentL2, currentFailover, revisionIPv4, revisionL2, revisionFailover)
	}
}

func assertNodeLineGroupMigration234ReceiptFields(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, userID uuid.UUID,
	want bool,
) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT (response_body->'group') ?&
		ARRAY['ipv4_resolved_value','l2_config_id','failover_mode']
		FROM node_scheduling_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND idempotency_key='migration-234-receipt'`,
		scopeID, userID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration 234 receipt fields present=%v, want %v", got, want)
	}
}

func assertNodeLineGroupMigration234Code(t *testing.T, err error, want string) {
	t.Helper()
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != want {
		t.Fatalf("migration 234 error=%v, want SQLSTATE %s", err, want)
	}
}
