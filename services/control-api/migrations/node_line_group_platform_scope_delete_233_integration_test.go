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

var nodeLineGroupMigration233Time = time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)

func TestNodeLineGroupPlatformScopeDelete233TenantUpDownUp(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 232)
	scopeID, _, groupID := seedNodeLineGroupMigration233(t, pool, "tenant", "tenant-roundtrip")

	if err := migrateVersionIsolated(t.Context(), pool, "up", 233); err != nil {
		t.Fatalf("232 -> 233: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 233)
	assertNodeLineGroupMigration233Columns(t, pool, true)
	assertNodeLineGroupMigration233Facts(t, pool, scopeID, groupID)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 233); err != nil {
		t.Fatalf("233 -> 232: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 232)
	assertNodeLineGroupMigration233Columns(t, pool, false)
	assertNodeLineGroupMigration233Facts(t, pool, scopeID, groupID)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 233); err != nil {
		t.Fatalf("232 -> 233 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 233)
	assertNodeLineGroupMigration233Columns(t, pool, true)
	assertNodeLineGroupMigration233Facts(t, pool, scopeID, groupID)
}

func TestNodeLineGroupPlatformScopeDelete233RollbackRefusesUnrepresentableFacts(t *testing.T) {
	t.Run("platform scope", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 232)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 233); err != nil {
			t.Fatal(err)
		}
		seedNodeLineGroupMigration233(t, pool, "platform", "platform-refusal")
		assertNodeLineGroupMigration233Code(t, migrateVersionIsolated(t.Context(), pool, "down", 233), "P2331")
		assertPackageCommerceRBAC079Ledger(t, pool, 233)
		assertNodeLineGroupMigration233Columns(t, pool, true)
	})

	t.Run("soft deleted tenant", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 232)
		scopeID, userID, groupID := seedNodeLineGroupMigration233(t, pool, "tenant", "deleted-refusal")
		if err := migrateVersionIsolated(t.Context(), pool, "up", 233); err != nil {
			t.Fatal(err)
		}
		deletedAt := nodeLineGroupMigration233Time.Add(time.Minute)
		if _, err := pool.Exec(t.Context(), `UPDATE node_line_groups
			SET deleted_at=$4,deleted_by_user_id=$3,updated_by_user_id=$3,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2`, scopeID, groupID, userID, deletedAt); err != nil {
			t.Fatalf("soft delete tenant line group: %v", err)
		}
		assertNodeLineGroupMigration233Code(t, migrateVersionIsolated(t.Context(), pool, "down", 233), "P2331")
		assertPackageCommerceRBAC079Ledger(t, pool, 233)
		assertNodeLineGroupMigration233Columns(t, pool, true)
	})
}

func seedNodeLineGroupMigration233(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeKind string,
	label string,
) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	if scopeKind != "tenant" && scopeKind != "platform" {
		t.Fatalf("unsupported scope kind %q", scopeKind)
	}
	ctx := t.Context()
	scopeID, userID, groupID := uuid.New(), uuid.New(), uuid.New()
	username := "migration-233-" + label + "-" + strings.ReplaceAll(userID.String(), "-", "")
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if scopeKind == "tenant" {
			tenantID := uuid.New()
			if _, err := tx.Exec(ctx, `INSERT INTO tenants(id,display_name,created_at,updated_at)
				VALUES($1,$2,$3,$3)`, tenantID, "Migration 233 "+label, nodeLineGroupMigration233Time); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id)
				VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
			VALUES($1,$2,$3,'test-only',$4,$4)`, userID, username, "Migration 233 "+label, nodeLineGroupMigration233Time); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(scope_id,user_id,created_at)
			VALUES($1,$2,$3)`, scopeID, userID, nodeLineGroupMigration233Time); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_groups(
			id,tenant_scope_id,name,region,resolved_value,note,sort_order,current_revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,'','migration-233-`+scopeKind+`','',100,1,$4,$4,$5,$5)`,
			groupID, scopeID, "Migration 233 "+label, userID, nodeLineGroupMigration233Time); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_group_revisions(
			line_group_id,tenant_scope_id,revision,name,region,resolved_value,note,sort_order,
			probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,
			failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,
			created_by_user_id,created_at)
			VALUES($1,$2,1,$3,'','migration-233-`+scopeKind+`','',100,
			10000,3000,3,3,0,0,0,$4,$5,$6)`, groupID, scopeID, "Migration 233 "+label,
			make([]byte, 32), userID, nodeLineGroupMigration233Time); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE node_line_group_revisions SET sealed_at=$4
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`,
			scopeID, groupID, int64(1), nodeLineGroupMigration233Time)
		return err
	}); err != nil {
		t.Fatalf("seed %s line group: %v", scopeKind, err)
	}
	return scopeID, userID, groupID
}

func assertNodeLineGroupMigration233Columns(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='node_line_groups'
		  AND column_name IN ('deleted_at','deleted_by_user_id')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if got := count == 2; got != want {
		t.Fatalf("migration 233 columns present=%v, want %v (count=%d)", got, want, count)
	}
}

func assertNodeLineGroupMigration233Facts(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	groupID uuid.UUID,
) {
	t.Helper()
	var groupCount, revisionCount int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM node_line_groups WHERE tenant_scope_id=$1 AND id=$2),
		(SELECT count(*) FROM node_line_group_revisions
		 WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1 AND sealed_at IS NOT NULL)`,
		scopeID, groupID).Scan(&groupCount, &revisionCount); err != nil {
		t.Fatal(err)
	}
	if groupCount != 1 || revisionCount != 1 {
		t.Fatalf("migration 233 facts group=%d revision=%d", groupCount, revisionCount)
	}
}

func assertNodeLineGroupMigration233Code(t *testing.T, err error, want string) {
	t.Helper()
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != want {
		t.Fatalf("migration 233 error=%v, want SQLSTATE %s", err, want)
	}
}
