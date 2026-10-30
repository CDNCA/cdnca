//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPackageCatalogSubtransactionXIDGuard130Contract(t *testing.T) {
	up := readPackageCatalogGuard130(t, "130_package_catalog_subtransaction_xid_guard.up.sql")
	down := readPackageCatalogGuard130(t, "130_package_catalog_subtransaction_xid_guard.down.sql")
	for _, fragment := range []string{
		"package_catalog_current_backend_owns_xid_130(candidate xid)",
		"lock_row.pid=pg_backend_pid()",
		"lock_row.locktype='transactionid'",
		"lock_row.transactionid=candidate",
		"lock_row.mode='ExclusiveLock'",
		"lock_row.granted",
		"CREATE OR REPLACE FUNCTION protect_package_catalog_state_090()",
		"package_catalog_current_backend_owns_xid_130(source.xmin)",
		"package_catalog_current_backend_owns_xid_130(audit.xmin)",
		"package_catalog_subtransaction_xid_guard_130",
		"ERRCODE='P1300'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("130 up missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"pg_current_xact_id", "::text::xid", "backend_xid=candidate"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("130 up uses unsafe transaction identity fragment %q", forbidden)
		}
	}
	for _, fragment := range []string{
		"rollback would discard subtransaction-safe catalog facts",
		"ERRCODE='P1301'",
		"source.xmin=current_package_catalog_xid_090()",
		"DROP FUNCTION package_catalog_current_backend_owns_xid_130(xid)",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("130 down missing %q", fragment)
		}
	}
}

func TestPackageCatalogSubtransactionXIDGuard130RoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 90)

	t.Run("empty down and up", func(t *testing.T) {
		applyPackageCatalogGuard130(t, pool)
		if err := rollbackPackageCatalogGuard130(t, pool); err != nil {
			t.Fatalf("empty 130 down: %v", err)
		}
		var helperExists, markerExists bool
		if err := pool.QueryRow(t.Context(), `SELECT
			to_regprocedure('package_catalog_current_backend_owns_xid_130(xid)') IS NOT NULL,
			to_regclass('package_catalog_subtransaction_xid_guard_130') IS NOT NULL`).Scan(
			&helperExists, &markerExists); err != nil {
			t.Fatal(err)
		}
		if helperExists || markerExists {
			t.Fatalf("130 down helper/marker=%v/%v", helperExists, markerExists)
		}
		applyPackageCatalogGuard130(t, pool)
	})

	t.Run("top sub foreign and completed xid ownership", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `CREATE TABLE package_catalog_xid_probe_130(id integer PRIMARY KEY)`); err != nil {
			t.Fatal(err)
		}

		top, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := top.Exec(t.Context(), `INSERT INTO package_catalog_xid_probe_130(id) VALUES(1)`); err != nil {
			t.Fatal(err)
		}
		var topOwned bool
		if err := top.QueryRow(t.Context(), `SELECT package_catalog_current_backend_owns_xid_130(xmin)
			FROM package_catalog_xid_probe_130 WHERE id=1`).Scan(&topOwned); err != nil || !topOwned {
			t.Fatalf("top transaction ownership=%v err=%v", topOwned, err)
		}
		if err := top.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}

		holder, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Rollback(t.Context())
		nested, err := holder.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nested.Exec(t.Context(), `SELECT 1`); err != nil {
			t.Fatal(err)
		}
		if err := nested.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := holder.Exec(t.Context(), `INSERT INTO package_catalog_xid_probe_130(id) VALUES(2)`); err != nil {
			t.Fatal(err)
		}
		var holderPID int32
		var subtransactionOwned bool
		if err := holder.QueryRow(t.Context(), `SELECT pg_backend_pid(),
			package_catalog_current_backend_owns_xid_130(xmin)
			FROM package_catalog_xid_probe_130 WHERE id=2`).Scan(&holderPID, &subtransactionOwned); err != nil || !subtransactionOwned {
			t.Fatalf("subtransaction ownership=%v pid=%d err=%v", subtransactionOwned, holderPID, err)
		}
		var foreignOwned bool
		if err := pool.QueryRow(t.Context(), `SELECT COALESCE(bool_or(
			package_catalog_current_backend_owns_xid_130(transactionid)),false)
			FROM pg_locks WHERE pid=$1 AND locktype='transactionid' AND mode='ExclusiveLock' AND granted`,
			holderPID).Scan(&foreignOwned); err != nil || foreignOwned {
			t.Fatalf("foreign backend ownership=%v err=%v", foreignOwned, err)
		}
		if err := holder.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		var completedOwned bool
		if err := pool.QueryRow(t.Context(), `SELECT package_catalog_current_backend_owns_xid_130(xmin)
			FROM package_catalog_xid_probe_130 WHERE id=2`).Scan(&completedOwned); err != nil || completedOwned {
			t.Fatalf("completed xid ownership=%v err=%v", completedOwned, err)
		}
	})

	t.Run("savepoint rollback catalog write and fail closed down", func(t *testing.T) {
		identity := seedPackageOfferIdentity090(t, pool)
		groupID := uuid.New()
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			preflight, err := tx.Begin(t.Context())
			if err != nil {
				return err
			}
			if _, err := preflight.Exec(t.Context(), `SELECT 1`); err != nil {
				return err
			}
			if err := preflight.Rollback(t.Context()); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO package_groups(
				id,name,visible,sort_order,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,'Subtransaction package group',true,10,1,$2,$2,clock_timestamp(),clock_timestamp())`,
				groupID, identity.userID); err != nil {
				return err
			}
			return insertPackageCatalogAudit090(t.Context(), tx, identity, "package.group.create",
				"package_group", groupID, map[string]any{"revision": int64(1), "visible": true})
		}); err != nil {
			t.Fatalf("valid savepoint-rollback catalog write: %v", err)
		}
		var facts, links, highWater int64
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM package_group_state_facts_090 WHERE group_id=$1 AND revision=1),
			(SELECT count(*) FROM package_catalog_audit_links_090 WHERE resource_id=$1),
			(SELECT high_water FROM package_catalog_commit_watermark_090 WHERE singleton)`, groupID).Scan(
			&facts, &links, &highWater); err != nil {
			t.Fatal(err)
		}
		if facts != 1 || links != 1 || highWater != 1 {
			t.Fatalf("savepoint fact/link/high-water=%d/%d/%d", facts, links, highWater)
		}
		assertPackageOfferCode090(t, rollbackPackageCatalogGuard130(t, pool), "P1301")
	})
}

func applyPackageCatalogGuard130(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	up := []byte(readPackageCatalogGuard130(t, "130_package_catalog_subtransaction_xid_guard.up.sql"))
	down := []byte(readPackageCatalogGuard130(t, "130_package_catalog_subtransaction_xid_guard.down.sql"))
	upDigest, downDigest := sha256.Sum256(up), sha256.Sum256(down)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), string(up)); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO schema_migrations(
			version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at)
			VALUES(130,'130_package_catalog_subtransaction_xid_guard',$1,$2,'verified',clock_timestamp())`,
			fmt.Sprintf("%x", upDigest), fmt.Sprintf("%x", downDigest))
		return err
	}); err != nil {
		t.Fatalf("apply migration 130: %v", err)
	}
}

func rollbackPackageCatalogGuard130(t *testing.T, pool *pgxpool.Pool) error {
	t.Helper()
	down := readPackageCatalogGuard130(t, "130_package_catalog_subtransaction_xid_guard.down.sql")
	return pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), down); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=130`)
		return err
	})
}

func readPackageCatalogGuard130(t *testing.T, name string) string {
	t.Helper()
	payload, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
