//go:build integration

package migrations_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestSiteGroups272(t *testing.T) {
	if _, err := controlmigrations.FS.ReadFile("272_site_group_administration.up.sql"); err != nil {
		t.Fatal(err)
	}
	t.Run("backfill immutable IDs and versioned remarks", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 271)
		f := seedSiteGroup082Identity(t, pool, "admin272")
		id := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO site_groups(id,scope_id,name) VALUES($1,$2,'legacy')`, id, f.scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO site_group_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,resource_id,response_status,response_body,completed_at)
			VALUES($1,$2,$3,$3,'site_group.create','legacy',$4,$5,201,'{"name":"legacy"}',now())`, uuid.New(), f.userID, f.scopeID, make([]byte, 32), id); err != nil {
			t.Fatal(err)
		}
		var receiptBefore, receiptAfter []byte
		if err := pool.QueryRow(t.Context(), `SELECT row_to_json(r)::text FROM site_group_write_requests r WHERE idempotency_key='legacy'`).Scan(&receiptBefore); err != nil {
			t.Fatal(err)
		}
		if err := migrateVersionIsolated(t.Context(), pool, "up", 272); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(t.Context(), `SELECT row_to_json(r)::text FROM site_group_write_requests r WHERE idempotency_key='legacy'`).Scan(&receiptAfter); err != nil || !bytes.Equal(receiptBefore, receiptAfter) {
			t.Fatalf("legacy receipt changed: %v", err)
		}
		var display int64
		if err := pool.QueryRow(t.Context(), `SELECT display_id FROM site_group_display_ids WHERE scope_id=$1 AND group_id=$2`, f.scopeID, id).Scan(&display); err != nil || display != 1 {
			t.Fatalf("backfill=%d %v", display, err)
		}
		for _, sql := range []string{`UPDATE site_group_display_ids SET display_id=DEFAULT`, `DELETE FROM site_group_display_ids`, `TRUNCATE site_group_display_ids`} {
			_, err := pool.Exec(t.Context(), sql)
			assertSiteGroup082Code(t, err, "P2721")
		}
		_, generatedErr := pool.Exec(t.Context(), `UPDATE site_group_display_ids SET display_id=999`)
		assertSiteGroup082Code(t, generatedErr, "428C9")
		_, err := pool.Exec(t.Context(), `UPDATE site_groups SET remark='no revision' WHERE id=$1`, id)
		assertSiteGroup082Code(t, err, "P8209")
		if _, err := pool.Exec(t.Context(), `UPDATE site_groups SET remark=E'line1\nline2',revision=2,updated_at=now() WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(t.Context(), `UPDATE site_groups SET remark=chr(1),revision=3 WHERE id=$1`, id)
		assertSiteGroup082Code(t, err, "23514")
		var workers sync.WaitGroup
		for i := 0; i < 12; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				next := uuid.New()
				if _, err := pool.Exec(t.Context(), `INSERT INTO site_groups(id,scope_id,name) VALUES($1,$2,$3)`, next, f.scopeID, next.String()); err != nil {
					t.Error(err)
				}
			}()
		}
		workers.Wait()
		var count, unique int
		if err := pool.QueryRow(t.Context(), `SELECT count(*),count(DISTINCT display_id) FROM site_group_display_ids`).Scan(&count, &unique); err != nil || count != 13 || unique != count {
			t.Fatalf("IDs=%d/%d %v", count, unique, err)
		}
		assertSiteGroup082Code(t, migrateVersionIsolated(t.Context(), pool, "down", 272), "P2722")
		assertSiteGroup082Head(t, pool, 272)
	})
	t.Run("empty lossless round trip", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 271)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 272); err != nil {
			t.Fatal(err)
		}
		if err := migrateVersionIsolated(t.Context(), pool, "down", 272); err != nil {
			t.Fatal(err)
		}
		assertSiteGroup082Head(t, pool, 271)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 272); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("schema-bound runtime allocator and restricted mapping", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 271)
		f := seedSiteGroup082Identity(t, pool, "runtime272")
		if err := migrateVersionIsolated(t.Context(), pool, "up", 272); err != nil {
			t.Fatal(err)
		}
		var schema string
		if err := pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `GRANT USAGE ON SCHEMA `+pgx.Identifier{schema}.Sanitize()+` TO cdnca_control_app`); err != nil {
			t.Fatal(err)
		}
		// The isolated fixture has no deployment-time grants on pre-existing tables.
		if _, err := pool.Exec(t.Context(), `GRANT INSERT,SELECT ON site_groups TO cdnca_control_app; GRANT SELECT,UPDATE ON access_scopes TO cdnca_control_app`); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `SET LOCAL ROLE cdnca_control_app`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `CREATE TEMP TABLE site_group_display_ids(scope_id uuid,group_id uuid,display_id bigint) ON COMMIT DROP`); err != nil {
			t.Fatal(err)
		}
		id := uuid.New()
		if _, err := tx.Exec(t.Context(), `INSERT INTO `+pgx.Identifier{schema, "site_groups"}.Sanitize()+`(id,scope_id,name,remark) VALUES($1,$2,'runtime','kept')`, id, f.scopeID); err != nil {
			t.Fatal(err)
		}
		var shadow int
		if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM pg_temp.site_group_display_ids`).Scan(&shadow); err != nil || shadow != 0 {
			t.Fatalf("shadow=%d %v", shadow, err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		var display int64
		if err := pool.QueryRow(t.Context(), `SELECT display_id FROM site_group_display_ids WHERE scope_id=$1 AND group_id=$2`, f.scopeID, id).Scan(&display); err != nil || display != 1 {
			t.Fatalf("display=%d %v", display, err)
		}
		var read, write, sequence, execute bool
		if err := pool.QueryRow(t.Context(), `SELECT has_table_privilege('cdnca_control_app',$1,'SELECT'),has_table_privilege('cdnca_control_app',$1,'INSERT,UPDATE,DELETE,TRUNCATE'),has_sequence_privilege('cdnca_control_app',$2,'USAGE,SELECT,UPDATE'),has_function_privilege('cdnca_control_app',$3,'EXECUTE')`,
			schema+".site_group_display_ids", schema+".site_group_display_ids_display_id_seq", schema+".assign_site_group_display_id_272()").Scan(&read, &write, &sequence, &execute); err != nil || !read || write || sequence || execute {
			t.Fatalf("grants=%v/%v/%v/%v %v", read, write, sequence, execute, err)
		}
	})
	t.Run("refuses a corrupted predecessor without partial DDL", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 271)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations SET checksum_sha256=repeat('0',64) WHERE version=271`); err != nil {
			t.Fatal(err)
		}
		if err := migrateVersionIsolated(t.Context(), pool, "up", 272); err == nil || !strings.Contains(err.Error(), "migration 271 up checksum mismatch") {
			t.Fatalf("migrator did not reject the corrupted predecessor: %v", err)
		}
		up, err := controlmigrations.FS.ReadFile("272_site_group_administration.up.sql")
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), string(up))
		assertSiteGroup082Code(t, err, "P2720")
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		var absent bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema()||'.site_group_display_ids') IS NULL`).Scan(&absent); err != nil || !absent {
			t.Fatalf("partial table exists: %v", err)
		}
		assertSiteGroup082Head(t, pool, 271)
	})
}
