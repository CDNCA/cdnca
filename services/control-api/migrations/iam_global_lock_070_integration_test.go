package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIAMAuthority070RestrictedEntryAndRoundTrip(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()

	if err := migrate070(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 70)

	scopeID := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var locked []uuid.UUID
		return tx.QueryRow(t.Context(), `SELECT iam_begin_authority_mutation_v1($1::text,$2::uuid[])`,
			"identity.session.revoke", []uuid.UUID{scopeID}).Scan(&locked)
	})
	if err != nil {
		t.Fatalf("begin restricted authority mutation: %v", err)
	}

	if err := migrate070(t.Context(), pool, "down"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 69)
	if err := pool.QueryRow(t.Context(), `SELECT iam_begin_authority_mutation_v1(
		'identity.session.revoke',ARRAY[$1::uuid])`, scopeID).Scan(new([]uuid.UUID)); err == nil {
		t.Fatal("070 authority entry still exists after down")
	}
	if err := migrate070(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 70)
}

func TestIAMAuthority070RejectsUnboundedInputsAndPublicExecute(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate070(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}

	for _, operation := range []string{"", "SELECT 1", "identity.unknown", strings.Repeat("a", 129)} {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `SELECT iam_begin_authority_mutation_v1($1::text,ARRAY[$2::uuid])`,
				operation, uuid.New())
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P7000" {
			t.Fatalf("operation %q error = %v, want P7000", operation, err)
		}
	}

	var publicExecute bool
	if err := pool.QueryRow(t.Context(), `SELECT has_function_privilege(
		'public','iam_begin_authority_mutation_v1(text,uuid[])','EXECUTE')`).Scan(&publicExecute); err != nil {
		t.Fatal(err)
	}
	if publicExecute {
		t.Fatal("PUBLIC can execute Stage2A authority entry")
	}
}

func TestIAMAuthority070CollisionReentryLegacyIsolationAndRollback(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate070(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}

	first := uuid.MustParse("2e3b59e0-cc21-4548-73fd-ec3b8f1c0744")
	second := uuid.MustParse("e67ca162-05d5-3aad-1b66-0bec1ae748d7")
	holder, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	var initial, reentered []uuid.UUID
	if err := holder.QueryRow(t.Context(), `SELECT iam_begin_authority_mutation_v1(
		'identity.session.revoke',$1::uuid[])`, []uuid.UUID{first, second}).Scan(&initial); err != nil {
		t.Fatal(err)
	}
	if err := holder.QueryRow(t.Context(), `SELECT iam_begin_authority_mutation_v1(
		'identity.session.revoke',$1::uuid[])`, []uuid.UUID{second, first, first}).Scan(&reentered); err != nil {
		t.Fatal(err)
	}
	want := []uuid.UUID{first, second}
	if !equalUUIDs069(initial, want) || !equalUUIDs069(reentered, want) {
		t.Fatalf("070 canonical scopes = %v/%v, want %v", initial, reentered, want)
	}
	var physicalLocks int
	if err := holder.QueryRow(t.Context(), `SELECT count(*) FROM pg_catalog.pg_locks
		WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory'
		  AND classid=1229016322::oid AND objsubid=2 AND granted`).Scan(&physicalLocks); err != nil {
		t.Fatal(err)
	}
	if physicalLocks != 1 {
		t.Fatalf("070 colliding physical scope locks = %d, want 1", physicalLocks)
	}

	type waiter struct {
		name string
		done chan error
	}
	waiters := make([]waiter, 0, 2)
	for _, legacy := range []struct {
		name string
		key  string
	}{
		{name: "iam authz", key: "iam-authz:v1:" + second.String()},
		{name: "custom rbac", key: "custom-rbac-tenant:" + second.String()},
	} {
		done := make(chan error, 1)
		go func(key string) {
			done <- pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
				_, err := tx.Exec(context.Background(),
					`SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`, key)
				return err
			})
		}(legacy.key)
		select {
		case err := <-done:
			t.Fatalf("070 %s legacy exclusive did not wait: %v", legacy.name, err)
		case <-time.After(75 * time.Millisecond):
		}
		waiters = append(waiters, waiter{name: legacy.name, done: done})
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, waiter := range waiters {
		if err := <-waiter.done; err != nil {
			t.Fatalf("070 %s legacy waiter: %v", waiter.name, err)
		}
	}

	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	for _, scopeID := range []uuid.UUID{first, second} {
		tx, err := connection.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_begin_authority_mutation_v1(
			'identity.session.revoke',ARRAY[$1::uuid])`, scopeID); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIAMAuthority070NonOwnerCannotBypassRestrictedEntry(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate070(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := "iam070_entry_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	roleSQL := pgx.Identifier{role}.Sanitize()
	schemaSQL := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(t.Context(), "CREATE ROLE "+roleSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "GRANT USAGE ON SCHEMA "+schemaSQL+" TO "+roleSQL+";"+
		"GRANT EXECUTE ON FUNCTION "+schemaSQL+".iam_begin_authority_mutation_v1(text,uuid[]) TO "+roleSQL); err != nil {
		_, _ = pool.Exec(context.Background(), "DROP ROLE "+roleSQL)
		t.Fatal(err)
	}
	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), `RESET ROLE`)
		_, _ = connection.Exec(context.Background(), `DISCARD TEMP`)
		connection.Release()
		_, _ = pool.Exec(context.Background(), "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA "+schemaSQL+" FROM "+roleSQL)
		_, _ = pool.Exec(context.Background(), "REVOKE USAGE ON SCHEMA "+schemaSQL+" FROM "+roleSQL)
		if _, err := pool.Exec(context.Background(), "DROP ROLE "+roleSQL); err != nil {
			t.Errorf("drop 070 entry role: %v", err)
		}
	}()
	if _, err := connection.Exec(t.Context(), "SET ROLE "+roleSQL); err != nil {
		t.Fatal(err)
	}

	first := uuid.MustParse("2e3b59e0-cc21-4548-73fd-ec3b8f1c0744")
	second := uuid.MustParse("e67ca162-05d5-3aad-1b66-0bec1ae748d7")
	tx, err := connection.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SELECT iam_begin_authority_mutation_v1(
		'identity.session.revoke',ARRAY[$1::uuid])`, first); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SELECT pg_catalog.set_config(
		'cdnca.iam_scope_identity_v1',$1,true)`, "v1:"+second.String()); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	_, switchErr := tx.Exec(t.Context(), `SELECT iam_begin_authority_mutation_v1(
		'identity.session.revoke',ARRAY[$1::uuid])`, second)
	assert069PGCode(t, switchErr, "P6902")
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	for _, statement := range []string{
		`SELECT iam_global_lock_exclusive_v1()`,
		`SELECT iam_scope_locks_v1(ARRAY['2e3b59e0-cc21-4548-73fd-ec3b8f1c0744'::uuid])`,
		`INSERT INTO iam_global_lock_protocol_claims(component,caller,authority_table,mutation_kind)
		 VALUES('iam-stage2a','forged','users','update')`,
	} {
		_, err := connection.Exec(t.Context(), statement)
		assert069PGCode(t, err, "42501")
	}
}

func TestIAMAuthority070DownGuardRejectsStage2Facts(t *testing.T) {
	for _, test := range []struct {
		name string
		seed string
	}{
		{
			name: "stage2a claim",
			seed: `INSERT INTO iam_global_lock_protocol_claims(
				component,caller,authority_table,mutation_kind
			) VALUES('iam-stage2a','identity.Store.ChangePassword','users','update')`,
		},
		{
			name: "entry grant",
			seed: `INSERT INTO iam_global_lock_authority_grants(
				role_name,authority_procedure,base_table
			) VALUES(current_user,'iam_begin_authority_mutation_v1(text,uuid[])','users')`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, cleanup := new069Pool(t)
			defer cleanup()
			if err := migrate070(t.Context(), pool, "up"); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), test.seed); err != nil {
				t.Fatal(err)
			}
			err := migrate070(t.Context(), pool, "down")
			assert069PGCode(t, err, "55000")
			assert069Head(t, pool, 70)
		})
	}
}

func migrate070(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	const target int64 = 70
	if direction != "up" && direction != "down" {
		return fmt.Errorf("unsupported 070 migration direction %q", direction)
	}
	if direction == "down" {
		script, err := fs.ReadFile(controlmigrations.FS, "070_iam_global_lock_stage2_authority.down.sql")
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var current int64
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
				return err
			}
			if err := validate070Ledger(ctx, tx.QueryRow, current); err != nil {
				return err
			}
			if current != target {
				return fmt.Errorf("migration head = %d, want %d before down", current, target)
			}
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			command, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=70`)
			if err == nil && command.RowsAffected() != 1 {
				return fmt.Errorf("delete 070 ledger rows = %d, want 1", command.RowsAffected())
			}
			if err != nil {
				return err
			}
			return validate070Ledger(ctx, tx.QueryRow, target-1)
		}); err != nil {
			return fmt.Errorf("migrate 070 down: %w", err)
		}
		return nil
	}

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version bigint PRIMARY KEY,
		migration_id text,
		checksum_sha256 text,
		down_checksum_sha256 text,
		integrity_state text,
		metadata_recorded_at timestamptz,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}
	var current int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	if err := validate070Ledger(ctx, pool.QueryRow, current); err != nil {
		return err
	}

	if current > target {
		return fmt.Errorf("migration head = %d, want at most %d", current, target)
	}
	for version := current + 1; version <= target; version++ {
		upMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(upMatches) != 1 {
			return fmt.Errorf("resolve migration %03d up: matches=%v err=%v", version, upMatches, err)
		}
		downMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.down.sql", version))
		if err != nil || len(downMatches) != 1 {
			return fmt.Errorf("resolve migration %03d down: matches=%v err=%v", version, downMatches, err)
		}
		upScript, err := fs.ReadFile(controlmigrations.FS, upMatches[0])
		if err != nil {
			return err
		}
		downScript, err := fs.ReadFile(controlmigrations.FS, downMatches[0])
		if err != nil {
			return err
		}
		identifier := strings.TrimSuffix(upMatches[0], ".up.sql")
		upChecksum := fmt.Sprintf("%x", sha256.Sum256(upScript))
		downChecksum := fmt.Sprintf("%x", sha256.Sum256(downScript))
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(upScript)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(
				version,migration_id,checksum_sha256,down_checksum_sha256,
				integrity_state,metadata_recorded_at
			) VALUES($1,$2,$3,$4,'verified',now())`,
				version, identifier, upChecksum, downChecksum)
			return err
		}); err != nil {
			return fmt.Errorf("migrate %03d up: %w", version, err)
		}
	}
	return validate070Ledger(ctx, pool.QueryRow, target)
}

func validate070Ledger(
	ctx context.Context,
	queryRow func(context.Context, string, ...any) pgx.Row,
	wantHead int64,
) error {
	var count, minimum, maximum int64
	if err := queryRow(ctx, `SELECT count(*),COALESCE(min(version),0),COALESCE(max(version),0)
		FROM schema_migrations`).Scan(&count, &minimum, &maximum); err != nil {
		return err
	}
	wantMinimum := int64(1)
	if wantHead == 0 {
		wantMinimum = 0
	}
	if count != wantHead || minimum != wantMinimum || maximum != wantHead {
		return fmt.Errorf("migration ledger = count:%d min:%d max:%d, want %d/%d/%d",
			count, minimum, maximum, wantHead, wantMinimum, wantHead)
	}
	for version := int64(1); version <= wantHead; version++ {
		upMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(upMatches) != 1 {
			return fmt.Errorf("resolve migration %03d up: matches=%v err=%v", version, upMatches, err)
		}
		downMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.down.sql", version))
		if err != nil || len(downMatches) != 1 {
			return fmt.Errorf("resolve migration %03d down: matches=%v err=%v", version, downMatches, err)
		}
		upScript, err := fs.ReadFile(controlmigrations.FS, upMatches[0])
		if err != nil {
			return err
		}
		downScript, err := fs.ReadFile(controlmigrations.FS, downMatches[0])
		if err != nil {
			return err
		}
		var identifier, upChecksum, downChecksum, integrity string
		var metadataRecorded bool
		if err := queryRow(ctx, `SELECT migration_id,checksum_sha256,down_checksum_sha256,
			integrity_state,metadata_recorded_at IS NOT NULL
			FROM schema_migrations WHERE version=$1`, version).Scan(
			&identifier, &upChecksum, &downChecksum, &integrity, &metadataRecorded); err != nil {
			return err
		}
		if identifier != strings.TrimSuffix(upMatches[0], ".up.sql") ||
			upChecksum != fmt.Sprintf("%x", sha256.Sum256(upScript)) ||
			downChecksum != fmt.Sprintf("%x", sha256.Sum256(downScript)) ||
			integrity != "verified" || !metadataRecorded {
			return fmt.Errorf("migration %03d ledger metadata mismatch", version)
		}
	}
	return nil
}
