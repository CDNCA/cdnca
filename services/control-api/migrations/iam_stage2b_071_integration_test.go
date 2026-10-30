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

var stage2BOperations071 = []string{
	"identity.account_recovery.request",
	"identity.account_recovery.reset",
	"mfa.enrollment.begin",
	"mfa.enrollment.activate",
	"mfa.step_up.issue",
	"mfa.step_up.consume",
	"mfa.disable",
	"mfa.reset",
	"identity.impersonation.create",
	"identity.impersonation.exchange",
	"identity.impersonation.revoke",
}

func TestIAMStage2B071RestrictedEntryAndRoundTrip(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate071(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 71)

	for _, operation := range stage2BOperations071 {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var locked []uuid.UUID
			return tx.QueryRow(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1($1,$2::uuid[])`,
				operation, []uuid.UUID{uuid.New()}).Scan(&locked)
		})
		if err != nil {
			t.Fatalf("operation %q: %v", operation, err)
		}
	}
	var claims, grants int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM iam_global_lock_protocol_claims),
		(SELECT count(*) FROM iam_global_lock_authority_grants)`).Scan(&claims, &grants); err != nil {
		t.Fatal(err)
	}
	if claims != 0 || grants != 0 {
		t.Fatalf("071 wrote adoption facts: claims=%d grants=%d", claims, grants)
	}

	if err := migrate071(t.Context(), pool, "down"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 70)
	if err := pool.QueryRow(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1(
		'identity.impersonation.revoke',ARRAY[$1::uuid])`, uuid.New()).Scan(new([]uuid.UUID)); err == nil {
		t.Fatal("071 authority entry still exists after down")
	}
	if err := migrate071(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 71)
}

func TestIAMStage2B071RejectsInvalidOperationsAndPublicExecute(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate071(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"", "identity.session.revoke", "identity.stage2b.unknown", strings.Repeat("a", 129)} {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1($1,ARRAY[$2::uuid])`,
				operation, uuid.New())
			return err
		})
		assert071PGCode(t, err, "P7100")
		err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `SELECT iam_assert_stage2b_authority_mutation_v1($1,ARRAY[$2::uuid])`,
				operation, uuid.New())
			return err
		})
		assert071PGCode(t, err, "P7100")
	}
	for _, signature := range []string{
		"iam_validate_stage2b_authority_operation_v1(text)",
		"iam_check_stage2b_authority_operation_state_v1(text,boolean)",
		"iam_begin_stage2b_authority_mutation_v1(text,uuid[])",
		"iam_require_stage2b_global_exclusive_v1()",
		"iam_assert_stage2b_authority_mutation_v1(text,uuid[])",
	} {
		var allowed bool
		if err := pool.QueryRow(t.Context(), `SELECT has_function_privilege('public',$1,'EXECUTE')`,
			signature).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if allowed {
			t.Fatalf("PUBLIC can execute %s", signature)
		}
	}
}

func TestIAMStage2B071BindsOneExactOperationPerTransaction(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate071(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	scopeID := uuid.New()

	for _, statement := range []string{
		`SELECT iam_begin_stage2b_authority_mutation_v1($2,ARRAY[$1::uuid])`,
		`SELECT iam_assert_stage2b_authority_mutation_v1($2,ARRAY[$1::uuid])`,
	} {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1(
				$1,ARRAY[$2::uuid])`, stage2BOperations071[0], scopeID); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), statement, scopeID, stage2BOperations071[1])
			return err
		})
		assert071PGCode(t, err, "P7101")
	}

	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	for _, operation := range []string{stage2BOperations071[0], stage2BOperations071[1]} {
		tx, err := connection.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1(
			$1,ARRAY[$2::uuid])`, operation, scopeID); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_assert_stage2b_authority_mutation_v1(
			$1,ARRAY[$2::uuid])`, operation, scopeID); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIAMStage2B071RejectsTamperedOperationState(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate071(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		scopeID := uuid.New()
		if _, err := tx.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1(
			$1,ARRAY[$2::uuid])`, stage2BOperations071[0], scopeID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `ALTER TABLE pg_temp.iam_stage2b_authority_state_v1
			ADD COLUMN injected boolean`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `SELECT iam_assert_stage2b_authority_mutation_v1(
			$1,ARRAY[$2::uuid])`, stage2BOperations071[0], scopeID)
		return err
	})
	assert071PGCode(t, err, "P7101")
}

func TestIAMStage2B071AssertionRequiresExclusiveExactSet(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate071(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	first := uuid.MustParse("2e3b59e0-cc21-4548-73fd-ec3b8f1c0744")
	second := uuid.MustParse("e67ca162-05d5-3aad-1b66-0bec1ae748d7")
	third := uuid.New()

	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`,
			[]uuid.UUID{first, second}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `SELECT iam_assert_stage2b_authority_mutation_v1($1,$2::uuid[])`,
			stage2BOperations071[0], []uuid.UUID{first, second})
		return err
	})
	assert071PGCode(t, err, "P6901")

	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var locked []uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1($1,$2::uuid[])`,
			stage2BOperations071[0], []uuid.UUID{second, first, first}).Scan(&locked); err != nil {
			return err
		}
		if !equalUUIDs069(locked, []uuid.UUID{first, second}) {
			t.Fatalf("canonical scopes = %v, want [%s %s]", locked, first, second)
		}
		_, err := tx.Exec(t.Context(), `SELECT iam_assert_stage2b_authority_mutation_v1($1,$2::uuid[])`,
			stage2BOperations071[0], []uuid.UUID{second, first, first})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	for _, required := range [][]uuid.UUID{{first}, {first, second, third}} {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1($1,$2::uuid[])`,
				stage2BOperations071[0], []uuid.UUID{first, second}); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `SELECT iam_assert_stage2b_authority_mutation_v1($1,$2::uuid[])`,
				stage2BOperations071[0], required)
			return err
		})
		assert071PGCode(t, err, "P6902")
	}
}

func TestIAMStage2B071RestrictedCallerCannotReachInternalAuthority(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate071(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := "iam071_entry_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	roleSQL := pgx.Identifier{role}.Sanitize()
	schemaSQL := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(t.Context(), "CREATE ROLE "+roleSQL); err != nil {
		t.Fatal(err)
	}
	grantSQL := "GRANT USAGE ON SCHEMA " + schemaSQL + " TO " + roleSQL + ";" +
		"GRANT EXECUTE ON FUNCTION " + schemaSQL + ".iam_begin_stage2b_authority_mutation_v1(text,uuid[]) TO " + roleSQL + ";" +
		"GRANT EXECUTE ON FUNCTION " + schemaSQL + ".iam_assert_stage2b_authority_mutation_v1(text,uuid[]) TO " + roleSQL
	if _, err := pool.Exec(t.Context(), grantSQL); err != nil {
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
			t.Errorf("drop 071 entry role: %v", err)
		}
	}()
	if _, err := connection.Exec(t.Context(), "SET ROLE "+roleSQL); err != nil {
		t.Fatal(err)
	}

	scopeID := uuid.New()
	if _, err := connection.Exec(t.Context(), `CREATE TEMP TABLE pg_temp.iam_stage2b_authority_state_v1 (
		singleton boolean PRIMARY KEY CHECK (singleton), operation text NOT NULL
	) ON COMMIT DELETE ROWS`); err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), connection, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1($1,ARRAY[$2::uuid])`,
			stage2BOperations071[0], scopeID)
		return err
	})
	assert071PGCode(t, err, "P7101")
	if _, err := connection.Exec(t.Context(), `DISCARD TEMP`); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), connection, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1($1,ARRAY[$2::uuid])`,
			stage2BOperations071[0], scopeID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `SELECT iam_assert_stage2b_authority_mutation_v1($1,ARRAY[$2::uuid])`,
			stage2BOperations071[0], scopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	for _, statement := range []string{
		`SELECT iam_validate_stage2b_authority_operation_v1('mfa.reset')`,
		`SELECT iam_check_stage2b_authority_operation_state_v1('mfa.reset',true)`,
		`SELECT iam_require_stage2b_global_exclusive_v1()`,
		`SELECT iam_global_lock_exclusive_v1()`,
		`SELECT iam_scope_locks_v1(ARRAY['11111111-1111-1111-1111-111111111111'::uuid])`,
		`SELECT iam_assert_scope_locks_v1(ARRAY['11111111-1111-1111-1111-111111111111'::uuid])`,
		`INSERT INTO iam_global_lock_protocol_claims(component,caller,authority_table,mutation_kind)
		 VALUES('iam-stage2b','reviewer','users','update')`,
		`INSERT INTO iam_global_lock_authority_grants(role_name,authority_procedure,base_table)
			 VALUES(current_user,'iam_begin_stage2b_authority_mutation_v1(text,uuid[])','users')`,
		`SELECT * FROM pg_temp.iam_stage2b_authority_state_v1`,
		`INSERT INTO pg_temp.iam_stage2b_authority_state_v1(singleton,operation)
			 VALUES(true,'mfa.reset')`,
		`ALTER TABLE pg_temp.iam_stage2b_authority_state_v1 ADD COLUMN injected boolean`,
		`DROP TABLE pg_temp.iam_stage2b_authority_state_v1`,
	} {
		err := pgx.BeginFunc(t.Context(), connection, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), statement)
			return err
		})
		assert071PGCode(t, err, "42501")
	}
}

func TestIAMStage2B071BoundHelpersIgnoreHostileSearchPath(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate071(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), `DISCARD TEMP`)
		connection.Release()
	}()
	for _, statement := range []string{
		`CREATE FUNCTION pg_temp.iam_validate_stage2b_authority_operation_v1(text) RETURNS void
			 LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION USING ERRCODE=''P0001''; END'`,
		`CREATE FUNCTION pg_temp.iam_check_stage2b_authority_operation_state_v1(text,boolean) RETURNS void
			 LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION USING ERRCODE=''P0001''; END'`,
		`CREATE FUNCTION pg_temp.iam_global_lock_exclusive_v1() RETURNS void
		 LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION USING ERRCODE=''P0001''; END'`,
		`CREATE FUNCTION pg_temp.iam_scope_locks_v1(uuid[]) RETURNS uuid[]
		 LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION USING ERRCODE=''P0001''; END'`,
		`CREATE FUNCTION pg_temp.iam_require_stage2b_global_exclusive_v1() RETURNS void
		 LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION USING ERRCODE=''P0001''; END'`,
		`CREATE FUNCTION pg_temp.iam_assert_scope_locks_v1(uuid[]) RETURNS void
		 LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION USING ERRCODE=''P0001''; END'`,
	} {
		if _, err := connection.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	scopeID := uuid.New()
	schemaSQL := pgx.Identifier{schema}.Sanitize()
	beginSQL := "SELECT " + schemaSQL +
		".iam_begin_stage2b_authority_mutation_v1($1,ARRAY[$2::uuid])"
	assertSQL := "SELECT " + schemaSQL +
		".iam_assert_stage2b_authority_mutation_v1($1,ARRAY[$2::uuid])"
	if err := pgx.BeginFunc(t.Context(), connection, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL search_path=pg_temp,pg_catalog`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), beginSQL, stage2BOperations071[0], scopeID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), assertSQL, stage2BOperations071[0], scopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIAMStage2B071CollisionExactSetAndRollback(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate071(t.Context(), pool, "up"); err != nil {
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
	if err := holder.QueryRow(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1($1,$2::uuid[])`,
		stage2BOperations071[0], []uuid.UUID{first, second}).Scan(&initial); err != nil {
		t.Fatal(err)
	}
	if err := holder.QueryRow(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1($1,$2::uuid[])`,
		stage2BOperations071[0], []uuid.UUID{second, first, first}).Scan(&reentered); err != nil {
		t.Fatal(err)
	}
	if want := []uuid.UUID{first, second}; !equalUUIDs069(initial, want) || !equalUUIDs069(reentered, want) {
		t.Fatalf("canonical scopes = %v/%v, want %v", initial, reentered, want)
	}
	done := make(chan error, 1)
	go func() {
		done <- pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(),
				`SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`,
				"iam-authz:v1:"+second.String())
			return err
		})
	}()
	select {
	case err := <-done:
		t.Fatalf("legacy exclusive did not wait: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	switcher, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer switcher.Rollback(context.Background())
	if _, err := switcher.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1(
		$1,ARRAY[$2::uuid])`, stage2BOperations071[0], first); err != nil {
		t.Fatal(err)
	}
	_, switchErr := switcher.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1(
		$1,ARRAY[$2::uuid])`, stage2BOperations071[0], second)
	assert071PGCode(t, switchErr, "P6902")
	if err := switcher.Rollback(t.Context()); err != nil {
		t.Fatal(err)
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
		if _, err := tx.Exec(t.Context(), `SELECT iam_begin_stage2b_authority_mutation_v1(
			$1,ARRAY[$2::uuid])`, stage2BOperations071[1], scopeID); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_assert_stage2b_authority_mutation_v1(
			$1,ARRAY[$2::uuid])`, stage2BOperations071[1], scopeID); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIAMStage2B071DownGuardRejectsFutureAdoptionFacts(t *testing.T) {
	for _, test := range []struct {
		name string
		seed string
	}{
		{
			name: "stage2b claim",
			seed: `INSERT INTO iam_global_lock_protocol_claims(
				component,caller,authority_table,mutation_kind
			) VALUES('iam-stage2b','mfa.Service.Reset','mfa_credential_events','insert')`,
		},
		{
			name: "stage2b entry grant",
			seed: `INSERT INTO iam_global_lock_authority_grants(
				role_name,authority_procedure,base_table
			) VALUES(current_user,'iam_begin_stage2b_authority_mutation_v1(text,uuid[])','mfa_credential_events')`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, cleanup := new069Pool(t)
			defer cleanup()
			if err := migrate071(t.Context(), pool, "up"); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), test.seed); err != nil {
				t.Fatal(err)
			}
			err := migrate071(t.Context(), pool, "down")
			assert071PGCode(t, err, "55000")
			assert069Head(t, pool, 71)
		})
	}
}

func TestIAMStage2B071RejectedDownRollsBackFreshSchema(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()

	type schemaState struct {
		objects       int
		tables        int
		businessFacts int
		ledgerExists  bool
		ledgerRows    int
	}
	snapshot := func() schemaState {
		t.Helper()
		var state schemaState
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM pg_catalog.pg_class c
			 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
			 WHERE n.nspname=current_schema()),
			(SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname=current_schema()),
			to_regclass('schema_migrations') IS NOT NULL`).Scan(
			&state.objects, &state.tables, &state.ledgerExists); err != nil {
			t.Fatal(err)
		}
		if state.ledgerExists {
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM schema_migrations`).Scan(&state.ledgerRows); err != nil {
				t.Fatal(err)
			}
		}
		for _, table := range []string{"iam_global_lock_protocol_claims", "iam_global_lock_authority_grants"} {
			var exists bool
			if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if exists {
				var facts int
				if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&facts); err != nil {
					t.Fatal(err)
				}
				state.businessFacts += facts
			}
		}
		return state
	}

	before := snapshot()
	if err := migrate071(t.Context(), pool, "down"); err == nil {
		t.Fatal("071 down on a fresh schema succeeded")
	}
	if after := snapshot(); after != before {
		t.Fatalf("rejected 071 down changed schema state: before=%+v after=%+v", before, after)
	}
}

func assert071PGCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func migrate071(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	const target int64 = 71
	if direction != "up" && direction != "down" {
		return fmt.Errorf("unsupported 071 migration direction %q", direction)
	}
	if direction == "down" {
		script, err := fs.ReadFile(controlmigrations.FS, "071_iam_stage2b_package_adoption.down.sql")
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
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
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
				return err
			}
			if err := validate071Ledger(ctx, tx.QueryRow, current); err != nil {
				return err
			}
			if current != target {
				return fmt.Errorf("migration head = %d, want %d before down", current, target)
			}
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			command, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=71`)
			if err == nil && command.RowsAffected() != 1 {
				return fmt.Errorf("delete 071 ledger rows = %d, want 1", command.RowsAffected())
			}
			if err != nil {
				return err
			}
			return validate071Ledger(ctx, tx.QueryRow, target-1)
		}); err != nil {
			return fmt.Errorf("migrate 071 down: %w", err)
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
	if err := validate071Ledger(ctx, pool.QueryRow, current); err != nil {
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
	return validate071Ledger(ctx, pool.QueryRow, target)
}

func validate071Ledger(
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
