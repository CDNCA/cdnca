package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIAMGlobalLock069MigrationRoundTripAndHelperSecurity(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()

	migrate069(t, pool, "up")
	assert069Head(t, pool, 69)
	assert069HelperSecurity(t, pool)

	migrate069(t, pool, "down")
	assert069Head(t, pool, 68)
	assert069Installed(t, pool, false)

	migrate069(t, pool, "up")
	assert069Head(t, pool, 69)
	assert069Installed(t, pool, true)
}

func TestIAMGlobalLock069HelpersValidateOrderAndCanonicalScopes(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	migrate069(t, pool, "up")

	assert069TxCode(t, pool, "P6901", func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, uuid.New())
		return err
	})
	assert069TxCode(t, pool, "P6900", func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT iam_scope_locks_v1(NULL::uuid[])`)
		return err
	})
	assert069TxCode(t, pool, "P6903", func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT iam_global_lock_exclusive_v1()`)
		return err
	})
	if _, err := pool.Exec(t.Context(), `CREATE TABLE iam069_lock_order_probe(id integer PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	assert069TxCode(t, pool, "P6902", func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO iam069_lock_order_probe(id) VALUES(1)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`)
		return err
	})
	assert069TxCode(t, pool, "P6902", func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(90069001)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`)
		return err
	})

	first, second := uuid.New(), uuid.New()
	if strings.Compare(first.String(), second.String()) > 0 {
		first, second = second, first
	}
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		var got []uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`,
			[]uuid.UUID{second, first, second}).Scan(&got); err != nil {
			return err
		}
		want := []uuid.UUID{first, second}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			return fmt.Errorf("canonical scopes = %v, want %v", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	tooMany := make([]uuid.UUID, 65)
	for index := range tooMany {
		tooMany[index] = uuid.New()
	}
	assert069TxCode(t, pool, "P6900", func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT iam_scope_locks_v1($1::uuid[])`, tooMany)
		return err
	})

	atLimit := append([]uuid.UUID(nil), tooMany[:64]...)
	reversed := append([]uuid.UUID(nil), atLimit...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		var initial, reentered []uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`, atLimit).Scan(&initial); err != nil {
			return err
		}
		if err := tx.QueryRow(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`, reversed).Scan(&reentered); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_assert_scope_locks_v1($1::uuid[])`, reversed); err != nil {
			return err
		}
		if len(initial) != 64 || !equalUUIDs069(initial, reentered) {
			return fmt.Errorf("64-scope canonical reentry = %d/%d", len(initial), len(reentered))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIAMGlobalLock069LoginNonOwnerCannotPreclaimGlobalAuthority(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	migrate069(t, pool, "up")

	var schema string
	if err := pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := "iam069_login_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := "iam069_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	roleSQL := pgx.Identifier{role}.Sanitize()
	schemaSQL := pgx.Identifier{schema}.Sanitize()
	var createRoleSQL string
	if err := pool.QueryRow(t.Context(),
		`SELECT pg_catalog.format('CREATE ROLE %I LOGIN PASSWORD %L',$1::text,$2::text)`,
		role, password).Scan(&createRoleSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), createRoleSQL); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA "+schemaSQL+" FROM "+roleSQL)
		_, _ = pool.Exec(context.Background(), "REVOKE USAGE ON SCHEMA "+schemaSQL+" FROM "+roleSQL)
		if _, err := pool.Exec(context.Background(), "DROP ROLE "+roleSQL); err != nil {
			t.Errorf("drop login role: %v", err)
		}
	}()
	if _, err := pool.Exec(t.Context(),
		"GRANT USAGE ON SCHEMA "+schemaSQL+" TO "+roleSQL+";"+
			"GRANT EXECUTE ON FUNCTION "+schemaSQL+".iam_global_lock_shared_v1() TO "+roleSQL); err != nil {
		t.Fatal(err)
	}

	config, err := pgxpool.ParseConfig(strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = role
	config.ConnConfig.Password = password
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 1
	callerPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer callerPool.Close()
	if err := callerPool.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}

	var backendPID int
	if err := callerPool.QueryRow(t.Context(), `SELECT pg_catalog.pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	if _, err := callerPool.Exec(t.Context(), `SELECT pg_catalog.pg_advisory_lock(999999,77)`); err != nil {
		t.Fatal(err)
	}
	if _, err := callerPool.Exec(t.Context(), `SELECT pg_catalog.pg_advisory_lock(1229016321,1)`); err != nil {
		t.Fatal(err)
	}
	defer callerPool.Exec(context.Background(), `SELECT pg_catalog.pg_advisory_unlock_all()`)

	for _, finish := range []string{"rollback", "commit"} {
		t.Run(finish, func(t *testing.T) {
			boundary, err := callerPool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if finish == "commit" {
				err = boundary.Commit(t.Context())
			} else {
				err = boundary.Rollback(t.Context())
			}
			if err != nil {
				t.Fatal(err)
			}

			var reusedPID int
			err = pgx.BeginFunc(t.Context(), callerPool, func(tx pgx.Tx) error {
				if err := tx.QueryRow(t.Context(), `SELECT pg_catalog.pg_backend_pid()`).Scan(&reusedPID); err != nil {
					return err
				}
				_, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`)
				return err
			})
			if reusedPID != backendPID {
				t.Fatalf("pooled backend = %d, want preclaim backend %d", reusedPID, backendPID)
			}
			assert069PGCode(t, err, "P6902")
			if !strings.Contains(err.Error(), "iam_global_lock_not_first_effective_lock") {
				t.Fatalf("global preclaim reason = %v", err)
			}
		})
	}
}

func TestIAMGlobalLock069ScopeHashCollisionPreservesExactIdentityAndLegacyLocks(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	migrate069(t, pool, "up")

	first := uuid.MustParse("2e3b59e0-cc21-4548-73fd-ec3b8f1c0744")
	second := uuid.MustParse("e67ca162-05d5-3aad-1b66-0bec1ae748d7")
	const collisionKey = 50453019
	var firstKey, secondKey int
	if err := pool.QueryRow(t.Context(), `SELECT
		pg_catalog.hashtext('iam-scope:v1:' || $1::uuid::text) & 2147483647,
		pg_catalog.hashtext('iam-scope:v1:' || $2::uuid::text) & 2147483647`,
		first, second).Scan(&firstKey, &secondKey); err != nil {
		t.Fatal(err)
	}
	if firstKey != collisionKey || secondKey != collisionKey {
		t.Fatalf("collision keys = %d/%d, want %d/%d", firstKey, secondKey, collisionKey, collisionKey)
	}

	for _, test := range []struct {
		name   string
		first  []uuid.UUID
		second []uuid.UUID
	}{
		{name: "same set reentry", first: []uuid.UUID{first, second}, second: []uuid.UUID{first, second}},
		{name: "order and duplicates are equivalent", first: []uuid.UUID{first, second}, second: []uuid.UUID{second, first, first}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
				if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
					return err
				}
				var initial, reentered []uuid.UUID
				if err := tx.QueryRow(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`, test.first).Scan(&initial); err != nil {
					return err
				}
				if err := tx.QueryRow(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`, test.second).Scan(&reentered); err != nil {
					return err
				}
				if _, err := tx.Exec(t.Context(), `SELECT iam_assert_scope_locks_v1($1::uuid[])`, test.second); err != nil {
					return err
				}
				want := []uuid.UUID{first, second}
				if !equalUUIDs069(initial, want) || !equalUUIDs069(reentered, want) {
					return fmt.Errorf("collision canonical scopes = %v/%v, want %v", initial, reentered, want)
				}
				var physicalLocks int
				if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM pg_catalog.pg_locks
					WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory'
					  AND classid=1229016322::oid AND objsubid=2 AND granted`).Scan(&physicalLocks); err != nil {
					return err
				}
				if physicalLocks != 1 {
					return fmt.Errorf("colliding physical scope locks = %d, want 1", physicalLocks)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("different exact set is rejected", func(t *testing.T) {
		assert069TxCode(t, pool, "P6902", func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, first); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, second)
			return err
		})
	})

	t.Run("assert rejects different exact set", func(t *testing.T) {
		assert069TxCode(t, pool, "P6902", func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, first); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `SELECT iam_assert_scope_locks_v1(ARRAY[$1::uuid])`, second)
			return err
		})
	})

	for _, legacy := range []struct {
		name string
		key  string
	}{
		{name: "iam authz", key: "iam-authz:v1:" + second.String()},
		{name: "custom rbac", key: "custom-rbac-tenant:" + second.String()},
	} {
		t.Run("legacy exclusive waits for "+legacy.name, func(t *testing.T) {
			holder, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(context.Background())
			if _, err := holder.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
				t.Fatal(err)
			}
			if _, err := holder.Exec(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`,
				[]uuid.UUID{first, second}); err != nil {
				t.Fatal(err)
			}
			var holderPID int
			if err := holder.QueryRow(t.Context(), `SELECT pg_catalog.pg_backend_pid()`).Scan(&holderPID); err != nil {
				t.Fatal(err)
			}
			waiterPID, done := start069LockWaiter(t, pool,
				`SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))`, legacy.key)
			waitForBlockedBy069(t, pool, waiterPID, holderPID)
			if err := holder.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("physical collision only over serializes", func(t *testing.T) {
		holder, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Rollback(context.Background())
		if _, err := holder.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			t.Fatal(err)
		}
		if _, err := holder.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, first); err != nil {
			t.Fatal(err)
		}
		var holderPID int
		if err := holder.QueryRow(t.Context(), `SELECT pg_catalog.pg_backend_pid()`).Scan(&holderPID); err != nil {
			t.Fatal(err)
		}
		waiterPID, done := start069LockWaiter(t, pool,
			`SELECT pg_catalog.pg_advisory_xact_lock(1229016322, $1)`, collisionKey)
		waitForBlockedBy069(t, pool, waiterPID, holderPID)
		if err := holder.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("rollback clears transaction identity", func(t *testing.T) {
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
			if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
				_ = tx.Rollback(context.Background())
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, scopeID); err != nil {
				_ = tx.Rollback(context.Background())
				t.Fatal(err)
			}
			if err := tx.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestIAMGlobalLock069NonOwnerCannotForgeOrTamperScopeIdentityState(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	migrate069(t, pool, "up")

	var schema string
	if err := pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := "iam069_helper_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := "iam069_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	roleSQL := pgx.Identifier{role}.Sanitize()
	schemaSQL := pgx.Identifier{schema}.Sanitize()
	var createRoleSQL string
	if err := pool.QueryRow(t.Context(),
		`SELECT pg_catalog.format('CREATE ROLE %I LOGIN PASSWORD %L',$1::text,$2::text)`,
		role, password).Scan(&createRoleSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), createRoleSQL); err != nil {
		t.Fatal(err)
	}
	grantSQL := "GRANT USAGE ON SCHEMA " + schemaSQL + " TO " + roleSQL + ";" +
		"GRANT EXECUTE ON FUNCTION " + schemaSQL + ".iam_global_lock_shared_v1() TO " + roleSQL + ";" +
		"GRANT EXECUTE ON FUNCTION " + schemaSQL + ".iam_scope_locks_v1(uuid[]) TO " + roleSQL + ";" +
		"GRANT EXECUTE ON FUNCTION " + schemaSQL + ".iam_assert_scope_locks_v1(uuid[]) TO " + roleSQL
	if _, err := pool.Exec(t.Context(), grantSQL); err != nil {
		_, _ = pool.Exec(context.Background(), "DROP ROLE "+roleSQL)
		t.Fatal(err)
	}

	config, err := pgxpool.ParseConfig(strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = role
	config.ConnConfig.Password = password
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 1
	callerPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		callerPool.Close()
		_, _ = pool.Exec(context.Background(), "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA "+schemaSQL+" FROM "+roleSQL)
		_, _ = pool.Exec(context.Background(), "REVOKE USAGE ON SCHEMA "+schemaSQL+" FROM "+roleSQL)
		if _, err := pool.Exec(context.Background(), "DROP ROLE "+roleSQL); err != nil {
			t.Errorf("drop helper role: %v", err)
		}
	}()
	if err := callerPool.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}

	connection, err := callerPool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), `DISCARD TEMP`)
		connection.Release()
	}()

	first := uuid.MustParse("2e3b59e0-cc21-4548-73fd-ec3b8f1c0744")
	second := uuid.MustParse("e67ca162-05d5-3aad-1b66-0bec1ae748d7")
	canonicalSecond := "v1:" + second.String()

	if _, err := connection.Exec(t.Context(), `CREATE TEMP TABLE iam_scope_lock_state_v1(
		canonical_identity text NOT NULL
	) ON COMMIT PRESERVE ROWS`); err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), connection, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, first)
		return err
	})
	assert069PGCode(t, err, "P6902")
	if _, err := connection.Exec(t.Context(), `DROP TABLE pg_temp.iam_scope_lock_state_v1`); err != nil {
		t.Fatal(err)
	}

	for _, scopes := range [][]uuid.UUID{{first}, {first, second}} {
		tx, err := connection.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`, scopes); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		nested, err := tx.Begin(t.Context())
		if err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		if _, err := nested.Exec(t.Context(), `SELECT pg_catalog.set_config(
			'cdnca.iam_scope_identity_v1',$1,true)`, canonicalSecond); err != nil {
			_ = nested.Rollback(context.Background())
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		_, assertErr := nested.Exec(t.Context(), `SELECT iam_assert_scope_locks_v1(ARRAY[$1::uuid])`, second)
		if assertErr == nil {
			_ = nested.Rollback(context.Background())
			_ = tx.Rollback(context.Background())
			t.Fatalf("non-owner forged scope identity after acquiring %v", scopes)
		}
		assert069PGCode(t, assertErr, "P6902")
		if err := nested.Rollback(t.Context()); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	for _, operation := range []struct {
		name      string
		statement string
	}{
		{name: "reacquire", statement: `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`},
		{name: "assert", statement: `SELECT iam_assert_scope_locks_v1(ARRAY[$1::uuid])`},
	} {
		t.Run("discard-temp/"+operation.name, func(t *testing.T) {
			tx, err := connection.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, first); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `DISCARD TEMP`); err != nil {
				t.Fatalf("DISCARD TEMP: %v", err)
			}
			var stateMissing bool
			if err := tx.QueryRow(t.Context(),
				`SELECT pg_catalog.to_regclass('pg_temp.iam_scope_lock_state_v1') IS NULL`).Scan(
				&stateMissing); err != nil {
				t.Fatal(err)
			}
			if !stateMissing {
				t.Fatal("DISCARD TEMP did not remove protected scope state")
			}
			var sentinelCount int
			if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM pg_catalog.pg_locks
				WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory'
				  AND classid=1229016321::oid AND objid=2::oid AND objsubid=2 AND granted`).Scan(
				&sentinelCount); err != nil {
				t.Fatal(err)
			}
			if sentinelCount != 1 {
				t.Fatalf("scope state sentinel count = %d, want 1", sentinelCount)
			}
			_, operationErr := tx.Exec(t.Context(), operation.statement, second)
			assert069PGCode(t, operationErr, "P6902")
		})
	}

	for _, preclaim := range []struct {
		name      string
		statement string
	}{
		{name: "shared", statement: `SELECT pg_catalog.pg_advisory_xact_lock_shared(1229016321,2)`},
		{name: "exclusive", statement: `SELECT pg_catalog.pg_advisory_xact_lock(1229016321,2)`},
	} {
		t.Run("preclaimed-sentinel/"+preclaim.name, func(t *testing.T) {
			tx, err := connection.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), preclaim.statement); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, first)
			assert069PGCode(t, err, "P6902")
		})
	}

	t.Run("assert-requires-sentinel", func(t *testing.T) {
		tx, err := connection.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `SELECT iam_assert_scope_locks_v1(ARRAY[$1::uuid])`, first)
		assert069PGCode(t, err, "P6901")
		if !strings.Contains(err.Error(), "iam_scope_lock_sentinel_required") {
			t.Fatalf("assert without sentinel reason = %v", err)
		}
	})

	t.Run("discard-temp-savepoint-rollback", func(t *testing.T) {
		tx, err := connection.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, first); err != nil {
			t.Fatal(err)
		}
		nested, err := tx.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nested.Exec(t.Context(), `DISCARD TEMP`); err != nil {
			_ = nested.Rollback(context.Background())
			t.Fatal(err)
		}
		_, switchErr := nested.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, second)
		assert069PGCode(t, switchErr, "P6902")
		if err := nested.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_assert_scope_locks_v1(ARRAY[$1::uuid])`, first); err != nil {
			t.Fatalf("scope state was not restored by savepoint rollback: %v", err)
		}
	})

	t.Run("first-acquire-savepoint-rollback", func(t *testing.T) {
		tx, err := connection.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			t.Fatal(err)
		}
		nested, err := tx.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nested.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, first); err != nil {
			_ = nested.Rollback(context.Background())
			t.Fatal(err)
		}
		if err := nested.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		var sentinelCount int
		if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM pg_catalog.pg_locks
			WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory'
			  AND classid=1229016321::oid AND objid=2::oid AND objsubid=2 AND granted`).Scan(
			&sentinelCount); err != nil {
			t.Fatal(err)
		}
		if sentinelCount != 0 {
			t.Fatalf("savepoint rollback left %d scope sentinels", sentinelCount)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, second); err != nil {
			t.Fatalf("scope retry after savepoint rollback: %v", err)
		}
	})

	holder, err := connection.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if _, err := holder.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`,
		[]uuid.UUID{first, second}); err != nil {
		t.Fatal(err)
	}

	var stateOwner, tempSchema string
	var stateIsTemp bool
	if err := holder.QueryRow(t.Context(), `SELECT owner.rolname,relation.relpersistence='t',namespace.nspname
		FROM pg_catalog.pg_class relation
		JOIN pg_catalog.pg_roles owner ON owner.oid=relation.relowner
		JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
		WHERE relation.oid=pg_catalog.to_regclass('pg_temp.iam_scope_lock_state_v1')`).Scan(
		&stateOwner, &stateIsTemp, &tempSchema); err != nil {
		t.Fatal(err)
	}
	if stateOwner == role || !stateIsTemp {
		t.Fatalf("scope state owner/temp = %s/%t, want definer-owned temp relation", stateOwner, stateIsTemp)
	}

	for _, operation := range []struct {
		name      string
		statement string
		code      string
	}{
		{name: "select", statement: `SELECT * FROM pg_temp.iam_scope_lock_state_v1`, code: "42501"},
		{name: "insert", statement: `INSERT INTO pg_temp.iam_scope_lock_state_v1 VALUES(true,'forged')`, code: "42501"},
		{name: "update", statement: `UPDATE pg_temp.iam_scope_lock_state_v1 SET canonical_identity='forged'`, code: "42501"},
		{name: "delete", statement: `DELETE FROM pg_temp.iam_scope_lock_state_v1`, code: "42501"},
		{name: "truncate", statement: `TRUNCATE pg_temp.iam_scope_lock_state_v1`, code: "42501"},
		{name: "grant", statement: "GRANT SELECT ON pg_temp.iam_scope_lock_state_v1 TO " + roleSQL, code: "42501"},
		{name: "alter", statement: `ALTER TABLE pg_temp.iam_scope_lock_state_v1 ADD COLUMN forged text`, code: "42501"},
		{name: "drop", statement: `DROP TABLE pg_temp.iam_scope_lock_state_v1`, code: "42501"},
		{name: "replace", statement: `CREATE TEMP TABLE iam_scope_lock_state_v1(forged text)`, code: "42P07"},
		{name: "drop namespace", statement: "DROP SCHEMA " + pgx.Identifier{tempSchema}.Sanitize() + " CASCADE", code: "42501"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			nested, err := holder.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, operationErr := nested.Exec(t.Context(), operation.statement)
			if operationErr == nil {
				_ = nested.Rollback(context.Background())
				t.Fatalf("non-owner tamper unexpectedly succeeded: %s", operation.statement)
			}
			assert069PGCode(t, operationErr, operation.code)
			if err := nested.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}

	type legacyWaiter struct {
		name string
		done chan error
	}
	var holderPID int
	if err := holder.QueryRow(t.Context(), `SELECT pg_catalog.pg_backend_pid()`).Scan(&holderPID); err != nil {
		t.Fatal(err)
	}
	waiters := make([]legacyWaiter, 0, 2)
	for _, legacy := range []struct {
		name string
		key  string
	}{
		{name: "iam authz", key: "iam-authz:v1:" + second.String()},
		{name: "custom rbac", key: "custom-rbac-tenant:" + second.String()},
	} {
		waiterPID, done := start069LockWaiter(t, pool,
			`SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`, legacy.key)
		waitForBlockedBy069(t, pool, waiterPID, holderPID)
		waiters = append(waiters, legacyWaiter{name: legacy.name, done: done})
	}
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, waiter := range waiters {
		if err := <-waiter.done; err != nil {
			t.Fatalf("%s legacy waiter: %v", waiter.name, err)
		}
	}

	for _, finish := range []string{"commit", "rollback"} {
		for _, scopeID := range []uuid.UUID{first, second} {
			tx, err := connection.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
				_ = tx.Rollback(context.Background())
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, scopeID); err != nil {
				_ = tx.Rollback(context.Background())
				t.Fatalf("%s session reuse for %s: %v", finish, scopeID, err)
			}
			if finish == "commit" {
				err = tx.Commit(t.Context())
			} else {
				err = tx.Rollback(t.Context())
			}
			if err != nil {
				t.Fatal(err)
			}
			var sentinelCount int
			if err := connection.QueryRow(t.Context(), `SELECT count(*) FROM pg_catalog.pg_locks
				WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory'
				  AND classid=1229016321::oid AND objid=2::oid AND objsubid=2 AND granted`).Scan(
				&sentinelCount); err != nil {
				t.Fatal(err)
			}
			if sentinelCount != 0 {
				t.Fatalf("%s left %d scope sentinels", finish, sentinelCount)
			}
		}
	}
}

func TestIAMGlobalLock069DownFailsClosedAfterStage2Facts(t *testing.T) {
	for _, test := range []struct {
		name string
		seed string
	}{
		{
			name: "adoption claim",
			seed: `INSERT INTO iam_global_lock_protocol_claims(
				component,caller,authority_table,mutation_kind
			) VALUES('identity','identity.Store.DisableUser','users','update')`,
		},
		{
			name: "authority grant",
			seed: `INSERT INTO iam_global_lock_authority_grants(
				role_name,authority_procedure,base_table
			) VALUES(current_user,'identity.disable_user_v1(uuid)','users')`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, cleanup := new069Pool(t)
			defer cleanup()
			migrate069(t, pool, "up")
			if _, err := pool.Exec(t.Context(), test.seed); err != nil {
				t.Fatal(err)
			}
			err := database.Migrate(t.Context(), pool, "down")
			assert069PGCode(t, err, "55000")
			assert069Head(t, pool, 69)
			assert069Installed(t, pool, true)
		})
	}
}

func TestIAMGlobalLock069ProtocolFactsACLAndTamperProtection(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	migrate069(t, pool, "up")

	rows, err := pool.Query(t.Context(), `
		SELECT relation.relname,
		       owner.rolname = current_user,
		       NOT EXISTS (
		           SELECT 1 FROM aclexplode(relation.relacl) acl WHERE acl.grantee=0
		       ),
		       has_table_privilege(current_user, relation.oid, 'SELECT'),
		       has_table_privilege(current_user, relation.oid, 'INSERT')
		FROM pg_class relation
		JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
		JOIN pg_roles owner ON owner.oid=relation.relowner
		WHERE namespace.nspname=current_schema()
		  AND relation.relname = ANY(ARRAY[
		      'iam_global_lock_protocol_claims',
		      'iam_global_lock_authority_grants'
		  ])
		ORDER BY relation.relname`)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		var name string
		var owned, publicRevoked, canSelect, canInsert bool
		if err := rows.Scan(&name, &owned, &publicRevoked, &canSelect, &canInsert); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if !owned || !publicRevoked || !canSelect || !canInsert {
			rows.Close()
			t.Fatalf("fact table %s ACL = owner:%t public-revoked:%t select:%t insert:%t",
				name, owned, publicRevoked, canSelect, canInsert)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if count != 2 {
		t.Fatalf("secured fact table count = %d, want 2", count)
	}

	if _, err := pool.Exec(t.Context(), `INSERT INTO iam_global_lock_protocol_claims(
		component,caller,authority_table,mutation_kind
	) VALUES('identity','identity.Store.DisableUser','users','update')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO iam_global_lock_authority_grants(
		role_name,authority_procedure,base_table
	) VALUES(current_user,'identity.disable_user_v1(uuid)','users')`); err != nil {
		t.Fatal(err)
	}

	for _, operation := range []struct {
		name      string
		statement string
	}{
		{name: "claim update", statement: `UPDATE iam_global_lock_protocol_claims SET caller=caller`},
		{name: "claim delete", statement: `DELETE FROM iam_global_lock_protocol_claims`},
		{name: "claim truncate", statement: `TRUNCATE iam_global_lock_protocol_claims`},
		{name: "grant update", statement: `UPDATE iam_global_lock_authority_grants SET base_table=base_table`},
		{name: "grant delete", statement: `DELETE FROM iam_global_lock_authority_grants`},
		{name: "grant truncate", statement: `TRUNCATE iam_global_lock_authority_grants`},
	} {
		t.Run(operation.name, func(t *testing.T) {
			_, err := pool.Exec(t.Context(), operation.statement)
			assert069PGCode(t, err, "55000")
		})
	}

	var claims, grants int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM iam_global_lock_protocol_claims),
		(SELECT count(*) FROM iam_global_lock_authority_grants)`).Scan(&claims, &grants); err != nil {
		t.Fatal(err)
	}
	if claims != 1 || grants != 1 {
		t.Fatalf("protocol facts after tamper attempts = claims:%d grants:%d, want 1/1", claims, grants)
	}
}

func assert069HelperSecurity(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		SELECT procedure.proname,
		       procedure.prosecdef,
		       owner.rolname = current_user,
		       procedure.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'],
		       NOT EXISTS (
		           SELECT 1 FROM aclexplode(procedure.proacl) acl WHERE acl.grantee=0
		       ),
		       has_function_privilege(current_user, procedure.oid, 'EXECUTE')
		FROM pg_proc procedure
		JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace
		JOIN pg_roles owner ON owner.oid=procedure.proowner
		WHERE namespace.nspname=current_schema()
		  AND procedure.proname = ANY(ARRAY[
		      'iam_global_lock_shared_v1',
		      'iam_global_lock_exclusive_v1',
		      'iam_scope_locks_v1',
		      'iam_assert_scope_locks_v1'
		  ])
		ORDER BY procedure.proname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var name string
		var securityDefiner, owned, safePath, publicRevoked, callerGranted bool
		if err := rows.Scan(&name, &securityDefiner, &owned, &safePath, &publicRevoked, &callerGranted); err != nil {
			t.Fatal(err)
		}
		if !securityDefiner || !owned || !safePath || !publicRevoked || !callerGranted {
			t.Fatalf("helper %s security = definer:%t owner:%t path:%t public-revoked:%t caller:%t",
				name, securityDefiner, owned, safePath, publicRevoked, callerGranted)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("secured helper count = %d, want 4", count)
	}
}

func equalUUIDs069(left, right []uuid.UUID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func start069LockWaiter(t *testing.T, pool *pgxpool.Pool, statement string, arguments ...any) (int, chan error) {
	t.Helper()
	type startResult struct {
		pid int
		err error
	}
	started := make(chan startResult, 1)
	done := make(chan error, 1)
	go func() {
		tx, err := pool.Begin(context.Background())
		if err != nil {
			started <- startResult{err: err}
			done <- err
			return
		}
		var pid int
		if err = tx.QueryRow(context.Background(), `SELECT pg_catalog.pg_backend_pid()`).Scan(&pid); err != nil {
			_ = tx.Rollback(context.Background())
			started <- startResult{err: err}
			done <- err
			return
		}
		started <- startResult{pid: pid}
		_, err = tx.Exec(context.Background(), statement, arguments...)
		if err == nil {
			err = tx.Commit(context.Background())
		} else {
			_ = tx.Rollback(context.Background())
		}
		done <- err
	}()
	result := <-started
	if result.err != nil {
		t.Fatal(result.err)
	}
	return result.pid, done
}

func waitForBlockedBy069(t *testing.T, pool *pgxpool.Pool, waiterPID, blockerPID int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var blocked bool
		if err := pool.QueryRow(t.Context(),
			`SELECT $2::integer = ANY(pg_catalog.pg_blocking_pids($1::integer))`,
			waiterPID, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("backend %d was not blocked by holder %d", waiterPID, blockerPID)
}

func assert069Installed(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var installed bool
	if err := pool.QueryRow(t.Context(), `
		SELECT to_regclass('iam_global_lock_protocol_claims') IS NOT NULL
		   AND to_regclass('iam_global_lock_authority_grants') IS NOT NULL
		   AND to_regprocedure('iam_global_lock_shared_v1()') IS NOT NULL
		   AND to_regprocedure('iam_global_lock_exclusive_v1()') IS NOT NULL
		   AND to_regprocedure('iam_scope_locks_v1(uuid[])') IS NOT NULL
		   AND to_regprocedure('iam_assert_scope_locks_v1(uuid[])') IS NOT NULL`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if installed != want {
		t.Fatalf("069 installed = %t, want %t", installed, want)
	}
}

func assert069TxCode(t *testing.T, pool *pgxpool.Pool, code string,
	operation func(context.Context, pgx.Tx) error,
) {
	t.Helper()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return operation(t.Context(), tx)
	})
	assert069PGCode(t, err, code)
}

func assert069PGCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func assert069Head(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var count, minimum, maximum int64
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*),min(version),max(version) FROM schema_migrations`).Scan(
		&count, &minimum, &maximum); err != nil {
		t.Fatal(err)
	}
	if count != want || minimum != 1 || maximum != want {
		t.Fatalf("migration ledger = count:%d min:%d max:%d, want %d/1/%d",
			count, minimum, maximum, want, want)
	}
}

func migrate069(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	if direction != "up" && direction != "down" {
		t.Fatalf("unsupported 069 migration direction %q", direction)
	}
	if direction == "down" {
		script, err := fs.ReadFile(controlmigrations.FS, "069_iam_global_lock_protocol.down.sql")
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), string(script)); err != nil {
				return err
			}
			command, err := tx.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=69`)
			if err == nil && command.RowsAffected() != 1 {
				return fmt.Errorf("delete 069 ledger rows = %d, want 1", command.RowsAffected())
			}
			return err
		}); err != nil {
			t.Fatalf("migrate 069 down: %v", err)
		}
		return
	}

	if _, err := pool.Exec(t.Context(), `CREATE TABLE IF NOT EXISTS schema_migrations (
		version bigint PRIMARY KEY,
		migration_id text,
		checksum_sha256 text,
		down_checksum_sha256 text,
		integrity_state text,
		metadata_recorded_at timestamptz,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatal(err)
	}
	var current int
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	for version := current + 1; version <= 69; version++ {
		upMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(upMatches) != 1 {
			t.Fatalf("resolve migration %03d up: matches=%v err=%v", version, upMatches, err)
		}
		downMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.down.sql", version))
		if err != nil || len(downMatches) != 1 {
			t.Fatalf("resolve migration %03d down: matches=%v err=%v", version, downMatches, err)
		}
		upScript, err := fs.ReadFile(controlmigrations.FS, upMatches[0])
		if err != nil {
			t.Fatal(err)
		}
		downScript, err := fs.ReadFile(controlmigrations.FS, downMatches[0])
		if err != nil {
			t.Fatal(err)
		}
		identifier := strings.TrimSuffix(upMatches[0], ".up.sql")
		upChecksum := fmt.Sprintf("%x", sha256.Sum256(upScript))
		downChecksum := fmt.Sprintf("%x", sha256.Sum256(downScript))
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), string(upScript)); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO schema_migrations(
				version,migration_id,checksum_sha256,down_checksum_sha256,
				integrity_state,metadata_recorded_at
			) VALUES($1,$2,$3,$4,'verified',now())`,
				version, identifier, upChecksum, downChecksum)
			return err
		}); err != nil {
			t.Fatalf("migrate %03d up: %v", version, err)
		}
	}
}

func new069Pool(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "iam069_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	}
	return pool, cleanup
}
