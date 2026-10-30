//go:build integration

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

func TestIdentityMembership073RoundTripAndAuthorityReentry(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate073(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 73)
	assertIdentityMembership073State(t, pool, true)

	first, second := uuid.New(), uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var initial, reentered []uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT iam_begin_authority_mutation_v1($1,$2::uuid[])`,
			"identity.membership.suspend", []uuid.UUID{second, first, second}).Scan(&initial); err != nil {
			return err
		}
		if err := tx.QueryRow(t.Context(), `SELECT iam_begin_authority_mutation_v1($1,$2::uuid[])`,
			"identity.membership.suspend", []uuid.UUID{first, second}).Scan(&reentered); err != nil {
			return err
		}
		if !equalUUIDs069(initial, reentered) || len(initial) != 2 {
			t.Fatalf("authority reentry scopes = %v/%v", initial, reentered)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assert073PGCode(t, pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `SELECT iam_begin_authority_mutation_v1(
			'identity.membership.revoke',ARRAY[$1::uuid])`, uuid.New())
		return err
	}), "P7000")

	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	for range 2 {
		tx, err := connection.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_begin_authority_mutation_v1(
			'identity.membership.suspend',ARRAY[$1::uuid])`, first); err != nil {
			cleanupContext, cancelCleanup := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
			_ = tx.Rollback(cleanupContext)
			cancelCleanup()
			t.Fatal(err)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	if err := migrate073(t.Context(), pool, "down"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 72)
	assertIdentityMembership073State(t, pool, false)
	if err := migrate073(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	assert069Head(t, pool, 73)
	assertIdentityMembership073State(t, pool, true)
}

func TestIdentityMembership073AuthorityUsesRestrictedSearchPathAndACL(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if err := migrate073(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	qualified := pgx.Identifier{schema}.Sanitize() + ".iam_validate_authority_operation_v1($1)"
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL search_path=pg_temp,pg_catalog`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), "SELECT "+qualified, "identity.membership.suspend")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	assertIdentityMembership073State(t, pool, true)
}

func TestIdentityMembership073FactsPreventRollbackAtomically(t *testing.T) {
	for _, fact := range []string{"receipt", "audit"} {
		t.Run(fact, func(t *testing.T) {
			pool, cleanup := new069Pool(t)
			defer cleanup()
			if err := migrate073(t.Context(), pool, "up"); err != nil {
				t.Fatal(err)
			}
			scopeID, userID := seedIdentityMembership073Actor(t, pool)
			switch fact {
			case "receipt":
				if _, err := pool.Exec(t.Context(), `INSERT INTO identity_write_requests(
					id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest
				) VALUES($1,$2,$3,'identity.membership.suspend','rollback-fact',$4)`,
					uuid.New(), userID, scopeID, make([]byte, 32)); err != nil {
					t.Fatal(err)
				}
			case "audit":
				if _, err := pool.Exec(t.Context(), `INSERT INTO audit_events(
					id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
					request_id,result,payload,previous_hash,event_hash,occurred_at
				) VALUES($1,$2,1,$3,'identity.membership.suspend','membership',$4,
					'rollback-fact','success','{}',NULL,$5,now())`,
					uuid.New(), scopeID, userID, scopeID.String()+":"+userID.String(), bytes073(0x73)); err != nil {
					t.Fatal(err)
				}
			}
			err := migrate073(t.Context(), pool, "down")
			assert073PGCode(t, err, "55000")
			assert069Head(t, pool, 73)
			assertIdentityMembership073State(t, pool, true)
		})
	}
}

func TestIdentityMembership073RejectsTamperedState(t *testing.T) {
	for _, test := range []struct {
		name      string
		direction string
		tamper    string
		wantHead  int64
	}{
		{
			name: "up rejects altered validator", direction: "up", wantHead: 72,
			tamper: `ALTER FUNCTION iam_validate_authority_operation_v1(text) VOLATILE`,
		},
		{
			name: "up rejects altered body with valid metadata", direction: "up", wantHead: 72,
			tamper: `CREATE OR REPLACE FUNCTION iam_validate_authority_operation_v1(operation text)
				RETURNS void LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
				BEGIN
					IF operation = 'identity.membership.suspend' THEN
						RAISE EXCEPTION USING ERRCODE='P7000', MESSAGE='iam_authority_operation_invalid';
					END IF;
				END;
				$$`,
		},
		{
			name: "up rejects non-owner execute", direction: "up", wantHead: 72,
			tamper: `GRANT EXECUTE ON FUNCTION iam_validate_authority_operation_v1(text) TO pg_monitor`,
		},
		{
			name: "up rejects case backdoor receipt constraint", direction: "up", wantHead: 72,
			tamper: `ALTER TABLE identity_write_requests
				DROP CONSTRAINT identity_write_requests_operation_check,
				ADD CONSTRAINT identity_write_requests_operation_check CHECK (
					CASE WHEN operation='backdoor' THEN true ELSE operation IN (
						'identity.user.create','identity.user.update','identity.self.update'
					) END
				)`,
		},
		{
			name: "down rejects public execute", direction: "down", wantHead: 73,
			tamper: `GRANT EXECUTE ON FUNCTION iam_validate_authority_operation_v1(text) TO PUBLIC`,
		},
		{
			name: "down rejects non-owner execute", direction: "down", wantHead: 73,
			tamper: `GRANT EXECUTE ON FUNCTION iam_validate_authority_operation_v1(text) TO pg_monitor`,
		},
		{
			name: "down rejects altered body with valid metadata", direction: "down", wantHead: 73,
			tamper: `CREATE OR REPLACE FUNCTION iam_validate_authority_operation_v1(operation text)
				RETURNS void LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
				BEGIN
					IF operation <> 'identity.membership.suspend' THEN
						RAISE EXCEPTION USING ERRCODE='P7000', MESSAGE='iam_authority_operation_invalid';
					END IF;
				END;
				$$`,
		},
		{
			name: "down rejects broadened receipt constraint", direction: "down", wantHead: 73,
			tamper: `ALTER TABLE identity_write_requests
				DROP CONSTRAINT identity_write_requests_operation_check,
				ADD CONSTRAINT identity_write_requests_operation_check CHECK (true)`,
		},
		{
			name: "down rejects case backdoor receipt constraint", direction: "down", wantHead: 73,
			tamper: `ALTER TABLE identity_write_requests
				DROP CONSTRAINT identity_write_requests_operation_check,
				ADD CONSTRAINT identity_write_requests_operation_check CHECK (
					CASE WHEN operation='backdoor' THEN true ELSE operation IN (
						'identity.user.create','identity.user.update','identity.self.update',
						'identity.membership.suspend'
					) END
				)`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, cleanup := new069Pool(t)
			defer cleanup()
			if err := migrate073(t.Context(), pool, "up"); err != nil {
				t.Fatal(err)
			}
			if test.direction == "up" {
				if err := migrate073(t.Context(), pool, "down"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pool.Exec(t.Context(), test.tamper); err != nil {
				t.Fatal(err)
			}
			assert073PGCode(t, migrate073(t.Context(), pool, test.direction), "P7300")
			assert069Head(t, pool, test.wantHead)
		})
	}
}

func TestIdentityMembership073RejectsUnexpectedZeroVersionBeforeApplying(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations (
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
	if _, err := pool.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at
	) VALUES(0,'000_unexpected',repeat('0',64),repeat('0',64),'verified',now())`); err != nil {
		t.Fatal(err)
	}
	var beforeObjects int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM pg_catalog.pg_class relation
		JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
		WHERE namespace.nspname=current_schema()`).Scan(&beforeObjects); err != nil {
		t.Fatal(err)
	}

	if err := migrate073(t.Context(), pool, "up"); err == nil {
		t.Fatal("073 up accepted unexpected version 0 ledger")
	}
	var afterObjects, ledgerRows, maximum int64
	var firstMigrationApplied bool
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*)
		 FROM pg_catalog.pg_class relation
		 JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
		 WHERE namespace.nspname=current_schema()),
		(SELECT count(*) FROM schema_migrations),
		(SELECT COALESCE(max(version),0) FROM schema_migrations),
		to_regclass('access_scopes') IS NOT NULL`).Scan(
		&afterObjects, &ledgerRows, &maximum, &firstMigrationApplied); err != nil {
		t.Fatal(err)
	}
	if afterObjects != beforeObjects || ledgerRows != 1 || maximum != 0 || firstMigrationApplied {
		t.Fatalf("073 rejected up state = objects:%d/%d ledger:%d/%d first_applied:%t, want unchanged/1/0/false",
			beforeObjects, afterObjects, ledgerRows, maximum, firstMigrationApplied)
	}
}

func assertIdentityMembership073State(t *testing.T, pool *pgxpool.Pool, installed bool) {
	t.Helper()
	var ownerMatches, immutable, securityDefiner, foreignPrivilege bool
	var settings []string
	var bodyHash string
	if err := pool.QueryRow(t.Context(), `SELECT
		procedure.proowner = (SELECT role.oid FROM pg_catalog.pg_roles role WHERE role.rolname=CURRENT_USER),
		procedure.provolatile = 'i',
		procedure.prosecdef,
		procedure.proconfig,
		pg_catalog.md5(procedure.prosrc),
		EXISTS (
				SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
					procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
				)) privilege
				WHERE privilege.grantee<>procedure.proowner
				   OR privilege.privilege_type<>'EXECUTE'
			)
		FROM pg_catalog.pg_proc procedure
		WHERE procedure.oid='iam_validate_authority_operation_v1(text)'::pg_catalog.regprocedure`,
	).Scan(&ownerMatches, &immutable, &securityDefiner, &settings, &bodyHash, &foreignPrivilege); err != nil {
		t.Fatal(err)
	}
	wantBodyHash := "b4b844b0a87f0843919ef5d0ffc63caa"
	if installed {
		wantBodyHash = "c1bffb83f161889631231268d2c91591"
	}
	if !ownerMatches || !immutable || securityDefiner || foreignPrivilege ||
		len(settings) != 1 || settings[0] != "search_path=pg_catalog, pg_temp" || bodyHash != wantBodyHash {
		t.Fatalf("validator security = owner:%t immutable:%t definer:%t foreign_privilege:%t settings:%v body:%s",
			ownerMatches, immutable, securityDefiner, foreignPrivilege, settings, bodyHash)
	}
	err := func() error {
		_, err := pool.Exec(t.Context(), `SELECT iam_validate_authority_operation_v1('identity.membership.suspend')`)
		return err
	}()
	if installed && err != nil {
		t.Fatalf("membership operation rejected at 073: %v", err)
	}
	if !installed {
		assert073PGCode(t, err, "P7000")
	}
	var constraint string
	if err := pool.QueryRow(t.Context(), `SELECT pg_get_constraintdef(oid)
		FROM pg_constraint WHERE conrelid='identity_write_requests'::regclass
		  AND conname='identity_write_requests_operation_check'`).Scan(&constraint); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(constraint, "identity.membership.suspend") != installed {
		t.Fatalf("receipt constraint at installed=%t: %s", installed, constraint)
	}
}

func seedIdentityMembership073Actor(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'073 Actor','unused')`, userID, "actor-"+strings.ReplaceAll(uuid.NewString(), "-", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID
}

func bytes073(value byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = value
	}
	return result
}

func assert073PGCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func migrate073(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	const target int64 = 73
	if direction != "up" && direction != "down" {
		return fmt.Errorf("unsupported 073 migration direction %q", direction)
	}
	if direction == "down" {
		script, err := fs.ReadFile(controlmigrations.FS, "073_identity_membership_mutation.down.sql")
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var current int64
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
				return err
			}
			if err := validate073Ledger(ctx, tx.QueryRow, current); err != nil {
				return err
			}
			if current != target {
				return fmt.Errorf("migration head = %d, want %d before down", current, target)
			}
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			command, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=73`)
			if err == nil && command.RowsAffected() != 1 {
				return fmt.Errorf("delete 073 ledger rows = %d, want 1", command.RowsAffected())
			}
			if err != nil {
				return err
			}
			return validate073Ledger(ctx, tx.QueryRow, target-1)
		}); err != nil {
			return fmt.Errorf("migrate 073 down: %w", err)
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
	if err := validate073Ledger(ctx, pool.QueryRow, current); err != nil {
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
	return validate073Ledger(ctx, pool.QueryRow, target)
}

func validate073Ledger(
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
