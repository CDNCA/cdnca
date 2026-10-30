package migrations_test

import (
	"context"
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

func TestChallengePolicyIdempotency072BackfillConstraintsAndRoundTrip(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	migrate069(t, pool, "up")
	seedChallengePolicy072Identity(t, pool)

	completedAtBeforeMigration := time.Now().UTC().Truncate(time.Microsecond)
	completed := insertChallengePolicy072Request(t, pool, "completed", completedAtBeforeMigration.Add(-time.Hour))
	pending := insertChallengePolicy072Request(t, pool, "pending", completedAtBeforeMigration)
	completeChallengePolicy072Request(t, pool, completed, completedAtBeforeMigration)
	for _, historical := range []struct {
		id          uuid.UUID
		key         string
		completedAt time.Time
	}{
		{
			id: uuid.MustParse("07200000-0000-4000-8000-000000000010"), key: "dst-spring",
			completedAt: challengePolicy072LocalTime(t, "2026-03-07T12:00:00"),
		},
		{
			id: uuid.MustParse("07200000-0000-4000-8000-000000000011"), key: "dst-fall",
			completedAt: challengePolicy072LocalTime(t, "2026-10-31T12:00:00"),
		},
	} {
		insertChallengePolicy072RequestWithID(t, pool, historical.id, historical.key, historical.completedAt.Add(-time.Hour))
		completeChallengePolicy072Request(t, pool, historical.id, historical.completedAt)
	}
	if err := applyChallengePolicy072WithTimeZoneError(pool, "up", "America/New_York"); err != nil {
		t.Fatalf("apply 072 up in DST zone: %v", err)
	}

	var completedAt, expiresAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT completed_at,retention_expires_at
		FROM challenge_policy_write_requests WHERE id=$1`, completed).Scan(&completedAt, &expiresAt); err != nil {
		t.Fatal(err)
	}
	if want := completedAt.Add(168 * time.Hour); !expiresAt.Equal(want) {
		t.Fatalf("backfill expiry=%s want=%s", expiresAt, want)
	}
	for _, key := range []string{"dst-spring", "dst-fall"} {
		var elapsed float64
		if err := pool.QueryRow(t.Context(), `SELECT extract(epoch FROM retention_expires_at-completed_at)
			FROM challenge_policy_write_requests WHERE idempotency_key=$1`, key).Scan(&elapsed); err != nil {
			t.Fatal(err)
		}
		if elapsed != 168*60*60 {
			t.Fatalf("%s retention elapsed=%.0f seconds want=%d", key, elapsed, 168*60*60)
		}
	}
	dstCompletion := insertChallengePolicy072Request(t, pool, "dst-new-completion",
		challengePolicy072LocalTime(t, "2026-03-07T11:00:00"))
	if err := completeChallengePolicy072RequestInTimeZone(pool, dstCompletion,
		challengePolicy072LocalTime(t, "2026-03-07T12:00:00"), "America/New_York"); err != nil {
		t.Fatal(err)
	}
	var triggerElapsed float64
	if err := pool.QueryRow(t.Context(), `SELECT extract(epoch FROM retention_expires_at-completed_at)
		FROM challenge_policy_write_requests WHERE id=$1`, dstCompletion).Scan(&triggerElapsed); err != nil {
		t.Fatal(err)
	}
	if triggerElapsed != 168*60*60 {
		t.Fatalf("DST completion retention elapsed=%.0f seconds want=%d", triggerElapsed, 168*60*60)
	}
	var pendingExpiry *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT retention_expires_at
		FROM challenge_policy_write_requests WHERE id=$1`, pending).Scan(&pendingExpiry); err != nil {
		t.Fatal(err)
	}
	if pendingExpiry != nil {
		t.Fatalf("pending expiry=%s want NULL", *pendingExpiry)
	}

	for _, statement := range []string{
		`UPDATE challenge_policy_write_requests SET retention_expires_at=retention_expires_at+interval '1 second' WHERE id=$1`,
		`UPDATE challenge_policy_write_requests SET retention_expires_at=now() WHERE id=$1`,
		`DELETE FROM challenge_policy_write_requests WHERE id=$1`,
	} {
		_, err := pool.Exec(t.Context(), statement, completed)
		assertChallengePolicy072Code(t, err, "P0001")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE challenge_policy_write_requests
		SET retention_expires_at=now() WHERE id=$1`, pending); err == nil {
		t.Fatal("pending receipt accepted an expiry")
	}
	for _, infinite := range []string{"infinity", "-infinity"} {
		candidate := insertChallengePolicy072Request(t, pool, "completion-"+infinite, time.Now().UTC())
		_, err := pool.Exec(t.Context(), `UPDATE challenge_policy_write_requests SET
			outcome='success',resource_id=$2,response_status=201,response_body='{}',completed_at=$3::timestamptz
			WHERE id=$1`, candidate, uuid.New(), infinite)
		assertChallengePolicy072Code(t, err, "P0001")
	}

	if err := applyChallengePolicy072Error(pool, "down"); err == nil {
		t.Fatal("072 down accepted completed retention facts")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE challenge_policy_write_requests SET completed_at=NULL,
		outcome=NULL,resource_id=NULL,response_status=NULL,response_body=NULL,retention_expires_at=NULL WHERE id=$1`, completed); err == nil {
		t.Fatal("completed fact became pending")
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM challenge_policy_write_requests
		WHERE id=$1`, pending); err == nil {
		t.Fatal("pending fact was deleted")
	}
}

func TestChallengePolicyIdempotency072RejectsHistoricalInfiniteCompletion(t *testing.T) {
	for _, infinite := range []string{"infinity", "-infinity"} {
		t.Run(infinite, func(t *testing.T) {
			pool, cleanup := new069Pool(t)
			defer cleanup()
			migrate069(t, pool, "up")
			seedChallengePolicy072Identity(t, pool)
			var id uuid.UUID
			if infinite == "-infinity" {
				id = insertChallengePolicy072RequestAtText(t, pool, "historical-"+infinite, infinite)
			} else {
				id = insertChallengePolicy072Request(t, pool, "historical-"+infinite, time.Now().UTC())
			}
			completeChallengePolicy072RequestText(t, pool, id, infinite)
			if err := applyChallengePolicy072Error(pool, "up"); err == nil {
				t.Fatalf("072 accepted historical %s completion", infinite)
			}
			assertChallengePolicy072RolledBack(t, pool)
		})
	}
}

func TestChallengePolicyIdempotency072DownSerializesCompletion(t *testing.T) {
	t.Run("completion_first", func(t *testing.T) {
		pool, cleanup := new069Pool(t)
		defer cleanup()
		migrate069(t, pool, "up")
		seedChallengePolicy072Identity(t, pool)
		id := insertChallengePolicy072Request(t, pool, "down-completion-first", time.Now().UTC().Add(-time.Hour))
		applyChallengePolicy072(t, pool, "up")
		if err := runChallengePolicy072CompletionFirst(t.Context(), pool, id); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("down_first", func(t *testing.T) {
		pool, cleanup := new069Pool(t)
		defer cleanup()
		migrate069(t, pool, "up")
		seedChallengePolicy072Identity(t, pool)
		id := insertChallengePolicy072Request(t, pool, "down-first", time.Now().UTC().Add(-time.Hour))
		applyChallengePolicy072(t, pool, "up")

		if err := runChallengePolicy072DownFirst(t.Context(), pool, id); err != nil {
			t.Fatal(err)
		}
	})
}

const challengePolicy072DownLock = "LOCK TABLE challenge_policy_write_requests IN ACCESS EXCLUSIVE MODE;\n\n"

func runChallengePolicy072CompletionFirst(parent context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	downScript, err := fs.ReadFile(controlmigrations.FS, "072_challenge_policy_idempotency_retention.down.sql")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(downScript), challengePolicy072DownLock) {
		return errors.New("072 down must lock before inspecting completed facts")
	}
	completionPool, err := newChallengePolicy072ApplicationPool(parent, pool, "challenge072_completion_holder")
	if err != nil {
		return err
	}
	downPool, err := newChallengePolicy072ApplicationPool(parent, pool, "challenge072_down_waiter")
	if err != nil {
		completionPool.Close()
		return err
	}
	completionCtx, cancelCompletion := context.WithTimeout(parent, 10*time.Second)
	downCtx, cancelDown := context.WithTimeout(parent, 10*time.Second)
	completionTx, err := completionPool.Begin(completionCtx)
	if err != nil {
		cancelCompletion()
		cancelDown()
		downPool.Close()
		completionPool.Close()
		return err
	}
	var downDone chan error
	downReceived := false
	cleanup := func() {
		cancelCompletion()
		cancelDown()
		rollbackCtx, cancelRollback := context.WithTimeout(context.Background(), time.Second)
		_ = completionTx.Rollback(rollbackCtx)
		cancelRollback()
		if downDone != nil && !downReceived {
			select {
			case <-downDone:
			case <-time.After(time.Second):
			}
		}
		downPool.Close()
		completionPool.Close()
	}
	defer cleanup()

	if _, err := completionTx.Exec(completionCtx, `UPDATE challenge_policy_write_requests SET
		outcome='success',resource_id=$2,response_status=201,response_body='{}',completed_at=$3
		WHERE id=$1`, id, uuid.New(), time.Now().UTC()); err != nil {
		return err
	}
	if err := waitChallengePolicy072RelationLock(completionCtx, pool,
		"challenge072_completion_holder", "RowExclusiveLock", true); err != nil {
		return err
	}
	downDone = make(chan error, 1)
	go func() {
		downDone <- executeChallengePolicy072Script(downCtx, downPool, downScript)
	}()
	if err := waitChallengePolicy072RelationLock(downCtx, pool,
		"challenge072_down_waiter", "AccessExclusiveLock", false); err != nil {
		return err
	}
	if err := completionTx.Commit(completionCtx); err != nil {
		return err
	}
	select {
	case downErr := <-downDone:
		downReceived = true
		if downErr == nil {
			return errors.New("overlapping 072 down accepted the committed completion")
		}
	case <-downCtx.Done():
		return fmt.Errorf("wait for overlapping 072 down: %w", downCtx.Err())
	}
	return assertChallengePolicy072RetentionInstalled(parent, pool, id)
}

func runChallengePolicy072DownFirst(parent context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	downScript, err := fs.ReadFile(controlmigrations.FS, "072_challenge_policy_idempotency_retention.down.sql")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(downScript), challengePolicy072DownLock) {
		return errors.New("072 down must lock before inspecting completed facts")
	}
	remainder := strings.TrimPrefix(string(downScript), challengePolicy072DownLock)
	downPool, err := newChallengePolicy072ApplicationPool(parent, pool, "challenge072_down_holder")
	if err != nil {
		return err
	}
	completionPool, err := newChallengePolicy072ApplicationPool(parent, pool, "challenge072_completion_waiter")
	if err != nil {
		downPool.Close()
		return err
	}
	downCtx, cancelDown := context.WithTimeout(parent, 10*time.Second)
	completionCtx, cancelCompletion := context.WithTimeout(parent, 10*time.Second)
	downTx, err := downPool.Begin(downCtx)
	if err != nil {
		cancelDown()
		cancelCompletion()
		completionPool.Close()
		downPool.Close()
		return err
	}
	var completionDone chan error
	completionReceived := false
	cleanup := func() {
		cancelCompletion()
		cancelDown()
		rollbackCtx, cancelRollback := context.WithTimeout(context.Background(), time.Second)
		_ = downTx.Rollback(rollbackCtx)
		cancelRollback()
		if completionDone != nil && !completionReceived {
			select {
			case <-completionDone:
			case <-time.After(time.Second):
			}
		}
		completionPool.Close()
		downPool.Close()
	}
	defer cleanup()

	if _, err := downTx.Exec(downCtx, strings.TrimSpace(challengePolicy072DownLock)); err != nil {
		return err
	}
	if err := waitChallengePolicy072RelationLock(downCtx, pool,
		"challenge072_down_holder", "AccessExclusiveLock", true); err != nil {
		return err
	}
	completionDone = make(chan error, 1)
	go func() {
		_, err := completionPool.Exec(completionCtx, `UPDATE challenge_policy_write_requests SET
			outcome='success',resource_id=$2,response_status=201,response_body='{}',completed_at=$3
			WHERE id=$1`, id, uuid.New(), time.Now().UTC())
		completionDone <- err
	}()
	if err := waitChallengePolicy072RelationLock(completionCtx, pool,
		"challenge072_completion_waiter", "RowExclusiveLock", false); err != nil {
		return err
	}
	if _, err := downTx.Exec(downCtx, remainder); err != nil {
		return err
	}
	if err := downTx.Commit(downCtx); err != nil {
		return err
	}
	select {
	case completionErr := <-completionDone:
		completionReceived = true
		if completionErr != nil {
			return fmt.Errorf("completion after 072 down: %w", completionErr)
		}
	case <-completionCtx.Done():
		return fmt.Errorf("wait for completion after 072 down: %w", completionCtx.Err())
	}
	return assertChallengePolicy072DownState(parent, pool, id)
}

func executeChallengePolicy072Script(ctx context.Context, pool *pgxpool.Pool, script []byte) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, string(script))
		return err
	})
}

func assertChallengePolicy072RetentionInstalled(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	var completed, expires, columnExists, constraintExists, guardExists bool
	err := pool.QueryRow(ctx, `SELECT
		(SELECT completed_at IS NOT NULL FROM challenge_policy_write_requests WHERE id=$1),
		(SELECT retention_expires_at=completed_at+interval '168 hours'
		 FROM challenge_policy_write_requests WHERE id=$1),
		EXISTS(SELECT 1 FROM information_schema.columns
		 WHERE table_schema=current_schema() AND table_name='challenge_policy_write_requests'
		   AND column_name='retention_expires_at'),
		EXISTS(SELECT 1 FROM pg_constraint
		 WHERE conrelid='challenge_policy_write_requests'::regclass
		   AND conname='challenge_policy_write_requests_retention_072'),
		EXISTS(SELECT 1 FROM pg_trigger
		 WHERE tgrelid='challenge_policy_write_requests'::regclass
		   AND tgname='challenge_policy_write_requests_guard_053' AND NOT tgisinternal)`, id).Scan(
		&completed, &expires, &columnExists, &constraintExists, &guardExists)
	if err != nil {
		return err
	}
	if !completed || !expires || !columnExists || !constraintExists || !guardExists {
		return fmt.Errorf("retention state completed=%t expiry=%t column=%t constraint=%t guard=%t",
			completed, expires, columnExists, constraintExists, guardExists)
	}
	return nil
}

func assertChallengePolicy072DownState(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	var completed, columnExists, guardExists bool
	err := pool.QueryRow(ctx, `SELECT
		(SELECT completed_at IS NOT NULL FROM challenge_policy_write_requests WHERE id=$1),
		EXISTS(SELECT 1 FROM information_schema.columns
		 WHERE table_schema=current_schema() AND table_name='challenge_policy_write_requests'
		   AND column_name='retention_expires_at'),
		EXISTS(SELECT 1 FROM pg_trigger
		 WHERE tgrelid='challenge_policy_write_requests'::regclass
		   AND tgname='challenge_policy_write_requests_guard_053' AND NOT tgisinternal)`, id).Scan(
		&completed, &columnExists, &guardExists)
	if err != nil {
		return err
	}
	if !completed || columnExists || !guardExists {
		return fmt.Errorf("down state completed=%t column=%t guard=%t", completed, columnExists, guardExists)
	}
	return nil
}

func TestChallengePolicyIdempotency072DownWithoutCompletedFacts(t *testing.T) {
	pool, cleanup := new069Pool(t)
	defer cleanup()
	migrate069(t, pool, "up")
	seedChallengePolicy072Identity(t, pool)
	insertChallengePolicy072Request(t, pool, "pending-down", time.Now().UTC())
	applyChallengePolicy072(t, pool, "up")
	applyChallengePolicy072(t, pool, "down")
	var columnExists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='challenge_policy_write_requests'
		  AND column_name='retention_expires_at')`).Scan(&columnExists); err != nil {
		t.Fatal(err)
	}
	if columnExists {
		t.Fatal("072 retention column remains after guarded down")
	}
	applyChallengePolicy072(t, pool, "up")
}

func applyChallengePolicy072(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	if err := applyChallengePolicy072Error(pool, direction); err != nil {
		t.Fatalf("apply 072 %s: %v", direction, err)
	}
}

func applyChallengePolicy072Error(pool *pgxpool.Pool, direction string) error {
	return applyChallengePolicy072WithTimeZoneError(pool, direction, "")
}

func applyChallengePolicy072WithTimeZoneError(pool *pgxpool.Pool, direction, timeZone string) error {
	name := "072_challenge_policy_idempotency_retention." + direction + ".sql"
	script, err := fs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if timeZone != "" {
			if timeZone != "America/New_York" {
				return errors.New("unsupported challenge policy 072 test time zone")
			}
			if _, err := tx.Exec(context.Background(), `SET LOCAL TIME ZONE 'America/New_York'`); err != nil {
				return err
			}
		}
		_, err := tx.Exec(context.Background(), string(script))
		return err
	})
}

func completeChallengePolicy072RequestInTimeZone(
	pool *pgxpool.Pool, id uuid.UUID, completedAt time.Time, timeZone string,
) error {
	return pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if timeZone != "America/New_York" {
			return errors.New("unsupported challenge policy 072 test time zone")
		}
		if _, err := tx.Exec(context.Background(), `SET LOCAL TIME ZONE 'America/New_York'`); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE challenge_policy_write_requests SET
			outcome='success',resource_id=$2,response_status=201,response_body='{}',completed_at=$3
			WHERE id=$1`, id, uuid.New(), completedAt)
		return err
	})
}

func assertChallengePolicy072RolledBack(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var columnExists, triggerExists bool
	if err := pool.QueryRow(t.Context(), `SELECT
		EXISTS(SELECT 1 FROM information_schema.columns
		 WHERE table_schema=current_schema() AND table_name='challenge_policy_write_requests'
		   AND column_name='retention_expires_at'),
		EXISTS(SELECT 1 FROM pg_trigger
		 WHERE tgrelid='challenge_policy_write_requests'::regclass
		   AND tgname='challenge_policy_write_requests_guard_053' AND NOT tgisinternal)`).Scan(
		&columnExists, &triggerExists); err != nil {
		t.Fatal(err)
	}
	if columnExists || !triggerExists {
		t.Fatalf("072 rollback column=%t 053 guard=%t, want false/true", columnExists, triggerExists)
	}
}

func newChallengePolicy072ApplicationPool(
	ctx context.Context, source *pgxpool.Pool, applicationName string,
) (*pgxpool.Pool, error) {
	config := source.Config().Copy()
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	return pgxpool.NewWithConfig(ctx, config)
}

func waitChallengePolicy072RelationLock(
	ctx context.Context, pool *pgxpool.Pool, applicationName, mode string, granted bool,
) error {
	for {
		var matched bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1
			FROM pg_locks lock
			JOIN pg_stat_activity activity ON activity.pid=lock.pid
			WHERE activity.application_name=$1
			  AND lock.locktype='relation'
			  AND lock.relation='challenge_policy_write_requests'::regclass
			  AND lock.mode=$2 AND lock.granted=$3)`, applicationName, mode, granted).Scan(&matched)
		if err != nil {
			return err
		}
		if matched {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for %s %s granted=%t: %w", applicationName, mode, granted, err)
		}
	}
}

var challengePolicy072Scope = uuid.MustParse("07200000-0000-4000-8000-000000000001")
var challengePolicy072User = uuid.MustParse("07200000-0000-4000-8000-000000000002")

func seedChallengePolicy072Identity(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	tenantID := uuid.MustParse("07200000-0000-4000-8000-000000000003")
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO tenants(id,display_name)
			VALUES($1,'Retention Tenant')`, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id)
			VALUES($1,'tenant',$2)`, challengePolicy072Scope, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,'retention-owner','Retention Owner','hash')`, challengePolicy072User); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
			challengePolicy072Scope, challengePolicy072User)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func insertChallengePolicy072Request(t *testing.T, pool *pgxpool.Pool, key string, createdAt time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	insertChallengePolicy072RequestWithID(t, pool, id, key, createdAt)
	return id
}

func insertChallengePolicy072RequestWithID(
	t *testing.T, pool *pgxpool.Pool, id uuid.UUID, key string, createdAt time.Time,
) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO challenge_policy_write_requests(
		id,actor_scope_id,actor_user_id,target_scope_id,operation,idempotency_key,
		request_digest,request_id,trace_id,created_at
	) VALUES($1,$2,$3,$2,'challenge_policy.create',$4,$5,$6,$7,$8)`,
		id, challengePolicy072Scope, challengePolicy072User, key, make([]byte, 32),
		key+"-request", key+"-trace", createdAt); err != nil {
		t.Fatal(err)
	}
}

func insertChallengePolicy072RequestAtText(
	t *testing.T, pool *pgxpool.Pool, key, createdAt string,
) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO challenge_policy_write_requests(
		id,actor_scope_id,actor_user_id,target_scope_id,operation,idempotency_key,
		request_digest,request_id,trace_id,created_at
	) VALUES($1,$2,$3,$2,'challenge_policy.create',$4,$5,$6,$7,$8::timestamptz)`,
		id, challengePolicy072Scope, challengePolicy072User, key, make([]byte, 32),
		key+"-request", key+"-trace", createdAt); err != nil {
		t.Fatal(err)
	}
	return id
}

func completeChallengePolicy072Request(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, completedAt time.Time) {
	t.Helper()
	resourceID := uuid.New()
	if _, err := pool.Exec(t.Context(), `UPDATE challenge_policy_write_requests SET
		outcome='success',resource_id=$2,response_status=201,response_body='{}',completed_at=$3
		WHERE id=$1`, id, resourceID, completedAt); err != nil {
		t.Fatal(err)
	}
}

func completeChallengePolicy072RequestText(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, completedAt string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE challenge_policy_write_requests SET
		outcome='success',resource_id=$2,response_status=201,response_body='{}',completed_at=$3::timestamptz
		WHERE id=$1`, id, uuid.New(), completedAt); err != nil {
		t.Fatal(err)
	}
}

func challengePolicy072LocalTime(t *testing.T, value string) time.Time {
	t.Helper()
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := time.ParseInLocation("2006-01-02T15:04:05", value, location)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func assertChallengePolicy072Code(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("PostgreSQL error=%v want SQLSTATE %s", err, code)
	}
}
