//go:build integration

package notificationcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	_ "unsafe"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const notificationControlMigration091UpSHA = "9c556085f7396024a5011f74b06e0a6e3b83f5f6c5ab050b4b5c7b2ad036758c"

func TestNotificationControlIdempotencyReceipts091Contract(t *testing.T) {
	up := mustReadNotificationControlMigration091(t, "091_notification_control_idempotency_receipts.up.sql")
	down := mustReadNotificationControlMigration091(t, "091_notification_control_idempotency_receipts.down.sql")

	for _, fragment := range []string{
		"migration 091 requires the exact verified 090 release head",
		"090_package_offer_publication",
		"1bfa2cccb6b15dab981cf73b23754c7a1751f2f60921dda5959f51fef545b284",
		"9450025870421a3d594f3a9e210bd463ba3021b3ac19b815dee5a127ddaf5c9b",
		"CREATE TABLE notification_control_idempotency_receipts",
		"CREATE UNIQUE INDEX audit_events_notification_control_denied_identity_091",
		"notification.channels.update",
		"notification.template.put",
		"notification.subscription.update",
		"DEFERRABLE INITIALLY DEFERRED",
		"BEFORE TRUNCATE ON notification_control_idempotency_receipts",
		"ERRCODE = 'P9102'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("091 up missing %q", fragment)
		}
	}
	if strings.Contains(up, "audit_event_id") {
		t.Fatal("091 must not treat audit events as idempotency receipts")
	}
	actualUpSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(up)))
	if actualUpSHA != notificationControlMigration091UpSHA {
		t.Fatalf("091 embedded up checksum = %s, want %s", actualUpSHA, notificationControlMigration091UpSHA)
	}
	for _, fragment := range []string{
		"migration 091 rollback requires the verified 091 head",
		notificationControlMigration091UpSHA,
		"090_package_offer_publication",
		"1bfa2cccb6b15dab981cf73b23754c7a1751f2f60921dda5959f51fef545b284",
		"9450025870421a3d594f3a9e210bd463ba3021b3ac19b815dee5a127ddaf5c9b",
		"migration 091 rollback would discard notification control idempotency receipts",
		"DROP INDEX audit_events_notification_control_denied_identity_091",
		"IN ACCESS EXCLUSIVE MODE",
		"ERRCODE = 'P9101'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("091 down missing %q", fragment)
		}
	}
}

func TestNotificationControlIdempotencyReceipts091RoundTripAndFrozenHead(t *testing.T) {
	pool := notificationControlMigrationPool091(t, 90)
	if err := migrateNotificationControlVersion091(t.Context(), pool, "up", 91); err != nil {
		t.Fatalf("apply 091: %v", err)
	}
	assertNotificationControlMigrationHead091(t, pool, 91)
	assertNotificationControlReceiptTable091(t, pool, true)

	if err := migrateNotificationControlVersion091(t.Context(), pool, "down", 91); err != nil {
		t.Fatalf("empty 091 down: %v", err)
	}
	assertNotificationControlMigrationHead091(t, pool, 90)
	assertNotificationControlReceiptTable091(t, pool, false)
	if err := migrateNotificationControlVersion091(t.Context(), pool, "up", 91); err != nil {
		t.Fatalf("reapply 091: %v", err)
	}
	assertNotificationControlMigrationHead091(t, pool, 91)

	for name, test := range map[string]struct {
		column string
		value  string
	}{
		"migration id":    {column: "migration_id", value: "090_forged"},
		"up checksum":     {column: "checksum_sha256", value: strings.Repeat("a", 64)},
		"down checksum":   {column: "down_checksum_sha256", value: strings.Repeat("a", 64)},
		"integrity state": {column: "integrity_state", value: "forged"},
	} {
		t.Run("wrong 090 "+name, func(t *testing.T) {
			wrongHead := notificationControlMigrationPool091(t, 90)
			if _, err := wrongHead.Exec(t.Context(), "UPDATE schema_migrations SET "+test.column+"=$1 WHERE version=90", test.value); err != nil {
				t.Fatal(err)
			}
			up := mustReadNotificationControlMigration091(t, "091_notification_control_idempotency_receipts.up.sql")
			_, err := wrongHead.Exec(t.Context(), up)
			assertNotificationControlCode091(t, err, "P9100")
			assertNotificationControlReceiptTable091(t, wrongHead, false)
		})
	}

	down := mustReadNotificationControlMigration091(t, "091_notification_control_idempotency_receipts.down.sql")
	for name, test := range map[string]struct {
		version int
		column  string
		value   string
	}{
		"forged parent id":   {version: 90, column: "migration_id", value: "090_forged"},
		"forged parent up":   {version: 90, column: "checksum_sha256", value: strings.Repeat("b", 64)},
		"forged parent down": {version: 90, column: "down_checksum_sha256", value: strings.Repeat("b", 64)},
		"tampered 091 head":  {version: 91, column: "checksum_sha256", value: strings.Repeat("c", 64)},
	} {
		t.Run(name+" after 091", func(t *testing.T) {
			err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
				if _, updateErr := tx.Exec(t.Context(), "UPDATE schema_migrations SET "+test.column+"=$1 WHERE version=$2", test.value, test.version); updateErr != nil {
					return updateErr
				}
				_, downErr := tx.Exec(t.Context(), down)
				return downErr
			})
			assertNotificationControlCode091(t, err, "P9100")
			assertNotificationControlMigrationHead091(t, pool, 91)
			assertNotificationControlReceiptTable091(t, pool, true)
		})
	}
}

func TestNotificationControlIdempotencyReceipts091TransitionAndRollbackGuards(t *testing.T) {
	pool := notificationControlMigrationPool091(t, 91)
	actor := seedControlActor(t, pool, "platform", "system_configuration.read", "system_configuration.manage")
	digest := sha256.Sum256([]byte("receipt-guard"))

	_, err := pool.Exec(t.Context(), `INSERT INTO notification_control_idempotency_receipts(
		id,actor_scope_id,actor_user_id,operation,request_key,request_digest,response_body,created_at,completed_at)
		VALUES($1,$2,$3,'notification.channels.update','completed-insert',$4,'{}'::jsonb,$5,$5)`,
		uuid.New(), actor.ScopeID, actor.UserID, digest[:], controlTestNow)
	assertNotificationControlCode091(t, err, "P9102")

	_, err = pool.Exec(t.Context(), `INSERT INTO notification_control_idempotency_receipts(
		id,actor_scope_id,actor_user_id,operation,request_key,request_digest,created_at)
		VALUES($1,$2,$3,'notification.channels.update','incomplete-commit',$4,$5)`,
		uuid.New(), actor.ScopeID, actor.UserID, digest[:], controlTestNow)
	assertNotificationControlCode091(t, err, "P9102")

	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		id := uuid.New()
		if _, insertErr := tx.Exec(t.Context(), `INSERT INTO notification_control_idempotency_receipts(
			id,actor_scope_id,actor_user_id,operation,request_key,request_digest,created_at)
			VALUES($1,$2,$3,'notification.channels.update','identity-mutation',$4,$5)`,
			id, actor.ScopeID, actor.UserID, digest[:], controlTestNow); insertErr != nil {
			return insertErr
		}
		_, updateErr := tx.Exec(t.Context(), `UPDATE notification_control_idempotency_receipts
			SET request_digest=$2 WHERE id=$1`, id, make([]byte, sha256.Size))
		return updateErr
	})
	assertNotificationControlCode091(t, err, "P9102")

	receiptID := uuid.New()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, insertErr := tx.Exec(t.Context(), `INSERT INTO notification_control_idempotency_receipts(
			id,actor_scope_id,actor_user_id,operation,request_key,request_digest,created_at)
			VALUES($1,$2,$3,'notification.channels.update','guarded-receipt',$4,$5)`,
			receiptID, actor.ScopeID, actor.UserID, digest[:], controlTestNow); insertErr != nil {
			return insertErr
		}
		_, updateErr := tx.Exec(t.Context(), `UPDATE notification_control_idempotency_receipts
			SET response_body='{"revision":2}'::jsonb,completed_at=$2 WHERE id=$1`, receiptID, controlTestNow)
		return updateErr
	}); err != nil {
		t.Fatalf("complete receipt once: %v", err)
	}

	for name, statement := range map[string]string{
		"second completion": `UPDATE notification_control_idempotency_receipts SET response_body='{"revision":3}'::jsonb WHERE id='` + receiptID.String() + `'`,
		"delete":            `DELETE FROM notification_control_idempotency_receipts WHERE id='` + receiptID.String() + `'`,
		"truncate":          `TRUNCATE notification_control_idempotency_receipts`,
	} {
		t.Run(name, func(t *testing.T) {
			_, guardErr := pool.Exec(t.Context(), statement)
			assertNotificationControlCode091(t, guardErr, "P9102")
		})
	}
	assertNotificationControlCode091(t, migrateNotificationControlVersion091(t.Context(), pool, "down", 91), "P9101")
}

func TestNotificationControlIdempotencyReceipts091ReplayAuthorizationAndAudit(t *testing.T) {
	pool := notificationControlPool(t)
	actor := seedControlActor(t, pool, "platform", "system_configuration.read", "system_configuration.manage")
	store, err := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	request := UpdateChannelsRequest{
		ExpectedRevision: 1, EmailEnabled: true, RequestID: "receipt-replay-091",
	}
	first, err := store.UpdateChannels(t.Context(), actor, request)
	if err != nil || !first.Changed || first.Revision != 2 {
		t.Fatalf("first update = %+v, %v", first, err)
	}
	replay, err := store.UpdateChannels(t.Context(), actor, request)
	if err != nil || replay != first {
		t.Fatalf("exact replay = %+v, %v, want %+v", replay, err, first)
	}
	changed := request
	changed.EmailEnabled = false
	if _, err := store.UpdateChannels(t.Context(), actor, changed); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("changed digest replay = %v", err)
	}
	assertNotificationControlReceiptAndAudit091(t, pool, request.RequestID, 1, 1)

	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
		actor.ScopeID, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateChannels(t.Context(), actor, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked exact replay = %v, want permission denied", err)
	}
	assertNotificationControlReceiptAndAudit091(t, pool, request.RequestID, 1, 2)
}

func TestNotificationControlIdempotencyReceipts091ConcurrentExactReplay(t *testing.T) {
	pool := notificationControlPool(t)
	actor := seedControlActor(t, pool, "platform", "system_configuration.read", "system_configuration.manage")
	differentActor := seedControlActor(t, pool, "tenant")
	tests := []struct {
		name, operation string
		conflictErr     error
	}{
		{name: "channels", operation: writeOperationChannelsUpdate, conflictErr: ErrVersionConflict},
		{name: "template", operation: writeOperationTemplatePut, conflictErr: ErrTemplateVersionConflict},
		{name: "subscription", operation: writeOperationSubscriptionUpdate, conflictErr: ErrVersionConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestKey := "receipt-conflict-" + test.name
			digest := sha256.Sum256([]byte("notification-control-receipt-conflict:" + test.operation))
			responseValue := map[string]any{"operation": test.operation, "winner": "tx1"}

			tx1Conn, err := pool.Acquire(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx1Conn.Release()
			tx1, err := tx1Conn.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			tx1Committed := false
			defer func() {
				if !tx1Committed {
					_ = tx1.Rollback(context.Background())
				}
			}()
			var tx1PID int32
			if err := tx1.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&tx1PID); err != nil {
				t.Fatal(err)
			}
			receiptID, response, replayed, err := claimNotificationWriteReceipt(
				t.Context(), tx1, actor, test.operation, requestKey, digest, test.conflictErr, controlTestNow,
			)
			if err != nil || receiptID == uuid.Nil || replayed || response != nil {
				t.Fatalf("tx1 claim = %s, %q, %t, %v", receiptID, response, replayed, err)
			}
			if err := completeNotificationWriteReceipt(
				t.Context(), tx1, receiptID, digest, responseValue, controlTestNow,
			); err != nil {
				t.Fatal(err)
			}
			var storedResponse []byte
			if err := tx1.QueryRow(t.Context(), `SELECT response_body
				FROM notification_control_idempotency_receipts WHERE id=$1`, receiptID).Scan(&storedResponse); err != nil {
				t.Fatal(err)
			}

			tx2Conn, err := pool.Acquire(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			tx2, err := tx2Conn.Begin(t.Context())
			if err != nil {
				tx2Conn.Release()
				t.Fatal(err)
			}
			var tx2PID int32
			if err := tx2.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&tx2PID); err != nil {
				_ = tx2.Rollback(context.Background())
				tx2Conn.Release()
				t.Fatal(err)
			}
			workerContext, stopWorker := context.WithTimeout(context.Background(), 15*time.Second)
			defer stopWorker()
			tx2Outcome := make(chan notificationControlReceiptClaimOutcome091, 1)
			tx2Returned := make(chan struct{})
			go func() {
				defer close(tx2Returned)
				defer tx2Conn.Release()
				claimedID, claimedResponse, claimedReplay, claimErr := claimNotificationWriteReceipt(
					workerContext, tx2, actor, test.operation, requestKey, digest, test.conflictErr, controlTestNow,
				)
				if claimErr == nil {
					claimErr = tx2.Commit(workerContext)
				} else {
					_ = tx2.Rollback(context.Background())
				}
				tx2Outcome <- notificationControlReceiptClaimOutcome091{
					receiptID: claimedID, response: claimedResponse, replayed: claimedReplay, err: claimErr,
				}
			}()
			waitNotificationControlReceiptConflict091(t, pool, tx1PID, tx2PID, tx2Returned)

			differentContext, stopDifferent := context.WithTimeout(t.Context(), 5*time.Second)
			defer stopDifferent()
			var differentReceiptID uuid.UUID
			err = pgx.BeginFunc(differentContext, pool, func(tx pgx.Tx) error {
				var claimErr error
				differentReceiptID, response, replayed, claimErr = claimNotificationWriteReceipt(
					differentContext, tx, differentActor, test.operation, requestKey, digest, test.conflictErr, controlTestNow,
				)
				if claimErr != nil {
					return claimErr
				}
				if replayed || response != nil {
					return fmt.Errorf("different identity unexpectedly replayed receipt")
				}
				return completeNotificationWriteReceipt(
					differentContext, tx, differentReceiptID, digest,
					map[string]any{"operation": test.operation, "winner": "different-identity"}, controlTestNow,
				)
			})
			if err != nil || differentReceiptID == uuid.Nil || differentReceiptID == receiptID {
				t.Fatalf("different identity claim = %s, %v", differentReceiptID, err)
			}

			if err := tx1.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			tx1Committed = true
			var outcome notificationControlReceiptClaimOutcome091
			select {
			case outcome = <-tx2Outcome:
			case <-workerContext.Done():
				t.Fatalf("tx2 did not return after tx1 commit: %v", workerContext.Err())
			}
			if outcome.err != nil || !outcome.replayed || outcome.receiptID != receiptID ||
				!bytes.Equal(outcome.response, storedResponse) {
				t.Fatalf("tx2 replay = %s, %q, %t, %v; want %s, %q, true",
					outcome.receiptID, outcome.response, outcome.replayed, outcome.err, receiptID, storedResponse)
			}
			var receiptCount int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_control_idempotency_receipts
				WHERE operation=$1 AND request_key=$2`, test.operation, requestKey).Scan(&receiptCount); err != nil {
				t.Fatal(err)
			}
			if receiptCount != 2 {
				t.Fatalf("receipt identities = %d, want 2", receiptCount)
			}
		})
	}
}

type notificationControlReceiptClaimOutcome091 struct {
	receiptID uuid.UUID
	response  []byte
	replayed  bool
	err       error
}

func waitNotificationControlReceiptConflict091(
	t *testing.T,
	pool *pgxpool.Pool,
	tx1PID, tx2PID int32,
	tx2Returned <-chan struct{},
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		select {
		case <-tx2Returned:
			t.Fatal("tx2 returned before the receipt conflict wait was observed")
		default:
		}
		var exactBlocker, transactionConflict, receiptRelation, receiptInsert bool
		err := pool.QueryRow(ctx, `SELECT
			$1 = ANY(pg_blocking_pids($2)),
			EXISTS (
				SELECT 1 FROM pg_locks waiter JOIN pg_locks holder
				  ON holder.locktype=waiter.locktype AND holder.transactionid=waiter.transactionid
				WHERE waiter.pid=$2 AND waiter.locktype='transactionid' AND waiter.mode='ShareLock'
				  AND NOT waiter.granted AND holder.pid=$1 AND holder.mode='ExclusiveLock' AND holder.granted
			),
			EXISTS (
				SELECT 1 FROM pg_locks WHERE pid=$2 AND locktype='relation'
				  AND relation='notification_control_idempotency_receipts'::regclass
				  AND mode='RowExclusiveLock' AND granted
			),
			EXISTS (
				SELECT 1 FROM pg_stat_activity WHERE pid=$2
				  AND query LIKE '%INSERT INTO notification_control_idempotency_receipts%'
			)`, tx1PID, tx2PID).Scan(&exactBlocker, &transactionConflict, &receiptRelation, &receiptInsert)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			t.Fatal(err)
		}
		if exactBlocker && transactionConflict && receiptRelation && receiptInsert {
			return
		}
	}
	t.Fatal("tx2 did not expose the exact receipt transaction conflict")
}

func TestNotificationControlIdempotencyReceipts091AuditFailureRollsBack(t *testing.T) {
	pool := notificationControlPool(t)
	actor := seedControlActor(t, pool, "platform", "system_configuration.read", "system_configuration.manage")
	injected := errors.New("injected notification control audit failure")
	store, err := NewStoreWithDependencies(pool, notificationControlFailingAuditor091{err: injected}, func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	request := UpdateChannelsRequest{ExpectedRevision: 1, EmailEnabled: true, RequestID: "receipt-audit-failure-091"}
	if _, err := store.UpdateChannels(t.Context(), actor, request); !errors.Is(err, injected) {
		t.Fatalf("audit failure = %v", err)
	}
	var revision int64
	var emailEnabled bool
	if err := pool.QueryRow(t.Context(), `SELECT revision,email_enabled FROM notification_channel_settings WHERE singleton`).Scan(
		&revision, &emailEnabled,
	); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || emailEnabled {
		t.Fatalf("audit failure committed channels revision=%d email=%t", revision, emailEnabled)
	}
	assertNotificationControlReceiptAndAudit091(t, pool, request.RequestID, 0, 0)

	retry, err := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	result, err := retry.UpdateChannels(t.Context(), actor, request)
	if err != nil || !result.Changed || result.Revision != 2 {
		t.Fatalf("retry after audit rollback = %+v, %v", result, err)
	}
	assertNotificationControlReceiptAndAudit091(t, pool, request.RequestID, 1, 1)
}

type notificationControlFailingAuditor091 struct{ err error }

func (auditor notificationControlFailingAuditor091) Append(context.Context, pgx.Tx, audit.Event) error {
	return auditor.err
}

func assertNotificationControlReceiptAndAudit091(
	t *testing.T,
	pool *pgxpool.Pool,
	requestID string,
	wantReceipts, wantAudits int,
) {
	t.Helper()
	var receipts, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM notification_control_idempotency_receipts WHERE request_key=$1),
		(SELECT count(*) FROM audit_events WHERE request_id=$1)`, requestID).Scan(&receipts, &audits); err != nil {
		t.Fatal(err)
	}
	if receipts != wantReceipts || audits != wantAudits {
		t.Fatalf("request %q receipts/audits=%d/%d want=%d/%d",
			requestID, receipts, audits, wantReceipts, wantAudits)
	}
}

func assertNotificationControlReceiptTable091(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema()||'.notification_control_idempotency_receipts') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Fatalf("notification receipt table exists=%t want=%t", exists, want)
	}
}

func assertNotificationControlMigrationHead091(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var count, maximum int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*),COALESCE(max(version),0) FROM schema_migrations`).Scan(
		&count, &maximum,
	); err != nil {
		t.Fatal(err)
	}
	if count != want || maximum != want {
		t.Fatalf("migration ledger count/max=%d/%d want=%d/%d", count, maximum, want, want)
	}
}

func assertNotificationControlCode091(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v, want SQLSTATE %s", err, want)
	}
}

func mustReadNotificationControlMigration091(t *testing.T, name string) string {
	t.Helper()
	payload, err := fs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

//go:linkname migrateNotificationControlFS091 github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migrateNotificationControlFS091(context.Context, *pgxpool.Pool, string, fs.FS) error

func migrateNotificationControlVersion091(
	ctx context.Context,
	pool *pgxpool.Pool,
	direction string,
	target int64,
) error {
	source, err := notificationControlMigrationFS091(target)
	if err != nil {
		return err
	}
	return migrateNotificationControlFS091(ctx, pool, direction, source)
}

func notificationControlMigrationFS091(target int64) (fs.FS, error) {
	files := make(fstest.MapFS, int(target)*2)
	for version := int64(1); version <= target; version++ {
		for _, direction := range []string{"up", "down"} {
			pattern := fmt.Sprintf("%03d_*.%s.sql", version, direction)
			matches, err := fs.Glob(controlmigrations.FS, pattern)
			if err != nil || len(matches) != 1 {
				return nil, fmt.Errorf("resolve migration %03d %s: matches=%v err=%v", version, direction, matches, err)
			}
			content, err := fs.ReadFile(controlmigrations.FS, matches[0])
			if err != nil {
				return nil, err
			}
			files[matches[0]] = &fstest.MapFile{Data: content}
		}
	}
	return files, nil
}

func notificationControlMigrationPool091(t *testing.T, maximum int64) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "notification_receipts_091_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^notification_receipts_091_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop notification receipt schema: %v", err)
		}
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateNotificationControlVersion091(ctx, pool, "up", maximum); err != nil {
		t.Fatalf("apply migrations through %03d: %v", maximum, err)
	}
	return pool
}
