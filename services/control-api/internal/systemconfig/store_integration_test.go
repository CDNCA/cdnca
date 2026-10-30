package systemconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
	_ "unsafe"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:linkname migrateSystemConfigVersionIsolatedFS github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migrateSystemConfigVersionIsolatedFS(context.Context, *pgxpool.Pool, string, fs.FS) error

var systemConfigTestNow = time.Date(2026, 7, 22, 12, 0, 0, 123456000, time.UTC)

var errInjectedAudit = errors.New("injected audit failure")

type failingAuditor struct{}

func (failingAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errInjectedAudit
}

type systemConfigFixture struct {
	pool     *pgxpool.Pool
	service  *Service
	platform Actor
	tenant   Actor
	clock    *systemConfigClock
}

type systemConfigClock struct {
	mu    sync.Mutex
	value time.Time
}

func (clock *systemConfigClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.value
}

func (clock *systemConfigClock) Set(value time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.value = value
}

type blockingAuditor struct {
	delegate AuditAppender
	reached  chan struct{}
	release  chan struct{}
}

func (auditor *blockingAuditor) Append(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	if err := auditor.delegate.Append(ctx, tx, event); err != nil {
		return err
	}
	close(auditor.reached)
	select {
	case <-auditor.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestSystemConfigurationMigrationUpDownUp(t *testing.T) {
	pool := isolatedSystemConfigPoolAtVersion(t, 35)
	if !migrationApplied(t, pool, 35) {
		t.Fatal("migration 35 is not recorded after migration up")
	}
	if !relationExists(t, pool, "system_configuration_revisions") {
		t.Fatal("system configuration relation is missing after migration up")
	}
	if err := applySystemConfigMigration(context.Background(), pool, "down"); err != nil {
		t.Fatalf("migration down: %v", err)
	}
	if relationExists(t, pool, "system_configuration_revisions") || migrationApplied(t, pool, 35) {
		t.Fatal("migration 35 objects or ledger entry remain after down")
	}
	if err := applySystemConfigMigration(context.Background(), pool, "up"); err != nil {
		t.Fatalf("migration re-up: %v", err)
	}
	if !relationExists(t, pool, "system_configuration_revisions") || !migrationApplied(t, pool, 35) {
		t.Fatal("migration 35 did not apply after down/up")
	}
}

func TestSystemConfigurationMigrationDownRejectsPopulatedFactsAtomically(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	if _, err := fixture.service.CreateDraft(context.Background(), fixture.platform,
		createDraftRequest(0, "down-populated", validConfiguration())); err != nil {
		t.Fatal(err)
	}
	beforePermissions := countPermissionRows(t, fixture.pool)
	err := applySystemConfigMigration(context.Background(), fixture.pool, "down")
	assertPGTriggerError(t, err, "system configuration migration 035 down refused: facts exist")
	if !migrationApplied(t, fixture.pool, 35) ||
		!relationExists(t, fixture.pool, "system_configuration_revisions") ||
		countRows(t, fixture.pool, "system_configuration_streams") != 1 ||
		countRows(t, fixture.pool, "system_configuration_revisions") != 1 ||
		countRows(t, fixture.pool, "system_configuration_write_requests") != 1 ||
		countPermissionRows(t, fixture.pool) != beforePermissions {
		t.Fatal("failed populated down did not preserve ledger, facts, permissions, and schema objects atomically")
	}
}

func TestSystemConfigurationDatabaseAcceptsServiceCanonicalSnapshot(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	for _, test := range []struct {
		name          string
		configuration Configuration
	}{
		{name: "distinct references", configuration: validConfiguration()},
		{name: "same value references", configuration: func() Configuration {
			configuration := validConfiguration()
			shared := &RevisionReference{ID: uuid.MustParse("10000000-0000-0000-0000-000000000001"), Revision: 3}
			configuration.Defaults.SiteTemplate = shared
			configuration.Defaults.CachePolicy = shared
			return configuration
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, snapshot, hash, err := CanonicalSnapshot(test.configuration)
			if err != nil {
				t.Fatal(err)
			}
			hashBytes, err := hex.DecodeString(hash)
			if err != nil {
				t.Fatal(err)
			}
			var snapshotValid, digestValid, actorValid bool
			if err := fixture.pool.QueryRow(context.Background(), `SELECT
				system_configuration_snapshot_is_valid($1),sha256($1)=$2,
				system_configuration_actor_has_permission($3,$4,'system_configuration.manage')`,
				snapshot, hashBytes, fixture.platform.ScopeID, fixture.platform.UserID).
				Scan(&snapshotValid, &digestValid, &actorValid); err != nil {
				t.Fatal(err)
			}
			if !snapshotValid || !digestValid || !actorValid {
				t.Fatalf("database canonical prerequisites: snapshot=%t digest=%t actor=%t",
					snapshotValid, digestValid, actorValid)
			}
		})
	}
}

func TestSystemConfigurationLifecycleCASRollbackAndAuditAtomicity(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	ctx := context.Background()

	createOne := createDraftRequest(0, "draft-one", validConfiguration())
	draftOne, err := fixture.service.CreateDraft(ctx, fixture.platform, createOne)
	if err != nil {
		t.Fatal(err)
	}
	if draftOne.Revision != 1 || draftOne.Status != StatusDraft ||
		!draftOne.CreatedAt.Equal(systemConfigTestNow) || !draftOne.StateChangedAt.Equal(systemConfigTestNow) {
		t.Fatalf("unexpected first draft: %#v", draftOne)
	}
	assertMaskedRevision(t, draftOne)

	replayed, err := fixture.service.CreateDraft(ctx, fixture.platform, createOne)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Revision != draftOne.Revision || countRows(t, fixture.pool, "system_configuration_revisions") != 1 {
		t.Fatalf("unexpected create replay: %#v", replayed)
	}
	conflicting := createOne
	conflicting.Configuration.Nginx.WorkerConnections = 2048
	if _, err := fixture.service.CreateDraft(ctx, fixture.platform, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different payload replay error = %v, want ErrIdempotencyConflict", err)
	}

	validatedOne, err := fixture.service.RecordPreflight(ctx, fixture.platform,
		passingPreflight(1, draftOne.SnapshotSHA256, "preflight-one"))
	if err != nil {
		t.Fatal(err)
	}
	if validatedOne.Status != StatusValidated {
		t.Fatalf("preflight status = %q, want validated", validatedOne.Status)
	}
	activeOne, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 1, ExpectedActiveRevision: 0, IdempotencyKey: "activate-one", RequestID: "activate-one",
	})
	if err != nil {
		t.Fatal(err)
	}
	if activeOne.Status != StatusActive {
		t.Fatalf("active status = %q", activeOne.Status)
	}

	configurationTwo := validConfiguration()
	configurationTwo.Nginx.WorkerConnections = 2048
	draftTwo, err := fixture.service.CreateDraft(ctx, fixture.platform,
		createDraftRequest(1, "draft-two", configurationTwo))
	if err != nil {
		t.Fatal(err)
	}
	configurationThree := validConfiguration()
	configurationThree.Nginx.WorkerConnections = 3072
	draftThree, err := fixture.service.CreateDraft(ctx, fixture.platform,
		createDraftRequest(2, "draft-three", configurationThree))
	if err != nil {
		t.Fatal(err)
	}

	stalePreflight := passingPreflight(2, draftOne.SnapshotSHA256, "preflight-stale")
	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform, stalePreflight); !errors.Is(err, ErrPreflightHash) {
		t.Fatalf("stale preflight error = %v, want ErrPreflightHash", err)
	}
	if got, err := fixture.service.GetRevision(ctx, fixture.platform, 2); err != nil || got.Status != StatusDraft {
		t.Fatalf("stale preflight changed draft: revision=%#v error=%v", got, err)
	}
	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform,
		passingPreflight(2, draftTwo.SnapshotSHA256, "preflight-two")); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform,
		passingPreflight(3, draftThree.SnapshotSHA256, "preflight-three")); err != nil {
		t.Fatal(err)
	}

	type activationResult struct {
		revision Revision
		err      error
	}
	start := make(chan struct{})
	results := make(chan activationResult, 2)
	var wait sync.WaitGroup
	for _, revision := range []int64{2, 3} {
		wait.Add(1)
		go func(revision int64) {
			defer wait.Done()
			<-start
			item, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
				Revision: revision, ExpectedActiveRevision: 1,
				IdempotencyKey: "activate-race-" + string(rune('0'+revision)),
				RequestID:      "activate-race-" + string(rune('0'+revision)),
			})
			results <- activationResult{item, err}
		}(revision)
	}
	close(start)
	wait.Wait()
	close(results)
	var winner int64
	var successes, conflicts int
	for result := range results {
		if result.err == nil {
			successes++
			winner = result.revision.Revision
		} else if errors.Is(result.err, ErrRevisionConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent activation error: %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 || (winner != 2 && winner != 3) {
		t.Fatalf("activation race successes=%d conflicts=%d winner=%d", successes, conflicts, winner)
	}
	if countStatus(t, fixture.pool, StatusActive) != 1 {
		t.Fatal("concurrent activation produced more than one active revision")
	}

	rollback, err := fixture.service.Rollback(ctx, fixture.platform, RollbackRequest{
		TargetRevision: 1, ExpectedHeadRevision: 3, ExpectedActiveRevision: winner,
		IdempotencyKey: "rollback-one", RequestID: "rollback-one",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rollback.Revision != 4 || rollback.Status != StatusDraft || rollback.SourceRevision == nil ||
		*rollback.SourceRevision != 1 || rollback.SnapshotSHA256 != draftOne.SnapshotSHA256 {
		t.Fatalf("unexpected rollback revision: %#v", rollback)
	}
	if _, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 4, ExpectedActiveRevision: winner, IdempotencyKey: "activate-unchecked", RequestID: "activate-unchecked",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unchecked rollback activation error = %v, want ErrInvalidTransition", err)
	}
	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform,
		passingPreflight(4, rollback.SnapshotSHA256, "preflight-rollback")); err != nil {
		t.Fatal(err)
	}
	activeRollback, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 4, ExpectedActiveRevision: winner, IdempotencyKey: "activate-rollback", RequestID: "activate-rollback",
	})
	if err != nil || activeRollback.Status != StatusActive {
		t.Fatalf("activate rollback: revision=%#v error=%v", activeRollback, err)
	}

	configurationFive := validConfiguration()
	configurationFive.Nginx.GzipLevel = 5
	draftFive, err := fixture.service.CreateDraft(ctx, fixture.platform,
		createDraftRequest(4, "draft-five", configurationFive))
	if err != nil {
		t.Fatal(err)
	}
	failedChecks := passingChecks()
	for index := range failedChecks {
		if failedChecks[index].Name == PreflightNginxSafety {
			failedChecks[index].Status = CheckFail
			failedChecks[index].Code = "nginx.precheck_failed"
		}
	}
	rejected, err := fixture.service.RecordPreflight(ctx, fixture.platform, RecordPreflightRequest{
		Revision: 5, ExpectedStatus: StatusDraft, SnapshotSHA256: draftFive.SnapshotSHA256,
		Checks:         failedChecks,
		IdempotencyKey: "preflight-five-fail", RequestID: "preflight-five-fail",
	})
	if err != nil || rejected.Status != StatusRejected {
		t.Fatalf("reject failed preflight: revision=%#v error=%v", rejected, err)
	}
	if _, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 5, ExpectedActiveRevision: 4, IdempotencyKey: "activate-rejected", RequestID: "activate-rejected",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("rejected activation error = %v, want ErrInvalidTransition", err)
	}

	beforeRevisions := countRows(t, fixture.pool, "system_configuration_revisions")
	beforeWrites := countRows(t, fixture.pool, "system_configuration_write_requests")
	beforeAudits := countRows(t, fixture.pool, "audit_events")
	failing, err := NewServiceWithDependencies(fixture.pool, failingAuditor{}, func() time.Time { return systemConfigTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.CreateDraft(ctx, fixture.platform,
		createDraftRequest(5, "audit-failure", validConfiguration())); !errors.Is(err, errInjectedAudit) {
		t.Fatalf("audit failure error = %v, want injected failure", err)
	}
	if countRows(t, fixture.pool, "system_configuration_revisions") != beforeRevisions ||
		countRows(t, fixture.pool, "system_configuration_write_requests") != beforeWrites ||
		countRows(t, fixture.pool, "audit_events") != beforeAudits || streamHead(t, fixture.pool) != 5 {
		t.Fatal("audit failure did not roll back configuration, idempotency, and audit writes")
	}

	if _, err := fixture.service.CreateDraft(ctx, fixture.tenant,
		createDraftRequest(0, "tenant-denied", validConfiguration())); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant create error = %v, want ErrPermissionDenied", err)
	}
	if countRows(t, fixture.pool, "system_configuration_revisions") != beforeRevisions {
		t.Fatal("tenant denial mutated system configuration")
	}
	if beforeAudits != 13 {
		t.Fatalf("audit count = %d, want 13 successful mutations", beforeAudits)
	}
	assertNoPlaintextColumns(t, fixture.pool)
}

func TestSystemConfigurationDatabaseMutationGuards(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	ctx := context.Background()
	request := createDraftRequest(0, "guard-draft", validConfiguration())
	draft, err := fixture.service.CreateDraft(ctx, fixture.platform, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform,
		passingPreflight(1, draft.SnapshotSHA256, "guard-preflight")); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 1, ExpectedActiveRevision: 0,
		IdempotencyKey: "guard-activate", RequestID: "guard-activate",
	}); err != nil {
		t.Fatal(err)
	}
	replayed, err := fixture.service.CreateDraft(ctx, fixture.platform, request)
	if err != nil || !replayed.Replayed {
		t.Fatalf("normal idempotency replay regressed: revision=%#v error=%v", replayed, err)
	}
	type protectedState struct {
		streamCount, revisionCount, preflightCount, writeCount int
		head, active                                           int64
		revisionStatus                                         string
		canonicalSnapshot, revisionHash, preflightHash         []byte
		checks                                                 string
		passed                                                 bool
		performedAt, expiresAt                                 time.Time
	}
	readProtectedState := func() protectedState {
		state := protectedState{
			streamCount:    countRows(t, fixture.pool, "system_configuration_streams"),
			revisionCount:  countRows(t, fixture.pool, "system_configuration_revisions"),
			preflightCount: countRows(t, fixture.pool, "system_configuration_preflights"),
			writeCount:     countRows(t, fixture.pool, "system_configuration_write_requests"),
		}
		if err := fixture.pool.QueryRow(ctx, `SELECT head_revision,active_revision
			FROM system_configuration_streams WHERE platform_scope_id=$1`, fixture.platform.ScopeID).
			Scan(&state.head, &state.active); err != nil {
			t.Fatal(err)
		}
		if err := fixture.pool.QueryRow(ctx, `SELECT status,canonical_snapshot,snapshot_sha256
			FROM system_configuration_revisions WHERE platform_scope_id=$1 AND revision=1`, fixture.platform.ScopeID).
			Scan(&state.revisionStatus, &state.canonicalSnapshot, &state.revisionHash); err != nil {
			t.Fatal(err)
		}
		if err := fixture.pool.QueryRow(ctx, `SELECT snapshot_sha256,passed,checks::text,performed_at,expires_at
			FROM system_configuration_preflights
			WHERE platform_scope_id=$1 AND revision=1 AND preflight_sequence=1`, fixture.platform.ScopeID).
			Scan(&state.preflightHash, &state.passed, &state.checks, &state.performedAt, &state.expiresAt); err != nil {
			t.Fatal(err)
		}
		return state
	}
	assertProtectedState := func(want protectedState) {
		got := readProtectedState()
		if got.streamCount != want.streamCount || got.revisionCount != want.revisionCount ||
			got.preflightCount != want.preflightCount || got.writeCount != want.writeCount ||
			got.head != want.head || got.active != want.active || got.revisionStatus != want.revisionStatus ||
			!bytes.Equal(got.canonicalSnapshot, want.canonicalSnapshot) ||
			!bytes.Equal(got.revisionHash, want.revisionHash) ||
			!bytes.Equal(got.preflightHash, want.preflightHash) || got.checks != want.checks ||
			got.passed != want.passed || !got.performedAt.Equal(want.performedAt) || !got.expiresAt.Equal(want.expiresAt) {
			t.Fatalf("protected facts changed after rejected SQL:\n got=%#v\nwant=%#v", got, want)
		}
	}
	beforeDirectSQL := readProtectedState()
	for _, test := range []struct {
		name, sql, message string
	}{
		{
			name: "delete stream", sql: `DELETE FROM system_configuration_streams WHERE platform_scope_id=$1`,
			message: "invalid system configuration stream transition",
		},
		{
			name: "decrement stream head", sql: `UPDATE system_configuration_streams
				SET head_revision=head_revision-1 WHERE platform_scope_id=$1`,
			message: "invalid system configuration stream transition",
		},
		{
			name: "clear active stream pointer", sql: `UPDATE system_configuration_streams
				SET active_revision=NULL WHERE platform_scope_id=$1`,
			message: "system configuration active revision transition is inconsistent",
		},
		{
			name: "delete revision", sql: `DELETE FROM system_configuration_revisions
				WHERE platform_scope_id=$1 AND revision=1`,
			message: "system configuration revisions cannot be deleted",
		},
		{
			name: "update immutable revision snapshot", sql: `UPDATE system_configuration_revisions
				SET canonical_snapshot=canonical_snapshot || convert_to(' ', 'UTF8')
				WHERE platform_scope_id=$1 AND revision=1`,
			message: "invalid system configuration revision transition",
		},
		{
			name: "update preflight", sql: `UPDATE system_configuration_preflights
				SET checks=checks WHERE platform_scope_id=$1 AND revision=1`,
			message: "system configuration preflights are append-only",
		},
		{
			name: "delete preflight", sql: `DELETE FROM system_configuration_preflights
				WHERE platform_scope_id=$1 AND revision=1`,
			message: "system configuration preflights are append-only",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertRejectedTransaction(t, fixture.pool, test.message, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, test.sql, fixture.platform.ScopeID)
				return err
			})
			assertProtectedState(beforeDirectSQL)
		})
	}

	_, err = fixture.pool.Exec(ctx, `INSERT INTO system_configuration_write_requests (
		id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,
		request_digest,response_body,created_at,completed_at
	) VALUES($1,$2,$3,$3,'system_configuration.create_draft',$4,$5,$6,$7,$7)`,
		uuid.New(), fixture.platform.UserID, fixture.platform.ScopeID, "direct-completed",
		make([]byte, 32), []byte(`{"revision":99}`), systemConfigTestNow)
	assertPGTriggerError(t, err, "system configuration write request must start incomplete")

	_, err = fixture.pool.Exec(ctx, `UPDATE system_configuration_write_requests
		SET response_body='{"revision":2}'::jsonb,completed_at=completed_at
		WHERE actor_user_id=$1 AND operation='system_configuration.create_draft' AND idempotency_key='guard-draft'`,
		fixture.platform.UserID)
	assertPGTriggerError(t, err, "invalid system configuration write request transition")
	_, err = fixture.pool.Exec(ctx, `DELETE FROM system_configuration_write_requests
		WHERE actor_user_id=$1 AND operation='system_configuration.create_draft' AND idempotency_key='guard-draft'`,
		fixture.platform.UserID)
	assertPGTriggerError(t, err, "invalid system configuration write request transition")

	for _, table := range []string{
		"system_configuration_streams",
		"system_configuration_revisions",
		"system_configuration_preflights",
		"system_configuration_write_requests",
	} {
		_, err := fixture.pool.Exec(ctx, "TRUNCATE "+pgx.Identifier{table}.Sanitize()+" CASCADE")
		assertPGTriggerError(t, err, "system configuration table "+table+" cannot be truncated")
		assertProtectedState(beforeDirectSQL)
	}
	if countRows(t, fixture.pool, "system_configuration_streams") != 1 ||
		countRows(t, fixture.pool, "system_configuration_revisions") != 1 ||
		countRows(t, fixture.pool, "system_configuration_preflights") != 1 ||
		countRows(t, fixture.pool, "system_configuration_write_requests") != 3 {
		t.Fatal("database mutation guard failure changed protected rows")
	}
}

func TestSystemConfigurationDatabaseRejectsForgedFactsAndProjectionDrift(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	ctx := context.Background()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO system_configuration_streams(
		platform_scope_id,head_revision,created_at,updated_at) VALUES($1,0,$2,$2)`,
		fixture.platform.ScopeID, systemConfigTestNow); err != nil {
		t.Fatal(err)
	}
	_, snapshot, snapshotHash, err := CanonicalSnapshot(validConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	hashBytes, err := hex.DecodeString(snapshotHash)
	if err != nil {
		t.Fatal(err)
	}

	insertRevision := func(tx pgx.Tx, revision int64, status string, raw, digest []byte) error {
		_, err := tx.Exec(ctx, `INSERT INTO system_configuration_revisions(
			platform_scope_id,revision,status,canonical_schema,canonical_snapshot,snapshot_sha256,
			created_by_user_id,created_by_scope_id,created_at,state_changed_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$1,$8,$8)`, fixture.platform.ScopeID, revision,
			status, canonicalSchema, raw, digest, fixture.platform.UserID, systemConfigTestNow)
		return err
	}
	for _, test := range []struct {
		name     string
		revision int64
		status   string
		raw      []byte
		digest   []byte
	}{
		{name: "invalid canonical and forged digest", revision: 1, status: StatusDraft, raw: []byte("x"), digest: make([]byte, 32)},
		{name: "non draft insert", revision: 1, status: StatusActive, raw: snapshot, digest: hashBytes},
		{name: "head jump", revision: 100, status: StatusDraft, raw: snapshot, digest: hashBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertRejectedTransaction(t, fixture.pool, "invalid system configuration revision insert", func(tx pgx.Tx) error {
				return insertRevision(tx, test.revision, test.status, test.raw, test.digest)
			})
			if countRows(t, fixture.pool, "system_configuration_revisions") != 0 || streamHead(t, fixture.pool) != 0 {
				t.Fatal("rejected revision transaction left facts behind")
			}
		})
	}
	whitespaceSnapshot := append([]byte{'{', ' '}, snapshot[1:]...)
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(snapshot, &envelope); err != nil {
		t.Fatal(err)
	}
	keyOrderSnapshot := bytes.Join([][]byte{
		[]byte(`{"configuration":`), envelope["configuration"],
		[]byte(`,"schema":`), envelope["schema"], []byte(`}`),
	}, nil)
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "non canonical whitespace", raw: whitespaceSnapshot},
		{name: "non canonical key order", raw: keyOrderSnapshot},
	} {
		t.Run(test.name, func(t *testing.T) {
			if bytes.Equal(test.raw, snapshot) {
				t.Fatal("test mutation did not change canonical bytes")
			}
			digest := sha256.Sum256(test.raw)
			assertRejectedTransaction(t, fixture.pool, "invalid system configuration revision insert", func(tx pgx.Tx) error {
				return insertRevision(tx, 1, StatusDraft, test.raw, digest[:])
			})
			if countRows(t, fixture.pool, "system_configuration_revisions") != 0 || streamHead(t, fixture.pool) != 0 {
				t.Fatal("non-canonical revision transaction left facts behind")
			}
		})
	}
	_, err = fixture.pool.Exec(ctx, `INSERT INTO system_configuration_revisions(
		platform_scope_id,revision,status,canonical_schema,canonical_snapshot,snapshot_sha256,
		created_by_user_id,created_by_scope_id,created_at,state_changed_at
	) VALUES($1,1,'draft',$2,$3,$4,$5,$1,'infinity'::timestamptz,'infinity'::timestamptz)`,
		fixture.platform.ScopeID, canonicalSchema, snapshot, hashBytes, fixture.platform.UserID)
	assertPGErrorCode(t, err, "23514")
	if countRows(t, fixture.pool, "system_configuration_revisions") != 0 {
		t.Fatal("rejected infinite revision timestamp left facts behind")
	}

	draft, err := fixture.service.CreateDraft(ctx, fixture.platform,
		createDraftRequest(0, "direct-guard-draft", validConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	insertPreflight := func(tx pgx.Tx, passed bool, checks []byte, expiresAt time.Time) error {
		_, err := tx.Exec(ctx, `INSERT INTO system_configuration_preflights(
			platform_scope_id,revision,preflight_sequence,snapshot_sha256,passed,checks,
			performed_by_user_id,performed_by_scope_id,performed_at,expires_at
		) VALUES($1,1,1,$2,$3,$4,$5,$1,$6,$7)`, fixture.platform.ScopeID, hashBytes,
			passed, checks, fixture.platform.UserID, systemConfigTestNow, expiresAt)
		return err
	}
	validChecks, err := json.Marshal(passingChecks())
	if err != nil {
		t.Fatal(err)
	}
	largeChecks := passingChecks()
	for index := range largeChecks {
		largeChecks[index].Detail = strings.Repeat("𐀀", 512)
	}
	largeChecksJSON, err := json.Marshal(largeChecks)
	if err != nil {
		t.Fatal(err)
	}
	unknownChecks := passingChecks()
	unknownChecks[0].Name = "forged"
	unknownChecksJSON, err := json.Marshal(unknownChecks)
	if err != nil {
		t.Fatal(err)
	}
	duplicateChecks := passingChecks()
	duplicateChecks[0].Name = duplicateChecks[1].Name
	duplicateChecksJSON, err := json.Marshal(duplicateChecks)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		passed    bool
		checks    []byte
		expiresAt time.Time
	}{
		{name: "unknown check in exact five", passed: true, checks: unknownChecksJSON, expiresAt: systemConfigTestNow.Add(preflightTTL)},
		{name: "duplicate check in exact five", passed: true, checks: duplicateChecksJSON, expiresAt: systemConfigTestNow.Add(preflightTTL)},
		{name: "passed mismatch", passed: false, checks: validChecks, expiresAt: systemConfigTestNow.Add(preflightTTL)},
		{name: "checks byte overflow", passed: true, checks: largeChecksJSON, expiresAt: systemConfigTestNow.Add(preflightTTL)},
		{name: "invalid preflight ttl", passed: true, checks: validChecks, expiresAt: systemConfigTestNow.Add(preflightTTL + time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertRejectedTransaction(t, fixture.pool, "invalid system configuration preflight", func(tx pgx.Tx) error {
				return insertPreflight(tx, test.passed, test.checks, test.expiresAt)
			})
			if countRows(t, fixture.pool, "system_configuration_preflights") != 0 {
				t.Fatal("rejected preflight transaction left facts behind")
			}
		})
	}
	_, err = fixture.pool.Exec(ctx, `INSERT INTO system_configuration_preflights(
		platform_scope_id,revision,preflight_sequence,snapshot_sha256,passed,checks,
		performed_by_user_id,performed_by_scope_id,performed_at,expires_at
	) VALUES($1,1,1,$2,true,$3,$4,$1,'infinity'::timestamptz,'infinity'::timestamptz)`,
		fixture.platform.ScopeID, hashBytes, validChecks, fixture.platform.UserID)
	assertPGErrorCode(t, err, "23514")
	if countRows(t, fixture.pool, "system_configuration_preflights") != 0 {
		t.Fatal("rejected infinite preflight timestamp left facts behind")
	}

	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform,
		passingPreflight(1, draft.SnapshotSHA256, "direct-guard-preflight")); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 1, ExpectedActiveRevision: 0,
		IdempotencyKey: "direct-guard-activate", RequestID: "direct-guard-activate",
	}); err != nil {
		t.Fatal(err)
	}
	assertRejectedTransaction(t, fixture.pool, "inconsistent system configuration stream projection", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE system_configuration_revisions
			SET status='superseded',state_changed_at=state_changed_at + interval '1 microsecond'
			WHERE platform_scope_id=$1 AND revision=1`, fixture.platform.ScopeID)
		return err
	})
	var status string
	var active int64
	if err := fixture.pool.QueryRow(ctx, `SELECT revision.status,stream.active_revision
		FROM system_configuration_streams stream
		JOIN system_configuration_revisions revision
		  ON revision.platform_scope_id=stream.platform_scope_id AND revision.revision=stream.active_revision
		WHERE stream.platform_scope_id=$1`, fixture.platform.ScopeID).Scan(&status, &active); err != nil {
		t.Fatal(err)
	}
	if status != StatusActive || active != 1 {
		t.Fatalf("projection drift transaction was not fully rolled back: status=%s active=%d", status, active)
	}
}

func TestSystemConfigurationAuthorizationRevocationIsLinearizable(t *testing.T) {
	t.Run("revocation commits first", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			sql       string
			usesScope bool
		}{
			{name: "account", sql: `UPDATE users SET status='disabled' WHERE id=$1`},
			{name: "membership", sql: `UPDATE memberships SET status='suspended' WHERE scope_id=$2 AND user_id=$1`, usesScope: true},
			{name: "assignment", sql: `DELETE FROM role_assignments WHERE scope_id=$2 AND user_id=$1`, usesScope: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				fixture := newSystemConfigFixture(t)
				arguments := []any{fixture.platform.UserID}
				if test.usesScope {
					arguments = append(arguments, fixture.platform.ScopeID)
				}
				if _, err := fixture.pool.Exec(context.Background(), test.sql, arguments...); err != nil {
					t.Fatal(err)
				}
				if _, err := fixture.service.CreateDraft(context.Background(), fixture.platform,
					createDraftRequest(0, "revoked-first-"+test.name, validConfiguration())); !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("revoked actor error = %v, want ErrPermissionDenied", err)
				}
				if countRows(t, fixture.pool, "system_configuration_revisions") != 0 ||
					countRows(t, fixture.pool, "system_configuration_write_requests") != 0 ||
					countRows(t, fixture.pool, "audit_events") != 0 {
					t.Fatal("revoked request created configuration, idempotency, or audit side effects")
				}
			})
		}
	})

	t.Run("business commits before permission revocation", func(t *testing.T) {
		fixture := newSystemConfigFixture(t)
		blocker := &blockingAuditor{
			delegate: audit.New(fixture.pool), reached: make(chan struct{}), release: make(chan struct{}),
		}
		service, err := NewServiceWithDependencies(fixture.pool, blocker, fixture.clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		request := createDraftRequest(0, "business-first", validConfiguration())
		businessDone := make(chan error, 1)
		go func() {
			_, err := service.CreateDraft(context.Background(), fixture.platform, request)
			businessDone <- err
		}()
		select {
		case <-blocker.reached:
		case <-time.After(5 * time.Second):
			t.Fatal("business transaction did not reach audit append")
		}

		revokeDone := make(chan error, 1)
		go func() {
			_, err := fixture.pool.Exec(context.Background(), `DELETE FROM role_permissions permission
				USING roles role WHERE permission.role_id=role.id AND role.scope_id=$1
				AND permission.permission_name='system_configuration.manage'`, fixture.platform.ScopeID)
			revokeDone <- err
		}()
		select {
		case err := <-revokeDone:
			t.Fatalf("permission revocation bypassed in-flight authorization locks: %v", err)
		case <-time.After(150 * time.Millisecond):
		}
		close(blocker.release)
		if err := <-businessDone; err != nil {
			t.Fatalf("business-first mutation failed: %v", err)
		}
		if err := <-revokeDone; err != nil {
			t.Fatalf("permission revocation after business commit: %v", err)
		}
		beforeRevisions := countRows(t, fixture.pool, "system_configuration_revisions")
		beforeWrites := countRows(t, fixture.pool, "system_configuration_write_requests")
		beforeAudits := countRows(t, fixture.pool, "audit_events")
		if _, err := service.CreateDraft(context.Background(), fixture.platform, request); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("replay after revocation error = %v, want ErrPermissionDenied", err)
		}
		if countRows(t, fixture.pool, "system_configuration_revisions") != beforeRevisions ||
			countRows(t, fixture.pool, "system_configuration_write_requests") != beforeWrites ||
			countRows(t, fixture.pool, "audit_events") != beforeAudits {
			t.Fatal("denied replay after revocation created idempotency or audit side effects")
		}
	})
}

func TestSystemConfigurationPreflightExpiryRenewalAndClockRollback(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	ctx := context.Background()
	draft, err := fixture.service.CreateDraft(ctx, fixture.platform,
		createDraftRequest(0, "expiry-draft", validConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	original := passingPreflight(1, draft.SnapshotSHA256, "expiry-preflight")
	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform, original); err != nil {
		t.Fatal(err)
	}
	var originalExpiry time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT expires_at FROM system_configuration_preflights
		WHERE platform_scope_id=$1 AND revision=1 AND preflight_sequence=1`, fixture.platform.ScopeID).Scan(&originalExpiry); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Set(originalExpiry)
	beforeWrites := countRows(t, fixture.pool, "system_configuration_write_requests")
	beforeAudits := countRows(t, fixture.pool, "audit_events")
	if _, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 1, ExpectedActiveRevision: 0,
		IdempotencyKey: "expiry-boundary", RequestID: "expiry-boundary",
	}); !errors.Is(err, ErrPreflightExpired) {
		t.Fatalf("exact expiry boundary error = %v, want ErrPreflightExpired", err)
	}
	if countRows(t, fixture.pool, "system_configuration_write_requests") != beforeWrites ||
		countRows(t, fixture.pool, "audit_events") != beforeAudits {
		t.Fatal("expired activation left idempotency or audit side effects")
	}

	fixture.clock.Set(originalExpiry.Add(-time.Microsecond))
	if _, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 1, ExpectedActiveRevision: 0,
		IdempotencyKey: "clock-rollback", RequestID: "clock-rollback",
	}); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("clock rollback error = %v, want ErrClockRollback", err)
	}

	fixture.clock.Set(originalExpiry.Add(time.Microsecond))
	renewedRequest := passingPreflight(1, draft.SnapshotSHA256, "expiry-renewed")
	renewedRequest.ExpectedStatus = StatusValidated
	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform, renewedRequest); err != nil {
		t.Fatal(err)
	}
	var renewedExpiry time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT expires_at FROM system_configuration_preflights
		WHERE platform_scope_id=$1 AND revision=1 AND preflight_sequence=2`, fixture.platform.ScopeID).Scan(&renewedExpiry); err != nil {
		t.Fatal(err)
	}
	replayed, err := fixture.service.RecordPreflight(ctx, fixture.platform, original)
	if err != nil || !replayed.Replayed {
		t.Fatalf("old preflight idempotency replay: revision=%#v error=%v", replayed, err)
	}
	var latestExpiry time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT max(expires_at) FROM system_configuration_preflights
		WHERE platform_scope_id=$1 AND revision=1`, fixture.platform.ScopeID).Scan(&latestExpiry); err != nil {
		t.Fatal(err)
	}
	if countRows(t, fixture.pool, "system_configuration_preflights") != 2 ||
		!latestExpiry.Equal(renewedExpiry) || !renewedExpiry.After(originalExpiry) {
		t.Fatal("old preflight replay refreshed or replaced the renewed preflight")
	}
	if _, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
		Revision: 1, ExpectedActiveRevision: 0,
		IdempotencyKey: "expiry-renewed-activate", RequestID: "expiry-renewed-activate",
	}); err != nil {
		t.Fatalf("activate with renewed preflight: %v", err)
	}
}

func createDraftRequest(expected int64, key string, configuration Configuration) CreateDraftRequest {
	return CreateDraftRequest{
		ExpectedHeadRevision: expected, Configuration: configuration,
		IdempotencyKey: key, RequestID: key,
	}
}

func passingPreflight(revision int64, hash, key string) RecordPreflightRequest {
	return RecordPreflightRequest{
		Revision: revision, ExpectedStatus: StatusDraft, SnapshotSHA256: hash,
		Checks:         passingChecks(),
		IdempotencyKey: key, RequestID: key,
	}
}

func assertMaskedRevision(t *testing.T, revision Revision) {
	t.Helper()
	secret := revision.Configuration.Secrets.ErrorPageStorage
	if secret == nil || !secret.Masked || secret.Reference == "vault:error-pages/prod-html" || !strings.HasPrefix(secret.Reference, "****") {
		t.Fatalf("revision secret was not masked: %#v", secret)
	}
	encoded, err := json.Marshal(revision)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "vault:error-pages/prod-html") {
		t.Fatalf("revision response leaked secret reference: %s", encoded)
	}
}

func newSystemConfigFixture(t *testing.T) systemConfigFixture {
	t.Helper()
	pool := isolatedSystemConfigPool(t)
	platform := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	tenant := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	insertActor(t, pool, platform, "system-platform", uuid.Nil)
	insertActor(t, pool, tenant, "system-tenant", uuid.New())
	clock := &systemConfigClock{value: systemConfigTestNow}
	service, err := NewServiceWithDependencies(pool, audit.New(pool), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	return systemConfigFixture{pool: pool, service: service, platform: platform, tenant: tenant, clock: clock}
}

func insertActor(t *testing.T, pool *pgxpool.Pool, actor Actor, username string, tenantID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if actor.ScopeKind == "tenant" {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, username); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, actor.ScopeID, tenantID); err != nil {
			t.Fatal(err)
		}
	} else if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, actor.ScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'test-password-hash')`, actor.UserID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, actor.ScopeID, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if actor.ScopeKind == "platform" {
		roleID := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,system_role)
			VALUES($1,$2,'platform_owner',true)`, roleID, actor.ScopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,'system_configuration.read'),($1,'system_configuration.manage')`, roleID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, actor.ScopeID, actor.UserID, roleID); err != nil {
			t.Fatal(err)
		}
	}
}

func assertNoPlaintextColumns(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name LIKE 'system_configuration_%'
		AND (column_name LIKE '%plaintext%' OR column_name IN ('secret', 'ciphertext', 'secret_value'))`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("found %d forbidden plaintext/ciphertext columns", count)
	}
}

func assertPGTriggerError(t *testing.T, err error, message string) {
	t.Helper()
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "P0001" || databaseError.Message != message {
		t.Fatalf("database error = %v, want trigger P0001 %q", err, message)
	}
}

func assertPGErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != code {
		t.Fatalf("database error = %v, want SQLSTATE %s", err, code)
	}
}

func assertRejectedTransaction(t *testing.T, pool *pgxpool.Pool, message string, run func(pgx.Tx) error) {
	t.Helper()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = run(tx)
	if err == nil {
		err = tx.Commit(context.Background())
	} else {
		_ = tx.Rollback(context.Background())
	}
	assertPGTriggerError(t, err, message)
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countPermissionRows(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM permissions
		WHERE name IN ('system_configuration.read','system_configuration.manage')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countStatus(t *testing.T, pool *pgxpool.Pool, status string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM system_configuration_revisions WHERE status=$1`, status).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func streamHead(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var revision int64
	if err := pool.QueryRow(context.Background(), `SELECT head_revision FROM system_configuration_streams`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

func relationExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func migrationApplied(t *testing.T, pool *pgxpool.Pool, version int64) bool {
	t.Helper()
	var applied bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS(
		SELECT 1 FROM schema_migrations WHERE version=$1
	)`, version).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	return applied
}

func applySystemConfigMigration(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	name := "035_system_configuration." + direction + ".sql"
	script, err := fs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		if direction == "down" {
			_, err = tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=35`)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(35)`)
		}
		return err
	})
}

func isolatedSystemConfigPool(t *testing.T) *pgxpool.Pool {
	return isolatedSystemConfigPoolAtVersion(t, 0)
}

func isolatedSystemConfigPoolAtVersion(t *testing.T, maximum int64) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "system_config_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^system_config_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("refusing unexpected schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	var migrateErr error
	if maximum == 0 {
		migrateErr = database.Migrate(ctx, pool, "up")
	} else {
		source, err := systemConfigVersionIsolatedMigrationFS(maximum)
		if err != nil {
			pool.Close()
			_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
			admin.Close()
			t.Fatal(err)
		}
		migrateErr = migrateSystemConfigVersionIsolatedFS(ctx, pool, "up", source)
	}
	if migrateErr != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("migrate isolated system configuration schema: %v", migrateErr)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated system configuration schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func systemConfigVersionIsolatedMigrationFS(maximum int64) (fs.FS, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("system configuration migration target must be positive: %d", maximum)
	}
	files := make(fstest.MapFS, int(maximum)*2)
	for version := int64(1); version <= maximum; version++ {
		for _, direction := range []string{"up", "down"} {
			pattern := fmt.Sprintf("%03d_*.%s.sql", version, direction)
			matches, err := fs.Glob(controlmigrations.FS, pattern)
			if err != nil || len(matches) != 1 {
				return nil, fmt.Errorf("resolve migration %03d %s: matches=%v err=%v",
					version, direction, matches, err)
			}
			content, err := fs.ReadFile(controlmigrations.FS, matches[0])
			if err != nil {
				return nil, fmt.Errorf("read migration %q: %w", matches[0], err)
			}
			files[matches[0]] = &fstest.MapFile{Data: content}
		}
	}
	return files, nil
}
