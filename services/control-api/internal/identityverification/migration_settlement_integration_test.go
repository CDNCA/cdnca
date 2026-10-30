//go:build integration

package identityverification

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration037DownRejectsEveryPersistentFactAtomically(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): pin the
	// schema head to 037 for this test.
	pool := isolatedVerificationPool(t, false)
	ctx := context.Background()
	if err := databasetest.MigrateThrough(ctx, pool, "up", 37); err != nil {
		t.Fatal(err)
	}
	for migrationVersion(t, pool) > 37 {
		if err := databasetest.MigrateThrough(ctx, pool, "down", 37); err != nil {
			t.Fatalf("migrate to 037: %v", err)
		}
	}
	now := time.Date(2037, 7, 24, 1, 2, 3, 0, time.UTC)
	facts := []struct {
		name   string
		table  string
		insert string
		args   []any
	}{
		{"write_requests", "identity_verification_write_requests", `INSERT INTO identity_verification_write_requests
			(id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at)
			VALUES($1,$2,$3,'identity_verification.create_draft','down-guard',$4,$5)`,
			[]any{uuid.New(), uuid.New(), uuid.New(), bytesOf(32, 1), now}},
		{"cases", "identity_verification_cases", `INSERT INTO identity_verification_cases
			(id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,revision,
			 created_at,state_changed_at,retention_until)
			VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6)`,
			[]any{uuid.New(), uuid.New(), uuid.New(), bytesOf(32, 2), now, now.Add(time.Hour)}},
		{"materials", "identity_verification_materials", `INSERT INTO identity_verification_materials
			(id,tenant_scope_id,case_id,ordinal,material_kind,envelope_provider,envelope_key_id,
			 encrypted_envelope,envelope_sha256,object_reference,object_sha256,mime_type,size_bytes,created_at)
			VALUES($1,$2,$3,1,'identity_document','test-kms','test-key',$4,$5,'identity/test/object',$6,
			'image/jpeg',1,$7)`, []any{uuid.New(), uuid.New(), uuid.New(), bytesOf(16, 3),
			bytesOf(32, 4), bytesOf(32, 5), now}},
		{"state_events", "identity_verification_state_events", `INSERT INTO identity_verification_state_events
			(id,tenant_scope_id,case_id,case_revision,from_status,to_status,actor_user_id,reason_code,occurred_at)
			VALUES($1,$2,$3,1,NULL,'draft',$4,'case.created',$5)`,
			[]any{uuid.New(), uuid.New(), uuid.New(), uuid.New(), now}},
		{"submissions", "identity_verification_submissions", `INSERT INTO identity_verification_submissions
			(id,tenant_scope_id,case_id,applicant_user_id,case_revision,submission_digest,submitted_at,expires_at)
			VALUES($1,$2,$3,$4,2,$5,$6,$7)`, []any{uuid.New(), uuid.New(), uuid.New(), uuid.New(),
			bytesOf(32, 6), now, now.Add(time.Hour)}},
		{"review_assignments", "identity_verification_review_assignments", `INSERT INTO identity_verification_review_assignments
			(id,tenant_scope_id,case_id,reviewer_user_id,case_revision,assigned_at)
			VALUES($1,$2,$3,$4,2,$5)`, []any{uuid.New(), uuid.New(), uuid.New(), uuid.New(), now}},
		{"reviews", "identity_verification_reviews", `INSERT INTO identity_verification_reviews
			(id,tenant_scope_id,case_id,reviewer_user_id,decision,reason_code,expected_revision,
			 resulting_revision,reviewed_at)
			VALUES($1,$2,$3,$4,'rejected','evidence_incomplete',2,3,$5)`,
			[]any{uuid.New(), uuid.New(), uuid.New(), uuid.New(), now}},
		{"verified_persons", "identity_verified_persons", `INSERT INTO identity_verified_persons
			(tenant_scope_id,applicant_user_id,identity_fingerprint,initial_case_id,approved_at)
			VALUES($1,$2,$3,$4,$5)`, []any{uuid.New(), uuid.New(), bytesOf(32, 7), uuid.New(), now}},
		{"verified_organizations", "identity_verified_organizations", `INSERT INTO identity_verified_organizations
			(tenant_scope_id,subject_fingerprint,organization_name,legal_person_fingerprint,
			 agent_fingerprint,agent_relationship,approved_case_id,approved_at)
			VALUES($1,$2,'Guard Organization',$3,$4,'authorized_representative',$5,$6)`,
			[]any{uuid.New(), bytesOf(32, 8), bytesOf(32, 9), bytesOf(32, 10), uuid.New(), now}},
	}
	for _, fact := range facts {
		t.Run(fact.name, func(t *testing.T) {
			replicaExec(t, pool, fact.insert, fact.args...)
			assertMigrationSQLState(t, databasetest.MigrateThrough(ctx, pool, "down", 37), "55000")
			assertMigration037Intact(t, pool)
			var count int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{fact.table}.Sanitize()).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("%s fact count after failed down = %d", fact.table, count)
			}
			replicaExec(t, pool, "DELETE FROM "+pgx.Identifier{fact.table}.Sanitize())
		})
	}
}

func TestMigration037DownRejectsAuditResourceAndActionFacts(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): pin the
	// schema head to 037 for this test.
	pool := isolatedVerificationPool(t, false)
	ctx := context.Background()
	if err := databasetest.MigrateThrough(ctx, pool, "up", 37); err != nil {
		t.Fatal(err)
	}
	for migrationVersion(t, pool) > 37 {
		if err := databasetest.MigrateThrough(ctx, pool, "down", 37); err != nil {
			t.Fatal(err)
		}
	}
	// Today's audit writer needs 361's unified-log columns.
	databasetest.AddUnifiedAuditColumns(t, pool)
	scopeID := insertTenantScope(t, pool, "Migration 037 Audit Guard")
	appendMigrationAudit(t, pool, scopeID, "other.action", "identity_verification_case")
	assertMigrationSQLState(t, databasetest.MigrateThrough(ctx, pool, "down", 37), "55000")
	assertMigration037Intact(t, pool)
	replicaExec(t, pool, `DELETE FROM audit_events WHERE scope_id=$1`, scopeID)

	appendMigrationAudit(t, pool, scopeID, "identity_verification.guard", "other_resource")
	assertMigrationSQLState(t, databasetest.MigrateThrough(ctx, pool, "down", 37), "55000")
	assertMigration037Intact(t, pool)
}

func TestMigration037DownClosesFactAndAuditInsertionWindow(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): pin the
	// schema head to 037 for this test.
	pool := isolatedVerificationPool(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if err := databasetest.MigrateThrough(ctx, pool, "up", 37); err != nil {
		t.Fatal(err)
	}
	for migrationVersion(t, pool) > 37 {
		if err := databasetest.MigrateThrough(ctx, pool, "down", 37); err != nil {
			t.Fatal(err)
		}
	}
	scopeID := insertTenantScope(t, pool, "Migration 037 Race")
	actor := insertActor(t, pool, scopeID, "migration-037-race", permissionSelfManage)
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		_ = blocker.Rollback(cleanupCtx)
	}()
	if _, err := blocker.Exec(ctx, `SELECT count(*) FROM audit_events`); err != nil {
		t.Fatal(err)
	}

	downCtx, cancelDown := context.WithCancel(ctx)
	defer cancelDown()
	downResult := make(chan error, 1)
	go func() { downResult <- databasetest.MigrateThrough(downCtx, pool, "down", 37) }()
	waitForMigrationLocks(t, pool, `
		EXISTS (SELECT 1 FROM pg_locks lock_row JOIN pg_class relation ON relation.oid=lock_row.relation
			WHERE relation.relname='identity_verification_cases' AND lock_row.mode='AccessExclusiveLock'
			  AND lock_row.granted)
		AND EXISTS (SELECT 1 FROM pg_locks lock_row JOIN pg_class relation ON relation.oid=lock_row.relation
			WHERE relation.relname='audit_events' AND lock_row.mode='ShareRowExclusiveLock'
			  AND lock_row.granted)
		AND EXISTS (SELECT 1 FROM pg_locks lock_row JOIN pg_class relation ON relation.oid=lock_row.relation
			WHERE relation.relname='audit_events' AND lock_row.mode='AccessExclusiveLock'
			  AND NOT lock_row.granted)`)

	writeCtx, cancelWrite := context.WithCancel(ctx)
	auditCtx, cancelAudit := context.WithCancel(ctx)
	writeResult := make(chan error, 1)
	auditResult := make(chan error, 1)
	downCollected, writeCollected, auditCollected := false, false, false
	blockerReleased := false
	defer func() {
		cancelDown()
		cancelWrite()
		cancelAudit()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		if !blockerReleased {
			_ = blocker.Rollback(cleanupCtx)
		}
		for result, collected := range map[<-chan error]*bool{
			downResult: &downCollected, writeResult: &writeCollected, auditResult: &auditCollected,
		} {
			if *collected {
				continue
			}
			select {
			case <-result:
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
	go func() {
		_, writeErr := pool.Exec(writeCtx, `INSERT INTO identity_verification_write_requests
			(id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at)
			VALUES($1,$2,$3,'identity_verification.create_draft','race-window',$4,$5)`,
			uuid.New(), scopeID, actor.UserID, bytesOf(32, 0x91), time.Now())
		writeResult <- writeErr
	}()
	go func() {
		auditResult <- appendAuditContext(auditCtx, pool, scopeID,
			"identity_verification.race", "identity_verification_case")
	}()
	assertStillBlocked(t, ctx, writeResult, "identity verification write insertion")
	assertStillBlocked(t, ctx, auditResult, "identity verification audit insertion")

	cancelWrite()
	cancelAudit()
	cancelDown()
	if err := blocker.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	blockerReleased = true
	if err := receiveWorker(ctx, writeResult); err == nil {
		t.Fatal("blocked identity verification write unexpectedly committed")
	}
	writeCollected = true
	if err := receiveWorker(ctx, auditResult); err == nil {
		t.Fatal("blocked identity verification audit unexpectedly committed")
	}
	auditCollected = true
	if err := receiveWorker(ctx, downResult); err == nil {
		t.Fatal("canceled migration 037 down unexpectedly committed")
	}
	downCollected = true
	assertMigration037Intact(t, pool)
}

func TestMigration068LegacyBackfillNewCaseAndDownFacts(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): pin the
	// schema head to 068 for this test.
	pool := isolatedVerificationPool(t, false)
	ctx := context.Background()
	if err := databasetest.MigrateThrough(ctx, pool, "up", 68); err != nil {
		t.Fatal(err)
	}
	migrateDownToVersion(t, pool, 68)
	if migrationVersion(t, pool) != 68 {
		t.Fatalf("migration head = %d, want 68", migrationVersion(t, pool))
	}
	if err := databasetest.MigrateThrough(ctx, pool, "down", 68); err != nil {
		t.Fatalf("empty migration 068 down: %v", err)
	}
	if migrationVersion(t, pool) != 67 {
		t.Fatalf("migration after 068 down = %d", migrationVersion(t, pool))
	}

	// The tenant_viewer system role is assigned after the roll forward: one
	// present at 147 makes 148's sites.export backfill trip the 094 system-role
	// guard, a state no supported install reaches (tenant roles are created at
	// the release head).
	scopeID := insertTenantScope(t, pool, "Migration 068 Legacy")
	actor := insertActorWithoutViewer(t, pool, scopeID, "migration-legacy", permissionSelfManage)
	legacyActor := actor.Actor
	now := time.Date(2038, 7, 24, 1, 2, 3, 0, time.UTC)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	legacyID := insertRawDraft(t, tx, legacyActor, now, 0x71)
	insertRawMaterial(t, tx, legacyActor, legacyID, now, 1, MaterialIdentityDocument, 0x72)
	insertRawMaterial(t, tx, legacyActor, legacyID, now, 2, MaterialLivenessEvidence, 0x73)
	insertRawCreationEvent(t, tx, legacyActor, legacyID, now)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 68); err != nil {
		t.Fatalf("migration 068 up with legacy case: %v", err)
	}
	var required bool
	if err := pool.QueryRow(ctx, `SELECT evidence_settlement_required
		FROM identity_verification_cases WHERE id=$1`, legacyID).Scan(&required); err != nil {
		t.Fatal(err)
	}
	if required {
		t.Fatal("legacy identity verification case unexpectedly requires settlement")
	}
	// The current service needs the release head; 068's own checks above ran on
	// the 068 schema.
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("roll forward to release head: %v", err)
	}
	assignTenantViewerRole(t, pool, scopeID, actor.UserID)
	service := newAuthorizedTestService(t, pool, audit.New(pool), Config{Clock: func() time.Time { return now },
		ReviewTTL: time.Hour, RetentionPeriod: 24 * time.Hour})
	legacyCase := Case{ID: legacyID, TenantScopeID: scopeID, ApplicantUserID: actor.UserID,
		Status: StatusDraft, Revision: 1}
	if submitted, err := service.Submit(ctx, actor.Actor, mutation(legacyCase, "legacy-submit")); err != nil || submitted.Status != StatusSubmitted {
		t.Fatalf("legacy case submit = %#v, %v", submitted, err)
	}

	assertSQLRejected(t, pool, "new identity verification cases require evidence settlement", `
		INSERT INTO identity_verification_cases (
			id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,revision,
			created_at,state_changed_at,retention_until,evidence_settlement_required
		) VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6,false)`,
		uuid.New(), scopeID, actor.UserID, bytesOf(32, 0x74), now, now.Add(time.Hour))

	replicaExec(t, pool, `INSERT INTO identity_verification_evidence_settlements (
		id,tenant_scope_id,actor_user_id,case_id,write_request_id,operation,idempotency_key,
		request_digest,evidence_claim_digest,resolver_name,resolver_reference,state,revision,
		attempt_count,available_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,'identity_verification.create_draft','down-settlement',$6,$7,
		'test-resolver','down-settlement-reference','commit_pending',1,0,$8,$8,$8)`,
		uuid.New(), scopeID, actor.UserID, uuid.New(), uuid.New(), bytesOf(32, 0x75), bytesOf(32, 0x76), now)
	// At the release head, run 068's down script itself: settlement facts must
	// block it.
	downScript, err := fs.ReadFile(controlmigrations.FS, "068_identity_verification_evidence_settlement.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	assertMigrationSQLState(t, pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, string(downScript))
		return execErr
	}), "55000")
	assertMigrationVersion(t, pool, 68, true)
}

func TestMigration068DeferredResponseRequiresExactTenantApplicantBinding(t *testing.T) {
	for _, tamperedField := range []string{"tenant_scope_id", "applicant_user_id"} {
		t.Run(tamperedField, func(t *testing.T) {
			// Migration 268 cannot be rolled back; pin the schema head to 068.
			pool := isolatedVerificationPool(t, false)
			if err := databasetest.MigrateThrough(t.Context(), pool, "up", 68); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			migrateDownToVersion(t, pool, 67)
			if err := databasetest.MigrateThrough(ctx, pool, "up", 68); err != nil {
				t.Fatalf("migration 068 up: %v", err)
			}

			scopeID := insertTenantScope(t, pool, "Migration 068 Response Binding")
			actor := insertActor(t, pool, scopeID, "migration-response-binding", permissionSelfManage)
			now := time.Date(2038, 8, 24, 1, 2, 3, 0, time.UTC)
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeID, caseID := uuid.New(), uuid.New()
			key := "response-binding-" + tamperedField
			digest := bytesOf(32, 0x77)
			if _, err := tx.Exec(ctx, `INSERT INTO identity_verification_write_requests (
				id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at
			) VALUES($1,$2,$3,'identity_verification.create_draft',$4,$5,$6)`, writeID,
				scopeID, actor.UserID, key, digest, now); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO identity_verification_cases (
				id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,
				revision,created_at,state_changed_at,retention_until
			) VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6)`, caseID,
				scopeID, actor.UserID, bytesOf(32, 0x78), now, now.Add(24*time.Hour)); err != nil {
				t.Fatal(err)
			}
			insertRawMaterial(t, tx, actor.Actor, caseID, now, 1, MaterialIdentityDocument, 0x79)
			insertRawMaterial(t, tx, actor.Actor, caseID, now, 2, MaterialLivenessEvidence, 0x7a)
			insertRawCreationEvent(t, tx, actor.Actor, caseID, now)
			if _, err := tx.Exec(ctx, `INSERT INTO identity_verification_evidence_settlements (
				id,tenant_scope_id,actor_user_id,case_id,write_request_id,operation,idempotency_key,
				request_digest,evidence_claim_digest,resolver_name,resolver_reference,state,revision,
				attempt_count,available_at,created_at,updated_at
			) VALUES($1,$2,$3,$4,$5,'identity_verification.create_draft',$6,$7,$8,
				'test-resolver',$9,'commit_pending',1,0,$10,$10,$10)`, uuid.New(), scopeID,
				actor.UserID, caseID, writeID, key, digest, bytesOf(32, 0x7b),
				"response-binding-reference-"+tamperedField, now); err != nil {
				t.Fatal(err)
			}
			responseScopeID, responseApplicantID := scopeID, actor.UserID
			if tamperedField == "tenant_scope_id" {
				responseScopeID = uuid.New()
			} else {
				responseApplicantID = uuid.New()
			}
			if _, err := tx.Exec(ctx, `UPDATE identity_verification_write_requests
				SET response_body=jsonb_build_object(
					'id',$2::text,'tenant_scope_id',$3::text,'applicant_user_id',$4::text
				),completed_at=$5 WHERE id=$1`, writeID, caseID, responseScopeID,
				responseApplicantID, now); err != nil {
				t.Fatal(err)
			}
			assertCommitRejected(t, tx, "evidence settlement binding is incomplete")
		})
	}
}

func TestMigration068DownRejectsRequiredCaseAndSettlementAudit(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): pin the
	// schema head to 068 for this test.
	pool := isolatedVerificationPool(t, false)
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 68); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	migrateDownToVersion(t, pool, 68)
	now := time.Date(2039, 7, 24, 1, 2, 3, 0, time.UTC)
	requiredCaseID := uuid.New()
	replicaExec(t, pool, `INSERT INTO identity_verification_cases (
		id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,revision,
		created_at,state_changed_at,retention_until,evidence_settlement_required)
		VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6,true)`, requiredCaseID,
		uuid.New(), uuid.New(), bytesOf(32, 0x81), now, now.Add(time.Hour))
	assertMigrationSQLState(t, databasetest.MigrateThrough(ctx, pool, "down", 68), "55000")
	assertMigrationVersion(t, pool, 68, true)
	replicaExec(t, pool, `DELETE FROM identity_verification_cases WHERE id=$1`, requiredCaseID)

	// Today's audit writer needs 361's unified-log columns.
	databasetest.AddUnifiedAuditColumns(t, pool)
	scopeID := insertTenantScope(t, pool, "Migration 068 Audit Guard")
	appendMigrationAudit(t, pool, scopeID, "identity_verification.evidence_settlement.failed",
		"identity_verification_evidence_settlement")
	assertMigrationSQLState(t, databasetest.MigrateThrough(ctx, pool, "down", 68), "55000")
	assertMigrationVersion(t, pool, 68, true)
}

func TestMigration068DownClosesSettlementAndAuditInsertionWindow(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): pin the
	// schema head to 068 for this test.
	pool := isolatedVerificationPool(t, false)
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 68); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	migrateDownToVersion(t, pool, 68)
	scopeID := insertTenantScope(t, pool, "Migration 068 Race")
	actor := insertActor(t, pool, scopeID, "migration-068-race", permissionSelfManage)
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		_ = blocker.Rollback(cleanupCtx)
	}()
	if _, err := blocker.Exec(ctx, `SELECT count(*) FROM identity_verification_write_requests`); err != nil {
		t.Fatal(err)
	}

	downCtx, cancelDown := context.WithCancel(ctx)
	defer cancelDown()
	downResult := make(chan error, 1)
	go func() { downResult <- databasetest.MigrateThrough(downCtx, pool, "down", 68) }()
	waitForMigrationLocks(t, pool, `
		EXISTS (SELECT 1 FROM pg_locks lock_row JOIN pg_class relation ON relation.oid=lock_row.relation
			WHERE relation.relname='identity_verification_evidence_settlements'
			  AND lock_row.mode='AccessExclusiveLock' AND lock_row.granted)
		AND EXISTS (SELECT 1 FROM pg_locks lock_row JOIN pg_class relation ON relation.oid=lock_row.relation
			WHERE relation.relname='audit_events' AND lock_row.mode='ShareRowExclusiveLock'
			  AND lock_row.granted)
		AND EXISTS (SELECT 1 FROM pg_locks lock_row JOIN pg_class relation ON relation.oid=lock_row.relation
			WHERE relation.relname='identity_verification_write_requests'
			  AND lock_row.mode='AccessExclusiveLock' AND NOT lock_row.granted)`)

	caseCtx, cancelCase := context.WithCancel(ctx)
	auditCtx, cancelAudit := context.WithCancel(ctx)
	caseResult := make(chan error, 1)
	auditResult := make(chan error, 1)
	downCollected, caseCollected, auditCollected := false, false, false
	blockerReleased := false
	defer func() {
		cancelDown()
		cancelCase()
		cancelAudit()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		if !blockerReleased {
			_ = blocker.Rollback(cleanupCtx)
		}
		for result, collected := range map[<-chan error]*bool{
			downResult: &downCollected, caseResult: &caseCollected, auditResult: &auditCollected,
		} {
			if *collected {
				continue
			}
			select {
			case <-result:
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
	go func() {
		_, insertErr := pool.Exec(caseCtx, `INSERT INTO identity_verification_cases (
			id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,revision,
			created_at,state_changed_at,retention_until)
			VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6)`, uuid.New(), scopeID,
			actor.UserID, bytesOf(32, 0x92), time.Now(), time.Now().Add(time.Hour))
		caseResult <- insertErr
	}()
	go func() {
		auditResult <- appendAuditContext(auditCtx, pool, scopeID,
			"identity_verification.evidence_settlement.race", "identity_verification_evidence_settlement")
	}()
	assertStillBlocked(t, ctx, caseResult, "required case insertion")
	assertStillBlocked(t, ctx, auditResult, "settlement audit insertion")
	cancelCase()
	cancelAudit()
	cancelDown()
	if err := blocker.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	blockerReleased = true
	if err := receiveWorker(ctx, caseResult); err == nil {
		t.Fatal("blocked required case unexpectedly committed")
	}
	caseCollected = true
	if err := receiveWorker(ctx, auditResult); err == nil {
		t.Fatal("blocked settlement audit unexpectedly committed")
	}
	auditCollected = true
	if err := receiveWorker(ctx, downResult); err == nil {
		t.Fatal("canceled migration 068 down unexpectedly committed")
	}
	downCollected = true
	assertMigrationVersion(t, pool, 68, true)
	assertTable(t, pool, "identity_verification_evidence_settlements", true)
}

func migrateDownToVersion(t *testing.T, pool *pgxpool.Pool, target int64) {
	t.Helper()
	for current := migrationVersion(t, pool); current > target; current = migrationVersion(t, pool) {
		// Load only 1..current so a rollback never needs a version above 268.
		if err := databasetest.MigrateThrough(t.Context(), pool, "down", current); err != nil {
			t.Fatalf("migrate down to %d: %v", target, err)
		}
	}
	if version := migrationVersion(t, pool); version != target {
		t.Fatalf("migration version = %d, want %d", version, target)
	}
}

func replicaExec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(context.Background(), `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.Exec(context.Background(), `SET session_replication_role = origin`); err != nil {
			t.Errorf("restore session_replication_role: %v", err)
		}
	}()
	if _, err := conn.Exec(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func assertMigrationSQLState(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("migration error = %v, want SQLSTATE %s", err, code)
	}
}

func assertMigration037Intact(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	assertMigrationVersion(t, pool, 37, true)
	assertTable(t, pool, "identity_verification_write_requests", true)
	assertTable(t, pool, "identity_verification_cases", true)
	assertTrigger(t, pool, "audit_events", "audit_events_no_truncate", true)
	var functionPresent bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regprocedure(
		'identity_verification_actor_has_permission(uuid,uuid,text)') IS NOT NULL`).Scan(&functionPresent); err != nil {
		t.Fatal(err)
	}
	if !functionPresent {
		t.Fatal("identity verification permission function was dropped by failed migration")
	}
	var permissionCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM permissions
		WHERE name IN ('identity_verification.self.manage','identity_verification.read',
		'identity_verification.review')`).Scan(&permissionCount); err != nil {
		t.Fatal(err)
	}
	if permissionCount != 3 {
		t.Fatalf("identity verification permissions after failed down = %d", permissionCount)
	}
}

func appendMigrationAudit(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, action, resourceType string) {
	t.Helper()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	if err := audit.New(pool).Append(context.Background(), tx, audit.Event{ScopeID: scopeID,
		Action: action, ResourceType: resourceType, ResourceID: uuid.NewString(),
		RequestID: "migration-guard", Result: "success", Payload: map[string]any{"result": "guard"}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func appendAuditContext(ctx context.Context, pool *pgxpool.Pool, scopeID uuid.UUID,
	action, resourceType string,
) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	if err := audit.New(pool).Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: action,
		ResourceType: resourceType, ResourceID: uuid.NewString(), RequestID: "migration-race",
		Result: "success", Payload: map[string]any{"result": "race"}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func waitForMigrationLocks(t *testing.T, pool *pgxpool.Pool, expression string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		var ready bool
		if err := pool.QueryRow(ctx, "SELECT "+expression).Scan(&ready); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	t.Fatalf("migration did not reach guarded lock window: %v", ctx.Err())
}

func assertStillBlocked(t *testing.T, parent context.Context, result <-chan error, label string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 200*time.Millisecond)
	defer cancel()
	select {
	case err := <-result:
		t.Fatalf("%s crossed migration guard: %v", label, err)
	case <-ctx.Done():
	}
}
