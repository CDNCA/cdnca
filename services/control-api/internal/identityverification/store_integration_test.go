//go:build integration

package identityverification

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errInjectedIdentityAudit = errors.New("injected identity verification audit failure")

type fixedClock struct {
	mu    sync.RWMutex
	value time.Time
}

func (clock *fixedClock) now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.value
}

func (clock *fixedClock) set(value time.Time) {
	clock.mu.Lock()
	clock.value = value
	clock.mu.Unlock()
}

type failingAudit struct{}

func (failingAudit) Append(context.Context, pgx.Tx, audit.Event) error {
	return errInjectedIdentityAudit
}

type testActor struct {
	Actor
	roleID           uuid.UUID
	grantID          uuid.UUID
	managerUserID    uuid.UUID
	managerSessionID uuid.UUID
}

type verificationFixture struct {
	pool          *pgxpool.Pool
	clock         *fixedClock
	service       *Service
	applicant     testActor
	reviewer      testActor
	unauthorized  testActor
	otherReviewer testActor
	otherScope    uuid.UUID
}

func TestIdentityVerificationMigrationRoundTrip(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): round-trip 037
	// with only 1..037 loaded, then roll forward to the release head.
	pool := isolatedVerificationPool(t, false)
	ctx := context.Background()
	if err := databasetest.MigrateThrough(ctx, pool, "up", 37); err != nil {
		t.Fatal(err)
	}
	assertMigrationVersion(t, pool, 37, true)
	assertTable(t, pool, "identity_verification_cases", true)
	for migrationVersion(t, pool) > 37 {
		if err := databasetest.MigrateThrough(ctx, pool, "down", 37); err != nil {
			t.Fatalf("migrate down: %v", err)
		}
	}
	assertTrigger(t, pool, "audit_events", "audit_events_no_truncate", true)
	if err := databasetest.MigrateThrough(ctx, pool, "down", 37); err != nil {
		t.Fatalf("migrate 037 down: %v", err)
	}
	assertTable(t, pool, "identity_verification_cases", false)
	assertMigrationVersion(t, pool, 37, false)
	assertTrigger(t, pool, "audit_events", "audit_events_no_truncate", false)

	scopeID := insertTenantScope(t, pool, "Migration Permission Tenant")
	ownerRoleID := insertSystemRole(t, pool, scopeID, "tenant_owner")
	viewerRoleID := insertSystemRole(t, pool, scopeID, "tenant_viewer")
	// Roll forward through 068, which adds the settlement requeue permission
	// asserted below; later migrations are not part of this round trip.
	if err := databasetest.MigrateThrough(ctx, pool, "up", 68); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
	assertMigrationVersion(t, pool, 37, true)
	assertTable(t, pool, "identity_verification_reviews", true)
	assertRolePermissions(t, pool, ownerRoleID, []string{
		permissionSettlementRequeue, permissionRead, permissionReview, permissionSelfManage,
	})
	assertRolePermissions(t, pool, viewerRoleID, []string{permissionSelfManage})
}

func TestDatabaseCreationWriteRequestAndPermissionGuards(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx := context.Background()
	now := fixture.clock.now()

	assertSQLRejected(t, fixture.pool, "must start as a valid revision 1 draft", `
		INSERT INTO identity_verification_cases (
			id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,reviewer_user_id,
			revision,created_at,state_changed_at,submitted_at,expires_at,terminal_at,retention_until
		) VALUES($1,$2,$3,'personal_initial','approved',$4,$5,4,$6,$7,$6,$8,$7,$9)`,
		uuid.New(), fixture.applicant.ScopeID, fixture.applicant.UserID, bytesOf(32, 0x81),
		fixture.reviewer.UserID, now, now.Add(time.Hour), now.Add(2*time.Hour), now.Add(24*time.Hour))
	assertSQLRejected(t, fixture.pool, "must start as a valid revision 1 draft", `
		INSERT INTO identity_verification_cases (
			id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,
			revision,created_at,state_changed_at,retention_until
		) VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$6,$7)`,
		uuid.New(), fixture.applicant.ScopeID, fixture.applicant.UserID, bytesOf(32, 0x82),
		now, now.Add(time.Minute), now.Add(24*time.Hour))

	assertSQLRejected(t, fixture.pool, "requires an exact revision 1 creation event", `
		INSERT INTO identity_verification_cases (
			id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,
			revision,created_at,state_changed_at,retention_until
		) VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6)`,
		uuid.New(), fixture.applicant.ScopeID, fixture.applicant.UserID, bytesOf(32, 0x82),
		now, now.Add(24*time.Hour))

	emptyTx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	emptyCaseID := insertRawDraft(t, emptyTx, fixture.applicant.Actor, now, 0x83)
	insertRawCreationEvent(t, emptyTx, fixture.applicant.Actor, emptyCaseID, now)
	assertCommitRejected(t, emptyTx, "requires a contiguous compliant material set")

	missingTx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	missingCaseID := insertRawDraft(t, missingTx, fixture.applicant.Actor, now, 0x84)
	insertRawMaterial(t, missingTx, fixture.applicant.Actor, missingCaseID, now, 1,
		MaterialIdentityDocument, 0x85)
	insertRawMaterial(t, missingTx, fixture.applicant.Actor, missingCaseID, now, 2,
		MaterialSupplementary, 0x86)
	insertRawCreationEvent(t, missingTx, fixture.applicant.Actor, missingCaseID, now)
	assertCommitRejected(t, missingTx, "personal identity verification draft has an invalid material set")

	assertSQLRejected(t, fixture.pool, "must be inserted unfinished", `
		INSERT INTO identity_verification_write_requests (
			id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			response_body,created_at,completed_at
		) VALUES($1,$2,$3,'identity_verification.create_draft','forged-complete',$4,'{}'::jsonb,$5,$5)`,
		uuid.New(), fixture.applicant.ScopeID, fixture.applicant.UserID, bytesOf(32, 0x87), now)
	assertSQLRejected(t, fixture.pool, "write requests cannot be truncated",
		`TRUNCATE identity_verification_write_requests CASCADE`)

	viewerDraft, err := fixture.service.CreateDraft(ctx, fixture.unauthorized.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x88), "viewer-self"))
	if err != nil {
		t.Fatal(err)
	}
	assertSQLRejected(t, fixture.pool, "invalid identity verification write request transition", `
		UPDATE identity_verification_write_requests
		SET response_body=response_body,completed_at=completed_at
		WHERE tenant_scope_id=$1 AND actor_user_id=$2
		  AND operation='identity_verification.create_draft' AND idempotency_key='viewer-self'`,
		fixture.unauthorized.ScopeID, fixture.unauthorized.UserID)
	if _, err := fixture.service.Get(ctx, fixture.unauthorized.Actor, viewerDraft.ID); err != nil {
		t.Fatalf("viewer Get(self) error = %v", err)
	}
	otherDraft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x89), "viewer-other"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Get(ctx, fixture.unauthorized.Actor, otherDraft.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer Get(other user) error = %v", err)
	}
	// Another member's case is read through the reviewer path (read+review);
	// Get is the applicant's own read (identity_verification.self.manage).
	if _, err := fixture.service.GetForReview(ctx, fixture.reviewer.Actor, otherDraft.ID); err != nil {
		t.Fatalf("explicit read Get(other user) error = %v", err)
	}
}

func TestRevokedReviewerCannotInsertDecisionFacts(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx := context.Background()
	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x91), "revoked-reviewer"))
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
	submitted, err := fixture.service.Submit(ctx, fixture.applicant.Actor, mutation(draft, "revoked-submit"))
	if err != nil {
		t.Fatal(err)
	}
	reviewing, err := fixture.service.StartReview(ctx, fixture.reviewer.Actor,
		mutation(submitted, "revoked-start"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.reviewer.ScopeID,
		fixture.reviewer.UserID, fixture.reviewer.roleID); err != nil {
		t.Fatal(err)
	}
	assertSQLRejected(t, fixture.pool, "review does not match current assignment", `
		INSERT INTO identity_verification_reviews (
			id,tenant_scope_id,case_id,reviewer_user_id,decision,reason_code,
			expected_revision,resulting_revision,reviewed_at
		) VALUES($1,$2,$3,$4,'rejected','evidence_incomplete',$5,$6,$7)`,
		uuid.New(), fixture.reviewer.ScopeID, reviewing.ID, fixture.reviewer.UserID,
		reviewing.Revision, reviewing.Revision+1, fixture.clock.now())
	assertSQLRejected(t, fixture.pool, "decision actor mismatch", `
		INSERT INTO identity_verification_state_events (
			id,tenant_scope_id,case_id,case_revision,from_status,to_status,
			actor_user_id,reason_code,occurred_at
		) VALUES($1,$2,$3,$4,'reviewing','rejected',$5,'review.decided',$6)`,
		uuid.New(), fixture.reviewer.ScopeID, reviewing.ID, reviewing.Revision+1,
		fixture.reviewer.UserID, fixture.clock.now())
	if _, err := fixture.service.Review(ctx, fixture.reviewer.Actor, ReviewRequest{
		CaseID: reviewing.ID, ExpectedRevision: reviewing.Revision, Decision: DecisionReject,
		ReasonCode: ReasonEvidenceIncomplete, IdempotencyKey: "revoked-decision",
		RequestID: "revoked-decision-request",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Review(revoked reviewer) error = %v", err)
	}
}

func TestPersonalReverificationEnterpriseIsolationAndRedaction(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx := context.Background()
	identityFingerprint := bytesOf(32, 0x21)

	draftRequest := validPersonalDraft(KindPersonalInitial, identityFingerprint, "personal-initial")
	rawObjectReference := "identity/private/initial-document"
	draftRequest.Materials[0].ObjectReference = rawObjectReference
	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor, draftRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor, draftRequest)
	if err != nil || !replayed.Replayed || replayed.ID != draft.ID {
		t.Fatalf("CreateDraft(replay) = %#v, %v", replayed, err)
	}
	conflictingDraft := draftRequest
	conflictingDraft.SubjectFingerprint = bytesOf(32, 0x22)
	if _, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor, conflictingDraft); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("CreateDraft(conflicting replay) error = %v", err)
	}
	assertNoResponseLeak(t, draft, rawObjectReference, identityFingerprint, draftRequest.Materials[0].EncryptedEnvelope)

	if _, err := fixture.service.GetForReview(ctx, fixture.otherReviewer.Actor, draft.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(cross tenant) error = %v", err)
	}
	settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
	submitRequest := mutation(draft, "personal-submit")
	submitted, err := fixture.service.Submit(ctx, fixture.applicant.Actor, submitRequest)
	if err != nil || submitted.Status != StatusSubmitted || submitted.Revision != 2 {
		t.Fatalf("Submit() = %#v, %v", submitted, err)
	}
	replayedSubmit, err := fixture.service.Submit(ctx, fixture.applicant.Actor, submitRequest)
	if err != nil || !replayedSubmit.Replayed || replayedSubmit.ID != draft.ID {
		t.Fatalf("Submit(replay) = %#v, %v", replayedSubmit, err)
	}
	conflictingSubmit := submitRequest
	conflictingSubmit.ExpectedRevision++
	if _, err := fixture.service.Submit(ctx, fixture.applicant.Actor, conflictingSubmit); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Submit(conflicting replay) error = %v", err)
	}
	if _, err := fixture.service.StartReview(ctx, fixture.unauthorized.Actor,
		mutation(submitted, "unauthorized-review")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("StartReview(unauthorized) error = %v", err)
	}
	if _, err := fixture.service.StartReview(ctx, fixture.applicant.Actor,
		mutation(submitted, "self-review")); !errors.Is(err, ErrSelfReview) {
		t.Fatalf("StartReview(self) error = %v", err)
	}
	if _, err := fixture.service.StartReview(ctx, fixture.otherReviewer.Actor,
		mutation(submitted, "cross-tenant-review")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("StartReview(cross tenant) error = %v", err)
	}
	reviewing, err := fixture.service.StartReview(ctx, fixture.reviewer.Actor, mutation(submitted, "initial-start"))
	if err != nil || reviewing.Status != StatusReviewing || reviewing.ReviewerUserID == nil ||
		*reviewing.ReviewerUserID != fixture.reviewer.UserID {
		t.Fatalf("StartReview() = %#v, %v", reviewing, err)
	}
	approved, err := fixture.service.Review(ctx, fixture.reviewer.Actor, ReviewRequest{CaseID: reviewing.ID,
		ExpectedRevision: reviewing.Revision, Decision: DecisionApprove, ReasonCode: ReasonEvidenceVerified,
		IdempotencyKey: "initial-approve", RequestID: "initial-approve-request"})
	if err != nil || approved.Status != StatusApproved || approved.Revision != 4 {
		t.Fatalf("Review(approve) = %#v, %v", approved, err)
	}
	assertVerifiedPerson(t, fixture.pool, fixture.applicant.Actor, identityFingerprint)

	mismatchDraft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalReverification, bytesOf(32, 0x31), "reverify-mismatch"))
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, fixture.pool, mismatchDraft.ID, fixture.clock.now())
	if _, err := fixture.service.Submit(ctx, fixture.applicant.Actor,
		mutation(mismatchDraft, "reverify-mismatch-submit")); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Submit(reverification mismatch) error = %v", err)
	}
	reverify := approveCase(t, fixture, validPersonalDraft(
		KindPersonalReverification, identityFingerprint, "reverify-match"), "reverify")
	if reverify.Status != StatusApproved {
		t.Fatalf("reverification = %#v", reverify)
	}

	wrongEnterpriseRequest := validEnterpriseDraft(bytesOf(32, 0x40), bytesOf(32, 0x42),
		bytesOf(32, 0x43), "enterprise-agent-mismatch")
	wrongEnterprise, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor, wrongEnterpriseRequest)
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, fixture.pool, wrongEnterprise.ID, fixture.clock.now())
	if _, err := fixture.service.Submit(ctx, fixture.applicant.Actor,
		mutation(wrongEnterprise, "enterprise-agent-mismatch-submit")); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Submit(enterprise agent mismatch) error = %v", err)
	}
	enterpriseRequest := validEnterpriseDraft(bytesOf(32, 0x41), bytesOf(32, 0x42),
		identityFingerprint, "enterprise")
	enterprise := approveCase(t, fixture, enterpriseRequest, "enterprise")
	if enterprise.Status != StatusApproved || enterprise.AgentRelationship != RelationshipAuthorizedRepresentative ||
		enterprise.OrganizationName != enterpriseRequest.OrganizationName {
		t.Fatalf("enterprise verification = %#v", enterprise)
	}
	var organizationCount int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM identity_verified_organizations
		WHERE tenant_scope_id=$1 AND subject_fingerprint=$2`, fixture.applicant.ScopeID,
		enterpriseRequest.SubjectFingerprint).Scan(&organizationCount); err != nil || organizationCount != 1 {
		t.Fatalf("verified organization count = %d, %v", organizationCount, err)
	}

	if err := audit.New(fixture.pool).VerifyScope(ctx, fixture.applicant.ScopeID); err != nil {
		t.Fatalf("verify identity audit chain: %v", err)
	}
	var auditPayloads, writeResponses string
	if err := fixture.pool.QueryRow(ctx, `SELECT COALESCE(string_agg(payload::text,''),'') FROM audit_events
		WHERE scope_id=$1 AND resource_type='identity_verification_case'`, fixture.applicant.ScopeID).Scan(&auditPayloads); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT COALESCE(string_agg(response_body::text,''),'')
		FROM identity_verification_write_requests WHERE tenant_scope_id=$1`, fixture.applicant.ScopeID).Scan(&writeResponses); err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{rawObjectReference, fmt.Sprintf("%x", identityFingerprint),
		enterpriseRequest.OrganizationName} {
		if strings.Contains(auditPayloads, prohibited) || strings.Contains(writeResponses, rawObjectReference) ||
			strings.Contains(writeResponses, fmt.Sprintf("%x", identityFingerprint)) {
			t.Fatalf("audit or idempotency response leaked %q", prohibited)
		}
	}
	var prohibitedColumns int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name LIKE 'identity_verif%'
		  AND column_name IN ('document_number','identity_number','id_number','unified_credit_code')`).Scan(&prohibitedColumns); err != nil {
		t.Fatal(err)
	}
	if prohibitedColumns != 0 {
		t.Fatalf("identity verification schema exposes %d plaintext identifier columns", prohibitedColumns)
	}
}

func TestConcurrentSingleActiveReviewPerUserAndEnterpriseSubject(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	first, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x51), "race-personal-a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x52), "race-personal-b"))
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, fixture.pool, first.ID, fixture.clock.now())
	settleDraft(t, fixture.pool, second.ID, fixture.clock.now())
	assertConcurrentSingleWinner(t, func(index int) error {
		candidate := []Case{first, second}[index]
		_, err := fixture.service.Submit(ctx, fixture.applicant.Actor,
			mutation(candidate, fmt.Sprintf("race-personal-submit-%d", index)))
		return err
	})

	separate := newVerificationFixture(t)
	identityFingerprint := bytesOf(32, 0x61)
	approveCase(t, separate, validPersonalDraft(KindPersonalInitial, identityFingerprint, "race-base"), "race-base")
	subject := bytesOf(32, 0x62)
	enterpriseA, err := separate.service.CreateDraft(ctx, separate.applicant.Actor,
		validEnterpriseDraft(subject, bytesOf(32, 0x63), identityFingerprint, "race-enterprise-a"))
	if err != nil {
		t.Fatal(err)
	}
	enterpriseB, err := separate.service.CreateDraft(ctx, separate.applicant.Actor,
		validEnterpriseDraft(subject, bytesOf(32, 0x64), identityFingerprint, "race-enterprise-b"))
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, separate.pool, enterpriseA.ID, separate.clock.now())
	settleDraft(t, separate.pool, enterpriseB.ID, separate.clock.now())
	assertConcurrentSingleWinner(t, func(index int) error {
		candidate := []Case{enterpriseA, enterpriseB}[index]
		_, err := separate.service.Submit(ctx, separate.applicant.Actor,
			mutation(candidate, fmt.Sprintf("race-enterprise-submit-%d", index)))
		return err
	})
}

func TestAuditRollbackTamperProtectionAndFixedClockExpiry(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx := context.Background()
	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x71), "rollback-draft"))
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
	submitted, err := fixture.service.Submit(ctx, fixture.applicant.Actor, mutation(draft, "rollback-submit"))
	if err != nil {
		t.Fatal(err)
	}
	reviewing, err := fixture.service.StartReview(ctx, fixture.reviewer.Actor, mutation(submitted, "rollback-start"))
	if err != nil {
		t.Fatal(err)
	}
	failingService := newAuthorizedTestService(t, fixture.pool, failingAudit{}, Config{
		Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
	})
	before := counts(t, fixture.pool, "identity_verification_reviews", "identity_verified_persons",
		"identity_verification_state_events", "identity_verification_write_requests", "audit_events")
	_, err = failingService.Review(ctx, fixture.reviewer.Actor, ReviewRequest{CaseID: reviewing.ID,
		ExpectedRevision: reviewing.Revision, Decision: DecisionApprove, ReasonCode: ReasonEvidenceVerified,
		IdempotencyKey: "audit-failure", RequestID: "audit-failure-request"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Review(audit failure) error = %v", err)
	}
	after := counts(t, fixture.pool, "identity_verification_reviews", "identity_verified_persons",
		"identity_verification_state_events", "identity_verification_write_requests", "audit_events")
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("audit failure counts before=%v after=%v", before, after)
	}
	current, err := fixture.service.GetForReview(ctx, fixture.reviewer.Actor, reviewing.ID)
	if err != nil || current.Status != StatusReviewing || current.Revision != reviewing.Revision {
		t.Fatalf("case after audit failure = %#v, %v", current, err)
	}
	fixture.clock.set(fixture.clock.now().Add(time.Hour))
	rejected, err := fixture.service.Review(ctx, fixture.reviewer.Actor, ReviewRequest{CaseID: reviewing.ID,
		ExpectedRevision: reviewing.Revision, Decision: DecisionReject, ReasonCode: ReasonEvidenceIncomplete,
		IdempotencyKey: "reject-after-audit-recovery", RequestID: "reject-after-audit-recovery-request"})
	if err != nil || rejected.Status != StatusRejected || rejected.Revision != reviewing.Revision+1 {
		t.Fatalf("Review(reject after audit recovery) = %#v, %v", rejected, err)
	}
	if rejected.TerminalAt == nil || !rejected.Retention.EligibleAt.Equal(rejected.TerminalAt.Add(24*time.Hour)) {
		t.Fatalf("Review(reject) terminal retention = terminal:%v retention:%#v", rejected.TerminalAt, rejected.Retention)
	}

	assertSQLRejected(t, fixture.pool, "append-only", `UPDATE identity_verification_submissions
		SET submission_digest=$2 WHERE case_id=$1`, reviewing.ID, bytesOf(32, 1))
	assertSQLRejected(t, fixture.pool, "append-only", `UPDATE identity_verification_reviews
		SET reason_code='suspected_fraud' WHERE case_id=$1`, reviewing.ID)
	assertSQLRejected(t, fixture.pool, "append-only", `DELETE FROM identity_verification_review_assignments WHERE case_id=$1`, reviewing.ID)
	assertSQLRejected(t, fixture.pool, "invalid identity verification case transition", `UPDATE identity_verification_cases
		SET subject_fingerprint=$2 WHERE id=$1`, reviewing.ID, bytesOf(32, 2))
	assertSQLRejected(t, fixture.pool, "invalid identity verification case transition", `UPDATE identity_verification_cases
		SET status='reviewing',revision=revision+1,terminal_at=NULL WHERE id=$1`, reviewing.ID)
	assertSQLRejected(t, fixture.pool, "append-only", `TRUNCATE identity_verification_reviews`)
	assertSQLRejected(t, fixture.pool, "cannot be truncated", `TRUNCATE identity_verification_cases CASCADE`)
	_, truncateAuditErr := fixture.pool.Exec(context.Background(), `TRUNCATE audit_events`)
	var truncateAuditPGErr *pgconn.PgError
	if !errors.As(truncateAuditErr, &truncateAuditPGErr) ||
		!((truncateAuditPGErr.Code == "P0001" && strings.Contains(truncateAuditPGErr.Message, "append-only")) ||
			(truncateAuditPGErr.Code == "0A000" && strings.Contains(truncateAuditPGErr.Message, "foreign key"))) {
		t.Fatalf("truncate audit_events error = %v, want append-only or current-head foreign-key rejection", truncateAuditErr)
	}

	expiryFixture := newVerificationFixture(t)
	withdrawDraft, err := expiryFixture.service.CreateDraft(ctx, expiryFixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x73), "withdraw-draft"))
	if err != nil {
		t.Fatal(err)
	}
	expiryFixture.clock.set(expiryFixture.clock.now().Add(time.Hour))
	withdrawn, err := expiryFixture.service.Withdraw(ctx, expiryFixture.applicant.Actor,
		mutation(withdrawDraft, "withdraw-draft-case"))
	if err != nil || withdrawn.Status != StatusWithdrawn {
		t.Fatalf("Withdraw(draft) = %#v, %v", withdrawn, err)
	}
	if withdrawn.TerminalAt == nil || !withdrawn.Retention.EligibleAt.Equal(withdrawn.TerminalAt.Add(24*time.Hour)) {
		t.Fatalf("Withdraw(draft) terminal retention = terminal:%v retention:%#v", withdrawn.TerminalAt, withdrawn.Retention)
	}
	if _, err := expiryFixture.service.Submit(ctx, expiryFixture.applicant.Actor,
		MutationRequest{CaseID: withdrawn.ID, ExpectedRevision: withdrawn.Revision,
			IdempotencyKey: "withdrawn-resubmit", RequestID: "withdrawn-resubmit-request"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Submit(withdrawn) error = %v", err)
	}
	expiryDraft, err := expiryFixture.service.CreateDraft(ctx, expiryFixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0x72), "expiry-draft"))
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, expiryFixture.pool, expiryDraft.ID, expiryFixture.clock.now())
	expirySubmitted, err := expiryFixture.service.Submit(ctx, expiryFixture.applicant.Actor,
		mutation(expiryDraft, "expiry-submit"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expiryFixture.service.Expire(ctx, expiryFixture.applicant.Actor,
		mutation(expirySubmitted, "expiry-too-early")); !errors.Is(err, ErrNotExpired) {
		t.Fatalf("Expire(before deadline) error = %v", err)
	}
	expiryFixture.clock.set(*expirySubmitted.ExpiresAt)
	expired, err := expiryFixture.service.Expire(ctx, expiryFixture.applicant.Actor,
		mutation(expirySubmitted, "expiry-due"))
	if err != nil || expired.Status != StatusExpired || expired.TerminalAt == nil ||
		!expired.TerminalAt.Equal(*expirySubmitted.ExpiresAt) {
		t.Fatalf("Expire(at deadline) = %#v, %v", expired, err)
	}
	if !expired.Retention.EligibleAt.Equal(expired.TerminalAt.Add(24 * time.Hour)) {
		t.Fatalf("Expire(at deadline) terminal retention = terminal:%v retention:%#v", expired.TerminalAt, expired.Retention)
	}
	expiryFixture.clock.set(expired.Retention.EligibleAt)
	retained, err := expiryFixture.service.Get(ctx, expiryFixture.applicant.Actor, expired.ID)
	if err != nil || !retained.Retention.Eligible {
		t.Fatalf("Get(retention eligible) = %#v, %v", retained.Retention, err)
	}
}

func approveCase(t *testing.T, fixture *verificationFixture, request CreateDraftRequest, prefix string) Case {
	t.Helper()
	ctx := context.Background()
	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor, request)
	if err != nil {
		t.Fatalf("%s CreateDraft: %v", prefix, err)
	}
	settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
	submitted, err := fixture.service.Submit(ctx, fixture.applicant.Actor, mutation(draft, prefix+"-submit"))
	if err != nil {
		t.Fatalf("%s Submit: %v", prefix, err)
	}
	reviewing, err := fixture.service.StartReview(ctx, fixture.reviewer.Actor, mutation(submitted, prefix+"-start"))
	if err != nil {
		t.Fatalf("%s StartReview: %v", prefix, err)
	}
	approved, err := fixture.service.Review(ctx, fixture.reviewer.Actor, ReviewRequest{CaseID: reviewing.ID,
		ExpectedRevision: reviewing.Revision, Decision: DecisionApprove, ReasonCode: ReasonEvidenceVerified,
		IdempotencyKey: prefix + "-approve", RequestID: prefix + "-approve-request"})
	if err != nil {
		t.Fatalf("%s Review: %v", prefix, err)
	}
	return approved
}

func assertConcurrentSingleWinner(t *testing.T, operation func(int) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(start) }) }
	collected := 0
	defer func() {
		cancel()
		release()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		for collected < 2 {
			select {
			case <-results:
				collected++
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
	for index := range 2 {
		go func(index int) {
			select {
			case <-start:
			case <-ctx.Done():
				results <- ctx.Err()
				return
			}
			results <- operation(index)
		}(index)
	}
	release()
	first, second := receiveWorker(ctx, results), receiveWorker(ctx, results)
	collected = 2
	successes, conflicts := 0, 0
	for _, err := range []error{first, second} {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrActiveReview):
			conflicts++
		default:
			t.Fatalf("concurrent operation unexpected error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results = %v / %v", first, second)
	}
}

func mutation(item Case, key string) MutationRequest {
	return MutationRequest{CaseID: item.ID, ExpectedRevision: item.Revision,
		IdempotencyKey: key, RequestID: key + "-request"}
}

func assertNoResponseLeak(t *testing.T, item Case, objectReference string, fingerprint, envelope []byte) {
	t.Helper()
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, prohibited := range []string{objectReference, fmt.Sprintf("%x", fingerprint), fmt.Sprintf("%x", envelope),
		base64.StdEncoding.EncodeToString(fingerprint), base64.StdEncoding.EncodeToString(envelope)} {
		if strings.Contains(text, prohibited) {
			t.Fatalf("redacted case contains prohibited value %q: %s", prohibited, text)
		}
	}
}

func assertVerifiedPerson(t *testing.T, pool *pgxpool.Pool, actor Actor, expected []byte) {
	t.Helper()
	var actual []byte
	if err := pool.QueryRow(context.Background(), `SELECT identity_fingerprint FROM identity_verified_persons
		WHERE tenant_scope_id=$1 AND applicant_user_id=$2`, actor.ScopeID, actor.UserID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if !equalBytes(actual, expected) {
		t.Fatal("verified identity fingerprint mismatch")
	}
}

func counts(t *testing.T, pool *pgxpool.Pool, tables ...string) []int {
	t.Helper()
	result := make([]int, len(tables))
	for index, table := range tables {
		if !regexp.MustCompile(`^[a-z_]+$`).MatchString(table) {
			t.Fatalf("unsafe table %q", table)
		}
		if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&result[index]); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func settleDraft(t *testing.T, pool *pgxpool.Pool, caseID uuid.UUID, now time.Time) {
	t.Helper()
	token := uuid.New()
	command, err := pool.Exec(context.Background(), `UPDATE identity_verification_evidence_settlements
		SET state='leased',revision=revision+1,attempt_count=attempt_count+1,
			lease_token=$2,lease_expires_at=$3,updated_at=$4
		WHERE case_id=$1 AND state='commit_pending'`, caseID, token, now.Add(time.Minute), now)
	if err != nil || command.RowsAffected() != 1 {
		t.Fatalf("lease draft settlement: rows=%d error=%v", command.RowsAffected(), err)
	}
	command, err = pool.Exec(context.Background(), `UPDATE identity_verification_evidence_settlements
		SET state='settled',revision=revision+1,lease_token=NULL,lease_expires_at=NULL,
			updated_at=$2,settled_at=$2
		WHERE case_id=$1 AND state='leased' AND lease_token=$3`, caseID, now, token)
	if err != nil || command.RowsAffected() != 1 {
		t.Fatalf("settle draft evidence: rows=%d error=%v", command.RowsAffected(), err)
	}
}

func assertSQLRejected(t *testing.T, pool *pgxpool.Pool, message, query string, args ...any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), query, args...)
	assertPostgresRejection(t, err, message)
}

func assertCommitRejected(t *testing.T, tx pgx.Tx, message string) {
	t.Helper()
	err := tx.Commit(context.Background())
	assertPostgresRejection(t, err, message)
}

func assertPostgresRejection(t *testing.T, err error, message string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" || !strings.Contains(pgErr.Message, message) {
		t.Fatalf("SQL mutation error = %v, want P0001 containing %q", err, message)
	}
}

func insertRawDraft(t *testing.T, tx pgx.Tx, actor Actor, now time.Time, marker byte) uuid.UUID {
	t.Helper()
	caseID := uuid.New()
	if _, err := tx.Exec(context.Background(), `INSERT INTO identity_verification_cases (
		id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,
		revision,created_at,state_changed_at,retention_until
	) VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6)`,
		caseID, actor.ScopeID, actor.UserID, bytesOf(32, marker), now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return caseID
}

func insertRawMaterial(t *testing.T, tx pgx.Tx, actor Actor, caseID uuid.UUID, now time.Time,
	ordinal int, kind string, marker byte,
) {
	t.Helper()
	if _, err := tx.Exec(context.Background(), `INSERT INTO identity_verification_materials (
		id,tenant_scope_id,case_id,ordinal,material_kind,envelope_provider,envelope_key_id,
		encrypted_envelope,envelope_sha256,object_reference,object_sha256,mime_type,size_bytes,created_at
	) VALUES($1,$2,$3,$4,$5,'test-kms',$6,$7,$8,$9,$10,'image/jpeg',1024,$11)`,
		uuid.New(), actor.ScopeID, caseID, ordinal, kind, fmt.Sprintf("key-%02x", marker),
		bytesOf(16, marker), bytesOf(32, marker+1), fmt.Sprintf("identity/test/%02x", marker),
		bytesOf(32, marker+2), now); err != nil {
		t.Fatal(err)
	}
}

func insertRawCreationEvent(t *testing.T, tx pgx.Tx, actor Actor, caseID uuid.UUID, now time.Time) {
	t.Helper()
	if _, err := tx.Exec(context.Background(), `INSERT INTO identity_verification_state_events (
		id,tenant_scope_id,case_id,case_revision,from_status,to_status,actor_user_id,reason_code,occurred_at
	) VALUES($1,$2,$3,1,NULL,'draft',$4,'case.created',$5)`,
		uuid.New(), actor.ScopeID, caseID, actor.UserID, now); err != nil {
		t.Fatal(err)
	}
}

func newVerificationFixture(t *testing.T) *verificationFixture {
	t.Helper()
	pool := isolatedVerificationPool(t, true)
	clock := &fixedClock{value: time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)}
	service := newAuthorizedTestService(t, pool, audit.New(pool), Config{
		Clock: clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
	})
	scope := insertTenantScope(t, pool, "Identity Tenant")
	otherScope := insertTenantScope(t, pool, "Other Identity Tenant")
	return &verificationFixture{pool: pool, clock: clock, service: service,
		applicant:     insertActor(t, pool, scope, "applicant", permissionSelfManage, permissionRead, permissionReview),
		reviewer:      insertActor(t, pool, scope, "reviewer", permissionRead, permissionReview),
		unauthorized:  insertActor(t, pool, scope, "unauthorized", permissionSelfManage),
		otherReviewer: insertActor(t, pool, otherScope, "other-reviewer", permissionRead, permissionReview),
		otherScope:    otherScope}
}

func insertTenantScope(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	return scopeID
}

func insertSystemRole(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	roleID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'identity verification migration role',true)`, roleID, scopeID, name); err != nil {
		t.Fatal(err)
	}
	return roleID
}

func assertRolePermissions(t *testing.T, pool *pgxpool.Pool, roleID uuid.UUID, expected []string) {
	t.Helper()
	var actual []string
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(array_agg(permission_name ORDER BY permission_name), '{}')
		FROM role_permissions
		WHERE role_id=$1 AND permission_name LIKE 'identity_verification.%'`, roleID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(actual) != fmt.Sprint(expected) {
		t.Fatalf("identity verification role permissions = %v, want %v", actual, expected)
	}
}

func insertActor(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, label string, permissions ...string) testActor {
	t.Helper()
	actor := insertActorWithoutViewer(t, pool, scopeID, label, permissions...)
	assignTenantViewerRole(t, pool, scopeID, actor.UserID)
	return actor
}

// insertActorWithoutViewer is insertActor without the tenant_viewer system
// role, for a schema pinned below a migration that backfills that role.
func insertActorWithoutViewer(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, label string, permissions ...string) testActor {
	t.Helper()
	userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New()
	username := strings.ReplaceAll(label+"-"+uuid.NewString()[:8], "_", "-")
	if _, err := pool.Exec(context.Background(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'test-password-hash')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	sessionHash := sessionRefreshTokenHash(sessionID)
	if _, err := pool.Exec(context.Background(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, userID, scopeID, sessionHash[:],
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'identity verification test role',true)`, roleID, scopeID,
		"identity-verification-test-"+uuid.NewString()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO role_permissions(role_id,permission_name)
		SELECT $1,name FROM permissions WHERE name=ANY($2::text[])`, roleID, permissions); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
	return testActor{Actor: mintTestSessionActor(t, userID, scopeID, sessionID), roleID: roleID}
}

func assignTenantViewerRole(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) {
	t.Helper()
	viewerRoleID := ensureTenantViewerRole(t, pool, scopeID)
	if _, err := pool.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, scopeID, userID, viewerRoleID); err != nil {
		t.Fatal(err)
	}
}

func ensureTenantViewerRole(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) uuid.UUID {
	t.Helper()
	var roleID uuid.UUID
	err := pool.QueryRow(t.Context(), `SELECT id FROM roles
		WHERE scope_id=$1 AND name='tenant_viewer' AND system_role`, scopeID).Scan(&roleID)
	if err == nil {
		return roleID
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	roleID = uuid.New()
	// Since migration 459 the roles trigger grants a new tenant_viewer
	// identity_verification.self.manage (037's viewer grant). This viewer is only
	// the actors' baseline membership role: the permission under test must come
	// from the actor's own (revocable) role alone, otherwise reviewers gain
	// self.manage and revoking an assignment or role_permission leaves it in
	// place. Strip it here; the 094 system-role guard forbids deleting a
	// protected grant, so it is bypassed for this one statement as 459 down does.
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($1,$2,'tenant_viewer','identity verification test viewer role',true)`, roleID, scopeID); err != nil {
			return err
		}
		var granted bool
		if err := tx.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM role_permissions
			WHERE role_id=$1 AND permission_name LIKE 'identity_verification.%')`, roleID).Scan(&granted); err != nil || !granted {
			return err // schemas pinned below 459 grant nothing (and may predate the 042 guard)
		}
		_, err := tx.Exec(t.Context(), `
			ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
			DELETE FROM role_permissions WHERE role_id='`+roleID.String()+`' AND permission_name LIKE 'identity_verification.%';
			ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return roleID
}

func isolatedVerificationPool(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	if migrate {
		// A release-head clone of the template when one is configured (a full
		// migration per test timed out on a loaded host).
		if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
			return pool
		}
	}
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "identity_verification_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^identity_verification_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
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
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			pool.Close()
			_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
			admin.Close()
			t.Fatalf("migrate identity verification schema: %v", err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop identity verification schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func migrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func assertMigrationVersion(t *testing.T, pool *pgxpool.Pool, version int64, expected bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("migration %d applied = %t, want %t", version, actual, expected)
	}
}

func assertTable(t *testing.T, pool *pgxpool.Pool, table string, expected bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("table %s exists = %t, want %t", table, actual, expected)
	}
}

func assertTrigger(t *testing.T, pool *pgxpool.Pool, table, trigger string, expected bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM pg_trigger
		WHERE tgrelid=$1::regclass AND tgname=$2 AND NOT tgisinternal
	)`, table, trigger).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("trigger %s on %s exists = %t, want %t", trigger, table, actual, expected)
	}
}
