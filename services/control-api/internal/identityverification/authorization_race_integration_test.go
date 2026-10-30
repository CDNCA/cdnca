//go:build integration

package identityverification

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type blockingIDGenerator struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (generator *blockingIDGenerator) next() (uuid.UUID, error) {
	blocked := false
	generator.once.Do(func() {
		blocked = true
		close(generator.entered)
	})
	if blocked && generator.release != nil {
		<-generator.release
	}
	return uuid.NewV7()
}

type revocableReviewer struct {
	testActor
}

type caseReadResult struct {
	item Case
	err  error
}

func TestReviewerAuthorizationSerializesRevocationCommitOrder(t *testing.T) {
	for _, revocation := range []string{"session", "account", "membership", "assignment", "role_permission"} {
		for _, commandFirst := range []bool{true, false} {
			order := "revocation_first"
			if commandFirst {
				order = "command_first"
			}
			t.Run(revocation+"_"+order, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				fixture := newVerificationFixture(t)
				applicant := insertActor(t, fixture.pool, fixture.applicant.ScopeID,
					"race-applicant-"+revocation+"-"+order, permissionSelfManage)
				reviewer := insertRevocableReviewer(t, fixture, "race-reviewer-"+revocation+"-"+order)
				submitted := createSubmittedForAuthorizationRace(t, fixture, applicant, revocation+"-"+order)
				businessApplication := "iv-review-command-" + uuid.NewString()
				revocationApplication := "iv-review-revocation-" + uuid.NewString()
				businessPool := openNamedIsolationPool(t, fixture.pool, "read committed", businessApplication)
				revocationPool := openNamedIsolationPool(t, fixture.pool, "read committed", revocationApplication)
				var businessPID, revocationPID int
				if err := businessPool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&businessPID); err != nil {
					t.Fatal(err)
				}
				if err := revocationPool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&revocationPID); err != nil {
					t.Fatal(err)
				}
				apis := newStage2BRevocationAPIs(t, revocationPool, fixture.clock.now)
				generator := &blockingIDGenerator{entered: make(chan struct{}), release: make(chan struct{})}
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(generator.release) }) }
				service := newAuthorizedTestService(t, businessPool, audit.New(businessPool), Config{
					Clock: fixture.clock.now, NewID: generator.next,
					ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
				})
				request := mutation(submitted, "authorization-race-"+revocation+"-"+order)
				businessDone := make(chan error, 1)
				revocationDone := make(chan error, 1)
				businessCollected, revocationCollected := false, false
				var blocker pgx.Tx
				blockerReleased := false
				defer func() {
					cancel()
					release()
					cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
					defer cleanupCancel()
					if blocker != nil && !blockerReleased {
						_ = blocker.Rollback(cleanupCtx)
					}
					if !businessCollected {
						select {
						case <-businessDone:
						case <-cleanupCtx.Done():
						}
					}
					if !revocationCollected {
						select {
						case <-revocationDone:
						case <-cleanupCtx.Done():
						}
					}
				}()

				if commandFirst {
					go func() {
						_, commandErr := service.StartReview(ctx, reviewer.Actor, request)
						businessDone <- commandErr
					}()
					select {
					case <-generator.entered:
					case <-ctx.Done():
						t.Fatalf("review command did not pass transactional authorization: %v", ctx.Err())
					}
					go func() {
						revocationDone <- revokeReviewer(ctx, apis, reviewer, revocation,
							"review-command-first-"+uuid.NewString())
					}()
					waitForIAMGlobalExclusiveWaiter(t, fixture.pool, revocationPID,
						revocationApplication, revocationDone)
					release()
					if err := receiveWorker(ctx, businessDone); err != nil {
						t.Errorf("command that serialized first: %v", err)
					}
					businessCollected = true
					if err := receiveWorker(ctx, revocationDone); err != nil {
						t.Errorf("revoke reviewer after command: %v", err)
					}
					revocationCollected = true
					return
				}

				var err error
				blocker, err = fixture.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := blockStage2BRevocationTarget(ctx, blocker, reviewer.testActor, revocation); err != nil {
					t.Fatal(err)
				}
				go func() {
					revocationDone <- revokeReviewer(ctx, apis, reviewer, revocation,
						"review-revoke-first-"+uuid.NewString())
				}()
				waitForBackendLockWait(t, fixture.pool, revocationPID, revocationDone)
				assertIAMGlobalExclusiveHeld(t, fixture.pool, revocationPID, revocationApplication)
				go func() {
					_, commandErr := service.StartReview(ctx, reviewer.Actor, request)
					businessDone <- commandErr
				}()
				waitForIAMGlobalSharedWaiter(t, fixture.pool, businessPID, businessApplication, businessDone)
				if err := blocker.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
					t.Fatal(err)
				}
				blockerReleased = true
				if err := receiveWorker(ctx, revocationDone); err != nil {
					t.Fatalf("revoke reviewer first: %v", err)
				}
				revocationCollected = true
				if err := receiveWorker(ctx, businessDone); !errors.Is(err, ErrPermissionDenied) {
					t.Errorf("command after committed revocation error = %v", err)
				}
				businessCollected = true
			})
		}
	}
}

func TestReviewerReplayRevalidatesAllAuthorizationFacts(t *testing.T) {
	fixture := newVerificationFixture(t)
	for _, revocation := range []string{"session", "account", "membership", "assignment", "role_permission"} {
		t.Run(revocation, func(t *testing.T) {
			applicant := insertActor(t, fixture.pool, fixture.applicant.ScopeID,
				"replay-applicant-"+revocation, permissionSelfManage)
			reviewer := insertRevocableReviewer(t, fixture, "replay-reviewer-"+revocation)
			submitted := createSubmittedForAuthorizationRace(t, fixture, applicant, "replay-"+revocation)
			request := mutation(submitted, "replay-claim-"+revocation)
			claimed, err := fixture.service.StartReview(t.Context(), reviewer.Actor, request)
			if err != nil || claimed.Status != StatusReviewing {
				t.Fatalf("initial claim = %#v, %v", claimed, err)
			}
			apis := newStage2BRevocationAPIs(t, fixture.pool, fixture.clock.now)
			if err := revokeReviewer(t.Context(), apis, reviewer, revocation,
				"review-replay-revoke-"+uuid.NewString()); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.service.StartReview(t.Context(), reviewer.Actor, request); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("claim replay after %s revocation error = %v", revocation, err)
			}
		})
	}
}

func TestReviewerReadSerializesRevocationAndNeverFallsBackToSelfPermission(t *testing.T) {
	for _, revocation := range []string{"assignment", "role_permission", "membership", "account"} {
		for _, readFirst := range []bool{true, false} {
			order := "revocation_first"
			if readFirst {
				order = "read_first"
			}
			t.Run(revocation+"_"+order, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				fixture := newVerificationFixture(t)
				reviewer := insertRevocableReviewer(t, fixture, "read-reviewer-"+revocation+"-"+order)
				grantSystemPermission(t, fixture, reviewer.Actor, permissionSelfManage)
				draft, err := fixture.service.CreateDraft(ctx, reviewer.Actor,
					validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xe1), "read-self-"+revocation+"-"+order))
				if err != nil {
					t.Fatal(err)
				}
				businessApplication := "iv-review-read-" + uuid.NewString()
				revocationApplication := "iv-read-revocation-" + uuid.NewString()
				businessPool := openNamedIsolationPool(t, fixture.pool, "read committed", businessApplication)
				revocationPool := openNamedIsolationPool(t, fixture.pool, "read committed", revocationApplication)
				var businessPID, revocationPID int
				if err := businessPool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&businessPID); err != nil {
					t.Fatal(err)
				}
				if err := revocationPool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&revocationPID); err != nil {
					t.Fatal(err)
				}
				apis := newStage2BRevocationAPIs(t, revocationPool, fixture.clock.now)
				hook := &blockingAfterAuthorization{
					delegate: newTestTxAuthorizer(t, businessPool, fixture.clock.now),
					entered:  make(chan struct{}), release: make(chan struct{}),
				}
				service, err := newServiceWithTransactionAuthorizer(businessPool, audit.New(businessPool), hook, Config{
					Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
				})
				if err != nil {
					t.Fatal(err)
				}
				beforeAudit := countAuditEvents(t, fixture.pool)
				result := make(chan caseReadResult, 1)
				readFinished := make(chan error, 1)
				revocationDone := make(chan error, 1)
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(hook.release) }) }
				readCollected, revocationCollected := false, false
				var blocker pgx.Tx
				blockerReleased := false
				defer func() {
					cancel()
					release()
					cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
					defer cleanupCancel()
					if blocker != nil && !blockerReleased {
						_ = blocker.Rollback(cleanupCtx)
					}
					if !readCollected {
						select {
						case <-result:
						case <-cleanupCtx.Done():
						}
					}
					if !revocationCollected {
						select {
						case <-revocationDone:
						case <-cleanupCtx.Done():
						}
					}
				}()

				if readFirst {
					go func() {
						item, readErr := service.GetForReview(ctx, reviewer.Actor, draft.ID)
						readFinished <- readErr
						result <- caseReadResult{item: item, err: readErr}
					}()
					select {
					case <-hook.entered:
					case <-ctx.Done():
						t.Fatalf("review read did not acquire transactional authorization: %v", ctx.Err())
					}
					go func() {
						revocationDone <- revokeReviewer(ctx, apis, reviewer, revocation,
							"review-read-first-"+uuid.NewString())
					}()
					waitForIAMGlobalExclusiveWaiter(t, fixture.pool, revocationPID,
						revocationApplication, revocationDone)
					release()
					var read caseReadResult
					select {
					case read = <-result:
						readCollected = true
					case <-ctx.Done():
						t.Fatalf("review read worker did not finish: %v", ctx.Err())
					}
					if read.err != nil || read.item.ID != draft.ID || read.item.ApplicantUserID != reviewer.UserID {
						t.Fatalf("read serialized first = %#v, %v", read.item, read.err)
					}
					if err := receiveWorker(ctx, revocationDone); err != nil {
						t.Fatal(err)
					}
					revocationCollected = true
				} else {
					blocker, err = fixture.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := blockStage2BRevocationTarget(ctx, blocker, reviewer.testActor, revocation); err != nil {
						t.Fatal(err)
					}
					go func() {
						revocationDone <- revokeReviewer(ctx, apis, reviewer, revocation,
							"review-read-revoke-first-"+uuid.NewString())
					}()
					waitForBackendLockWait(t, fixture.pool, revocationPID, revocationDone)
					assertIAMGlobalExclusiveHeld(t, fixture.pool, revocationPID, revocationApplication)
					go func() {
						item, readErr := service.GetForReview(ctx, reviewer.Actor, draft.ID)
						readFinished <- readErr
						result <- caseReadResult{item: item, err: readErr}
					}()
					waitForIAMGlobalSharedWaiter(t, fixture.pool, businessPID, businessApplication, readFinished)
					if err := blocker.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
						t.Fatal(err)
					}
					blockerReleased = true
					if err := receiveWorker(ctx, revocationDone); err != nil {
						t.Fatal(err)
					}
					revocationCollected = true
					var read caseReadResult
					select {
					case read = <-result:
						readCollected = true
					case <-ctx.Done():
						t.Fatalf("review read worker did not finish: %v", ctx.Err())
					}
					assertDeniedReviewRead(t, read.item, read.err)
				}

				denied, err := service.GetForReview(t.Context(), reviewer.Actor, draft.ID)
				assertDeniedReviewRead(t, denied, err)
				if afterAudit := countAuditEvents(t, fixture.pool); afterAudit != beforeAudit {
					t.Fatalf("review read changed audit count: before=%d after=%d", beforeAudit, afterAudit)
				}
			})
		}
	}
}

func TestReviewerReadTenantBoundaryAndSelfReviewer(t *testing.T) {
	fixture := newVerificationFixture(t)
	draft, err := fixture.service.CreateDraft(t.Context(), fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xe2), "reviewer-read-boundary"))
	if err != nil {
		t.Fatal(err)
	}
	self, err := fixture.service.GetForReview(t.Context(), fixture.applicant.Actor, draft.ID)
	if err != nil || self.ID != draft.ID || self.ApplicantUserID != fixture.applicant.UserID {
		t.Fatalf("self reviewer read = %#v, %v", self, err)
	}
	crossTenant, err := fixture.service.GetForReview(t.Context(), fixture.otherReviewer.Actor, draft.ID)
	if !errors.Is(err, ErrNotFound) || crossTenant.ID != uuid.Nil || len(crossTenant.Materials) != 0 {
		t.Fatalf("cross-tenant reviewer read = %#v, %v", crossTenant, err)
	}
}

func assertDeniedReviewRead(t *testing.T, item Case, err error) {
	t.Helper()
	if !errors.Is(err, ErrPermissionDenied) || item.ID != uuid.Nil || item.SubjectFingerprintHint != "" ||
		item.LegalFingerprintHint != "" || item.AgentFingerprintHint != "" || len(item.Materials) != 0 {
		t.Fatalf("denied reviewer read returned sensitive case: %#v, %v", item, err)
	}
}

func countAuditEvents(t *testing.T, executor interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) int64 {
	t.Helper()
	var count int64
	if err := executor.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action LIKE 'identity_verification.%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestConcurrentDuplicateSubmitReplaysOneCommittedResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fixture := newVerificationFixture(t)
	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xa1), "duplicate-submit-draft"))
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
	request := mutation(draft, "duplicate-submit")
	start := make(chan struct{})
	results := make(chan caseReadResult, 2)
	var startOnce sync.Once
	release := func() { startOnce.Do(func() { close(start) }) }
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
	for range 2 {
		go func() {
			select {
			case <-start:
			case <-ctx.Done():
				results <- caseReadResult{err: ctx.Err()}
				return
			}
			item, submitErr := fixture.service.Submit(ctx, fixture.applicant.Actor, request)
			results <- caseReadResult{item: item, err: submitErr}
		}()
	}
	release()
	var first, second caseReadResult
	select {
	case first = <-results:
		collected++
	case <-ctx.Done():
		t.Fatalf("first duplicate submit worker did not finish: %v", ctx.Err())
	}
	select {
	case second = <-results:
		collected++
	case <-ctx.Done():
		t.Fatalf("second duplicate submit worker did not finish: %v", ctx.Err())
	}
	if first.err != nil || second.err != nil || first.item.ID != second.item.ID ||
		first.item.Status != StatusSubmitted || second.item.Status != StatusSubmitted ||
		first.item.Replayed == second.item.Replayed {
		t.Fatalf("duplicate submit results = %#v / %#v", first, second)
	}
}

func TestConcurrentDecisionHasSingleWinner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fixture := newVerificationFixture(t)
	submitted := createSubmittedForAuthorizationRace(t, fixture, fixture.applicant, "decision-race")
	reviewing, err := fixture.service.StartReview(ctx, fixture.reviewer.Actor,
		mutation(submitted, "decision-race-claim"))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var startOnce sync.Once
	release := func() { startOnce.Do(func() { close(start) }) }
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
			_, reviewErr := fixture.service.Review(ctx, fixture.reviewer.Actor, ReviewRequest{
				CaseID: reviewing.ID, ExpectedRevision: reviewing.Revision,
				Decision: DecisionReject, ReasonCode: ReasonEvidenceIncomplete,
				IdempotencyKey: fmt.Sprintf("decision-race-%d", index),
				RequestID:      fmt.Sprintf("decision-race-request-%d", index),
			})
			results <- reviewErr
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
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent decision error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent decision results = %v / %v", first, second)
	}
}

func createSubmittedForAuthorizationRace(t *testing.T, fixture *verificationFixture, applicant testActor,
	key string,
) Case {
	t.Helper()
	draft, err := fixture.service.CreateDraft(t.Context(), applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, key[0]), key+"-draft"))
	if err != nil {
		t.Fatal(err)
	}
	settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
	submitted, err := fixture.service.Submit(t.Context(), applicant.Actor,
		mutation(draft, key+"-submit"))
	if err != nil {
		t.Fatal(err)
	}
	return submitted
}

func revokeReviewer(
	ctx context.Context,
	apis stage2BRevocationAPIs,
	reviewer revocableReviewer,
	revocation, key string,
) error {
	actor := reviewer.testActor
	switch revocation {
	case "session":
		return apis.identity.Logout(ctx, actor.SessionID().String(), key)
	case "account":
		// Keep this revocation focused on the account status fact; custom RBAC assignments are immutable projections.
		tx, err := apis.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := iamlock.AcquireExclusive(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET status=$2,revision=revision+1
				WHERE id=$1 AND status=$3`, actor.UserID, identity.UserStatusDisabled, identity.UserStatusActive); err != nil {
			return err
		}
		return tx.Commit(ctx)
	case "assignment":
		_, err := apis.rbac.RevokeGrant(ctx, stage2BRBACActor(actor), rbacmanager.RevokeGrantRequest{
			GrantID: actor.grantID, Mutation: stage2BMutation(key),
		})
		return err
	case "role_permission":
		var revision int64
		var permissions []string
		if err := apis.pool.QueryRow(ctx, `SELECT role.current_revision,current_revision.permissions
			FROM custom_roles role
			JOIN custom_role_revisions current_revision
			  ON current_revision.role_id=role.id AND current_revision.revision=role.current_revision
			WHERE role.id=$1 AND role.tenant_scope_id=$2`, actor.roleID, actor.ScopeID).
			Scan(&revision, &permissions); err != nil {
			return err
		}
		filtered := permissions[:0]
		for _, candidate := range permissions {
			if candidate != permissionRead {
				filtered = append(filtered, candidate)
			}
		}
		_, err := apis.rbac.PublishRevision(ctx, stage2BRBACActor(actor), rbacmanager.PublishRevisionRequest{
			RoleID: actor.roleID, ExpectedRevision: revision, Permissions: filtered,
			Mutation: stage2BMutation(key),
		})
		return err
	case "membership":
		_, err := apis.identity.SuspendMembership(ctx, identity.Actor{
			UserID: reviewer.managerUserID, ScopeID: actor.ScopeID, ScopeKind: "tenant",
		}, identity.SuspendMembershipInput{
			ScopeID: actor.ScopeID, UserID: actor.UserID,
			ExpectedStatus: identity.MembershipStatusActive,
			ReasonCode:     "identity_verification_access_revoked",
			IdempotencyKey: key, RequestID: key + "-request", TraceID: key + "-trace",
		})
		return err
	default:
		return fmt.Errorf("unknown revocation %q", revocation)
	}
}

func insertRevocableReviewer(t *testing.T, fixture *verificationFixture, label string) revocableReviewer {
	t.Helper()
	manager := insertActor(t, fixture.pool, fixture.applicant.ScopeID, label+"-manager",
		"identity.roles.manage", "identity.users.manage", permissionRead, permissionReview)
	userID, roleID, grantID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	viewerRoleID := ensureTenantViewerRole(t, fixture.pool, fixture.applicant.ScopeID)
	username := label + "-" + uuid.NewString()[:8]
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'test-password-hash')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id)
		VALUES($1,$2)`, fixture.applicant.ScopeID, userID); err != nil {
		t.Fatal(err)
	}
	sessionHash := sessionRefreshTokenHash(sessionID)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, userID, fixture.applicant.ScopeID,
		sessionHash[:], fixture.clock.now().Add(-time.Hour), fixture.clock.now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`,
		fixture.applicant.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	now := fixture.clock.now()
	roleName := "identity-revocable-" + uuid.NewString()[:8]
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO custom_roles(
		id,tenant_id,tenant_scope_id,current_revision,current_name,created_by_user_id,
		created_by_scope_id,created_at,updated_at
	) VALUES($1,$2,$3,0,$4,$5,$3,$6,$6)`, roleID, tenantID, fixture.applicant.ScopeID,
		roleName, manager.UserID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,step_up_proof_id,step_up_method,
		step_up_verified_at,created_at
	) VALUES($1,$2,$3,1,$4,ARRAY[$5,$6]::text[],'identity.custom_role.create',
		$7,$3,$8,'totp',$9,$9)`, roleID, tenantID, fixture.applicant.ScopeID, roleName,
		permissionRead, permissionReview, manager.UserID, uuid.New(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE custom_roles
		SET current_revision=1,updated_at=$3
		WHERE id=$1 AND tenant_scope_id=$2 AND current_revision=0`, roleID, fixture.applicant.ScopeID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO custom_role_grants(
		id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		granted_by_user_id,granted_by_scope_id,step_up_proof_id,step_up_method,
		step_up_verified_at,granted_at
	) VALUES($1,$2,$3,$4,1,$5,$6,$3,$7,'totp',$8,$8)`, grantID, tenantID,
		fixture.applicant.ScopeID, roleID, userID, manager.UserID, uuid.New(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.applicant.ScopeID, userID, viewerRoleID); err != nil {
		t.Fatal(err)
	}
	return revocableReviewer{testActor: testActor{
		Actor:  mintTestSessionActor(t, userID, fixture.applicant.ScopeID, sessionID),
		roleID: roleID, grantID: grantID, managerUserID: manager.UserID,
		managerSessionID: manager.SessionID(),
	}}
}

func grantSystemPermission(t *testing.T, fixture *verificationFixture, actor Actor, permission string) {
	t.Helper()
	roleID := insertSystemRole(t, fixture.pool, actor.ScopeID, "identity-self-"+uuid.NewString()[:8])
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,$2)`, roleID, permission); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, actor.ScopeID, actor.UserID, roleID); err != nil {
		t.Fatal(err)
	}
}
