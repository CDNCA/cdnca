//go:build integration

package identityverificationhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errInjectedHTTPAudit = errors.New("injected HTTP identity verification audit failure")

type integrationClock struct {
	mu    sync.RWMutex
	value time.Time
}

func (clock *integrationClock) now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.value
}

func (clock *integrationClock) set(value time.Time) {
	clock.mu.Lock()
	clock.value = value
	clock.mu.Unlock()
}

type integrationFailingAudit struct{}

func (integrationFailingAudit) Append(context.Context, pgx.Tx, audit.Event) error {
	return errInjectedHTTPAudit
}

type integrationActor struct {
	identityverification.Actor
	roleID uuid.UUID
	token  string
}

type httpIntegrationFixture struct {
	pool             *pgxpool.Pool
	clock            *integrationClock
	core             *identityverification.Service
	reader           *PostgresReader
	registry         *reservationRegistry
	settlementWorker *identityverification.SettlementWorker
	handler          http.Handler
	identity         *identity.Service
	iam              *iamlock.Authorizer
	tokens           *identity.TokenManager
	actorsByToken    map[string]integrationActor
	platformSessions map[string]identity.AuthenticatedSession
	applicant        integrationActor
	otherUser        integrationActor
	reviewer         integrationActor
	secondReviewer   integrationActor
	otherReviewer    integrationActor
}

func TestHTTPIntegrationLifecycleIsolationIdempotencyAndTrustedEvidence(t *testing.T) {
	fixture := newHTTPIntegrationFixture(t)
	identityFingerprint := bytesOf(32, 0x21)
	initialToken := integrationToken('a')
	initialEvidence := integrationPersonalEvidence(identityverification.KindPersonalInitial, identityFingerprint, 0x31)
	fixture.registry.add(fixture.applicant.Actor, initialToken, initialEvidence)

	createdRecorder := fixture.create(t, "applicant", identityverification.KindPersonalInitial,
		initialToken, "initial-create", http.StatusCreated)
	initial := decodeCase(t, createdRecorder)
	assertSensitiveHTTPResponse(t, createdRecorder.Body.String(), initialEvidence)

	replayRecorder := fixture.create(t, "applicant", identityverification.KindPersonalInitial,
		initialToken, "initial-create", http.StatusOK)
	replayed := decodeCase(t, replayRecorder)
	if !replayed.Replayed || replayed.ID != initial.ID {
		t.Fatalf("create replay = %#v", replayed)
	}
	conflictToken := integrationToken('b')
	fixture.registry.add(fixture.applicant.Actor, conflictToken,
		integrationPersonalEvidence(identityverification.KindPersonalInitial, bytesOf(32, 0x22), 0x32))
	conflict := fixture.request(t, "applicant", http.MethodPost, apiPrefix+"/cases",
		fmt.Sprintf(`{"kind":"personal_initial","evidence_token":%q}`, conflictToken), "initial-create", 0)
	assertAPIError(t, conflict, http.StatusConflict, "identity_verification_idempotency_conflict")
	fixture.settle(t, initial.ID)

	wrongRevision := fixture.request(t, "applicant", http.MethodPost,
		apiPrefix+"/cases/"+initial.ID.String()+"/submit", "", "initial-submit-wrong", initial.Revision+1)
	assertAPIError(t, wrongRevision, http.StatusConflict, "identity_verification_revision_conflict")
	submittedRecorder := fixture.request(t, "applicant", http.MethodPost,
		apiPrefix+"/cases/"+initial.ID.String()+"/submit", "", "initial-submit", initial.Revision)
	if submittedRecorder.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", submittedRecorder.Code, submittedRecorder.Body.String())
	}
	submitted := decodeCase(t, submittedRecorder)

	selfReview := fixture.request(t, "applicant", http.MethodPost,
		apiPrefix+"/reviewer/cases/"+initial.ID.String()+"/claim", "", "initial-self-claim", submitted.Revision)
	assertAPIError(t, selfReview, http.StatusForbidden, "identity_verification_self_review_forbidden")
	crossTenant := fixture.request(t, "other-reviewer", http.MethodPost,
		apiPrefix+"/reviewer/cases/"+initial.ID.String()+"/claim", "", "initial-cross-claim", submitted.Revision)
	assertAPIError(t, crossTenant, http.StatusNotFound, "identity_verification_not_found")
	crossUser := fixture.request(t, "other-user", http.MethodGet,
		apiPrefix+"/cases/"+initial.ID.String(), "", "", 0)
	assertAPIError(t, crossUser, http.StatusNotFound, "identity_verification_not_found")

	list := fixture.request(t, "reviewer", http.MethodGet,
		apiPrefix+"/reviewer/cases?status=submitted&kind=personal_initial&limit=20", "", "", 0)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), initial.ID.String()) {
		t.Fatalf("review list = %d %s", list.Code, list.Body.String())
	}
	reviewerDetail := fixture.request(t, "reviewer", http.MethodGet,
		apiPrefix+"/reviewer/cases/"+initial.ID.String(), "", "", 0)
	if reviewerDetail.Code != http.StatusOK {
		t.Fatalf("review detail = %d %s", reviewerDetail.Code, reviewerDetail.Body.String())
	}

	claimedRecorder := fixture.request(t, "reviewer", http.MethodPost,
		apiPrefix+"/reviewer/cases/"+initial.ID.String()+"/claim", "", "initial-claim", submitted.Revision)
	if claimedRecorder.Code != http.StatusOK {
		t.Fatalf("claim = %d %s", claimedRecorder.Code, claimedRecorder.Body.String())
	}
	claimed := decodeCase(t, claimedRecorder)
	approvedRecorder := fixture.request(t, "reviewer", http.MethodPost,
		apiPrefix+"/reviewer/cases/"+initial.ID.String()+"/decision",
		`{"decision":"approved","reason_code":"evidence_verified"}`, "initial-approve", claimed.Revision)
	if approvedRecorder.Code != http.StatusOK || decodeCase(t, approvedRecorder).Status != identityverification.StatusApproved {
		t.Fatalf("approve = %d %s", approvedRecorder.Code, approvedRecorder.Body.String())
	}
	approvalReplay := fixture.request(t, "reviewer", http.MethodPost,
		apiPrefix+"/reviewer/cases/"+initial.ID.String()+"/decision",
		`{"decision":"approved","reason_code":"evidence_verified"}`, "initial-approve", claimed.Revision)
	if approvalReplay.Code != http.StatusOK || !decodeCase(t, approvalReplay).Replayed {
		t.Fatalf("approval replay = %d %s", approvalReplay.Code, approvalReplay.Body.String())
	}
	approvalConflict := fixture.request(t, "reviewer", http.MethodPost,
		apiPrefix+"/reviewer/cases/"+initial.ID.String()+"/decision",
		`{"decision":"rejected","reason_code":"suspected_fraud"}`, "initial-approve", claimed.Revision)
	assertAPIError(t, approvalConflict, http.StatusConflict, "identity_verification_idempotency_conflict")

	mismatchToken := integrationToken('c')
	fixture.registry.add(fixture.applicant.Actor, mismatchToken,
		integrationPersonalEvidence(identityverification.KindPersonalReverification, bytesOf(32, 0x41), 0x42))
	mismatchDraft := decodeCase(t, fixture.create(t, "applicant",
		identityverification.KindPersonalReverification, mismatchToken, "reverify-create", http.StatusCreated))
	fixture.settle(t, mismatchDraft.ID)
	mismatch := fixture.request(t, "applicant", http.MethodPost,
		apiPrefix+"/cases/"+mismatchDraft.ID.String()+"/submit", "", "reverify-submit", mismatchDraft.Revision)
	assertAPIError(t, mismatch, http.StatusUnprocessableEntity, "identity_verification_identity_mismatch")

	invalidMaterialToken := integrationToken('d')
	invalidMaterials := integrationPersonalEvidence(identityverification.KindPersonalReverification, identityFingerprint, 0x43)
	invalidMaterials.Materials = invalidMaterials.Materials[:1]
	fixture.registry.add(fixture.applicant.Actor, invalidMaterialToken, invalidMaterials)
	invalidMaterial := fixture.create(t, "applicant", identityverification.KindPersonalReverification,
		invalidMaterialToken, "invalid-material", http.StatusBadRequest)
	assertAPIError(t, invalidMaterial, http.StatusBadRequest, "identity_verification_invalid_request")

	invalidRelationshipToken := integrationToken('e')
	invalidRelationship := integrationEnterpriseEvidence(identityFingerprint, 0x51)
	invalidRelationship.AgentRelationship = "owner"
	fixture.registry.add(fixture.applicant.Actor, invalidRelationshipToken, invalidRelationship)
	invalidEnterprise := fixture.create(t, "applicant", identityverification.KindEnterprise,
		invalidRelationshipToken, "invalid-enterprise", http.StatusBadRequest)
	assertAPIError(t, invalidEnterprise, http.StatusBadRequest, "identity_verification_invalid_request")

	validEnterpriseToken := integrationToken('f')
	validEnterprise := integrationEnterpriseEvidence(identityFingerprint, 0x52)
	fixture.registry.add(fixture.applicant.Actor, validEnterpriseToken, validEnterprise)
	enterpriseDraft := decodeCase(t, fixture.create(t, "applicant", identityverification.KindEnterprise,
		validEnterpriseToken, "enterprise-create", http.StatusCreated))
	if enterpriseDraft.AgentRelationship != identityverification.RelationshipAuthorizedRepresentative {
		t.Fatalf("enterprise relationship = %#v", enterpriseDraft)
	}
	fixture.settle(t, enterpriseDraft.ID)
	enterpriseSubmitted := fixture.request(t, "applicant", http.MethodPost,
		apiPrefix+"/cases/"+enterpriseDraft.ID.String()+"/submit", "", "enterprise-submit", enterpriseDraft.Revision)
	if enterpriseSubmitted.Code != http.StatusOK {
		t.Fatalf("enterprise submit = %d %s", enterpriseSubmitted.Code, enterpriseSubmitted.Body.String())
	}

	if err := audit.New(fixture.pool).VerifyScope(context.Background(), fixture.applicant.ScopeID); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

func TestHTTPIntegrationConcurrentClaimAuditRollbackRBACAndApplicantExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fixture := newHTTPIntegrationFixture(t)
	first := fixture.createSubmitted(t, "race-first", 0x61)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
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
	for _, reviewer := range []string{"reviewer", "second-reviewer"} {
		go func(reviewer string) {
			select {
			case <-start:
			case <-ctx.Done():
				results <- httptest.NewRecorder()
				return
			}
			results <- fixture.requestContext(ctx, reviewer, http.MethodPost,
				apiPrefix+"/reviewer/cases/"+first.ID.String()+"/claim", "", "claim-"+reviewer, first.Revision)
		}(reviewer)
	}
	release()
	var firstResult, secondResult *httptest.ResponseRecorder
	select {
	case firstResult = <-results:
		collected++
	case <-ctx.Done():
		t.Fatalf("first HTTP claim worker did not finish: %v", ctx.Err())
	}
	select {
	case secondResult = <-results:
		collected++
	case <-ctx.Done():
		t.Fatalf("second HTTP claim worker did not finish: %v", ctx.Err())
	}
	statuses := map[int]int{firstResult.Code: 1}
	statuses[secondResult.Code]++
	if statuses[http.StatusOK] != 1 || statuses[http.StatusConflict] != 1 {
		t.Fatalf("claim statuses = %d/%d bodies=%s / %s", firstResult.Code, secondResult.Code,
			firstResult.Body.String(), secondResult.Body.String())
	}
	reviewing := decodeCase(t, map[bool]*httptest.ResponseRecorder{true: firstResult, false: secondResult}[firstResult.Code == http.StatusOK])

	failingCore, err := identityverification.NewIAMService(fixture.pool, integrationFailingAudit{}, fixture.iam,
		identityverification.Config{Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	failingService := testService(t, failingCore, fixture.reader, fixture.registry)
	failingHandler, err := newHandler(failingService, fixture.authenticate, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	reviewerToken := "reviewer"
	if reviewing.ReviewerUserID != nil && *reviewing.ReviewerUserID == fixture.secondReviewer.UserID {
		reviewerToken = "second-reviewer"
	}
	auditFailure := integrationRequest(failingHandler, fixture.rawToken(reviewerToken), http.MethodPost,
		apiPrefix+"/reviewer/cases/"+reviewing.ID.String()+"/decision",
		`{"decision":"rejected","reason_code":"evidence_incomplete"}`, "audit-failure", reviewing.Revision)
	assertAPIError(t, auditFailure, http.StatusServiceUnavailable, "identity_verification_unavailable")
	current, err := fixture.core.GetForReview(ctx, fixture.reviewer.Actor, reviewing.ID)
	if err != nil || current.Status != identityverification.StatusReviewing || current.Revision != reviewing.Revision {
		t.Fatalf("audit rollback case = %#v, %v", current, err)
	}
	recovered := fixture.request(t, reviewerToken, http.MethodPost,
		apiPrefix+"/reviewer/cases/"+reviewing.ID.String()+"/decision",
		`{"decision":"rejected","reason_code":"evidence_incomplete"}`, "audit-recovered", reviewing.Revision)
	if recovered.Code != http.StatusOK || decodeCase(t, recovered).Status != identityverification.StatusRejected {
		t.Fatalf("decision after audit recovery = %d %s", recovered.Code, recovered.Body.String())
	}

	if _, err := fixture.pool.Exec(ctx, `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.reviewer.ScopeID,
		fixture.reviewer.UserID, fixture.reviewer.roleID); err != nil {
		t.Fatal(err)
	}
	revokedList := fixture.request(t, "reviewer", http.MethodGet, apiPrefix+"/reviewer/cases", "", "", 0)
	assertAPIError(t, revokedList, http.StatusForbidden, "identity_verification_permission_denied")

	expiry := fixture.createSubmitted(t, "expiry", 0x71)
	fixture.clock.set(*expiry.ExpiresAt)
	expired := fixture.request(t, "applicant", http.MethodPost,
		apiPrefix+"/cases/"+expiry.ID.String()+"/expire", "", "expiry-due", expiry.Revision)
	if expired.Code != http.StatusOK || decodeCase(t, expired).Status != identityverification.StatusExpired {
		t.Fatalf("applicant expire = %d %s", expired.Code, expired.Body.String())
	}
	reviewerExpire := fixture.request(t, "second-reviewer", http.MethodPost,
		apiPrefix+"/reviewer/cases/"+expiry.ID.String()+"/expire", "", "reviewer-expire", expiry.Revision)
	assertAPIError(t, reviewerExpire, http.StatusNotFound, "identity_verification_route_not_found")
}

func TestReviewerListSerializesRevocationCommitOrder(t *testing.T) {
	for _, revocation := range []string{
		"session",
		"assignment",
		"role_permission_read",
		"role_permission_review",
	} {
		for _, commandFirst := range []bool{true, false} {
			order := "revoke_first"
			if commandFirst {
				order = "command_first"
			}
			t.Run(revocation+"_"+order, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				fixture := newHTTPIntegrationFixture(t)
				reviewer := insertHTTPCustomReviewer(t, fixture, "reviewer-list-"+revocation+"-"+order)
				token := integrationToken('l')
				fixture.registry.add(fixture.applicant.Actor, token,
					integrationPersonalEvidence(identityverification.KindPersonalInitial, bytesOf(32, 0x81), 0x82))
				draft := decodeCase(t, fixture.create(t, "applicant",
					identityverification.KindPersonalInitial, token, "reviewer-list-race", http.StatusCreated))
				businessApplication := "iv-list-biz-" + uuid.NewString()
				revocationApplication := "iv-list-revoke-" + uuid.NewString()
				businessPool := openNamedHTTPPool(t, fixture.pool, businessApplication)
				revocationPool := openNamedHTTPPool(t, fixture.pool, revocationApplication)
				var businessPID, revocationPID int
				if err := businessPool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&businessPID); err != nil {
					t.Fatal(err)
				}
				if err := revocationPool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&revocationPID); err != nil {
					t.Fatal(err)
				}
				businessIdentity, err := identity.NewService(identity.NewStore(businessPool),
					fixture.tokens, 24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				businessHandler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true,
					Core: identityverification.Config{Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour,
						RetentionPeriod: 24 * time.Hour},
					Service: ServiceConfig{CursorKey: []byte("0123456789abcdef0123456789abcdef")}},
					RuntimeDependencies{Pool: businessPool, Identity: businessIdentity, IAM: fixture.iam,
						Resolver: fixture.registry, SettlementPublisher: registrySettlementCommitter{registry: fixture.registry},
						Clock: fixture.clock.now})
				if err != nil {
					t.Fatal(err)
				}
				apis := newHTTPRevocationAPIs(t, revocationPool, fixture.tokens, fixture.clock.now)
				result := make(chan *httptest.ResponseRecorder, 1)
				revoked := make(chan error, 1)
				var blocker pgx.Tx
				blockerReleased, readCollected, revocationCollected := false, false, false
				defer func() {
					cancel()
					cleanupCtx, cleanupCancel := context.WithTimeout(t.Context(), 3*time.Second)
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
						case <-revoked:
						case <-cleanupCtx.Done():
						}
					}
				}()

				if commandFirst {
					blocker, err = fixture.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := blocker.Exec(ctx,
						`LOCK TABLE identity_verification_cases IN ACCESS EXCLUSIVE MODE`); err != nil {
						t.Fatal(err)
					}
					go func() {
						result <- integrationRequestContext(ctx, businessHandler, reviewer.token,
							http.MethodGet, apiPrefix+"/reviewer/cases", "", "", 0)
					}()
					waitForReviewerListCaseLock(t, fixture.pool, businessPool, businessPID, businessApplication)
					go func() {
						revoked <- revokeHTTPReviewer(ctx, apis, reviewer, revocation,
							"http-list-command-first-"+uuid.NewString())
					}()
					waitForHTTPGlobalExclusiveWaiter(t, fixture.pool, revocationPID,
						revocationApplication)
					if err := blocker.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
						t.Fatal(err)
					}
					blockerReleased = true
					listed := receiveHTTPListWorker(t, ctx, result)
					readCollected = true
					if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), draft.ID.String()) {
						t.Fatalf("reviewer list serialized first = %d %s", listed.Code, listed.Body.String())
					}
					if err := receiveHTTPWorker(ctx, revoked); err != nil {
						t.Fatal(err)
					}
					revocationCollected = true
				} else {
					blocker, err = fixture.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					relation, err := blockHTTPRevocationTarget(ctx, blocker, reviewer, revocation)
					if err != nil {
						t.Fatal(err)
					}
					go func() {
						revoked <- revokeHTTPReviewer(ctx, apis, reviewer, revocation,
							"http-list-revoke-first-"+uuid.NewString())
					}()
					waitForHTTPRevocationTarget(t, fixture.pool, revocationPID,
						revocationApplication, relation)
					assertHTTPGlobalExclusiveHeld(t, fixture.pool, revocationPID, revocationApplication)
					go func() {
						result <- integrationRequestContext(ctx, businessHandler, reviewer.token,
							http.MethodGet, apiPrefix+"/reviewer/cases", "", "", 0)
					}()
					waitForHTTPGlobalSharedWaiter(t, fixture.pool, businessPID, businessApplication)
					assertHTTPListHasNoCaseLocks(t, fixture.pool, businessPID)
					if err := blocker.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
						t.Fatal(err)
					}
					blockerReleased = true
					if err := receiveHTTPWorker(ctx, revoked); err != nil {
						t.Fatal(err)
					}
					revocationCollected = true
					listed := receiveHTTPListWorker(t, ctx, result)
					readCollected = true
					assertAPIError(t, listed, http.StatusForbidden, "identity_verification_permission_denied")
					if strings.Contains(listed.Body.String(), draft.ID.String()) {
						t.Fatalf("reviewer list after %s revocation leaked case %s: %s",
							revocation, draft.ID, listed.Body.String())
					}
				}
			})
		}
	}
}

type httpRevocableReviewer struct {
	integrationActor
	roleName string
	manager  integrationActor
}

type httpRevocationAPIs struct {
	identity *identity.Service
	rbac     *rbacmanager.Service
	pool     *pgxpool.Pool
}

type httpStepUpVerifier struct {
	now func() time.Time
}

func (verifier httpStepUpVerifier) VerifyAndConsume(
	_ context.Context,
	tx pgx.Tx,
	proof rbacmanager.StepUpProof,
	check rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	if tx == nil || verifier.now == nil || proof.Token != "verified-token" ||
		check.RequestID == "" || check.TraceID == "" {
		return rbacmanager.StepUpEvidence{}, rbacmanager.ErrStepUpRequired
	}
	return rbacmanager.StepUpEvidence{
		ProofID: uuid.New(), Method: "totp", VerifiedAt: verifier.now().UTC().Truncate(time.Microsecond),
	}, nil
}

func newHTTPRevocationAPIs(
	t *testing.T,
	pool *pgxpool.Pool,
	tokens *identity.TokenManager,
	now func() time.Time,
) httpRevocationAPIs {
	t.Helper()
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rbacService, err := rbacmanager.NewServiceWithDependencies(pool, audit.New(pool),
		httpStepUpVerifier{now: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	return httpRevocationAPIs{identity: identityService, rbac: rbacService, pool: pool}
}

func revokeHTTPReviewer(
	ctx context.Context,
	apis httpRevocationAPIs,
	reviewer httpRevocableReviewer,
	revocation, key string,
) error {
	switch revocation {
	case "session":
		return apis.identity.Logout(ctx, reviewer.SessionID().String(), key)
	case "assignment":
		var grantID uuid.UUID
		if err := apis.pool.QueryRow(ctx, `SELECT id FROM custom_role_grants
			WHERE tenant_scope_id=$1 AND role_id=$2 AND subject_user_id=$3`,
			reviewer.ScopeID, reviewer.roleID, reviewer.UserID).Scan(&grantID); err != nil {
			return err
		}
		_, err := apis.rbac.RevokeGrant(ctx, httpRBACActor(reviewer), rbacmanager.RevokeGrantRequest{
			GrantID: grantID, Mutation: httpRBACMutation(key),
		})
		return err
	case "role_permission_read", "role_permission_review":
		if reviewer.roleName == "" {
			return errors.New("role permission revocation requires a custom reviewer role")
		}
		revokedPermission := "identity_verification.read"
		if revocation == "role_permission_review" {
			revokedPermission = "identity_verification.review"
		}
		var revision int64
		var permissions []string
		if err := apis.pool.QueryRow(ctx, `SELECT role.current_revision,current_revision.permissions
			FROM custom_roles role
			JOIN custom_role_revisions current_revision
			  ON current_revision.role_id=role.id AND current_revision.revision=role.current_revision
			WHERE role.id=$1 AND role.tenant_scope_id=$2`, reviewer.roleID, reviewer.ScopeID).
			Scan(&revision, &permissions); err != nil {
			return err
		}
		filtered := permissions[:0]
		for _, permission := range permissions {
			if permission != revokedPermission {
				filtered = append(filtered, permission)
			}
		}
		_, err := apis.rbac.PublishRevision(ctx, httpRBACActor(reviewer), rbacmanager.PublishRevisionRequest{
			RoleID: reviewer.roleID, ExpectedRevision: revision, Permissions: filtered,
			Mutation: httpRBACMutation(key),
		})
		return err
	default:
		return fmt.Errorf("unknown HTTP reviewer revocation %q", revocation)
	}
}

func httpRBACActor(reviewer httpRevocableReviewer) rbacmanager.Actor {
	return rbacmanager.Actor{
		UserID: reviewer.manager.UserID, ScopeID: reviewer.ScopeID,
		SessionID: reviewer.manager.SessionID(), ScopeKind: "tenant",
		IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
}

func httpRBACMutation(key string) rbacmanager.MutationContext {
	return rbacmanager.MutationContext{
		IdempotencyKey: key, RequestID: key, TraceID: key,
		StepUp: rbacmanager.StepUpProof{Token: "verified-token"},
	}
}

func insertHTTPCustomReviewer(t *testing.T, fixture *httpIntegrationFixture, label string) httpRevocableReviewer {
	t.Helper()
	manager := insertHTTPActor(t, fixture.pool, fixture.tokens, fixture.applicant.ScopeID, label+"-manager",
		"identity.roles.manage", "identity_verification.read", "identity_verification.review")
	userID, sessionID, roleID, grantID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	username := label + "-" + uuid.NewString()[:8]
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'test-password-hash')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id)
		VALUES($1,$2)`, fixture.applicant.ScopeID, userID); err != nil {
		t.Fatal(err)
	}
	sessionHash := sha256.Sum256([]byte(sessionID.String()))
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, userID, fixture.applicant.ScopeID,
		sessionHash[:], time.Now().UTC().Add(-time.Hour), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`,
		fixture.applicant.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	now := fixture.clock.now()
	roleName := "identity-http-revocable-" + uuid.NewString()[:8]
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
	) VALUES($1,$2,$3,1,$4,ARRAY['identity_verification.read','identity_verification.review']::text[],
		'identity.custom_role.create',$5,$3,$6,'totp',$7,$7)`, roleID, tenantID,
		fixture.applicant.ScopeID, roleName, manager.UserID, uuid.New(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE custom_roles
		SET current_revision=1,updated_at=$3
		WHERE id=$1 AND tenant_scope_id=$2 AND current_revision=0`, roleID,
		fixture.applicant.ScopeID, now); err != nil {
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
	rawSession, _, err := fixture.tokens.Mint(userID, fixture.applicant.ScopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := identityverification.NewSessionActor(userID, fixture.applicant.ScopeID, "tenant",
		sessionID, rawSession)
	if err != nil {
		t.Fatal(err)
	}
	return httpRevocableReviewer{integrationActor: integrationActor{Actor: actor, roleID: roleID,
		token: rawSession}, roleName: roleName, manager: manager}
}

func blockHTTPRevocationTarget(
	ctx context.Context,
	tx pgx.Tx,
	reviewer httpRevocableReviewer,
	revocation string,
) (string, error) {
	var id uuid.UUID
	switch revocation {
	case "session":
		return "auth_sessions", tx.QueryRow(ctx, `SELECT id FROM auth_sessions WHERE id=$1 FOR UPDATE`,
			reviewer.SessionID()).Scan(&id)
	case "assignment":
		return "custom_role_grants", tx.QueryRow(ctx, `SELECT id FROM custom_role_grants
			WHERE tenant_scope_id=$1 AND role_id=$2 AND subject_user_id=$3 FOR UPDATE`,
			reviewer.ScopeID, reviewer.roleID, reviewer.UserID).Scan(&id)
	case "role_permission_read", "role_permission_review":
		return "custom_roles", tx.QueryRow(ctx, `SELECT id FROM custom_roles WHERE id=$1 FOR UPDATE`,
			reviewer.roleID).Scan(&id)
	default:
		return "", fmt.Errorf("unsupported HTTP reviewer revocation %q", revocation)
	}
}

func waitForReviewerListCaseLock(
	t *testing.T,
	observerPool *pgxpool.Pool,
	businessPool *pgxpool.Pool,
	backendPID int,
	applicationName string,
) {
	t.Helper()
	if observerPool == businessPool {
		t.Fatal("reviewer list lock observer must not use the single-connection business pool")
	}
	waitForExactHTTPLock(t, observerPool, "reviewer list case relation wait", `SELECT EXISTS(
			SELECT 1 FROM pg_locks lock_row
			JOIN pg_class relation ON relation.oid=lock_row.relation
			JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
			JOIN pg_stat_activity activity ON activity.pid=lock_row.pid
			WHERE lock_row.pid=$1 AND activity.application_name=$2
			  AND relation.relname='identity_verification_cases'
			  AND namespace.nspname=current_schema()
			  AND lock_row.mode='AccessShareLock' AND NOT lock_row.granted
		)`, backendPID, applicationName)
}

func waitForHTTPGlobalExclusiveWaiter(
	t *testing.T,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName string,
) {
	t.Helper()
	waitForExactHTTPLock(t, pool, "HTTP revocation global exclusive wait", `SELECT EXISTS(
		SELECT 1 FROM pg_locks lock_row
		JOIN pg_stat_activity activity ON activity.pid=lock_row.pid
		WHERE lock_row.pid=$1 AND activity.application_name=$2
		  AND lock_row.locktype='advisory' AND lock_row.classid=1229016321::oid
		  AND lock_row.objid=1::oid AND lock_row.objsubid=2
		  AND lock_row.mode='ExclusiveLock' AND lock_row.granted=false
	)`, backendPID, applicationName)
}

func waitForHTTPGlobalSharedWaiter(
	t *testing.T,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName string,
) {
	t.Helper()
	waitForExactHTTPLock(t, pool, "reviewer list global shared wait", `SELECT EXISTS(
		SELECT 1 FROM pg_locks lock_row
		JOIN pg_stat_activity activity ON activity.pid=lock_row.pid
		WHERE lock_row.pid=$1 AND activity.application_name=$2
		  AND lock_row.locktype='advisory' AND lock_row.classid=1229016321::oid
		  AND lock_row.objid=1::oid AND lock_row.objsubid=2
		  AND lock_row.mode='ShareLock' AND lock_row.granted=false
	)`, backendPID, applicationName)
}

func waitForHTTPRevocationTarget(
	t *testing.T,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName, relationName string,
) {
	t.Helper()
	waitForExactHTTPLock(t, pool, "formal revocation target wait", `SELECT
		EXISTS(
			SELECT 1 FROM pg_locks relation_lock
			JOIN pg_class relation ON relation.oid=relation_lock.relation
			JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
			JOIN pg_stat_activity activity ON activity.pid=relation_lock.pid
			WHERE relation_lock.pid=$1 AND activity.application_name=$2
			  AND relation.relname=$3 AND namespace.nspname=current_schema()
			  AND relation_lock.mode='RowShareLock'
			  AND relation_lock.granted=true
		) AND EXISTS(
			SELECT 1 FROM pg_locks transaction_lock
			JOIN pg_stat_activity activity ON activity.pid=transaction_lock.pid
			WHERE transaction_lock.pid=$1 AND activity.application_name=$2
			  AND transaction_lock.locktype='transactionid'
			  AND transaction_lock.mode='ShareLock' AND transaction_lock.granted=false
		)`, backendPID, applicationName, relationName)
}

func waitForExactHTTPLock(
	t *testing.T,
	pool *pgxpool.Pool,
	description, query string,
	arguments ...any,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		var matched bool
		if err := pool.QueryRow(ctx, query, arguments...).Scan(&matched); err != nil {
			t.Fatal(err)
		}
		if matched {
			return
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	t.Fatalf("%s was not observed: %v", description, ctx.Err())
}

func assertHTTPGlobalExclusiveHeld(
	t *testing.T,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName string,
) {
	t.Helper()
	var matched bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM pg_locks lock_row
		JOIN pg_stat_activity activity ON activity.pid=lock_row.pid
		WHERE lock_row.pid=$1 AND activity.application_name=$2
		  AND lock_row.locktype='advisory' AND lock_row.classid=1229016321::oid
		  AND lock_row.objid=1::oid AND lock_row.objsubid=2
		  AND lock_row.mode='ExclusiveLock' AND lock_row.granted=true
	)`, backendPID, applicationName).Scan(&matched); err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatalf("backend %d (%s) does not hold the IAM global exclusive lock",
			backendPID, applicationName)
	}
}

func assertHTTPListHasNoCaseLocks(t *testing.T, pool *pgxpool.Pool, backendPID int) {
	t.Helper()
	var lockCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_locks lock_row
		JOIN pg_class relation ON relation.oid=lock_row.relation
		JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
		WHERE lock_row.pid=$1 AND relation.relname='identity_verification_cases'
		  AND namespace.nspname=current_schema()`, backendPID).
		Scan(&lockCount); err != nil {
		t.Fatal(err)
	}
	if lockCount != 0 {
		t.Fatalf("reviewer list backend %d acquired %d case locks before IAM authorization",
			backendPID, lockCount)
	}
}

func receiveHTTPListWorker(
	t *testing.T,
	ctx context.Context,
	result <-chan *httptest.ResponseRecorder,
) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case listed := <-result:
		return listed
	case <-ctx.Done():
		t.Fatalf("reviewer list worker did not finish: %v", ctx.Err())
		return nil
	}
}

func receiveHTTPWorker(ctx context.Context, result <-chan error) error {
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return fmt.Errorf("worker did not finish: %w", ctx.Err())
	}
}

func (fixture *httpIntegrationFixture) createSubmitted(t *testing.T, key string, marker byte) CaseView {
	t.Helper()
	token := integrationToken(marker)
	fixture.registry.add(fixture.applicant.Actor, token,
		integrationPersonalEvidence(identityverification.KindPersonalInitial, bytesOf(32, marker), marker+1))
	draft := decodeCase(t, fixture.create(t, "applicant", identityverification.KindPersonalInitial,
		token, key+"-create", http.StatusCreated))
	fixture.settle(t, draft.ID)
	submitted := fixture.request(t, "applicant", http.MethodPost,
		apiPrefix+"/cases/"+draft.ID.String()+"/submit", "", key+"-submit", draft.Revision)
	if submitted.Code != http.StatusOK {
		t.Fatalf("%s submit = %d %s", key, submitted.Code, submitted.Body.String())
	}
	return decodeCase(t, submitted)
}

type registrySettlementCommitter struct {
	registry *reservationRegistry
}

func (committer registrySettlementCommitter) Commit(ctx context.Context,
	request identityverification.SettlementCommitRequest,
) (identityverification.SettlementCommitResult, error) {
	if request.ResolverName != "test-resolver" {
		return identityverification.SettlementCommitResult{
			Outcome: identityverification.SettlementCommitPermanent, FailureCode: "resolver_not_supported",
		}, nil
	}
	if err := committer.registry.Commit(ctx, request.ResolverReference, request.CaseID); err != nil {
		return identityverification.SettlementCommitResult{}, err
	}
	return identityverification.SettlementCommitResult{Outcome: identityverification.SettlementCommitSucceeded}, nil
}

func (committer registrySettlementCommitter) Configured() bool {
	return committer.registry != nil
}

func (committer registrySettlementCommitter) Publish(ctx context.Context,
	request identityverification.SettlementCommitRequest,
) (identityverification.SettlementCommitResult, error) {
	return committer.Commit(ctx, request)
}

func (fixture *httpIntegrationFixture) settle(t *testing.T, caseID uuid.UUID) {
	t.Helper()
	processed, err := fixture.settlementWorker.RunOnce(context.Background())
	if err != nil || !processed {
		t.Fatalf("settle evidence for case %s: processed=%t error=%v", caseID, processed, err)
	}
	var state string
	if err := fixture.pool.QueryRow(context.Background(), `SELECT state
		FROM identity_verification_evidence_settlements WHERE case_id=$1`, caseID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != identityverification.SettlementSettled {
		t.Fatalf("case %s settlement state = %s", caseID, state)
	}
}

func (fixture *httpIntegrationFixture) create(t *testing.T, actorToken, kind, evidenceToken, key string,
	wantStatus int,
) *httptest.ResponseRecorder {
	t.Helper()
	recorder := fixture.request(t, actorToken, http.MethodPost, apiPrefix+"/cases",
		fmt.Sprintf(`{"kind":%q,"evidence_token":%q}`, kind, evidenceToken), key, 0)
	if recorder.Code != wantStatus {
		t.Fatalf("create status=%d want=%d body=%s", recorder.Code, wantStatus, recorder.Body.String())
	}
	return recorder
}

func (fixture *httpIntegrationFixture) request(t *testing.T, actorToken, method, path, body, key string,
	revision int64,
) *httptest.ResponseRecorder {
	t.Helper()
	return integrationRequest(fixture.handler, fixture.rawToken(actorToken), method, path, body, key, revision)
}

func (fixture *httpIntegrationFixture) requestContext(
	ctx context.Context,
	actorToken, method, path, body, key string,
	revision int64,
) *httptest.ResponseRecorder {
	return integrationRequestContext(ctx, fixture.handler, fixture.rawToken(actorToken), method, path, body, key, revision)
}

func (fixture *httpIntegrationFixture) rawToken(alias string) string {
	for _, actor := range fixture.actorsByToken {
		if actor.token == alias {
			return actor.token
		}
	}
	if actor, ok := fixture.actorsByToken[alias]; ok {
		return actor.token
	}
	return alias
}

func integrationRequest(handler http.Handler, actorToken, method, path, body, key string,
	revision int64,
) *httptest.ResponseRecorder {
	return integrationRequestContext(context.Background(), handler, actorToken, method, path, body, key, revision)
}

func integrationRequestContext(
	ctx context.Context,
	handler http.Handler,
	actorToken, method, path, body, key string,
	revision int64,
) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequestWithContext(ctx, method, path, reader)
	request.Header.Set("Authorization", "Bearer "+actorToken)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("X-Request-ID", "request-"+key)
	}
	if revision > 0 {
		request.Header.Set("If-Match", fmt.Sprintf(`"%d"`, revision))
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func (fixture *httpIntegrationFixture) authenticate(_ *http.Request,
	rawSession string,
) (identity.AuthenticatedSession, error) {
	if session, ok := fixture.platformSessions[rawSession]; ok {
		return session, nil
	}
	actor, ok := fixture.actorsByToken[rawSession]
	if !ok {
		return identity.AuthenticatedSession{}, ErrUnauthenticated
	}
	return identity.AuthenticatedSession{SessionID: actor.SessionID(), Principal: identity.Principal{
		UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind,
	}}, nil
}

func newHTTPIntegrationFixture(t *testing.T) *httpIntegrationFixture {
	t.Helper()
	pool := isolatedHTTPPool(t)
	clock := &integrationClock{value: time.Date(2036, 7, 23, 8, 0, 0, 0, time.UTC)}
	tokens, err := identity.NewTokenManager("identity-verification-http-session-secret-2026", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0xb8}, 32), clock.now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	core, err := identityverification.NewIAMService(pool, audit.New(pool), iam, identityverification.Config{
		Clock: clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	scope := insertHTTPScope(t, pool, "HTTP Identity Tenant")
	otherScope := insertHTTPScope(t, pool, "Other HTTP Identity Tenant")
	fixture := &httpIntegrationFixture{pool: pool, clock: clock, core: core, reader: reader,
		identity: identityService, iam: iam, tokens: tokens,
		registry:         newReservationRegistry(),
		platformSessions: map[string]identity.AuthenticatedSession{},
		actorsByToken:    map[string]integrationActor{}}
	fixture.settlementWorker, err = identityverification.NewSettlementWorker(pool, audit.New(pool),
		registrySettlementCommitter{registry: fixture.registry}, identityverification.SettlementWorkerConfig{
			Clock: clock.now, LeaseDuration: time.Minute, RetryDelay: time.Minute, MaxAttempts: 3,
		})
	if err != nil {
		t.Fatal(err)
	}
	fixture.applicant = insertHTTPActor(t, pool, tokens, scope, "applicant",
		"identity_verification.self.manage", "identity_verification.read", "identity_verification.review")
	fixture.otherUser = insertHTTPActor(t, pool, tokens, scope, "other-user", "identity_verification.self.manage")
	fixture.reviewer = insertHTTPActor(t, pool, tokens, scope, "reviewer",
		"identity_verification.read", "identity_verification.review")
	fixture.secondReviewer = insertHTTPActor(t, pool, tokens, scope, "second-reviewer",
		"identity_verification.read", "identity_verification.review")
	fixture.otherReviewer = insertHTTPActor(t, pool, tokens, otherScope, "other-reviewer",
		"identity_verification.read", "identity_verification.review")
	fixture.actorsByToken = map[string]integrationActor{
		"applicant": fixture.applicant, "other-user": fixture.otherUser,
		"reviewer": fixture.reviewer, "second-reviewer": fixture.secondReviewer,
		"other-reviewer":        fixture.otherReviewer,
		fixture.applicant.token: fixture.applicant, fixture.otherUser.token: fixture.otherUser,
		fixture.reviewer.token: fixture.reviewer, fixture.secondReviewer.token: fixture.secondReviewer,
		fixture.otherReviewer.token: fixture.otherReviewer,
	}
	fixture.handler, err = NewRuntimeHandler(RuntimeConfig{Enabled: true,
		Core: identityverification.Config{Clock: clock.now, ReviewTTL: 2 * time.Hour,
			RetentionPeriod: 24 * time.Hour},
		Service: ServiceConfig{CursorKey: []byte("0123456789abcdef0123456789abcdef")}},
		RuntimeDependencies{Pool: pool, Identity: identityService, IAM: iam, Resolver: fixture.registry,
			SettlementPublisher: registrySettlementCommitter{registry: fixture.registry}, Clock: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func isolatedHTTPPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return isolatedHTTPSchema(t, true)
}

// isolatedHTTPSchema returns a fresh schema in the TEST_DATABASE_URL database,
// migrated to the release head when migrate is set.
func isolatedHTTPSchema(t *testing.T, migrate bool) *pgxpool.Pool {
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
	// A full migration from scratch takes minutes on a loaded machine.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "identity_verification_http_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^identity_verification_http_test_[a-f0-9]{32}$`).MatchString(schema) {
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
	if !migrate {
		t.Cleanup(func() {
			pool.Close()
			cleanupCtx, cleanupCancel := databasetest.CleanupContext()
			defer cleanupCancel()
			if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
				t.Errorf("drop HTTP identity schema: %v", err)
			}
			admin.Close()
		})
		return pool
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("migrate HTTP identity schema: %v", err)
	}
	var migration37, identityTable bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=37),
		to_regclass('identity_verification_cases') IS NOT NULL`).Scan(&migration37, &identityTable); err != nil ||
		!migration37 || !identityTable {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("migration 037 compatibility = %t/%t, %v", migration37, identityTable, err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop HTTP identity schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func openNamedHTTPPool(t *testing.T, source *pgxpool.Pool, applicationName string) *pgxpool.Pool {
	t.Helper()
	var schema string
	if err := source.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	// Copy the source pool's settings so a sibling session reaches the same
	// database (a template clone is not the TEST_DATABASE_URL database).
	config := source.Config()
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func insertHTTPScope(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
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

func insertHTTPActor(t *testing.T, pool *pgxpool.Pool, tokens *identity.TokenManager,
	scopeID uuid.UUID, label string,
	permissions ...string,
) integrationActor {
	t.Helper()
	userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New()
	username := label + "-" + uuid.NewString()[:8]
	if _, err := pool.Exec(context.Background(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'test-password-hash')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	sessionHash := sha256.Sum256(sessionID[:])
	if _, err := pool.Exec(context.Background(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, userID, scopeID, sessionHash[:],
		time.Now().UTC().Add(-time.Hour), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'identity verification HTTP test role',true)`, roleID, scopeID,
		"identity-http-test-"+uuid.NewString()[:8]); err != nil {
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
	rawSession, _, err := tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := identityverification.NewSessionActor(userID, scopeID, "tenant", sessionID, rawSession)
	if err != nil {
		t.Fatal(err)
	}
	return integrationActor{Actor: actor, roleID: roleID, token: rawSession}
}

func integrationPersonalEvidence(kind string, fingerprint []byte, marker byte) ResolvedEvidence {
	return ResolvedEvidence{Kind: kind, SubjectFingerprint: fingerprint,
		Materials: []identityverification.MaterialInput{
			integrationMaterial(identityverification.MaterialIdentityDocument, marker),
			integrationMaterial(identityverification.MaterialLivenessEvidence, marker+1),
		}}
}

func integrationEnterpriseEvidence(agentFingerprint []byte, marker byte) ResolvedEvidence {
	return ResolvedEvidence{Kind: identityverification.KindEnterprise, SubjectFingerprint: bytesOf(32, marker),
		OrganizationName: "Confidential Network Organization", LegalPersonFingerprint: bytesOf(32, marker+1),
		AgentFingerprint: agentFingerprint, AgentRelationship: identityverification.RelationshipAuthorizedRepresentative,
		Materials: []identityverification.MaterialInput{
			integrationMaterial(identityverification.MaterialBusinessLicense, marker+2),
			integrationMaterial(identityverification.MaterialLegalIdentity, marker+3),
			integrationMaterial(identityverification.MaterialAgentIdentity, marker+4),
			integrationMaterial(identityverification.MaterialAuthorization, marker+5),
		}}
}

func integrationMaterial(kind string, marker byte) identityverification.MaterialInput {
	return identityverification.MaterialInput{Kind: kind, EnvelopeProvider: "kms",
		EnvelopeKeyID: fmt.Sprintf("kms/identity/key-%02x", marker), EncryptedEnvelope: bytesOf(32, marker),
		ObjectReference: fmt.Sprintf("identity/private/object-%02x", marker), ObjectSHA256: bytesOf(32, marker+7),
		MIMEType: "image/jpeg", SizeBytes: 1024}
}

func integrationToken(marker byte) string {
	return strings.Repeat(string([]byte{marker}), 32)
}

func decodeCase(t *testing.T, recorder *httptest.ResponseRecorder) CaseView {
	t.Helper()
	var item CaseView
	if err := json.NewDecoder(recorder.Body).Decode(&item); err != nil {
		t.Fatalf("decode case: %v: %s", err, recorder.Body.String())
	}
	return item
}

func assertSensitiveHTTPResponse(t *testing.T, response string, evidence ResolvedEvidence) {
	t.Helper()
	prohibited := []string{evidence.OrganizationName, fmt.Sprintf("%x", evidence.SubjectFingerprint),
		base64.StdEncoding.EncodeToString(evidence.SubjectFingerprint)}
	for _, material := range evidence.Materials {
		prohibited = append(prohibited, material.EnvelopeKeyID, material.ObjectReference,
			fmt.Sprintf("%x", material.EncryptedEnvelope), fmt.Sprintf("%x", material.ObjectSHA256),
			base64.StdEncoding.EncodeToString(material.EncryptedEnvelope), base64.StdEncoding.EncodeToString(material.ObjectSHA256))
	}
	for _, value := range prohibited {
		if value != "" && strings.Contains(response, value) {
			t.Fatalf("HTTP response leaked sensitive value %q: %s", value, response)
		}
	}
}
