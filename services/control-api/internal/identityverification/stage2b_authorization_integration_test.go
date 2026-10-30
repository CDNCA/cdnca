//go:build integration

package identityverification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var verificationWriteFactTables = []string{
	"identity_verification_cases",
	"identity_verification_materials",
	"identity_verification_evidence_settlements",
	"identity_verification_write_requests",
	"identity_verification_submissions",
	"identity_verification_review_assignments",
	"identity_verification_reviews",
	"identity_verification_state_events",
	"identity_verified_persons",
	"identity_verified_organizations",
	"audit_events",
}

func sessionRefreshTokenHash(sessionID uuid.UUID) [sha256.Size]byte {
	return sha256.Sum256([]byte(sessionID.String()))
}

func TestSessionRefreshTokenHashUsesFullUUIDDeterministically(t *testing.T) {
	ids := []uuid.UUID{
		uuid.MustParse("ab000000-0000-0000-0000-000000000001"),
		uuid.MustParse("ab000000-0000-0000-0000-000000000002"),
		uuid.MustParse("ab000000-0000-0000-0000-000000000003"),
	}
	seen := make(map[[sha256.Size]byte]uuid.UUID, len(ids))
	for _, id := range ids {
		if id[0] != ids[0][0] {
			t.Fatalf("test UUID %s does not share first byte", id)
		}
		hash := sessionRefreshTokenHash(id)
		if hash != sessionRefreshTokenHash(id) {
			t.Fatalf("session hash for %s is not deterministic", id)
		}
		if previous, exists := seen[hash]; exists {
			t.Fatalf("session hash collision for %s and %s", previous, id)
		}
		seen[hash] = id
	}
}

const identityVerificationTestSessionSecret = "identity-verification-test-session-secret-2026"

func newTestIAMAuthorizer(t *testing.T, pool *pgxpool.Pool, now Clock) *iamlock.Authorizer {
	t.Helper()
	tokens, err := identity.NewTokenManager(identityVerificationTestSessionSecret, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, sessioncredential.Clock(now))
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0xa7}, 32), apikeycredential.Clock(now))
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}

func mintTestSessionActor(t *testing.T, userID, scopeID, sessionID uuid.UUID) Actor {
	t.Helper()
	tokens, err := identity.NewTokenManager(identityVerificationTestSessionSecret, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rawSession, _, err := tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := NewSessionActor(userID, scopeID, "tenant", sessionID, rawSession)
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func newTestTxAuthorizer(t *testing.T, pool *pgxpool.Pool, now Clock) TxAuthorizer {
	t.Helper()
	authorizer, err := newIAMSessionTxAuthorizer(newTestIAMAuthorizer(t, pool, now))
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}

func newAuthorizedTestService(
	t *testing.T,
	pool *pgxpool.Pool,
	auditor AuditAppender,
	config Config,
) *Service {
	t.Helper()
	now := config.Clock
	if now == nil {
		now = time.Now
	}
	service, err := NewIAMService(pool, auditor, newTestIAMAuthorizer(t, pool, now), config)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type stage2BStepUpVerifier struct {
	now Clock
}

func (verifier stage2BStepUpVerifier) VerifyAndConsume(
	_ context.Context,
	tx pgx.Tx,
	proof rbacmanager.StepUpProof,
	check rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	if tx == nil || proof.Token != "verified-token" || check.RequestID == "" || check.TraceID == "" {
		return rbacmanager.StepUpEvidence{}, rbacmanager.ErrStepUpRequired
	}
	return rbacmanager.StepUpEvidence{
		ProofID: uuid.New(), Method: "totp", VerifiedAt: storeTime(verifier.now()),
	}, nil
}

type stage2BRevocationAPIs struct {
	identity     *identity.Service
	accountActor identity.Actor
	rbac         *rbacmanager.Service
	pool         *pgxpool.Pool
	now          Clock
}

func newStage2BRevocationAPIs(t *testing.T, pool *pgxpool.Pool, now Clock) stage2BRevocationAPIs {
	t.Helper()
	tokens, err := identity.NewTokenManager(identityVerificationTestSessionSecret, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rbacService, err := rbacmanager.NewServiceWithDependencies(pool, audit.New(pool),
		stage2BStepUpVerifier{now: now}, rbacmanager.Clock(now))
	if err != nil {
		t.Fatal(err)
	}
	return stage2BRevocationAPIs{
		identity: identityService, accountActor: insertStage2BPlatformAdmin(t, pool),
		rbac: rbacService, pool: pool, now: now,
	}
}

func insertStage2BPlatformAdmin(t *testing.T, pool *pgxpool.Pool) identity.Actor {
	t.Helper()
	var scopeID uuid.UUID
	err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		scopeID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	userID, roleID := uuid.New(), uuid.New()
	username := "identity-platform-admin-" + uuid.NewString()[:8]
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'test-password-hash')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
		scopeID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'identity verification platform user manager',true)`, roleID, scopeID,
		"identity-platform-admin-"+uuid.NewString()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'identity.users.manage')`, roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
	return identity.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
}

func TestIAMSessionTxAuthorizerRejectsMismatchedSealedSession(t *testing.T) {
	fixture := newVerificationFixture(t)
	actor := fixture.applicant.Actor
	actor.session.sessionID = uuid.New()
	before := counts(t, fixture.pool, verificationWriteFactTables...)
	_, err := fixture.service.CreateDraft(t.Context(), actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xa4), "mismatched-sealed-session"))
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("CreateDraft() error = %v, want permission denied", err)
	}
	assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))
}

func TestAuthorizeCreateDraftUsesLiveIAMStateWithoutBusinessWrites(t *testing.T) {
	for _, revocation := range []string{"session", "account", "membership", "assignment", "role_permission"} {
		t.Run(revocation, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			key := "create-preflight-" + revocation
			actor := insertActor(t, fixture.pool, fixture.applicant.ScopeID, key, permissionSelfManage)
			if revocation == "membership" || revocation == "assignment" || revocation == "role_permission" {
				actor = insertCustomStage2BActor(t, fixture, key+"-custom", permissionSelfManage)
			}
			before := counts(t, fixture.pool, verificationWriteFactTables...)
			if err := fixture.service.AuthorizeCreateDraft(t.Context(), actor.Actor); err != nil {
				t.Fatalf("AuthorizeCreateDraft() before revocation = %v", err)
			}
			assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))

			revokeStage2BActor(t, fixture, actor, revocation, permissionSelfManage)
			before = counts(t, fixture.pool, verificationWriteFactTables...)
			if err := fixture.service.AuthorizeCreateDraft(t.Context(), actor.Actor); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("AuthorizeCreateDraft() after %s revocation = %v", revocation, err)
			}
			assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))
		})
	}
}

func TestLegacyServiceConstructorFailsClosedWithoutTransactionAuthorizer(t *testing.T) {
	pool := isolatedVerificationPool(t, true)
	clock := &fixedClock{value: time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)}
	dependencyService, err := NewServiceWithDependencies(pool, audit.New(pool), Config{
		Clock: clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	zeroConfigService, err := NewServiceWithDependencies(pool, audit.New(pool), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defaultService, err := NewService(pool)
	if err != nil {
		t.Fatal(err)
	}
	if service, constructorErr := NewTenantSessionService(pool, audit.New(pool), nil, Config{}); service != nil || !errors.Is(constructorErr, ErrInvalidService) {
		t.Fatalf("legacy tenant-session constructor = (%T,%v)", service, constructorErr)
	}
	var typedNilAuthorizer *snapshotBeforeAuthorization
	if _, err := newServiceWithTransactionAuthorizer(pool, audit.New(pool), typedNilAuthorizer, Config{}); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("typed nil transaction authorizer error = %v", err)
	}
	scopeID := insertTenantScope(t, pool, "Legacy Constructor Tenant")
	actor := insertActor(t, pool, scopeID, "legacy-constructor", permissionSelfManage)
	tables := []string{
		"identity_verification_cases",
		"identity_verification_materials",
		"identity_verification_evidence_settlements",
		"identity_verification_write_requests",
		"identity_verification_state_events",
		"audit_events",
	}
	for name, service := range map[string]*Service{
		"new_service": defaultService, "new_service_with_dependencies": dependencyService,
	} {
		before := counts(t, pool, tables...)
		_, err = service.CreateDraft(t.Context(), actor.Actor,
			validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xa5), "legacy-constructor-deny-"+name))
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s CreateDraft() error = %v, want permission denied", name, err)
		}
		if after := counts(t, pool, tables...); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("%s write changed facts: before=%v after=%v", name, before, after)
		}
	}

	if _, err := pool.Exec(t.Context(), `ALTER TABLE identity_verification_cases
		RENAME TO identity_verification_cases_unreadable`); err != nil {
		t.Fatal(err)
	}
	zeroService := &Service{pool: pool, auditor: audit.New(pool)}
	for name, service := range map[string]*Service{
		"new_service": defaultService, "new_service_with_dependencies": dependencyService,
		"new_service_with_dependencies_zero_config": zeroConfigService, "zero_value": zeroService,
	} {
		for readName, read := range map[string]func(context.Context) error{
			"self": func(ctx context.Context) error {
				_, readErr := service.Get(ctx, actor.Actor, uuid.New())
				return readErr
			},
			"reviewer": func(ctx context.Context) error {
				_, readErr := service.GetForReview(ctx, actor.Actor, uuid.New())
				return readErr
			},
		} {
			if err := read(t.Context()); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("%s %s read error = %v, want permission denied before case query", name, readName, err)
			}
		}
	}
}

func TestWriteSessionBindingsFailClosed(t *testing.T) {
	fixture := newVerificationFixture(t)
	for name, mutate := range map[string]func(*Actor){
		"missing":               func(actor *Actor) { actor.session = sessionReference{} },
		"raw_missing":           func(actor *Actor) { actor.rawSession = "" },
		"session_mismatch":      func(actor *Actor) { actor.session.sessionID = uuid.New() },
		"scope_mismatch":        func(actor *Actor) { actor.session.scopeID = uuid.New() },
		"public_user_mismatch":  func(actor *Actor) { actor.UserID = uuid.New() },
		"public_scope_mismatch": func(actor *Actor) { actor.ScopeID = uuid.New() },
		"public_kind_mismatch":  func(actor *Actor) { actor.ScopeKind = "platform" },
	} {
		t.Run(name, func(t *testing.T) {
			actor := fixture.applicant.Actor
			mutate(&actor)
			before := counts(t, fixture.pool, verificationWriteFactTables...)
			_, err := fixture.service.CreateDraft(t.Context(), actor,
				validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xb1), "binding-"+name))
			if !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("CreateDraft(%s) error = %v, want closed rejection", name, err)
			}
			assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))
		})
	}
}

func TestIdentityVerificationWritesReauthorizeFreshAndReplay(t *testing.T) {
	operations := []struct {
		name        string
		permissions []string
	}{
		{name: "create", permissions: []string{permissionSelfManage}},
		{name: "submit", permissions: []string{permissionSelfManage}},
		{name: "start_review", permissions: []string{permissionRead, permissionReview}},
		{name: "review", permissions: []string{permissionRead, permissionReview}},
		{name: "withdraw", permissions: []string{permissionSelfManage}},
		{name: "expire", permissions: []string{permissionSelfManage}},
	}
	revocations := []string{"session", "account", "membership", "assignment", "role_permission"}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			for _, revocation := range revocations {
				for _, replay := range []bool{false, true} {
					mode := "fresh"
					if replay {
						mode = "replay"
					}
					t.Run(revocation+"_"+mode, func(t *testing.T) {
						fixture.clock.set(time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC))
						key := operation.name + "-" + revocation + "-" + mode + "-" + uuid.NewString()[:8]
						actor := insertActor(t, fixture.pool, fixture.applicant.ScopeID, key, operation.permissions...)
						if revocation == "membership" || revocation == "assignment" || revocation == "role_permission" {
							actor = insertCustomStage2BActor(t, fixture, key+"-custom", operation.permissions...)
						}
						command := prepareStage2BWrite(t, fixture, actor, operation.name, key)
						if replay {
							if err := command(t.Context()); err != nil {
								t.Fatalf("initial %s: %v", operation.name, err)
							}
						}
						revokeStage2BActor(t, fixture, actor, revocation, operation.permissions[len(operation.permissions)-1])
						before := counts(t, fixture.pool, verificationWriteFactTables...)
						if err := command(t.Context()); !errors.Is(err, ErrPermissionDenied) {
							t.Fatalf("%s after %s revocation error = %v", mode, revocation, err)
						}
						assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))
					})
				}
			}
		})
	}
}

func TestRequeueSettlementReauthorizesAndUsesStaleRevisionContract(t *testing.T) {
	for _, revocation := range []string{"session", "account", "membership", "assignment", "role_permission"} {
		for _, replay := range []bool{false, true} {
			mode := "fresh"
			if replay {
				mode = "replay"
			}
			t.Run(revocation+"_"+mode, func(t *testing.T) {
				fixture := newVerificationFixture(t)
				key := "requeue-" + revocation + "-" + mode
				settlementID, revision := preparePermanentSettlement(t, fixture, key)
				actor := insertActor(t, fixture.pool, fixture.applicant.ScopeID, key,
					permissionSettlementRequeue)
				if revocation == "membership" || revocation == "assignment" || revocation == "role_permission" {
					actor = insertCustomStage2BActor(t, fixture, key+"-custom",
						permissionSettlementRequeue)
				}
				request := RequeueSettlementRequest{SettlementID: settlementID, ExpectedRevision: revision,
					ReasonCode: "operator_retry", RequestID: "requeue-denied-" + revocation + "-" + mode}
				if replay {
					if _, err := fixture.service.RequeueSettlement(t.Context(), actor.Actor, request); err != nil {
						t.Fatalf("initial RequeueSettlement(%s) error = %v", revocation, err)
					}
				}
				revokeStage2BActor(t, fixture, actor, revocation, permissionSettlementRequeue)
				before := counts(t, fixture.pool, verificationWriteFactTables...)
				_, err := fixture.service.RequeueSettlement(t.Context(), actor.Actor, request)
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("RequeueSettlement(%s %s) error = %v", revocation, mode, err)
				}
				assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))
			})
		}
	}

	t.Run("authorized duplicate is stale revision, not replay", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		settlementID, revision := preparePermanentSettlement(t, fixture, "requeue-stale")
		actor := insertActor(t, fixture.pool, fixture.applicant.ScopeID, "requeue-stale",
			permissionSettlementRequeue)
		request := RequeueSettlementRequest{SettlementID: settlementID, ExpectedRevision: revision,
			ReasonCode: "operator_retry", RequestID: "requeue-stale-request"}
		if _, err := fixture.service.RequeueSettlement(t.Context(), actor.Actor, request); err != nil {
			t.Fatal(err)
		}
		before := counts(t, fixture.pool, verificationWriteFactTables...)
		if _, err := fixture.service.RequeueSettlement(t.Context(), actor.Actor, request); !errors.Is(err, ErrRevisionConflict) {
			t.Fatalf("duplicate RequeueSettlement() error = %v, want revision conflict", err)
		}
		assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))
	})
}

func TestWriteFirstLockIsIAMGlobalShared(t *testing.T) {
	operations := []struct {
		name        string
		permissions []string
	}{
		{name: "create", permissions: []string{permissionSelfManage}},
		{name: "submit", permissions: []string{permissionSelfManage}},
		{name: "start_review", permissions: []string{permissionRead, permissionReview}},
		{name: "review", permissions: []string{permissionRead, permissionReview}},
		{name: "withdraw", permissions: []string{permissionSelfManage}},
		{name: "expire", permissions: []string{permissionSelfManage}},
		{name: "requeue", permissions: []string{permissionSettlementRequeue}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			key := "first-lock-" + operation.name
			actor := insertActor(t, fixture.pool, fixture.applicant.ScopeID, key, operation.permissions...)
			// PostgreSQL keeps 63 bytes of application_name (NAMEDATALEN-1); the
			// lock probes compare it exactly, so the name stays within that.
			applicationName := "iv-first-lock-" + operation.name + "-" + uuid.NewString()
			workerPool := openNamedIsolationPool(t, fixture.pool, "read committed", applicationName)
			workerService, err := NewIAMService(workerPool, audit.New(workerPool),
				newTestIAMAuthorizer(t, workerPool, fixture.clock.now), Config{
					Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
				})
			if err != nil {
				workerPool.Close()
				t.Fatal(err)
			}
			var command func(context.Context) error
			if operation.name == "requeue" {
				settlementID, revision := preparePermanentSettlement(t, fixture, key)
				command = func(ctx context.Context) error {
					_, err := workerService.RequeueSettlement(ctx, actor.Actor, RequeueSettlementRequest{
						SettlementID: settlementID, ExpectedRevision: revision,
						ReasonCode: "operator_retry", RequestID: key + "-request",
					})
					return err
				}
			} else {
				command = prepareStage2BWriteWithService(t, fixture, workerService, actor, operation.name, key)
			}
			var backendPID int
			if err := workerPool.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
				workerPool.Close()
				t.Fatal(err)
			}
			holder, err := fixture.pool.Begin(t.Context())
			if err != nil {
				workerPool.Close()
				t.Fatal(err)
			}
			workerCtx, cancelWorker := context.WithTimeout(t.Context(), 5*time.Second)
			workerDone := make(chan error, 1)
			workerCollected := false
			defer func() {
				cancelWorker()
				cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
				defer cleanupCancel()
				_ = holder.Rollback(cleanupCtx)
				if !workerCollected {
					select {
					case <-workerDone:
					case <-cleanupCtx.Done():
					}
				}
				workerPool.Close()
			}()
			if err := iamlock.AcquireExclusive(t.Context(), holder); err != nil {
				t.Fatal(err)
			}
			before := counts(t, fixture.pool, verificationWriteFactTables...)
			go func() { workerDone <- command(workerCtx) }()
			waitForIAMGlobalSharedWaiter(t, fixture.pool, backendPID, applicationName, workerDone)
			assertNoIdentityVerificationRelationLocks(t, fixture.pool, backendPID)
			assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))
			if err := holder.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-workerDone:
				workerCollected = true
				if err != nil {
					t.Fatal(err)
				}
			case <-workerCtx.Done():
				t.Fatalf("write remained blocked after IAM global exclusive release: %v", workerCtx.Err())
			}
		})
	}
}

func TestStrongIsolationOldSnapshotReturnsStableUnavailable(t *testing.T) {
	for _, isolation := range []string{"repeatable read", "serializable"} {
		t.Run(strings.ReplaceAll(isolation, " ", "_"), func(t *testing.T) {
			fixture := newVerificationFixture(t)
			draft, err := fixture.service.CreateDraft(t.Context(), fixture.applicant.Actor,
				validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xc2), "old-snapshot-"+strings.ReplaceAll(isolation, " ", "-")))
			if err != nil {
				t.Fatal(err)
			}
			pool := openStrongIsolationPool(t, fixture.pool, isolation)
			delegate := newTestTxAuthorizer(t, pool, fixture.clock.now)
			hook := &snapshotBeforeAuthorization{
				delegate: delegate, entered: make(chan struct{}), release: make(chan struct{}),
			}
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(hook.release) })
			service, err := newServiceWithTransactionAuthorizer(pool, audit.New(pool), hook, Config{
				Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			workerCtx, cancelWorker := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancelWorker()
			result := make(chan error, 1)
			workerCollected := false
			defer func() {
				cancelWorker()
				releaseOnce.Do(func() { close(hook.release) })
				if !workerCollected {
					cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
					defer cleanupCancel()
					select {
					case <-result:
					case <-cleanupCtx.Done():
					}
				}
			}()
			go func() {
				_, withdrawErr := service.Withdraw(workerCtx, fixture.applicant.Actor,
					mutation(draft, "old-snapshot-withdraw"))
				result <- withdrawErr
			}()
			select {
			case <-hook.entered:
			case <-workerCtx.Done():
				t.Fatalf("write did not establish old snapshot: %v", workerCtx.Err())
			}
			revoker := newStage2BRevocationAPIs(t, fixture.pool, fixture.clock.now)
			if err := revoker.revoke(t.Context(), fixture.applicant, "session", permissionSelfManage,
				"old-snapshot-revoke-"+uuid.NewString()); err != nil {
				t.Fatal(err)
			}
			before := identityVerificationFactCounts(t, fixture.pool)
			releaseOnce.Do(func() { close(hook.release) })
			err = receiveWorker(workerCtx, result)
			workerCollected = true
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Withdraw(%s old snapshot) error = %v", isolation, err)
			}
			assertStableUnavailable(t, err)
			assertFactCountsEqual(t, before, identityVerificationFactCounts(t, fixture.pool))
		})
	}
}

func TestStrongIsolationRevocationCommitOrderMatrix(t *testing.T) {
	for _, isolation := range []string{"repeatable read", "serializable"} {
		for _, revocation := range []string{"session", "account", "membership", "assignment", "role_permission"} {
			for _, businessFirst := range []bool{true, false} {
				for _, replay := range []bool{false, true} {
					order := "revoke_first"
					if businessFirst {
						order = "business_first"
					}
					mode := "fresh"
					if replay {
						mode = "replay"
					}
					name := strings.ReplaceAll(isolation, " ", "_") + "/" + revocation + "/" + order + "/" + mode
					t.Run(name, func(t *testing.T) {
						runStrongIsolationRevocationCase(t, isolation, revocation, businessFirst, replay)
					})
				}
			}
		}
	}
}

func runStrongIsolationRevocationCase(
	t *testing.T,
	isolation, revocation string,
	businessFirst, replay bool,
) {
	t.Helper()
	fixture := newVerificationFixture(t)
	key := strings.ReplaceAll(isolation, " ", "-") + "-" + revocation + "-" + uuid.NewString()[:8]
	actor := insertActor(t, fixture.pool, fixture.applicant.ScopeID, key, permissionSelfManage)
	if revocation == "membership" || revocation == "assignment" || revocation == "role_permission" {
		actor = insertCustomStage2BActor(t, fixture, key+"-custom", permissionSelfManage)
	}
	draft, err := fixture.service.CreateDraft(t.Context(), actor.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, key[0]), key+"-draft"))
	if err != nil {
		t.Fatal(err)
	}
	request := mutation(draft, key+"-withdraw")
	if replay {
		if _, err := fixture.service.Withdraw(t.Context(), actor.Actor, request); err != nil {
			t.Fatal(err)
		}
	}

	// Within application_name's 63 bytes (see TestWriteFirstLockIsIAMGlobalShared).
	businessApplication := "iv-business-" + uuid.NewString()
	revocationApplication := "iv-revocation-" + uuid.NewString()
	businessPool := openNamedIsolationPool(t, fixture.pool, isolation, businessApplication)
	defer businessPool.Close()
	revocationPool := openNamedIsolationPool(t, fixture.pool, "read committed", revocationApplication)
	defer revocationPool.Close()
	var businessPID, revocationPID int
	if err := businessPool.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&businessPID); err != nil {
		t.Fatal(err)
	}
	if err := revocationPool.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&revocationPID); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	revoker := newStage2BRevocationAPIs(t, revocationPool, fixture.clock.now)
	businessDone := make(chan error, 1)
	revocationDone := make(chan error, 1)
	businessCollected, revocationCollected := false, false
	var releaseOnce sync.Once
	var release func()
	defer func() {
		cancel()
		if release != nil {
			releaseOnce.Do(release)
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
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

	if businessFirst {
		hook := &blockingAfterAuthorization{
			delegate: newTestTxAuthorizer(t, businessPool, fixture.clock.now),
			entered:  make(chan struct{}), release: make(chan struct{}),
		}
		release = func() { close(hook.release) }
		service, err := newServiceWithTransactionAuthorizer(businessPool, audit.New(businessPool), hook, Config{
			Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_, writeErr := service.Withdraw(ctx, actor.Actor, request)
			businessDone <- writeErr
		}()
		select {
		case <-hook.entered:
		case <-ctx.Done():
			t.Fatalf("business write did not acquire IAM shared authorization: %v", ctx.Err())
		}
		go func() {
			revocationDone <- revoker.revoke(ctx, actor, revocation, permissionSelfManage,
				"strong-revoke-"+uuid.NewString())
		}()
		waitForIAMGlobalExclusiveWaiter(t, fixture.pool, revocationPID, revocationApplication, revocationDone)
		releaseOnce.Do(release)
		if err := receiveWorker(ctx, businessDone); err != nil {
			t.Fatalf("business-first write: %v", err)
		}
		businessCollected = true
		if err := receiveWorker(ctx, revocationDone); err != nil {
			t.Fatalf("business-first revocation: %v", err)
		}
		revocationCollected = true
		before := identityVerificationFactCounts(t, fixture.pool)
		_, err = service.Withdraw(t.Context(), actor.Actor, request)
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("revoked replay error = %v, want permission denied", err)
		}
		assertFactCountsEqual(t, before, identityVerificationFactCounts(t, fixture.pool))
		return
	}

	blocker, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	release = func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		_ = blocker.Rollback(cleanupCtx)
	}
	if err := blockStage2BRevocationTarget(t.Context(), blocker, actor, revocation); err != nil {
		t.Fatal(err)
	}
	go func() {
		revocationDone <- revoker.revoke(ctx, actor, revocation, permissionSelfManage,
			"strong-revoke-"+uuid.NewString())
	}()
	waitForBackendLockWait(t, fixture.pool, revocationPID, revocationDone)
	assertIAMGlobalExclusiveHeld(t, fixture.pool, revocationPID, revocationApplication)
	service, err := NewIAMService(businessPool, audit.New(businessPool),
		newTestIAMAuthorizer(t, businessPool, fixture.clock.now), Config{
			Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
		})
	if err != nil {
		t.Fatal(err)
	}
	before := identityVerificationFactCounts(t, fixture.pool)
	go func() {
		_, writeErr := service.Withdraw(ctx, actor.Actor, request)
		businessDone <- writeErr
	}()
	waitForIAMGlobalSharedWaiter(t, fixture.pool, businessPID, businessApplication, businessDone)
	releaseOnce.Do(release)
	if err := receiveWorker(ctx, revocationDone); err != nil {
		t.Fatalf("revoke-first revocation: %v", err)
	}
	revocationCollected = true
	err = receiveWorker(ctx, businessDone)
	businessCollected = true
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoke-first write error = %v, want unavailable", err)
	}
	assertStableUnavailable(t, err)
	assertFactCountsEqual(t, before, identityVerificationFactCounts(t, fixture.pool))
}

func TestAuthorizationDenialDoesNotQuerySettlementRecovery(t *testing.T) {
	pool := isolatedVerificationPool(t, true)
	service, err := NewServiceWithDependencies(pool, audit.New(pool), Config{})
	if err != nil {
		t.Fatal(err)
	}
	scopeID := insertTenantScope(t, pool, "Unreadable Settlement Tenant")
	actor := insertActor(t, pool, scopeID, "unreadable-settlement", permissionSelfManage)
	if _, err := pool.Exec(t.Context(), `ALTER TABLE identity_verification_evidence_settlements
		RENAME TO identity_verification_evidence_settlements_unreadable`); err != nil {
		t.Fatal(err)
	}
	_, err = service.CreateDraftWithSettlement(t.Context(), actor.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xc3), "unreadable-settlement"))
	if !errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrCommitOutcomeUnknown) {
		t.Fatalf("authorization denial with unreadable settlement table error = %v", err)
	}
}

func TestUnknownDatabaseErrorIsStableUnavailable(t *testing.T) {
	fixture := newVerificationFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `ALTER TABLE identity_verification_write_requests
		RENAME TO identity_verification_write_requests_unavailable`); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.service.CreateDraft(t.Context(), fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xc4), "unknown-database-error"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateDraft() error = %v, want unavailable", err)
	}
	assertStableUnavailable(t, err)
}

func prepareStage2BWrite(
	t *testing.T,
	fixture *verificationFixture,
	actor testActor,
	operation, key string,
) func(context.Context) error {
	return prepareStage2BWriteWithService(t, fixture, fixture.service, actor, operation, key)
}

func prepareStage2BWriteWithService(
	t *testing.T,
	fixture *verificationFixture,
	service *Service,
	actor testActor,
	operation, key string,
) func(context.Context) error {
	t.Helper()
	switch operation {
	case "create":
		request := validPersonalDraft(KindPersonalInitial, bytesOf(32, key[0]), key)
		return func(ctx context.Context) error {
			_, err := service.CreateDraft(ctx, actor.Actor, request)
			return err
		}
	case "submit":
		draft, err := service.CreateDraft(t.Context(), actor.Actor,
			validPersonalDraft(KindPersonalInitial, bytesOf(32, key[0]), key+"-draft"))
		if err != nil {
			t.Fatal(err)
		}
		settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
		request := mutation(draft, key)
		return func(ctx context.Context) error {
			_, err := service.Submit(ctx, actor.Actor, request)
			return err
		}
	case "start_review":
		applicant := insertActor(t, fixture.pool, fixture.applicant.ScopeID, key+"-applicant", permissionSelfManage)
		submitted := createSubmittedForAuthorizationRace(t, fixture, applicant, key)
		request := mutation(submitted, key+"-start")
		return func(ctx context.Context) error {
			_, err := service.StartReview(ctx, actor.Actor, request)
			return err
		}
	case "review":
		applicant := insertActor(t, fixture.pool, fixture.applicant.ScopeID, key+"-applicant", permissionSelfManage)
		submitted := createSubmittedForAuthorizationRace(t, fixture, applicant, key)
		reviewing, err := service.StartReview(t.Context(), actor.Actor, mutation(submitted, key+"-start"))
		if err != nil {
			t.Fatal(err)
		}
		request := ReviewRequest{CaseID: reviewing.ID, ExpectedRevision: reviewing.Revision,
			Decision: DecisionApprove, ReasonCode: ReasonEvidenceVerified,
			IdempotencyKey: key + "-review", RequestID: key + "-review-request"}
		return func(ctx context.Context) error {
			_, err := service.Review(ctx, actor.Actor, request)
			return err
		}
	case "withdraw":
		draft, err := service.CreateDraft(t.Context(), actor.Actor,
			validPersonalDraft(KindPersonalInitial, bytesOf(32, key[0]), key+"-draft"))
		if err != nil {
			t.Fatal(err)
		}
		request := mutation(draft, key+"-withdraw")
		return func(ctx context.Context) error {
			_, err := service.Withdraw(ctx, actor.Actor, request)
			return err
		}
	case "expire":
		draft, err := service.CreateDraft(t.Context(), actor.Actor,
			validPersonalDraft(KindPersonalInitial, bytesOf(32, key[0]), key+"-draft"))
		if err != nil {
			t.Fatal(err)
		}
		settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
		submitted, err := service.Submit(t.Context(), actor.Actor, mutation(draft, key+"-submit"))
		if err != nil {
			t.Fatal(err)
		}
		fixture.clock.set(*submitted.ExpiresAt)
		request := mutation(submitted, key+"-expire")
		return func(ctx context.Context) error {
			_, err := service.Expire(ctx, actor.Actor, request)
			return err
		}
	default:
		t.Fatalf("unknown write operation %q", operation)
		return nil
	}
}

func revokeStage2BActor(
	t *testing.T,
	fixture *verificationFixture,
	actor testActor,
	revocation, permission string,
) {
	t.Helper()
	apis := newStage2BRevocationAPIs(t, fixture.pool, fixture.clock.now)
	err := apis.revoke(t.Context(), actor, revocation, permission, "stage2b-revoke-"+uuid.NewString())
	if err != nil {
		t.Fatalf("%s revocation: %v", revocation, err)
	}
}

func (apis stage2BRevocationAPIs) revoke(
	ctx context.Context,
	actor testActor,
	revocation, permission, key string,
) error {
	switch revocation {
	case "session":
		return apis.identity.Logout(ctx, actor.SessionID().String(), key)
	case "account":
		current, err := apis.identity.GetUser(ctx, apis.accountActor, actor.UserID)
		if err != nil {
			return err
		}
		fields := identity.UserFields{DisplayName: current.DisplayName}
		if current.Email != nil {
			fields.Email = *current.Email
		}
		if current.Phone != nil {
			fields.Phone = *current.Phone
		}
		_, err = apis.identity.UpdateUser(ctx, apis.accountActor, identity.UpdateUserInput{
			ID: actor.UserID, ExpectedRevision: current.Revision, Fields: fields,
			Status: identity.UserStatusDisabled, Role: current.Role,
			IdempotencyKey: key, RequestID: key,
		})
		return err
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
			if candidate != permission {
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
			UserID: actor.managerUserID, ScopeID: actor.ScopeID, ScopeKind: "tenant",
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

func stage2BRBACActor(actor testActor) rbacmanager.Actor {
	return rbacmanager.Actor{
		UserID: actor.managerUserID, ScopeID: actor.ScopeID, SessionID: actor.managerSessionID,
		ScopeKind: "tenant", IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
}

func stage2BMutation(key string) rbacmanager.MutationContext {
	return rbacmanager.MutationContext{
		IdempotencyKey: key, RequestID: key, TraceID: key,
		StepUp: rbacmanager.StepUpProof{Token: "verified-token"},
	}
}

func insertCustomStage2BActor(
	t *testing.T,
	fixture *verificationFixture,
	label string,
	permissions ...string,
) testActor {
	t.Helper()
	permissionSet := map[string]struct{}{permissionRead: {}}
	for _, permission := range permissions {
		permissionSet[permission] = struct{}{}
	}
	normalizedPermissions := make([]string, 0, len(permissionSet))
	for permission := range permissionSet {
		normalizedPermissions = append(normalizedPermissions, permission)
	}
	sort.Strings(normalizedPermissions)
	permissions = normalizedPermissions
	managerPermissions := append([]string{"identity.roles.manage", "identity.users.manage"}, permissions...)
	manager := insertActor(t, fixture.pool, fixture.applicant.ScopeID, label+"-manager",
		managerPermissions...)
	userID, sessionID, roleID, grantID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	viewerRoleID := ensureTenantViewerRole(t, fixture.pool, fixture.applicant.ScopeID)
	username := strings.ReplaceAll(label+"-"+uuid.NewString()[:8], "_", "-")
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
		sessionHash[:], fixture.clock.now().Add(-time.Hour), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`,
		fixture.applicant.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	now := fixture.clock.now()
	roleName := "identity-stage2b-" + uuid.NewString()[:8]
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
	) VALUES($1,$2,$3,1,$4,$5,'identity.custom_role.create',$6,$3,$7,'totp',$8,$8)`,
		roleID, tenantID, fixture.applicant.ScopeID, roleName, permissions, manager.UserID,
		uuid.New(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE custom_roles
		SET current_revision=1,updated_at=$3
		WHERE id=$1 AND tenant_scope_id=$2 AND current_revision=0`,
		roleID, fixture.applicant.ScopeID, now); err != nil {
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
	return testActor{Actor: mintTestSessionActor(t, userID, fixture.applicant.ScopeID, sessionID),
		roleID: roleID, grantID: grantID, managerUserID: manager.UserID,
		managerSessionID: manager.SessionID()}
}

func preparePermanentSettlement(t *testing.T, fixture *verificationFixture, key string) (uuid.UUID, int64) {
	t.Helper()
	draft, err := fixture.service.CreateDraft(t.Context(), fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, key[0]), key+"-draft"))
	if err != nil {
		t.Fatal(err)
	}
	worker := newTestSettlementWorker(t, fixture, &scriptedSettlementCommitter{results: []SettlementCommitResult{{
		Outcome: SettlementCommitRetry, FailureCode: "resolver_timeout",
	}}}, 1)
	if processed, err := worker.RunOnce(t.Context()); err != nil || !processed {
		t.Fatalf("RunOnce(permanent failure) = %t, %v", processed, err)
	}
	return assertSettlementState(t, fixture, draft.ID, SettlementPermanentFailed, 1, 3)
}

func waitForBackendLockWait(t *testing.T, pool *pgxpool.Pool, backendPID int, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		select {
		case err := <-done:
			t.Fatalf("database operation completed before the expected lock wait: %v", err)
		default:
		}
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT COALESCE((
			SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=$1
		),false)`, backendPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	t.Fatalf("database operation did not reach the expected lock wait: %v", ctx.Err())
}

func waitForIAMGlobalSharedWaiter(
	t *testing.T,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName string,
	done <-chan error,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		select {
		case err := <-done:
			t.Fatalf("write returned before IAM global lock release: %v", err)
		default:
		}
		var matched bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1
			FROM pg_catalog.pg_locks lock_row
			JOIN pg_catalog.pg_stat_activity activity ON activity.pid=lock_row.pid
			WHERE lock_row.pid=$1 AND activity.application_name=$2
			  AND lock_row.locktype='advisory' AND lock_row.classid=1229016321::oid
			  AND lock_row.objid=1::oid AND lock_row.objsubid=2
			  AND lock_row.mode='ShareLock' AND lock_row.granted=false
		)`, backendPID, applicationName).Scan(&matched)
		if err == nil && matched {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	t.Fatalf("backend %d (%s) did not wait on the exact IAM global shared lock: %v",
		backendPID, applicationName, ctx.Err())
}

func waitForIAMGlobalExclusiveWaiter(
	t *testing.T,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName string,
	done <-chan error,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		select {
		case err := <-done:
			t.Fatalf("revocation returned before IAM global lock release: %v", err)
		default:
		}
		var matched bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1
			FROM pg_catalog.pg_locks lock_row
			JOIN pg_catalog.pg_stat_activity activity ON activity.pid=lock_row.pid
			WHERE lock_row.pid=$1 AND activity.application_name=$2
			  AND lock_row.locktype='advisory' AND lock_row.classid=1229016321::oid
			  AND lock_row.objid=1::oid AND lock_row.objsubid=2
			  AND lock_row.mode='ExclusiveLock' AND lock_row.granted=false
		)`, backendPID, applicationName).Scan(&matched)
		if err != nil {
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
	t.Fatalf("backend %d (%s) did not wait on the exact IAM global exclusive lock: %v",
		backendPID, applicationName, ctx.Err())
}

func assertIAMGlobalExclusiveHeld(
	t *testing.T,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName string,
) {
	t.Helper()
	var matched bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1
		FROM pg_catalog.pg_locks lock_row
		JOIN pg_catalog.pg_stat_activity activity ON activity.pid=lock_row.pid
		WHERE lock_row.pid=$1 AND activity.application_name=$2
		  AND lock_row.locktype='advisory' AND lock_row.classid=1229016321::oid
		  AND lock_row.objid=1::oid AND lock_row.objsubid=2
		  AND lock_row.mode='ExclusiveLock' AND lock_row.granted=true
	)`, backendPID, applicationName).Scan(&matched); err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatalf("backend %d (%s) does not hold the exact IAM global exclusive lock",
			backendPID, applicationName)
	}
}

func assertNoIdentityVerificationRelationLocks(t *testing.T, pool *pgxpool.Pool, backendPID int) {
	t.Helper()
	var locked int
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM pg_catalog.pg_locks lock_row
		JOIN pg_catalog.pg_class relation ON relation.oid=lock_row.relation
		WHERE lock_row.pid=$1 AND lock_row.granted
		  AND relation.relname=ANY($2::text[])`, backendPID, verificationWriteFactTables[:10]).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	if locked != 0 {
		t.Fatalf("backend %d acquired %d identity-verification relation locks before IAM authorization", backendPID, locked)
	}
}

type snapshotBeforeAuthorization struct {
	delegate TxAuthorizer
	once     sync.Once
	entered  chan struct{}
	release  chan struct{}
}

type blockingAfterAuthorization struct {
	delegate TxAuthorizer
	once     sync.Once
	entered  chan struct{}
	release  chan struct{}
}

func (hook *blockingAfterAuthorization) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permissions ...string,
) error {
	if err := hook.delegate.Authorize(ctx, tx, actor, targetScopeID, permissions...); err != nil {
		return err
	}
	hook.once.Do(func() { close(hook.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-hook.release:
		return nil
	}
}

func (hook *snapshotBeforeAuthorization) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permissions ...string,
) error {
	var snapshot string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.txid_current_snapshot()`).Scan(&snapshot); err != nil {
		return err
	}
	hook.once.Do(func() { close(hook.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-hook.release:
	}
	return hook.delegate.Authorize(ctx, tx, actor, targetScopeID, permissions...)
}

func openStrongIsolationPool(t *testing.T, source *pgxpool.Pool, isolation string) *pgxpool.Pool {
	return openNamedIsolationPool(t, source, isolation, "")
}

func openNamedIsolationPool(
	t *testing.T,
	source *pgxpool.Pool,
	isolation, applicationName string,
) *pgxpool.Pool {
	t.Helper()
	var schema string
	if err := source.QueryRow(t.Context(), `SELECT pg_catalog.current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	// Copy the source pool's settings so a sibling session reaches the same
	// database (a template clone is not the TEST_DATABASE_URL database).
	config := source.Config()
	config.ConnConfig.RuntimeParams["search_path"] = schema
	if applicationName != "" {
		config.ConnConfig.RuntimeParams["application_name"] = applicationName
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	var statement string
	switch isolation {
	case "read committed":
		statement = `SET default_transaction_isolation='read committed'`
	case "repeatable read":
		statement = `SET default_transaction_isolation='repeatable read'`
	case "serializable":
		statement = `SET default_transaction_isolation='serializable'`
	default:
		t.Fatalf("unsupported isolation %q", isolation)
	}
	if _, err := pool.Exec(t.Context(), statement); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func receiveWorker(ctx context.Context, result <-chan error) error {
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return fmt.Errorf("worker did not finish: %w", ctx.Err())
	}
}

func blockStage2BRevocationTarget(
	ctx context.Context,
	tx pgx.Tx,
	actor testActor,
	revocation string,
) error {
	var id uuid.UUID
	switch revocation {
	case "session":
		return tx.QueryRow(ctx, `SELECT id FROM auth_sessions WHERE id=$1 FOR UPDATE`,
			actor.SessionID()).Scan(&id)
	case "account":
		return tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, actor.UserID).Scan(&id)
	case "membership":
		return tx.QueryRow(ctx, `SELECT user_id FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`,
			actor.ScopeID, actor.UserID).Scan(&id)
	case "assignment":
		return tx.QueryRow(ctx, `SELECT id FROM custom_role_grants WHERE id=$1 FOR UPDATE`,
			actor.grantID).Scan(&id)
	case "role_permission":
		return tx.QueryRow(ctx, `SELECT id FROM custom_roles WHERE id=$1 FOR UPDATE`, actor.roleID).Scan(&id)
	default:
		return fmt.Errorf("unsupported formal revocation %q", revocation)
	}
}

func identityVerificationFactCounts(t *testing.T, pool *pgxpool.Pool) []int {
	t.Helper()
	result := counts(t, pool, verificationWriteFactTables[:len(verificationWriteFactTables)-1]...)
	var auditCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action LIKE 'identity_verification.%'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	return append(result, auditCount)
}

func assertFactCountsEqual(t *testing.T, before, after []int) {
	t.Helper()
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("identity-verification facts changed: before=%v after=%v", before, after)
	}
}

func assertStableUnavailable(t *testing.T, err error) {
	t.Helper()
	for _, leaked := range []string{"SQLSTATE", "40001", "40P01", "55P03", "42P01", "secret"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("unavailable error leaked %q: %v", leaked, err)
		}
	}
}
