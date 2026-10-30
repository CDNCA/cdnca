//go:build integration

package httppolicycontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var httpPolicyTenantSessionRevocations = []string{
	"session", "account", "membership", "assignment", "role_permission",
}

type httpPolicyStepUpVerifier struct{}

func (httpPolicyStepUpVerifier) VerifyAndConsume(
	context.Context,
	pgx.Tx,
	rbacmanager.StepUpProof,
	rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	return rbacmanager.StepUpEvidence{}, rbacmanager.ErrStepUpRequired
}

type tenantSessionAuthorizationHooks struct {
	backendPID chan<- int
	entered    chan<- struct{}
	authorized chan<- struct{}
	release    <-chan struct{}
	permission string
}

type hookedTenantSessionAuthorizer struct {
	delegate tenantSessionAuthorizer
	hooks    *tenantSessionAuthorizationHooks
}

func (authorizer hookedTenantSessionAuthorizer) AuthorizeTenantSessionTx(
	ctx context.Context,
	tx pgx.Tx,
	session rbacmanager.AuthenticatedSessionReference,
	permission string,
) (uuid.UUID, error) {
	if authorizer.hooks.backendPID != nil {
		var backendPID int
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
			return uuid.Nil, err
		}
		authorizer.hooks.backendPID <- backendPID
	}
	if authorizer.hooks.entered != nil {
		authorizer.hooks.entered <- struct{}{}
	}
	if authorizer.hooks.permission != "" {
		permission = authorizer.hooks.permission
	}
	tenantID, err := authorizer.delegate.AuthorizeTenantSessionTx(ctx, tx, session, permission)
	if err != nil {
		return uuid.Nil, err
	}
	if authorizer.hooks.authorized != nil {
		authorizer.hooks.authorized <- struct{}{}
	}
	if authorizer.hooks.release != nil {
		select {
		case <-ctx.Done():
			return uuid.Nil, ctx.Err()
		case <-authorizer.hooks.release:
		}
	}
	return tenantID, nil
}

type snapshotTenantSessionAuthorizer struct {
	delegate   tenantSessionAuthorizer
	entered    chan<- struct{}
	release    <-chan struct{}
	permission string
}

type mismatchedTenantSessionAuthorizer struct {
	delegate  tenantSessionAuthorizer
	tenantID  uuid.UUID
	succeeded *bool
}

func (authorizer mismatchedTenantSessionAuthorizer) AuthorizeTenantSessionTx(
	ctx context.Context,
	tx pgx.Tx,
	session rbacmanager.AuthenticatedSessionReference,
	permission string,
) (uuid.UUID, error) {
	if _, err := authorizer.delegate.AuthorizeTenantSessionTx(ctx, tx, session, permission); err != nil {
		return uuid.Nil, err
	}
	*authorizer.succeeded = true
	return authorizer.tenantID, nil
}

func (authorizer snapshotTenantSessionAuthorizer) AuthorizeTenantSessionTx(
	ctx context.Context,
	tx pgx.Tx,
	session rbacmanager.AuthenticatedSessionReference,
	permission string,
) (uuid.UUID, error) {
	var snapshot string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.txid_current_snapshot()`).Scan(&snapshot); err != nil {
		return uuid.Nil, err
	}
	authorizer.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return uuid.Nil, ctx.Err()
	case <-authorizer.release:
	}
	if authorizer.permission != "" {
		permission = authorizer.permission
	}
	return authorizer.delegate.AuthorizeTenantSessionTx(ctx, tx, session, permission)
}

func TestHTTPPolicyTenantSessionSafeConstructorUsesRBACManager(t *testing.T) {
	proof := newReviewerLeaseFixture(t)
	installReviewerLease(t, proof, 1, 3)
	rbacService := newHTTPPolicyRBACService(t, proof.fixture)
	store, err := NewTenantSessionStore(
		proof.fixture.pool, func() time.Time { return proof.now }, proof.trust, rbacService)
	if err != nil {
		t.Fatal(err)
	}
	proof.fixture.service = NewService(store)
	proof.fixture.ownerA.Permissions = nil
	before := readHTTPPolicyReviewerFacts(t, proof.fixture.pool)
	request := CreateRequest{
		TargetScopeID: proof.fixture.tenantA, SiteID: proof.fixture.siteA, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("tenant-session-safe-constructor"),
	}
	if _, err := proof.fixture.service.Create(context.Background(), proof.fixture.ownerA, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("legacy tenant-session constructor error = %v, want ErrPermissionDenied", err)
	}
	assertHTTPPolicyReviewerFacts(t, proof.fixture.pool, before)
}

func TestHTTPPolicyTenantSessionReturnedTenantMustMatchTarget(t *testing.T) {
	fixture := newIntegrationFixture(t, allowTestGate())
	succeeded := false
	authorizer := tenantSessionTxAuthorizer{sessions: mismatchedTenantSessionAuthorizer{
		delegate: newHTTPPolicyRBACService(t, fixture), tenantID: uuid.New(), succeeded: &succeeded,
	}}
	store, err := newStoreWithDependencies(
		fixture.pool, func() time.Time { return fixture.now }, allowTestGate(), nil, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = NewService(store)
	before := readHTTPPolicyReviewerFacts(t, fixture.pool)
	request := CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("tenant-session-target-tenant"),
	}
	if _, err := fixture.service.Create(context.Background(), fixture.ownerA, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("mismatched returned tenant error = %v, want ErrPermissionDenied", err)
	}
	if !succeeded {
		t.Fatal("real rbacmanager authorization did not succeed before tenant mismatch")
	}
	assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
}

func TestHTTPPolicyTenantSessionCommitOrderMatrix(t *testing.T) {
	for _, operation := range httpPolicyAuthorizationOperations() {
		for _, replay := range []bool{false, true} {
			for _, order := range []string{"revocation_first", "business_first"} {
				name := fmt.Sprintf("%s/replay_%t/%s", operation.name, replay, order)
				t.Run(name, func(t *testing.T) {
					fixture := newIntegrationFixture(t, allowTestGate())
					roleID := httpPolicyManageRoleID(t, fixture)
					for _, revocation := range httpPolicyTenantSessionRevocations {
						t.Run(revocation, func(t *testing.T) {
							defer restoreHTTPPolicyTenantSessionAuthorization(t, fixture, roleID)
							hooks := &tenantSessionAuthorizationHooks{permission: httpPolicyAuthorizationTestPermission}
							useHTTPPolicyTenantSessionAuthorizer(
								t, fixture, fixture.pool, hooks, allowTestGate())
							fixture.siteA = insertTestSite(t, fixture.pool, fixture.tenantA,
								fixture.ownerA.UserID, strings.ReplaceAll(fmt.Sprintf("commit-%s-%s-%t-%s.example.test",
									operation.name, order, replay, revocation), "_", "-"))
							key := "tenant-session-" + revocation + "-" + operation.name + "-" + order
							invoke := prepareHTTPPolicyTenantSessionOperation(
								t, fixture, operation.name, key+"-seed")
							if replay {
								result, err := invoke(context.Background(), key)
								if err != nil || result.Replayed {
									t.Fatalf("prepare replay = (%#v, %v)", result, err)
								}
							}
							before := readHTTPPolicyReviewerFacts(t, fixture.pool)
							if order == "revocation_first" {
								runHTTPPolicyTenantSessionRevocationFirst(
									t, fixture, hooks, roleID, revocation, invoke, key)
								assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
								return
							}
							result := runHTTPPolicyTenantSessionBusinessFirst(
								t, fixture, hooks, roleID, revocation, invoke, key)
							if result.err != nil || result.result.Replayed != replay {
								t.Fatalf("business first = (%#v, %v), replay=%t", result.result, result.err, replay)
							}
							after := readHTTPPolicyReviewerFacts(t, fixture.pool)
							if _, err := invoke(context.Background(), key); !errors.Is(err, ErrPermissionDenied) {
								t.Fatalf("completed replay after revocation error = %v", err)
							}
							assertHTTPPolicyReviewerFacts(t, fixture.pool, after)
						})
					}
				})
			}
		}
	}
}

func TestHTTPPolicyTenantSessionCredentialsFailClosed(t *testing.T) {
	credentials := []struct {
		name  string
		apply func(Actor, *integrationFixture) Actor
	}{
		{name: "missing", apply: func(actor Actor, _ *integrationFixture) Actor {
			actor.Credential = CredentialReference{}
			return actor
		}},
		{name: "unknown", apply: func(actor Actor, _ *integrationFixture) Actor {
			actor.Credential = CredentialReference{Kind: "bearer", ID: uuid.New()}
			return actor
		}},
		{name: "empty_session", apply: func(actor Actor, _ *integrationFixture) Actor {
			actor.Credential = CredentialReference{Kind: CredentialKindSession}
			return actor
		}},
		{name: "unknown_session", apply: func(actor Actor, _ *integrationFixture) Actor {
			actor.Credential = CredentialReference{Kind: CredentialKindSession, ID: uuid.New()}
			return actor
		}},
		{name: "api_key", apply: func(actor Actor, _ *integrationFixture) Actor {
			actor.Credential = CredentialReference{Kind: CredentialKindAPIKey, ID: uuid.New()}
			return actor
		}},
		{name: "platform_session", apply: func(_ Actor, fixture *integrationFixture) Actor {
			return fixture.platform
		}},
		{name: "cross_tenant", apply: func(_ Actor, fixture *integrationFixture) Actor {
			actor := fixture.ownerB
			actor.ScopeID = fixture.tenantA
			return actor
		}},
		{name: "cross_scope_session", apply: func(actor Actor, fixture *integrationFixture) Actor {
			actor.Credential = fixture.ownerB.Credential
			return actor
		}},
	}
	for _, operation := range httpPolicyAuthorizationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newIntegrationFixture(t, allowTestGate())
			useHTTPPolicyTenantSessionAuthorizer(t, fixture, fixture.pool, nil, allowTestGate())
			invoke := operation.prepare(t, fixture)
			validActor := fixture.ownerA
			for _, credential := range credentials {
				t.Run(credential.name, func(t *testing.T) {
					defer func() { fixture.ownerA = validActor }()
					fixture.ownerA = credential.apply(fixture.ownerA, fixture)
					before := readHTTPPolicyReviewerFacts(t, fixture.pool)
					if _, err := invoke(context.Background(), "credential-"+credential.name+"-"+operation.name); !errors.Is(err, ErrPermissionDenied) {
						t.Fatalf("credential error = %v, want ErrPermissionDenied", err)
					}
					assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
				})
			}
		})
	}
}

func TestHTTPPolicyTenantSessionStrongIsolationRevocation(t *testing.T) {
	for _, isolation := range []struct {
		name  string
		level string
	}{
		{name: "repeatable_read", level: "repeatable read"},
		{name: "serializable", level: "serializable"},
	} {
		for _, operation := range httpPolicyAuthorizationOperations() {
			name := isolation.name + "/" + operation.name
			t.Run(name, func(t *testing.T) {
				fixture := newIntegrationFixture(t, allowTestGate())
				roleID := httpPolicyManageRoleID(t, fixture)
				isolationPool := newHTTPPolicyIsolationPool(t, fixture.pool, isolation.level)
				for _, revocation := range httpPolicyTenantSessionRevocations {
					t.Run(revocation, func(t *testing.T) {
						defer restoreHTTPPolicyTenantSessionAuthorization(t, fixture, roleID)
						useHTTPPolicyTenantSessionAuthorizer(t, fixture, fixture.pool,
							&tenantSessionAuthorizationHooks{permission: httpPolicyAuthorizationTestPermission},
							allowTestGate())
						fixture.siteA = insertTestSite(t, fixture.pool, fixture.tenantA,
							fixture.ownerA.UserID, strings.ReplaceAll(fmt.Sprintf("strong-%s-%s-%s.example.test",
								isolation.name, operation.name, revocation), "_", "-"))
						invoke := prepareHTTPPolicyTenantSessionOperation(t, fixture, operation.name,
							"strong-seed-"+isolation.name+"-"+operation.name+"-"+revocation)
						rbacService := newHTTPPolicyRBACService(t, fixture)
						entered := make(chan struct{}, 1)
						release := make(chan struct{})
						authorizer := tenantSessionTxAuthorizer{sessions: snapshotTenantSessionAuthorizer{
							delegate: rbacService, entered: entered, release: release,
							permission: httpPolicyAuthorizationTestPermission,
						}}
						store, err := newStoreWithDependencies(
							isolationPool, func() time.Time { return fixture.now }, allowTestGate(), nil, authorizer)
						if err != nil {
							t.Fatal(err)
						}
						fixture.service = NewService(store)
						before := readHTTPPolicyReviewerFacts(t, fixture.pool)
						resultChannel := make(chan authorizationResult, 1)
						go func() {
							result, err := invoke(context.Background(), "strong-"+isolation.name+"-"+revocation+"-"+operation.name)
							resultChannel <- authorizationResult{result: result, err: err}
						}()
						<-entered
						revocationErr := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
							return applyHTTPPolicyTenantSessionRevocation(
								context.Background(), tx, fixture, roleID, revocation)
						})
						close(release)
						if revocationErr != nil {
							t.Fatalf("commit %s revocation: %v", revocation, revocationErr)
						}
						result := receiveHTTPPolicyAuthorizationResult(t, resultChannel)
						if result.err != ErrUnavailable {
							t.Fatalf("strong isolation result = (%#v, %v), want ErrUnavailable", result.result, result.err)
						}
						assertStableHTTPPolicyError(t, result.err)
						assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
					})
				}
			})
		}
	}
}

func TestHTTPPolicyTenantSessionGlobalLockIsFirst(t *testing.T) {
	for _, operation := range httpPolicyAuthorizationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newIntegrationFixture(t, allowTestGate())
			hooks := &tenantSessionAuthorizationHooks{}
			useHTTPPolicyTenantSessionAuthorizer(t, fixture, fixture.pool, hooks, allowTestGate())
			invoke := operation.prepare(t, fixture)
			before := readHTTPPolicyReviewerFacts(t, fixture.pool)

			holder, err := fixture.pool.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(context.Background())
			if err := iamlock.AcquireExclusive(context.Background(), holder); err != nil {
				t.Fatal(err)
			}
			backendPID := make(chan int, 1)
			entered := make(chan struct{}, 1)
			hooks.backendPID = backendPID
			hooks.entered = entered
			resultChannel := make(chan authorizationResult, 1)
			go func() {
				result, err := invoke(context.Background(), "first-lock-"+operation.name)
				resultChannel <- authorizationResult{result: result, err: err}
			}()
			pid := <-backendPID
			<-entered
			waitForHTTPPolicyBackendLock(t, fixture.pool, pid)
			assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
			assertNoHTTPPolicyBusinessLocks(t, fixture.pool, pid)
			if err := holder.Commit(context.Background()); err != nil {
				t.Fatal(err)
			}
			result := receiveHTTPPolicyAuthorizationResult(t, resultChannel)
			if result.err != nil || result.result.Replayed {
				t.Fatalf("first-lock result = (%#v, %v)", result.result, result.err)
			}
		})
	}
}

func useHTTPPolicyTenantSessionAuthorizer(
	t *testing.T,
	fixture *integrationFixture,
	storePool *pgxpool.Pool,
	hooks *tenantSessionAuthorizationHooks,
	gate entitlementGate,
) *rbacmanager.Service {
	t.Helper()
	rbacService := newHTTPPolicyRBACService(t, fixture)
	var sessions tenantSessionAuthorizer = rbacService
	if hooks != nil {
		sessions = hookedTenantSessionAuthorizer{delegate: rbacService, hooks: hooks}
	}
	store, err := newStoreWithDependencies(storePool, func() time.Time { return fixture.now }, gate, nil,
		tenantSessionTxAuthorizer{sessions: sessions})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = NewService(store)
	fixture.ownerA.Permissions = nil
	return rbacService
}

func prepareHTTPPolicyTenantSessionOperation(
	t *testing.T,
	fixture *integrationFixture,
	operation, seedKey string,
) func(context.Context, string) (WriteResult, error) {
	t.Helper()
	switch operation {
	case "create":
		request := CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: fixture.siteA,
			Enabled: true, Config: validTestConfig(),
		}
		return func(ctx context.Context, key string) (WriteResult, error) {
			request.WriteMetadata = testMetadata(key)
			return fixture.service.Create(ctx, fixture.ownerA, request)
		}
	case "update":
		policy := createServicePolicy(t, fixture, fixture.siteA, seedKey)
		config := validTestConfig()
		config.MaxUploadBytes = 32
		request := UpdateRequest{
			TargetScopeID: fixture.tenantA, ID: policy.ID,
			ExpectedRevision: policy.Revision, Config: config,
		}
		return func(ctx context.Context, key string) (WriteResult, error) {
			request.WriteMetadata = testMetadata(key)
			return fixture.service.Update(ctx, fixture.ownerA, request)
		}
	case "enable":
		created, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: false,
			Config: validTestConfig(), WriteMetadata: testMetadata(seedKey),
		})
		if err != nil {
			t.Fatalf("prepare tenant-session enable: %v", err)
		}
		request := StateRequest{
			TargetScopeID: fixture.tenantA, ID: created.Policy.ID,
			ExpectedRevision: created.Policy.Revision, Enabled: true,
		}
		return func(ctx context.Context, key string) (WriteResult, error) {
			request.WriteMetadata = testMetadata(key)
			return fixture.service.SetEnabled(ctx, fixture.ownerA, request)
		}
	case "disable":
		policy := createServicePolicy(t, fixture, fixture.siteA, seedKey)
		request := StateRequest{
			TargetScopeID: fixture.tenantA, ID: policy.ID,
			ExpectedRevision: policy.Revision, Enabled: false,
		}
		return func(ctx context.Context, key string) (WriteResult, error) {
			request.WriteMetadata = testMetadata(key)
			return fixture.service.SetEnabled(ctx, fixture.ownerA, request)
		}
	case "delete":
		policy := createServicePolicy(t, fixture, fixture.siteA, seedKey)
		request := DeleteRequest{
			TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision,
		}
		return func(ctx context.Context, key string) (WriteResult, error) {
			request.WriteMetadata = testMetadata(key)
			return fixture.service.Delete(ctx, fixture.ownerA, request)
		}
	default:
		t.Fatalf("unknown HTTP policy tenant-session operation %q", operation)
		return nil
	}
}

func newHTTPPolicyRBACService(t *testing.T, fixture *integrationFixture) *rbacmanager.Service {
	t.Helper()
	service, err := rbacmanager.NewServiceWithDependencies(
		fixture.pool, audit.New(fixture.pool), httpPolicyStepUpVerifier{}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func httpPolicyManageRoleID(t *testing.T, fixture *integrationFixture) uuid.UUID {
	t.Helper()
	roleID := uuid.New()
	if err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireExclusive(context.Background(), tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(
			context.Background(), tx, []uuid.UUID{fixture.ownerA.ScopeID}); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO permissions(name,description)
			VALUES($1,$2) ON CONFLICT DO NOTHING`, httpPolicyAuthorizationTestPermission,
			"HTTP policy Stage2B transaction authorization test"); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO roles(id,scope_id,name,system_role)
			VALUES($1,$2,$3,true)`, roleID, fixture.ownerA.ScopeID,
			"http_policy_stage2b_"+strings.ReplaceAll(roleID.String(), "-", "")); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,$2)`, roleID, httpPolicyAuthorizationTestPermission); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, fixture.ownerA.ScopeID, fixture.ownerA.UserID, roleID)
		return err
	}); err != nil {
		t.Fatalf("create HTTP policy Stage2B manager role: %v", err)
	}
	return roleID
}

func runHTTPPolicyTenantSessionRevocationFirst(
	t *testing.T,
	fixture *integrationFixture,
	hooks *tenantSessionAuthorizationHooks,
	roleID uuid.UUID,
	revocation string,
	invoke func(context.Context, string) (WriteResult, error),
	key string,
) {
	t.Helper()
	tx, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := applyHTTPPolicyTenantSessionRevocation(
		context.Background(), tx, fixture, roleID, revocation); err != nil {
		t.Fatalf("hold %s revocation: %v", revocation, err)
	}
	backendPID := make(chan int, 1)
	entered := make(chan struct{}, 1)
	hooks.backendPID = backendPID
	hooks.entered = entered
	resultChannel := make(chan authorizationResult, 1)
	go func() {
		result, err := invoke(context.Background(), key)
		resultChannel <- authorizationResult{result: result, err: err}
	}()
	pid := <-backendPID
	<-entered
	waitForHTTPPolicyBackendLock(t, fixture.pool, pid)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s revocation: %v", revocation, err)
	}
	result := receiveHTTPPolicyAuthorizationResult(t, resultChannel)
	if !errors.Is(result.err, ErrPermissionDenied) {
		t.Fatalf("revocation-first result = (%#v, %v)", result.result, result.err)
	}
}

func runHTTPPolicyTenantSessionBusinessFirst(
	t *testing.T,
	fixture *integrationFixture,
	hooks *tenantSessionAuthorizationHooks,
	roleID uuid.UUID,
	revocation string,
	invoke func(context.Context, string) (WriteResult, error),
	key string,
) authorizationResult {
	t.Helper()
	authorized := make(chan struct{}, 1)
	release := make(chan struct{})
	hooks.authorized = authorized
	hooks.release = release
	resultChannel := make(chan authorizationResult, 1)
	go func() {
		result, err := invoke(context.Background(), key)
		resultChannel <- authorizationResult{result: result, err: err}
	}()
	<-authorized

	revocationTx, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer revocationTx.Rollback(context.Background())
	var revocationPID int
	if err := revocationTx.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&revocationPID); err != nil {
		t.Fatal(err)
	}
	revocationResult := make(chan error, 1)
	go func() {
		revocationResult <- applyHTTPPolicyTenantSessionRevocation(
			context.Background(), revocationTx, fixture, roleID, revocation)
	}()
	waitForHTTPPolicyBackendLock(t, fixture.pool, revocationPID)
	close(release)
	result := receiveHTTPPolicyAuthorizationResult(t, resultChannel)
	if err := <-revocationResult; err != nil {
		t.Fatalf("apply %s revocation: %v", revocation, err)
	}
	if err := revocationTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s revocation: %v", revocation, err)
	}
	return result
}

func applyHTTPPolicyTenantSessionRevocation(
	ctx context.Context,
	tx pgx.Tx,
	fixture *integrationFixture,
	roleID uuid.UUID,
	revocation string,
) error {
	if err := iamlock.AcquireExclusive(ctx, tx); err != nil {
		return err
	}
	if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{fixture.ownerA.ScopeID}); err != nil {
		return err
	}
	switch revocation {
	case "session":
		_, err := tx.Exec(ctx, `UPDATE auth_sessions
			SET revoked_at=$2,revocation_reason='http-policy-stage2b'
			WHERE id=$1`, fixture.ownerA.Credential.ID, fixture.now)
		return err
	case "account":
		_, err := tx.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, fixture.ownerA.UserID)
		return err
	case "membership":
		_, err := tx.Exec(ctx, `UPDATE memberships SET status='suspended'
			WHERE scope_id=$1 AND user_id=$2`, fixture.ownerA.ScopeID, fixture.ownerA.UserID)
		return err
	case "assignment":
		_, err := tx.Exec(ctx, `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
			fixture.ownerA.ScopeID, fixture.ownerA.UserID, roleID)
		return err
	case "role_permission":
		_, err := tx.Exec(ctx, `DELETE FROM role_permissions
			WHERE role_id=$1 AND permission_name=$2`, roleID, httpPolicyAuthorizationTestPermission)
		return err
	default:
		return fmt.Errorf("unknown HTTP policy revocation %q", revocation)
	}
}

func restoreHTTPPolicyTenantSessionAuthorization(
	t *testing.T,
	fixture *integrationFixture,
	roleID uuid.UUID,
) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireExclusive(context.Background(), tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(
			context.Background(), tx, []uuid.UUID{fixture.ownerA.ScopeID}); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `UPDATE users SET status='active' WHERE id=$1`,
			fixture.ownerA.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `UPDATE memberships SET status='active'
			WHERE scope_id=$1 AND user_id=$2`, fixture.ownerA.ScopeID, fixture.ownerA.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `UPDATE auth_sessions
			SET revoked_at=NULL,revocation_reason=NULL WHERE id=$1`, fixture.ownerA.Credential.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,$2) ON CONFLICT DO NOTHING`, roleID, httpPolicyAuthorizationTestPermission); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, fixture.ownerA.ScopeID, fixture.ownerA.UserID, roleID)
		return err
	}); err != nil {
		t.Fatalf("restore tenant-session authorization: %v", err)
	}
}

func newHTTPPolicyIsolationPool(t *testing.T, pool *pgxpool.Pool, isolation string) *pgxpool.Pool {
	t.Helper()
	config := pool.Config().Copy()
	config.ConnConfig.RuntimeParams["default_transaction_isolation"] = isolation
	isolationPool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(isolationPool.Close)
	return isolationPool
}

func receiveHTTPPolicyAuthorizationResult(
	t *testing.T,
	results <-chan authorizationResult,
) authorizationResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("HTTP policy authorization result timed out")
		return authorizationResult{}
	}
}

func assertStableHTTPPolicyError(t *testing.T, err error) {
	t.Helper()
	for _, leaked := range []string{"SQLSTATE", "40001", "40P01", "55P03"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("HTTP policy error leaked %q: %v", leaked, err)
		}
	}
}

func assertNoHTTPPolicyBusinessLocks(t *testing.T, pool *pgxpool.Pool, backendPID int) {
	t.Helper()
	var locks int
	if err := pool.QueryRow(context.Background(), `SELECT count(*)
		FROM pg_catalog.pg_locks lock
		JOIN pg_catalog.pg_class relation ON relation.oid=lock.relation
		JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
		WHERE lock.pid=$1 AND lock.granted AND namespace.nspname=current_schema()
		  AND lock.mode IN ('RowShareLock','RowExclusiveLock','ShareLock','ExclusiveLock','AccessExclusiveLock')
		  AND relation.relname IN (
		    'sites','http_policies','http_policy_revisions',
		    'http_policy_publication_heads','http_policy_write_requests','audit_events'
		  )`, backendPID).Scan(&locks); err != nil {
		t.Fatal(err)
	}
	if locks != 0 {
		t.Fatalf("business backend %d acquired %d HTTP policy row/relation locks before global authorization", backendPID, locks)
	}
}
