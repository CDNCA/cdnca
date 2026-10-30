package httppolicycontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const httpPolicyAuthorizationTestPermission = "http_policy_authorization_test.manage"

type authorizationResult struct {
	result WriteResult
	err    error
}

type httpPolicyFactCounts struct {
	policies  int
	revisions int
	writes    int
	audits    int
}

type authorizationOperation struct {
	name    string
	prepare func(*testing.T, *integrationFixture) func(context.Context, string) (WriteResult, error)
}

func TestHTTPPolicyWriteAuthorizationCommitOrderMatrix(t *testing.T) {
	mutations := []string{"assignment", "membership", "role_permission", "account"}
	for _, mutation := range mutations {
		for _, operation := range httpPolicyAuthorizationOperations() {
			for _, replay := range []bool{false, true} {
				for _, order := range []string{"revocation_first", "business_first"} {
					name := fmt.Sprintf("%s/%s/replay_%t/%s", mutation, operation.name, replay, order)
					t.Run(name, func(t *testing.T) {
						hooks := &authorizationHooks{}
						fixture := newIntegrationFixtureWithAuthorizer(
							t, allowTestGate(), lockingTestAuthorizer{
								hooks: hooks, permission: httpPolicyAuthorizationTestPermission,
							})
						fixture.ownerA.Permissions = nil
						roleID := replaceHTTPPolicyAuthorizationRole(t, fixture)
						invoke := operation.prepare(t, fixture)
						key := "authorization-" + mutation + "-" + operation.name
						if replay {
							result, err := invoke(context.Background(), key)
							if err != nil || result.Replayed {
								t.Fatalf("prepare replay result = (%#v, %v)", result, err)
							}
						}
						before := readHTTPPolicyFactCounts(t, fixture.pool)
						if order == "revocation_first" {
							runHTTPPolicyRevocationFirst(t, fixture, hooks, roleID, mutation, invoke, key)
							assertHTTPPolicyFactCounts(t, fixture.pool, before)
							return
						}
						result := runHTTPPolicyBusinessFirst(t, fixture, hooks, roleID, mutation, invoke, key)
						if result.err != nil || result.result.Replayed != replay {
							t.Fatalf("business-first result = (%#v, %v), replay=%t", result.result, result.err, replay)
						}
						afterSuccess := readHTTPPolicyReviewerFacts(t, fixture.pool)
						if _, err := invoke(context.Background(), key); !errors.Is(err, ErrPermissionDenied) {
							t.Fatalf("completed replay after committed revoke error = %v", err)
						}
						assertHTTPPolicyReviewerFacts(t, fixture.pool, afterSuccess)
					})
				}
			}
		}
	}
}

func TestHTTPPolicyAuthorizationDeadlockStress(t *testing.T) {
	hooks := &authorizationHooks{}
	fixture := newIntegrationFixtureWithAuthorizer(t, allowTestGate(), lockingTestAuthorizer{
		hooks: hooks, permission: httpPolicyAuthorizationTestPermission,
	})
	fixture.ownerA.Permissions = nil
	roleID := replaceHTTPPolicyAuthorizationRole(t, fixture)
	mutations := []string{"assignment", "membership", "role_permission", "account"}
	for iteration := 0; iteration < 30; iteration++ {
		mutation := mutations[iteration%len(mutations)]
		if err := restoreHTTPPolicyAuthorization(context.Background(), fixture.pool, fixture, roleID); err != nil {
			t.Fatalf("iteration %d restore authorization: %v", iteration, err)
		}
		*hooks = authorizationHooks{}
		siteID := insertTestSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID,
			fmt.Sprintf("authorization-stress-%d.example.test", iteration))
		request := CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: siteID, Enabled: true,
			Config: validTestConfig(), WriteMetadata: testMetadata(fmt.Sprintf("authorization-stress-%d", iteration)),
		}
		invoke := func(ctx context.Context, _ string) (WriteResult, error) {
			return fixture.service.Create(ctx, fixture.ownerA, request)
		}
		if iteration%2 == 0 {
			before := readHTTPPolicyFactCounts(t, fixture.pool)
			runHTTPPolicyRevocationFirst(t, fixture, hooks, roleID, mutation, invoke, request.IdempotencyKey)
			assertHTTPPolicyFactCounts(t, fixture.pool, before)
			continue
		}
		result := runHTTPPolicyBusinessFirst(t, fixture, hooks, roleID, mutation, invoke, request.IdempotencyKey)
		if result.err != nil || result.result.Replayed {
			t.Fatalf("iteration %d business-first result = (%#v, %v)", iteration, result.result, result.err)
		}
	}
}

func TestHTTPPolicyPackageRuntimeHandlerSmoke(t *testing.T) {
	pool := openHTTPPolicyTestPool(t)
	fixture := seedIntegrationFixture(t, pool)
	now := httpPolicyTestBase.Add(8 * time.Minute)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "http-policy-test-key", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	installTestLease(t, pool, trust, privateKey, now, 1, true)
	request := CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("runtime-missing-authorizer"),
	}
	before := readHTTPPolicyFactCounts(t, pool)
	if _, err := NewService(NewStoreWithClock(pool, func() time.Time { return now }, trust)).Create(
		context.Background(), fixture.ownerA, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("compatibility constructor without authorizer error = %v", err)
	}
	assertHTTPPolicyFactCounts(t, pool, before)

	store, err := newStoreWithAuthorizer(
		pool, func() time.Time { return now }, trust, lockingTestAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = NewService(store)
	fixture.ownerA.Permissions = nil
	handler, err := NewHandler(fixture.service, AuthenticatorFunc(func(request *http.Request) (Actor, error) {
		if request.Header.Get("Authorization") != "Bearer owner-a" {
			return Actor{}, ErrUnauthenticated
		}
		return fixture.ownerA, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler = handler
	payload := createPayload(fixture.siteA, validTestConfig(), true)
	created := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), payload, "runtime-create", "")
	if created.Code != http.StatusCreated {
		t.Fatalf("runtime create status=%d body=%s", created.Code, created.Body)
	}
	replayed := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), payload, "runtime-create", "")
	if replayed.Code != http.StatusCreated || replayed.Header().Get("X-Idempotent-Replay") != "true" {
		t.Fatalf("runtime replay status=%d replay=%q body=%s",
			replayed.Code, replayed.Header().Get("X-Idempotent-Replay"), replayed.Body)
	}
	crossTenant := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantB),
		createPayload(fixture.siteB, validTestConfig(), true), "runtime-cross-tenant", "")
	assertHTTPError(t, crossTenant, http.StatusNotFound, "not_found")
	before = readHTTPPolicyFactCounts(t, pool)
	if _, err := pool.Exec(context.Background(), `UPDATE users SET status='disabled' WHERE id=$1`, fixture.ownerA.UserID); err != nil {
		t.Fatal(err)
	}
	denied := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), payload, "runtime-create", "")
	assertHTTPError(t, denied, http.StatusForbidden, "permission_denied")
	if denied.Header().Get("X-Request-ID") != "http-request-runtime-create" ||
		denied.Header().Get("X-Trace-ID") != "http-trace-runtime-create" {
		t.Fatalf("denied replay correlation headers = (%q, %q)",
			denied.Header().Get("X-Request-ID"), denied.Header().Get("X-Trace-ID"))
	}
	assertHTTPPolicyFactCounts(t, pool, before)
}

func httpPolicyAuthorizationOperations() []authorizationOperation {
	return []authorizationOperation{
		{name: "create", prepare: func(t *testing.T, fixture *integrationFixture) func(context.Context, string) (WriteResult, error) {
			request := CreateRequest{TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true, Config: validTestConfig()}
			return func(ctx context.Context, key string) (WriteResult, error) {
				request.WriteMetadata = testMetadata(key)
				return fixture.service.Create(ctx, fixture.ownerA, request)
			}
		}},
		{name: "update", prepare: func(t *testing.T, fixture *integrationFixture) func(context.Context, string) (WriteResult, error) {
			policy := createServicePolicy(t, fixture, fixture.siteA, "authorization-seed-update")
			config := validTestConfig()
			config.MaxUploadBytes = 32
			request := UpdateRequest{TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision, Config: config}
			return func(ctx context.Context, key string) (WriteResult, error) {
				request.WriteMetadata = testMetadata(key)
				return fixture.service.Update(ctx, fixture.ownerA, request)
			}
		}},
		{name: "enable", prepare: func(t *testing.T, fixture *integrationFixture) func(context.Context, string) (WriteResult, error) {
			created, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
				TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: false,
				Config: validTestConfig(), WriteMetadata: testMetadata("authorization-seed-enable"),
			})
			if err != nil {
				t.Fatalf("prepare enable: %v", err)
			}
			request := StateRequest{TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: created.Policy.Revision, Enabled: true}
			return func(ctx context.Context, key string) (WriteResult, error) {
				request.WriteMetadata = testMetadata(key)
				return fixture.service.SetEnabled(ctx, fixture.ownerA, request)
			}
		}},
		{name: "disable", prepare: func(t *testing.T, fixture *integrationFixture) func(context.Context, string) (WriteResult, error) {
			policy := createServicePolicy(t, fixture, fixture.siteA, "authorization-seed-disable")
			request := StateRequest{TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision, Enabled: false}
			return func(ctx context.Context, key string) (WriteResult, error) {
				request.WriteMetadata = testMetadata(key)
				return fixture.service.SetEnabled(ctx, fixture.ownerA, request)
			}
		}},
		{name: "delete", prepare: func(t *testing.T, fixture *integrationFixture) func(context.Context, string) (WriteResult, error) {
			policy := createServicePolicy(t, fixture, fixture.siteA, "authorization-seed-delete")
			request := DeleteRequest{TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision}
			return func(ctx context.Context, key string) (WriteResult, error) {
				request.WriteMetadata = testMetadata(key)
				return fixture.service.Delete(ctx, fixture.ownerA, request)
			}
		}},
	}
}

func replaceHTTPPolicyAuthorizationRole(t *testing.T, fixture *integrationFixture) uuid.UUID {
	t.Helper()
	roleID := uuid.New()
	if err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `INSERT INTO permissions(name,description)
			VALUES($1,$2)`, httpPolicyAuthorizationTestPermission,
			"HTTP policy transaction authorization test"); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO roles(id,scope_id,name,system_role)
			VALUES($1,$2,$3,true)`, roleID, fixture.ownerA.ScopeID,
			"http_policy_authorization_"+strings.ReplaceAll(roleID.String(), "-", "")); err != nil {
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
		t.Fatalf("replace HTTP policy authorization role: %v", err)
	}
	return roleID
}

func runHTTPPolicyRevocationFirst(
	t *testing.T,
	fixture *integrationFixture,
	hooks *authorizationHooks,
	roleID uuid.UUID,
	mutation string,
	invoke func(context.Context, string) (WriteResult, error),
	key string,
) {
	t.Helper()
	tx, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := applyHTTPPolicyAuthorizationRevocation(context.Background(), tx, fixture, roleID, mutation); err != nil {
		t.Fatalf("hold %s revocation: %v", mutation, err)
	}
	backendPID := make(chan int, 1)
	beforeLock := make(chan struct{}, 1)
	hooks.backendPID = backendPID
	switch mutation {
	case "account":
		hooks.beforeAccount = beforeLock
	case "membership":
		hooks.beforeMembership = beforeLock
	default:
		hooks.beforePermission = beforeLock
	}
	resultChannel := make(chan authorizationResult, 1)
	go func() {
		result, err := invoke(context.Background(), key)
		resultChannel <- authorizationResult{result: result, err: err}
	}()
	pid := <-backendPID
	<-beforeLock
	waitForHTTPPolicyBackendLock(t, fixture.pool, pid)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s revocation: %v", mutation, err)
	}
	result := <-resultChannel
	if !errors.Is(result.err, ErrPermissionDenied) {
		t.Fatalf("revocation-first result = (%#v, %v)", result.result, result.err)
	}
}

func runHTTPPolicyBusinessFirst(
	t *testing.T,
	fixture *integrationFixture,
	hooks *authorizationHooks,
	roleID uuid.UUID,
	mutation string,
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
	defer func() { _ = revocationTx.Rollback(context.Background()) }()
	var revocationPID int
	if err := revocationTx.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&revocationPID); err != nil {
		t.Fatal(err)
	}
	revocationResult := make(chan error, 1)
	go func() {
		revocationResult <- applyHTTPPolicyAuthorizationRevocation(
			context.Background(), revocationTx, fixture, roleID, mutation)
	}()
	waitForHTTPPolicyBackendLock(t, fixture.pool, revocationPID)
	close(release)
	result := <-resultChannel
	if err := <-revocationResult; err != nil {
		t.Fatalf("apply %s revocation after business: %v", mutation, err)
	}
	if err := revocationTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s revocation after business: %v", mutation, err)
	}
	return result
}

func applyHTTPPolicyAuthorizationRevocation(
	ctx context.Context,
	tx pgx.Tx,
	fixture *integrationFixture,
	roleID uuid.UUID,
	mutation string,
) error {
	switch mutation {
	case "assignment":
		_, err := tx.Exec(ctx, `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.ownerA.ScopeID, fixture.ownerA.UserID, roleID)
		return err
	case "membership":
		_, err := tx.Exec(ctx, `UPDATE memberships SET status='suspended'
			WHERE scope_id=$1 AND user_id=$2`, fixture.ownerA.ScopeID, fixture.ownerA.UserID)
		return err
	case "role_permission":
		_, err := tx.Exec(ctx, `DELETE FROM role_permissions
			WHERE role_id=$1 AND permission_name=$2`, roleID, httpPolicyAuthorizationTestPermission)
		return err
	case "account":
		_, err := tx.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, fixture.ownerA.UserID)
		return err
	default:
		return fmt.Errorf("unknown authorization mutation %q", mutation)
	}
}

func restoreHTTPPolicyAuthorization(
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture *integrationFixture,
	roleID uuid.UUID,
) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET status='active' WHERE id=$1`, fixture.ownerA.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE memberships SET status='active'
			WHERE scope_id=$1 AND user_id=$2`, fixture.ownerA.ScopeID, fixture.ownerA.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,$2) ON CONFLICT DO NOTHING`, roleID, httpPolicyAuthorizationTestPermission); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, fixture.ownerA.ScopeID, fixture.ownerA.UserID, roleID)
		return err
	})
}

func waitForHTTPPolicyBackendLock(t *testing.T, pool *pgxpool.Pool, backendPID int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		err := pool.QueryRow(context.Background(), `SELECT COALESCE(wait_event_type='Lock',false)
			FROM pg_stat_activity WHERE pid=$1`, backendPID).Scan(&waiting)
		if err == nil && waiting {
			return
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("inspect backend %d wait: %v", backendPID, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("backend %d did not wait on an authorization lock", backendPID)
}

func readHTTPPolicyFactCounts(t *testing.T, pool *pgxpool.Pool) httpPolicyFactCounts {
	t.Helper()
	var counts httpPolicyFactCounts
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM http_policies),
		(SELECT count(*) FROM http_policy_revisions),
		(SELECT count(*) FROM http_policy_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'http_policy.%')`).Scan(
		&counts.policies, &counts.revisions, &counts.writes, &counts.audits); err != nil {
		t.Fatal(err)
	}
	return counts
}

func assertHTTPPolicyFactCounts(t *testing.T, pool *pgxpool.Pool, expected httpPolicyFactCounts) {
	t.Helper()
	if actual := readHTTPPolicyFactCounts(t, pool); actual != expected {
		t.Fatalf("HTTP policy facts changed: got=%+v want=%+v", actual, expected)
	}
}
