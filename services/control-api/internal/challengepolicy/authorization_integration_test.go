package challengepolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const challengeAuthorizationTestPermission = "challenge_policy_authorization_test.manage"

type authorizationResult struct {
	result WriteResult
	err    error
}

type challengeFactCounts struct {
	policies  int
	revisions int
	writes    int
	audits    int
}

type authorizationOperation struct {
	name    string
	prepare func(*testing.T, *testFixture) func(context.Context, string) (WriteResult, error)
}

type readAuthorizationOperation struct {
	name   string
	invoke func(context.Context, *testFixture, Actor, Policy) (int, error)
}

type blockingChallengeGate struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (gate blockingChallengeGate) Check(ctx context.Context, _ pgx.Tx, _ entitlementCheck) error {
	gate.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gate.release:
		return nil
	}
}

func TestChallengePolicyWriteAuthorizationCommitOrderMatrix(t *testing.T) {
	mutations := []string{"assignment", "role_permission", "account"}
	operations := challengeAuthorizationOperations()
	for _, mutation := range mutations {
		for _, operation := range operations {
			for _, replay := range []bool{false, true} {
				for _, order := range []string{"revocation_first", "business_first"} {
					name := fmt.Sprintf("%s/%s/replay_%t/%s", mutation, operation.name, replay, order)
					t.Run(name, func(t *testing.T) {
						hooks := &testAuthorizationHooks{}
						fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{
							hooks: hooks, permission: challengeAuthorizationTestPermission,
						})
						roleID := replaceChallengeAuthorizationRole(t, fixture)
						invoke := operation.prepare(t, fixture)
						key := "authorization-" + mutation + "-" + operation.name
						if replay {
							result, err := invoke(context.Background(), key)
							if err != nil || result.Replayed {
								t.Fatalf("prepare replay result = (%#v, %v)", result, err)
							}
						}
						before := readChallengeFactCounts(t, fixture.pool)
						if order == "revocation_first" {
							runChallengeRevocationFirst(t, fixture, hooks, roleID, mutation, invoke, key)
							assertChallengeFactCounts(t, fixture.pool, before)
							return
						}
						result := runChallengeBusinessFirst(t, fixture, hooks, roleID, mutation, invoke, key)
						if result.err != nil || result.result.Replayed != replay {
							t.Fatalf("business-first result = (%#v, %v), replay=%t", result.result, result.err, replay)
						}
						afterSuccess := readChallengeFactCounts(t, fixture.pool)
						if _, err := invoke(context.Background(), key+"-after-revoke"); !errors.Is(err, ErrPermissionDenied) {
							t.Fatalf("request after committed revoke error = %v", err)
						}
						assertChallengeFactCounts(t, fixture.pool, afterSuccess)
					})
				}
			}
		}
	}
}

func TestChallengePolicySharedSessionAuthorizationCommitOrderMatrix(t *testing.T) {
	mutations := []string{"assignment", "account", "membership_suspend", "session"}
	for _, mutation := range mutations {
		for _, operation := range challengeAuthorizationOperations() {
			for _, replay := range []bool{false, true} {
				for _, order := range []string{"revocation_first", "business_first"} {
					name := fmt.Sprintf("%s/%s/replay_%t/%s", mutation, operation.name, replay, order)
					t.Run(name, func(t *testing.T) {
						hooks := &testAuthorizationHooks{}
						fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
						useSharedSessionAuthorizer(t, fixture, hooks, allowGate())
						roleID := challengeAuthorizationRoleID(t, fixture)
						invoke := operation.prepare(t, fixture)
						key := "shared-authorization-" + mutation + "-" + operation.name
						if replay {
							result, err := invoke(context.Background(), key)
							if err != nil || result.Replayed {
								t.Fatalf("prepare replay result = (%#v, %v)", result, err)
							}
						}
						before := readChallengeFactCounts(t, fixture.pool)
						if order == "revocation_first" {
							runChallengeRevocationFirst(t, fixture, hooks, roleID, mutation, invoke, key)
							assertChallengeFactCounts(t, fixture.pool, before)
							return
						}
						result := runChallengeBusinessFirst(t, fixture, hooks, roleID, mutation, invoke, key)
						if result.err != nil || result.result.Replayed != replay {
							t.Fatalf("business-first result = (%#v, %v), replay=%t", result.result, result.err, replay)
						}
						afterSuccess := readChallengeFactCounts(t, fixture.pool)
						if _, err := invoke(context.Background(), key+"-after-revoke"); !errors.Is(err, ErrPermissionDenied) {
							t.Fatalf("request after committed revoke error = %v", err)
						}
						assertChallengeFactCounts(t, fixture.pool, afterSuccess)
					})
				}
			}
		}
	}
}

func TestChallengePolicyRevokedSessionAfterAuthenticationFailsClosed(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprintf("replay_%t", replay), func(t *testing.T) {
			fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
			useSharedSessionAuthorizer(t, fixture, nil, allowGate())
			request := CreateRequest{
				TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
				Config: validConfig(ModeClick), WriteMetadata: metadata("revoked-session"),
			}
			if replay {
				if _, err := fixture.service.Create(context.Background(), fixture.ownerA, request); err != nil {
					t.Fatal(err)
				}
			}
			before := readChallengeFactCounts(t, fixture.pool)
			if _, err := fixture.pool.Exec(context.Background(), `UPDATE auth_sessions
				SET revoked_at=CURRENT_TIMESTAMP,revocation_reason='challenge policy test'
				WHERE id=$1`, fixture.ownerASession); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.service.Create(context.Background(), fixture.ownerA, request); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("revoked session write error = %v", err)
			}
			assertChallengeFactCounts(t, fixture.pool, before)
		})
	}
}

func TestChallengePolicyReadsRecheckExactDatabasePermission(t *testing.T) {
	fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
	useSharedSessionAuthorizer(t, fixture, nil, allowGate())
	created := createServicePolicy(t, fixture, fixture.siteA, "a.example.test", "read-permission-seed")
	rbacService, err := rbacmanager.NewServiceWithDependencies(
		fixture.pool, audit.New(fixture.pool), challengeStepUpVerifier{}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	manager := rbacmanager.Actor{
		UserID: fixture.ownerA.UserID, ScopeID: fixture.ownerA.ScopeID,
		SessionID: fixture.ownerA.Credential.ID, ScopeKind: "tenant",
		IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
	role, err := rbacService.CreateRole(context.Background(), manager, rbacmanager.CreateRoleRequest{
		Name: "challenge-read-recheck", Permissions: []string{PermissionRead},
		Mutation: challengeRBACMutation("challenge-read-recheck-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := rbacService.AssignRole(context.Background(), manager, rbacmanager.AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision, SubjectUserID: fixture.memberA.UserID,
		Mutation: challengeRBACMutation("challenge-read-recheck-assign"),
	})
	if err != nil {
		t.Fatal(err)
	}
	reader := fixture.memberA
	reader.Permissions = []string{PermissionRead}
	if _, err := fixture.service.Get(context.Background(), reader, fixture.tenantA, created.ID); err != nil {
		t.Fatalf("Get before exact read permission revoke error = %v", err)
	}
	if _, err := rbacService.RevokeGrant(context.Background(), manager, rbacmanager.RevokeGrantRequest{
		GrantID: grant.ID, Mutation: challengeRBACMutation("challenge-read-recheck-revoke"),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.service.Get(context.Background(), reader, fixture.tenantA, created.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Get after exact read permission revoke error = %v", err)
	}
	if result, err := fixture.service.List(context.Background(), reader, ListFilter{
		TargetScopeID: fixture.tenantA, Limit: 10,
	}); !errors.Is(err, ErrPermissionDenied) || len(result.Items) != 0 {
		t.Fatalf("List after exact read permission revoke = (%#v, %v)", result, err)
	}
	handler, err := NewHandler(fixture.service, AuthenticatorFunc(func(*http.Request) (Actor, error) {
		return reader, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, itemPath(fixture.tenantA, created.ID), nil)
	request.Header.Set("X-Request-ID", "read-revoked-handler-request")
	request.Header.Set("X-Trace-ID", "read-revoked-handler-trace")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertHTTPError(t, response, http.StatusForbidden, "permission_denied")
}

func TestChallengePolicyReadAuthorizationCommitOrderMatrix(t *testing.T) {
	for _, mutation := range []string{"assignment", "account", "membership_suspend", "session"} {
		for _, operation := range challengeReadAuthorizationOperations() {
			for _, order := range []string{"revocation_first", "read_first"} {
				t.Run(mutation+"/"+operation.name+"/"+order, func(t *testing.T) {
					hooks := &testAuthorizationHooks{}
					fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
					useSharedSessionAuthorizer(t, fixture, hooks, allowGate())
					created := createServicePolicy(t, fixture, fixture.siteA, "a.example.test", "read-order-seed")
					roleID := challengeAuthorizationRoleID(t, fixture)
					invoke := func(ctx context.Context) (int, error) {
						return operation.invoke(ctx, fixture, fixture.ownerA, created)
					}
					before := readChallengeFactCounts(t, fixture.pool)
					if order == "revocation_first" {
						runChallengeReadRevocationFirst(t, fixture, hooks, roleID, mutation, invoke)
					} else {
						runChallengeReadFirst(t, fixture, hooks, roleID, mutation, invoke)
					}
					assertChallengeFactCounts(t, fixture.pool, before)
				})
			}
		}
	}
}

func TestChallengePolicyReadPermissionCommitOrderMatrix(t *testing.T) {
	for _, operation := range challengeReadAuthorizationOperations() {
		for _, order := range []string{"revocation_first", "read_first"} {
			t.Run(operation.name+"/"+order, func(t *testing.T) {
				hooks := &testAuthorizationHooks{}
				fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
				useSharedSessionAuthorizer(t, fixture, hooks, allowGate())
				created := createServicePolicy(t, fixture, fixture.siteA, "a.example.test", "read-permission-order-seed")
				rbacService, err := rbacmanager.NewServiceWithDependencies(
					fixture.pool, audit.New(fixture.pool), challengeStepUpVerifier{}, func() time.Time { return fixture.now })
				if err != nil {
					t.Fatal(err)
				}
				manager := rbacmanager.Actor{
					UserID: fixture.ownerA.UserID, ScopeID: fixture.ownerA.ScopeID,
					SessionID: fixture.ownerA.Credential.ID, ScopeKind: "tenant",
					IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
				}
				role, err := rbacService.CreateRole(context.Background(), manager, rbacmanager.CreateRoleRequest{
					Name: "challenge-read-permission-order", Permissions: []string{PermissionRead},
					Mutation: challengeRBACMutation("challenge-read-permission-order-create"),
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := rbacService.AssignRole(context.Background(), manager, rbacmanager.AssignRoleRequest{
					RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision,
					SubjectUserID: fixture.memberA.UserID,
					Mutation:      challengeRBACMutation("challenge-read-permission-order-assign"),
				}); err != nil {
					t.Fatal(err)
				}
				reader := fixture.memberA
				reader.Permissions = []string{PermissionRead}
				invoke := func(ctx context.Context) (int, error) {
					return operation.invoke(ctx, fixture, reader, created)
				}
				if count, err := invoke(context.Background()); err != nil || count == 0 {
					t.Fatalf("read before permission revoke = (%d,%v)", count, err)
				}
				revoke := func() error {
					_, err := rbacService.PublishRevision(context.Background(), manager, rbacmanager.PublishRevisionRequest{
						RoleID: role.ID, ExpectedRevision: role.CurrentRevision,
						Permissions: []string{PermissionManage},
						Mutation:    challengeRBACMutation("challenge-read-permission-order-revoke"),
					})
					return err
				}
				before := readChallengeFactCounts(t, fixture.pool)
				if order == "revocation_first" {
					if err := revoke(); err != nil {
						t.Fatal(err)
					}
					if count, err := invoke(context.Background()); !errors.Is(err, ErrPermissionDenied) || count != 0 {
						t.Fatalf("permission-revocation-first read = (%d,%v)", count, err)
					}
				} else {
					authorized := make(chan struct{}, 1)
					release := make(chan struct{})
					hooks.authorized = authorized
					hooks.release = release
					readResult := make(chan struct {
						count int
						err   error
					}, 1)
					go func() {
						count, err := invoke(context.Background())
						readResult <- struct {
							count int
							err   error
						}{count: count, err: err}
					}()
					select {
					case <-authorized:
					case <-time.After(10 * time.Second):
						t.Fatal("read authorization timed out")
					}
					revokeResult := make(chan error, 1)
					go func() { revokeResult <- revoke() }()
					select {
					case err := <-revokeResult:
						close(release)
						t.Fatalf("permission revocation bypassed read transaction lock: %v", err)
					case <-time.After(100 * time.Millisecond):
					}
					close(release)
					result := <-readResult
					if result.err != nil || result.count == 0 {
						t.Fatalf("read-first result = (%d,%v)", result.count, result.err)
					}
					if err := <-revokeResult; err != nil {
						t.Fatal(err)
					}
					if count, err := invoke(context.Background()); !errors.Is(err, ErrPermissionDenied) || count != 0 {
						t.Fatalf("read after permission revoke = (%d,%v)", count, err)
					}
				}
				assertChallengeFactCounts(t, fixture.pool, before)
			})
		}
	}
}

func TestChallengePolicyReadCredentialReferencesFailClosed(t *testing.T) {
	fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
	useSharedSessionAuthorizer(t, fixture, nil, allowGate())
	created := createServicePolicy(t, fixture, fixture.siteA, "a.example.test", "read-credential-seed")
	for _, test := range []struct {
		name  string
		actor Actor
	}{
		{name: "missing", actor: fixture.ownerA},
		{name: "unknown", actor: fixture.ownerA},
		{name: "empty_session", actor: fixture.ownerA},
		{name: "api_key", actor: fixture.ownerA},
		{name: "platform_session", actor: fixture.platform},
	} {
		t.Run(test.name, func(t *testing.T) {
			actor := test.actor
			switch test.name {
			case "missing":
				actor.Credential = CredentialReference{}
			case "unknown":
				actor.Credential = CredentialReference{Kind: "bearer", ID: uuid.New()}
			case "empty_session":
				actor.Credential = CredentialReference{Kind: CredentialKindSession}
			case "api_key":
				actor.Credential = CredentialReference{Kind: CredentialKindAPIKey, ID: uuid.New()}
			}
			if policy, err := fixture.service.Get(context.Background(), actor, fixture.tenantA, created.ID); !errors.Is(err, ErrPermissionDenied) || policy.ID != uuid.Nil {
				t.Fatalf("Get = (%#v,%v)", policy, err)
			}
			if result, err := fixture.service.List(context.Background(), actor, ListFilter{
				TargetScopeID: fixture.tenantA, Limit: 10,
			}); !errors.Is(err, ErrPermissionDenied) || len(result.Items) != 0 {
				t.Fatalf("List = (%#v,%v)", result, err)
			}
		})
	}

	store, err := NewStore(fixture.pool, fixture.cursor)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store)
	if _, err := service.Get(context.Background(), fixture.ownerA, fixture.tenantA, created.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("default deny Get error = %v", err)
	}
	if result, err := service.List(context.Background(), fixture.ownerA, ListFilter{
		TargetScopeID: fixture.tenantA, Limit: 10,
	}); !errors.Is(err, ErrPermissionDenied) || len(result.Items) != 0 {
		t.Fatalf("default deny List = (%#v,%v)", result, err)
	}
}

func TestChallengePolicyWriteCredentialReferencesFailClosed(t *testing.T) {
	fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
	useSharedSessionAuthorizer(t, fixture, nil, allowGate())
	for _, test := range []struct {
		name       string
		credential CredentialReference
	}{
		{name: "missing"},
		{name: "unknown", credential: CredentialReference{Kind: "bearer", ID: uuid.New()}},
		{name: "empty_session", credential: CredentialReference{Kind: CredentialKindSession}},
		{name: "api_key_without_transaction_adapter", credential: CredentialReference{Kind: CredentialKindAPIKey, ID: uuid.New()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			actor := fixture.ownerA
			actor.Credential = test.credential
			before := readChallengeFactCounts(t, fixture.pool)
			_, err := fixture.service.Create(context.Background(), actor, CreateRequest{
				TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
				Config: validConfig(ModeClick), WriteMetadata: metadata("credential-" + test.name),
			})
			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("credential %q error = %v", test.name, err)
			}
			assertChallengeFactCounts(t, fixture.pool, before)
		})
	}
}

func TestChallengePolicyDeletedMembershipFreshWritesFailClosed(t *testing.T) {
	for _, operation := range challengeAuthorizationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
			useSharedSessionAuthorizer(t, fixture, nil, allowGate())
			invoke := operation.prepare(t, fixture)
			roleID := challengeAuthorizationRoleID(t, fixture)
			// Migration 079 makes tenant_owner and tenant_viewer mutually exclusive: promote by replacing the viewer role.
			if _, err := fixture.pool.Exec(context.Background(), `DELETE FROM role_assignments
				WHERE scope_id=$1 AND user_id=$2`, fixture.viewerA.ScopeID, fixture.viewerA.UserID); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
				VALUES($1,$2,$3)`, fixture.viewerA.ScopeID, fixture.viewerA.UserID, roleID); err != nil {
				t.Fatal(err)
			}
			fixture.ownerA = fixture.viewerA
			before := readChallengeFactCounts(t, fixture.pool)
			if err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
				if _, err := tx.Exec(context.Background(), `DELETE FROM auth_sessions
					WHERE scope_id=$1 AND user_id=$2`, fixture.ownerA.ScopeID, fixture.ownerA.UserID); err != nil {
					return err
				}
				if _, err := tx.Exec(context.Background(), `DELETE FROM role_assignments
					WHERE scope_id=$1 AND user_id=$2`, fixture.ownerA.ScopeID, fixture.ownerA.UserID); err != nil {
					return err
				}
				_, err := tx.Exec(context.Background(), `DELETE FROM memberships
					WHERE scope_id=$1 AND user_id=$2`, fixture.ownerA.ScopeID, fixture.ownerA.UserID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := invoke(context.Background(), "deleted-membership-"+operation.name); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("fresh write after membership delete error = %v", err)
			}
			assertChallengeFactCounts(t, fixture.pool, before)
		})
	}
}

func TestChallengePolicyInProgressSameKeyReplayAuthorization(t *testing.T) {
	for _, operation := range challengeAuthorizationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			hooks := &testAuthorizationHooks{}
			gateEntered := make(chan struct{}, 1)
			gateRelease := make(chan struct{})
			gate := entitlementGate(allowGate())
			if operation.name == "create" {
				gate = blockingChallengeGate{entered: gateEntered, release: gateRelease}
			}
			fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
			useSharedSessionAuthorizer(t, fixture, hooks, gate)
			invoke := operation.prepare(t, fixture)
			before := readChallengeFactCounts(t, fixture.pool)

			var policyBlocker pgx.Tx
			if operation.name != "create" {
				var policyID uuid.UUID
				if err := fixture.pool.QueryRow(context.Background(), `SELECT id FROM challenge_policies
					WHERE tenant_scope_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1`,
					fixture.tenantA).Scan(&policyID); err != nil {
					t.Fatal(err)
				}
				var err error
				policyBlocker, err = fixture.pool.Begin(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = policyBlocker.Rollback(context.Background()) }()
				if _, err := policyBlocker.Exec(context.Background(), `SELECT id FROM challenge_policies
					WHERE id=$1 FOR UPDATE`, policyID); err != nil {
					t.Fatal(err)
				}
			}

			backendPIDs := make(chan int, 2)
			hooks.backendPID = backendPIDs
			key := "in-progress-" + operation.name
			firstResult := make(chan authorizationResult, 1)
			go func() {
				result, err := invoke(context.Background(), key)
				firstResult <- authorizationResult{result: result, err: err}
			}()
			firstPID := <-backendPIDs
			if operation.name == "create" {
				<-gateEntered
			} else {
				waitForChallengeBackendLock(t, fixture.pool, firstPID)
			}

			secondResult := make(chan authorizationResult, 1)
			go func() {
				result, err := invoke(context.Background(), key)
				secondResult <- authorizationResult{result: result, err: err}
			}()
			secondPID := <-backendPIDs
			waitForChallengeBackendLock(t, fixture.pool, secondPID)

			if operation.name == "create" {
				close(gateRelease)
			} else if err := policyBlocker.Commit(context.Background()); err != nil {
				t.Fatal(err)
			}
			first := receiveChallengeAuthorizationResult(t, firstResult)
			second := receiveChallengeAuthorizationResult(t, secondResult)
			if first.err != nil || first.result.Replayed {
				t.Fatalf("first result = (%#v,%v)", first.result, first.err)
			}
			if second.err != nil || !second.result.Replayed || second.result.Policy.ID != first.result.Policy.ID ||
				second.result.Policy.Revision != first.result.Policy.Revision {
				t.Fatalf("second result = (%#v,%v), first=%#v", second.result, second.err, first.result)
			}

			after := readChallengeFactCounts(t, fixture.pool)
			expected := before
			if operation.name == "create" {
				expected.policies++
			}
			expected.revisions++
			expected.writes++
			expected.audits++
			if after != expected {
				t.Fatalf("in-progress facts got=%+v want=%+v", after, expected)
			}
			var writes int
			var completed bool
			if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*),bool_and(completed_at IS NOT NULL)
				FROM challenge_policy_write_requests WHERE actor_scope_id=$1 AND actor_user_id=$2
				  AND operation=$3 AND idempotency_key=$4`, fixture.ownerA.ScopeID, fixture.ownerA.UserID,
				"challenge_policy."+operation.name, key).Scan(&writes, &completed); err != nil {
				t.Fatal(err)
			}
			if writes != 1 || !completed {
				t.Fatalf("same-key writes=%d completed=%t", writes, completed)
			}

			if _, err := fixture.pool.Exec(context.Background(), `UPDATE auth_sessions
				SET revoked_at=CURRENT_TIMESTAMP,revocation_reason='in-progress replay test'
				WHERE id=$1`, fixture.ownerA.Credential.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := invoke(context.Background(), key); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("same-key replay after session revoke error = %v", err)
			}
			assertChallengeFactCounts(t, fixture.pool, after)
		})
	}
}

func TestChallengePolicyInProgressSameKeyRevocationLinearization(t *testing.T) {
	for _, mutation := range []string{"role_permission", "account", "membership_suspend", "session"} {
		for _, operation := range challengeAuthorizationOperations() {
			t.Run(mutation+"/"+operation.name, func(t *testing.T) {
				hooks := &testAuthorizationHooks{}
				gateEntered := make(chan struct{}, 1)
				gateRelease := make(chan struct{})
				var workers sync.WaitGroup
				var releaseGateOnce sync.Once
				releaseGate := func() {
					releaseGateOnce.Do(func() { close(gateRelease) })
				}
				ctx, cancel := context.WithCancel(context.Background())
				var policyBlocker pgx.Tx
				var revocationTx pgx.Tx
				defer func() {
					cancel()
					releaseGate()
					workers.Wait()
					if revocationTx != nil {
						_ = revocationTx.Rollback(context.Background())
					}
					if policyBlocker != nil {
						_ = policyBlocker.Rollback(context.Background())
					}
				}()
				gate := entitlementGate(allowGate())
				if operation.name == "create" {
					gate = blockingChallengeGate{entered: gateEntered, release: gateRelease}
				}
				fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
				var roleID uuid.UUID
				if mutation == "role_permission" {
					roleID = replaceChallengeAuthorizationRole(t, fixture)
					store, err := newStoreWithGate(fixture.pool, func() time.Time { return fixture.now }, gate,
						fixture.cursor, testTxAuthorizer{hooks: hooks, permission: challengeAuthorizationTestPermission})
					if err != nil {
						t.Fatal(err)
					}
					fixture.service = NewService(store)
				} else {
					useSharedSessionAuthorizer(t, fixture, hooks, gate)
					roleID = challengeAuthorizationRoleID(t, fixture)
				}
				invoke := operation.prepare(t, fixture)
				before := readChallengeFactCounts(t, fixture.pool)

				var policyBlockerPID int
				if operation.name != "create" {
					var policyID uuid.UUID
					if err := fixture.pool.QueryRow(ctx, `SELECT id FROM challenge_policies
						WHERE tenant_scope_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1`,
						fixture.tenantA).Scan(&policyID); err != nil {
						t.Fatal(err)
					}
					var err error
					policyBlocker, err = fixture.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := policyBlocker.QueryRow(ctx, `SELECT pg_backend_pid() FROM challenge_policies
						WHERE id=$1 FOR UPDATE`, policyID).Scan(&policyBlockerPID); err != nil {
						t.Fatal(err)
					}
				}

				backendPIDs := make(chan int, 2)
				hooks.backendPID = backendPIDs
				receiveBackendPID := func(label string) int {
					select {
					case pid := <-backendPIDs:
						return pid
					case <-time.After(10 * time.Second):
						t.Fatalf("%s backend PID timed out", label)
						return 0
					}
				}
				key := "in-progress-revoke-" + mutation + "-" + operation.name
				firstResult := make(chan authorizationResult, 1)
				workers.Add(1)
				go func() {
					defer workers.Done()
					result, err := invoke(ctx, key)
					firstResult <- authorizationResult{result: result, err: err}
				}()
				firstPID := receiveBackendPID("first request")
				if operation.name == "create" {
					select {
					case <-gateEntered:
					case <-time.After(10 * time.Second):
						t.Fatal("first create request did not reach entitlement gate")
					}
				} else {
					waitForChallengeBackendBlockedBy(t, fixture.pool, firstPID, policyBlockerPID)
				}

				// Fix the second request before revocation by queuing it on the first request's claim.
				secondResult := make(chan authorizationResult, 1)
				workers.Add(1)
				go func() {
					defer workers.Done()
					result, err := invoke(ctx, key)
					secondResult <- authorizationResult{result: result, err: err}
				}()
				secondPID := receiveBackendPID("second request")
				waitForChallengeBackendBlockedBy(t, fixture.pool, secondPID, firstPID)

				revocationTx, err := fixture.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var revocationPID int
				if err := revocationTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&revocationPID); err != nil {
					t.Fatal(err)
				}
				revocationResult := make(chan error, 1)
				workers.Add(1)
				go func() {
					defer workers.Done()
					revocationResult <- applyChallengeAuthorizationRevocation(
						ctx, revocationTx, fixture, roleID, mutation)
				}()
				waitForChallengeBackendBlockedBy(t, fixture.pool, revocationPID, firstPID)

				if operation.name == "create" {
					releaseGate()
				} else if err := policyBlocker.Commit(ctx); err != nil {
					t.Fatal(err)
				} else {
					policyBlocker = nil
				}
				first := receiveChallengeAuthorizationResult(t, firstResult)
				if first.err != nil || first.result.Replayed {
					t.Fatalf("first result = (%#v,%v)", first.result, first.err)
				}
				second := receiveChallengeAuthorizationResult(t, secondResult)
				if second.err != nil || !second.result.Replayed || second.result.Policy.ID != first.result.Policy.ID ||
					second.result.Policy.Revision != first.result.Policy.Revision {
					t.Fatalf("second result = (%#v,%v), first=%#v", second.result, second.err, first.result)
				}
				select {
				case err := <-revocationResult:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("revocation remained blocked after replay commit")
				}
				if err := revocationTx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				revocationTx = nil
				if _, err := invoke(context.Background(), key); !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("same-key replay after revocation error = %v", err)
				}

				after := readChallengeFactCounts(t, fixture.pool)
				expected := before
				if operation.name == "create" {
					expected.policies++
				}
				expected.revisions++
				expected.writes++
				expected.audits++
				if after != expected {
					t.Fatalf("replay-first in-progress facts got=%+v want=%+v", after, expected)
				}
			})
		}
	}
}

func TestChallengePolicyRealCustomRBACMutationGate(t *testing.T) {
	hooks := &testAuthorizationHooks{}
	fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
	useSharedSessionAuthorizer(t, fixture, hooks, allowGate())
	rbacService, err := rbacmanager.NewServiceWithDependencies(
		fixture.pool, audit.New(fixture.pool), challengeStepUpVerifier{}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	manager := rbacmanager.Actor{
		UserID: fixture.ownerA.UserID, ScopeID: fixture.ownerA.ScopeID,
		SessionID: fixture.ownerA.Credential.ID, ScopeKind: "tenant",
		IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
	role, err := rbacService.CreateRole(context.Background(), manager, rbacmanager.CreateRoleRequest{
		Name: "challenge-operator", Permissions: []string{PermissionManage},
		Mutation: challengeRBACMutation("challenge-custom-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := rbacService.AssignRole(context.Background(), manager, rbacmanager.AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision, SubjectUserID: fixture.viewerA.UserID,
		Mutation: challengeRBACMutation("challenge-custom-assign"),
	})
	if err != nil {
		t.Fatal(err)
	}

	request := CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("custom-rbac-replay"),
	}
	created, err := fixture.service.Create(context.Background(), fixture.viewerA, request)
	if err != nil || created.Replayed {
		t.Fatalf("custom RBAC create = (%#v,%v)", created, err)
	}
	replayed, err := fixture.service.Create(context.Background(), fixture.viewerA, request)
	if err != nil || !replayed.Replayed || replayed.Policy.ID != created.Policy.ID {
		t.Fatalf("custom RBAC replay = (%#v,%v)", replayed, err)
	}

	role, err = rbacService.PublishRevision(context.Background(), manager, rbacmanager.PublishRevisionRequest{
		RoleID: role.ID, ExpectedRevision: role.CurrentRevision, Permissions: []string{PermissionRead},
		Mutation: challengeRBACMutation("challenge-custom-publish-remove"),
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeDeniedReplay := readChallengeFactCounts(t, fixture.pool)
	if _, err := fixture.service.Create(context.Background(), fixture.viewerA, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("completed replay after custom publish revoke error = %v", err)
	}
	assertChallengeFactCounts(t, fixture.pool, beforeDeniedReplay)

	role, err = rbacService.PublishRevision(context.Background(), manager, rbacmanager.PublishRevisionRequest{
		RoleID: role.ID, ExpectedRevision: role.CurrentRevision, Permissions: []string{PermissionManage},
		Mutation: challengeRBACMutation("challenge-custom-publish-restore"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = role
	concurrentSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "custom-rbac-lock.example.test")
	concurrentRequest := CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: concurrentSite, Host: "custom-rbac-lock.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("custom-rbac-lock"),
	}
	authorized := make(chan struct{}, 1)
	release := make(chan struct{})
	hooks.authorized = authorized
	hooks.release = release
	businessResult := make(chan authorizationResult, 1)
	go func() {
		result, err := fixture.service.Create(context.Background(), fixture.viewerA, concurrentRequest)
		businessResult <- authorizationResult{result: result, err: err}
	}()
	<-authorized
	revokeResult := make(chan error, 1)
	go func() {
		_, err := rbacService.RevokeGrant(context.Background(), manager, rbacmanager.RevokeGrantRequest{
			GrantID: grant.ID, Mutation: challengeRBACMutation("challenge-custom-revoke"),
		})
		revokeResult <- err
	}()
	select {
	case err := <-revokeResult:
		close(release)
		t.Fatalf("custom grant revocation bypassed challenge authorization lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	business := receiveChallengeAuthorizationResult(t, businessResult)
	if business.err != nil || business.result.Replayed {
		t.Fatalf("business before custom revoke = (%#v,%v)", business.result, business.err)
	}
	select {
	case err := <-revokeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("custom grant revocation remained blocked after challenge commit")
	}
	afterRevocation := readChallengeFactCounts(t, fixture.pool)
	if _, err := fixture.service.Create(context.Background(), fixture.viewerA, concurrentRequest); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("completed replay after custom grant revoke error = %v", err)
	}
	freshSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "custom-rbac-denied.example.test")
	if _, err := fixture.service.Create(context.Background(), fixture.viewerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: freshSite, Host: "custom-rbac-denied.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("custom-rbac-denied-fresh"),
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("fresh write after custom grant revoke error = %v", err)
	}
	assertChallengeFactCounts(t, fixture.pool, afterRevocation)
}

type customRBACScenario struct {
	fixture *testFixture
	hooks   *testAuthorizationHooks
	service *rbacmanager.Service
	manager rbacmanager.Actor
	role    rbacmanager.Role
	grant   rbacmanager.Grant
	invoke  func(context.Context, string) (WriteResult, error)
}

func TestChallengePolicyRealCustomRBACMutationOperationMatrix(t *testing.T) {
	for _, revocation := range []string{"publish_revision", "revoke_grant"} {
		for _, operation := range challengeAuthorizationOperations() {
			for _, state := range []string{"fresh", "completed", "in_progress"} {
				for _, order := range []string{"revocation_first", "business_first"} {
					name := fmt.Sprintf("%s/%s/%s/%s", revocation, operation.name, state, order)
					t.Run(name, func(t *testing.T) {
						if state == "in_progress" {
							runCustomRBACInProgressCase(t, revocation, operation, order)
							return
						}
						runCustomRBACFreshOrCompletedCase(t, revocation, operation, state, order)
					})
				}
			}
		}
	}
}

func newCustomRBACScenario(
	t *testing.T,
	operation authorizationOperation,
	gate entitlementGate,
) *customRBACScenario {
	t.Helper()
	hooks := &testAuthorizationHooks{}
	fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{})
	useSharedSessionAuthorizer(t, fixture, hooks, gate)
	service, err := rbacmanager.NewServiceWithDependencies(
		fixture.pool, audit.New(fixture.pool), challengeStepUpVerifier{}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	manager := rbacmanager.Actor{
		UserID: fixture.ownerA.UserID, ScopeID: fixture.ownerA.ScopeID,
		SessionID: fixture.ownerA.Credential.ID, ScopeKind: "tenant",
		IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
	role, err := service.CreateRole(context.Background(), manager, rbacmanager.CreateRoleRequest{
		Name: "challenge-operation-matrix", Permissions: []string{PermissionManage},
		Mutation: challengeRBACMutation("challenge-custom-matrix-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.AssignRole(context.Background(), manager, rbacmanager.AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision, SubjectUserID: fixture.viewerA.UserID,
		Mutation: challengeRBACMutation("challenge-custom-matrix-assign"),
	})
	if err != nil {
		t.Fatal(err)
	}
	invoke := operation.prepare(t, fixture)
	fixture.ownerA = fixture.viewerA
	return &customRBACScenario{
		fixture: fixture, hooks: hooks, service: service, manager: manager,
		role: role, grant: grant, invoke: invoke,
	}
}

func (scenario *customRBACScenario) revoke(ctx context.Context, kind, key string) error {
	switch kind {
	case "publish_revision":
		_, err := scenario.service.PublishRevision(ctx, scenario.manager, rbacmanager.PublishRevisionRequest{
			RoleID: scenario.role.ID, ExpectedRevision: scenario.role.CurrentRevision,
			Permissions: []string{PermissionRead}, Mutation: challengeRBACMutation(key),
		})
		return err
	case "revoke_grant":
		_, err := scenario.service.RevokeGrant(ctx, scenario.manager, rbacmanager.RevokeGrantRequest{
			GrantID: scenario.grant.ID, Mutation: challengeRBACMutation(key),
		})
		return err
	default:
		return fmt.Errorf("unknown custom RBAC revocation %q", kind)
	}
}

func runCustomRBACFreshOrCompletedCase(
	t *testing.T,
	revocation string,
	operation authorizationOperation,
	state string,
	order string,
) {
	t.Helper()
	scenario := newCustomRBACScenario(t, operation, allowGate())
	key := fmt.Sprintf("custom-%s-%s-%s", revocation, operation.name, state)
	if state == "completed" {
		result, err := scenario.invoke(context.Background(), key)
		if err != nil || result.Replayed {
			t.Fatalf("prepare completed replay = (%#v,%v)", result, err)
		}
	}
	if order == "revocation_first" {
		if err := scenario.revoke(context.Background(), revocation, key+"-revoke-first"); err != nil {
			t.Fatal(err)
		}
		before := readChallengeFactCounts(t, scenario.fixture.pool)
		if _, err := scenario.invoke(context.Background(), key); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("request after formal revocation error = %v", err)
		}
		assertChallengeFactCounts(t, scenario.fixture.pool, before)
		return
	}

	before := readChallengeFactCounts(t, scenario.fixture.pool)
	authorized := make(chan struct{}, 1)
	release := make(chan struct{})
	scenario.hooks.authorized = authorized
	scenario.hooks.release = release
	businessResult := make(chan authorizationResult, 1)
	go func() {
		result, err := scenario.invoke(context.Background(), key)
		businessResult <- authorizationResult{result: result, err: err}
	}()
	select {
	case <-authorized:
	case <-time.After(10 * time.Second):
		t.Fatal("custom RBAC business authorization timed out")
	}
	revocationStarted := make(chan struct{})
	revocationResult := make(chan error, 1)
	go func() {
		close(revocationStarted)
		revocationResult <- scenario.revoke(context.Background(), revocation, key+"-revoke-after-business")
	}()
	<-revocationStarted
	select {
	case err := <-revocationResult:
		close(release)
		t.Fatalf("formal revocation bypassed custom RBAC authorization lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	business := receiveChallengeAuthorizationResult(t, businessResult)
	if business.err != nil || business.result.Replayed != (state == "completed") {
		t.Fatalf("business-first result = (%#v,%v), state=%s", business.result, business.err, state)
	}
	receiveCustomRBACRevocation(t, revocationResult)
	after := readChallengeFactCounts(t, scenario.fixture.pool)
	expected := before
	if state == "fresh" {
		if operation.name == "create" {
			expected.policies++
		}
		expected.revisions++
		expected.writes++
		expected.audits++
	}
	if after != expected {
		t.Fatalf("business-first facts got=%+v want=%+v", after, expected)
	}
	if _, err := scenario.invoke(context.Background(), key+"-after-revoke"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("fresh request after formal revocation error = %v", err)
	}
	assertChallengeFactCounts(t, scenario.fixture.pool, after)
}

func runCustomRBACInProgressCase(
	t *testing.T,
	revocation string,
	operation authorizationOperation,
	order string,
) {
	t.Helper()
	gateEntered := make(chan struct{}, 1)
	gateRelease := make(chan struct{})
	gate := entitlementGate(allowGate())
	if operation.name == "create" {
		gate = blockingChallengeGate{entered: gateEntered, release: gateRelease}
	}
	scenario := newCustomRBACScenario(t, operation, gate)
	key := fmt.Sprintf("custom-in-progress-%s-%s", revocation, operation.name)
	if order == "revocation_first" {
		if err := scenario.revoke(context.Background(), revocation, key+"-revoke-first"); err != nil {
			t.Fatal(err)
		}
		before := readChallengeFactCounts(t, scenario.fixture.pool)
		results := make(chan authorizationResult, 2)
		for index := 0; index < 2; index++ {
			go func() {
				result, err := scenario.invoke(context.Background(), key)
				results <- authorizationResult{result: result, err: err}
			}()
		}
		for index := 0; index < 2; index++ {
			result := receiveChallengeAuthorizationResult(t, results)
			if !errors.Is(result.err, ErrPermissionDenied) {
				t.Fatalf("revocation-first request = (%#v,%v)", result.result, result.err)
			}
		}
		assertChallengeFactCounts(t, scenario.fixture.pool, before)
		var claims int
		if err := scenario.fixture.pool.QueryRow(context.Background(), `SELECT count(*)
			FROM challenge_policy_write_requests
			WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
			scenario.fixture.ownerA.ScopeID, scenario.fixture.ownerA.UserID,
			"challenge_policy."+operation.name, key).Scan(&claims); err != nil {
			t.Fatal(err)
		}
		if claims != 0 {
			t.Fatalf("revocation-first unexpectedly formed in-progress claim count=%d", claims)
		}
		return
	}

	before := readChallengeFactCounts(t, scenario.fixture.pool)
	var policyBlocker pgx.Tx
	if operation.name != "create" {
		var policyID uuid.UUID
		if err := scenario.fixture.pool.QueryRow(context.Background(), `SELECT id FROM challenge_policies
			WHERE tenant_scope_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1`,
			scenario.fixture.tenantA).Scan(&policyID); err != nil {
			t.Fatal(err)
		}
		var err error
		policyBlocker, err = scenario.fixture.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = policyBlocker.Rollback(context.Background()) }()
		if _, err := policyBlocker.Exec(context.Background(), `SELECT id FROM challenge_policies WHERE id=$1 FOR UPDATE`, policyID); err != nil {
			t.Fatal(err)
		}
	}
	backendPIDs := make(chan int, 2)
	scenario.hooks.backendPID = backendPIDs
	firstResult := make(chan authorizationResult, 1)
	go func() {
		result, err := scenario.invoke(context.Background(), key)
		firstResult <- authorizationResult{result: result, err: err}
	}()
	firstPID := <-backendPIDs
	if operation.name == "create" {
		select {
		case <-gateEntered:
		case <-time.After(10 * time.Second):
			t.Fatal("custom RBAC create did not reach entitlement gate")
		}
	} else {
		waitForChallengeBackendLock(t, scenario.fixture.pool, firstPID)
	}

	revocationStarted := make(chan struct{})
	revocationResult := make(chan error, 1)
	go func() {
		close(revocationStarted)
		revocationResult <- scenario.revoke(context.Background(), revocation, key+"-revoke-after-claim")
	}()
	<-revocationStarted
	select {
	case err := <-revocationResult:
		if operation.name == "create" {
			close(gateRelease)
		} else {
			_ = policyBlocker.Rollback(context.Background())
		}
		t.Fatalf("formal revocation bypassed in-progress custom RBAC lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	secondResult := make(chan authorizationResult, 1)
	go func() {
		result, err := scenario.invoke(context.Background(), key)
		secondResult <- authorizationResult{result: result, err: err}
	}()
	secondPID := <-backendPIDs
	waitForChallengeBackendLock(t, scenario.fixture.pool, secondPID)

	if operation.name == "create" {
		close(gateRelease)
	} else if err := policyBlocker.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := receiveChallengeAuthorizationResult(t, firstResult)
	if first.err != nil || first.result.Replayed {
		t.Fatalf("in-progress first result = (%#v,%v)", first.result, first.err)
	}
	receiveCustomRBACRevocation(t, revocationResult)
	second := receiveChallengeAuthorizationResult(t, secondResult)
	if !errors.Is(second.err, ErrPermissionDenied) {
		t.Fatalf("same-key request queued after formal revoke = (%#v,%v)", second.result, second.err)
	}
	after := readChallengeFactCounts(t, scenario.fixture.pool)
	expected := before
	if operation.name == "create" {
		expected.policies++
	}
	expected.revisions++
	expected.writes++
	expected.audits++
	if after != expected {
		t.Fatalf("in-progress custom RBAC facts got=%+v want=%+v", after, expected)
	}
	if _, err := scenario.invoke(context.Background(), key); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("completed replay after formal revoke error = %v", err)
	}
	assertChallengeFactCounts(t, scenario.fixture.pool, after)
}

func receiveCustomRBACRevocation(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("formal custom RBAC revocation timed out")
	}
}

func challengeRBACMutation(key string) rbacmanager.MutationContext {
	return rbacmanager.MutationContext{
		IdempotencyKey: key, RequestID: "request-" + key, TraceID: "trace-" + key,
		StepUp: rbacmanager.StepUpProof{Token: "challenge-policy-step-up"},
	}
}

func receiveChallengeAuthorizationResult(
	t *testing.T,
	results <-chan authorizationResult,
) authorizationResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("challenge policy authorization request timed out")
		return authorizationResult{}
	}
}

func TestChallengePolicyAuthorizationDeadlockStress(t *testing.T) {
	hooks := &testAuthorizationHooks{}
	fixture := newFixtureWithAuthorizer(t, allowGate(), testTxAuthorizer{
		hooks: hooks, permission: challengeAuthorizationTestPermission,
	})
	roleID := replaceChallengeAuthorizationRole(t, fixture)
	mutations := []string{"assignment", "role_permission", "account"}
	for iteration := 0; iteration < 30; iteration++ {
		mutation := mutations[iteration%len(mutations)]
		if err := restoreChallengeAuthorization(
			context.Background(), fixture.pool, fixture, roleID); err != nil {
			t.Fatalf("iteration %d restore authorization: %v", iteration, err)
		}
		*hooks = testAuthorizationHooks{}
		host := fmt.Sprintf("authorization-stress-%d.example.test", iteration)
		siteID := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, host)
		request := CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: siteID, Host: host, Enabled: true,
			Config: validConfig(ModeClick), WriteMetadata: metadata(fmt.Sprintf("authorization-stress-%d", iteration)),
		}
		invoke := func(ctx context.Context, _ string) (WriteResult, error) {
			return fixture.service.Create(ctx, fixture.ownerA, request)
		}
		if iteration%2 == 0 {
			before := readChallengeFactCounts(t, fixture.pool)
			runChallengeRevocationFirst(t, fixture, hooks, roleID, mutation, invoke, request.IdempotencyKey)
			assertChallengeFactCounts(t, fixture.pool, before)
			continue
		}
		result := runChallengeBusinessFirst(
			t, fixture, hooks, roleID, mutation, invoke, request.IdempotencyKey)
		if result.err != nil || result.result.Replayed {
			t.Fatalf("iteration %d business-first result = (%#v, %v)", iteration, result.result, result.err)
		}
	}
}

func TestChallengePolicyPackageRuntimeSmoke(t *testing.T) {
	pool := openChallengeTestPool(t)
	fixture := seedFixture(t, pool)
	// The revocation LKG trigger (084) checks the set's window against the database's physical clock.
	now := time.Now().UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "challenge-test-key", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	installLease(t, pool, trust, privateKey, now, 1, true)
	cursor := testCursorCodec(t, 9)
	legacyStore, err := NewStoreWithClock(pool, func() time.Time { return now }, trust, cursor)
	if err != nil {
		t.Fatal(err)
	}
	deniedRequest := CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("runtime-missing-authorizer"),
	}
	before := readChallengeFactCounts(t, pool)
	if _, err := NewService(legacyStore).Create(context.Background(), fixture.ownerA, deniedRequest); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("legacy constructor without authorizer error = %v", err)
	}
	assertChallengeFactCounts(t, pool, before)

	rbacService, err := rbacmanager.NewServiceWithDependencies(
		pool, audit.New(pool), challengeStepUpVerifier{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewTenantSessionTxAuthorizer(rbacService)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreWithDependencies(
		pool, func() time.Time { return now }, trust, cursor, authorizer)
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
	payload := createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true)
	created := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), payload, "runtime-create", "")
	if created.Code != http.StatusCreated {
		t.Fatalf("runtime create status=%d body=%s", created.Code, created.Body)
	}
	replay := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), payload, "runtime-create", "")
	if replay.Code != http.StatusCreated || replay.Header().Get("X-Idempotent-Replay") != "true" {
		t.Fatalf("runtime replay status=%d replay=%q body=%s",
			replay.Code, replay.Header().Get("X-Idempotent-Replay"), replay.Body)
	}
	before = readChallengeFactCounts(t, pool)
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
	assertChallengeFactCounts(t, pool, before)
}

func challengeAuthorizationOperations() []authorizationOperation {
	return []authorizationOperation{
		{
			name: "create",
			prepare: func(t *testing.T, fixture *testFixture) func(context.Context, string) (WriteResult, error) {
				t.Helper()
				base := CreateRequest{
					TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
					Config: validConfig(ModeClick),
				}
				return func(ctx context.Context, key string) (WriteResult, error) {
					request := base
					request.Config = cloneChallengeAuthorizationConfig(base.Config)
					request.WriteMetadata = metadata(key)
					return fixture.service.Create(ctx, fixture.ownerA, request)
				}
			},
		},
		{
			name: "update",
			prepare: func(t *testing.T, fixture *testFixture) func(context.Context, string) (WriteResult, error) {
				policy := createServicePolicy(t, fixture, fixture.siteA, "a.example.test", "authorization-seed-update")
				base := UpdateRequest{
					TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision,
					Config: validConfig(ModeSlider),
				}
				return func(ctx context.Context, key string) (WriteResult, error) {
					request := base
					request.Config = cloneChallengeAuthorizationConfig(base.Config)
					request.WriteMetadata = metadata(key)
					return fixture.service.Update(ctx, fixture.ownerA, request)
				}
			},
		},
		{
			name: "enable",
			prepare: func(t *testing.T, fixture *testFixture) func(context.Context, string) (WriteResult, error) {
				created, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
					TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: false,
					Config: validConfig(ModeClick), WriteMetadata: metadata("authorization-seed-enable"),
				})
				if err != nil {
					t.Fatalf("prepare enable: %v", err)
				}
				base := StateRequest{
					TargetScopeID: fixture.tenantA, ID: created.Policy.ID,
					ExpectedRevision: created.Policy.Revision, Enabled: true,
				}
				return func(ctx context.Context, key string) (WriteResult, error) {
					request := base
					request.WriteMetadata = metadata(key)
					return fixture.service.SetEnabled(ctx, fixture.ownerA, request)
				}
			},
		},
		{
			name: "disable",
			prepare: func(t *testing.T, fixture *testFixture) func(context.Context, string) (WriteResult, error) {
				policy := createServicePolicy(t, fixture, fixture.siteA, "a.example.test", "authorization-seed-disable")
				base := StateRequest{
					TargetScopeID: fixture.tenantA, ID: policy.ID,
					ExpectedRevision: policy.Revision, Enabled: false,
				}
				return func(ctx context.Context, key string) (WriteResult, error) {
					request := base
					request.WriteMetadata = metadata(key)
					return fixture.service.SetEnabled(ctx, fixture.ownerA, request)
				}
			},
		},
		{
			name: "delete",
			prepare: func(t *testing.T, fixture *testFixture) func(context.Context, string) (WriteResult, error) {
				policy := createServicePolicy(t, fixture, fixture.siteA, "a.example.test", "authorization-seed-delete")
				base := DeleteRequest{
					TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision,
				}
				return func(ctx context.Context, key string) (WriteResult, error) {
					request := base
					request.WriteMetadata = metadata(key)
					return fixture.service.Delete(ctx, fixture.ownerA, request)
				}
			},
		},
	}
}

func challengeReadAuthorizationOperations() []readAuthorizationOperation {
	return []readAuthorizationOperation{
		{
			name: "get",
			invoke: func(ctx context.Context, fixture *testFixture, actor Actor, expected Policy) (int, error) {
				item, err := fixture.service.Get(ctx, actor, fixture.tenantA, expected.ID)
				if err != nil {
					return 0, err
				}
				if item.ID != expected.ID {
					return 0, fmt.Errorf("Get returned policy %s, want %s", item.ID, expected.ID)
				}
				return 1, nil
			},
		},
		{
			name: "list",
			invoke: func(ctx context.Context, fixture *testFixture, actor Actor, expected Policy) (int, error) {
				result, err := fixture.service.List(ctx, actor, ListFilter{
					TargetScopeID: fixture.tenantA, Limit: 10,
				})
				if err != nil {
					return 0, err
				}
				for _, item := range result.Items {
					if item.ID == expected.ID {
						return len(result.Items), nil
					}
				}
				return 0, fmt.Errorf("List omitted policy %s", expected.ID)
			},
		},
	}
}

func runChallengeReadRevocationFirst(
	t *testing.T,
	fixture *testFixture,
	hooks *testAuthorizationHooks,
	roleID uuid.UUID,
	mutation string,
	invoke func(context.Context) (int, error),
) {
	t.Helper()
	tx, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := applyChallengeAuthorizationRevocation(context.Background(), tx, fixture, roleID, mutation); err != nil {
		t.Fatalf("hold %s read revocation: %v", mutation, err)
	}
	backendPID := make(chan int, 1)
	entered := make(chan struct{}, 1)
	hooks.backendPID = backendPID
	hooks.entered = entered
	resultChannel := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		count, err := invoke(context.Background())
		resultChannel <- struct {
			count int
			err   error
		}{count: count, err: err}
	}()
	var pid int
	select {
	case pid = <-backendPID:
	case <-time.After(10 * time.Second):
		t.Fatal("revocation-first read did not enter transaction authorizer")
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("revocation-first read authorizer hook timed out")
	}
	waitForChallengeBackendLock(t, fixture.pool, pid)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s read revocation: %v", mutation, err)
	}
	result := <-resultChannel
	if !errors.Is(result.err, ErrPermissionDenied) || result.count != 0 {
		t.Fatalf("revocation-first read result = (%d,%v)", result.count, result.err)
	}
}

func runChallengeReadFirst(
	t *testing.T,
	fixture *testFixture,
	hooks *testAuthorizationHooks,
	roleID uuid.UUID,
	mutation string,
	invoke func(context.Context) (int, error),
) {
	t.Helper()
	authorized := make(chan struct{}, 1)
	release := make(chan struct{})
	hooks.authorized = authorized
	hooks.release = release
	resultChannel := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		count, err := invoke(context.Background())
		resultChannel <- struct {
			count int
			err   error
		}{count: count, err: err}
	}()
	select {
	case <-authorized:
	case <-time.After(10 * time.Second):
		t.Fatal("read-first authorization timed out")
	}

	revocationTx, err := fixture.pool.Begin(context.Background())
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer func() { _ = revocationTx.Rollback(context.Background()) }()
	var revocationPID int
	if err := revocationTx.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&revocationPID); err != nil {
		close(release)
		t.Fatal(err)
	}
	revocationResult := make(chan error, 1)
	go func() {
		revocationResult <- applyChallengeAuthorizationRevocation(
			context.Background(), revocationTx, fixture, roleID, mutation)
	}()
	waitForChallengeBackendLock(t, fixture.pool, revocationPID)
	close(release)
	result := <-resultChannel
	if result.err != nil || result.count == 0 {
		t.Fatalf("read-first result = (%d,%v)", result.count, result.err)
	}
	if err := <-revocationResult; err != nil {
		t.Fatalf("apply %s revocation after read: %v", mutation, err)
	}
	if err := revocationTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s revocation after read: %v", mutation, err)
	}
	if count, err := invoke(context.Background()); !errors.Is(err, ErrPermissionDenied) || count != 0 {
		t.Fatalf("read after committed %s revocation = (%d,%v)", mutation, count, err)
	}
}

func cloneChallengeAuthorizationConfig(config Config) Config {
	copy := config
	copy.BypassRoutes = append([]BypassRoute(nil), config.BypassRoutes...)
	if config.ExternalProvider != nil {
		provider := *config.ExternalProvider
		copy.ExternalProvider = &provider
	}
	return copy
}

func challengeAuthorizationRoleID(t *testing.T, fixture *testFixture) uuid.UUID {
	t.Helper()
	var roleID uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `SELECT role.id
		FROM roles role JOIN role_assignments assignment ON assignment.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		  AND role.system_role AND role.name='tenant_owner'`,
		fixture.ownerA.ScopeID, fixture.ownerA.UserID).Scan(&roleID); err != nil {
		t.Fatalf("find challenge authorization role: %v", err)
	}
	return roleID
}

func replaceChallengeAuthorizationRole(t *testing.T, fixture *testFixture) uuid.UUID {
	t.Helper()
	roleID := uuid.New()
	ctx := context.Background()
	if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO permissions(name,description) VALUES($1,$2)`,
			challengeAuthorizationTestPermission, "Challenge policy transaction authorization test"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,$3,true)`,
			roleID, fixture.ownerA.ScopeID,
			"challenge_authorization_"+strings.ReplaceAll(roleID.String(), "-", "")); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`,
			roleID, challengeAuthorizationTestPermission); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
			fixture.ownerA.ScopeID, fixture.ownerA.UserID, roleID)
		return err
	}); err != nil {
		t.Fatalf("replace challenge authorization role: %v", err)
	}
	return roleID
}

func runChallengeRevocationFirst(
	t *testing.T,
	fixture *testFixture,
	hooks *testAuthorizationHooks,
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
	if err := applyChallengeAuthorizationRevocation(context.Background(), tx, fixture, roleID, mutation); err != nil {
		t.Fatalf("hold %s revocation: %v", mutation, err)
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
	waitForChallengeBackendLock(t, fixture.pool, pid)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit %s revocation: %v", mutation, err)
	}
	result := <-resultChannel
	if !errors.Is(result.err, ErrPermissionDenied) {
		t.Fatalf("revocation-first result = (%#v, %v)", result.result, result.err)
	}
}

func runChallengeBusinessFirst(
	t *testing.T,
	fixture *testFixture,
	hooks *testAuthorizationHooks,
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
		revocationResult <- applyChallengeAuthorizationRevocation(
			context.Background(), revocationTx, fixture, roleID, mutation)
	}()
	waitForChallengeBackendLock(t, fixture.pool, revocationPID)
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

func applyChallengeAuthorizationRevocation(
	ctx context.Context,
	tx pgx.Tx,
	fixture *testFixture,
	roleID uuid.UUID,
	mutation string,
) error {
	switch mutation {
	case "assignment":
		_, err := tx.Exec(ctx, `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
			fixture.ownerA.ScopeID, fixture.ownerA.UserID, roleID)
		return err
	case "role_permission":
		_, err := tx.Exec(ctx, `DELETE FROM role_permissions
			WHERE role_id=$1 AND permission_name=$2`, roleID, challengeAuthorizationTestPermission)
		return err
	case "account":
		_, err := tx.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, fixture.ownerA.UserID)
		return err
	case "membership_suspend":
		_, err := tx.Exec(ctx, `UPDATE memberships SET status='suspended'
			WHERE scope_id=$1 AND user_id=$2`, fixture.ownerA.ScopeID, fixture.ownerA.UserID)
		return err
	case "session":
		_, err := tx.Exec(ctx, `UPDATE auth_sessions
			SET revoked_at=CURRENT_TIMESTAMP,revocation_reason='challenge authorization test'
			WHERE id=$1`, fixture.ownerA.Credential.ID)
		return err
	default:
		return fmt.Errorf("unknown authorization mutation %q", mutation)
	}
}

func restoreChallengeAuthorization(
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture *testFixture,
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
		if _, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=NULL,revocation_reason=NULL
			WHERE id=$1`, fixture.ownerA.Credential.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
			SELECT $1,CASE WHEN EXISTS(SELECT 1 FROM permissions WHERE name=$2) THEN $2 ELSE $3 END
			ON CONFLICT DO NOTHING`, roleID, challengeAuthorizationTestPermission, PermissionManage); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, fixture.ownerA.ScopeID, fixture.ownerA.UserID, roleID)
		return err
	})
}

type challengeStepUpVerifier struct{}

func (challengeStepUpVerifier) VerifyAndConsume(
	_ context.Context,
	tx pgx.Tx,
	proof rbacmanager.StepUpProof,
	check rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	if tx == nil || proof.Token != "challenge-policy-step-up" || check.Actor.SessionID == uuid.Nil {
		return rbacmanager.StepUpEvidence{}, rbacmanager.ErrStepUpRequired
	}
	return rbacmanager.StepUpEvidence{
		ProofID: uuid.New(), Method: "totp", VerifiedAt: time.Date(2026, 7, 23, 1, 59, 0, 0, time.UTC),
	}, nil
}

type hookedTenantSessionAuthorizer struct {
	delegate TenantSessionAuthorizer
	hooks    *testAuthorizationHooks
}

func (authorizer hookedTenantSessionAuthorizer) AuthorizeTenantSessionTx(
	ctx context.Context,
	tx pgx.Tx,
	session rbacmanager.AuthenticatedSessionReference,
	permission string,
) (uuid.UUID, error) {
	if authorizer.hooks != nil && authorizer.hooks.backendPID != nil {
		var backendPID int
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
			return uuid.Nil, err
		}
		authorizer.hooks.backendPID <- backendPID
	}
	if authorizer.hooks != nil && authorizer.hooks.entered != nil {
		authorizer.hooks.entered <- struct{}{}
	}
	tenantID, err := authorizer.delegate.AuthorizeTenantSessionTx(ctx, tx, session, permission)
	if err != nil {
		return uuid.Nil, err
	}
	if authorizer.hooks != nil && authorizer.hooks.authorized != nil {
		authorizer.hooks.authorized <- struct{}{}
	}
	if authorizer.hooks != nil && authorizer.hooks.release != nil {
		select {
		case <-ctx.Done():
			return uuid.Nil, ctx.Err()
		case <-authorizer.hooks.release:
		}
	}
	return tenantID, nil
}

func useSharedSessionAuthorizer(
	t *testing.T,
	fixture *testFixture,
	hooks *testAuthorizationHooks,
	gate entitlementGate,
) {
	t.Helper()
	service, err := rbacmanager.NewServiceWithDependencies(
		fixture.pool, audit.New(fixture.pool), challengeStepUpVerifier{}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewTenantSessionTxAuthorizer(hookedTenantSessionAuthorizer{delegate: service, hooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStoreWithGate(
		fixture.pool, func() time.Time { return fixture.now }, gate, fixture.cursor, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = NewService(store)
}

func waitForChallengeBackendLock(t *testing.T, pool *pgxpool.Pool, backendPID int) {
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

func waitForChallengeBackendBlockedBy(t *testing.T, pool *pgxpool.Pool, backendPID, blockerPID int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blocked bool
		err := pool.QueryRow(context.Background(), `SELECT $2 = ANY(pg_blocking_pids($1))`,
			backendPID, blockerPID).Scan(&blocked)
		if err == nil && blocked {
			return
		}
		if err != nil {
			t.Fatalf("inspect backend %d blocker %d: %v", backendPID, blockerPID, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("backend %d was not blocked by backend %d", backendPID, blockerPID)
}

func readChallengeFactCounts(t *testing.T, pool *pgxpool.Pool) challengeFactCounts {
	t.Helper()
	var counts challengeFactCounts
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM challenge_policies),
		(SELECT count(*) FROM challenge_policy_revisions),
		(SELECT count(*) FROM challenge_policy_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'challenge_policy.%')`).Scan(
		&counts.policies, &counts.revisions, &counts.writes, &counts.audits); err != nil {
		t.Fatal(err)
	}
	return counts
}

func assertChallengeFactCounts(t *testing.T, pool *pgxpool.Pool, expected challengeFactCounts) {
	t.Helper()
	if actual := readChallengeFactCounts(t, pool); actual != expected {
		t.Fatalf("challenge facts changed: got=%+v want=%+v", actual, expected)
	}
}
