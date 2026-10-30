package originauthcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type runtimePGFixture struct {
	integrationFixture
	handler       http.Handler
	dependencies  RuntimeDependencies
	ownerToken    string
	viewerToken   string
	platformToken string
	revokedToken  string
	ownerRoleID   uuid.UUID
	roleManagerID uuid.UUID
}

type originWriteCounts struct {
	credentials  int
	rules        int
	publications int
	writes       int
	audits       int
}

type runtimeAuthorizationBarrier struct {
	inner       runtimeTxAuthorizer
	arrived     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func (barrier *runtimeAuthorizationBarrier) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) error {
	select {
	case barrier.arrived <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-barrier.release:
		return barrier.inner.Authorize(ctx, tx, actor, targetScopeID, permission)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (barrier *runtimeAuthorizationBarrier) releaseRequests() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

type runtimeAuthorizationResult struct {
	response *httptest.ResponseRecorder
}

func TestRuntimeHandlerPostgreSQLSmoke(t *testing.T) {
	fixture := newRuntimePGFixture(t)
	base := "/v1/tenant-scopes/" + fixture.tenantScopeID.String() + "/origin-auth"
	credentialPath := base + "/credentials"

	beforeDenied := readOriginWriteCounts(t, fixture)
	deniedBody := createCredentialBody{Provider: ProviderS3, Name: "denied", Secret: credentialSecret("denied")}
	assertRuntimeStatus(t, runtimeServe(fixture.handler, http.MethodPost, credentialPath, deniedBody,
		"definitely-not-a-token", "unknown-session", ""), http.StatusUnauthorized)
	assertRuntimeStatus(t, runtimeServe(fixture.handler, http.MethodPost, credentialPath, deniedBody,
		fixture.revokedToken, "revoked-session", ""), http.StatusUnauthorized)
	assertRuntimeStatus(t, runtimeServe(fixture.handler, http.MethodPost, credentialPath,
		deniedBody, fixture.viewerToken, "viewer-denied", ""), http.StatusForbidden)
	assertRuntimeStatus(t, runtimeServe(fixture.handler, http.MethodGet,
		"/v1/tenant-scopes/"+fixture.otherScopeID.String()+"/origin-auth/credentials", nil,
		fixture.ownerToken, "", ""), http.StatusNotFound)
	assertRuntimeStatus(t, runtimeServe(fixture.handler, http.MethodPost, credentialPath,
		createCredentialBody{Provider: ProviderS3, Name: "invalid", Secret: CredentialSecret{}},
		fixture.ownerToken, "invalid-credential", ""), http.StatusUnprocessableEntity)
	assertOriginWriteCounts(t, fixture, beforeDenied)

	platformList := runtimeServe(fixture.handler, http.MethodGet, credentialPath, nil,
		fixture.platformToken, "", "")
	assertRuntimeStatus(t, platformList, http.StatusOK)

	disposableBody := createCredentialBody{
		Provider: ProviderS3, Name: "runtime-disposable", Secret: credentialSecret("runtime-disposable"),
	}
	createdResponse := runtimeServe(fixture.handler, http.MethodPost, credentialPath, disposableBody,
		fixture.ownerToken, "runtime-disposable-create", "")
	assertRuntimeStatus(t, createdResponse, http.StatusCreated)
	disposable := decodeRuntimeResponse[Credential](t, createdResponse)
	replayResponse := runtimeServe(fixture.handler, http.MethodPost, credentialPath, disposableBody,
		fixture.ownerToken, "runtime-disposable-create", "")
	assertRuntimeStatus(t, replayResponse, http.StatusCreated)
	if replayResponse.Header().Get("X-Idempotent-Replay") != "true" ||
		decodeRuntimeResponse[Credential](t, replayResponse).ID != disposable.ID {
		t.Fatal("credential create replay was not stable")
	}
	listResponse := runtimeServe(fixture.handler, http.MethodGet, credentialPath, nil,
		fixture.ownerToken, "", "")
	assertRuntimeStatus(t, listResponse, http.StatusOK)
	assertRuntimeResponseRedacted(t, listResponse.Body.String())

	replaceResponse := runtimeServe(fixture.handler, http.MethodPost,
		credentialPath+"/"+disposable.ID.String()+"/replace",
		replaceCredentialBody{Secret: credentialSecret("runtime-replacement")}, fixture.ownerToken,
		"runtime-disposable-replace", quoteRevision(disposable.Revision))
	assertRuntimeStatus(t, replaceResponse, http.StatusOK)
	disposable = decodeRuntimeResponse[Credential](t, replaceResponse)
	disableResponse := runtimeServe(fixture.handler, http.MethodPost,
		credentialPath+"/"+disposable.ID.String()+"/disable", struct{}{}, fixture.ownerToken,
		"runtime-disposable-disable", quoteRevision(disposable.Revision))
	assertRuntimeStatus(t, disableResponse, http.StatusOK)
	disposable = decodeRuntimeResponse[Credential](t, disableResponse)
	deleteResponse := runtimeServe(fixture.handler, http.MethodDelete,
		credentialPath+"/"+disposable.ID.String(), struct{}{}, fixture.ownerToken,
		"runtime-disposable-delete", quoteRevision(disposable.Revision))
	assertRuntimeStatus(t, deleteResponse, http.StatusOK)

	current := createVerifiedRuntimeCredential(t, fixture, "runtime-current")
	next := createVerifiedRuntimeCredential(t, fixture, "runtime-next")
	rulePath := base + "/rules"
	ruleConfig := s3RuleConfig(current.ID, current.Revision)
	createRule := createRuleBody{
		SiteID: fixture.siteA.String(), SourcePosition: 1, Config: ruleConfig, Enabled: true,
	}
	beforeRuleDenied := readOriginWriteCounts(t, fixture)
	assertRuntimeStatus(t, runtimeServe(fixture.handler, http.MethodPost, rulePath, createRule,
		fixture.viewerToken, "runtime-rule-denied", ""), http.StatusForbidden)
	invalidRule := createRule
	invalidRule.SourcePosition = 0
	assertRuntimeStatus(t, runtimeServe(fixture.handler, http.MethodPost, rulePath, invalidRule,
		fixture.ownerToken, "runtime-rule-invalid", ""), http.StatusBadRequest)
	assertOriginWriteCounts(t, fixture, beforeRuleDenied)

	createRuleResponse := runtimeServe(fixture.handler, http.MethodPost, rulePath, createRule,
		fixture.ownerToken, "runtime-rule-create", "")
	assertRuntimeStatus(t, createRuleResponse, http.StatusCreated)
	rule := decodeRuntimeResponse[Rule](t, createRuleResponse)
	ruleReplay := runtimeServe(fixture.handler, http.MethodPost, rulePath, createRule,
		fixture.ownerToken, "runtime-rule-create", "")
	assertRuntimeStatus(t, ruleReplay, http.StatusCreated)
	if ruleReplay.Header().Get("X-Idempotent-Replay") != "true" ||
		decodeRuntimeResponse[Rule](t, ruleReplay).ID != rule.ID {
		t.Fatal("rule create replay was not stable")
	}

	rule.SignatureTTLSeconds = 301
	updateResponse := runtimeServe(fixture.handler, http.MethodPatch, rulePath+"/"+rule.ID.String(),
		updateRuleBody{Config: rule.RuleConfig}, fixture.ownerToken, "runtime-rule-update", quoteRevision(rule.Revision))
	assertRuntimeStatus(t, updateResponse, http.StatusOK)
	rule = decodeRuntimeResponse[Rule](t, updateResponse)
	disableRuleResponse := runtimeServe(fixture.handler, http.MethodPost,
		rulePath+"/"+rule.ID.String()+"/disable", struct{}{}, fixture.ownerToken,
		"runtime-rule-disable", quoteRevision(rule.Revision))
	assertRuntimeStatus(t, disableRuleResponse, http.StatusOK)
	rule = decodeRuntimeResponse[Rule](t, disableRuleResponse)
	enableRuleResponse := runtimeServe(fixture.handler, http.MethodPost,
		rulePath+"/"+rule.ID.String()+"/enable", struct{}{}, fixture.ownerToken,
		"runtime-rule-enable", quoteRevision(rule.Revision))
	assertRuntimeStatus(t, enableRuleResponse, http.StatusOK)
	rule = decodeRuntimeResponse[Rule](t, enableRuleResponse)
	rotateResponse := runtimeServe(fixture.handler, http.MethodPost,
		rulePath+"/"+rule.ID.String()+"/rotate", rotateRuleBody{
			CurrentCredential: CredentialReference{CredentialID: next.ID, Revision: next.Revision},
			ActivateCurrentAt: originAuthTestNow.Add(time.Hour),
		}, fixture.ownerToken, "runtime-rule-rotate", quoteRevision(rule.Revision))
	assertRuntimeStatus(t, rotateResponse, http.StatusOK)
	rule = decodeRuntimeResponse[Rule](t, rotateResponse)

	publicationPath := base + "/publications"
	publicationResponse := runtimeServe(fixture.handler, http.MethodPost, publicationPath, struct{}{},
		fixture.ownerToken, "runtime-publication-create", quoteRevision(0))
	assertRuntimeStatus(t, publicationResponse, http.StatusCreated)
	publication := decodeRuntimeResponse[Publication](t, publicationResponse)
	if len(publication.Snapshot.Rules) != 1 {
		t.Fatalf("publication rule count = %d", len(publication.Snapshot.Rules))
	}
	latestResponse := runtimeServe(fixture.handler, http.MethodGet, publicationPath, nil,
		fixture.ownerToken, "", "")
	assertRuntimeStatus(t, latestResponse, http.StatusOK)
	if decodeRuntimeResponse[Publication](t, latestResponse).SnapshotHash != publication.SnapshotHash {
		t.Fatal("latest publication hash changed")
	}
	deleteRuleResponse := runtimeServe(fixture.handler, http.MethodDelete,
		rulePath+"/"+rule.ID.String(), struct{}{}, fixture.ownerToken,
		"runtime-rule-delete", quoteRevision(rule.Revision))
	assertRuntimeStatus(t, deleteRuleResponse, http.StatusOK)

	assertRuntimePermissionRevokedBetweenAuthenticationAndTransaction(t, fixture, disposableBody)
	assertRuntimeFailureRecovery(t, fixture)
	assertRuntimeStoredDataRedacted(t, fixture)
}

func TestRuntimeIAMRejectionDoesNotStarveBoundedPool(t *testing.T) {
	const concurrentRequests = 4
	tests := []struct {
		name              string
		invalidCredential bool
		revokeSession     bool
		wantStatus        int
		wantCode          string
	}{
		{name: "invalid credential", invalidCredential: true,
			wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		{name: "valid without permission",
			wantStatus: http.StatusForbidden, wantCode: "permission_denied"},
		{name: "formally revoked session", revokeSession: true,
			wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := newRuntimeOriginAuthFixture(t)
			requestPool := newRuntimeBoundedPool(t, base.pool, concurrentRequests)
			tokens, err := identity.NewTokenManager("origin-auth-runtime-pool-starvation-secret", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			identityService, err := identity.NewService(identity.NewStore(requestPool), tokens, 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x52}, 32), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
			if err != nil {
				t.Fatal(err)
			}

			actor := base.viewer
			if test.revokeSession {
				actor = base.owner
			}
			rawToken := mintRuntimeSession(t, base, tokens, actor)
			var authenticator Authenticator = runtimeAuthenticator{identity: identityService}
			if test.invalidCredential {
				request := httptest.NewRequest(http.MethodGet, "http://control.test", nil)
				request.Header.Set("Authorization", "Bearer "+rawToken)
				authenticated, err := (runtimeAuthenticator{identity: identityService}).Authenticate(request)
				if err != nil {
					t.Fatal(err)
				}
				authenticated.rawSession = "definitely-not-a-session"
				rawToken = authenticated.rawSession
				authenticator = AuthenticatorFunc(func(*http.Request) (Actor, error) {
					return authenticated, nil
				})
			}

			barrier := &runtimeAuthorizationBarrier{
				inner:   runtimeTxAuthorizer{identity: identityService, iam: iam},
				arrived: make(chan struct{}, concurrentRequests), release: make(chan struct{}),
			}
			defer barrier.releaseRequests()
			config := Config{
				Clock:       func() time.Time { return originAuthTestNow },
				Verifier:    CredentialVerifierFunc(func(context.Context, VerificationRequest) error { return nil }),
				Entitlement: allowEntitlement{},
			}
			service, err := newService(requestPool, testKeyring(t, "new"), config, barrier)
			if err != nil {
				t.Fatal(err)
			}
			inner, err := NewHandler(service, authenticator, HandlerConfig{})
			if err != nil {
				t.Fatal(err)
			}
			handler := runtimeMetadataHandler{inner: inner}
			factsFixture := runtimePGFixture{integrationFixture: base}
			path := "/v1/tenant-scopes/" + base.tenantScopeID.String() + "/origin-auth/credentials"

			requestCtx, cancelRequests := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancelRequests()
			start := make(chan struct{})
			results := make(chan runtimeAuthorizationResult, concurrentRequests)
			for index := 0; index < concurrentRequests; index++ {
				go func() {
					<-start
					results <- runtimeAuthorizationResult{response: runtimeServeWithContext(
						requestCtx, handler, http.MethodPost, path,
						createCredentialBody{Provider: ProviderS3, Name: "pool-starvation", Secret: credentialSecret("pool-starvation")},
						rawToken, "pool-starvation-"+uuid.NewString())}
				}()
			}
			close(start)
			for index := 0; index < concurrentRequests; index++ {
				select {
				case <-barrier.arrived:
				case <-requestCtx.Done():
					t.Fatalf("requests did not hold %d business transactions: %v", concurrentRequests, requestCtx.Err())
				}
			}
			if acquired := requestPool.Stat().AcquiredConns(); acquired != concurrentRequests {
				t.Fatalf("acquired business connections=%d want=%d", acquired, concurrentRequests)
			}

			if test.revokeSession {
				_, _, sessionID, err := tokens.Parse(rawToken)
				if err != nil {
					t.Fatal(err)
				}
				var refreshHash []byte
				if err := base.pool.QueryRow(requestCtx,
					`SELECT refresh_token_hash FROM auth_sessions WHERE id=$1`, sessionID).Scan(&refreshHash); err != nil {
					t.Fatal(err)
				}
				if err := identity.NewStore(base.pool).RevokeSessionFamily(
					requestCtx, refreshHash, "origin-auth-pool-starvation-revoke"); err != nil {
					t.Fatal(err)
				}
			}
			before := readOriginWriteCounts(t, factsFixture)
			barrier.releaseRequests()

			for index := 0; index < concurrentRequests; index++ {
				select {
				case result := <-results:
					assertRuntimeAuthorizationError(t, result.response, test.wantStatus, test.wantCode)
				case <-requestCtx.Done():
					t.Fatalf("request %d exceeded bounded completion deadline: %v", index, requestCtx.Err())
				}
			}
			if acquired := requestPool.Stat().AcquiredConns(); acquired != 0 {
				t.Fatalf("acquired connections after rejection=%d want=0", acquired)
			}
			assertOriginWriteCounts(t, factsFixture, before)
		})
	}
}

func createVerifiedRuntimeCredential(t *testing.T, fixture runtimePGFixture, name string) Credential {
	t.Helper()
	path := "/v1/tenant-scopes/" + fixture.tenantScopeID.String() + "/origin-auth/credentials"
	response := runtimeServe(fixture.handler, http.MethodPost, path,
		createCredentialBody{Provider: ProviderS3, Name: name, Secret: credentialSecret(name)},
		fixture.ownerToken, name+"-create", "")
	assertRuntimeStatus(t, response, http.StatusCreated)
	credential := decodeRuntimeResponse[Credential](t, response)
	response = runtimeServe(fixture.handler, http.MethodPost,
		path+"/"+credential.ID.String()+"/verify", struct{}{}, fixture.ownerToken,
		name+"-verify", quoteRevision(credential.Revision))
	assertRuntimeStatus(t, response, http.StatusOK)
	return decodeRuntimeResponse[Credential](t, response)
}

func assertRuntimePermissionRevokedBetweenAuthenticationAndTransaction(
	t *testing.T,
	fixture runtimePGFixture,
	body createCredentialBody,
) {
	t.Helper()
	before := readOriginWriteCounts(t, fixture)
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := protocol.BeginAuthorityMutation(t.Context(), tx,
		protocol.OperationCustomRolePublish, []uuid.UUID{fixture.tenantScopeID}); err != nil {
		t.Fatal(err)
	}

	path := "/v1/tenant-scopes/" + fixture.tenantScopeID.String() + "/origin-auth/credentials"
	responseChannel := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responseChannel <- runtimeServe(fixture.handler, http.MethodPost, path, body,
			fixture.ownerToken, "runtime-permission-race", "")
	}()
	waitForRuntimeSharedIAMWaiter(t, fixture)
	if err := publishRuntimeRolePermissions(t.Context(), tx, fixture, []string{PermissionRead}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	response := <-responseChannel
	assertRuntimeStatus(t, response, http.StatusForbidden)
	assertOriginWriteCounts(t, fixture, before)

	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(restore pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(t.Context(), restore,
			protocol.OperationCustomRolePublish, []uuid.UUID{fixture.tenantScopeID}); err != nil {
			return err
		}
		return publishRuntimeRolePermissions(t.Context(), restore, fixture,
			[]string{PermissionManage, PermissionRead})
	}); err != nil {
		t.Fatal(err)
	}
}

func assertRuntimeFailureRecovery(t *testing.T, fixture runtimePGFixture) {
	t.Helper()
	dependencies := fixture.dependencies
	dependencies.Service.Auditor = failingAuditAdapter{}
	failing, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/tenant-scopes/" + fixture.tenantScopeID.String() + "/origin-auth/credentials"
	body := createCredentialBody{
		Provider: ProviderS3, Name: "runtime-recovery", Secret: credentialSecret("runtime-recovery"),
	}
	before := readOriginWriteCounts(t, fixture)
	response := runtimeServe(failing, http.MethodPost, path, body,
		fixture.ownerToken, "runtime-recovery", "")
	assertRuntimeStatus(t, response, http.StatusServiceUnavailable)
	for _, leaked := range []string{"SQLSTATE", "injected audit failure", "origin_auth_write_requests"} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("runtime failure leaked %q: %s", leaked, response.Body)
		}
	}
	assertOriginWriteCounts(t, fixture, before)
	response = runtimeServe(fixture.handler, http.MethodPost, path, body,
		fixture.ownerToken, "runtime-recovery", "")
	assertRuntimeStatus(t, response, http.StatusCreated)
}

func waitForRuntimeSharedIAMWaiter(t *testing.T, fixture runtimePGFixture) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_catalog.pg_locks
			WHERE locktype='advisory' AND classid=1229016321::oid AND objid=1::oid
			  AND objsubid=2 AND mode='ShareLock' AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("runtime authorization did not wait for the IAM global lock")
}

func newRuntimePGFixture(t *testing.T) runtimePGFixture {
	t.Helper()
	base := newRuntimeOriginAuthFixture(t)
	roleManagerID := uuid.New()
	var systemOwnerRoleID uuid.UUID
	if err := pgx.BeginFunc(t.Context(), base.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(), `SELECT id FROM roles
			WHERE scope_id=$1 AND name='tenant_owner' AND system_role`, base.tenantScopeID).
			Scan(&systemOwnerRoleID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,'origin auth role manager','hash')`, roleManagerID,
			"origin-auth-role-manager-"+strings.ReplaceAll(roleManagerID.String(), "-", "")); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
			base.tenantScopeID, roleManagerID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, base.tenantScopeID, roleManagerID, systemOwnerRoleID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ownerRoleID := createRuntimeOwnerCustomRole(t, base, roleManagerID, systemOwnerRoleID)
	assertRuntimeRoleGuards(t, base, ownerRoleID, systemOwnerRoleID)
	tokens, err := identity.NewTokenManager("origin-auth-runtime-integration-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(base.pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x51}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := RuntimeDependencies{
		Pool: base.pool, Identity: identityService, IAM: authorizer, Keyring: testKeyring(t, "new"),
		Service: Config{
			Clock:          func() time.Time { return originAuthTestNow },
			Verifier:       CredentialVerifierFunc(func(context.Context, VerificationRequest) error { return nil }),
			Entitlement:    allowEntitlement{},
			EgressPolicies: map[string][]string{"minio-prod": {"objects.example.test"}},
		},
	}
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	fixture := runtimePGFixture{
		integrationFixture: base,
		handler:            handler,
		dependencies:       dependencies,
		ownerRoleID:        ownerRoleID,
		roleManagerID:      roleManagerID,
	}
	fixture.ownerToken = mintRuntimeSession(t, base, tokens, base.owner)
	fixture.viewerToken = mintRuntimeSession(t, base, tokens, base.viewer)
	fixture.platformToken = mintRuntimeSession(t, base, tokens, base.platform)
	revoked := mintRuntimeSession(t, base, tokens, base.owner)
	fixture.revokedToken = revoked
	_, _, revokedSessionID, err := tokens.Parse(revoked)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), base.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(t.Context(), tx,
			protocol.OperationSessionRevoke, []uuid.UUID{base.owner.ScopeID}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test'
			WHERE id=$1`, revokedSessionID, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func createRuntimeOwnerCustomRole(
	t *testing.T,
	base integrationFixture,
	roleManagerID uuid.UUID,
	systemOwnerRoleID uuid.UUID,
) uuid.UUID {
	t.Helper()
	roleID := uuid.New()
	now := time.Now().UTC()
	if err := pgx.BeginFunc(t.Context(), base.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(t.Context(), tx,
			protocol.OperationCustomRolePublish, []uuid.UUID{base.tenantScopeID}); err != nil {
			return err
		}
		name := "origin_auth_runtime_owner_" + strings.ReplaceAll(roleID.String(), "-", "")
		if _, err := tx.Exec(t.Context(), `INSERT INTO custom_roles(
			id,tenant_id,tenant_scope_id,current_revision,current_name,created_by_user_id,
			created_by_scope_id,created_at,updated_at
		) VALUES($1,$2,$3,0,$4,$5,$3,$6,$6)`, roleID, base.tenantID,
			base.tenantScopeID, name, base.owner.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO custom_role_revisions(
			role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
			created_by_user_id,created_by_scope_id,step_up_proof_id,step_up_method,
			step_up_verified_at,created_at
		) VALUES($1,$2,$3,1,$4,$5,'identity.custom_role.create',$6,$3,$7,'totp',$8,$8)`,
			roleID, base.tenantID, base.tenantScopeID, name,
			[]string{PermissionManage, PermissionRead}, base.owner.UserID, uuid.New(), now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE custom_roles SET current_revision=1,updated_at=$2
			WHERE id=$1 AND current_revision=0`, roleID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO custom_role_grants(
			id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
			granted_by_user_id,granted_by_scope_id,step_up_proof_id,step_up_method,
			step_up_verified_at,granted_at
		) VALUES($1,$2,$3,$4,1,$5,$6,$3,$7,'totp',$8,$8)`, uuid.New(), base.tenantID,
			base.tenantScopeID, roleID, base.owner.UserID, roleManagerID, uuid.New(), now); err != nil {
			return err
		}
		command, err := tx.Exec(t.Context(), `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, base.tenantScopeID,
			base.owner.UserID, systemOwnerRoleID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return fmt.Errorf("switch runtime owner assignment rows=%d", command.RowsAffected())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return roleID
}

func assertRuntimeRoleGuards(
	t *testing.T,
	base integrationFixture,
	customRoleID uuid.UUID,
	systemOwnerRoleID uuid.UUID,
) {
	t.Helper()
	var systemRole bool
	if err := base.pool.QueryRow(t.Context(), `SELECT system_role FROM roles WHERE id=$1`, customRoleID).
		Scan(&systemRole); err != nil {
		t.Fatal(err)
	}
	if systemRole {
		t.Fatal("runtime owner role was projected as a system role")
	}

	tx, err := base.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.BeginAuthorityMutation(t.Context(), tx,
		protocol.OperationCustomRolePublish, []uuid.UUID{base.tenantScopeID}); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	_, mutationErr := tx.Exec(t.Context(), `DELETE FROM role_permissions
		WHERE role_id=$1 AND permission_name=$2`, systemOwnerRoleID, PermissionManage)
	_ = tx.Rollback(t.Context())
	if mutationErr == nil || !strings.Contains(mutationErr.Error(), "system role permissions are immutable") {
		t.Fatalf("system role permission mutation error = %v", mutationErr)
	}
	var systemPermissionPresent bool
	if err := base.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM role_permissions
		WHERE role_id=$1 AND permission_name=$2)`, systemOwnerRoleID, PermissionManage).
		Scan(&systemPermissionPresent); err != nil {
		t.Fatal(err)
	}
	if !systemPermissionPresent {
		t.Fatal("system owner permission changed after rejected mutation")
	}
}

func publishRuntimeRolePermissions(
	ctx context.Context,
	tx pgx.Tx,
	fixture runtimePGFixture,
	permissions []string,
) error {
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT current_revision FROM custom_roles
		WHERE id=$1 AND tenant_scope_id=$2 FOR UPDATE`, fixture.ownerRoleID, fixture.tenantScopeID).
		Scan(&currentRevision); err != nil {
		return err
	}
	nextRevision := currentRevision + 1
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,step_up_proof_id,step_up_method,
		step_up_verified_at,created_at
	) SELECT id,tenant_id,tenant_scope_id,$2,current_name,$3,'identity.custom_role.publish',
		$4,tenant_scope_id,$5,'totp',$6,$6 FROM custom_roles
		WHERE id=$1 AND current_revision=$7`, fixture.ownerRoleID, nextRevision, permissions,
		fixture.roleManagerID, uuid.New(), now, currentRevision); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE custom_roles SET current_revision=$2,updated_at=$3
		WHERE id=$1 AND current_revision=$4`, fixture.ownerRoleID, nextRevision, now, currentRevision)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("publish runtime owner role rows=%d", command.RowsAffected())
	}
	return nil
}

// newRuntimeOriginAuthFixture seeds the origin auth fixture on a schema migrated to the
// release head: the runtime handler goes through identity (users.display_id, 209), the
// IAM global lock protocol (069/070) and custom roles, which a 055-only schema lacks.
func newRuntimeOriginAuthFixture(t *testing.T) integrationFixture {
	t.Helper()
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		pool = isolatedOriginAuthPool(t, func(ctx context.Context, pool *pgxpool.Pool) error {
			return database.Migrate(ctx, pool, "up")
		})
	}
	return seedOriginAuthFixture(t, pool)
}

func mintRuntimeSession(
	t *testing.T,
	fixture integrationFixture,
	tokens *identity.TokenManager,
	actor Actor,
) string {
	t.Helper()
	now := time.Now().UTC()
	sessionID, familyID := uuid.New(), uuid.New()
	refresh := sha256.Sum256([]byte(sessionID.String()))
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, familyID, actor.UserID, actor.ScopeID,
		refresh[:], now.Add(-time.Minute), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	raw, _, err := tokens.Mint(actor.UserID, actor.ScopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runtimeServe(
	handler http.Handler,
	method, path string,
	body any,
	token, idempotencyKey, revision string,
) *httptest.ResponseRecorder {
	var payload *bytes.Reader
	if body == nil {
		payload = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			response := httptest.NewRecorder()
			response.WriteHeader(http.StatusInternalServerError)
			return response
		}
		payload = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, payload)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
		request.Header.Set("X-Request-ID", "req-"+idempotencyKey)
		request.Header.Set("X-Trace-ID", "trace-"+idempotencyKey)
	}
	if revision != "" {
		request.Header.Set("If-Match", revision)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func runtimeServeWithContext(
	ctx context.Context,
	handler http.Handler,
	method, path string,
	body any,
	token, idempotencyKey string,
) *httptest.ResponseRecorder {
	encoded, _ := json.Marshal(body)
	request := httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("X-Request-ID", "req-"+idempotencyKey)
	request.Header.Set("X-Trace-ID", "trace-"+idempotencyKey)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertRuntimeAuthorizationError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()
	assertRuntimeStatus(t, response, status)
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code {
		t.Fatalf("runtime error code=%q want=%q body=%s", envelope.Error.Code, code, response.Body)
	}
}

func newRuntimeBoundedPool(t *testing.T, source *pgxpool.Pool, maxConns int32) *pgxpool.Pool {
	t.Helper()
	config := source.Config().Copy()
	config.ConnConfig.RuntimeParams["application_name"] = "origin_auth_pool_starvation_" + uuid.NewString()
	config.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func decodeRuntimeResponse[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode response %d: %v: %s", response.Code, err, response.Body)
	}
	return value
}

func assertRuntimeStatus(t *testing.T, response *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if response.Code != expected {
		t.Fatalf("runtime response = %d, want %d: %s", response.Code, expected, response.Body)
	}
	if response.Header().Get("X-Request-ID") == "" || response.Header().Get("X-Trace-ID") == "" {
		t.Fatalf("runtime response lacks correlation metadata: %v", response.Header())
	}
}

func readOriginWriteCounts(t *testing.T, fixture runtimePGFixture) originWriteCounts {
	t.Helper()
	var counts originWriteCounts
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM origin_auth_credentials),
			(SELECT count(*) FROM origin_auth_rules),
			(SELECT count(*) FROM origin_auth_publications),
			(SELECT count(*) FROM origin_auth_write_requests),
			(SELECT count(*) FROM audit_events)`).Scan(
		&counts.credentials, &counts.rules, &counts.publications, &counts.writes, &counts.audits); err != nil {
		t.Fatal(err)
	}
	return counts
}

func assertOriginWriteCounts(t *testing.T, fixture runtimePGFixture, expected originWriteCounts) {
	t.Helper()
	if actual := readOriginWriteCounts(t, fixture); actual != expected {
		t.Fatalf("origin write counts = %+v, want %+v", actual, expected)
	}
}

func assertRuntimeResponseRedacted(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{"AK-", "SK-", "session-", "ciphertext", "envelope_key_id"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("runtime response leaked %q: %s", forbidden, body)
		}
	}
}

func assertRuntimeStoredDataRedacted(t *testing.T, fixture runtimePGFixture) {
	t.Helper()
	var auditText string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(payload::text, E'\n'), '')
		FROM audit_events WHERE action LIKE 'origin_auth.%'`).Scan(&auditText); err != nil {
		t.Fatal(err)
	}
	assertRuntimeResponseRedacted(t, auditText)
	var publicationText string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(
		convert_from(canonical_snapshot,'UTF8'), E'\n'), '') FROM origin_auth_publications`).Scan(&publicationText); err != nil {
		t.Fatal(err)
	}
	assertRuntimeResponseRedacted(t, publicationText)
	if strings.Contains(auditText+publicationText, "secret_access_key") {
		t.Fatalf("stored public facts leaked credential fields: %s", auditText+publicationText)
	}
}
