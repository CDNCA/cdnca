package challengepolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type challengeRuntimeFixture struct {
	base          *testFixture
	pool          *pgxpool.Pool
	appName       string
	mutationApp   string
	token         string
	platformToken string
	identity      *identity.Service
	identityStore *identity.Store
	identityAdmin identity.Actor
	sessionHash   []byte
}

func TestChallengePolicyRuntimeCurrentHeadBearerCRUD(t *testing.T) {
	fixture := newChallengeRuntimeFixture(t)
	assertChallengeRuntimeCurrentHead(t, fixture.base.pool)

	payload := createPayload(fixture.base.siteA, "a.example.test", validConfig(ModeClick), true)
	created := fixture.base.request(t, fixture.token, http.MethodPost,
		collectionPath(fixture.base.tenantA), payload, "runtime-create", "")
	assertHTTPError(t, created, http.StatusCreated, "")
	policy := decodePolicyResponse(t, created)
	if policy.Revision != 1 || policy.ID == uuid.Nil {
		t.Fatalf("runtime create policy = %#v", policy)
	}

	replay := fixture.base.request(t, fixture.token, http.MethodPost,
		collectionPath(fixture.base.tenantA), payload, "runtime-create", "")
	assertHTTPError(t, replay, http.StatusCreated, "")
	if replay.Header().Get("X-Idempotent-Replay") != "true" {
		t.Fatalf("runtime replay header = %q", replay.Header().Get("X-Idempotent-Replay"))
	}

	list := fixture.base.request(t, fixture.token, http.MethodGet,
		collectionPath(fixture.base.tenantA), nil, "", "")
	assertHTTPError(t, list, http.StatusOK, "")
	if decoded := decodePolicyList(t, list); len(decoded.Items) != 1 || decoded.Items[0].ID != policy.ID {
		t.Fatalf("runtime list = %#v", decoded)
	}

	platformList := fixture.base.request(t, fixture.platformToken, http.MethodGet,
		collectionPath(fixture.base.tenantA), nil, "", "")
	assertHTTPError(t, platformList, http.StatusOK, "")
	beforeCrossTarget := readChallengeFactCounts(t, fixture.base.pool)
	crossTarget := fixture.base.request(t, fixture.token, http.MethodGet,
		collectionPath(fixture.base.tenantB), nil, "", "")
	assertHTTPError(t, crossTarget, http.StatusNotFound, "not_found")
	assertChallengeFactCounts(t, fixture.base.pool, beforeCrossTarget)
}

func TestChallengePolicyRuntimeRevocationRechecksBeforeWrite(t *testing.T) {
	for _, test := range []struct {
		name       string
		revocation string
		wantStatus int
		wantCode   string
	}{
		{name: "session", revocation: "session", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		{name: "user_role", revocation: "user_role", wantStatus: http.StatusForbidden, wantCode: "permission_denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, replay := range []bool{false, true} {
				t.Run("replay="+strconv.FormatBool(replay), func(t *testing.T) {
					fixture := newChallengeRuntimeFixture(t)
					payload := createPayload(fixture.base.siteA, "a.example.test", validConfig(ModeClick), true)
					key := "runtime-revoke-" + test.name + "-" + strconv.FormatBool(replay)
					if replay {
						created := fixture.base.request(t, fixture.token, http.MethodPost,
							collectionPath(fixture.base.tenantA), payload, key, "")
						assertHTTPError(t, created, http.StatusCreated, "")
					}
					runChallengeRuntimeFormalRevocation(t, fixture, payload, key,
						test.revocation, test.wantStatus, test.wantCode)
				})
			}
		})
	}
}

func newChallengeRuntimeFixture(t *testing.T) *challengeRuntimeFixture {
	t.Helper()
	base := seedFixture(t, openChallengeTestPool(t))
	// The revocation LKG trigger (084) checks the set's window against the database's physical clock.
	now := time.Now().UTC().Truncate(time.Second)
	base.now = now

	config := base.pool.Config().Copy()
	appName := "challenge-runtime-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	config.ConnConfig.RuntimeParams["application_name"] = appName
	runtimePool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtimePool.Close)
	mutationConfig := base.pool.Config().Copy()
	mutationApp := "challenge-mutation-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	mutationConfig.ConnConfig.RuntimeParams["application_name"] = mutationApp
	mutationPool, err := pgxpool.NewWithConfig(context.Background(), mutationConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mutationPool.Close)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: "challenge-test-key", PublicKey: publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	installLease(t, base.pool, trust, privateKey, now, 1, true)

	tokens, err := identity.NewTokenManager("challenge-policy-runtime-integration-secret-2026", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(runtimePool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x71}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRuntimeHandler(RuntimeConfig{
		Enabled: true, CursorAudience: "control-challenge-policies", CursorKeyID: "runtime-v1",
	}, RuntimeDependencies{
		Pool: runtimePool, Identity: identityService, IAM: iam,
		EntitlementTrust: trust, Now: func() time.Time { return now },
		CursorKey: bytes.Repeat([]byte{0x55}, minCursorKeyBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	base.handler = handler
	token, _, err := tokens.Mint(base.ownerA.UserID, base.ownerA.ScopeID, base.ownerA.Credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	platformToken, _, err := tokens.Mint(base.platform.UserID, base.platform.ScopeID, base.platform.Credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(mutationPool)
	identityMutator, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var sessionHash []byte
	if err := base.pool.QueryRow(context.Background(),
		`SELECT refresh_token_hash FROM auth_sessions WHERE id=$1`, base.ownerASession).Scan(&sessionHash); err != nil {
		t.Fatal(err)
	}
	return &challengeRuntimeFixture{
		base: base, pool: runtimePool, appName: appName,
		mutationApp: mutationApp,
		token:       token, platformToken: platformToken,
		identity: identityMutator, identityStore: identityStore,
		identityAdmin: identity.Actor{
			UserID: base.platform.UserID, ScopeID: base.platform.ScopeID, ScopeKind: "platform",
		},
		sessionHash: append([]byte(nil), sessionHash...),
	}
}

func assertChallengeRuntimeCurrentHead(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var present bool
	if err := pool.QueryRow(context.Background(), `SELECT
		to_regprocedure('iam_global_lock_shared_v1()') IS NOT NULL
		AND to_regprocedure('iam_global_lock_exclusive_v1()') IS NOT NULL
		AND to_regprocedure('iam_begin_authority_mutation_v1(text,uuid[])') IS NOT NULL
		AND to_regprocedure('iam_begin_stage2b_authority_mutation_v1(text,uuid[])') IS NOT NULL`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("runtime fixture did not apply current IAM migration head 071")
	}
}

func runChallengeRuntimeFormalRevocation(
	t *testing.T,
	fixture *challengeRuntimeFixture,
	payload map[string]any,
	key string,
	revocation string,
	wantStatus int,
	wantCode string,
) {
	t.Helper()
	before := readChallengeFactCounts(t, fixture.base.pool)
	blocker, err := fixture.base.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	var mutate func() error
	var verify func()
	switch revocation {
	case "session":
		if _, err := blocker.Exec(context.Background(),
			`SELECT id FROM auth_sessions WHERE id=$1 FOR UPDATE`, fixture.base.ownerASession); err != nil {
			t.Fatal(err)
		}
		mutate = func() error {
			return fixture.identityStore.RevokeSessionFamily(
				context.Background(), fixture.sessionHash, key+"-formal-session-revoke")
		}
		verify = func() {
			var revoked bool
			if err := fixture.base.pool.QueryRow(context.Background(),
				`SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id=$1`, fixture.base.ownerASession).Scan(&revoked); err != nil {
				t.Fatal(err)
			}
			if !revoked {
				t.Fatal("formal session-family revocation did not revoke the runtime session")
			}
		}
	case "user_role":
		current, err := fixture.identity.GetUser(context.Background(), fixture.identityAdmin, fixture.base.ownerA.UserID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := blocker.Exec(context.Background(),
			`SELECT id FROM users WHERE id=$1 FOR UPDATE`, fixture.base.ownerA.UserID); err != nil {
			t.Fatal(err)
		}
		fields := identity.UserFields{DisplayName: current.DisplayName}
		if current.Email != nil {
			fields.Email = *current.Email
		}
		if current.Phone != nil {
			fields.Phone = *current.Phone
		}
		mutate = func() error {
			_, err := fixture.identity.UpdateUser(context.Background(), fixture.identityAdmin, identity.UpdateUserInput{
				ID: current.ID, ExpectedRevision: current.Revision, Fields: fields,
				Status: current.Status, Role: identity.UserRoleViewer,
				IdempotencyKey: key + "-formal-role-update", RequestID: key + "-formal-role-update",
			})
			return err
		}
		verify = func() {
			updated, err := fixture.identity.GetUser(context.Background(), fixture.identityAdmin, fixture.base.ownerA.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if updated.Role != identity.UserRoleViewer {
				t.Fatalf("formal user role = %q, want %q", updated.Role, identity.UserRoleViewer)
			}
		}
	default:
		t.Fatalf("unknown challenge runtime revocation %q", revocation)
	}

	revocationResult := make(chan error, 1)
	go func() {
		revocationResult <- mutate()
	}()
	waitForChallengeRuntimeExclusiveHolder(t, fixture.pool, fixture.mutationApp, revocationResult)

	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response <- fixture.base.request(t, fixture.token, http.MethodPost,
			collectionPath(fixture.base.tenantA), payload, key, "")
	}()
	waitForChallengeRuntimeSharedWaiter(t, fixture.pool, fixture.appName)
	if err := blocker.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-revocationResult:
		if err != nil {
			t.Fatalf("formal %s revocation: %v", revocation, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("formal identity mutation did not finish")
	}

	select {
	case denied := <-response:
		assertHTTPError(t, denied, wantStatus, wantCode)
		if strings.Contains(denied.Body.String(), "SQLSTATE") {
			t.Fatalf("runtime denial leaked SQLSTATE: %s", denied.Body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runtime request did not finish after formal revocation commit")
	}
	assertChallengeFactCounts(t, fixture.base.pool, before)
	verify()
}

func waitForChallengeRuntimeExclusiveHolder(
	t *testing.T,
	pool *pgxpool.Pool,
	mutationApp string,
	mutationResult <-chan error,
) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-mutationResult:
			t.Fatalf("formal identity mutation %q ended before holding the exclusive global lock: %v", mutationApp, err)
		default:
		}
		var held bool
		err := pool.QueryRow(context.Background(), `SELECT EXISTS(
			SELECT 1
			FROM pg_locks lock
			JOIN pg_stat_activity activity ON activity.pid=lock.pid
			WHERE lock.locktype='advisory'
			  AND lock.classid=1229016321::oid AND lock.objid=1::oid AND lock.objsubid=2
			  AND lock.mode='ExclusiveLock' AND lock.granted
			  AND activity.application_name=$1)`, mutationApp).Scan(&held)
		if err != nil {
			t.Fatal(err)
		}
		if held {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("formal identity mutation %q did not hold the exclusive global lock", mutationApp)
}

func waitForChallengeRuntimeSharedWaiter(t *testing.T, pool *pgxpool.Pool, appName string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		err := pool.QueryRow(context.Background(), `SELECT EXISTS(
			SELECT 1
			FROM pg_locks lock
			JOIN pg_stat_activity activity ON activity.pid=lock.pid
			WHERE activity.application_name=$1
			  AND lock.locktype='advisory'
			  AND lock.classid=1229016321::oid AND lock.objid=1::oid AND lock.objsubid=2
			  AND lock.mode='ShareLock' AND NOT lock.granted)`, appName).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("runtime request did not wait for the revocation global lock")
}

func decodePolicyList(t *testing.T, response *httptest.ResponseRecorder) ListResult {
	t.Helper()
	var result ListResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode policy list status=%d body=%s: %v", response.Code, response.Body, err)
	}
	return result
}
