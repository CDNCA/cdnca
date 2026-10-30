//go:build integration

package challengepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type challengePoolBarrier struct {
	inner       runtimeTxAuthorizer
	total       int
	reached     chan struct{}
	release     chan struct{}
	mu          sync.Mutex
	arrivals    int
	reachedOnce sync.Once
	releaseOnce sync.Once
}

func newChallengePoolBarrier(total int, inner runtimeTxAuthorizer) *challengePoolBarrier {
	return &challengePoolBarrier{
		inner: inner, total: total, reached: make(chan struct{}), release: make(chan struct{}),
	}
}

func (barrier *challengePoolBarrier) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	barrier.mu.Lock()
	barrier.arrivals++
	if barrier.arrivals == barrier.total {
		barrier.reachedOnce.Do(func() { close(barrier.reached) })
	}
	barrier.mu.Unlock()
	select {
	case <-ctx.Done():
		return uuid.Nil, ctx.Err()
	case <-barrier.release:
		return barrier.inner.Authorize(ctx, tx, actor, targetScopeID, permission)
	}
}

func (barrier *challengePoolBarrier) releaseRequests() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

type challengePoolResponse struct {
	response *httptest.ResponseRecorder
	err      error
}

func TestChallengePolicyRuntimeIAMRejectionDoesNotStarveBoundedPool(t *testing.T) {
	const concurrentRequests = 4
	for _, scenario := range []struct {
		name         string
		invalidToken bool
		revoke       bool
		noPermission bool
		wantStatus   int
		wantCode     string
	}{
		{name: "invalid transaction credential", invalidToken: true, wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		{name: "valid without permission", noPermission: true, wantStatus: http.StatusForbidden, wantCode: "permission_denied"},
		{name: "formally revoked session", revoke: true, wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := seedFixture(t, openChallengePoolStarvationTestPool(t))
			fixture.now = time.Date(2026, 7, 23, 2, 0, 0, 0, time.UTC)
			actor := fixture.ownerA
			if scenario.noPermission {
				actor = fixture.memberA
			}
			requestPool := newChallengePool(t, fixture.pool, concurrentRequests)
			tokens, err := identity.NewTokenManager(strings.Repeat("challenge-pool-starvation-", 2), time.Hour)
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
			apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x4c}, 32), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
			if err != nil {
				t.Fatal(err)
			}
			barrier := newChallengePoolBarrier(concurrentRequests,
				runtimeTxAuthorizer{identity: identityService, iam: iam})
			defer barrier.releaseRequests()
			store, err := newStoreWithGate(requestPool, func() time.Time { return fixture.now }, allowGate(),
				testCursorCodec(t, 0x4c), barrier)
			if err != nil {
				t.Fatal(err)
			}
			rawToken, _, err := tokens.Mint(actor.UserID, actor.ScopeID, actor.Credential.ID)
			if err != nil {
				t.Fatal(err)
			}
			var authenticator Authenticator = runtimeAuthenticator{identity: identityService}
			if scenario.invalidToken {
				request := httptest.NewRequest(http.MethodGet, "/", nil)
				request.Header.Set("Authorization", "Bearer "+rawToken)
				authenticated, err := (runtimeAuthenticator{identity: identityService}).Authenticate(request)
				if err != nil {
					t.Fatal(err)
				}
				unknownSession, _, err := tokens.Mint(actor.UserID, actor.ScopeID, uuid.New())
				if err != nil {
					t.Fatal(err)
				}
				authenticated.rawCredential = unknownSession
				rawToken = authenticated.rawCredential
				authenticator = AuthenticatorFunc(func(*http.Request) (Actor, error) { return authenticated, nil })
			}
			handler, err := NewHandler(NewService(store), authenticator)
			if err != nil {
				t.Fatal(err)
			}
			before := readChallengeFactCounts(t, fixture.pool)

			requestCtx, cancelRequests := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancelRequests()
			start := make(chan struct{})
			responses := make(chan challengePoolResponse, concurrentRequests)
			payload, err := json.Marshal(createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true))
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < concurrentRequests; index++ {
				go func(index int) {
					select {
					case <-requestCtx.Done():
						responses <- challengePoolResponse{err: requestCtx.Err()}
					case <-start:
						request := httptest.NewRequestWithContext(requestCtx, http.MethodPost,
							collectionPath(fixture.tenantA), bytes.NewReader(payload))
						key := fmt.Sprintf("challenge-pool-starvation-%d", index)
						request.Header.Set("Authorization", "Bearer "+rawToken)
						request.Header.Set("Content-Type", "application/json")
						request.Header.Set("Idempotency-Key", key)
						request.Header.Set("X-Request-ID", key+"-request")
						request.Header.Set("X-Trace-ID", key+"-trace")
						response := httptest.NewRecorder()
						handler.ServeHTTP(response, request)
						responses <- challengePoolResponse{response: response}
					}
				}(index)
			}
			close(start)
			select {
			case <-barrier.reached:
			case <-requestCtx.Done():
				t.Fatalf("requests did not acquire %d business transactions: %v", concurrentRequests, requestCtx.Err())
			}
			if acquired := requestPool.Stat().AcquiredConns(); acquired != concurrentRequests {
				t.Fatalf("acquired connections=%d want=%d", acquired, concurrentRequests)
			}
			if scenario.revoke {
				var refreshHash []byte
				if err := fixture.pool.QueryRow(requestCtx,
					`SELECT refresh_token_hash FROM auth_sessions WHERE id=$1`, actor.Credential.ID).Scan(&refreshHash); err != nil {
					t.Fatal(err)
				}
				if err := identity.NewStore(fixture.pool).RevokeSessionFamily(
					requestCtx, refreshHash, "challenge-pool-starvation-revoke"); err != nil {
					t.Fatal(err)
				}
			}
			barrier.releaseRequests()

			for index := 0; index < concurrentRequests; index++ {
				select {
				case result := <-responses:
					if result.err != nil {
						t.Fatal(result.err)
					}
					assertHTTPError(t, result.response, scenario.wantStatus, scenario.wantCode)
				case <-requestCtx.Done():
					t.Fatalf("request %d exceeded bounded completion deadline: %v", index, requestCtx.Err())
				}
			}
			if acquired := requestPool.Stat().AcquiredConns(); acquired != 0 {
				t.Fatalf("acquired connections after rejection=%d want=0", acquired)
			}
			assertChallengeFactCounts(t, fixture.pool, before)
		})
	}
}

func newChallengePool(t *testing.T, source *pgxpool.Pool, maxConns int32) *pgxpool.Pool {
	t.Helper()
	config := source.Config().Copy()
	config.MaxConns = maxConns
	config.ConnConfig.RuntimeParams["application_name"] = "challenge_pool_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func openChallengePoolStarvationTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "challenge_pool_starvation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err == nil {
		err = migrateChallengePoolStarvationSchema(ctx, pool)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
		adminPool.Close()
	})
	return pool
}

func migrateChallengePoolStarvationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return database.Migrate(ctx, pool, "up")
}
