//go:build integration

package httppolicycontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type httpPolicyPoolBarrier struct {
	inner       runtimeTxAuthorizer
	total       int
	reached     chan struct{}
	release     chan struct{}
	mu          sync.Mutex
	arrivals    int
	reachedOnce sync.Once
	releaseOnce sync.Once
}

func newHTTPPolicyPoolBarrier(total int, inner runtimeTxAuthorizer) *httpPolicyPoolBarrier {
	return &httpPolicyPoolBarrier{
		inner: inner, total: total, reached: make(chan struct{}), release: make(chan struct{}),
	}
}

func (barrier *httpPolicyPoolBarrier) AuthorizeWrite(
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
		return barrier.inner.AuthorizeWrite(ctx, tx, actor, targetScopeID, permission)
	}
}

func (barrier *httpPolicyPoolBarrier) releaseRequests() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

type httpPolicyPoolResponse struct {
	response *httptest.ResponseRecorder
	err      error
}

type httpPolicyPoolFacts struct {
	policies         int
	revisions        int
	publicationHeads int
	writes           int
	audits           int
}

func TestHTTPPolicyRuntimeIAMRejectionDoesNotStarveBoundedPool(t *testing.T) {
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
			fixture := newHTTPPolicyRuntimeFixture(t, "read committed")
			actor := fixture.proof.fixture.ownerA
			siteID := fixture.proof.fixture.siteA
			if scenario.noPermission {
				actor = fixture.proof.fixture.viewerA
				siteID = insertTestSite(t, fixture.pool, fixture.proof.fixture.tenantA,
					actor.UserID, "pool-starvation-viewer.example.test")
			}
			requestPool := newHTTPPolicyPool(t, fixture.pool, concurrentRequests)
			tokens, err := identity.NewTokenManager(strings.Repeat("http-policy-pool-starvation-", 2), time.Hour)
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
			apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x4b}, 32), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
			if err != nil {
				t.Fatal(err)
			}
			barrier := newHTTPPolicyPoolBarrier(concurrentRequests,
				runtimeTxAuthorizer{identity: identityService, iam: iam})
			defer barrier.releaseRequests()
			store, err := newStoreWithAuthorizer(requestPool, func() time.Time { return fixture.proof.now },
				fixture.proof.trust, barrier)
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
				authenticated.rawSession = unknownSession
				rawToken = authenticated.rawSession
				authenticator = AuthenticatorFunc(func(*http.Request) (Actor, error) { return authenticated, nil })
			}
			handler, err := NewHandler(NewService(store), authenticator)
			if err != nil {
				t.Fatal(err)
			}
			before := readHTTPPolicyPoolFacts(t, fixture.pool)

			requestCtx, cancelRequests := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancelRequests()
			start := make(chan struct{})
			responses := make(chan httpPolicyPoolResponse, concurrentRequests)
			payload, err := json.Marshal(createPayload(siteID, validTestConfig(), true))
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < concurrentRequests; index++ {
				go func(index int) {
					select {
					case <-requestCtx.Done():
						responses <- httpPolicyPoolResponse{err: requestCtx.Err()}
					case <-start:
						request := httptest.NewRequestWithContext(requestCtx, http.MethodPost,
							collectionPath(fixture.proof.fixture.tenantA), bytes.NewReader(payload))
						key := fmt.Sprintf("http-policy-pool-starvation-%d", index)
						request.Header.Set("Authorization", "Bearer "+rawToken)
						request.Header.Set("Content-Type", "application/json")
						request.Header.Set("Idempotency-Key", key)
						request.Header.Set("X-Request-ID", key+"-request")
						request.Header.Set("X-Trace-ID", key+"-trace")
						response := httptest.NewRecorder()
						handler.ServeHTTP(response, request)
						responses <- httpPolicyPoolResponse{response: response}
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
					requestCtx, refreshHash, "http-policy-pool-starvation-revoke"); err != nil {
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
			assertHTTPPolicyPoolFacts(t, fixture.pool, before)
		})
	}
}

func newHTTPPolicyPool(t *testing.T, source *pgxpool.Pool, maxConns int32) *pgxpool.Pool {
	t.Helper()
	config := source.Config().Copy()
	config.MaxConns = maxConns
	config.ConnConfig.RuntimeParams["application_name"] = "http_policy_pool_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func readHTTPPolicyPoolFacts(t *testing.T, pool *pgxpool.Pool) httpPolicyPoolFacts {
	t.Helper()
	var facts httpPolicyPoolFacts
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM http_policies),
		(SELECT count(*) FROM http_policy_revisions),
		(SELECT count(*) FROM http_policy_publication_heads),
		(SELECT count(*) FROM http_policy_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'http_policy.%')`).Scan(
		&facts.policies, &facts.revisions, &facts.publicationHeads, &facts.writes, &facts.audits); err != nil {
		t.Fatal(err)
	}
	return facts
}

func assertHTTPPolicyPoolFacts(t *testing.T, pool *pgxpool.Pool, expected httpPolicyPoolFacts) {
	t.Helper()
	if actual := readHTTPPolicyPoolFacts(t, pool); actual != expected {
		t.Fatalf("HTTP policy side effects changed: got=%+v want=%+v", actual, expected)
	}
}
