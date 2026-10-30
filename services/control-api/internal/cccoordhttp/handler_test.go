package cccoordhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cccoord"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTenantStatusAndManualReleaseBindDurableState(t *testing.T) {
	tenant, site, stateID, user := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	poolConfig, err := pgxpool.ParseConfig("postgres://test:test@127.0.0.1:1/test")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	state := cccoord.State{
		ID: stateID, TenantScopeID: tenant, SiteID: site, SourcePolicyID: uuid.New(), RuleID: uuid.New(),
		ClientCIDR: "203.0.113.9/32", Host: "edge.example.test", Path: "/login", Method: "POST",
		ListenerPort: 443, Protocol: "https", RequestClass: cccoord.RequestClassStandard,
		Generation: 7, State: cccoord.StateBlocked, ReasonCode: cccoord.ReasonThresholdReached,
		HitCount: 22, NodeCount: 2, CurrentPolicyVersion: 8, LKGPolicyVersion: 7,
		ExpiresAt: time.Now().Add(time.Hour), ReleaseHoldTill: time.Now().Add(time.Hour), UpdatedAt: time.Now(),
	}
	store := &storeStub{state: state}
	authenticated := principal{userID: user, scopeID: tenant, tenantID: uuid.New(), scopeKind: "tenant", credentialKind: "session"}
	var permission string
	handler, err := newHandler(store, pool, func(*http.Request) (principal, error) {
		return authenticated, nil
	}, func(_ context.Context, got principal, target uuid.UUID, required string) (securitypolicy.Actor, error) {
		if got.userID != user || target != tenant {
			t.Fatalf("authorization scope = (%+v, %s)", got, target)
		}
		permission = required
		return securitypolicy.Actor{UserID: user, ScopeID: tenant, ScopeKind: "tenant"}, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet,
		"/v1/analytics/logs/cc-coordination?site_id="+site.String(), nil))
	if list.Code != http.StatusOK || permission != readPermission || store.listCalls != 1 || !strings.Contains(list.Body.String(), stateID.String()) {
		t.Fatalf("list response=%d permission=%s calls=%d body=%s", list.Code, permission, store.listCalls, list.Body.String())
	}

	release := httptest.NewRequest(http.MethodPost,
		"/v1/analytics/logs/cc-coordination/"+stateID.String()+"/release?site_id="+site.String(),
		strings.NewReader(`{"reason_code":"false_positive_confirmed","expected_generation":7}`))
	release.Header.Set("Authorization", "Bearer ignored-by-test-adapter")
	release.Header.Set("Idempotency-Key", "cc-release-7")
	release.Header.Set("X-Request-ID", "cc-release-request-7")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, release)
	if response.Code != http.StatusAccepted || permission != managePermission || store.releaseCalls != 1 ||
		store.release.TenantScopeID != tenant || store.release.SiteID != site || store.release.RuleID != state.RuleID ||
		store.release.ClientCIDR != state.ClientCIDR || store.release.Host != state.Host || store.release.Path != state.Path ||
		store.release.Method != state.Method || store.release.ListenerPort != state.ListenerPort ||
		store.release.Protocol != state.Protocol || store.release.ExpectedGeneration != state.Generation ||
		store.release.IdempotencyKey != "cc-release-7" || store.release.RequestID != "cc-release-request-7" {
		t.Fatalf("release response=%d permission=%s calls=%d input=%+v body=%s",
			response.Code, permission, store.releaseCalls, store.release, response.Body.String())
	}

	// Without a site the tenant lists every site of its own scope.
	allSites := httptest.NewRecorder()
	handler.ServeHTTP(allSites, httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/cc-coordination", nil))
	if allSites.Code != http.StatusOK || store.listCalls != 2 || store.lastScope != tenant || store.lastSite != uuid.Nil {
		t.Fatalf("all-sites response=%d calls=%d scope=%s site=%s", allSites.Code, store.listCalls, store.lastScope, store.lastSite)
	}
	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/cc-coordination?site_id=bad", nil))
	if invalid.Code != http.StatusBadRequest || store.listCalls != 2 {
		t.Fatalf("invalid response=%d list calls=%d", invalid.Code, store.listCalls)
	}
	// A release still names its site.
	noSite := httptest.NewRequest(http.MethodPost, "/v1/analytics/logs/cc-coordination/"+stateID.String()+"/release",
		strings.NewReader(`{"reason_code":"false_positive_confirmed","expected_generation":7}`))
	noSite.Header.Set("Idempotency-Key", "cc-release-8")
	noSite.Header.Set("X-Request-ID", "cc-release-request-8")
	noSiteResponse := httptest.NewRecorder()
	handler.ServeHTTP(noSiteResponse, noSite)
	if noSiteResponse.Code != http.StatusBadRequest || store.releaseCalls != 1 {
		t.Fatalf("release without site=%d calls=%d", noSiteResponse.Code, store.releaseCalls)
	}
}

// stats-platform-l7: the platform operator lists every tenant's states
// without a tenant or site; authorization runs against the operator's own
// platform scope and the store receives no tenant or site filter.
func TestPlatformListsEveryTenantWithoutFilters(t *testing.T) {
	user, platformScope := uuid.New(), uuid.New()
	poolConfig, err := pgxpool.ParseConfig("postgres://test:test@127.0.0.1:1/test")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := &storeStub{state: cccoord.State{ID: uuid.New()}, anyScope: true}
	identity := principal{userID: user, scopeID: platformScope, scopeKind: "platform", credentialKind: "session"}
	var authorizedScope uuid.UUID
	handler, err := newHandler(store, pool, func(*http.Request) (principal, error) { return identity, nil },
		func(_ context.Context, _ principal, target uuid.UUID, _ string) (securitypolicy.Actor, error) {
			authorizedScope = target
			return securitypolicy.Actor{UserID: user, ScopeID: platformScope, ScopeKind: "platform"}, nil
		}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/logs/cc-coordination", nil))
	if response.Code != http.StatusOK || store.listCalls != 1 || store.lastScope != uuid.Nil || store.lastSite != uuid.Nil ||
		authorizedScope != platformScope {
		t.Fatalf("platform list=%d calls=%d scope=%s site=%s authorized=%s body=%s", response.Code, store.listCalls,
			store.lastScope, store.lastSite, authorizedScope, response.Body.String())
	}
	site := uuid.New()
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/logs/cc-coordination?site_id="+site.String(), nil))
	if response.Code != http.StatusOK || store.lastScope != uuid.Nil || store.lastSite != site {
		t.Fatalf("platform site filter=%d scope=%s site=%s", response.Code, store.lastScope, store.lastSite)
	}
	// An API key cannot use the platform route.
	identity.credentialKind = "api_key"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/logs/cc-coordination", nil))
	if response.Code != http.StatusForbidden || store.listCalls != 2 {
		t.Fatalf("platform api key=%d calls=%d", response.Code, store.listCalls)
	}
	// A tenant identity cannot reach the platform route.
	identity = principal{userID: user, scopeID: uuid.New(), tenantID: uuid.New(), scopeKind: "tenant", credentialKind: "session"}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/logs/cc-coordination", nil))
	if response.Code != http.StatusForbidden || store.listCalls != 2 {
		t.Fatalf("tenant on platform route=%d calls=%d", response.Code, store.listCalls)
	}
}

type storeStub struct {
	state        cccoord.State
	anyScope     bool
	lastScope    uuid.UUID
	lastSite     uuid.UUID
	listCalls    int
	releaseCalls int
	release      cccoord.ReleaseInput
}

func (store *storeStub) ListStates(_ context.Context, tenantScopeID, siteID uuid.UUID, limit int) ([]cccoord.State, error) {
	store.listCalls++
	store.lastScope, store.lastSite = tenantScopeID, siteID
	if store.anyScope || siteID == uuid.Nil && tenantScopeID == store.state.TenantScopeID {
		return []cccoord.State{store.state}, nil
	}
	if tenantScopeID != store.state.TenantScopeID || siteID != store.state.SiteID || limit != 50 {
		return nil, cccoord.ErrScopeMismatch
	}
	return []cccoord.State{store.state}, nil
}

func (store *storeStub) GetState(_ context.Context, tenantScopeID, siteID, stateID uuid.UUID) (cccoord.State, error) {
	if tenantScopeID != store.state.TenantScopeID || siteID != store.state.SiteID || stateID != store.state.ID {
		return cccoord.State{}, cccoord.ErrScopeMismatch
	}
	return store.state, nil
}

func (store *storeStub) Release(_ context.Context, _ securitypolicy.Actor, input cccoord.ReleaseInput) (cccoord.ReleaseResult, error) {
	store.releaseCalls++
	store.release = input
	return cccoord.ReleaseResult{State: store.state}, nil
}

func decodeResponse(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), target); err != nil {
		t.Fatal(err)
	}
}
