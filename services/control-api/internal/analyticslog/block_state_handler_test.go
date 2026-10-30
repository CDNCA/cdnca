package analyticslog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type blockHandlerStoreStub struct {
	current      CurrentBlockPage
	currentErr   error
	history      BlockHistoryPage
	historyErr   error
	count        SiteBlacklistCountPage
	countErr     error
	preparation  BlockUnlockPreparation
	prepareErr   error
	currentScope uuid.UUID
	historyScope uuid.UUID
	countScope   uuid.UUID
	currentQuery BlockListRequest
	historyQuery BlockListRequest
	currentCalls int
}

func (store *blockHandlerStoreStub) ListCurrent(_ context.Context, scopeID uuid.UUID,
	request BlockListRequest,
) (CurrentBlockPage, error) {
	store.currentCalls++
	store.currentScope, store.currentQuery = scopeID, request
	return store.current, store.currentErr
}

func TestBlockStateHandlerAllowsPlatformGlobalCurrentRead(t *testing.T) {
	platformScopeID, userID := uuid.New(), uuid.New()
	store := &blockHandlerStoreStub{current: CurrentBlockPage{SnapshotAt: time.Now().UTC()}}
	authorizer := new(recordingAuthorizer)
	handler, _, _ := newBlockHandlerForTest(t, store, func(*http.Request) (Principal, error) {
		return Principal{
			ID: userID.String(), ScopeID: platformScopeID.String(), ScopeKind: "platform",
			credentialKind: credentialSession,
		}, nil
	}, authorizer)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/admin/analytics/logs/blocks/current?limit=10", nil))

	if response.Code != http.StatusOK || store.currentCalls != 1 || store.currentScope != uuid.Nil ||
		store.currentQuery.Limit != 10 {
		t.Fatalf("global current response=%d calls=%d scope=%s query=%+v body=%s",
			response.Code, store.currentCalls, store.currentScope, store.currentQuery, response.Body.String())
	}
	calls := authorizer.calls()
	if len(calls) != 1 || calls[0] != (AuthorizationRequest{
		Permission: ReadPermission, Audience: AudiencePlatform,
	}) {
		t.Fatalf("authorization calls = %+v", calls)
	}
}

func TestPlatformGlobalBlockReadUsesPlatformAuthorizationScope(t *testing.T) {
	platformScopeID, userID := uuid.New(), uuid.New()
	principal := Principal{
		ID: userID.String(), ScopeID: platformScopeID.String(), ScopeKind: "platform",
		credentialKind: credentialSession,
	}
	scoped, actor, err := scopedPrincipal(principal, AudiencePlatform, "")
	if err != nil || scoped.ScopeKind != "platform" || actor.TenantID != "" {
		t.Fatalf("scoped principal=%+v actor=%+v error=%v", scoped, actor, err)
	}
	targetScopeID, targetTenantID, err := new(iamAuthorizer).targetScopeHint(
		t.Context(), scoped, platformScopeID, AuthorizationRequest{Audience: AudiencePlatform},
	)
	if err != nil || targetScopeID != platformScopeID || targetTenantID != uuid.Nil {
		t.Fatalf("target scope=%s tenant=%s error=%v", targetScopeID, targetTenantID, err)
	}
}

func (store *blockHandlerStoreStub) ListHistory(_ context.Context, scopeID uuid.UUID,
	request BlockListRequest,
) (BlockHistoryPage, error) {
	store.historyScope, store.historyQuery = scopeID, request
	return store.history, store.historyErr
}

func (store *blockHandlerStoreStub) PrepareUnlock(context.Context, uuid.UUID,
	uuid.UUID,
) (BlockUnlockPreparation, error) {
	return store.preparation, store.prepareErr
}

func (store *blockHandlerStoreStub) CountCurrent(_ context.Context, scopeID uuid.UUID,
) (SiteBlacklistCountPage, error) {
	store.countScope = scopeID
	return store.count, store.countErr
}

func newBlockHandlerTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgres://postgres:postgres@127.0.0.1:1/cdnca?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func newBlockHandlerForTest(t *testing.T, store BlockStateStore, authenticate AuthenticatePrincipalFunc,
	authorizer Authorizer,
) (*BlockStateHandler, *policyUpdaterStub, *activationStarterStub) {
	t.Helper()
	updater := new(policyUpdaterStub)
	starter := new(activationStarterStub)
	service, err := NewBlockStateService(store, updater, starter, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewBlockStateHandler(service, newBlockHandlerTestPool(t), authenticate, authorizer,
		&Handler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return handler, updater, starter
}

func tenantBlockPrincipal(scopeID, userID uuid.UUID) Principal {
	return Principal{
		ID: userID.String(), ScopeID: scopeID.String(), TenantID: scopeID.String(), ScopeKind: "tenant",
		credentialKind: credentialSession,
	}
}

func TestBlockStateHandlerBindsTenantScopeBeforeAuthorization(t *testing.T) {
	scopeID, userID, siteID, policyID, blockID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
	store := &blockHandlerStoreStub{current: CurrentBlockPage{
		Items: []CurrentBlock{{ID: blockID, SiteID: siteID, CIDR: "192.0.2.10/32"}}, SnapshotAt: snapshot,
	}}
	authorizer := new(recordingAuthorizer)
	handler, _, _ := newBlockHandlerForTest(t, store, func(*http.Request) (Principal, error) {
		return tenantBlockPrincipal(scopeID, userID), nil
	}, authorizer)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet,
		"/v1/analytics/logs/blocks/current?site_id="+siteID.String()+"&policy_id="+policyID.String()+"&cidr=192.0.2.10%2F32&limit=20", nil)
	request.Header.Set("X-Request-ID", "block-current-tenant")
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || store.currentScope != scopeID || store.currentQuery.Limit != 20 ||
		store.currentQuery.SiteID == nil || *store.currentQuery.SiteID != siteID ||
		store.currentQuery.PolicyID == nil || *store.currentQuery.PolicyID != policyID || store.currentQuery.CIDR != "192.0.2.10/32" {
		t.Fatalf("current response=%d scope=%s query=%+v body=%s",
			response.Code, store.currentScope, store.currentQuery, response.Body.String())
	}
	calls := authorizer.calls()
	if len(calls) != 1 || calls[0] != (AuthorizationRequest{
		Permission: ReadPermission, Audience: AudienceTenant, TenantID: scopeID.String(), SiteID: siteID.String(),
	}) {
		t.Fatalf("authorization calls = %+v", calls)
	}
	var page CurrentBlockPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Items) != 1 ||
		page.Items[0].ID != blockID || !page.SnapshotAt.Equal(snapshot) {
		t.Fatalf("current page = %+v error=%v", page, err)
	}
}

func TestBlockStateHandlerRejectsPlatformAPIKeyBeforeAuthorization(t *testing.T) {
	platformScopeID, userID, tenantID := uuid.New(), uuid.New(), uuid.New()
	store := new(blockHandlerStoreStub)
	authorizer := new(recordingAuthorizer)
	handler, _, _ := newBlockHandlerForTest(t, store, func(*http.Request) (Principal, error) {
		return Principal{
			ID: userID.String(), ScopeID: platformScopeID.String(), ScopeKind: "platform",
			credentialKind: credentialAPIKey,
		}, nil
	}, authorizer)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/admin/analytics/logs/blocks/current?tenant_id="+tenantID.String(), nil))

	if response.Code != http.StatusUnauthorized || len(authorizer.calls()) != 0 || store.currentScope != uuid.Nil {
		t.Fatalf("platform API-key response=%d authorizations=%+v scope=%s",
			response.Code, authorizer.calls(), store.currentScope)
	}
	if strings.Contains(response.Body.String(), "api_key") {
		t.Fatalf("credential kind leaked: %s", response.Body.String())
	}
}

func TestBlockStateHandlerUnlockRequiresStableReasonAndIdempotency(t *testing.T) {
	scopeID, userID, siteID, policyID, nodeID, ruleID :=
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	blockID := blockIdentity(siteID, policyID, "192.0.2.10/32")
	policy := securitypolicy.Policy{
		ID: policyID, ScopeID: scopeID, Kind: securitypolicy.KindACL, Name: "site ACL", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Revision: 3,
		Rules: []securitypolicy.Rule{{
			ID: ruleID, Name: "blocked clients", Priority: 10, Enabled: true,
			Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{
				Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.10/32", "198.51.100.0/24"},
			}},
		}},
	}
	store := &blockHandlerStoreStub{preparation: BlockUnlockPreparation{
		Block:  CurrentBlock{ID: blockID, SiteID: siteID, PolicyID: policyID, CIDR: "192.0.2.10/32"},
		Policy: policy, BindingRevision: 2, ActivePolicyVersion: 3, LatestPolicyVersion: 3,
		TargetNodeIDs: []uuid.UUID{nodeID},
	}}
	authorizer := new(recordingAuthorizer)
	handler, updater, starter := newBlockHandlerForTest(t, store, func(*http.Request) (Principal, error) {
		return tenantBlockPrincipal(scopeID, userID), nil
	}, authorizer)
	updater.result = securitypolicy.WriteResult{Policy: securitypolicy.Policy{ID: policyID, Revision: 4}}
	starter.result = securityactivation.StartResult{
		Candidate:  securityactivation.Candidate{ID: uuid.New(), Status: securityactivation.StatusClaimed},
		ReasonCode: securityactivation.RecoveryResultClaimed,
	}
	path := "/v1/analytics/logs/blocks/current/" + blockID.String() + "/unlock"

	for _, test := range []struct {
		name string
		body string
		key  string
	}{
		{name: "missing idempotency", body: `{"reason_code":"false_positive_confirmed"}`},
		{name: "unsupported reason", body: `{"reason_code":"operator_override"}`, key: "unlock-reason"},
		{name: "unknown field", body: `{"reason_code":"false_positive_confirmed","secret":"raw"}`, key: "unlock-unknown"},
		{name: "over capacity", body: `{"reason_code":"false_positive_confirmed","padding":"` + strings.Repeat("x", 4096) + `"}`, key: "unlock-large"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(test.body))
			if test.key != "" {
				request.Header.Set("Idempotency-Key", test.key)
			}
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "raw") {
				t.Fatalf("invalid unlock response=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if updater.request.ID != uuid.Nil || starter.input.PolicyID != uuid.Nil {
		t.Fatal("invalid unlock reached a durable writer")
	}
	unexpectedQuery := httptest.NewRecorder()
	unexpectedQueryRequest := httptest.NewRequest(http.MethodPost, path+"?site_id="+siteID.String(),
		strings.NewReader(`{"reason_code":"false_positive_confirmed"}`))
	unexpectedQueryRequest.Header.Set("Idempotency-Key", "unlock-query")
	handler.ServeHTTP(unexpectedQuery, unexpectedQueryRequest)
	if unexpectedQuery.Code != http.StatusBadRequest || updater.request.ID != uuid.Nil || starter.input.PolicyID != uuid.Nil {
		t.Fatalf("unlock list query response=%d update=%+v activation=%+v",
			unexpectedQuery.Code, updater.request, starter.input)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path,
		strings.NewReader(`{"reason_code":"false_positive_confirmed"}`))
	request.Header.Set("Idempotency-Key", "unlock-valid")
	request.Header.Set("X-Request-ID", "block-unlock-valid")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || updater.request.ID != policyID || starter.input.PolicyID != policyID ||
		starter.input.Recovery == nil || starter.input.Recovery.ReasonCode != securityactivation.RecoveryReasonFalsePositiveConfirmed {
		t.Fatalf("valid unlock response=%d update=%+v activation=%+v body=%s",
			response.Code, updater.request, starter.input, response.Body.String())
	}
}

func TestBlockStateHandlerReturnsStableNotFoundConflictAndUnavailableErrors(t *testing.T) {
	scopeID, userID := uuid.New(), uuid.New()
	authenticate := func(*http.Request) (Principal, error) { return tenantBlockPrincipal(scopeID, userID), nil }

	notFoundHandler, _, _ := newBlockHandlerForTest(t, new(blockHandlerStoreStub), authenticate, new(recordingAuthorizer))
	notFound := httptest.NewRecorder()
	notFoundHandler.ServeHTTP(notFound, httptest.NewRequest(http.MethodGet,
		"/v1/analytics/logs/blocks/current/not-a-uuid/unlock", nil))
	if notFound.Code != http.StatusNotFound || !strings.Contains(notFound.Body.String(), `"code":"analytics_block_not_found"`) {
		t.Fatalf("not found response=%d body=%s", notFound.Code, notFound.Body.String())
	}

	conflictStore := &blockHandlerStoreStub{prepareErr: ErrBlockStateConflict}
	conflictHandler, _, _ := newBlockHandlerForTest(t, conflictStore, authenticate, new(recordingAuthorizer))
	conflict := httptest.NewRecorder()
	conflictRequest := httptest.NewRequest(http.MethodPost,
		"/v1/analytics/logs/blocks/current/"+uuid.NewString()+"/unlock",
		strings.NewReader(`{"reason_code":"false_positive_confirmed"}`))
	conflictRequest.Header.Set("Idempotency-Key", "unlock-conflict")
	conflictHandler.ServeHTTP(conflict, conflictRequest)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), `"code":"analytics_block_unlock_conflict"`) {
		t.Fatalf("conflict response=%d body=%s", conflict.Code, conflict.Body.String())
	}

	unavailableStore := &blockHandlerStoreStub{currentErr: errors.New("private database secret")}
	unavailableHandler, _, _ := newBlockHandlerForTest(t, unavailableStore, authenticate, new(recordingAuthorizer))
	unavailable := httptest.NewRecorder()
	unavailableHandler.ServeHTTP(unavailable, httptest.NewRequest(http.MethodGet,
		"/v1/analytics/logs/blocks/current", nil))
	if unavailable.Code != http.StatusServiceUnavailable ||
		!strings.Contains(unavailable.Body.String(), `"code":"analytics_logs_storage_unavailable"`) ||
		strings.Contains(unavailable.Body.String(), "private database secret") {
		t.Fatalf("unavailable response=%d body=%s", unavailable.Code, unavailable.Body.String())
	}
}
