package cachecontrolhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestHandlerRequiresExactPermissionsAndExplicitPlatformScope(t *testing.T) {
	tenantScope, platformScope, userID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var actors []cachecontrol.Actor
	control := &fakeControl{getPolicy: func(_ context.Context, actor cachecontrol.Actor, gotSite uuid.UUID, revision int64) (cachecontrol.PolicyRevision, error) {
		actors = append(actors, actor)
		return cachecontrol.PolicyRevision{SiteID: gotSite, ScopeID: actor.ScopeID, Revision: 1}, nil
	}}
	handler := testHandler(t, control, &fakeReader{}, func(request *http.Request) (identity.Principal, error) {
		switch request.Header.Get("Authorization") {
		case "tenant":
			return principal(userID, tenantScope, "tenant", PermissionPoliciesRead), nil
		case "platform":
			return principal(userID, platformScope, "platform", PermissionPoliciesRead), nil
		case "platform-admin-only":
			return principal(userID, platformScope, "platform", "platform.admin"), nil
		case "tenant-admin-only":
			return principal(userID, tenantScope, "tenant", "platform.admin"), nil
		default:
			return identity.Principal{}, errors.New("no session")
		}
	})

	tests := []struct {
		name, authorization, path string
		status                    int
	}{
		{"tenant own scope", "tenant", "/v1/cache-policies/" + siteID.String(), 200},
		{"tenant scope override rejected", "tenant", "/v1/cache-policies/" + siteID.String() + "?scope_id=" + uuid.NewString(), 400},
		{"platform scope required", "platform", "/v1/admin/cache-policies/" + siteID.String(), 400},
		{"platform explicit scope", "platform", "/v1/admin/cache-policies/" + siteID.String() + "?scope_id=" + tenantScope.String(), 200},
		{"tenant cannot use admin route", "tenant", "/v1/admin/cache-policies/" + siteID.String() + "?scope_id=" + tenantScope.String(), 403},
		{"platform admin wildcard", "platform-admin-only", "/v1/admin/cache-policies/" + siteID.String() + "?scope_id=" + tenantScope.String(), 200},
		{"tenant platform admin string denied", "tenant-admin-only", "/v1/cache-policies/" + siteID.String(), 403},
		{"authentication required", "", "/v1/cache-policies/" + siteID.String(), 401},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serve(t, handler, http.MethodGet, test.path, nil, test.authorization, "")
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if len(actors) != 3 || actors[0].ScopeID != tenantScope || actors[1].ScopeID != tenantScope ||
		actors[2].ScopeID != tenantScope {
		t.Fatalf("authorized actors=%+v", actors)
	}
}

func TestHandlerCreateReplayRedactsSecretsAndRejectsUnknownFields(t *testing.T) {
	scopeID, userID, siteID, nodeID, operationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	querySecret := "signed-token-do-not-return"
	idempotencyKey := "idem-secret-do-not-return"
	createCalls := 0
	control := &fakeControl{createOperation: func(_ context.Context, actor cachecontrol.Actor, request cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error) {
		createCalls++
		if request.IdempotencyKey != idempotencyKey || actor.ScopeID != scopeID {
			t.Fatalf("actor=%+v request=%+v", actor, request)
		}
		return cachecontrol.OperationWriteResult{Replayed: true, Operation: cachecontrol.Operation{
			ID: operationID, ScopeID: scopeID, TenantID: uuid.New(), SiteID: siteID,
			Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
			IdempotencyKey: idempotencyKey, State: cachecontrol.StateQueued, MaxAttempts: 2,
			Targets: []cachecontrol.Target{{Ordinal: 1, CanonicalURL: "https://example.com/a?token=" + querySecret, CanonicalPath: "/a"}},
			Nodes:   []cachecontrol.NodeProjection{{NodeID: nodeID, State: cachecontrol.StateQueued}},
		}}, nil
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsManage), nil
	})
	body := map[string]any{
		"site_id": siteID, "action": "purge", "target_type": "exact_url",
		"targets":  []string{"https://example.com/a?token=" + querySecret},
		"node_ids": []string{nodeID.String()}, "max_retries": 1,
	}
	response := serve(t, handler, http.MethodPost, "/v1/cache-operations", body, "tenant", idempotencyKey)
	if response.Code != http.StatusAccepted || response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	encoded := response.Body.String()
	for _, secret := range []string{querySecret, idempotencyKey, "token="} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("response leaked %q: %s", secret, encoded)
		}
	}
	if !strings.Contains(encoded, "query=redacted") || !strings.Contains(encoded, "target_sha256") {
		t.Fatalf("redacted target missing: %s", encoded)
	}

	unknown := map[string]any{
		"site_id": siteID, "action": "purge", "target_type": "whole_site",
		"targets": []string{}, "node_ids": []string{nodeID.String()}, "max_retries": 0,
		"credential": "must-not-be-accepted",
	}
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations", unknown, "tenant", "unknown-field")
	if response.Code != http.StatusBadRequest || createCalls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, createCalls, response.Body.String())
	}
}

func TestHandlerRejectsNonCanonicalQueriesBeforeReading(t *testing.T) {
	scopeID, platformScope, userID := uuid.New(), uuid.New(), uuid.New()
	readCalls := 0
	handler := testHandler(t, &fakeControl{}, &fakeReader{operationPage: func(
		context.Context, cachecontrol.Actor, OperationPageQuery,
	) (OperationReadPage, error) {
		readCalls++
		return OperationReadPage{}, nil
	}}, func(request *http.Request) (identity.Principal, error) {
		if request.Header.Get("Authorization") == "platform" {
			return principal(userID, platformScope, "platform", PermissionOperationsRead), nil
		}
		return principal(userID, scopeID, "tenant", PermissionOperationsRead), nil
	})
	tests := []struct {
		name, path, rawQuery, authorization string
	}{
		{"malformed percent encoding", "/v1/cache-operations", "limit=%", "tenant"},
		{"duplicate key", "/v1/cache-operations", "limit=1&limit=2", "tenant"},
		{"empty limit", "/v1/cache-operations", "limit=", "tenant"},
		{"empty site", "/v1/cache-operations", "site_id=", "tenant"},
		{"empty cursor", "/v1/cache-operations", "cursor=", "tenant"},
		{"encoded key alias", "/v1/cache-operations", "%6cimit=1", "tenant"},
		{"empty platform scope", "/v1/admin/cache-operations", "scope_id=", "platform"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.URL.RawQuery = test.rawQuery
			request.Header.Set("X-Request-ID", "strict-query")
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if readCalls != 0 {
		t.Fatalf("reader called %d times for invalid query", readCalls)
	}
}

func TestHandlerRequiresExactJSONFieldsButAcceptsLegalZeroValues(t *testing.T) {
	scopeID, userID, siteID, nodeID, operationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	createCalls, publishCalls := 0, 0
	control := &fakeControl{
		createOperation: func(_ context.Context, _ cachecontrol.Actor, request cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error) {
			createCalls++
			if request.MaxRetries != 0 {
				t.Fatalf("max retries=%d", request.MaxRetries)
			}
			return cachecontrol.OperationWriteResult{Operation: cachecontrol.Operation{
				ID: operationID, ScopeID: scopeID, SiteID: siteID, Action: request.Action,
				TargetType: request.TargetType, State: cachecontrol.StateQueued, MaxAttempts: 1,
			}}, nil
		},
		publishPolicy: func(_ context.Context, _ cachecontrol.Actor, request cachecontrol.PublishPolicyRequest) (cachecontrol.PolicyWriteResult, error) {
			publishCalls++
			if request.ExpectedRevision != 0 || request.Document.Mode != cachecontrol.PolicyDisabled || request.Document.DiskQuotaBytes != 0 {
				t.Fatalf("publish request=%+v", request)
			}
			return cachecontrol.PolicyWriteResult{Policy: cachecontrol.PolicyRevision{
				SiteID: siteID, ScopeID: scopeID, Revision: 1, Document: request.Document,
			}}, nil
		},
	}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsManage, PermissionPoliciesManage), nil
	})
	validOperation := fmt.Sprintf(`{"site_id":%q,"action":"purge","target_type":"exact_url","targets":["https://example.com/a"],"node_ids":[%q],"max_retries":0}`, siteID, nodeID)
	invalidBodies := []struct {
		name, body string
	}{
		{"upper case field", strings.Replace(validOperation, `"targets"`, `"TARGETS"`, 1)},
		{"title case field", strings.Replace(validOperation, `"targets"`, `"Targets"`, 1)},
		{"case folded duplicate", strings.Replace(validOperation, `"targets":[`, `"targets":[],"TARGETS":[`, 1)},
		{"required field omitted", strings.Replace(validOperation, `,"max_retries":0`, ``, 1)},
		{"required field null", strings.Replace(validOperation, `"max_retries":0`, `"max_retries":null`, 1)},
	}
	for _, test := range invalidBodies {
		t.Run(test.name, func(t *testing.T) {
			response := serveRaw(t, handler, http.MethodPost, "/v1/cache-operations", test.body, "tenant", "strict-body")
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if createCalls != 0 {
		t.Fatalf("create called %d times for invalid JSON", createCalls)
	}
	response := serveRaw(t, handler, http.MethodPost, "/v1/cache-operations", validOperation, "tenant", "zero-max-retries")
	if response.Code != http.StatusAccepted || createCalls != 1 {
		t.Fatalf("legal zero create status=%d calls=%d body=%s", response.Code, createCalls, response.Body.String())
	}
	validPolicy := `{"expected_revision":0,"document":{"mode":"disabled","rules":[],"query_mode":"ignore","query_names":[],"vary_headers":[],"disk_quota_bytes":0}}`
	response = serveRaw(t, handler, http.MethodPost, "/v1/cache-policies/"+siteID.String(), validPolicy, "tenant", "zero-policy-values")
	if response.Code != http.StatusCreated || publishCalls != 1 {
		t.Fatalf("legal zero policy status=%d calls=%d body=%s", response.Code, publishCalls, response.Body.String())
	}
	for _, body := range []string{
		strings.Replace(validPolicy, `"expected_revision":0,`, ``, 1),
		strings.Replace(validPolicy, `"expected_revision":0`, `"expected_revision":null`, 1),
	} {
		response = serveRaw(t, handler, http.MethodPost, "/v1/cache-policies/"+siteID.String(), body, "tenant", "missing-policy-field")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid policy status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if publishCalls != 1 {
		t.Fatalf("publish called %d times", publishCalls)
	}
}

func TestHandlerEnforcesEdgeV2TargetEnvelope(t *testing.T) {
	scopeID, userID, siteID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	createCalls := 0
	control := &fakeControl{createOperation: func(_ context.Context, _ cachecontrol.Actor, request cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error) {
		createCalls++
		return cachecontrol.OperationWriteResult{Operation: cachecontrol.Operation{
			ID: uuid.New(), ScopeID: scopeID, SiteID: siteID, Action: request.Action,
			TargetType: request.TargetType, State: cachecontrol.StateQueued, MaxAttempts: 1,
		}}, nil
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsManage), nil
	})
	targets := func(lengths ...int) []string {
		result := make([]string, len(lengths))
		for index, length := range lengths {
			prefix := fmt.Sprintf("https://example.com/%d?padding=", index)
			result[index] = prefix + strings.Repeat("x", length-len(prefix))
		}
		return result
	}
	maximumCountTargets := make([]string, EdgeCacheTaskV2MaxTargets)
	for index := range maximumCountTargets {
		maximumCountTargets[index] = fmt.Sprintf("https://example.com/%d", index)
	}
	body := func(values []string) map[string]any {
		return map[string]any{
			"site_id": siteID, "action": "purge", "target_type": "exact_url",
			"targets": values, "node_ids": []string{nodeID.String()}, "max_retries": 0,
		}
	}
	validCases := []struct {
		name    string
		targets []string
	}{
		{"maximum count", maximumCountTargets},
		{"maximum single target bytes", targets(EdgeCacheTaskV2MaxTargetBytes)},
		{"maximum aggregate target bytes", targets(slices.Repeat([]int{EdgeCacheTaskV2MaxTargetBytes},
			EdgeCacheTaskV2MaxTaskTargetBytes/EdgeCacheTaskV2MaxTargetBytes)...)},
	}
	for _, test := range validCases {
		t.Run("accepts "+test.name, func(t *testing.T) {
			response := serve(t, handler, http.MethodPost, "/v1/cache-operations", body(test.targets), "tenant", "valid-target-envelope")
			if response.Code != http.StatusAccepted {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	invalidCases := []struct {
		name    string
		targets []string
	}{
		{"over maximum count", append(validCases[0].targets, "https://example.com/overflow")},
		{"over maximum single target bytes", targets(EdgeCacheTaskV2MaxTargetBytes + 1)},
		{"over maximum aggregate target bytes", targets(slices.Repeat([]int{EdgeCacheTaskV2MaxTargetBytes},
			EdgeCacheTaskV2MaxTaskTargetBytes/EdgeCacheTaskV2MaxTargetBytes+1)...)},
	}
	accepted := createCalls
	for _, test := range invalidCases {
		t.Run("rejects "+test.name, func(t *testing.T) {
			response := serve(t, handler, http.MethodPost, "/v1/cache-operations", body(test.targets), "tenant", "invalid-target-envelope")
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if createCalls != accepted {
		t.Fatalf("create called %d times for invalid target envelopes", createCalls-accepted)
	}
}

func TestHandlerReturnsStableErrorsWithoutRawStorageDetails(t *testing.T) {
	scopeID, userID, operationID := uuid.New(), uuid.New(), uuid.New()
	rawSecret := "postgres://admin:password@db/cache"
	control := &fakeControl{getOperation: func(context.Context, cachecontrol.Actor, uuid.UUID) (cachecontrol.Operation, error) {
		return cachecontrol.Operation{}, fmt.Errorf("select failed %s", rawSecret)
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsRead), nil
	})
	response := serve(t, handler, http.MethodGet, "/v1/cache-operations/"+operationID.String(), nil, "tenant", "")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"service_unavailable"`) ||
		strings.Contains(response.Body.String(), rawSecret) || strings.Contains(response.Body.String(), "select failed") {
		t.Fatalf("unsafe error response: status=%d body=%s", response.Code, response.Body.String())
	}

	control.getOperation = func(context.Context, cachecontrol.Actor, uuid.UUID) (cachecontrol.Operation, error) {
		return cachecontrol.Operation{}, cachecontrol.ErrNotFound
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations/"+operationID.String(), nil, "tenant", "")
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
		t.Fatalf("not found response: %d %s", response.Code, response.Body.String())
	}

	// A "*.a.com" target host has its own code, not the generic invalid_request.
	control.getOperation = func(context.Context, cachecontrol.Actor, uuid.UUID) (cachecontrol.Operation, error) {
		return cachecontrol.Operation{}, cachecontrol.ErrWildcardTargetHost
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations/"+operationID.String(), nil, "tenant", "")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"wildcard_target_host"`) {
		t.Fatalf("wildcard target host response: %d %s", response.Code, response.Body.String())
	}
}

func TestHandlerPropagatesCancelledContext(t *testing.T) {
	scopeID, userID, operationID := uuid.New(), uuid.New(), uuid.New()
	control := &fakeControl{getOperation: func(ctx context.Context, _ cachecontrol.Actor, _ uuid.UUID) (cachecontrol.Operation, error) {
		<-ctx.Done()
		return cachecontrol.Operation{}, ctx.Err()
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsRead), nil
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/cache-operations/"+operationID.String(), nil)
	request.Header.Set("X-Request-ID", "cancelled-request")
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request.WithContext(ctx))
	if response.Code != http.StatusRequestTimeout || !strings.Contains(response.Body.String(), `"code":"request_cancelled"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerReturnsStableNotFoundForUnknownRoute(t *testing.T) {
	scopeID, userID := uuid.New(), uuid.New()
	handler := testHandler(t, &fakeControl{}, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsRead), nil
	})
	secret := "query-secret-must-not-be-reflected"
	response := serve(t, handler, http.MethodGet, "/v1/cache-unknown?token="+secret, nil, "tenant", "")
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) ||
		strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "cache-unknown") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func testHandler(t *testing.T, control ControlStore, reader ReadStore, authenticate AuthenticateFunc) *Handler {
	t.Helper()
	service, err := NewService(control, reader, bytes.Repeat([]byte{0x4c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, authenticate)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func principal(userID, scopeID uuid.UUID, kind string, permissions ...string) identity.Principal {
	return identity.Principal{UserID: userID, ScopeID: scopeID, ScopeKind: kind, Permissions: permissions}
}

func serve(t *testing.T, handler http.Handler, method, path string, body any, authorization, idempotencyKey string) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, requestBody)
	request.Header.Set("X-Request-ID", "request-01")
	request.Header.Set("Authorization", authorization)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func serveRaw(t *testing.T, handler http.Handler, method, path, body, authorization, idempotencyKey string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("X-Request-ID", "request-raw-01")
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type fakeControl struct {
	publishPolicy   func(context.Context, cachecontrol.Actor, cachecontrol.PublishPolicyRequest) (cachecontrol.PolicyWriteResult, error)
	getPolicy       func(context.Context, cachecontrol.Actor, uuid.UUID, int64) (cachecontrol.PolicyRevision, error)
	createOperation func(context.Context, cachecontrol.Actor, cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error)
	getOperation    func(context.Context, cachecontrol.Actor, uuid.UUID) (cachecontrol.Operation, error)
	retry           func(context.Context, cachecontrol.Actor, cachecontrol.RetryRequest) (cachecontrol.OperationWriteResult, error)
	resubmit        func(context.Context, cachecontrol.Actor, cachecontrol.ResubmitRequest) (cachecontrol.OperationWriteResult, error)
	cancel          func(context.Context, cachecontrol.Actor, cachecontrol.CancelRequest) (cachecontrol.OperationWriteResult, error)
	dailyUsage      func(context.Context, cachecontrol.Actor) (cachecontrol.DailyUsage, error)
	setLimits       func(context.Context, cachecontrol.Actor, cachecontrol.SetAccountLimitsRequest) (cachecontrol.DailyUsage, error)
	targetSites     func(context.Context, cachecontrol.Actor, bool, cachecontrol.ResolveTargetSitesRequest) (cachecontrol.TargetSiteGrouping, error)
	carryingNodes   func(context.Context, cachecontrol.Actor) ([]cachecontrol.CarryingNode, error)
	writeReceipt    func(context.Context, cachecontrol.Actor, cachecontrol.WriteReceiptRequest) (cachecontrol.WriteReceipt, error)
}

func (store *fakeControl) WriteReceipt(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.WriteReceiptRequest) (cachecontrol.WriteReceipt, error) {
	if store.writeReceipt == nil {
		return cachecontrol.WriteReceipt{}, ErrStoreUnavailable
	}
	return store.writeReceipt(ctx, actor, request)
}

func (store *fakeControl) ResolveTargetSites(ctx context.Context, actor cachecontrol.Actor, allScopes bool, request cachecontrol.ResolveTargetSitesRequest) (cachecontrol.TargetSiteGrouping, error) {
	if store.targetSites == nil {
		return cachecontrol.TargetSiteGrouping{}, ErrStoreUnavailable
	}
	return store.targetSites(ctx, actor, allScopes, request)
}

func (store *fakeControl) CarryingNodes(ctx context.Context, actor cachecontrol.Actor) ([]cachecontrol.CarryingNode, error) {
	if store.carryingNodes == nil {
		return nil, ErrStoreUnavailable
	}
	return store.carryingNodes(ctx, actor)
}

func (store *fakeControl) DailyUsage(ctx context.Context, actor cachecontrol.Actor) (cachecontrol.DailyUsage, error) {
	if store.dailyUsage == nil {
		return cachecontrol.DailyUsage{}, ErrStoreUnavailable
	}
	return store.dailyUsage(ctx, actor)
}

func (store *fakeControl) SetAccountLimits(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.SetAccountLimitsRequest) (cachecontrol.DailyUsage, error) {
	if store.setLimits == nil {
		return cachecontrol.DailyUsage{}, ErrStoreUnavailable
	}
	return store.setLimits(ctx, actor, request)
}

func (store *fakeControl) PublishPolicy(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.PublishPolicyRequest) (cachecontrol.PolicyWriteResult, error) {
	if store.publishPolicy == nil {
		return cachecontrol.PolicyWriteResult{}, ErrStoreUnavailable
	}
	return store.publishPolicy(ctx, actor, request)
}

func (store *fakeControl) GetPolicy(ctx context.Context, actor cachecontrol.Actor, siteID uuid.UUID, revision int64) (cachecontrol.PolicyRevision, error) {
	if store.getPolicy == nil {
		return cachecontrol.PolicyRevision{}, ErrStoreUnavailable
	}
	return store.getPolicy(ctx, actor, siteID, revision)
}

func (store *fakeControl) CreateOperation(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error) {
	if store.createOperation == nil {
		return cachecontrol.OperationWriteResult{}, ErrStoreUnavailable
	}
	return store.createOperation(ctx, actor, request)
}

func (store *fakeControl) GetOperation(ctx context.Context, actor cachecontrol.Actor, operationID uuid.UUID) (cachecontrol.Operation, error) {
	if store.getOperation == nil {
		return cachecontrol.Operation{}, ErrStoreUnavailable
	}
	return store.getOperation(ctx, actor, operationID)
}

func (store *fakeControl) Retry(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.RetryRequest) (cachecontrol.OperationWriteResult, error) {
	if store.retry == nil {
		return cachecontrol.OperationWriteResult{}, ErrStoreUnavailable
	}
	return store.retry(ctx, actor, request)
}

func (store *fakeControl) Resubmit(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.ResubmitRequest) (cachecontrol.OperationWriteResult, error) {
	if store.resubmit == nil {
		return cachecontrol.OperationWriteResult{}, ErrStoreUnavailable
	}
	return store.resubmit(ctx, actor, request)
}

func (store *fakeControl) Cancel(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.CancelRequest) (cachecontrol.OperationWriteResult, error) {
	if store.cancel == nil {
		return cachecontrol.OperationWriteResult{}, ErrStoreUnavailable
	}
	return store.cancel(ctx, actor, request)
}

type fakeReader struct {
	policyPage    func(context.Context, cachecontrol.Actor, uuid.UUID, PolicyPageQuery) (PolicyReadPage, error)
	operationPage func(context.Context, cachecontrol.Actor, OperationPageQuery) (OperationReadPage, error)
}

func (reader *fakeReader) ListPolicyRevisions(ctx context.Context, actor cachecontrol.Actor, siteID uuid.UUID, query PolicyPageQuery) (PolicyReadPage, error) {
	if reader.policyPage == nil {
		return PolicyReadPage{}, ErrStoreUnavailable
	}
	return reader.policyPage(ctx, actor, siteID, query)
}

func (reader *fakeReader) ListOperations(ctx context.Context, actor cachecontrol.Actor, query OperationPageQuery) (OperationReadPage, error) {
	if reader.operationPage == nil {
		return OperationReadPage{}, ErrStoreUnavailable
	}
	return reader.operationPage(ctx, actor, query)
}

var _ ControlStore = (*fakeControl)(nil)
var _ ReadStore = (*fakeReader)(nil)

func testOperationSummary(id, siteID uuid.UUID, createdAt time.Time) OperationSummary {
	return OperationSummary{ID: id, SiteID: siteID, Action: cachecontrol.ActionPurge,
		TargetType: cachecontrol.TargetExactURL, State: cachecontrol.StateQueued,
		MaxAttempts: 2, TargetCount: 1, NodeCount: 1, Progress: cachecontrol.Progress{Total: 1},
		CreatedAt: createdAt, UpdatedAt: createdAt}
}
