package systemconfighttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
)

type categoryServiceStub struct {
	getResult  systemconfig.CategoryDocument
	getErr     error
	saveResult systemconfig.CategoryDocument
	saveErr    error
	actor      systemconfig.Actor
	save       systemconfig.SaveCategoryRequest
}

func (stub *categoryServiceStub) GetActiveCategory(_ context.Context, actor systemconfig.Actor,
	_ string,
) (systemconfig.CategoryDocument, error) {
	stub.actor = actor
	return stub.getResult, stub.getErr
}

func (stub *categoryServiceStub) SaveCategory(_ context.Context, actor systemconfig.Actor,
	request systemconfig.SaveCategoryRequest,
) (systemconfig.CategoryDocument, error) {
	stub.actor = actor
	stub.save = request
	return stub.saveResult, stub.saveErr
}

type rollbackCategoryServiceStub struct {
	categoryServiceStub
	rollbackResult  systemconfig.Revision
	rollbackErr     error
	rollbackActor   systemconfig.Actor
	rollbackRequest systemconfig.RollbackRequest
}

func (stub *rollbackCategoryServiceStub) RollbackRevision(_ context.Context, actor systemconfig.Actor,
	request systemconfig.RollbackRequest,
) (systemconfig.Revision, error) {
	stub.rollbackActor = actor
	stub.rollbackRequest = request
	return stub.rollbackResult, stub.rollbackErr
}

func TestHandlerUsesOnlyFormalAuthenticatedSession(t *testing.T) {
	userID, scopeID, sessionID := uuid.New(), uuid.New(), uuid.New()
	stub := &categoryServiceStub{getResult: systemconfig.CategoryDocument{
		Schema: "cdnca.system-configuration/v1", Category: systemconfig.CategoryNginx,
		HeadRevision: 4, ActiveRevision: 3, Revision: 4, Status: systemconfig.StatusDraft,
		SnapshotSHA256: strings.Repeat("a", 64), Value: systemconfig.NginxLimits{},
	}}
	handler := testHandler(t, stub, identity.AuthenticatedSession{SessionID: sessionID, Principal: identity.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: "platform",
	}})
	request := httptest.NewRequest(http.MethodGet,
		"/v1/admin/system-configuration/categories/nginx", nil)
	request.Header.Set("Authorization", "Bearer formal-session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"4"` {
		t.Fatalf("status=%d ETag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	var document systemconfig.CategoryDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil || document.Revision != 4 ||
		document.HeadRevision != 4 || document.ActiveRevision != 3 || document.Status != systemconfig.StatusDraft {
		t.Fatalf("GET did not return head snapshot with active metadata: document=%#v err=%v", document, err)
	}
	if stub.actor != (systemconfig.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}) {
		t.Fatalf("actor = %#v", stub.actor)
	}

	spoofed := httptest.NewRequest(http.MethodGet,
		"/v1/admin/system-configuration/categories/nginx", nil)
	spoofed.Header.Set("Authorization", "Bearer formal-session")
	spoofed.Header.Set("X-User-ID", uuid.NewString())
	spoofedResponse := httptest.NewRecorder()
	handler.ServeHTTP(spoofedResponse, spoofed)
	assertErrorCode(t, spoofedResponse, http.StatusUnauthorized, "system_configuration_unauthenticated")
}

func TestHandlerAllowsFreshInstallRevisionZero(t *testing.T) {
	bootstrap := systemconfig.ProjectBootstrapConfiguration()
	stub := &categoryServiceStub{
		getResult: systemconfig.CategoryDocument{
			Schema: "cdnca.system-configuration/v2", Category: systemconfig.CategoryResources,
			HeadRevision: 0, ActiveRevision: 0, Revision: 0, Status: systemconfig.StatusDraft,
			SnapshotSHA256: strings.Repeat("a", 64), Value: bootstrap.Resources,
		},
		saveResult: systemconfig.CategoryDocument{
			Schema: "cdnca.system-configuration/v2", Category: systemconfig.CategoryResources,
			HeadRevision: 1, ActiveRevision: 0, Revision: 1, Status: systemconfig.StatusDraft,
			SnapshotSHA256: strings.Repeat("b", 64), Value: bootstrap.Resources,
		},
	}
	handler := testHandler(t, stub, identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}})

	getRequest := httptest.NewRequest(http.MethodGet,
		"/v1/admin/system-configuration/categories/resources", nil)
	getRequest.Header.Set("Authorization", "Bearer formal-session")
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != `"0"` {
		t.Fatalf("fresh GET status=%d ETag=%q body=%s", getResponse.Code,
			getResponse.Header().Get("ETag"), getResponse.Body.String())
	}

	body, err := json.Marshal(map[string]any{"value": bootstrap.Resources})
	if err != nil {
		t.Fatal(err)
	}
	putRequest := httptest.NewRequest(http.MethodPut,
		"/v1/admin/system-configuration/categories/resources", bytes.NewReader(body))
	putRequest.Header.Set("Authorization", "Bearer formal-session")
	putRequest.Header.Set("Content-Type", "application/json")
	putRequest.Header.Set("If-Match", `"0"`)
	putRequest.Header.Set("Idempotency-Key", "fresh-category-http-key")
	putRequest.Header.Set("X-Request-ID", "fresh-category-http-request")
	putResponse := httptest.NewRecorder()
	handler.ServeHTTP(putResponse, putRequest)
	if putResponse.Code != http.StatusOK || stub.save.ExpectedHeadRevision != 0 || stub.save.Change.Resources == nil {
		t.Fatalf("fresh PUT status=%d save=%#v body=%s", putResponse.Code, stub.save, putResponse.Body.String())
	}
}

func TestHandlerAuthenticatesBeforeProtectedRouteAndInputLookup(t *testing.T) {
	for _, test := range []struct {
		name, method, target string
	}{
		{name: "unknown category", method: http.MethodGet, target: "/v1/admin/system-configuration/categories/private"},
		{name: "unknown route", method: http.MethodGet, target: "/v1/admin/system-configuration/private"},
		{name: "query input", method: http.MethodGet, target: "/v1/admin/system-configuration/categories/nginx?probe=true"},
		{name: "unsupported method", method: http.MethodPost, target: "/v1/admin/system-configuration/categories/nginx"},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticateCalls := 0
			handler, err := NewHandler(&categoryServiceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
				authenticateCalls++
				return identity.AuthenticatedSession{}, identity.ErrInvalidSession
			}, HandlerConfig{})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, test.target, nil)
			request.Header.Set("Authorization", "Bearer invalid-session")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertErrorCode(t, response, http.StatusUnauthorized, "system_configuration_unauthenticated")
			if authenticateCalls != 1 {
				t.Fatalf("authenticate calls = %d, want 1 before protected lookup", authenticateCalls)
			}
		})
	}
}

func TestHandlerPUTStrictCategoryAndSecretIntent(t *testing.T) {
	userID, scopeID := uuid.New(), uuid.New()
	stub := &categoryServiceStub{saveResult: systemconfig.CategoryDocument{
		Schema: "cdnca.system-configuration/v1", Category: systemconfig.CategoryResources,
		HeadRevision: 2, ActiveRevision: 1, Revision: 2, Status: systemconfig.StatusDraft,
		SnapshotSHA256: strings.Repeat("b", 64), Value: systemconfig.ResourceLimits{},
	}}
	handler := testHandler(t, stub, identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: "platform",
	}})
	resources := systemconfig.ResourceLimits{MaxSitesPerTenant: 10, MaxOriginsPerSite: 2,
		MaxDomainsPerSite: 3, MaxCertificatesPerTenant: 4, MaxBlacklistIPsPerSite: 5,
		MaxWhitelistIPsPerSite: 6, DailyURLPurgeLimit: 7, DailyDirectoryPurgeLimit: 8,
		DailyPrewarmLimit: 9, MaxACLRulesPerPolicy: 10, MaxCCRulesPerPolicy: 11,
		MaxCustomErrorPageBytes: 1024, MinimumRelatedConfigLimit: 1, RelatedConfigMaxMultiplier: 2}
	body, err := json.Marshal(map[string]any{"value": resources})
	if err != nil {
		t.Fatal(err)
	}
	response := servePUT(handler, systemconfig.CategoryResources, body)
	if response.Code != http.StatusOK || stub.save.ExpectedHeadRevision != 1 ||
		stub.save.IdempotencyKey != "category-http-key" || stub.save.RequestID != "category-http-request" ||
		stub.save.Change.Resources == nil {
		t.Fatalf("status=%d save=%#v body=%s", response.Code, stub.save, response.Body.String())
	}

	unknownField := servePUT(handler, systemconfig.CategoryResources,
		bytes.Replace(body, []byte(`{"value":`), []byte(`{"unknown":true,"value":`), 1))
	assertErrorCode(t, unknownField, http.StatusBadRequest, "system_configuration_validation_error")
	unknownCategory := servePUT(handler, "email", []byte(`{"value":{}}`))
	assertErrorCode(t, unknownCategory, http.StatusNotFound, "system_configuration_category_not_found")
	plaintext := servePUT(handler, systemconfig.CategorySecrets, []byte(`{"value":{"error_page_storage":{
		"intent":"replace","plaintext":"secret","replacement":{"provider":"vault","reference":"vault:ref",
		"key_id":"key","algorithm":"aes-256-gcm","ciphertext_sha256":"`+strings.Repeat("d", 64)+`"}}}}`))
	assertErrorCode(t, plaintext, http.StatusBadRequest, "system_configuration_validation_error")
	keep := servePUT(handler, systemconfig.CategorySecrets,
		[]byte(`{"value":{"error_page_storage":{"intent":"keep"}}}`))
	assertErrorCode(t, keep, http.StatusBadRequest, "system_configuration_validation_error")

	// A region override of a build-time setting gets its own
	// readable code, not the generic validation error.
	stub.saveErr = fmt.Errorf("save: %w", systemconfig.ErrRegionOverrideUnsupported)
	refused := servePUT(handler, systemconfig.CategoryResources, body)
	assertErrorCode(t, refused, http.StatusBadRequest, "system_configuration_region_override_unsupported")
}

func TestHandlerStableAuthenticationAuthorizationCASAndEntitlementErrors(t *testing.T) {
	baseSession := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"permission", systemconfig.ErrPermissionDenied, http.StatusForbidden, "system_configuration_permission_denied"},
		{"not found", systemconfig.ErrNotFound, http.StatusNotFound, "system_configuration_active_not_found"},
		{"CAS", systemconfig.ErrRevisionConflict, http.StatusConflict, "system_configuration_revision_conflict"},
		{"idempotency", systemconfig.ErrIdempotencyConflict, http.StatusConflict, "system_configuration_idempotency_conflict"},
		{"entitlement", systemconfig.ErrEntitlementDenied, http.StatusUnprocessableEntity, "system_configuration_entitlement_denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &categoryServiceStub{getErr: test.err}
			handler := testHandler(t, stub, baseSession)
			request := httptest.NewRequest(http.MethodGet,
				"/v1/admin/system-configuration/categories/nginx", nil)
			request.Header.Set("Authorization", "Bearer formal-session")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertErrorCode(t, response, test.status, test.code)
		})
	}

	unauthenticated, err := NewHandler(&categoryServiceStub{},
		func(*http.Request, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"/v1/admin/system-configuration/categories/nginx", nil)
	request.Header.Set("Authorization", "Bearer invalid")
	response := httptest.NewRecorder()
	unauthenticated.ServeHTTP(response, request)
	assertErrorCode(t, response, http.StatusUnauthorized, "system_configuration_unauthenticated")
}

func servePUT(handler http.Handler, category string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPut,
		"/v1/admin/system-configuration/categories/"+category, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer formal-session")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "category-http-key")
	request.Header.Set("X-Request-ID", "category-http-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func testHandler(t *testing.T, service CategoryService, session identity.AuthenticatedSession) http.Handler {
	t.Helper()
	handler, err := NewHandler(service, func(_ *http.Request, raw string) (identity.AuthenticatedSession, error) {
		if raw != "formal-session" {
			return identity.AuthenticatedSession{}, errors.New("unexpected session")
		}
		return session, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code {
		t.Fatalf("code=%q want=%q body=%s", envelope.Error.Code, code, response.Body.String())
	}
}

func TestHandlerPUTStrictNodeMonitoringCategory(t *testing.T) {
	stub := &categoryServiceStub{saveResult: systemconfig.CategoryDocument{
		Schema: "cdnca.system-configuration/v1", Category: systemconfig.CategoryNodeMonitoring,
		HeadRevision: 2, ActiveRevision: 1, Revision: 2, Status: systemconfig.StatusDraft,
		SnapshotSHA256: strings.Repeat("c", 64), Value: systemconfig.NodeMonitoringConfiguration{},
	}}
	handler := testHandler(t, stub, identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}})
	body := []byte(`{"value":{"port_mode":"custom","custom_port":8443,"probe_interval_ms":10000,` +
		`"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,` +
		`"failure_debounce_ms":0,"recovery_debounce_ms":0,"recovery_notification_enabled":true}}`)
	response := servePUT(handler, systemconfig.CategoryNodeMonitoring, body)
	if response.Code != http.StatusOK || stub.save.Change.NodeMonitoring == nil ||
		stub.save.Change.NodeMonitoring.CustomPort == nil || *stub.save.Change.NodeMonitoring.CustomPort != 8443 {
		t.Fatalf("status=%d save=%#v body=%s", response.Code, stub.save, response.Body.String())
	}
	unknown := servePUT(handler, systemconfig.CategoryNodeMonitoring,
		bytes.Replace(body, []byte(`"port_mode":"custom"`), []byte(`"port_mode":"custom","extra":true`), 1))
	assertErrorCode(t, unknown, http.StatusBadRequest, "system_configuration_validation_error")
}

func TestHandlerRollbackCreatesDraftWithExactCASAndMetadata(t *testing.T) {
	userID, scopeID := uuid.New(), uuid.New()
	sourceRevision := int64(2)
	stub := &rollbackCategoryServiceStub{rollbackResult: systemconfig.Revision{
		Revision: 5, Status: systemconfig.StatusDraft, SnapshotSHA256: strings.Repeat("e", 64),
		SourceRevision: &sourceRevision, Replayed: true,
	}}
	handler := testHandler(t, stub, identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: "platform",
	}})
	response := serveRollback(handler, 2, 4, 3, []byte(`{"expected_active_revision":3}`))
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"5"` ||
		response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if stub.rollbackActor != (systemconfig.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}) ||
		stub.rollbackRequest != (systemconfig.RollbackRequest{
			TargetRevision: 2, ExpectedHeadRevision: 4, ExpectedActiveRevision: 3,
			IdempotencyKey: "rollback-http-key", RequestID: "rollback-http-request",
		}) {
		t.Fatalf("actor=%#v request=%#v", stub.rollbackActor, stub.rollbackRequest)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 5 || body["revision"] != float64(5) || body["status"] != systemconfig.StatusDraft ||
		body["snapshot_sha256"] != strings.Repeat("e", 64) || body["source_revision"] != float64(2) ||
		body["replayed"] != true {
		t.Fatalf("body=%#v", body)
	}
}

func TestHandlerRollbackUsesStableErrorsAndStrictInput(t *testing.T) {
	baseSession := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "missing target", err: systemconfig.ErrNotFound, status: http.StatusNotFound,
			code: "system_configuration_revision_not_found"},
		{name: "invalid transition", err: systemconfig.ErrInvalidTransition, status: http.StatusConflict,
			code: "system_configuration_invalid_transition"},
		{name: "head changed", err: systemconfig.ErrRevisionConflict, status: http.StatusConflict,
			code: "system_configuration_revision_conflict"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &rollbackCategoryServiceStub{rollbackErr: test.err}
			handler := testHandler(t, stub, baseSession)
			response := serveRollback(handler, 2, 4, 3, []byte(`{"expected_active_revision":3}`))
			assertErrorCode(t, response, test.status, test.code)
		})
	}

	valid := &rollbackCategoryServiceStub{}
	handler := testHandler(t, valid, baseSession)
	for _, test := range []struct {
		name        string
		body        []byte
		contentType string
	}{
		{name: "missing active revision", body: []byte(`{}`), contentType: "application/json"},
		{name: "unknown field", body: []byte(`{"expected_active_revision":3,"force":true}`), contentType: "application/json"},
		{name: "wrong media type", body: []byte(`{"expected_active_revision":3}`), contentType: "text/plain"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost,
				"/v1/admin/system-configuration/revisions/2/rollback", bytes.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer formal-session")
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("If-Match", `"4"`)
			request.Header.Set("Idempotency-Key", "rollback-http-key")
			request.Header.Set("X-Request-ID", "rollback-http-request")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertErrorCode(t, response, http.StatusBadRequest, "system_configuration_validation_error")
		})
	}

	request := httptest.NewRequest(http.MethodGet,
		"/v1/admin/system-configuration/revisions/2/rollback", nil)
	request.Header.Set("Authorization", "Bearer formal-session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertErrorCode(t, response, http.StatusMethodNotAllowed, "system_configuration_method_not_allowed")
	if response.Header().Get("Allow") != "POST" {
		t.Fatalf("Allow=%q", response.Header().Get("Allow"))
	}
}

func serveRollback(handler http.Handler, targetRevision, expectedHeadRevision, expectedActiveRevision int64,
	body []byte,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost,
		"/v1/admin/system-configuration/revisions/"+strconv.FormatInt(targetRevision, 10)+"/rollback", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer formal-session")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", quotedRevision(expectedHeadRevision))
	request.Header.Set("Idempotency-Key", "rollback-http-key")
	request.Header.Set("X-Request-ID", "rollback-http-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
