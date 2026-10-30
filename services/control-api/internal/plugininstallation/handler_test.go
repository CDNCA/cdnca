package plugininstallation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestHandlerAuthenticationTenantIsolationAndReadWire(t *testing.T) {
	tenantID, authorizationID := uuid.New(), uuid.New()
	view := handlerTestView(tenantID, authorizationID)
	domain := &handlerTestDomain{listResult: Page{Items: []InstallationView{view}, NextCursor: "next-page"}, getResult: view}
	handler := newHandlerForTest(t, tenantID, domain)

	unauthenticated := httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/"+tenantID.String()+"/plugin-installations", nil)
	unauthenticatedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticatedResponse, unauthenticated)
	assertHandlerError(t, unauthenticatedResponse, http.StatusUnauthorized, "authentication_required")
	if domain.calls != 0 {
		t.Fatal("unauthenticated request reached domain")
	}

	otherTenant := uuid.New()
	forbidden := authenticatedHandlerRequest(http.MethodGet,
		"/v1/tenant-scopes/"+otherTenant.String()+"/plugin-installations", nil)
	forbiddenResponse := httptest.NewRecorder()
	handler.ServeHTTP(forbiddenResponse, forbidden)
	assertHandlerError(t, forbiddenResponse, http.StatusForbidden, "permission_denied")
	if domain.calls != 0 {
		t.Fatal("cross-tenant request reached domain")
	}

	list := authenticatedHandlerRequest(http.MethodGet,
		"/v1/tenant-scopes/"+tenantID.String()+"/plugin-installations?limit=20&status=enabled&plugin_id=acme.example", nil)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var page struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.NextCursor != "next-page" {
		t.Fatalf("list body=%s err=%v", listResponse.Body.String(), err)
	}
	assertInstallationWire(t, page.Items[0], tenantID, authorizationID)
	if domain.lastList.Limit != 20 || domain.lastList.Status != StatusEnabled || domain.lastList.PluginID != "acme.example" {
		t.Fatalf("list request=%+v", domain.lastList)
	}

	detail := authenticatedHandlerRequest(http.MethodGet,
		"/v1/tenant-scopes/"+tenantID.String()+"/plugin-installations/"+authorizationID.String(), nil)
	detailResponse := httptest.NewRecorder()
	handler.ServeHTTP(detailResponse, detail)
	if detailResponse.Code != http.StatusOK || detailResponse.Header().Get("ETag") != `"7"` {
		t.Fatalf("detail status=%d etag=%q body=%s", detailResponse.Code,
			detailResponse.Header().Get("ETag"), detailResponse.Body.String())
	}
}

func TestHandlerStrictMutationContractAndStableErrors(t *testing.T) {
	tenantID, authorizationID, verificationID := uuid.New(), uuid.New(), uuid.New()
	view := handlerTestView(tenantID, authorizationID)
	domain := &handlerTestDomain{mutationResult: view}
	handler := newHandlerForTest(t, tenantID, domain)
	path := "/v1/tenant-scopes/" + tenantID.String() + "/plugin-installations/" + authorizationID.String()

	approval := `{"verification_id":"` + verificationID.String() + `","approved_scopes":["plugin.read"],"sensitive_permissions_confirmed":true,"new_permissions_confirmed":true}`
	request := authenticatedHandlerRequest(http.MethodPost, path+"/upgrade", bytes.NewBufferString(approval))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"7"`)
	request.Header.Set("Idempotency-Key", "plugin-upgrade-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"7"` {
		t.Fatalf("upgrade status=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	if domain.lastMutation.Action != ActionUpgrade || domain.lastMutation.ExpectedRevision != 7 ||
		domain.lastMutation.IdempotencyKey != "plugin-upgrade-1" || domain.lastMutation.VerificationID != verificationID ||
		!domain.lastMutation.NewPermissionsConfirmed || !domain.lastMutation.SensitivePermissionsConfirmed {
		t.Fatalf("mutation request=%+v", domain.lastMutation)
	}

	for name, body := range map[string]string{
		"duplicate": `{"reason":"one","reason":"two"}`,
		"unknown":   `{"reason":"one","proof":"secret"}`,
		"null":      `{"reason":null}`,
		"trailing":  `{"reason":"one"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := authenticatedHandlerRequest(http.MethodPost, path+"/disable", bytes.NewBufferString(body))
			invalid.Header.Set("Content-Type", "application/json")
			invalid.Header.Set("If-Match", `"7"`)
			invalid.Header.Set("Idempotency-Key", "plugin-disable-"+name)
			invalidResponse := httptest.NewRecorder()
			handler.ServeHTTP(invalidResponse, invalid)
			assertHandlerError(t, invalidResponse, http.StatusBadRequest, "invalid_request")
		})
	}

	domain.err = ErrIdempotencyConflict
	conflict := authenticatedHandlerRequest(http.MethodPost, path+"/uninstall", bytes.NewBufferString(`{"reason":"customer removal"}`))
	conflict.Header.Set("Content-Type", "application/json")
	conflict.Header.Set("If-Match", `"7"`)
	conflict.Header.Set("Idempotency-Key", "plugin-uninstall-1")
	conflictResponse := httptest.NewRecorder()
	handler.ServeHTTP(conflictResponse, conflict)
	assertHandlerError(t, conflictResponse, http.StatusConflict, "plugin_installation_idempotency_conflict")

	domain.err = ErrResultUnknown
	unknown := authenticatedHandlerRequest(http.MethodPost, path+"/disable", bytes.NewBufferString(`{"reason":"containment"}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknown.Header.Set("If-Match", `"7"`)
	unknown.Header.Set("Idempotency-Key", "plugin-disable-unknown")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	assertHandlerError(t, unknownResponse, http.StatusServiceUnavailable, "plugin_installation_result_unknown")
}

func TestHandlerRejectsPlatformAndMissingExactPermissionsBeforeDomain(t *testing.T) {
	tenantID, authorizationID := uuid.New(), uuid.New()
	path := "/v1/tenant-scopes/" + tenantID.String() + "/plugin-installations"
	mutationPath := path + "/" + authorizationID.String() + "/disable"
	tests := []struct {
		name      string
		principal identity.Principal
		method    string
		path      string
		body      *bytes.Buffer
	}{
		{name: "platform principal", principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(),
			ScopeKind: "platform", Permissions: []string{PermissionRead, PermissionManage}}, method: http.MethodGet,
			path: path},
		{name: "missing read", principal: identity.Principal{UserID: uuid.New(), ScopeID: tenantID,
			ScopeKind: ScopeTenant, TenantID: &tenantID, Permissions: []string{PermissionManage}},
			method: http.MethodGet, path: path},
		{name: "missing manage", principal: identity.Principal{UserID: uuid.New(), ScopeID: tenantID,
			ScopeKind: ScopeTenant, TenantID: &tenantID, Permissions: []string{PermissionRead}},
			method: http.MethodPost, path: mutationPath, body: bytes.NewBufferString(`{"reason":"containment"}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := &handlerTestDomain{}
			handler, err := NewHandler(HandlerDependencies{
				AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
					return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: test.principal}, nil
				},
				Domain: domain,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := authenticatedHandlerRequest(test.method, test.path, test.body)
			if test.method == http.MethodPost {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("If-Match", `"1"`)
				request.Header.Set("Idempotency-Key", "plugin-permission-denied-1")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertHandlerError(t, response, http.StatusForbidden, "permission_denied")
			if domain.calls != 0 {
				t.Fatalf("denied request reached domain %d times", domain.calls)
			}
		})
	}
}

func newHandlerForTest(t *testing.T, tenantID uuid.UUID, domain Domain) *Handler {
	t.Helper()
	handler, err := NewHandler(HandlerDependencies{
		AuthenticateSession: func(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
			if raw != "customer-session" {
				return identity.AuthenticatedSession{}, identity.ErrInvalidSession
			}
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
				UserID: uuid.New(), ScopeID: tenantID, ScopeKind: ScopeTenant, TenantID: &tenantID,
				Permissions: []string{PermissionRead, PermissionManage},
			}}, nil
		},
		Domain: domain,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return handler
}

func authenticatedHandlerRequest(method, path string, body *bytes.Buffer) *http.Request {
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, body)
	}
	request.Header.Set("Authorization", "Bearer customer-session")
	request.Header.Set("X-Request-ID", "plugin-installation-request-1")
	return request
}

func handlerTestView(tenantID, authorizationID uuid.UUID) InstallationView {
	lkgID := uuid.New()
	lkgVersion, reason := "1.2.0", "upgrade_applied"
	return InstallationView{Installation: Installation{Schema: Schema, TenantID: tenantID,
		AuthorizationID: authorizationID, InstallationID: uuid.New(), VerificationID: uuid.New(),
		PluginID: "acme.example", Version: "1.2.0", ResourceScope: ResourceScopeTenant, EntrypointType: EntrypointExternalHTTPS, ManifestSHA256: digest("a"),
		ConfigurationSchemaSHA256: digest("1"), ManifestScopes: []string{"plugin.read", "plugin.write"},
		ApprovedScopes: []string{"plugin.read"}, SensitiveScopes: []string{"plugin.write"}, Status: StatusEnabled,
		Revision: 7, IdentityGeneration: 3, LKGVerificationID: lkgID, LKGVersion: lkgVersion,
		StableReasonCode: reason, UpdatedAt: time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)},
		NewScopes: []string{"plugin.write"}}
}

func assertInstallationWire(t *testing.T, value map[string]any, tenantID, authorizationID uuid.UUID) {
	t.Helper()
	if len(value) != 22 || value["schema"] != Schema || value["entrypoint_type"] != EntrypointExternalHTTPS || value["tenant_scope_id"] != tenantID.String() ||
		value["authorization_id"] != authorizationID.String() || value["lkg_verification_id"] == nil ||
		value["lkg_version"] != "1.2.0" || value["stable_reason_code"] != "upgrade_applied" {
		t.Fatalf("installation wire=%v", value)
	}
	newScopes, ok := value["new_scopes"].([]any)
	if !ok || len(newScopes) != 1 || newScopes[0] != "plugin.write" {
		t.Fatalf("new_scopes=%v", value["new_scopes"])
	}
}

func assertHandlerError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Error.Code != code {
		t.Fatalf("body=%s err=%v", response.Body.String(), err)
	}
}

type handlerTestDomain struct {
	calls          int
	lastActor      Actor
	listResult     Page
	getResult      InstallationView
	mutationResult InstallationView
	lastList       ListRequest
	lastMutation   MutationRequest
	err            error
}

func (domain *handlerTestDomain) List(_ context.Context, actor Actor, request ListRequest) (Page, error) {
	domain.calls++
	domain.lastActor = actor
	domain.lastList = request
	return domain.listResult, domain.err
}

func (domain *handlerTestDomain) Get(_ context.Context, _ Actor, _ uuid.UUID) (InstallationView, error) {
	domain.calls++
	return domain.getResult, domain.err
}

func (domain *handlerTestDomain) Mutate(_ context.Context, actor Actor, request MutationRequest) (InstallationView, error) {
	domain.calls++
	domain.lastActor = actor
	domain.lastMutation = request
	return domain.mutationResult, domain.err
}
