package plugininstallation

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// 报告 A：平台主题由主控平台管理员在 /v1/platform/plugin-installations 确认，作用域取自会话（平台
// access scope），权限只认精确的 plugin_installations.platform.*；租户路由守卫不变。
func TestHandlerPlatformRoutesUseSessionScopeAndExactPermissions(t *testing.T) {
	platformScope, tenantID, authorizationID := uuid.New(), uuid.New(), uuid.New()
	platform := identity.Principal{UserID: uuid.New(), ScopeID: platformScope, ScopeKind: ScopePlatform,
		Username: "platform-admin", Permissions: []string{PermissionPlatformRead, PermissionPlatformManage}}
	confirmBody := `{"verification_id":"` + uuid.NewString() + `","approved_scopes":["plugin.read"],` +
		`"sensitive_permissions_confirmed":true,"new_permissions_confirmed":true}`
	run := func(principal identity.Principal, method, path, body string) (*httptest.ResponseRecorder, *handlerTestDomain) {
		domain := &handlerTestDomain{mutationResult: handlerTestView(platformScope, authorizationID)}
		handler, err := NewHandler(HandlerDependencies{
			AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
				return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
			}, Domain: domain})
		if err != nil {
			t.Fatal(err)
		}
		var buffer *bytes.Buffer
		if body != "" {
			buffer = bytes.NewBufferString(body)
		}
		request := authenticatedHandlerRequest(method, path, buffer)
		if method == http.MethodPost {
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", `"1"`)
			request.Header.Set("Idempotency-Key", "platform-confirm-1")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response, domain
	}
	list := "/v1/platform/plugin-installations"
	confirm := list + "/" + authorizationID.String() + "/confirm"

	response, domain := run(platform, http.MethodGet, list, "")
	if response.Code != http.StatusOK || domain.lastActor.TenantID != platformScope ||
		domain.lastActor.ScopeKind != ScopePlatform || domain.lastList.TenantID != platformScope {
		t.Fatalf("platform list status=%d actor=%+v body=%s", response.Code, domain.lastActor, response.Body.String())
	}
	response, domain = run(platform, http.MethodPost, confirm, confirmBody)
	if response.Code != http.StatusOK || domain.lastMutation.TenantID != platformScope ||
		domain.lastMutation.ExpectedRevision != 1 || domain.lastActor.Username != "platform-admin" {
		t.Fatalf("platform confirm status=%d mutation=%+v body=%s", response.Code, domain.lastMutation, response.Body.String())
	}

	for name, test := range map[string]struct {
		principal identity.Principal
		method    string
		path      string
		body      string
	}{
		"platform.admin is not a fallback": {identity.Principal{UserID: uuid.New(), ScopeID: platformScope,
			ScopeKind: ScopePlatform, Permissions: []string{"platform.admin", PermissionRead, PermissionManage}},
			http.MethodGet, list, ""},
		"platform read cannot confirm": {identity.Principal{UserID: uuid.New(), ScopeID: platformScope,
			ScopeKind: ScopePlatform, Permissions: []string{PermissionPlatformRead}}, http.MethodPost, confirm, confirmBody},
		"tenant session on platform route": {identity.Principal{UserID: uuid.New(), ScopeID: tenantID,
			ScopeKind: ScopeTenant, TenantID: &tenantID,
			Permissions: []string{PermissionRead, PermissionManage, PermissionPlatformRead, PermissionPlatformManage}},
			http.MethodGet, list, ""},
		"platform session on tenant route": {platform, http.MethodGet,
			"/v1/tenant-scopes/" + platformScope.String() + "/plugin-installations", ""},
	} {
		t.Run(name, func(t *testing.T) {
			response, domain := run(test.principal, test.method, test.path, test.body)
			assertHandlerError(t, response, http.StatusForbidden, "permission_denied")
			if domain.calls != 0 {
				t.Fatalf("denied request reached domain %d times", domain.calls)
			}
		})
	}
	// The platform route never takes a scope from the path.
	response, _ = run(platform, http.MethodGet, "/v1/platform/"+tenantID.String()+"/plugin-installations", "")
	assertHandlerError(t, response, http.StatusNotFound, "not_found")
}
