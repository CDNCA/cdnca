package plugininstallation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// targetsTestDomain is a handlerTestDomain that also changes targets.
type targetsTestDomain struct {
	handlerTestDomain
	lastTargets TargetsUpdate
}

func (domain *targetsTestDomain) UpdateTargets(_ context.Context, actor Actor, update TargetsUpdate) (InstallationView, error) {
	domain.calls++
	domain.lastActor = actor
	domain.lastTargets = update
	return domain.mutationResult, domain.err
}

// 平台管理员确认租户插件时在请求体里给 targets（全部租户 / 指定租户），之后
// 用 PUT .../targets 改；租户路由不收 targets。If-Match、Idempotency-Key 与权限码照旧（只认
// plugin_installations.platform.manage）。
func TestHandlerPlatformConfirmCarriesTargetsAndTargetsRoute(t *testing.T) {
	platformScope, tenantScope, tenantB, authorizationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	platform := identity.Principal{UserID: uuid.New(), ScopeID: platformScope, ScopeKind: ScopePlatform,
		Username: "platform-admin", Permissions: []string{PermissionPlatformRead, PermissionPlatformManage}}
	tenant := identity.Principal{UserID: uuid.New(), ScopeID: tenantScope, ScopeKind: ScopeTenant, TenantID: &tenantScope,
		Permissions: []string{PermissionRead, PermissionManage}}
	view := handlerTestView(platformScope, authorizationID)
	view.ManagedBy = ManagedByPlatform
	view.Targets = &TargetsView{Revision: 2, Tenants: []TargetTenant{{ScopeID: tenantScope, DisplayName: "甲", DisplayID: "100001"}}}
	run := func(principal identity.Principal, method, path, body string, headers map[string]string) (*httptest.ResponseRecorder, *targetsTestDomain) {
		domain := &targetsTestDomain{handlerTestDomain: handlerTestDomain{mutationResult: view}}
		handler, err := NewHandler(HandlerDependencies{
			AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
				return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
			}, Domain: domain})
		if err != nil {
			t.Fatal(err)
		}
		request := authenticatedHandlerRequest(method, path, bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response, domain
	}
	write := map[string]string{"If-Match": `"1"`, "Idempotency-Key": "targets-1"}
	base := "/v1/platform/plugin-installations/" + authorizationID.String()
	approval := `"verification_id":"` + uuid.NewString() + `","approved_scopes":["plugin.read"],` +
		`"sensitive_permissions_confirmed":true,"new_permissions_confirmed":true`

	// Confirm with listed tenants: canonical order, de-duplicated.
	listed := `{` + approval + `,"targets":{"all_tenants":false,"tenant_scope_ids":["` + tenantB.String() + `","` +
		tenantScope.String() + `","` + tenantB.String() + `"]}}`
	response, domain := run(platform, http.MethodPost, base+"/confirm", listed, write)
	if response.Code != http.StatusOK || domain.lastMutation.Targets == nil || domain.lastMutation.Targets.AllTenants ||
		len(domain.lastMutation.Targets.TenantScopeIDs) != 2 {
		t.Fatalf("confirm with targets status=%d mutation=%+v body=%s", response.Code, domain.lastMutation, response.Body.String())
	}
	var wire struct {
		Installation struct {
			ManagedBy string `json:"managed_by"`
			Targets   struct {
				AllTenants bool   `json:"all_tenants"`
				Revision   uint64 `json:"revision"`
				Tenants    []struct {
					ScopeID     string `json:"scope_id"`
					DisplayName string `json:"display_name"`
				} `json:"tenants"`
			} `json:"targets"`
		} `json:"installation"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &wire); err != nil || wire.Installation.ManagedBy != ManagedByPlatform ||
		wire.Installation.Targets.Revision != 2 || len(wire.Installation.Targets.Tenants) != 1 ||
		wire.Installation.Targets.Tenants[0].DisplayName != "甲" {
		t.Fatalf("confirm wire=%s err=%v", response.Body.String(), err)
	}

	// The targets route: PUT with If-Match = targets revision.
	response, domain = run(platform, http.MethodPut, base+"/targets", `{"all_tenants":true,"tenant_scope_ids":[]}`, write)
	if response.Code != http.StatusOK || domain.lastTargets.AuthorizationID != authorizationID ||
		!domain.lastTargets.Targets.AllTenants || domain.lastTargets.ExpectedRevision != 1 ||
		domain.lastTargets.IdempotencyKey != "targets-1" || response.Header().Get("ETag") != `"2"` {
		t.Fatalf("targets status=%d update=%+v etag=%s body=%s", response.Code, domain.lastTargets,
			response.Header().Get("ETag"), response.Body.String())
	}

	for name, test := range map[string]struct {
		principal identity.Principal
		method    string
		path      string
		body      string
		headers   map[string]string
		status    int
		code      string
	}{
		"all tenants with a list": {platform, http.MethodPut, base + "/targets",
			`{"all_tenants":true,"tenant_scope_ids":["` + tenantScope.String() + `"]}`, write,
			http.StatusUnprocessableEntity, "plugin_installation_targets_invalid"},
		"empty list": {platform, http.MethodPut, base + "/targets", `{"all_tenants":false,"tenant_scope_ids":[]}`, write,
			http.StatusUnprocessableEntity, "plugin_installation_targets_invalid"},
		"non canonical id": {platform, http.MethodPut, base + "/targets",
			`{"all_tenants":false,"tenant_scope_ids":["` + uuid.NewString()[:8] + `"]}`, write,
			http.StatusUnprocessableEntity, "plugin_installation_targets_invalid"},
		"unknown field": {platform, http.MethodPut, base + "/targets", `{"all_tenants":true,"tenant_scope_ids":[],"x":1}`, write,
			http.StatusBadRequest, "invalid_request"},
		"missing if-match": {platform, http.MethodPut, base + "/targets", `{"all_tenants":true,"tenant_scope_ids":[]}`,
			map[string]string{"Idempotency-Key": "targets-1"}, http.StatusBadRequest, "invalid_request"},
		"missing idempotency key": {platform, http.MethodPut, base + "/targets", `{"all_tenants":true,"tenant_scope_ids":[]}`,
			map[string]string{"If-Match": `"1"`}, http.StatusBadRequest, "invalid_request"},
		"read permission cannot change targets": {identity.Principal{UserID: uuid.New(), ScopeID: platformScope,
			ScopeKind: ScopePlatform, Permissions: []string{PermissionPlatformRead}}, http.MethodPut, base + "/targets",
			`{"all_tenants":true,"tenant_scope_ids":[]}`, write, http.StatusForbidden, "permission_denied"},
		"targets on a non-confirm action": {platform, http.MethodPost, base + "/upgrade",
			`{` + approval + `,"targets":{"all_tenants":true,"tenant_scope_ids":[]}}`, write,
			http.StatusBadRequest, "invalid_request"},
		"tenant route has no targets": {tenant, http.MethodPut,
			"/v1/tenant-scopes/" + tenantScope.String() + "/plugin-installations/" + authorizationID.String() + "/targets",
			`{"all_tenants":true,"tenant_scope_ids":[]}`, write, http.StatusNotFound, "not_found"},
		"tenant confirm carries no targets": {tenant, http.MethodPost,
			"/v1/tenant-scopes/" + tenantScope.String() + "/plugin-installations/" + authorizationID.String() + "/confirm",
			`{` + approval + `,"targets":{"all_tenants":true,"tenant_scope_ids":[]}}`, write,
			http.StatusBadRequest, "invalid_request"},
		"post on targets": {platform, http.MethodPost, base + "/targets", `{"all_tenants":true,"tenant_scope_ids":[]}`, write,
			http.StatusNotFound, "not_found"},
	} {
		t.Run(name, func(t *testing.T) {
			response, domain := run(test.principal, test.method, test.path, test.body, test.headers)
			assertHandlerError(t, response, test.status, test.code)
			if domain.calls != 0 {
				t.Fatalf("domain called %d times", domain.calls)
			}
		})
	}

	// Domain refusals map to stable codes.
	for err, want := range map[error]struct {
		status int
		code   string
	}{
		ErrPlatformManaged:  {http.StatusForbidden, "plugin_installation_platform_managed"},
		ErrTargetsInvalid:   {http.StatusUnprocessableEntity, "plugin_installation_targets_invalid"},
		ErrRevisionConflict: {http.StatusConflict, "plugin_installation_revision_conflict"},
	} {
		domain := &targetsTestDomain{handlerTestDomain: handlerTestDomain{err: err}}
		handler, _ := NewHandler(HandlerDependencies{
			AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
				return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: platform}, nil
			}, Domain: domain})
		request := authenticatedHandlerRequest(http.MethodPut, base+"/targets", bytes.NewBufferString(`{"all_tenants":true,"tenant_scope_ids":[]}`))
		request.Header.Set("Content-Type", "application/json")
		for name, value := range write {
			request.Header.Set(name, value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertHandlerError(t, response, want.status, want.code)
	}
}
