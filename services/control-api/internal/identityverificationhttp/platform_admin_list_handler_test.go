package identityverificationhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

// 管理端加实名审核入口：平台管理员跨租户列出实名申请。
// 只认平台会话；租户会话 403；不接受 tenant_scope_id；游标绑定平台 scope。
func TestHandlerPlatformAdminListsCasesAcrossTenants(t *testing.T) {
	platformUser, platformScope, tenantScope := uuid.New(), uuid.New(), uuid.New()
	created := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	var seen []identityverification.PlatformAdmin
	reader := &readerStub{listAdmin: func(_ context.Context, admin identityverification.PlatformAdmin,
		query CasePageQuery,
	) ([]AdminCaseSummary, error) {
		seen = append(seen, admin)
		if query.Status != identityverification.StatusSubmitted || query.Limit != 2 {
			t.Fatalf("admin list query = %#v", query)
		}
		return []AdminCaseSummary{{CaseSummary: CaseSummary{ID: uuid.New(), ApplicantUserID: uuid.New(),
			Kind: identityverification.KindPersonalInitial, Status: query.Status, Revision: 2,
			CreatedAt: created, StateChangedAt: created},
			TenantScopeID: tenantScope, TenantName: "Tenant A", ApplicantUsername: "alice"}}, nil
	}}
	service := testService(t, &coreStub{}, reader, resolverStub{})
	platform, err := newHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
			UserID: platformUser, ScopeID: platformScope, ScopeKind: "platform",
		}}, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(handler http.Handler, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		setTestAuthorization(request)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	ok := serve(platform, apiPrefix+"/admin/cases?status=submitted&limit=1")
	if ok.Code != http.StatusOK || len(seen) != 1 {
		t.Fatalf("platform admin list = %d %s", ok.Code, ok.Body.String())
	}
	if seen[0].UserID != platformUser || seen[0].ScopeID != platformScope {
		t.Fatalf("admin = %s / %s", seen[0].UserID, seen[0].ScopeID)
	}
	var page struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &page); err != nil || len(page.Items) != 1 ||
		page.Items[0]["tenant_scope_id"] != tenantScope.String() || page.Items[0]["tenant_name"] != "Tenant A" ||
		page.Items[0]["applicant_username"] != "alice" || page.Items[0]["status"] != "submitted" {
		t.Fatalf("admin page = %s (%v)", ok.Body.String(), err)
	}
	assertAPIError(t, serve(platform, apiPrefix+"/admin/cases?tenant_scope_id="+tenantScope.String()),
		http.StatusBadRequest, "identity_verification_invalid_request")
	assertAPIError(t, serve(platform, apiPrefix+"/admin/cases?status=bogus"),
		http.StatusBadRequest, "identity_verification_invalid_request")
	tenant := testHandler(t, service, testActor())
	assertAPIError(t, serve(tenant, apiPrefix+"/admin/cases"), http.StatusForbidden,
		"identity_verification_permission_denied")
	if len(seen) != 1 {
		t.Fatalf("rejected requests reached the reader: %d", len(seen))
	}
}
