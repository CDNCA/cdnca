package analyticslog

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 73 用户端访问日志页 GET /v1/analytics/logs/access/exports?from=&to=（LOG-01 按查询范围
// 找回申请）稳定 400 analytics_logs_invalid_request：生产包装层 authorizationFor 对所有导出路由用
// parseExportScope（只接受 tenant_id），带查询条件的列表在进 handler 之前就被拒。
func TestAuthorizationForScopedExportList(t *testing.T) {
	collection := handlerRoute{audience: AudienceTenant, kind: routeAccessExportCollection}
	list := httptest.NewRequest(http.MethodGet,
		"/v1/analytics/logs/access/exports?from=2026-10-30T16%3A00%3A00.000Z&to=2026-10-31T16%3A00%3A00.000Z&site_id=018f0000-0000-7000-8000-000000000020", nil)
	authorization, err := authorizationFor(list, collection)
	if err != nil {
		t.Fatalf("scoped tenant list authorizationFor() error = %v", err)
	}
	if authorization.Audience != AudienceTenant || authorization.TenantID != "" ||
		authorization.SiteID != "018f0000-0000-7000-8000-000000000020" || authorization.Permission != ReadPermission {
		t.Fatalf("scoped tenant list authorization = %#v", authorization)
	}

	tenant := "018f0000-0000-7000-8000-000000000010"
	platform := handlerRoute{audience: AudiencePlatform, kind: routeAccessExportCollection}
	scoped := httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/logs/access/exports?tenant_id="+tenant+
		"&from=2026-10-30T16:00:00Z&to=2026-10-30T18:00:00Z", nil)
	if authorization, err := authorizationFor(scoped, platform); err != nil || authorization.TenantID != tenant {
		t.Fatalf("scoped platform list = (%#v, %v)", authorization, err)
	}

	for name, request := range map[string]*http.Request{
		"tenant names tenant":    httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/exports?tenant_id="+tenant+"&from=2026-10-30T16:00:00Z&to=2026-10-30T18:00:00Z", nil),
		"window over 31 days":    httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/exports?from=2026-08-01T00:00:00Z&to=2026-10-30T00:00:00Z", nil),
		"limit not accepted":     httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/exports?limit=1&from=2026-10-30T16:00:00Z&to=2026-10-30T18:00:00Z", nil),
		"create keeps tenant_id": httptest.NewRequest(http.MethodPost, "/v1/analytics/logs/access/exports?from=2026-10-30T16:00:00Z", nil),
	} {
		if _, err := authorizationFor(request, collection); err == nil {
			t.Errorf("%s: authorizationFor() accepted", name)
		} else if name == "tenant names tenant" && !errors.Is(err, ErrScopeForbidden) {
			t.Errorf("%s: error = %v, want scope forbidden", name, err)
		}
	}
	if _, err := authorizationFor(httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/exports", nil), collection); err != nil {
		t.Fatalf("plain list authorizationFor() error = %v", err)
	}
}
