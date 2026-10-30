package ccstatshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
)

type fakeReader struct {
	calls        int
	tenant, site uuid.UUID
	from, to     time.Time
	step         time.Duration
	err          error
}

func (reader *fakeReader) SiteCCStats(_ context.Context, tenant, site uuid.UUID, from, to time.Time, step time.Duration) (securityanalytics.CCSiteStats, error) {
	reader.calls++
	reader.tenant, reader.site, reader.from, reader.to, reader.step = tenant, site, from, to, step
	if reader.err != nil {
		return securityanalytics.CCSiteStats{}, reader.err
	}
	return securityanalytics.CCSiteStats{SiteID: site, From: from, To: to, StepSeconds: int64(step / time.Second),
		Series: []securityanalytics.CCStatPoint{{At: from, CCCounts: securityanalytics.CCCounts{Matched: 3, Blocked: 1}}},
		Rules:  []securityanalytics.CCRuleTotal{}, TopClients: []securityanalytics.CCTopValue{{Value: "198.51.100.7", Count: 1}},
		TopPaths: []securityanalytics.CCTopValue{}}, nil
}

func TestHandler(t *testing.T) {
	tenant, otherTenant, site := uuid.New(), uuid.New(), uuid.New()
	tenantID := uuid.New() // tenants.id 与 access_scopes.id 不同（001_identity）
	sessions := map[string]identity.Principal{
		"tenant":  {UserID: uuid.New(), ScopeID: tenant, ScopeKind: "tenant", TenantID: &tenantID, Permissions: []string{PermissionRead}},
		"noperm":  {UserID: uuid.New(), ScopeID: tenant, ScopeKind: "tenant", TenantID: &tenantID},
		"admin":   {UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionAdmin, PermissionRead}},
		"adminro": {UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionRead}},
	}
	reader := &fakeReader{}
	now := time.Date(2026, 10, 19, 14, 37, 12, 0, time.UTC)
	siteErr := error(nil)
	handler, err := NewHandler(Dependencies{Reader: reader, Now: func() time.Time { return now },
		SiteExists: func(_ context.Context, scope, id uuid.UUID) (bool, error) {
			return scope == tenant && id == site, siteErr
		},
		AuthenticateSession: func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
			principal, ok := sessions[token]
			if !ok {
				return identity.AuthenticatedSession{}, identity.ErrInvalidSession
			}
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, target, token string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, target, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	tenantURL := TenantRoute + "?site_id=" + site.String()
	adminURL := AdminRoute + "?tenant_scope_id=" + tenant.String() + "&site_id=" + site.String()

	response := do(http.MethodGet, tenantURL, "tenant")
	if response.Code != http.StatusOK {
		t.Fatalf("tenant: %d %s", response.Code, response.Body)
	}
	var body Response
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.TenantScopeID != tenant || body.Range != "1h" ||
		body.StepSeconds != 60 || len(body.Series) != 1 || body.Series[0].Matched != 3 {
		t.Fatalf("body = %s", response.Body)
	}
	if want := time.Date(2026, 10, 19, 14, 38, 0, 0, time.UTC); !reader.to.Equal(want) || !reader.from.Equal(want.Add(-time.Hour)) ||
		reader.tenant != tenant || reader.site != site {
		t.Fatalf("read %v..%v", reader.from, reader.to)
	}
	if response := do(http.MethodGet, adminURL+"&range=24h", "admin"); response.Code != http.StatusOK || reader.step != 15*time.Minute ||
		!reader.to.Equal(time.Date(2026, 10, 19, 14, 45, 0, 0, time.UTC)) {
		t.Fatalf("admin: %d %s %v", response.Code, response.Body, reader.to)
	}

	calls := reader.calls
	for name, test := range map[string]struct {
		method, target, token string
		status                int
	}{
		"no token":              {http.MethodGet, tenantURL, "", http.StatusUnauthorized},
		"bad token":             {http.MethodGet, tenantURL, "nope", http.StatusUnauthorized},
		"no permission":         {http.MethodGet, tenantURL, "noperm", http.StatusForbidden},
		"admin on tenant route": {http.MethodGet, tenantURL, "admin", http.StatusForbidden},
		"tenant on admin route": {http.MethodGet, adminURL, "tenant", http.StatusForbidden},
		"admin without admin":   {http.MethodGet, adminURL, "adminro", http.StatusForbidden},
		"tenant scope param":    {http.MethodGet, tenantURL + "&tenant_scope_id=" + otherTenant.String(), "tenant", http.StatusBadRequest},
		"unknown range":         {http.MethodGet, tenantURL + "&range=7d", "tenant", http.StatusBadRequest},
		"site id not canonical": {http.MethodGet, TenantRoute + "?site_id=" + site.String()[:35], "tenant", http.StatusBadRequest},
		"other tenant's site":   {http.MethodGet, AdminRoute + "?tenant_scope_id=" + otherTenant.String() + "&site_id=" + site.String(), "admin", http.StatusNotFound},
		"unknown site":          {http.MethodGet, TenantRoute + "?site_id=" + uuid.NewString(), "tenant", http.StatusNotFound},
		"post":                  {http.MethodPost, tenantURL, "tenant", http.StatusMethodNotAllowed},
		"other path":            {http.MethodGet, TenantRoute + "/x", "tenant", http.StatusNotFound},
	} {
		if response := do(test.method, test.target, test.token); response.Code != test.status {
			t.Errorf("%s: %d %s", name, response.Code, response.Body)
		}
	}
	if reader.calls != calls {
		t.Errorf("rejected requests read ClickHouse")
	}
	reader.err = errors.New("down")
	if response := do(http.MethodGet, tenantURL, "tenant"); response.Code != http.StatusServiceUnavailable {
		t.Errorf("reader failure: %d", response.Code)
	}
	reader.err, siteErr = nil, errors.New("pg down")
	if response := do(http.MethodGet, tenantURL, "tenant"); response.Code != http.StatusServiceUnavailable {
		t.Errorf("site lookup failure: %d", response.Code)
	}
}
