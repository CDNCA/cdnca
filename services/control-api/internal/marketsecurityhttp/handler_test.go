package marketsecurityhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
)

type fakeReader struct {
	calls  int
	tenant uuid.UUID
	filter securityanalytics.MarketSecurityFilter
	after  string
	limit  int
	rows   []securityanalytics.MarketSecurityLog
	err    error
}

func (f *fakeReader) ListMarketSecurityLogs(_ context.Context, tenant uuid.UUID, filter securityanalytics.MarketSecurityFilter,
	_, _ time.Time, after string, limit int) ([]securityanalytics.MarketSecurityLog, error) {
	f.calls++
	f.tenant, f.filter, f.after, f.limit = tenant, filter, after, limit
	return f.rows, f.err
}

func TestHandler(t *testing.T) {
	tenant, site := uuid.New(), uuid.New()
	sessions := map[string]identity.Principal{
		"tenant": {UserID: uuid.New(), ScopeID: tenant, ScopeKind: "tenant", TenantID: &tenant, Permissions: []string{PermissionRead}},
		"noperm": {UserID: uuid.New(), ScopeID: tenant, ScopeKind: "tenant", TenantID: &tenant},
		"admin":  {UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionAdmin}},
	}
	reader := &fakeReader{}
	handler, err := NewHandler(reader, func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
		p, ok := sessions[token]
		if !ok {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: p}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	window := url.Values{"from": {"2026-10-21T00:00:00Z"}, "to": {"2026-10-21T01:00:00Z"}}
	call := func(token, path string, q url.Values) (*httptest.ResponseRecorder, Response) {
		request := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		var body Response
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		return recorder, body
	}
	with := func(extra map[string]string) url.Values {
		q := url.Values{}
		for k, v := range window {
			q[k] = v
		}
		for k, v := range extra {
			q.Set(k, v)
		}
		return q
	}

	rows := make([]securityanalytics.MarketSecurityLog, 3)
	for i := range rows {
		rows[i] = securityanalytics.MarketSecurityLog{SiteID: site, LeafRef: "0123abcd", Cursor: "c" + string(rune('0'+i))}
	}
	reader.rows = rows
	recorder, body := call("tenant", TenantRoute, with(map[string]string{"site_id": site.String(), "client_ip": "::ffff:198.51.100.7",
		"host": "www.example.test", "limit": "2", "cursor": "prev"}))
	if recorder.Code != 200 || len(body.Data) != 2 || body.Meta.NextCursor != "c1" {
		t.Fatalf("tenant page %d %s", recorder.Code, recorder.Body)
	}
	if reader.tenant != tenant || reader.limit != 3 || reader.after != "prev" || reader.filter.Site != site ||
		reader.filter.ClientIP != "198.51.100.7" || reader.filter.Host != "www.example.test" {
		t.Fatalf("reader got %+v", reader)
	}
	reader.rows = rows[:1]
	if recorder, body := call("tenant", TenantRoute, window); recorder.Code != 200 || body.Meta.NextCursor != "" || reader.limit != defaultLimit+1 {
		t.Fatalf("last page %d %s", recorder.Code, recorder.Body)
	}
	other := uuid.New()
	if recorder, _ := call("admin", AdminRoute, with(map[string]string{"tenant_id": other.String()})); recorder.Code != 200 || reader.tenant != other {
		t.Fatalf("admin %d %s", recorder.Code, recorder.Body)
	}
	calls := reader.calls
	for name, c := range map[string]struct {
		token, path string
		q           url.Values
		status      int
	}{
		"anonymous":         {"", TenantRoute, window, 401},
		"no permission":     {"noperm", TenantRoute, window, 403},
		"tenant on admin":   {"tenant", AdminRoute, with(map[string]string{"tenant_id": other.String()}), 403},
		"admin on tenant":   {"admin", TenantRoute, window, 403},
		"tenant picks one":  {"tenant", TenantRoute, with(map[string]string{"tenant_id": other.String()}), 400},
		"admin no tenant":   {"admin", AdminRoute, window, 400},
		"bad window":        {"tenant", TenantRoute, url.Values{"from": {"2026-10-21T01:00:00Z"}, "to": {"2026-10-21T00:00:00Z"}}, 400},
		"window too long":   {"tenant", TenantRoute, url.Values{"from": {"2026-09-01T00:00:00Z"}, "to": {"2026-10-21T00:00:00Z"}}, 400},
		"bad ip":            {"tenant", TenantRoute, with(map[string]string{"client_ip": "x"}), 400},
		"bad host":          {"tenant", TenantRoute, with(map[string]string{"host": "A B"}), 400},
		"bad limit":         {"tenant", TenantRoute, with(map[string]string{"limit": "101"}), 400},
		"unknown parameter": {"tenant", TenantRoute, with(map[string]string{"x": "1"}), 400},
	} {
		if recorder, _ := call(c.token, c.path, c.q); recorder.Code != c.status {
			t.Errorf("%s: %d %s", name, recorder.Code, recorder.Body)
		}
	}
	if reader.calls != calls {
		t.Fatal("rejected requests reached ClickHouse")
	}
	reader.err = securityanalytics.ErrMarketCursor
	if recorder, _ := call("tenant", TenantRoute, window); recorder.Code != 400 {
		t.Fatalf("bad cursor %d", recorder.Code)
	}
}
