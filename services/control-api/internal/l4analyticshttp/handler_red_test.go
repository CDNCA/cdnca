package l4analyticshttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analytics"
	"github.com/google/uuid"
)

const (
	tenantID = "018f47a2-5b9c-7d31-8a60-104c9c0b7102"
	siteID   = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
	streamID = "018f47a2-5b9c-7d31-8a60-104c9c0b7104"
)

type readerStub struct {
	actor l4analytics.Actor
	query l4analytics.Query
}

func (stub *readerStub) Read(_ context.Context, actor l4analytics.Actor, query l4analytics.Query) (l4analytics.Response, error) {
	stub.actor, stub.query = actor, query
	return l4analytics.Response{
		Version: l4analytics.Version,
		Meta: l4analytics.Meta{Range: "1h", Timezone: "UTC", From: time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC),
			To: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC), Snapshot: l4analytics.Snapshot{SourceWatermark: 9}},
		Totals: l4analytics.Totals{Sessions: 2, BytesUp: 10, BytesDown: 20, Errors: 1}, Rows: []l4analytics.Row{},
	}, nil
}

func TestTenantL4RealtimeRouteDerivesScopeAndResponseContract(t *testing.T) {
	tenant := uuid.MustParse(tenantID)
	principal := identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenant,
		Permissions: []string{l4analytics.ReadPermission},
	}
	reader := &readerStub{}
	handler, err := NewHandler(reader, func(*http.Request) (identity.Principal, error) { return principal, nil }, Config{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/l4-realtime?range=1h&timezone=UTC&site_id="+siteID+"&stream_id="+streamID+"&listen_port=443&limit=50", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || reader.actor.TenantID != tenantID || reader.query.TenantID != tenantID ||
		reader.query.SiteID != siteID || reader.query.StreamID != streamID || reader.query.ListenPort != 443 || reader.query.Limit != 50 {
		t.Fatalf("status=%d actor=%#v query=%#v body=%s", recorder.Code, reader.actor, reader.query, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body["version"] != l4analytics.Version {
		t.Fatalf("response contract = %#v error=%v", body, err)
	}

	for _, target := range []string{
		"/v1/analytics/l4-realtime?tenant_id=" + tenantID + "&range=1h&timezone=UTC",
		"/v1/admin/analytics/l4-realtime?tenant_id=" + tenantID + "&range=1h&timezone=UTC",
	} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("tenant cross-scope target %q status=%d body=%s", target, recorder.Code, recorder.Body.String())
		}
	}
}

func TestPlatformL4RealtimeRouteAllowsGlobalScope(t *testing.T) {
	principal := identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
		Permissions: []string{"platform.admin"},
	}
	reader := &readerStub{}
	handler, err := NewHandler(reader, func(*http.Request) (identity.Principal, error) { return principal, nil }, Config{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/l4-realtime?range=1h&timezone=UTC&limit=100", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || reader.actor.ScopeKind != "platform" || reader.query.TenantID != "" || reader.query.Limit != 100 {
		t.Fatalf("status=%d actor=%#v query=%#v body=%s", recorder.Code, reader.actor, reader.query, recorder.Body.String())
	}
}
