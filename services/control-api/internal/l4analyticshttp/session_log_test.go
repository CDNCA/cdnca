package l4analyticshttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analytics"
	"github.com/google/uuid"
)

type sessionLogReaderStub struct {
	readerStub
	query l4analytics.SessionLogQuery
	err   error
}

func (stub *sessionLogReaderStub) ReadSessionLogs(_ context.Context, actor l4analytics.Actor, query l4analytics.SessionLogQuery) (l4analytics.SessionLogResponse, error) {
	stub.actor, stub.query = actor, query
	return l4analytics.SessionLogResponse{Version: l4analytics.SessionLogVersion, Rows: []l4analytics.SessionLogRow{}}, stub.err
}

func TestL4SessionLogRoutes(t *testing.T) {
	tenant := uuid.MustParse(tenantID)
	principal := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenant,
		Permissions: []string{l4analytics.ReadPermission}}
	reader := &sessionLogReaderStub{}
	handler, err := NewHandler(reader, func(*http.Request) (identity.Principal, error) { return principal, nil }, Config{})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/analytics/l4-session-logs?range=1h&timezone=UTC&stream_id="+streamID+
		"&client_ip=203.0.113.0/24&end_reason=rate_limited&listen_port=443&limit=50", nil))
	if recorder.Code != http.StatusOK || reader.query.TenantID != tenantID || reader.query.StreamID != streamID ||
		reader.query.ClientIP != "203.0.113.0/24" || reader.query.EndReason != "rate_limited" || reader.query.ListenPort != 443 ||
		!strings.Contains(recorder.Body.String(), l4analytics.SessionLogVersion) {
		t.Fatalf("status=%d query=%+v body=%s", recorder.Code, reader.query, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/analytics/l4-realtime?range=1h&timezone=UTC&client_ip=1.1.1.1", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("realtime accepted client_ip: %d", recorder.Code)
	}
	reader.err = l4analytics.ErrSessionLogUnavailable
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/analytics/l4-session-logs?range=1h&timezone=UTC", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "l4_session_log_unavailable") {
		t.Fatalf("unavailable: %d %s", recorder.Code, recorder.Body.String())
	}
}

// The platform access log needs no tenant: platform.admin reads every
// tenant's logs; tenant_id and node_id only narrow.
func TestPlatformL4SessionLogRouteAllowsGlobalScope(t *testing.T) {
	principal := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	reader := &sessionLogReaderStub{}
	handler, err := NewHandler(reader, func(*http.Request) (identity.Principal, error) { return principal, nil }, Config{})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/l4-session-logs?range=1h&timezone=UTC&limit=50", nil))
	if recorder.Code != http.StatusOK || reader.actor.ScopeKind != "platform" || reader.query.TenantID != "" || reader.query.NodeID != "" {
		t.Fatalf("status=%d actor=%+v query=%+v", recorder.Code, reader.actor, reader.query)
	}
	node := "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/l4-session-logs?range=1h&timezone=UTC&tenant_id="+tenantID+"&node_id="+node, nil))
	if recorder.Code != http.StatusOK || reader.query.TenantID != tenantID || reader.query.NodeID != node {
		t.Fatalf("status=%d query=%+v", recorder.Code, reader.query)
	}
}
