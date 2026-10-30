package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analyticshttp"
	"github.com/google/uuid"
)

type l4RealtimeSourceFunc func(context.Context, l4analytics.Scope, l4analytics.Filter) (l4analytics.Page, error)

func (source l4RealtimeSourceFunc) Read(ctx context.Context, scope l4analytics.Scope, filter l4analytics.Filter) (l4analytics.Page, error) {
	return source(ctx, scope, filter)
}

func TestL4RealtimeMountedErrorsKeepRequestContextID(t *testing.T) {
	now := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	tenantID, streamID, nodeID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, audience := range []string{"tenant", "platform"} {
		path := "/v1/analytics/l4-realtime"
		if audience == "platform" {
			path = "/v1/admin/analytics/l4-realtime"
		}
		for _, test := range []struct {
			name, query, header, code string
			status, maxResponse       int
			unauthenticated, denied   bool
			dependencyFailure         bool
			readSource                bool
		}{
			{name: "success", header: "client-request-1", status: 200, readSource: true},
			{name: "invalid handler query", query: "&limit=0", header: "client-request-2", status: 400, code: "l4_analytics_invalid_request"},
			{name: "invalid service query", query: "&protocol=invalid", status: 400, code: "l4_analytics_invalid_request"},
			{name: "invalid cursor", query: "&cursor=invalid", status: 400, code: "l4_analytics_invalid_cursor"},
			{name: "unauthenticated", unauthenticated: true, header: "client-request-3", status: 401, code: "l4_analytics_unauthenticated"},
			{name: "forbidden", denied: true, status: 403, code: "l4_analytics_forbidden"},
			{name: "dependency failed", dependencyFailure: true, header: "client-request-4", status: 503, code: "l4_analytics_dependency_unavailable", readSource: true},
			{name: "invalid input request ID", dependencyFailure: true, header: "untrusted/request/id", status: 503, code: "l4_analytics_dependency_unavailable", readSource: true},
			{name: "oversized response", maxResponse: 512, status: 500, code: "l4_analytics_response_too_large", readSource: true},
		} {
			t.Run(audience+"/"+test.name, func(t *testing.T) {
				var authRequestID, sourceRequestID string
				sourceCalls := 0
				source := l4RealtimeSourceFunc(func(ctx context.Context, scope l4analytics.Scope, filter l4analytics.Filter) (l4analytics.Page, error) {
					sourceCalls++
					sourceRequestID = requestID(ctx)
					if audience == "tenant" && scope.TenantID != tenantID.String() {
						t.Errorf("source tenant = %q", scope.TenantID)
					}
					if test.dependencyFailure {
						return l4analytics.Page{}, errors.New("private dependency failure")
					}
					return l4analytics.Page{
						Snapshot: l4analytics.Snapshot{At: now, SourceWatermark: 1, FinalizedThrough: now.Add(-time.Second)},
						Rows: []l4analytics.Row{{Bucket: now.Add(-time.Minute), NodeID: nodeID.String(), SiteID: siteID.String(),
							StreamID: streamID.String(), ListenerID: streamID.String(), Protocol: "tcp", ListenPort: 443, Sessions: 3}},
					}, nil
				})
				service, err := l4analytics.NewService(source, l4analytics.Config{Now: func() time.Time { return now }, CursorKey: bytes.Repeat([]byte{0x51}, 32)})
				if err != nil {
					t.Fatal(err)
				}
				handler, err := l4analyticshttp.NewHandler(service, func(request *http.Request) (identity.Principal, error) {
					authRequestID = requestID(request.Context())
					if test.unauthenticated {
						return identity.Principal{}, identity.ErrInvalidSession
					}
					principal := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: audience}
					if audience == "tenant" {
						principal.TenantID = &tenantID
						principal.Permissions = []string{l4analytics.ReadPermission}
					} else {
						principal.Permissions = []string{"platform.admin"}
					}
					if test.denied {
						principal.Permissions = nil
					}
					return principal, nil
				}, l4analyticshttp.Config{MaxResponseBytes: test.maxResponse})
				if err != nil {
					t.Fatal(err)
				}
				api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), L4AnalyticsHandler: handler})
				if err := api.InitializationError(); err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodGet, path+"?range=1h&timezone=UTC"+test.query, nil)
				request.Header.Set("X-Request-ID", test.header)
				response := httptest.NewRecorder()
				api.Handler().ServeHTTP(response, request)
				if response.Code != test.status {
					t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
				}
				id := response.Header().Get("X-Request-ID")
				if !requestIDPattern.MatchString(id) || id != authRequestID || (test.readSource && (sourceCalls != 1 || sourceRequestID != id)) || (!test.readSource && sourceCalls != 0) {
					t.Fatalf("header ID=%q auth ID=%q source ID=%q calls=%d", id, authRequestID, sourceRequestID, sourceCalls)
				}
				if requestIDPattern.MatchString(test.header) && id != test.header {
					t.Fatalf("valid client request ID replaced: %q", id)
				}
				if test.code == "" {
					var body l4analytics.Response
					if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Totals.Sessions != 3 || len(body.Rows) != 1 {
						t.Fatalf("successful response=%+v err=%v", body, err)
					}
					return
				}
				var body errorEnvelope
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Error.Code != test.code || body.Error.RequestID != id || body.Error.Message == "" {
					t.Fatalf("error body=%+v header ID=%q err=%v", body, id, err)
				}
				if response.Header().Get("Content-Type") != "application/json" || strings.Contains(response.Body.String(), "private dependency failure") {
					t.Fatalf("unsafe response: %s", response.Body.String())
				}
			})
		}
	}
}
