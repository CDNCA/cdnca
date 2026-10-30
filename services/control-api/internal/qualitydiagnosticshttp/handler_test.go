package qualitydiagnosticshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnostics"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const (
	tenantID = "018f0000-0000-7000-8000-000000000001"
	scopeID  = "018f0000-0000-7000-8000-000000000002"
	userID   = "018f0000-0000-7000-8000-000000000003"
	siteID   = "018f0000-0000-7000-8000-000000000004"
	nodeID   = "018f0000-0000-7000-8000-000000000005"
)

type readerStub struct {
	actor    qualitydiagnostics.Actor
	query    qualitydiagnostics.Query
	response qualitydiagnostics.Response
	err      error
	calls    int
}

func (stub *readerStub) Read(_ context.Context, actor qualitydiagnostics.Actor, query qualitydiagnostics.Query) (qualitydiagnostics.Response, error) {
	stub.calls++
	stub.actor, stub.query = actor, query
	return stub.response, stub.err
}

func TestHandlerBindsTenantAndPlatformScopesAndDoesNotLeakRawFacts(t *testing.T) {
	for _, test := range []struct {
		name      string
		target    string
		principal identity.Principal
		audience  qualitydiagnostics.Audience
	}{
		{
			name: "tenant",
			target: "/v1/analytics/quality-diagnostics?from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z&site_id=" +
				siteID + "&node_id=" + nodeID + "&category=upstream_5xx&limit=20",
			principal: tenantPrincipal("sites.read"), audience: qualitydiagnostics.AudienceTenant,
		},
		{
			name: "platform",
			target: "/v1/admin/analytics/quality-diagnostics?tenant_id=" + tenantID +
				"&from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z&limit=20",
			principal: platformPrincipal("platform.admin"), audience: qualitydiagnostics.AudiencePlatform,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &readerStub{response: responseFixture(test.audience)}
			handler := newTestHandler(t, reader, test.principal, nil)
			response := serve(handler, http.MethodGet, test.target, nil)
			if response.Code != http.StatusOK || reader.calls != 1 || reader.query.Audience != test.audience {
				t.Fatalf("status/calls/query = %d %d %#v body=%s", response.Code, reader.calls, reader.query, response.Body.String())
			}
			wantTenantID := uuid.Nil
			if test.name == "platform" {
				wantTenantID = uuid.MustParse(tenantID)
			}
			if reader.query.TenantID != wantTenantID || reader.query.From.Location() != time.UTC ||
				reader.query.SiteID != func() uuid.UUID {
					if test.name == "tenant" {
						return uuid.MustParse(siteID)
					}
					return uuid.Nil
				}() {
				t.Fatalf("query = %#v", reader.query)
			}
			body := response.Body.String()
			for _, secret := range []string{"Authorization", "Bearer secret", "/private", "203.0.113.9", "upstream raw secret"} {
				if strings.Contains(body, secret) {
					t.Fatalf("response leaked %q: %s", secret, body)
				}
			}
			if !strings.Contains(body, `"items":[`) || !strings.Contains(body, `"next_cursor":null`) {
				t.Fatalf("response shape = %s", body)
			}
			assertNoCacheHeaders(t, response)
		})
	}
}

func TestHandlerRejectsAmbiguousScopeQueryBodyAndMethodBeforeRead(t *testing.T) {
	base := "from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z"
	tests := []struct {
		name      string
		method    string
		target    string
		principal identity.Principal
		body      *strings.Reader
		transfer  bool
		want      int
	}{
		{name: "duplicate", method: http.MethodGet, target: "/v1/analytics/quality-diagnostics?" + base + "&limit=1&limit=2", principal: tenantPrincipal("sites.read"), want: 400},
		{name: "unknown", method: http.MethodGet, target: "/v1/analytics/quality-diagnostics?" + base + "&secret=x", principal: tenantPrincipal("sites.read"), want: 400},
		{name: "tenant override", method: http.MethodGet, target: "/v1/analytics/quality-diagnostics?" + base + "&tenant_id=" + tenantID, principal: tenantPrincipal("sites.read"), want: 403},
		{name: "platform tenant missing", method: http.MethodGet, target: "/v1/admin/analytics/quality-diagnostics?" + base, principal: platformPrincipal("platform.admin"), want: 400},
		{name: "non canonical uuid", method: http.MethodGet, target: "/v1/admin/analytics/quality-diagnostics?" + base + "&tenant_id=018F0000-0000-7000-8000-000000000001", principal: platformPrincipal("platform.admin"), want: 400},
		{name: "sub millisecond", method: http.MethodGet, target: "/v1/analytics/quality-diagnostics?from=2026-08-08T01:00:00.000001Z&to=2026-08-08T02:00:00Z", principal: tenantPrincipal("sites.read"), want: 400},
		{name: "invalid category", method: http.MethodGet, target: "/v1/analytics/quality-diagnostics?" + base + "&category=raw_secret", principal: tenantPrincipal("sites.read"), want: 400},
		{name: "body", method: http.MethodGet, target: "/v1/analytics/quality-diagnostics?" + base, principal: tenantPrincipal("sites.read"), body: strings.NewReader("{}"), want: 400},
		{name: "transfer", method: http.MethodGet, target: "/v1/analytics/quality-diagnostics?" + base, principal: tenantPrincipal("sites.read"), transfer: true, want: 400},
		{name: "method", method: http.MethodPost, target: "/v1/analytics/quality-diagnostics?" + base, principal: tenantPrincipal("sites.read"), want: 405},
		{name: "route", method: http.MethodGet, target: "/v1/analytics/quality-diagnostics/extra?" + base, principal: tenantPrincipal("sites.read"), want: 404},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := new(readerStub)
			handler := newTestHandler(t, reader, test.principal, nil)
			var response *httptest.ResponseRecorder
			if test.transfer {
				request := httptest.NewRequest(test.method, test.target, nil)
				request.TransferEncoding = []string{"chunked"}
				response = httptest.NewRecorder()
				handler.ServeHTTP(response, request)
			} else {
				response = serve(handler, test.method, test.target, test.body)
			}
			if response.Code != test.want || reader.calls != 0 {
				t.Fatalf("status/calls = %d/%d body=%s", response.Code, reader.calls, response.Body.String())
			}
			assertNoCacheHeaders(t, response)
		})
	}
}

func TestHandlerSeparatesPermissionsAndMapsStableErrors(t *testing.T) {
	base := "/v1/analytics/quality-diagnostics?from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z"
	for _, test := range []struct {
		name      string
		principal identity.Principal
		authErr   error
		readErr   error
		want      int
		code      string
	}{
		{name: "tenant permission", principal: tenantPrincipal(), want: 403, code: "quality_diagnostics_permission_denied"},
		{name: "platform principal", principal: platformPrincipal("sites.read"), want: 403, code: "quality_diagnostics_scope_forbidden"},
		{name: "authentication", authErr: identity.ErrInvalidSession, want: 401, code: "quality_diagnostics_authentication_required"},
		{name: "cancelled", principal: tenantPrincipal("sites.read"), readErr: context.Canceled, want: 408, code: "quality_diagnostics_request_cancelled"},
		{name: "deadline", principal: tenantPrincipal("sites.read"), readErr: context.DeadlineExceeded, want: 504, code: "quality_diagnostics_timeout"},
		{name: "invalid cursor", principal: tenantPrincipal("sites.read"), readErr: qualitydiagnostics.ErrInvalidCursor, want: 400, code: "quality_diagnostics_invalid_cursor"},
		{name: "snapshot", principal: tenantPrincipal("sites.read"), readErr: qualitydiagnostics.ErrInvalidSnapshot, want: 409, code: "quality_diagnostics_snapshot_conflict"},
		{name: "unavailable", principal: tenantPrincipal("sites.read"), readErr: qualitydiagnostics.ErrUnavailable, want: 503, code: "quality_diagnostics_unavailable"},
		{name: "raw server", principal: tenantPrincipal("sites.read"), readErr: errors.New("clickhouse password secret"), want: 500, code: "quality_diagnostics_internal_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &readerStub{err: test.readErr}
			handler := newTestHandler(t, reader, test.principal, test.authErr)
			response := serve(handler, http.MethodGet, base, nil)
			if response.Code != test.want || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) ||
				strings.Contains(response.Body.String(), "password secret") {
				t.Fatalf("status/body = %d %s", response.Code, response.Body.String())
			}
			assertNoCacheHeaders(t, response)
		})
	}
}

func TestHandlerConfigTimeoutBoundsAndEmptyResponseShape(t *testing.T) {
	for _, timeout := range []time.Duration{time.Nanosecond, 10*time.Second + time.Nanosecond} {
		if _, err := NewHandler(new(readerStub), func(*http.Request) (identity.Principal, error) {
			return tenantPrincipal("sites.read"), nil
		}, Config{QueryTimeout: timeout}); !errors.Is(err, qualitydiagnostics.ErrInvalidConfiguration) {
			t.Fatalf("timeout %s error = %v", timeout, err)
		}
	}
	reader := &readerStub{response: qualitydiagnostics.Response{
		Items: []qualitydiagnostics.Item{}, Snapshot: analyticsrealtime.Snapshot{},
	}}
	handler, err := NewHandler(reader, func(*http.Request) (identity.Principal, error) {
		return tenantPrincipal("sites.read"), nil
	}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(handler, http.MethodGet,
		"/v1/analytics/quality-diagnostics?from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"items":[]`) ||
		!strings.Contains(response.Body.String(), `"next_cursor":null`) {
		t.Fatalf("empty response = %d %s", response.Code, response.Body.String())
	}
}

func TestQualityDiagnosticsOpenAPIIsStandaloneAndStrict(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/control-quality-diagnostics.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		OpenAPI string `yaml:"openapi"`
		Paths   map[string]struct {
			Get struct {
				OperationID string         `yaml:"operationId"`
				Permissions []string       `yaml:"x-required-permissions"`
				Responses   map[string]any `yaml:"responses"`
			} `yaml:"get"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string       `yaml:"required"`
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.OpenAPI != "3.1.0" || len(document.Paths) != 2 {
		t.Fatalf("openapi/paths = %q %#v", document.OpenAPI, document.Paths)
	}
	want := map[string]struct{ operation, permission string }{
		"/v1/analytics/quality-diagnostics":       {"getTenantQualityDiagnostics", "sites.read"},
		"/v1/admin/analytics/quality-diagnostics": {"getPlatformQualityDiagnostics", "platform.admin"},
	}
	for path, expected := range want {
		operation := document.Paths[path].Get
		if operation.OperationID != expected.operation || len(operation.Permissions) != 1 || operation.Permissions[0] != expected.permission {
			t.Fatalf("%s operation = %#v", path, operation)
		}
		for _, status := range []string{"200", "400", "401", "403", "405", "408", "409", "502", "503", "504"} {
			if _, ok := operation.Responses[status]; !ok {
				t.Errorf("%s missing response %s", path, status)
			}
		}
	}
	item := document.Components.Schemas["QualityDiagnostic"]
	for _, field := range []string{"event_id", "occurred_at", "site_id", "node_id", "category", "cause_code", "action_code", "config_version_id", "installation_id", "request_id", "task_id", "trace_id"} {
		if _, ok := item.Properties[field]; !ok {
			t.Errorf("QualityDiagnostic missing %s", field)
		}
	}
	for _, forbidden := range []string{"host", "uri_path", "client_ip", "request_headers", "response_headers", "request_body", "response_body", "upstream_result"} {
		if _, ok := item.Properties[forbidden]; ok {
			t.Errorf("QualityDiagnostic exposes %s", forbidden)
		}
	}
}

func responseFixture(audience qualitydiagnostics.Audience) qualitydiagnostics.Response {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	taskID := "018f0000-0000-7000-8000-000000000009"
	response := qualitydiagnostics.Response{
		Items: []qualitydiagnostics.Item{{
			EventID: "event-1", OccurredAt: now.Add(-time.Minute), SiteID: siteID, NodeID: nodeID,
			Category: qualitydiagnostics.CategoryUpstream5xx, CauseCode: qualitydiagnostics.CauseUpstreamFailure,
			ActionCode: qualitydiagnostics.ActionInspectUpstream, ConfigVersionID: "018f0000-0000-7000-8000-000000000006",
			InstallationID: "018f0000-0000-7000-8000-000000000007", RequestID: "request-1", TaskID: &taskID, TraceID: "trace-1",
		}},
		Snapshot: analyticsrealtime.Snapshot{At: now, SourceWatermark: 1, FinalizedThrough: now, ExpiresAt: now.Add(time.Minute)},
	}
	if audience == qualitydiagnostics.AudiencePlatform {
		value := tenantID
		response.EffectiveTenantID = &value
	}
	return response
}

func newTestHandler(t *testing.T, reader *readerStub, principal identity.Principal, authErr error) *Handler {
	t.Helper()
	handler, err := NewHandler(reader, func(*http.Request) (identity.Principal, error) {
		return principal, authErr
	}, Config{QueryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serve(handler http.Handler, method, target string, body *strings.Reader) *httptest.ResponseRecorder {
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, body)
	}
	request.Header.Set("Authorization", "Bearer session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func tenantPrincipal(permissions ...string) identity.Principal {
	tenant := uuid.MustParse(tenantID)
	return identity.Principal{
		UserID: uuid.MustParse(userID), ScopeID: uuid.MustParse(scopeID), ScopeKind: "tenant",
		TenantID: &tenant, Permissions: permissions,
	}
}

func platformPrincipal(permissions ...string) identity.Principal {
	return identity.Principal{
		UserID: uuid.MustParse(userID), ScopeID: uuid.MustParse(scopeID), ScopeKind: "platform", Permissions: permissions,
	}
}

func assertNoCacheHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers = %#v", response.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v body=%s", err, response.Body.String())
	}
}
