package analyticsrealtimehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const (
	testTenantID = "018f0000-0000-7000-8000-000000000001"
	testScopeID  = "018f0000-0000-7000-8000-000000000002"
	testUserID   = "018f0000-0000-7000-8000-000000000003"
	testSiteID   = "018f0000-0000-7000-8000-000000000004"
	testNodeID   = "018f0000-0000-7000-8000-000000000005"
)

type readerStub struct {
	response analyticsrealtime.Response
	err      error
	actor    analyticsrealtime.Actor
	query    analyticsrealtime.Query
	calls    int
}

func (stub *readerStub) Read(
	_ context.Context,
	actor analyticsrealtime.Actor,
	query analyticsrealtime.Query,
) (analyticsrealtime.Response, error) {
	stub.calls++
	stub.actor, stub.query = actor, query
	return stub.response, stub.err
}

func TestHandlerBindsTenantAndPlatformMonitoringScopes(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		principal  identity.Principal
		audience   analyticsrealtime.Audience
		tenantID   string
		permission string
	}{
		{
			name: "tenant identity supplies tenant",
			target: "/v1/analytics/site-monitoring?range=6h&timezone=Asia%2FShanghai&site_id=" + testSiteID +
				"&node_id=" + testNodeID + "&domain=cdn.example.test&listen_port=443&rank_by=host&limit=10",
			principal:  tenantPrincipal("sites.read"),
			audience:   analyticsrealtime.AudienceTenant,
			tenantID:   testTenantID,
			permission: "sites.read",
		},
		{
			name: "platform requires explicit tenant",
			target: "/v1/admin/analytics/site-monitoring?tenant_id=" + testTenantID +
				"&range=custom&from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z&timezone=UTC&rank_by=status_code&limit=10",
			principal:  platformPrincipal("platform.admin"),
			audience:   analyticsrealtime.AudiencePlatform,
			tenantID:   testTenantID,
			permission: "platform.admin",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := new(readerStub)
			handler := newTestHandler(t, reader, test.principal, nil)
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.Header.Set("Authorization", "Bearer session")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if reader.calls != 1 || reader.query.Audience != test.audience || reader.query.TenantID != test.tenantID {
				t.Fatalf("reader actor/query = %#v %#v", reader.actor, reader.query)
			}
			wantActorTenantID := test.tenantID
			if test.audience == analyticsrealtime.AudiencePlatform {
				wantActorTenantID = ""
			}
			if reader.actor.ScopeKind != test.principal.ScopeKind || reader.actor.TenantID != wantActorTenantID ||
				!contains(reader.actor.Permissions, test.permission) {
				t.Fatalf("reader actor = %#v", reader.actor)
			}
			if reader.query.Timezone == "" || reader.query.RankBy == "" || reader.query.Limit != 10 {
				t.Fatalf("reader query = %#v", reader.query)
			}
			for _, field := range []string{"\"meta\"", "\"snapshot_at\"", "\"source_watermark\"", "\"finalized_through\"",
				"\"basic\"", "\"quality\"", "\"origin\"", "\"rank\""} {
				if !strings.Contains(response.Body.String(), field) {
					t.Errorf("response missing %s: %s", field, response.Body.String())
				}
			}
		})
	}
}

func TestHandlerRejectsScopePermissionAndSelfAssertedIdentityBeforeRead(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		principal identity.Principal
		header    string
		want      int
	}{
		{name: "tenant override", target: "/v1/analytics/site-monitoring?tenant_id=" + testTenantID + "&range=1h&timezone=UTC", principal: tenantPrincipal("sites.read"), want: http.StatusForbidden},
		{name: "platform tenant missing", target: "/v1/admin/analytics/site-monitoring?range=1h&timezone=UTC", principal: platformPrincipal("platform.admin"), want: http.StatusBadRequest},
		{name: "tenant permission missing", target: "/v1/analytics/site-monitoring?range=1h&timezone=UTC", principal: tenantPrincipal(), want: http.StatusForbidden},
		{name: "platform permission missing", target: "/v1/admin/analytics/site-monitoring?tenant_id=" + testTenantID + "&range=1h&timezone=UTC", principal: platformPrincipal(), want: http.StatusForbidden},
		{name: "tenant on platform route", target: "/v1/admin/analytics/site-monitoring?tenant_id=" + testTenantID + "&range=1h&timezone=UTC", principal: tenantPrincipal("platform.admin"), want: http.StatusForbidden},
		{name: "platform on tenant route", target: "/v1/analytics/site-monitoring?range=1h&timezone=UTC", principal: platformPrincipal("sites.read"), want: http.StatusForbidden},
		{name: "self asserted tenant", target: "/v1/analytics/site-monitoring?range=1h&timezone=UTC", principal: tenantPrincipal("sites.read"), header: "X-Tenant-ID", want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := new(readerStub)
			handler := newTestHandler(t, reader, test.principal, nil)
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.Header.Set("Authorization", "Bearer session")
			if test.header != "" {
				request.Header.Set(test.header, testTenantID)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || reader.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, reader.calls, response.Body.String())
			}
		})
	}
}

func TestHandlerRejectsNonCanonicalAndAmbiguousQueries(t *testing.T) {
	tests := []string{
		"range=6h&range=12h&timezone=UTC",
		"range=6H&timezone=UTC",
		"range=custom&timezone=UTC",
		"range=custom&from=2026-08-08T01:00:00Z&to=2026-08-08T01:00:00Z&timezone=UTC",
		"range=1h&timezone=Local",
		"range=1h&timezone=UTC&site_id=018F0000-0000-7000-8000-000000000004",
		"range=1h&timezone=UTC&node_id=00000000-0000-0000-0000-000000000000",
		"range=1h&timezone=UTC&domain=CDN.example.test",
		"range=1h&timezone=UTC&listen_port=0",
		"range=1h&timezone=UTC&listen_port=65536",
		"range=1h&timezone=UTC&rank_by=unknown",
		"range=1h&timezone=UTC&limit=0",
		"range=1h&timezone=UTC&limit=101",
		"range=1h&timezone=UTC&cursor=has%20space",
		"range=1h&timezone=UTC&unknown=value",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			reader := new(readerStub)
			handler := newTestHandler(t, reader, tenantPrincipal("sites.read"), nil)
			request := httptest.NewRequest(http.MethodGet, "/v1/analytics/site-monitoring?"+raw, nil)
			request.Header.Set("Authorization", "Bearer session")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || reader.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, reader.calls, response.Body.String())
			}
		})
	}
}

func TestHandlerEnforcesMethodTimeoutAndStableErrors(t *testing.T) {
	reader := new(readerStub)
	handler := newTestHandler(t, reader, tenantPrincipal("sites.read"), nil)
	request := httptest.NewRequest(http.MethodPost, "/v1/analytics/site-monitoring?range=1h&timezone=UTC", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet || reader.calls != 0 {
		t.Fatalf("method status=%d calls=%d body=%s", response.Code, reader.calls, response.Body.String())
	}

	for _, test := range []struct {
		name string
		err  error
		want int
		code string
	}{
		{name: "cancelled", err: context.Canceled, want: http.StatusRequestTimeout, code: "analytics_monitoring_request_cancelled"},
		{name: "timeout", err: context.DeadlineExceeded, want: http.StatusGatewayTimeout, code: "analytics_monitoring_timeout"},
		{name: "dependency", err: errors.New("clickhouse dsn secret"), want: http.StatusServiceUnavailable, code: "analytics_monitoring_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &readerStub{err: test.err}
			handler := newTestHandler(t, reader, tenantPrincipal("sites.read"), nil)
			request := httptest.NewRequest(http.MethodGet, "/v1/analytics/site-monitoring?range=1h&timezone=UTC", nil)
			request.Header.Set("Authorization", "Bearer session")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) ||
				strings.Contains(response.Body.String(), test.err.Error()) {
				t.Fatalf("status/body = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMonitoringOpenAPIIsStandaloneAndComplete(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/control-analytics-realtime.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		OpenAPI string `yaml:"openapi"`
		Paths   map[string]struct {
			Get struct {
				OperationID string               `yaml:"operationId"`
				Permissions []string             `yaml:"x-required-permissions"`
				Responses   map[string]yaml.Node `yaml:"responses"`
			} `yaml:"get"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string             `yaml:"required"`
				Properties map[string]yaml.Node `yaml:"properties"`
				OneOf      []yaml.Node          `yaml:"oneOf"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.OpenAPI != "3.1.0" {
		t.Fatalf("openapi = %q", document.OpenAPI)
	}
	wantPaths := map[string]struct {
		operation  string
		permission string
	}{
		"/v1/analytics/site-monitoring":       {"getTenantSiteMonitoring", "sites.read"},
		"/v1/admin/analytics/site-monitoring": {"getPlatformSiteMonitoring", "platform.admin"},
	}
	for path, want := range wantPaths {
		operation := document.Paths[path].Get
		if operation.OperationID != want.operation || !contains(operation.Permissions, want.permission) {
			t.Errorf("%s operation/permissions = %q %v", path, operation.OperationID, operation.Permissions)
		}
		for _, status := range []string{"200", "400", "401", "403", "405", "408", "502", "503", "504"} {
			if _, ok := operation.Responses[status]; !ok {
				t.Errorf("%s missing response %s", path, status)
			}
		}
	}
	response := document.Components.Schemas["SiteMonitoringResponse"]
	for _, field := range []string{"version", "meta", "basic", "quality", "origin", "rank"} {
		if !contains(response.Required, field) {
			t.Errorf("SiteMonitoringResponse.required = %v, want %s", response.Required, field)
		}
	}
	meta := document.Components.Schemas["SiteMonitoringMeta"]
	for _, field := range []string{"snapshot_at", "source_watermark", "finalized_through", "snapshot_expires_at", "from", "to", "timezone", "bucket", "downsample"} {
		if !contains(meta.Required, field) {
			t.Errorf("SiteMonitoringMeta.required = %v, want %s", meta.Required, field)
		}
	}
	for _, section := range []string{"BasicSection", "QualitySection", "OriginSection", "RankSection"} {
		if len(document.Components.Schemas[section].OneOf) != 2 {
			t.Errorf("%s must expose available and degraded branches", section)
		}
	}
}

func newTestHandler(t *testing.T, reader *readerStub, principal identity.Principal, authErr error) *Handler {
	t.Helper()
	handler, err := NewHandler(reader, func(*http.Request) (identity.Principal, error) {
		return principal, authErr
	}, Config{QueryTimeout: time.Second, MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func tenantPrincipal(permissions ...string) identity.Principal {
	tenantID := uuid.MustParse(testTenantID)
	return identity.Principal{
		UserID: uuid.MustParse(testUserID), ScopeID: uuid.MustParse(testScopeID), ScopeKind: "tenant",
		TenantID: &tenantID, Permissions: permissions,
	}
}

func platformPrincipal(permissions ...string) identity.Principal {
	return identity.Principal{
		UserID: uuid.MustParse(testUserID), ScopeID: uuid.MustParse(testScopeID), ScopeKind: "platform",
		Permissions: permissions,
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
