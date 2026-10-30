package securitycoordmetricshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetrics"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

func TestHandlerReturnsOnlyBoundedPlatformSecurityCoordinationMetrics(t *testing.T) {
	ccRegistry := securitycoordmetrics.NewRegistry()
	ccRegistry.RecordCCObserve(securitycoordmetrics.CCObserve{Accepted: 3, Rejected: 1, Reason: securitycoordmetrics.ReasonCapacityRejected})
	ccRegistry.RecordFirewallDispatch(securitycoordmetrics.FirewallDispatch{Published: 9})
	firewallRegistry := securitycoordmetrics.NewRegistry()
	firewallRegistry.RecordCCObserve(securitycoordmetrics.CCObserve{Accepted: 8})
	firewallRegistry.RecordFirewallDispatch(securitycoordmetrics.FirewallDispatch{Claimed: 2, Published: 1, Duplicates: 1})
	handler, err := NewHandler(metricsDependencies(ccRegistry, firewallRegistry, platformMetricsSession))
	if err != nil {
		t.Fatal(err)
	}
	request := metricsRequest(http.MethodGet)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Pragma") != "no-cache" || response.Header().Get("X-Content-Type-Options") != "nosniff" ||
		response.Header().Get("X-Request-ID") != "security-metrics-request-1" {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var body struct {
		Schema   string            `json:"schema"`
		CC       map[string]uint64 `json:"cc"`
		Firewall map[string]uint64 `json:"firewall"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Schema != SchemaVersion || body.CC["accepted"] != 3 || body.CC["capacity_rejected"] != 1 ||
		body.Firewall["published"] != 1 || body.Firewall["puback_duplicates"] != 1 {
		t.Fatalf("body = %#v", body)
	}
	for _, forbidden := range []string{"node_id", "policy_id", "subject", "tenant_id", "client_cidr"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("response exposed %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestHandlerRequiresLivePlatformAdminAndSecurityPolicyRead(t *testing.T) {
	tests := []struct {
		name          string
		auth          AuthenticateSessionFunc
		authorization string
		status        int
		code          string
	}{
		{name: "api key", auth: platformMetricsSession, authorization: "ApiKey secret", status: 401, code: "security_coordination_metrics_authentication_required"},
		{name: "tenant", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			tenantID := uuid.New()
			return metricsSession("tenant", &tenantID, []string{"platform.admin", "security_policies.read"}), nil
		}, authorization: "Bearer live-session", status: 403, code: "security_coordination_metrics_permission_denied"},
		{name: "missing explicit read", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return metricsSession("platform", nil, []string{"platform.admin"}), nil
		}, authorization: "Bearer live-session", status: 403, code: "security_coordination_metrics_permission_denied"},
		{name: "missing platform admin", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return metricsSession("platform", nil, []string{"security_policies.read"}), nil
		}, authorization: "Bearer live-session", status: 403, code: "security_coordination_metrics_permission_denied"},
		{name: "revoked", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}, authorization: "Bearer revoked", status: 401, code: "security_coordination_metrics_authentication_required"},
		{name: "disabled", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{}, identity.ErrAccountDisabled
		}, authorization: "Bearer disabled", status: 401, code: "security_coordination_metrics_authentication_required"},
		{name: "identity unavailable", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{}, errors.New("identity unavailable")
		}, authorization: "Bearer live-session", status: 503, code: "security_coordination_metrics_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := securitycoordmetrics.NewRegistry()
			handler, err := NewHandler(metricsDependencies(registry, registry, test.auth))
			if err != nil {
				t.Fatal(err)
			}
			request := metricsRequest(http.MethodGet)
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestHandlerRejectsAPIKeyAlongsideValidBearerBeforeDependencies(t *testing.T) {
	notCalled := func() securitycoordmetrics.Snapshot {
		t.Fatal("snapshot dependency was called")
		return securitycoordmetrics.Snapshot{}
	}
	handler, err := NewHandler(Dependencies{
		CCSnapshot: notCalled, FirewallSnapshot: notCalled,
		AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			t.Fatal("authentication dependency was called")
			return identity.AuthenticatedSession{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := metricsRequest(http.MethodGet)
	request.Header.Set("X-API-Key", "ambiguous")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"security_coordination_metrics_authentication_required"`) {
		t.Fatalf("response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerRejectsEveryNonCanonicalReadShape(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
		code   string
	}{
		{name: "method", mutate: func(r *http.Request) { r.Method = http.MethodPost }, status: 405, code: "security_coordination_metrics_method_not_allowed"},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "node_id=forbidden" }, status: 400, code: "security_coordination_metrics_invalid_request"},
		{name: "body", mutate: func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 2 }, status: 400, code: "security_coordination_metrics_invalid_request"},
		{name: "duplicate request id", mutate: func(r *http.Request) { r.Header.Add("X-Request-ID", "duplicate") }, status: 400, code: "security_coordination_metrics_invalid_request"},
		{name: "actor spoof", mutate: func(r *http.Request) { r.Header.Set("X-Scope-Kind", "platform") }, status: 400, code: "security_coordination_metrics_invalid_request"},
		{name: "route", mutate: func(r *http.Request) { r.URL.Path += "/extra" }, status: 404, code: "security_coordination_metrics_not_found"},
	}
	registry := securitycoordmetrics.NewRegistry()
	handler, err := NewHandler(metricsDependencies(registry, registry, platformMetricsSession))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := metricsRequest(http.MethodGet)
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("response = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestNewHandlerFailsClosedForMissingProductionDependencies(t *testing.T) {
	for _, dependencies := range []Dependencies{
		{},
		{CCSnapshot: func() securitycoordmetrics.Snapshot { return securitycoordmetrics.Snapshot{} }, AuthenticateSession: platformMetricsSession},
		{FirewallSnapshot: func() securitycoordmetrics.Snapshot { return securitycoordmetrics.Snapshot{} }, AuthenticateSession: platformMetricsSession},
		{CCSnapshot: func() securitycoordmetrics.Snapshot { return securitycoordmetrics.Snapshot{} }, FirewallSnapshot: func() securitycoordmetrics.Snapshot { return securitycoordmetrics.Snapshot{} }},
	} {
		if handler, err := NewHandler(dependencies); handler != nil || !errors.Is(err, ErrInvalidDependencies) {
			t.Fatalf("NewHandler() = (%v, %v)", handler, err)
		}
	}
}

func TestOpenAPIFragmentDeclaresOnlyBearerPlatformMetricsRead(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/control-security-coordination-metrics.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	paths, ok := document["paths"].(map[string]any)
	if !ok || len(paths) != 1 {
		t.Fatalf("paths = %#v", document["paths"])
	}
	path, ok := paths[Route].(map[string]any)
	if !ok {
		t.Fatalf("route = %#v", paths[Route])
	}
	get, ok := path["get"].(map[string]any)
	if !ok || get["operationId"] != "getSecurityCoordinationMetrics" {
		t.Fatalf("get = %#v", path["get"])
	}
	permissions, ok := get["x-required-permissions"].([]any)
	if !ok || len(permissions) != 2 || permissions[0] != "platform.admin" || permissions[1] != PermissionRead {
		t.Fatalf("permissions = %#v", get["x-required-permissions"])
	}
	components, ok := document["components"].(map[string]any)
	if !ok {
		t.Fatal("components are missing")
	}
	schemes, ok := components["securitySchemes"].(map[string]any)
	if !ok || len(schemes) != 1 || schemes["bearerSession"] == nil {
		t.Fatalf("security schemes = %#v", components["securitySchemes"])
	}
	for _, forbidden := range []string{"cdncaApiKey", "node_id:", "policy_id:", "subject:", "tenant_id:", "client_cidr:"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("fragment exposed %q", forbidden)
		}
	}
}

func metricsRequest(method string) *http.Request {
	request := httptest.NewRequest(method, "/v1/admin/security/coordination/metrics", nil)
	request.Header.Set("Authorization", "Bearer live-session")
	request.Header.Set("X-Request-ID", "security-metrics-request-1")
	return request
}

func platformMetricsSession(ctx context.Context, raw string) (identity.AuthenticatedSession, error) {
	if ctx == nil || raw != "live-session" {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	return metricsSession("platform", nil, []string{"platform.admin", "security_policies.read"}), nil
}

func metricsDependencies(cc, firewall *securitycoordmetrics.Registry, auth AuthenticateSessionFunc) Dependencies {
	return Dependencies{CCSnapshot: cc.Snapshot, FirewallSnapshot: firewall.Snapshot, AuthenticateSession: auth}
}

func metricsSession(kind string, tenantID *uuid.UUID, permissions []string) identity.AuthenticatedSession {
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: kind, TenantID: tenantID, Permissions: permissions,
	}}
}
