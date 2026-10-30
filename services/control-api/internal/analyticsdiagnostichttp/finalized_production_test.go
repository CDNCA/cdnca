package analyticsdiagnostichttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostic"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnostics"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnosticshttp"
)

func TestFinalizedProductionPrincipalFailsClosed(t *testing.T) {
	t.Parallel()

	const (
		actorID  = "018f0000-0000-7000-8000-000000000021"
		scopeID  = "018f0000-0000-7000-8000-000000000022"
		tenantID = "018f0000-0000-7000-8000-000000000023"
	)
	tests := []struct {
		name       string
		actor      analyticsdiagnostic.Actor
		wantTenant bool
		wantError  bool
	}{
		{name: "tenant", actor: analyticsdiagnostic.Actor{ScopeKind: "tenant", ActorID: actorID, ScopeID: scopeID, TenantID: tenantID, Permissions: []string{analyticslog.ReadPermission}}, wantTenant: true},
		{name: "platform", actor: analyticsdiagnostic.Actor{ScopeKind: "platform", ActorID: actorID, ScopeID: scopeID, Permissions: []string{"platform.admin"}}},
		{name: "actor UUID", actor: analyticsdiagnostic.Actor{ScopeKind: "tenant", ActorID: "not-a-uuid", ScopeID: scopeID, TenantID: tenantID}, wantError: true},
		{name: "scope UUID", actor: analyticsdiagnostic.Actor{ScopeKind: "tenant", ActorID: actorID, ScopeID: "not-a-uuid", TenantID: tenantID}, wantError: true},
		{name: "tenant UUID", actor: analyticsdiagnostic.Actor{ScopeKind: "tenant", ActorID: actorID, ScopeID: scopeID, TenantID: "not-a-uuid"}, wantError: true},
		{name: "platform tenant", actor: analyticsdiagnostic.Actor{ScopeKind: "platform", ActorID: actorID, ScopeID: scopeID, TenantID: tenantID}, wantError: true},
		{name: "scope kind", actor: analyticsdiagnostic.Actor{ScopeKind: "system", ActorID: actorID, ScopeID: scopeID}, wantError: true},
		{name: "permission", actor: analyticsdiagnostic.Actor{ScopeKind: "tenant", ActorID: actorID, ScopeID: scopeID, TenantID: tenantID, Permissions: []string{" sites.read"}}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			principal, err := finalizedProductionPrincipal(test.actor)
			if test.wantError {
				if !errors.Is(err, identity.ErrInvalidSession) {
					t.Fatalf("error = %v, want invalid session", err)
				}
				return
			}
			if err != nil || principal.UserID.String() != actorID || principal.ScopeID.String() != scopeID ||
				(principal.TenantID != nil) != test.wantTenant || principal.ScopeKind != test.actor.ScopeKind ||
				len(principal.Permissions) != 1 || principal.Permissions[0] != test.actor.Permissions[0] {
				t.Fatalf("principal = %#v, error = %v", principal, err)
			}
		})
	}
}

type finalizedProductionContextKey struct{}

func TestNewFinalizedProductionHandlerRewritesOnlyExactLegacyRoutes(t *testing.T) {
	t.Parallel()

	client, err := analyticslog.NewClient(analyticslog.ClientConfig{
		Endpoint: "http://127.0.0.1:1", Database: "quality_diagnostics_bridge", QueryTimeout: time.Second,
		CursorKeyring: analyticslog.CursorKeyring{ActiveKID: "bridge", Keys: map[string][]byte{
			"bridge": []byte(strings.Repeat("k", 32)),
		}},
	}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	observed := make([]string, 0, 2)
	handler, err := NewFinalizedProductionHandler(client, func(request *http.Request) (analyticsdiagnostic.Actor, error) {
		if request.Header.Get("X-Bridge-Probe") != "preserved" || request.Context().Value(finalizedProductionContextKey{}) != "context" ||
			request.URL.Query().Get("category") != string(qualitydiagnostics.CategoryEdge530) {
			t.Fatalf("request metadata was not preserved: %#v", request)
		}
		observed = append(observed, request.URL.Path)
		return analyticsdiagnostic.Actor{}, identity.ErrInvalidSession
	}, qualitydiagnosticshttp.ProductionConfig{
		Source:  analyticslog.FinalizedAccessConfig{QueryTimeout: time.Second},
		Service: qualitydiagnostics.RuntimeConfig{CursorKey: []byte(strings.Repeat("c", 32))},
		Handler: qualitydiagnosticshttp.Config{QueryTimeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	paths := []struct{ legacy, canonical string }{
		{legacy: "/v1/analytics/site-quality-diagnostics", canonical: "/v1/analytics/quality-diagnostics"},
		{legacy: "/v1/admin/analytics/site-quality-diagnostics", canonical: "/v1/admin/analytics/quality-diagnostics"},
	}
	for _, path := range paths {
		request := httptest.NewRequest(http.MethodGet, path.legacy+"?from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z&category=edge_530", nil)
		request = request.WithContext(context.WithValue(t.Context(), finalizedProductionContextKey{}, "context"))
		request.Header.Set("X-Bridge-Probe", "preserved")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || observed[len(observed)-1] != path.canonical {
			t.Fatalf("%s response/observed = %d %#v", path.legacy, response.Code, observed)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/analytics/site-quality-diagnostics/neighbor", nil))
	if response.Code != http.StatusNotFound || len(observed) != 2 {
		t.Fatalf("adjacent route = %d, observed = %#v", response.Code, observed)
	}
}
