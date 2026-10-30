package systemothersettingshttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
	"github.com/google/uuid"
)

type serviceStub struct {
	document systemothersettings.Document
	saveErr  error
	saved    systemothersettings.SaveRequest
}

func (s *serviceStub) Get(context.Context, systemothersettings.Actor) (systemothersettings.Document, error) {
	return s.document, nil
}
func (s *serviceStub) Save(_ context.Context, _ systemothersettings.Actor, request systemothersettings.SaveRequest) (systemothersettings.Document, error) {
	s.saved = request
	return s.document, s.saveErr
}
func session() identity.AuthenticatedSession {
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}}
}

func TestHandlerRejectsUnauthenticated(t *testing.T) {
	h, err := New(&serviceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, errors.New("invalid")
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, route, nil))
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String())
	}
}

func TestHandlerWritesTypedSettings(t *testing.T) {
	stub := &serviceStub{document: systemothersettings.Document{Schema: systemothersettings.Schema(), Revision: 2, Value: systemothersettings.DefaultSettings()}}
	h, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return session(), nil })
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPut, route, strings.NewReader(`{"value":{"source_ip_header":"X-Forwarded-For","api_key_enabled":false,"dns_protection":"api,www","record_repair_mode":"repair_delete_extra","sync_batch":200,"sync_scope":"region","disable_failed_sync_nodes":true,"resource_rank":20,"http_proxy":"","tcp_factor":1.25}}`))
	r.Header.Set("Authorization", "Bearer session")
	r.Header.Set("X-Request-ID", "other-write-1")
	r.Header.Set("Idempotency-Key", "other-write-1")
	r.Header.Set("If-Match", `"2"`)
	r.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != http.StatusOK || stub.saved.ExpectedRevision != 2 || stub.saved.Value.APIKeyEnabled || stub.saved.Value.DNSProtection != "api,www" || stub.saved.Value.TCPFactor != 1.25 || stub.saved.Value.RecordRepairMode != "repair_delete_extra" || stub.saved.Value.SyncScope != "region" || !stub.saved.Value.DisableFailedSyncNodes {
		t.Fatalf("status=%d saved=%+v body=%s", out.Code, stub.saved, out.Body.String())
	}
}

func TestHandlerMapsUnavailableToServiceUnavailable(t *testing.T) {
	stub := &serviceStub{
		document: systemothersettings.Document{Schema: systemothersettings.Schema(), Revision: 2, Value: systemothersettings.DefaultSettings()},
		saveErr:  systemothersettings.ErrUnavailable,
	}
	h, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return session(), nil })
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPut, route, strings.NewReader(`{"value":{"source_ip_header":"X-Real-IP","api_key_enabled":true,"dns_protection":"","record_repair_mode":"repair","sync_batch":1000,"sync_scope":"line_group","disable_failed_sync_nodes":false,"resource_rank":100,"http_proxy":"","tcp_factor":1.1}}`))
	r.Header.Set("Authorization", "Bearer session")
	r.Header.Set("X-Request-ID", "other-unavailable-1")
	r.Header.Set("Idempotency-Key", "other-unavailable-1")
	r.Header.Set("If-Match", `"2"`)
	r.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestHandlerDistinguishesTenantDenialFromInvalidSession(t *testing.T) {
	tenantID := uuid.New()
	validTenant := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenantID}}
	for _, tc := range []struct {
		name    string
		session identity.AuthenticatedSession
		status  int
	}{
		{"authenticated tenant", validTenant, http.StatusForbidden},
		{"missing session", identity.AuthenticatedSession{Principal: validTenant.Principal}, http.StatusUnauthorized},
		{"missing identity", identity.AuthenticatedSession{SessionID: uuid.New()}, http.StatusUnauthorized},
	} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				handler, err := New(&serviceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return tc.session, nil })
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(method, route, nil)
				request.Header.Set("Authorization", "Bearer test-session")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != tc.status {
					t.Fatalf("status=%d want=%d body=%s", response.Code, tc.status, response.Body.String())
				}
			})
		}
	}
}
