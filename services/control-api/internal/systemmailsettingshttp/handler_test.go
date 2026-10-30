package systemmailsettingshttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/google/uuid"
)

type serviceStub struct {
	document systemmailsettings.Document
	getErr   error
	saveErr  error
	saved    systemmailsettings.SaveRequest
}

func (s *serviceStub) Get(context.Context, systemmailsettings.Actor) (systemmailsettings.Document, error) {
	return s.document, s.getErr
}
func (s *serviceStub) Save(_ context.Context, _ systemmailsettings.Actor, request systemmailsettings.SaveRequest) (systemmailsettings.Document, error) {
	s.saved = request
	return s.document, s.saveErr
}

func testSession() identity.AuthenticatedSession {
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}}
}

func TestHandlerRejectsUnauthenticatedRequests(t *testing.T) {
	h, err := New(&serviceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, errors.New("bad session")
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHandlerReadsAndWritesWithCASHeaders(t *testing.T) {
	document := systemmailsettings.Document{Schema: systemmailsettings.Schema(), Revision: 4, Value: systemmailsettings.Settings{SMTPSSL: true, SMTPPort: 465}}
	stub := &serviceStub{document: document}
	h, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, route, nil)
	request.Header.Set("Authorization", "Bearer session")
	h.ServeHTTP(get, request)
	if get.Code != http.StatusOK || get.Header().Get("ETag") != `"4"` {
		t.Fatalf("GET status=%d etag=%q body=%s", get.Code, get.Header().Get("ETag"), get.Body.String())
	}
	put := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPut, route, strings.NewReader(`{"value":{"smtp_address":"smtp.internal","smtp_ssl":true,"smtp_port":465,"smtp_user":"sender","smtp_password_reference":"vault://smtp/password","sms_provider":"https_json","sms_access_key_id":"key","sms_access_key_reference":"kms-envelope://sms/key","sms_signature_name":"CDNCA"}}`))
	request.Header.Set("Authorization", "Bearer session")
	request.Header.Set("X-Request-ID", "mail-write-1")
	request.Header.Set("Idempotency-Key", "mail-write-1")
	request.Header.Set("If-Match", `"4"`)
	request.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(put, request)
	if put.Code != http.StatusOK || stub.saved.ExpectedRevision != 4 || stub.saved.Value.SMTPPasswordReference != "vault://smtp/password" {
		t.Fatalf("PUT status=%d saved=%+v body=%s", put.Code, stub.saved, put.Body.String())
	}
}

func TestHandlerMapsUnavailableToServiceUnavailable(t *testing.T) {
	stub := &serviceStub{saveErr: systemmailsettings.ErrUnavailable}
	h, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, route, strings.NewReader(`{"value":{"smtp_address":"","smtp_ssl":true,"smtp_port":465,"smtp_user":"","smtp_password_reference":"","sms_provider":"","sms_access_key_id":"","sms_access_key_reference":"","sms_signature_name":""}}`))
	request.Header.Set("Authorization", "Bearer session")
	request.Header.Set("X-Request-ID", "mail-unavailable-1")
	request.Header.Set("Idempotency-Key", "mail-unavailable-1")
	request.Header.Set("If-Match", `"0"`)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
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
