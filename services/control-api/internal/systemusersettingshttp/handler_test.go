package systemusersettingshttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

type serviceStub struct {
	document systemusersettings.Document
	getErr   error
	saveErr  error
	saved    *systemusersettings.SaveRequest
}

func (stub *serviceStub) Get(context.Context, systemusersettings.Actor) (systemusersettings.Document, error) {
	return stub.document, stub.getErr
}

func (stub *serviceStub) Save(_ context.Context, _ systemusersettings.Actor, request systemusersettings.SaveRequest) (systemusersettings.Document, error) {
	stub.saved = &request
	return stub.document, stub.saveErr
}

func platformSession() identity.AuthenticatedSession {
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}}
}

func settingsDocument(revision int64) systemusersettings.Document {
	return systemusersettings.Document{Schema: systemusersettings.Schema(), Revision: revision, Value: systemusersettings.DefaultSettings()}
}

func newTestHandler(t *testing.T, stub *serviceStub) *Handler {
	t.Helper()
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return platformSession(), nil })
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func putRequest(t *testing.T, body any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, route, bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer session-token")
	request.Header.Set("If-Match", `"4"`)
	request.Header.Set("Idempotency-Key", "system-user-settings-write")
	request.Header.Set("X-Request-ID", "system-user-settings-request")
	return request
}

func TestHandlerRejectsUnauthenticatedRequestBeforeService(t *testing.T) {
	called := false
	handler, err := New(&serviceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		called = true
		return identity.AuthenticatedSession{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("status=%d authenticate_called=%v", response.Code, called)
	}
}

func TestHandlerReturnsDocumentAndETag(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, route, nil)
	request.Header.Set("Authorization", "Bearer session-token")
	newTestHandler(t, &serviceStub{document: settingsDocument(4)}).ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"4"` || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d etag=%q cache=%q", response.Code, response.Header().Get("ETag"), response.Header().Get("Cache-Control"))
	}
}

func TestHandlerRequiresStrictWriteMetadataAndBody(t *testing.T) {
	settings := systemusersettings.DefaultSettings()
	tests := []struct {
		name    string
		request func(*testing.T) *http.Request
	}{
		{"missing metadata", func(t *testing.T) *http.Request {
			request := httptest.NewRequest(http.MethodPut, route, nil)
			request.Header.Set("Authorization", "Bearer session-token")
			return request
		}},
		{"unknown top-level field", func(t *testing.T) *http.Request {
			return putRequest(t, map[string]any{"value": settings, "extra": true})
		}},
		{"unknown settings field", func(t *testing.T) *http.Request {
			var raw map[string]any
			encoded, _ := json.Marshal(settings)
			_ = json.Unmarshal(encoded, &raw)
			raw["plaintext_secret"] = "secret"
			return putRequest(t, map[string]any{"value": raw})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &serviceStub{document: settingsDocument(5)}
			response := httptest.NewRecorder()
			newTestHandler(t, stub).ServeHTTP(response, test.request(t))
			if response.Code != http.StatusBadRequest || stub.saved != nil {
				t.Fatalf("status=%d saved=%v", response.Code, stub.saved != nil)
			}
		})
	}
}

func TestHandlerForwardsCASAndIdempotencyMetadata(t *testing.T) {
	stub := &serviceStub{document: settingsDocument(5)}
	response := httptest.NewRecorder()
	newTestHandler(t, stub).ServeHTTP(response, putRequest(t, map[string]any{"value": systemusersettings.DefaultSettings()}))
	if response.Code != http.StatusOK || stub.saved == nil || stub.saved.ExpectedRevision != 4 || stub.saved.IdempotencyKey != "system-user-settings-write" || stub.saved.RequestID != "system-user-settings-request" {
		t.Fatalf("status=%d request=%#v", response.Code, stub.saved)
	}
}

func TestHandlerMapsInvalidSettingsWithoutReturningDocument(t *testing.T) {
	value := systemusersettings.DefaultSettings()
	value.CaptchaSecretKeyReference = "plaintext-secret"
	stub := &serviceStub{saveErr: systemusersettings.ErrInvalidInput}
	response := httptest.NewRecorder()
	newTestHandler(t, stub).ServeHTTP(response, putRequest(t, map[string]any{"value": value}))
	if response.Code != http.StatusBadRequest || stub.saved == nil {
		t.Fatalf("status=%d saved=%v", response.Code, stub.saved != nil)
	}
}

func TestHandlerMapsPermissionAndRevisionErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{"permission denied", systemusersettings.ErrPermissionDenied, http.StatusForbidden},
		{"revision conflict", systemusersettings.ErrRevisionConflict, http.StatusConflict},
		{"unavailable", systemusersettings.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			newTestHandler(t, &serviceStub{saveErr: test.err}).ServeHTTP(response, putRequest(t, map[string]any{"value": systemusersettings.DefaultSettings()}))
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d", response.Code, test.want)
			}
		})
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
