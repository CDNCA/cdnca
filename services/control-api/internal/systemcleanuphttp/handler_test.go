package systemcleanuphttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemcleanup"
	"github.com/google/uuid"
)

type handlerServiceStub struct {
	document systemcleanup.Document
	getErr   error
	saveErr  error
}

func (stub *handlerServiceStub) Get(context.Context, systemcleanup.Actor) (systemcleanup.Document, error) {
	return stub.document, stub.getErr
}

func (stub *handlerServiceStub) Save(context.Context, systemcleanup.Actor, systemcleanup.SaveRequest) (systemcleanup.Document, error) {
	return stub.document, stub.saveErr
}

func testSession() identity.AuthenticatedSession {
	return identity.AuthenticatedSession{
		SessionID: uuid.New(),
		Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"},
	}
}

func testDocument() systemcleanup.Document {
	return systemcleanup.Document{Schema: systemcleanup.Schema(), Revision: 2, UpdatedAt: time.Now().UTC(), Value: systemcleanup.DefaultSettings()}
}

func newTestHandler(t *testing.T, stub *handlerServiceStub) *Handler {
	t.Helper()
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestHandlerRejectsMissingBearer(t *testing.T) {
	handler, err := New(&handlerServiceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		t.Fatal("authenticate must not run")
		return identity.AuthenticatedSession{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestHandlerReturnsDocumentAndETag(t *testing.T) {
	response := httptest.NewRecorder()
	newTestHandler(t, &handlerServiceStub{document: testDocument()}).ServeHTTP(response, func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, route, nil)
		r.Header.Set("Authorization", "Bearer session-token")
		return r
	}())
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` {
		t.Fatalf("status=%d etag=%q", response.Code, response.Header().Get("ETag"))
	}
	var document systemcleanup.Document
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != systemcleanup.Schema() {
		t.Fatalf("schema=%q", document.Schema)
	}
}

func TestHandlerRequiresStrictWriteMetadata(t *testing.T) {
	response := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, route, bytes.NewReader([]byte(`{"value":{}}`)))
	r.Header.Set("Authorization", "Bearer session-token")
	newTestHandler(t, &handlerServiceStub{document: testDocument()}).ServeHTTP(response, r)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestHandlerMapsRevisionConflictAndPermissionDenied(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{name: "revision", err: systemcleanup.ErrRevisionConflict, want: http.StatusConflict},
		{name: "permission", err: systemcleanup.ErrPermissionDenied, want: http.StatusForbidden},
		{name: "unavailable", err: systemcleanup.ErrUnavailable, want: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"value": systemcleanup.DefaultSettings()})
			r := httptest.NewRequest(http.MethodPut, route, bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer session-token")
			r.Header.Set("If-Match", `"2"`)
			r.Header.Set("Idempotency-Key", "system-cleanup-settings-test")
			r.Header.Set("X-Request-ID", "system-cleanup-request")
			response := httptest.NewRecorder()
			newTestHandler(t, &handlerServiceStub{saveErr: test.err}).ServeHTTP(response, r)
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
				handler, err := New(&handlerServiceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return tc.session, nil })
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
