package httppolicycontrol

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHTTPPolicyHandlerPreservesAuthenticationErrorClass(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "unauthenticated", err: ErrUnauthenticated, status: http.StatusUnauthorized, code: "authentication_required"},
		{name: "unavailable", err: ErrUnavailable, status: http.StatusServiceUnavailable, code: "service_unavailable"},
		{name: "unknown dependency", err: errors.New("identity database secret"), status: http.StatusServiceUnavailable, code: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := newHTTPPolicyProtocolTestHandler(t, AuthenticatorFunc(func(*http.Request) (Actor, error) {
				return Actor{}, test.err
			}))
			request := httptest.NewRequest(http.MethodGet, collectionPath(uuid.New()), nil)
			request.Header.Set("X-Request-ID", "auth-class-request")
			request.Header.Set("X-Trace-ID", "auth-class-trace")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertHTTPPolicyProtocolError(t, response, test.status, test.code)
			if strings.Contains(response.Body.String(), "identity database secret") {
				t.Fatalf("authentication dependency detail leaked: %s", response.Body)
			}
		})
	}
}

func TestHTTPPolicyHandlerRejectsDuplicateSingletonHeadersBeforeAuthentication(t *testing.T) {
	for _, name := range []string{"X-Request-ID", "X-Trace-ID", "Idempotency-Key", "If-Match", "Content-Type"} {
		t.Run(name, func(t *testing.T) {
			authenticationCalls := 0
			handler := newHTTPPolicyProtocolTestHandler(t, AuthenticatorFunc(func(*http.Request) (Actor, error) {
				authenticationCalls++
				return Actor{}, ErrUnauthenticated
			}))
			request := httptest.NewRequest(http.MethodGet, collectionPath(uuid.New()), nil)
			request.Header.Set("X-Request-ID", "duplicate-request")
			request.Header.Set("X-Trace-ID", "duplicate-trace")
			request.Header.Add(name, "first")
			request.Header.Add(name, "second")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertHTTPPolicyProtocolError(t, response, http.StatusBadRequest, "invalid_request")
			if authenticationCalls != 0 {
				t.Fatalf("authentication calls = %d, want 0", authenticationCalls)
			}
		})
	}
}

func TestHTTPPolicyBodyAndRevisionHelpersRejectDuplicateHeaders(t *testing.T) {
	revision := httptest.NewRequest(http.MethodPatch, "/", nil)
	revision.Header.Add("If-Match", `"1"`)
	revision.Header.Add("If-Match", `"2"`)
	if _, err := expectedRevision(revision); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate If-Match error = %v, want ErrInvalidInput", err)
	}
	body := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	body.Header.Add("Content-Type", "application/json")
	body.Header.Add("Content-Type", "application/json")
	if err := decodeBody(httptest.NewRecorder(), body, &struct{}{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate Content-Type error = %v, want ErrInvalidInput", err)
	}
}

func newHTTPPolicyProtocolTestHandler(t *testing.T, authenticator Authenticator) *Handler {
	t.Helper()
	store, err := newStoreWithDependencies(
		new(pgxpool.Pool), time.Now, runtimeTestGate{}, nil, allowTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewService(store), authenticator)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func assertHTTPPolicyProtocolError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d body=%s", response.Code, status, response.Body)
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code {
		t.Fatalf("code = %q, want %q body=%s", envelope.Error.Code, code, response.Body)
	}
}
