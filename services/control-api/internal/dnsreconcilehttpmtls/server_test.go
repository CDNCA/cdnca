package dnsreconcilehttpmtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const maxDownstreamResponseBytes = 1 << 20

func TestServerCloseBeforeStartReleasesListenerAndCompletesWait(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{httpServer: &http.Server{}, listener: listener, done: make(chan struct{})}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- server.Wait() }()
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("wait after pre-start close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait remained blocked after pre-start close")
	}
	if err := server.Start(); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("start after close error=%v", err)
	}
	rebound, err := net.Listen("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("listener was not released: %v", err)
	}
	if err := rebound.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRouteGuardRejectsNilVerifiedLeafWithoutPanic(t *testing.T) {
	tenantID, siteID := uuid.New(), uuid.New()
	authenticator, err := NewAuthenticator([]Identity{{
		URI: "spiffe://cdnca.local/dns-reconcile/provider-a", WorkloadID: "provider-a",
		TenantID: tenantID, SiteID: siteID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	guard := &routeGuard{authenticator: authenticator, next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	})}
	request := httptest.NewRequest(http.MethodPost,
		"https://control/internal/v1/dns/reconcile/tasks/11111111-1111-4111-8111-111111111111/provider-reports", nil)
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{nil}}}
	response := httptest.NewRecorder()
	guard.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("nil leaf status=%d calls=%d body=%q", response.Code, calls, response.Body.String())
	}
}

func TestRouteGuardRejectsUnsafeDownstreamResponses(t *testing.T) {
	tenantID, siteID := uuid.New(), uuid.New()
	authenticator, err := NewAuthenticator([]Identity{{
		URI: "spiffe://cdnca.local/dns-reconcile/provider-a", WorkloadID: "provider-a",
		TenantID: tenantID, SiteID: siteID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		status     int
		body       string
		location   string
		wantStatus int
		wantBody   bool
		panic      bool
	}{
		{name: "401", status: http.StatusUnauthorized, body: `{"error":"authentication_required"}`, wantStatus: http.StatusUnauthorized, wantBody: true},
		{name: "403", status: http.StatusForbidden, body: `{"error":"permission_denied"}`, wantStatus: http.StatusForbidden, wantBody: true},
		{name: "429", status: http.StatusTooManyRequests, body: `{"error":"rate_limited"}`, wantStatus: http.StatusTooManyRequests, wantBody: true},
		{name: "500", status: http.StatusInternalServerError, body: `{"error":"unavailable"}`, wantStatus: http.StatusInternalServerError, wantBody: true},
		{name: "503", status: http.StatusServiceUnavailable, body: `{"error":"unknown"}`, wantStatus: http.StatusServiceUnavailable, wantBody: true},
		{name: "redirect", status: http.StatusFound, body: "secret", location: "https://attacker.invalid", wantStatus: http.StatusInternalServerError},
		{name: "unknown 2xx", status: 299, body: "secret", wantStatus: http.StatusInternalServerError},
		{name: "oversize", status: http.StatusOK, body: strings.Repeat("x", maxDownstreamResponseBytes+1), wantStatus: http.StatusInternalServerError},
		{name: "panic", panic: true, wantStatus: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			guard := &routeGuard{authenticator: authenticator, next: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if test.panic {
					panic("downstream failure")
				}
				if test.location != "" {
					writer.Header().Set("Location", test.location)
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			})}
			request := httptest.NewRequest(http.MethodPost,
				"https://control/internal/v1/dns/reconcile/tasks/11111111-1111-4111-8111-111111111111/provider-reports", nil)
			request.TLS = verifiedTLSState(t, "spiffe://cdnca.local/dns-reconcile/provider-a")
			response := httptest.NewRecorder()
			guard.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%q", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantBody {
				if response.Body.String() != test.body {
					t.Fatalf("body=%q want=%q", response.Body.String(), test.body)
				}
			} else if response.Body.Len() != 0 || response.Header().Get("Location") != "" || strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("unsafe response leaked body/header: status=%d body=%q location=%q", response.Code, response.Body.String(), response.Header().Get("Location"))
			}
		})
	}
}

func TestRouteGuardValidatesDownstreamHeaders(t *testing.T) {
	tenantID, siteID := uuid.New(), uuid.New()
	authenticator, err := NewAuthenticator([]Identity{{
		URI: "spiffe://cdnca.local/dns-reconcile/provider-a", WorkloadID: "provider-a",
		TenantID: tenantID, SiteID: siteID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(handler http.HandlerFunc) *httptest.ResponseRecorder {
		guard := &routeGuard{authenticator: authenticator, next: handler}
		request := httptest.NewRequest(http.MethodPost,
			"https://control/internal/v1/dns/reconcile/tasks/11111111-1111-4111-8111-111111111111/provider-reports", nil)
		request.TLS = verifiedTLSState(t, "spiffe://cdnca.local/dns-reconcile/provider-a")
		response := httptest.NewRecorder()
		guard.ServeHTTP(response, request)
		return response
	}
	assertRejected := func(t *testing.T, response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusInternalServerError || response.Body.Len() != 0 ||
			response.Header().Get("X-Downstream-Leak") != "" || response.Header().Get("X-Internal") != "" {
			t.Fatalf("unsafe response leaked: status=%d body=%q headers=%#v",
				response.Code, response.Body.String(), response.Header())
		}
	}

	for _, headerName := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
		"TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		t.Run("hop-by-hop "+headerName, func(t *testing.T) {
			response := serve(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header()[headerName] = []string{"downstream-secret"}
				writer.Header().Set("X-Downstream-Leak", "secret")
				writer.WriteHeader(http.StatusAccepted)
				_, _ = writer.Write([]byte("secret-body"))
			})
			assertRejected(t, response)
		})
	}

	for _, test := range []struct {
		name        string
		headerName  string
		headerValue string
	}{
		{name: "invalid name", headerName: "Bad Header", headerValue: "value"},
		{name: "carriage return", headerName: "X-Test", headerValue: "safe\rsecret"},
		{name: "line feed", headerName: "X-Test", headerValue: "safe\nsecret"},
		{name: "invalid control", headerName: "X-Test", headerValue: "safe\x01secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := serve(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header()[test.headerName] = []string{test.headerValue}
				writer.Header().Set("X-Downstream-Leak", "secret")
				writer.WriteHeader(http.StatusAccepted)
				_, _ = writer.Write([]byte("secret-body"))
			})
			assertRejected(t, response)
		})
	}

	t.Run("connection nominated header", func(t *testing.T) {
		response := serve(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header()["cOnNeCtIoN"] = []string{"X-Internal"}
			writer.Header().Set("X-Internal", "secret")
			writer.Header().Set("X-Downstream-Leak", "secret")
			writer.WriteHeader(http.StatusAccepted)
			_, _ = writer.Write([]byte("secret-body"))
		})
		assertRejected(t, response)
	})

	t.Run("legal end-to-end headers", func(t *testing.T) {
		response := serve(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Content-Length", "2")
			writer.Header().Set("ETag", `"report-v1"`)
			writer.Header().Set("Retry-After", "30")
			writer.Header().Set("X-Report-Accepted", "true")
			writer.WriteHeader(http.StatusAccepted)
			_, _ = writer.Write([]byte("{}"))
		})
		if response.Code != http.StatusAccepted || response.Body.String() != "{}" ||
			response.Header().Get("Content-Type") != "application/json" ||
			response.Header().Get("Content-Length") != "2" || response.Header().Get("ETag") != `"report-v1"` ||
			response.Header().Get("Retry-After") != "30" || response.Header().Get("X-Report-Accepted") != "true" {
			t.Fatalf("legal response changed: status=%d body=%q headers=%#v",
				response.Code, response.Body.String(), response.Header())
		}
	})
}
