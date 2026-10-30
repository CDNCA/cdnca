package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// Every audit event written while serving a request gets the client address
// (unified-log): the client-IP middleware hands it to audit.WithSourceIP.
func TestClientIPMiddlewareSetsAuditSourceIP(t *testing.T) {
	resolver, err := accountrecoverycontext.NewSourceIPResolver(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{apiKeySourceIP: resolver}
	var got string
	handler := server.withAPIKeyClientIP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = audit.SourceIPFrom(r.Context())
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.20:51234"
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if got != "203.0.113.20" {
		t.Fatalf("audit source IP = %q, want 203.0.113.20", got)
	}

	// A spoofed forwarding header from an untrusted peer must not be recorded.
	got = ""
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.20:51234"
	request.Header.Set("X-Forwarded-For", "198.51.100.1")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if got == "198.51.100.1" {
		t.Fatal("untrusted X-Forwarded-For was recorded as the audit source IP")
	}
}
