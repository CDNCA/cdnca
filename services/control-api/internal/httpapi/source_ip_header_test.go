package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/clientip"
)

// sourceIPHeaderServer is a Server with the console nginx as trusted proxy
// (127.0.0.1) and the 源IP请求头 setting in setting.
func sourceIPHeaderServer(t *testing.T, setting *clientip.Setting) *Server {
	t.Helper()
	resolver, err := accountrecoverycontext.NewSourceIPResolver([]string{"127.0.0.1/32"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{apiKeySourceIP: resolver, sourceIPHeader: setting}
	directory := t.TempDir()
	server.controlOriginAuth.confPath = filepath.Join(directory, "origin-auth.conf")
	server.controlOriginAuth.hostPortsPath = filepath.Join(directory, "runtime.env")
	server.controlOriginAuth.nginxPath = filepath.Join(directory, "nginx.conf")
	return server
}

func fixedSetting(value string) *clientip.Setting {
	return clientip.NewSetting(func(context.Context) (string, error) { return value, nil }, time.Hour)
}

// consoleRequest is a request as the console nginx forwards it: the TCP peer
// (a CDN node here) in X-Real-IP / X-Forwarded-For, the client's own values
// of those in the X-Cdnca-Client-* copies, other headers unchanged.
func consoleRequest(headers ...string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil)
	request.RemoteAddr = "127.0.0.1:41000"
	request.Header.Set("X-Real-IP", "104.23.1.10")
	request.Header.Set("X-Forwarded-For", "104.23.1.10")
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Set(headers[index], headers[index+1])
	}
	return request
}

// sourceIPOf is the audit source IP WithClientSourceIP recorded for request.
func sourceIPOf(server *Server, request *http.Request) string {
	var seen string
	server.WithClientSourceIP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = audit.SourceIPFrom(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), request)
	return seen
}

// each 源IP请求头 value gives the visitor
// address to every source IP resolver; empty keeps today's direct address.
func TestSourceIPHeaderEachSetting(t *testing.T) {
	cdn := []string{"CF-Connecting-IP", "203.0.113.1", "True-Client-IP", "203.0.113.2",
		clientip.ForwardedXRealIP, "203.0.113.3", clientip.ForwardedXForwardedFor, "203.0.113.4, 198.51.100.9"}
	for setting, want := range map[string]string{
		"":                 "104.23.1.10",
		"CF-Connecting-IP": "203.0.113.1",
		"True-Client-IP":   "203.0.113.2",
		"X-Real-IP":        "203.0.113.3",
		"X-Forwarded-For":  "203.0.113.4",
	} {
		if got := sourceIPOf(sourceIPHeaderServer(t, fixedSetting(setting)), consoleRequest(cdn...)); got != want {
			t.Errorf("setting %q: source %q, want %q", setting, got, want)
		}
	}
	// no setting at all (Server built without one): direct
	if got := sourceIPOf(sourceIPHeaderServer(t, nil), consoleRequest(cdn...)); got != "104.23.1.10" {
		t.Errorf("unset: %q", got)
	}
}

// A missing or invalid value falls back to the connection's address.
func TestSourceIPHeaderInvalidFallsBack(t *testing.T) {
	server := sourceIPHeaderServer(t, fixedSetting("CF-Connecting-IP"))
	for name, request := range map[string]*http.Request{
		"missing":   consoleRequest(),
		"garbage":   consoleRequest("CF-Connecting-IP", "not-an-ip"),
		"with port": consoleRequest("CF-Connecting-IP", "203.0.113.9:443"),
		"loopback":  consoleRequest("CF-Connecting-IP", "127.0.0.1"),
		"list":      consoleRequest("CF-Connecting-IP", "203.0.113.9, 203.0.113.10"),
	} {
		if got := sourceIPOf(server, request); got != "104.23.1.10" {
			t.Errorf("%s: %q, want the connection's", name, got)
		}
	}
	// X-Real-IP / X-Forwarded-For read only the copies nginx writes, never the originals it rewrote
	for _, setting := range []string{"X-Real-IP", "X-Forwarded-For"} {
		if got := sourceIPOf(sourceIPHeaderServer(t, fixedSetting(setting)), consoleRequest()); got != "104.23.1.10" {
			t.Errorf("%s without the nginx copy: %q", setting, got)
		}
	}
}

// On a host with origin authentication applied, a request nginx confirmed
// with the origin key keeps the visitor address nginx wrote; the setting
// applies to the others, and a client's own confirmation means nothing
// without origin-auth.conf.
func TestSourceIPHeaderOriginAuthVerifiedFirst(t *testing.T) {
	server := sourceIPHeaderServer(t, fixedSetting("CF-Connecting-IP"))
	verified := func() *http.Request {
		request := consoleRequest("CF-Connecting-IP", "203.0.113.9", controlOriginAuthVerifiedHeader, "1")
		request.Header.Set("X-Forwarded-For", "198.51.100.5") // $cdnca_client_ip
		return request
	}
	if got := sourceIPOf(server, verified()); got != "203.0.113.9" {
		t.Fatalf("forged confirmation without origin-auth.conf: %q", got)
	}
	if err := os.WriteFile(server.controlOriginAuth.confPath, []byte("# real-ip-header: True-Client-IP\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.controlOriginAuth.confCheckedAt.Store(0)
	if got := sourceIPOf(server, verified()); got != "198.51.100.5" {
		t.Fatalf("origin authentication confirmed: %q", got)
	}
	unconfirmed := consoleRequest("CF-Connecting-IP", "203.0.113.9", controlOriginAuthVerifiedHeader, "0")
	if got := sourceIPOf(server, unconfirmed); got != "203.0.113.9" {
		t.Fatalf("key not matched: %q", got)
	}
}

// A save applies to the next request without a restart (Service.WithSaved → Store).
func TestSourceIPHeaderSaveAppliesAtOnce(t *testing.T) {
	setting := fixedSetting("")
	server := sourceIPHeaderServer(t, setting)
	request := func() *http.Request { return consoleRequest("True-Client-IP", "203.0.113.2") }
	if got := sourceIPOf(server, request()); got != "104.23.1.10" {
		t.Fatalf("before: %q", got)
	}
	setting.Store("True-Client-IP")
	if got := sourceIPOf(server, request()); got != "203.0.113.2" {
		t.Fatalf("after save: %q", got)
	}
}

// The visitor address the setting gave confirms the request for the hint;
// client_headers_forwarded tells whether nginx passes the two copies.
func TestSourceIPHeaderConfirmsTheHint(t *testing.T) {
	server := sourceIPHeaderServer(t, fixedSetting("CF-Connecting-IP"))
	handler := server.withControlOriginAuthObserver(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	now := time.Now()
	handler.ServeHTTP(httptest.NewRecorder(), consoleRequest("Ali-Cdn-Real-Ip", "203.0.113.9"))
	if status := server.controlOriginAuth.status(now); !status.CDNWithoutOriginAuth || status.VisitorIPConfirmed {
		t.Fatalf("unresolved CDN request: %+v", status)
	}
	handler.ServeHTTP(httptest.NewRecorder(), consoleRequest("CF-Connecting-IP", "203.0.113.9"))
	status := server.controlOriginAuth.status(time.Now())
	if status.CDNWithoutOriginAuth || !status.VisitorIPConfirmed || status.OriginAuthEnabled || status.ClientHeadersForwarded {
		t.Fatalf("resolved CDN request: %+v", status)
	}
	line := "            " + controlNginxClientHeaders + "\n"
	if err := os.WriteFile(server.controlOriginAuth.nginxPath, []byte("http {\n"+line+"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	server.controlOriginAuth.confCheckedAt.Store(0)
	if status := server.controlOriginAuth.status(time.Now()); !status.ClientHeadersForwarded {
		t.Fatalf("nginx passes the copies: %+v", status)
	}
}
