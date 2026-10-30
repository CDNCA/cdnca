package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type authorizationStub struct {
	mu      sync.Mutex
	calls   int
	realIPs []string
	xffs    []string
	status  int
	delay   time.Duration
	server  *httptest.Server
}

func newAuthorizationStub(t *testing.T, status int) *authorizationStub {
	t.Helper()
	stub := &authorizationStub{status: status}
	stub.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		stub.mu.Lock()
		stub.calls++
		stub.realIPs = append(stub.realIPs, request.Header.Get("X-Real-IP"))
		stub.xffs = append(stub.xffs, strings.Join(request.Header.Values("X-Forwarded-For"), "|"))
		status, delay := stub.status, stub.delay
		stub.mu.Unlock()
		if request.URL.Path != "/download-authorization/v1/master" || request.Method != http.MethodGet {
			status = http.StatusNotFound
		}
		time.Sleep(delay)
		response.WriteHeader(status)
	}))
	t.Cleanup(stub.server.Close)
	return stub
}

func (stub *authorizationStub) url(t *testing.T) *url.URL {
	t.Helper()
	parsed, err := url.Parse(stub.server.URL + "/download-authorization/v1/master")
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func downloadRoot(t *testing.T) string {
	t.Helper()
	root := testStaticRoot(t)
	files := map[string]string{
		"downloads/control-native/latest/SHA256SUMS":               "native-sums\n",
		"downloads/control-native/latest/cdnca-control-native.tar": "tar",
		"downloads/control-native/artifacts.json":                  `{"version":1}`,
		"downloads/control-api/latest/SHA256SUMS":                  "api-sums\n",
		"downloads/agent-gateway/latest/SHA256SUMS":                "gw-sums\n",
		"downloads/control-web/latest/SHA256SUMS":                  "web-sums\n",
		"downloads/edge-agent/latest/SHA256SUMS":                   "edge-sums\n",
		"downloads/install-control.sh":                             "#!/bin/sh\n",
	}
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func gatedHandler(t *testing.T, authorization *url.URL) http.Handler {
	t.Helper()
	upstream, _ := url.Parse("http://127.0.0.1:1")
	handler, err := newHandlerWithOptions(downloadRoot(t), upstream, handlerOptions{
		MasterDownloadAuthorization: authorization, AuthorizationTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serve(handler http.Handler, method, target, remote string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	request.RemoteAddr = remote
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestMasterDownloadAllowedForAuthorizedSource(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusNoContent)
	handler := gatedHandler(t, stub.url(t))
	for _, target := range []string{
		"/downloads/control-native/latest/SHA256SUMS", "/downloads/control-api/latest/SHA256SUMS",
		"/downloads/agent-gateway/latest/SHA256SUMS", "/downloads/control-web/latest/SHA256SUMS",
		"/operator/downloads/control-native/latest/SHA256SUMS",
	} {
		response := serve(handler, http.MethodGet, target, "198.51.100.7:4000", nil)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "sums") ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status=%d cache=%q body=%q", target, response.Code, response.Header().Get("Cache-Control"), response.Body.String())
		}
	}
	// Hash-looking archive names must not be cached as immutable once gated.
	response := serve(handler, http.MethodGet, "/downloads/control-native/latest/cdnca-control-native.tar", "198.51.100.7:4000", nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("archive status=%d cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
	if stub.realIPs[0] != "198.51.100.7" || stub.xffs[0] != "198.51.100.7" {
		t.Fatalf("authorization saw real-ip=%q xff=%q", stub.realIPs[0], stub.xffs[0])
	}
}

func TestMasterDownloadDeniedReturnsChineseHint(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusForbidden)
	handler := gatedHandler(t, stub.url(t))
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := serve(handler, method, "/downloads/control-native/latest/SHA256SUMS", "[2001:db8::7]:4000", nil)
		if response.Code != http.StatusForbidden || response.Header().Get("X-CDNCA-Download-Denied") != "master-ip" ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s denied status=%d headers=%v", method, response.Code, response.Header())
		}
		if method == http.MethodGet && (!strings.Contains(response.Body.String(), "本机公网 IP 2001:db8::7 未登记为主控 IP") ||
			!strings.Contains(response.Body.String(), "请在授权门户确认主控 IP")) {
			t.Fatalf("denied body = %q", response.Body.String())
		}
		if strings.Contains(response.Body.String(), "native-sums") {
			t.Fatal("denied response leaked the artifact")
		}
	}
}

func TestMasterDownloadIgnoresClientForwardingHeaders(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusForbidden)
	handler := gatedHandler(t, stub.url(t))
	response := serve(handler, http.MethodGet, "/downloads/control-api/latest/SHA256SUMS", "203.0.113.9:4000",
		map[string]string{"X-Forwarded-For": "198.51.100.7", "X-Real-IP": "198.51.100.7", "Forwarded": "for=198.51.100.7"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("forged status=%d", response.Code)
	}
	if len(stub.realIPs) != 1 || stub.realIPs[0] != "203.0.113.9" || stub.xffs[0] != "203.0.113.9" {
		t.Fatalf("authorization saw real-ip=%v xff=%v, want only the TCP peer", stub.realIPs, stub.xffs)
	}
}

func TestMasterDownloadFailsClosedWhenAuthorizationUnavailable(t *testing.T) {
	closed := newAuthorizationStub(t, http.StatusNoContent)
	closedURL := closed.url(t)
	closed.server.Close()
	broken := newAuthorizationStub(t, http.StatusInternalServerError)
	slow := newAuthorizationStub(t, http.StatusNoContent)
	slow.delay = 2 * time.Second
	redirect := newAuthorizationStub(t, http.StatusFound)
	for name, authorization := range map[string]*url.URL{"closed": closedURL, "500": broken.url(t), "slow": slow.url(t),
		"redirect": redirect.url(t)} {
		started := time.Now()
		response := serve(gatedHandler(t, authorization), http.MethodGet, "/downloads/control-native/latest/SHA256SUMS", "198.51.100.7:1", nil)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "授权服务暂时无法校验主控 IP") ||
			response.Header().Get("Retry-After") == "" || strings.Contains(response.Body.String(), "native-sums") {
			t.Fatalf("%s: status=%d body=%q", name, response.Code, response.Body.String())
		}
		if time.Since(started) > 1500*time.Millisecond {
			t.Fatalf("%s: authorization timeout not applied", name)
		}
	}
}

func TestPublicDownloadsAndTraversalAroundGate(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusForbidden)
	handler := gatedHandler(t, stub.url(t))
	for _, target := range []string{"/downloads/edge-agent/latest/SHA256SUMS", "/downloads/install-control.sh",
		"/downloads/control-native/artifacts.json", "/operator/downloads/edge-agent/latest/SHA256SUMS"} {
		if response := serve(handler, http.MethodGet, target, "203.0.113.9:1", nil); response.Code != http.StatusOK {
			t.Fatalf("public %s status=%d", target, response.Code)
		}
	}
	if stub.calls != 0 {
		t.Fatalf("public downloads called authorization %d times", stub.calls)
	}
	for _, target := range []string{"/downloads/edge-agent/../control-native/latest/SHA256SUMS",
		"/operator/downloads/edge-agent/%2e%2e/control-api/latest/SHA256SUMS", "/downloads//control-native/latest/SHA256SUMS",
		"/downloads/control-native/artifacts.json/../latest/SHA256SUMS"} {
		if response := serve(handler, http.MethodGet, target, "203.0.113.9:1", nil); response.Code != http.StatusForbidden {
			t.Fatalf("traversal %s status=%d body=%q", target, response.Code, response.Body.String())
		}
	}
}

func TestMasterDownloadGateDisabledByDefault(t *testing.T) {
	handler := gatedHandler(t, nil)
	if response := serve(handler, http.MethodGet, "/downloads/control-native/latest/SHA256SUMS", "203.0.113.9:1", nil); response.Code != http.StatusOK {
		t.Fatalf("ungated status=%d", response.Code)
	}
}

func TestAPIProxyOverwritesClientForwardingHeaders(t *testing.T) {
	var realIP, xff string
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		realIP, xff = request.Header.Get("X-Real-IP"), strings.Join(request.Header.Values("X-Forwarded-For"), "|")
		response.WriteHeader(http.StatusOK)
	}))
	defer upstreamServer.Close()
	upstream, _ := url.Parse(upstreamServer.URL)
	handler, err := newHandler(downloadRoot(t), upstream)
	if err != nil {
		t.Fatal(err)
	}
	response := serve(handler, http.MethodPost, "/activation/v1/installations:activate", "203.0.113.9:1",
		map[string]string{"X-Forwarded-For": "198.51.100.7", "X-Real-IP": "198.51.100.7"})
	// ReverseProxy re-appends the peer after the Director overwrote the
	// header, so every hop is the TCP peer and the forged value is gone.
	hops := strings.Split(strings.ReplaceAll(xff, " ", ""), ",")
	if response.Code != http.StatusOK || realIP != "203.0.113.9" || strings.Contains(xff, "198.51.100.7") ||
		hops[0] != "203.0.113.9" || hops[len(hops)-1] != "203.0.113.9" {
		t.Fatalf("proxy status=%d real-ip=%q xff=%q", response.Code, realIP, xff)
	}
}

// The authorization host fetches its own artifacts through the public name
// (release repository verification), arriving from one of its own addresses.
func TestMasterDownloadAllowsThisHostsOwnAddresses(t *testing.T) {
	stub := newAuthorizationStub(t, http.StatusForbidden)
	handler := gatedHandler(t, stub.url(t))
	for _, remote := range []string{"127.0.0.1:4000", "[::1]:4000"} {
		response := serve(handler, http.MethodGet, "/downloads/control-api/latest/SHA256SUMS", remote, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%q", remote, response.Code, response.Body.String())
		}
	}
	if stub.calls != 0 {
		t.Fatalf("own addresses must not consult authorization, calls=%d", stub.calls)
	}
	if response := serve(handler, http.MethodGet, "/downloads/control-api/latest/SHA256SUMS", "198.51.100.9:4000", nil); response.Code != http.StatusForbidden {
		t.Fatalf("foreign peer status=%d", response.Code)
	}
}
