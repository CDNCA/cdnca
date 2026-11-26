package dnsproviderremote

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsapiproxy"
)

// testConnectProxy is a CONNECT proxy requiring Basic ops:s3cret.
func testConnectProxy(t *testing.T) (address string, tunnels *atomic.Int32) {
	t.Helper()
	tunnels = new(atomic.Int32)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops:s3cret"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") != want {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		target, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer target.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		tunnels.Add(1)
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(target, buffered) }()
		_, _ = io.Copy(client, target)
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://"), tunnels
}

func useTestProxy(t *testing.T, raw string) {
	t.Helper()
	dnsapiproxy.Use(dnsapiproxy.NewSetting(func(context.Context) (string, error) { return raw, nil }, time.Minute))
	t.Cleanup(func() { dnsapiproxy.Use(nil) })
}

// with http代理 set, provider API requests go through it; a proxy
// that cannot be used is CodeProxyUnavailable and nothing reaches the provider.
func TestProviderRequestsUseHTTPProxy(t *testing.T) {
	var requests atomic.Int32
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "cloudflare-secret-token"}},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
		}), 5*time.Second)
	address, tunnels := testConnectProxy(t)

	useTestProxy(t, "http://ops:s3cret@"+address)
	response, err := adapter.http.do(t.Context(), http.MethodGet, adapter.endpoints.cloudflare, "/zones", nil, nil)
	if err != nil || response.status != http.StatusOK || tunnels.Load() != 1 || requests.Load() != 1 {
		t.Fatalf("via proxy: status=%d err=%v tunnels=%d requests=%d", response.status, err, tunnels.Load(), requests.Load())
	}

	dnsapiproxy.Use(nil)
	if _, err := adapter.http.do(t.Context(), http.MethodGet, adapter.endpoints.cloudflare, "/zones", nil, nil); err != nil ||
		tunnels.Load() != 1 || requests.Load() != 2 {
		t.Fatalf("direct: err=%v tunnels=%d requests=%d", err, tunnels.Load(), requests.Load())
	}

	useTestProxy(t, "http://ops:wr0ng@"+address)
	_, err = adapter.http.do(t.Context(), http.MethodGet, adapter.endpoints.cloudflare, "/zones", nil, nil)
	assertRemoteError(t, err, CodeProxyUnavailable)
	if requests.Load() != 2 || mutationResultUnknown(err) {
		t.Fatalf("refused proxy: requests=%d unknown=%v", requests.Load(), mutationResultUnknown(err))
	}
}
