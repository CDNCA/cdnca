package dnsapiproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// connectProxy is a CONNECT proxy requiring Basic ops:s3cret; it counts the
// tunnels it opened.
func connectProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	tunnels := new(atomic.Int32)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops:s3cret"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Proxy-Authorization") != want {
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
	return server, tunnels
}

// provider is an HTTPS "DNS provider API" and a transport trusting it.
func provider(t *testing.T) (*httptest.Server, *http.Transport) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)
	return server, server.Client().Transport.(*http.Transport)
}

func useProxy(t *testing.T, raw string) {
	t.Helper()
	Use(NewSetting(func(context.Context) (string, error) { return raw, nil }, time.Minute))
	t.Cleanup(func() { Use(nil) })
}

func get(t *testing.T, transport *Transport, url string) (*http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if response != nil {
		t.Cleanup(func() { response.Body.Close() })
	}
	return response, err
}

func TestTransportGoesThroughConfiguredProxy(t *testing.T) {
	target, base := provider(t)
	proxy, tunnels := connectProxy(t)
	useProxy(t, "http://ops:s3cret@"+strings.TrimPrefix(proxy.URL, "http://"))
	response, err := get(t, NewTransport(base), target.URL+"/zones")
	if err != nil || response.StatusCode != http.StatusOK || tunnels.Load() != 1 {
		t.Fatalf("via proxy: response=%v err=%v tunnels=%d", response, err, tunnels.Load())
	}
}

func TestTransportDirectWhenUnsetAndIgnoresEnvironmentProxy(t *testing.T) {
	target, base := provider(t)
	proxy, tunnels := connectProxy(t)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	for _, setting := range []*Setting{nil, NewSetting(func(context.Context) (string, error) { return "", nil }, time.Minute)} {
		Use(setting)
		response, err := get(t, NewTransport(base), target.URL)
		if err != nil || response.StatusCode != http.StatusOK || tunnels.Load() != 0 {
			t.Fatalf("direct: response=%v err=%v tunnels=%d", response, err, tunnels.Load())
		}
	}
	Use(nil)
}

func TestTransportProxyFailureIsRecognisedWithoutCredentials(t *testing.T) {
	target, base := provider(t)
	proxy, _ := connectProxy(t)
	proxyAddress := strings.TrimPrefix(proxy.URL, "http://")
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddress := dead.Addr().String()
	dead.Close()
	for name, raw := range map[string]string{
		"wrong password": "http://ops:wr0ng-pass@" + proxyAddress,
		"unreachable":    "http://ops:wr0ng-pass@" + deadAddress,
		"tls to proxy":   "https://ops:wr0ng-pass@" + proxyAddress,
	} {
		useProxy(t, raw)
		ctx, failed := WithFailureRecorder(t.Context())
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
		_, err := (&http.Client{Transport: NewTransport(base)}).Do(request)
		if !errors.Is(err, ErrProxyUnavailable) || !failed() {
			t.Fatalf("%s: err=%v recorded=%v, want ErrProxyUnavailable", name, err, failed())
		}
		if strings.Contains(err.Error(), "wr0ng-pass") || strings.Contains(err.Error(), "ops:") {
			t.Fatalf("%s: error %q carries proxy credentials", name, err)
		}
	}
}

// The provider certificate is still verified through the tunnel, and a
// provider-side failure is not reported as a proxy failure.
func TestTransportKeepsProviderTLSVerification(t *testing.T) {
	target, _ := provider(t)
	proxy, tunnels := connectProxy(t)
	useProxy(t, "http://ops:s3cret@"+strings.TrimPrefix(proxy.URL, "http://"))
	_, err := get(t, NewTransport(nil), target.URL)
	if err == nil || errors.Is(err, ErrProxyUnavailable) || tunnels.Load() != 1 {
		t.Fatalf("untrusted provider certificate: err=%v tunnels=%d", err, tunnels.Load())
	}
}

func TestSettingRefreshAndStore(t *testing.T) {
	stored := "http://proxy-a.example:3128"
	reads := 0
	setting := NewSetting(func(context.Context) (string, error) { reads++; return stored, nil }, 5*time.Second)
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	setting.now = func() time.Time { return now }
	if got := setting.Current(t.Context()); got == nil || got.Host != "proxy-a.example:3128" {
		t.Fatalf("first read = %v", got)
	}
	stored = "http://proxy-b.example:3128"
	if got := setting.Current(t.Context()); got.Host != "proxy-a.example:3128" || reads != 1 {
		t.Fatalf("within ttl = %v reads=%d", got, reads)
	}
	now = now.Add(5 * time.Second)
	if got := setting.Current(t.Context()); got.Host != "proxy-b.example:3128" || reads != 2 {
		t.Fatalf("after ttl = %v reads=%d", got, reads)
	}
	setting.Store("")
	if got := setting.Current(t.Context()); got != nil {
		t.Fatalf("after Store(\"\") = %v, want direct", got)
	}
	setting.Store("not a proxy")
	if got := setting.Current(t.Context()); got != nil {
		t.Fatalf("after Store(invalid) = %v, want direct", got)
	}
}

// providerH2 is provider over HTTP/2 (like the real DNS provider APIs).
func providerH2(t *testing.T) (*httptest.Server, *http.Transport) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			w.WriteHeader(http.StatusHTTPVersionNotSupported)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, server.Client().Transport.(*http.Transport)
}

// CONTROL-SOURCE-IP-HTTP-PROXY-RESTORE: an HTTP/2 connection opened
// before the http代理 was set (or changed, or cleared) is not reused after;
// every request takes the route of the setting in force.
func TestTransportDoesNotReuseConnectionsAcrossProxyChanges(t *testing.T) {
	target, base := providerH2(t)
	proxy, tunnels := connectProxy(t)
	transport := NewTransport(base)
	value := ""
	Use(NewSetting(func(context.Context) (string, error) { return value, nil }, time.Minute))
	t.Cleanup(func() { Use(nil) })
	if response, err := get(t, transport, target.URL); err != nil || response.StatusCode != http.StatusOK || tunnels.Load() != 0 {
		t.Fatalf("direct: response=%v err=%v tunnels=%d", response, err, tunnels.Load())
	}
	Store("http://ops:s3cret@" + strings.TrimPrefix(proxy.URL, "http://"))
	for range 2 {
		if response, err := get(t, transport, target.URL); err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("via proxy: response=%v err=%v", response, err)
		}
	}
	if tunnels.Load() != 1 {
		t.Fatalf("after setting the proxy: tunnels=%d, want 1 (direct HTTP/2 connection reused)", tunnels.Load())
	}
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddress := dead.Addr().String()
	dead.Close()
	Store("http://ops:s3cret@" + deadAddress)
	if _, err := get(t, transport, target.URL); !errors.Is(err, ErrProxyUnavailable) {
		t.Fatalf("proxy gone: err=%v, want ErrProxyUnavailable (tunnel connection reused)", err)
	}
	Store("")
	if response, err := get(t, transport, target.URL); err != nil || response.StatusCode != http.StatusOK || tunnels.Load() != 1 {
		t.Fatalf("direct again: response=%v err=%v tunnels=%d", response, err, tunnels.Load())
	}
}
