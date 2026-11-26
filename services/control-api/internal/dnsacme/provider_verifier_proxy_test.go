package dnsacme

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsapiproxy"
)

// assertPlatformProxyClient: a production verifier client goes through the
// platform http代理 only (never environment proxies).
func assertPlatformProxyClient(t *testing.T, client *http.Client) {
	t.Helper()
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	transport, ok := client.Transport.(*dnsapiproxy.Transport)
	if !ok {
		t.Fatalf("production transport = %T, want *dnsapiproxy.Transport", client.Transport)
	}
	probe, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	if proxy, err := transport.Proxy(probe); proxy != nil || err != nil {
		t.Fatalf("without http代理 the verifier uses proxy %v (%v)", proxy, err)
	}
}

func TestProductionVerifiersUsePlatformProxy(t *testing.T) {
	dispatcher := NewProviderVerifierDispatcher()
	for name, client := range map[string]*http.Client{
		"cloudflare": dispatcher.cloudflare.client, "aliyun": dispatcher.aliyun.client, "huawei": dispatcher.huawei.client,
		"dnspod": dispatcher.dnspod.client, "dnscom": dispatcher.dnscom.client, "dnsla": dispatcher.dnsla.client,
		"namecom": dispatcher.namecom.client, "dnspodcom": dispatcher.dnspodcom.client, "godaddy": dispatcher.godaddy.client,
		"namesilo": dispatcher.namesilo.client, "namecheap": dispatcher.namecheap.client, "jdcloud": dispatcher.jdcloud.client,
		"cloudns": dispatcher.cloudns.client,
	} {
		t.Run(name, func(t *testing.T) { assertPlatformProxyClient(t, client) })
	}
}

// a credential check whose http代理 cannot be used is
// ErrProviderProxyUnavailable, and the provider is not reached.
func TestVerifyCredentialsReportsUnusableProxy(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := &http.Client{Transport: dnsapiproxy.NewTransport(server.Client().Transport.(*http.Transport))}
	dispatcher := newProviderVerifierDispatcher(newCloudflareProviderVerifier(server.URL, client, time.Second), nil, nil, nil, nil)
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddress := dead.Addr().String()
	dead.Close()
	dnsapiproxy.Use(dnsapiproxy.NewSetting(func(context.Context) (string, error) { return "http://ops:s3cret@" + deadAddress, nil }, time.Minute))
	defer dnsapiproxy.Use(nil)
	err = dispatcher.VerifyCredentials(t.Context(), "cloudflare", map[string]string{"api_token": "cf-token"})
	if !errors.Is(err, ErrProviderProxyUnavailable) || requests.Load() != 0 {
		t.Fatalf("unusable proxy: err=%v requests=%d", err, requests.Load())
	}
	dnsapiproxy.Use(nil)
	err = dispatcher.VerifyCredentials(t.Context(), "cloudflare", map[string]string{"api_token": "cf-token"})
	if errors.Is(err, ErrProviderProxyUnavailable) || requests.Load() != 1 {
		t.Fatalf("direct: err=%v requests=%d", err, requests.Load())
	}
}

// tunnelProxy is a CONNECT proxy counting its tunnels; kill stops it like
// the process exiting (listener and every open tunnel closed).
func tunnelProxy(t *testing.T) (address string, tunnels *atomic.Int32, kill func()) {
	t.Helper()
	tunnels = new(atomic.Int32)
	var mu sync.Mutex
	var open []net.Conn
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		target, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			target.Close()
			return
		}
		mu.Lock()
		open = append(open, client, target)
		mu.Unlock()
		tunnels.Add(1)
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(target, buffered) }()
		_, _ = io.Copy(client, target)
	}))
	kill = func() {
		server.Listener.Close()
		mu.Lock()
		for _, conn := range open {
			conn.Close()
		}
		mu.Unlock()
		server.Close()
	}
	t.Cleanup(kill)
	return strings.TrimPrefix(server.URL, "http://"), tunnels, kill
}

// CONTROL-SOURCE-IP-HTTP-PROXY-RESTORE (retest): 连接测试 after a
// direct one went direct again over the cached HTTP/2 connection — the
// http代理 saw no CONNECT and a stopped proxy still answered "已连接". Now
// the check goes through the proxy once it is set and a stopped proxy is
// ErrProviderProxyUnavailable (503 provider_proxy_unavailable).
func TestPlatformConnectionCheckFollowsProxyChanges(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"tok","status":"active"},"errors":[]}`))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Transport: dnsapiproxy.NewTransport(server.Client().Transport.(*http.Transport))}
	dispatcher := newProviderVerifierDispatcher(newCloudflareProviderVerifier(server.URL, client, 2*time.Second), nil, nil, nil, nil)
	value := ""
	dnsapiproxy.Use(dnsapiproxy.NewSetting(func(context.Context) (string, error) { return value, nil }, time.Minute))
	defer dnsapiproxy.Use(nil)
	verify := func() error {
		return dispatcher.VerifyCredentials(t.Context(), "cloudflare", map[string]string{"api_token": "cf-token"})
	}
	if err := verify(); err != nil {
		t.Fatalf("direct baseline: %v", err)
	}
	address, tunnels, kill := tunnelProxy(t)
	dnsapiproxy.Store("http://" + address) // saved in 系统设置 › 其它配置
	for range 3 {
		if err := verify(); err != nil {
			t.Fatalf("via proxy: %v", err)
		}
	}
	if tunnels.Load() != 1 || requests.Load() != 4 {
		t.Fatalf("after setting the proxy: tunnels=%d requests=%d, want 1 tunnel for 3 checks", tunnels.Load(), requests.Load())
	}
	kill()
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := verify()
		if errors.Is(err, ErrProviderProxyUnavailable) {
			break
		}
		// The client may first notice the closed tunnel on this request; it
		// must never succeed (that would be a direct request).
		if err == nil || time.Now().After(deadline) {
			t.Fatalf("proxy stopped: err=%v, want ErrProviderProxyUnavailable", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if requests.Load() != 4 {
		t.Fatalf("proxy stopped: provider reached directly (requests=%d)", requests.Load())
	}
	dnsapiproxy.Store("")
	if err := verify(); err != nil || requests.Load() != 5 {
		t.Fatalf("direct after clearing the proxy: err=%v requests=%d", err, requests.Load())
	}
}
