package wafsubscription

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestValidateURL(t *testing.T) {
	for _, value := range []string{
		"https://rules.example.com/waf.json", "https://rules.example.com:8443/a?b=c", "https://8.8.8.8/rules.json",
	} {
		if err := ValidateURL(value); err != nil {
			t.Errorf("%s refused: %v", value, err)
		}
	}
	for _, value := range []string{
		"http://rules.example.com/waf.json", "ftp://rules.example.com/x", "https://user:pw@rules.example.com/x",
		"https:///nohost", "https://localhost/x", "https://a.localhost/x", "https://127.0.0.1/x", "https://10.1.2.3/x",
		"https://192.168.1.1/x", "https://169.254.169.254/latest/meta-data", "https://[::1]/x", "https://[fd00::1]/x",
		"https://100.64.0.1/x", "https://0.0.0.0/x", "https://rules.example.com/x#frag", "not a url",
		"https://" + strings.Repeat("a", 2050) + ".com/",
	} {
		if err := ValidateURL(value); err == nil {
			t.Errorf("%s accepted", value)
		}
	}
}

func TestBlockedAddress(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "64:ff9b::a00:1",
		"198.18.0.1", "192.0.0.1", "2001:db8::1"} {
		if !blockedAddress(netip.MustParseAddr(value)) {
			t.Errorf("%s allowed", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if blockedAddress(netip.MustParseAddr(value)) {
			t.Errorf("%s blocked", value)
		}
	}
}

// The production fetcher re-checks the address it actually connects to, so a
// public name resolving to loopback (DNS rebinding) is refused at dial time.
func TestFetcherRefusesLoopbackAtDialTime(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(competitorSample))
	}))
	defer server.Close()
	fetcher := newFetcher(blockedAddress, server.Client().Transport.(*http.Transport).TLSClientConfig)
	_, err := fetcher.fetch(context.Background(), server.URL)
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("err = %v", err)
	}
	// A name (not a literal) passes the URL check; the dial-time check must
	// refuse the loopback address the name resolves to.
	named := strings.Replace(server.URL, "127.0.0.1", "localhost.test-rebind.invalid", 1)
	fetcher.client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return fetcher.dialer.DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	if _, err := fetcher.fetch(context.Background(), named); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("rebinding name: %v", err)
	}
}

func TestFetcherLimits(t *testing.T) {
	var redirectTo string
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(competitorSample)) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat(" ", MaxDocumentBytes+1)))
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "gone", http.StatusNotFound) })
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, redirectTo, http.StatusFound) })
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	allowAll := func(netip.Addr) bool { return false }
	fetcher := newFetcher(allowAll, server.Client().Transport.(*http.Transport).TLSClientConfig)
	ctx := context.Background()

	body, err := fetcher.fetch(ctx, server.URL+"/ok")
	if err != nil || string(body) != competitorSample {
		t.Fatalf("ok: %v", err)
	}
	if _, err := fetcher.fetch(ctx, server.URL+"/big"); err == nil || !strings.Contains(err.Error(), "8388608") {
		t.Fatalf("big: %v", err)
	}
	if _, err := fetcher.fetch(ctx, server.URL+"/missing"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing: %v", err)
	}
	redirectTo = strings.Replace(server.URL, "https://", "http://", 1) + "/ok"
	if _, err := fetcher.fetch(ctx, server.URL+"/redirect"); err == nil {
		t.Fatal("redirect to http followed")
	}
	redirectTo = server.URL + "/ok"
	if _, err := fetcher.fetch(ctx, server.URL+"/redirect"); err != nil {
		t.Fatalf("https redirect: %v", err)
	}
}
