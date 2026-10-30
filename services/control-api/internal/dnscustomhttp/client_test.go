package dnscustomhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef-secret"

func testServer(t *testing.T, handler http.Handler) (*httptest.Server, Options) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	// httptest listens on 127.0.0.1: allow loopback only in tests.
	allowLoopback := func(address netip.Addr) bool { return !address.IsLoopback() && Blocked(address) }
	return server, Options{Blocked: allowLoopback, TLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
}

func TestCredentialsAndEndpoint(t *testing.T) {
	good := map[string]string{FieldEndpoint: "https://dns.example.net/api", FieldSecret: testSecret}
	if _, _, err := Credentials(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]string{
		{FieldEndpoint: "http://dns.example.net/api", FieldSecret: testSecret},
		{FieldEndpoint: "https://user:pw@dns.example.net/api", FieldSecret: testSecret},
		{FieldEndpoint: "https://dns.example.net/api?x=1", FieldSecret: testSecret},
		{FieldEndpoint: "https://localhost/api", FieldSecret: testSecret},
		{FieldEndpoint: "https://127.0.0.1/api", FieldSecret: testSecret},
		{FieldEndpoint: "https://169.254.169.254/latest", FieldSecret: testSecret},
		{FieldEndpoint: "https://10.0.0.1/api", FieldSecret: testSecret},
		{FieldEndpoint: "https://[::1]/api", FieldSecret: testSecret},
		{FieldEndpoint: "https://dns.example.net/api", FieldSecret: "short"},
		{FieldEndpoint: "https://dns.example.net/api", FieldSecret: testSecret, "extra": "x"},
	} {
		if _, _, err := Credentials(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestClientAgainstReferenceEndpoint(t *testing.T) {
	fake := &FakeEndpoint{Secret: testSecret, Zone: "example.com"}
	fake.Seed(Record{Name: "www.example.com", Type: "A", Value: "198.51.100.1", TTL: 600, Line: "默认"})
	server, options := testServer(t, fake)
	client, err := New(map[string]string{FieldEndpoint: server.URL + "/dns", FieldSecret: testSecret}, options)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	if err := client.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	id, err := client.CreateRecord(ctx, "example.com", Record{Name: "s1.example.com", Type: "CNAME", Value: "edge.example.net", TTL: 300, Line: "电信"})
	if err != nil || id == "" {
		t.Fatalf("create: %q %v", id, err)
	}
	records, err := client.ListRecords(ctx, "example.com", "s1.example.com")
	if err != nil || len(records) != 1 || records[0].ID != id || records[0].Line != "电信" || records[0].Type != "CNAME" {
		t.Fatalf("list: %+v %v", records, err)
	}
	records[0].Value = "edge2.example.net"
	if err := client.UpdateRecord(ctx, "example.com", records[0]); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteRecord(ctx, "example.com", id); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteRecord(ctx, "example.com", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if all, err := client.ListRecords(ctx, "example.com", ""); err != nil || len(all) != 1 {
		t.Fatalf("zone list: %+v %v", all, err)
	}
	var remote *RemoteError
	if _, err := client.ListRecords(ctx, "other.com", ""); !errors.As(err, &remote) || remote.Code != "zone_not_found" {
		t.Fatalf("foreign zone: %v", err)
	}
	// Wrong secret: the endpoint refuses the signature.
	wrong, _ := New(map[string]string{FieldEndpoint: server.URL + "/dns", FieldSecret: "another-secret-value"}, options)
	if err := wrong.Verify(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong secret: %v", err)
	}
	// A skewed clock is refused (the timestamp is signed).
	skewed, _ := New(map[string]string{FieldEndpoint: server.URL + "/dns", FieldSecret: testSecret},
		Options{Blocked: options.Blocked, TLS: options.TLS, Now: func() time.Time { return time.Now().Add(-10 * time.Minute) }})
	if err := skewed.Verify(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("skewed clock: %v", err)
	}
}

func TestClientRefusesUnsafeTransport(t *testing.T) {
	fake := &FakeEndpoint{Secret: testSecret, Zone: "example.com"}
	server, options := testServer(t, fake)
	ctx := context.Background()
	// The production address policy refuses the loopback test server at dial time.
	strict, err := New(map[string]string{FieldEndpoint: strings.Replace(server.URL, "127.0.0.1", "localhost.test", 1), FieldSecret: testSecret},
		Options{TLS: options.TLS})
	if err != nil {
		t.Fatal(err)
	}
	if err := strict.Verify(ctx); err == nil {
		t.Fatal("unresolvable/blocked endpoint accepted")
	}
	if _, err := New(map[string]string{FieldEndpoint: server.URL, FieldSecret: testSecret}, Options{TLS: options.TLS}); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("literal loopback endpoint: %v", err)
	}
	// TLS is verified: without the test CA the call fails.
	untrusted, _ := New(map[string]string{FieldEndpoint: server.URL, FieldSecret: testSecret}, Options{Blocked: options.Blocked})
	if err := untrusted.Verify(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("untrusted certificate: %v", err)
	}
	// Redirects are not followed; a protocol mismatch is malformed.
	redirect, redirectOptions := testServer(t, http.RedirectHandler("https://example.net/", http.StatusFound))
	client, _ := New(map[string]string{FieldEndpoint: redirect.URL, FieldSecret: testSecret}, redirectOptions)
	if err := client.Verify(ctx); !errors.Is(err, ErrMalformed) {
		t.Fatalf("redirect: %v", err)
	}
	other, otherOptions := testServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"protocol":"other","ok":true}`))
	}))
	client, _ = New(map[string]string{FieldEndpoint: other.URL, FieldSecret: testSecret}, otherOptions)
	if err := client.Verify(ctx); !errors.Is(err, ErrMalformed) {
		t.Fatalf("protocol mismatch: %v", err)
	}
}

func TestSignatureBindsBody(t *testing.T) {
	a := Sign([]byte(testSecret), "1", "n", []byte(`{"a":1}`))
	if a == Sign([]byte(testSecret), "1", "n", []byte(`{"a":2}`)) || a == Sign([]byte(testSecret), "2", "n", []byte(`{"a":1}`)) ||
		a == Sign([]byte(testSecret), "1", "m", []byte(`{"a":1}`)) {
		t.Fatal("signature must bind body, timestamp and nonce")
	}
}
