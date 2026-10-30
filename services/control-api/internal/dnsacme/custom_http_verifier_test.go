package dnsacme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
)

func TestCustomHTTPProviderCredentialsAndVerification(t *testing.T) {
	const secret = "verifier-secret-0123456"
	fake := &dnscustomhttp.FakeEndpoint{Secret: secret, Zone: "example.com"}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	dispatcher := NewProviderVerifierDispatcher()
	dispatcher.customHTTP = &dnscustomhttp.Options{
		Blocked: func(address netip.Addr) bool { return !address.IsLoopback() && dnscustomhttp.Blocked(address) },
		TLS:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	if !supportedProvider("custom_http") {
		t.Fatal("custom_http must be a supported provider type")
	}
	if !validProviderCredentialSchema("custom_http", map[string]string{"endpoint": "https://dns.example.net/api", "secret": secret}) ||
		validProviderCredentialSchema("custom_http", map[string]string{"endpoint": "https://10.0.0.1/api", "secret": secret}) ||
		validProviderCredentialSchema("custom_http", map[string]string{"endpoint": "http://dns.example.net/api", "secret": secret}) {
		t.Fatal("credential schema")
	}
	// The httptest URL is a literal loopback, so the save-time schema refuses
	// it; verification runs with the test address policy.
	ctx := context.Background()
	credentials := map[string]string{"endpoint": server.URL + "/api", "secret": secret}
	if err := verifyCustomHTTP(ctx, credentials, dispatcher.customHTTP); err != nil {
		t.Fatalf("verify: %v", err)
	}
	credentials["secret"] = "another-secret-012345"
	if err := verifyCustomHTTP(ctx, credentials, dispatcher.customHTTP); !errors.Is(err, ErrProviderCredentialsRejected) {
		t.Fatalf("wrong secret: %v", err)
	}
	if err := dispatcher.VerifyCredentials(ctx, "custom_http", map[string]string{"endpoint": "https://169.254.169.254/x",
		"secret": secret}); !errors.Is(err, ErrProviderCredentialsInvalid) {
		t.Fatalf("metadata endpoint: %v", err)
	}
}
