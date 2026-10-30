package accountregistrationchallenge

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTurnstileVerifierUsesCustomCAAndRejectsForgedToken(t *testing.T) {
	validToken := strings.Repeat("v", 32)
	var tlsVersion atomic.Uint32
	server, caFile := newTurnstileTestServer(t, tls.VersionTLS13, func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		values, _ := url.ParseQuery(string(body))
		if request.TLS != nil {
			tlsVersion.Store(uint32(request.TLS.Version))
		}
		if request.Method != http.MethodPost || values.Get("secret") != "turnstile-secret-value" ||
			values.Get("remoteip") != "192.0.2.10" || values.Get("idempotency_key") != "human-attempt-1" {
			t.Errorf("unexpected Turnstile request: method=%s values=%v", request.Method, values)
		}
		writer.Header().Set("Content-Type", "application/json")
		if values.Get("response") != validToken {
			_, _ = writer.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
			return
		}
		_, _ = writer.Write([]byte(`{"success":true,"hostname":"register.example","action":"register","challenge_ts":"2026-08-08T08:59:00Z"}`))
	})

	verifier, err := NewTurnstileVerifier(TurnstileConfig{
		Endpoint: server.URL, CAFile: caFile, Secret: "turnstile-secret-value",
		ExpectedHostname: "register.example", ExpectedAction: "register",
		Timeout: time.Second, MaxResponseBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := HumanVerification{Token: validToken, Source: "192.0.2.10", IdempotencyKey: "human-attempt-1"}
	if err := verifier.Verify(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	request.Token = strings.Repeat("f", 32)
	if err := verifier.Verify(t.Context(), request); err != ErrHumanInvalid {
		t.Fatalf("forged token error = %v, want ErrHumanInvalid", err)
	}
	if tlsVersion.Load() != tls.VersionTLS13 {
		t.Fatalf("Turnstile TLS version = %#x", tlsVersion.Load())
	}
}

func TestTurnstileVerifierRequiresExactResponseAndHTTPS(t *testing.T) {
	var duplicate atomic.Bool
	server, caFile := newTurnstileTestServer(t, tls.VersionTLS13, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if duplicate.Load() {
			_, _ = writer.Write([]byte(`{"success":true,"success":false,"hostname":"register.example","action":"register"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"success":true,"hostname":"register.example","action":"register","challenge_ts":"2026-08-08T08:59:00Z"}`))
	})
	verifier, err := NewTurnstileVerifier(TurnstileConfig{
		Endpoint: server.URL, CAFile: caFile, Secret: "turnstile-secret-value",
		ExpectedHostname: "register.example", ExpectedAction: "register",
		Timeout: time.Second, MaxResponseBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := HumanVerification{Token: strings.Repeat("t", 32), Source: "192.0.2.10", IdempotencyKey: "human-attempt-1"}
	if err := verifier.Verify(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	duplicate.Store(true)
	if err := verifier.Verify(t.Context(), request); err != ErrHumanUnavailable {
		t.Fatalf("duplicate JSON error = %v, want ErrHumanUnavailable", err)
	}

	insecure := TurnstileConfig{
		Endpoint: "http://challenges.example/siteverify", Secret: "turnstile-secret-value",
		ExpectedHostname: "register.example", ExpectedAction: "register",
	}
	if _, err := NewTurnstileVerifier(insecure); err != ErrInvalidConfig {
		t.Fatalf("insecure endpoint error = %v, want ErrInvalidConfig", err)
	}
}

func TestTurnstileVerifierDefaultsToCloudflareWithSystemRootsAndTLS13(t *testing.T) {
	verifier, err := NewTurnstileVerifier(TurnstileConfig{
		Secret: "turnstile-secret-value", ExpectedHostname: "register.example", ExpectedAction: "register",
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := verifier.client.Transport.(*http.Transport)
	if !ok || verifier.endpoint.String() != defaultTurnstileEndpoint || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS13 || transport.TLSClientConfig.RootCAs != nil ||
		transport.Proxy != nil {
		t.Fatalf("default verifier endpoint=%q transport=%#v", verifier.endpoint.String(), verifier.client.Transport)
	}
}

func TestTurnstileVerifierFailsClosedForTLS12WrongHostAndUntrustedCertificate(t *testing.T) {
	success := func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"hostname":"register.example","action":"register","challenge_ts":"2026-08-08T08:59:00Z"}`))
	}
	tls12Server, tls12CA := newTurnstileTestServer(t, tls.VersionTLS12, success)
	trustedServer, trustedCA := newTurnstileTestServer(t, tls.VersionTLS13, success)
	untrustedServer, _ := newTurnstileTestServer(t, tls.VersionTLS13, success)
	trustedURL, err := url.Parse(trustedServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	trustedURL.Host = "localhost:" + trustedURL.Port()

	for _, test := range []struct {
		name     string
		endpoint string
		caFile   string
	}{
		{name: "TLS 1.2 only", endpoint: tls12Server.URL, caFile: tls12CA},
		{name: "wrong server name", endpoint: trustedURL.String(), caFile: trustedCA},
		{name: "untrusted certificate", endpoint: untrustedServer.URL, caFile: trustedCA},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := NewTurnstileVerifier(TurnstileConfig{
				Endpoint: test.endpoint, CAFile: test.caFile, Secret: "turnstile-secret-value",
				ExpectedHostname: "register.example", ExpectedAction: "register", Timeout: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := HumanVerification{Token: strings.Repeat("t", 32), Source: "192.0.2.10", IdempotencyKey: "human-attempt-1"}
			if err := verifier.Verify(t.Context(), request); err != ErrHumanUnavailable {
				t.Fatalf("Verify() = %v, want ErrHumanUnavailable", err)
			}
		})
	}
}

func TestTurnstileVerifierRejectsUnsafeCustomCAFilesAndImplicitEndpoint(t *testing.T) {
	server, validCA := newTurnstileTestServer(t, tls.VersionTLS13, func(http.ResponseWriter, *http.Request) {})
	directory := t.TempDir()
	symlink := filepath.Join(directory, "ca-link.pem")
	if err := os.Symlink(validCA, symlink); err != nil {
		t.Fatal(err)
	}
	ownerUnreadable := filepath.Join(directory, "owner-unreadable.pem")
	if err := os.WriteFile(ownerUnreadable, []byte("invalid"), 0o200); err != nil {
		t.Fatal(err)
	}
	groupWritable := filepath.Join(directory, "group-writable.pem")
	encoded, err := os.ReadFile(validCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groupWritable, encoded, 0o620); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupWritable, 0o620); err != nil {
		t.Fatal(err)
	}
	invalidPEM := filepath.Join(directory, "invalid.pem")
	if err := os.WriteFile(invalidPEM, []byte("not a CA PEM"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		endpoint string
		caFile   string
	}{
		{name: "implicit default endpoint", caFile: validCA},
		{name: "relative path", endpoint: server.URL, caFile: "ca.pem"},
		{name: "unclean path", endpoint: server.URL, caFile: filepath.Dir(validCA) + "/./" + filepath.Base(validCA)},
		{name: "symlink", endpoint: server.URL, caFile: symlink},
		{name: "directory", endpoint: server.URL, caFile: directory},
		{name: "owner unreadable", endpoint: server.URL, caFile: ownerUnreadable},
		{name: "group writable", endpoint: server.URL, caFile: groupWritable},
		{name: "invalid PEM", endpoint: server.URL, caFile: invalidPEM},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewTurnstileVerifier(TurnstileConfig{
				Endpoint: test.endpoint, CAFile: test.caFile, Secret: "turnstile-secret-value",
				ExpectedHostname: "register.example", ExpectedAction: "register",
			})
			if err != ErrInvalidConfig {
				t.Fatalf("NewTurnstileVerifier() = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func newTurnstileTestServer(
	t *testing.T,
	maximumTLSVersion uint16,
	handler http.HandlerFunc,
) (*httptest.Server, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "turnstile.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"turnstile.test"},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: maximumTLSVersion,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	caFile := filepath.Join(t.TempDir(), "turnstile-ca.pem")
	if err := os.WriteFile(caFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return server, caFile
}
