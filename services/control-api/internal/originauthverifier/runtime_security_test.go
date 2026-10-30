package originauthverifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
)

type constantResolver struct {
	addresses []netip.Addr
	err       error
	calls     atomic.Int64
}

func (resolver *constantResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	resolver.calls.Add(1)
	return append([]netip.Addr(nil), resolver.addresses...), resolver.err
}

func validRuntimeCredential(config Config) originauthcontrol.CredentialSecret {
	now := config.Now()
	return originauthcontrol.CredentialSecret{
		AccessKeyID: "test-access-not-real", SecretAccessKey: "test-secret-not-real",
		SessionToken: "test-token-not-real", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func providerSet(provider providerVerifier) map[string]providerVerifier {
	return map[string]providerVerifier{
		originauthcontrol.ProviderS3: provider, originauthcontrol.ProviderOSS: provider,
		originauthcontrol.ProviderCOS: provider,
	}
}

func TestNewBuildsProductionProviderSet(t *testing.T) {
	verifier, err := New(validTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil || len(verifier.providers) != 3 || cap(verifier.semaphore) != validTestConfig().MaxConcurrent {
		t.Fatalf("verifier = %#v", verifier)
	}
}

func TestVerifierFailsClosedBeforeDNSForUnsupportedDisabledAndInactiveCredentials(t *testing.T) {
	config := validTestConfig()
	resolver := &constantResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	var providerCalls atomic.Int64
	provider := providerVerifierFunc(func(context.Context, Probe, originauthcontrol.CredentialSecret, *http.Client) error {
		providerCalls.Add(1)
		return nil
	})
	verifier, err := newVerifier(config, resolver, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("must not dial")
	}, providerSet(provider))
	if err != nil {
		t.Fatal(err)
	}
	credential := validRuntimeCredential(config)
	tests := []originauthcontrol.VerificationRequest{
		{Provider: "unsupported", Credential: credential},
		{Provider: originauthcontrol.ProviderS3, Credential: func() originauthcontrol.CredentialSecret {
			value := credential
			value.NotBefore = config.Now().Add(time.Minute)
			return value
		}()},
		{Provider: originauthcontrol.ProviderS3, Credential: func() originauthcontrol.CredentialSecret {
			value := credential
			value.ExpiresAt = config.Now()
			return value
		}()},
	}
	for _, request := range tests {
		result := Classify(verifier.Verify(t.Context(), request))
		if request.Provider == "unsupported" && result.Code != ResultInvalidConfiguration ||
			request.Provider != "unsupported" && result.Code != ResultCredentialRejected {
			t.Fatalf("provider %q result = %#v", request.Provider, result)
		}
	}
	disabled := config
	disabled.S3.Enabled = false
	verifier, err = newVerifier(disabled, resolver, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("must not dial")
	}, providerSet(provider))
	if err != nil {
		t.Fatal(err)
	}
	if result := Classify(verifier.Verify(t.Context(), originauthcontrol.VerificationRequest{
		Provider: originauthcontrol.ProviderS3, Credential: credential,
	})); result.Code != ResultInvalidConfiguration {
		t.Fatalf("disabled provider result = %#v", result)
	}
	if resolver.calls.Load() != 0 || providerCalls.Load() != 0 {
		t.Fatalf("rejected requests reached resolver=%d provider=%d", resolver.calls.Load(), providerCalls.Load())
	}
}

func TestVerifierRejectsProviderEndpointMismatchBeforeDNS(t *testing.T) {
	config := validTestConfig()
	config.OSS = validOSSProbe()
	config.OSS.Region = "cn-beijing"
	config.COS = validCOSProbe()
	config.COS.Region = "ap-beijing"
	resolver := &constantResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	var providerCalls atomic.Int64
	provider := providerVerifierFunc(func(context.Context, Probe, originauthcontrol.CredentialSecret, *http.Client) error {
		providerCalls.Add(1)
		return nil
	})
	verifier, err := newVerifier(config, resolver, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("must not dial")
	}, providerSet(provider))
	if err != nil {
		t.Fatal(err)
	}
	credential := validRuntimeCredential(config)
	for _, providerName := range []string{originauthcontrol.ProviderOSS, originauthcontrol.ProviderCOS} {
		result := Classify(verifier.Verify(t.Context(), originauthcontrol.VerificationRequest{
			Provider: providerName, Credential: credential,
		}))
		if result.Code != ResultInvalidConfiguration {
			t.Fatalf("provider %q result = %#v", providerName, result)
		}
	}
	if resolver.calls.Load() != 0 || providerCalls.Load() != 0 {
		t.Fatalf("invalid probes reached resolver=%d provider=%d", resolver.calls.Load(), providerCalls.Load())
	}
}

func TestVerifierClassifiesEmptyResolutionAndMappedPrivateAddress(t *testing.T) {
	config := validTestConfig()
	credential := validRuntimeCredential(config)
	provider := providerVerifierFunc(func(context.Context, Probe, originauthcontrol.CredentialSecret, *http.Client) error { return nil })
	for name, resolver := range map[string]*constantResolver{
		"empty":  {},
		"mapped": {addresses: []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}},
	} {
		t.Run(name, func(t *testing.T) {
			verifier, err := newVerifier(config, resolver, func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("must not dial")
			}, providerSet(provider))
			if err != nil {
				t.Fatal(err)
			}
			result := Classify(verifier.Verify(t.Context(), originauthcontrol.VerificationRequest{
				Provider: originauthcontrol.ProviderS3, Credential: credential,
			}))
			want := ResultProviderUnavailable
			if name == "mapped" {
				want = ResultInvalidConfiguration
			}
			if result.Code != want {
				t.Fatalf("result = %#v, want %s", result, want)
			}
		})
	}
}

func TestVerifierPreservesCanceledContextBeforeResolution(t *testing.T) {
	config := validTestConfig()
	resolver := &constantResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	verifier, err := newVerifier(config, resolver, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("must not dial")
	}, providerSet(providerVerifierFunc(func(context.Context, Probe, originauthcontrol.CredentialSecret, *http.Client) error {
		return nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = verifier.Verify(ctx, originauthcontrol.VerificationRequest{
		Provider: originauthcontrol.ProviderS3, Credential: validRuntimeCredential(config),
	})
	if !errors.Is(err, context.Canceled) || resolver.calls.Load() != 0 {
		t.Fatalf("error=%v resolver calls=%d", err, resolver.calls.Load())
	}
}

func TestVerifierUsesPinnedTLSAndIgnoresEnvironmentProxy(t *testing.T) {
	var hits atomic.Int64
	var sni atomic.Value
	serverAddress, roots, closeServer := startProbeTLSServer(t, "objects.example.test", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits.Add(1)
		sni.Store(request.TLS.ServerName)
		if request.Method != http.MethodHead {
			t.Errorf("method = %s", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer closeServer()
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	config := validTestConfig()
	config.RootCAs = roots
	verifier := runtimeVerifier(t, config, serverAddress, requestProvider())
	err := verifier.Verify(t.Context(), originauthcontrol.VerificationRequest{
		Provider: originauthcontrol.ProviderS3, Credential: validRuntimeCredential(config),
	})
	if err != nil || hits.Load() != 1 || sni.Load() != "objects.example.test" {
		t.Fatalf("verify error=%v hits=%d sni=%v", err, hits.Load(), sni.Load())
	}
}

func TestVerifierRejectsTLSHostnameMismatch(t *testing.T) {
	serverAddress, roots, closeServer := startProbeTLSServer(t, "wrong.example.test", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler must not receive a request after hostname verification failure")
	}))
	defer closeServer()
	config := validTestConfig()
	config.RootCAs = roots
	verifier := runtimeVerifier(t, config, serverAddress, requestProvider())
	result := Classify(verifier.Verify(t.Context(), originauthcontrol.VerificationRequest{
		Provider: originauthcontrol.ProviderS3, Credential: validRuntimeCredential(config),
	}))
	if result.Code != ResultInvalidConfiguration {
		t.Fatalf("TLS mismatch result = %#v", result)
	}
}

func TestVerifierDoesNotFollowRedirect(t *testing.T) {
	var first, second atomic.Int64
	serverAddress, roots, closeServer := startProbeTLSServer(t, "objects.example.test", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/private" {
			second.Add(1)
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		first.Add(1)
		writer.Header().Set("Location", "https://objects.example.test/private")
		writer.WriteHeader(http.StatusFound)
	}))
	defer closeServer()
	config := validTestConfig()
	config.RootCAs = roots
	verifier := runtimeVerifier(t, config, serverAddress, requestProvider())
	result := Classify(verifier.Verify(t.Context(), originauthcontrol.VerificationRequest{
		Provider: originauthcontrol.ProviderS3, Credential: validRuntimeCredential(config),
	}))
	if result.Code != ResultInvalidConfiguration || first.Load() != 1 || second.Load() != 0 {
		t.Fatalf("redirect result=%#v first=%d second=%d", result, first.Load(), second.Load())
	}
}

func TestVerifierBoundsResponseHeadersAndTotalTimeout(t *testing.T) {
	for name, handler := range map[string]http.Handler{
		"header": http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("X-Oversized", strings.Repeat("x", maxResponseHeaderBytes+1024))
			writer.WriteHeader(http.StatusNoContent)
		}),
		"timeout": http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			time.Sleep(150 * time.Millisecond)
			writer.WriteHeader(http.StatusNoContent)
		}),
	} {
		t.Run(name, func(t *testing.T) {
			serverAddress, roots, closeServer := startProbeTLSServer(t, "objects.example.test", handler)
			defer closeServer()
			config := validTestConfig()
			config.RootCAs = roots
			if name == "timeout" {
				config.ConnectTimeout = 25 * time.Millisecond
				config.TLSHandshakeTimeout = 25 * time.Millisecond
				config.ResponseHeaderTimeout = 40 * time.Millisecond
				config.RequestTimeout = 50 * time.Millisecond
			}
			verifier := runtimeVerifier(t, config, serverAddress, requestProvider())
			result := Classify(verifier.Verify(t.Context(), originauthcontrol.VerificationRequest{
				Provider: originauthcontrol.ProviderS3, Credential: validRuntimeCredential(config),
			}))
			if result.Code != ResultProviderUnavailable {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestVerifierAllowsBoundedTransientFailureRecovery(t *testing.T) {
	serverAddress, roots, closeServer := startProbeTLSServer(t, "objects.example.test", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer closeServer()
	config := validTestConfig()
	config.RootCAs = roots
	resolver := &constantResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	dialer := &net.Dialer{Timeout: time.Second}
	var dials atomic.Int64
	verifier, err := newVerifier(config, resolver, func(ctx context.Context, network, _ string) (net.Conn, error) {
		if dials.Add(1) == 1 {
			return nil, errors.New("transient dial failure")
		}
		return dialer.DialContext(ctx, network, serverAddress)
	}, providerSet(providerVerifierFunc(func(ctx context.Context, probe Probe, _ originauthcontrol.CredentialSecret, client *http.Client) error {
		for attempt := 0; attempt < 2; attempt++ {
			request, requestErr := http.NewRequestWithContext(ctx, http.MethodHead, probe.Endpoint+"/"+probe.Object, nil)
			if requestErr != nil {
				return ErrInvalidConfiguration
			}
			response, requestErr := client.Do(request)
			if requestErr == nil {
				response.Body.Close()
				return nil
			}
		}
		return ErrProviderUnavailable
	})))
	if err != nil {
		t.Fatal(err)
	}
	err = verifier.Verify(t.Context(), originauthcontrol.VerificationRequest{
		Provider: originauthcontrol.ProviderS3, Credential: validRuntimeCredential(config),
	})
	if err != nil || dials.Load() != 2 {
		t.Fatalf("recovery error=%v dials=%d", err, dials.Load())
	}
}

func TestVerifierEnforcesGlobalConcurrency(t *testing.T) {
	config := validTestConfig()
	config.MaxConcurrent = 2
	resolver := &constantResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	release := make(chan struct{})
	var active, peak atomic.Int64
	provider := providerVerifierFunc(func(ctx context.Context, _ Probe, _ originauthcontrol.CredentialSecret, _ *http.Client) error {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	verifier, err := newVerifier(config, resolver, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("not used")
	}, providerSet(provider))
	if err != nil {
		t.Fatal(err)
	}
	credential := validRuntimeCredential(config)
	var wait sync.WaitGroup
	errorsByCall := make(chan error, 5)
	for index := 0; index < 5; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsByCall <- verifier.Verify(context.Background(), originauthcontrol.VerificationRequest{
				Provider: originauthcontrol.ProviderS3, Credential: credential,
			})
		}()
	}
	deadline := time.Now().Add(time.Second)
	for peak.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatal(err)
		}
	}
	if peak.Load() != 2 {
		t.Fatalf("peak concurrency = %d", peak.Load())
	}
}

func TestBoundedTransportRejectsMethodBodyAttemptsAndOversizedBody(t *testing.T) {
	transport := &boundedTransport{base: &http.Transport{}, maxAttempts: 1, maxResponseBytes: 4}
	for _, request := range []*http.Request{
		{Method: http.MethodGet, Body: http.NoBody},
		{Method: http.MethodHead, Body: io.NopCloser(strings.NewReader("x")), ContentLength: 1},
	} {
		if _, err := transport.RoundTrip(request); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("unsafe request error = %v", err)
		}
	}
	attemptLimited := &boundedTransport{base: &http.Transport{}, maxAttempts: 1, maxResponseBytes: 4}
	attemptLimited.attempts.Store(1)
	if _, err := attemptLimited.RoundTrip(&http.Request{
		Method: http.MethodHead, Body: http.NoBody,
		URL: &url.URL{Scheme: "https", Host: "objects.example.test", Path: "/probe"},
	}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("attempt limit error = %v", err)
	}
	body := &boundedBody{reader: io.NopCloser(strings.NewReader("12345")), remaining: 4}
	buffer := make([]byte, 8)
	if read, err := body.Read(buffer); read != 4 || err != nil {
		t.Fatalf("bounded body first read = %d, %v", read, err)
	}
	if _, err := body.Read(buffer); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("body limit error = %v", err)
	}
}

func TestBoundedTransportRejectsNonTLSAndMismatchedAuthorityBeforeBase(t *testing.T) {
	for _, rawURL := range []string{
		"http://objects.example.test/probe",
		"https://127.0.0.1/probe",
		"https://objects.example.test:8443/probe",
		"https://user@objects.example.test/probe",
	} {
		t.Run(rawURL, func(t *testing.T) {
			var baseCalls atomic.Int64
			transport := &boundedTransport{
				base: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
					baseCalls.Add(1)
					return nil, errors.New("base transport called")
				}},
				maxAttempts: 1, maxResponseBytes: 4,
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodHead, rawURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = transport.RoundTrip(request); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("RoundTrip() error = %v, want ErrInvalidConfiguration", err)
			}
			if baseCalls.Load() != 0 {
				t.Fatalf("base transport calls = %d, want 0", baseCalls.Load())
			}
		})
	}
}

func TestConfigRepresentationsRedactProbeTargets(t *testing.T) {
	config := validTestConfig()
	config.S3.Endpoint = "https://sensitive-endpoint.example.test"
	config.S3.Bucket = "sensitive-bucket"
	config.S3.Object = "sensitive/object"
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{config.String(), config.GoString(), string(encoded), config.S3.String(), config.S3.GoString()} {
		for _, sensitive := range []string{config.S3.Endpoint, config.S3.Bucket, config.S3.Object} {
			if strings.Contains(output, sensitive) {
				t.Fatalf("representation leaked target: %q", output)
			}
		}
	}
}

func runtimeVerifier(t *testing.T, config Config, serverAddress string, provider providerVerifier) *Verifier {
	t.Helper()
	resolver := &constantResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	dialer := &net.Dialer{Timeout: time.Second}
	verifier, err := newVerifier(config, resolver, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, serverAddress)
	}, providerSet(provider))
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func requestProvider() providerVerifier {
	return providerVerifierFunc(func(ctx context.Context, probe Probe, _ originauthcontrol.CredentialSecret, client *http.Client) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodHead, probe.Endpoint+"/"+probe.Object, nil)
		if err != nil {
			return ErrInvalidConfiguration
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return nil
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return ErrInvalidConfiguration
		}
		return ErrProviderUnavailable
	})
}

func startProbeTLSServer(t *testing.T, certificateName string, handler http.Handler) (string, *x509.CertPool, func()) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: certificateName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{certificateName},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan struct{})
	go func() {
		_ = server.Serve(tlsListener)
		close(done)
	}()
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return listener.Addr().String(), roots, func() {
		_ = server.Close()
		<-done
	}
}
