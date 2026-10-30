package originauthverifier

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
)

type testResolver struct {
	answers [][]netip.Addr
	calls   atomic.Int64
}

func (resolver *testResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	index := int(resolver.calls.Add(1) - 1)
	if index >= len(resolver.answers) {
		return nil, nil
	}
	return append([]netip.Addr(nil), resolver.answers[index]...), nil
}

func validTestConfig() Config {
	probe := Probe{
		Endpoint: "https://objects.example.test",
		Region:   "test-region-1",
		Bucket:   "isolated-read-only-probe",
		Object:   "cdnca/verifier/probe.txt",
		Enabled:  true,
	}
	return Config{
		S3: probe, OSS: probe, COS: probe,
		ConnectTimeout: 100 * time.Millisecond, TLSHandshakeTimeout: 100 * time.Millisecond,
		ResponseHeaderTimeout: 100 * time.Millisecond, RequestTimeout: 500 * time.Millisecond,
		MaxResponseBytes: 4096, MaxAttempts: 2, MaxConcurrent: 2,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

func TestNewRejectsUnsafeConfigurationWithoutRenderingSensitiveValues(t *testing.T) {
	secretEndpoint := "endpoint-secret.example.test"
	secretObject := "private/object-secret"
	valid := validTestConfig()
	tests := map[string]func(*Config){
		"plain HTTP":       func(config *Config) { config.S3.Endpoint = "http://" + secretEndpoint },
		"userinfo":         func(config *Config) { config.S3.Endpoint = "https://user:pass@" + secretEndpoint },
		"query":            func(config *Config) { config.S3.Endpoint = "https://" + secretEndpoint + "?token=x" },
		"redirect path":    func(config *Config) { config.S3.Endpoint = "https://" + secretEndpoint + "/api" },
		"non TLS port":     func(config *Config) { config.S3.Endpoint = "https://" + secretEndpoint + ":8443" },
		"IP endpoint":      func(config *Config) { config.S3.Endpoint = "https://8.8.8.8" },
		"object traversal": func(config *Config) { config.S3.Object = "a/../" + secretObject },
		"empty object":     func(config *Config) { config.S3.Object = "" },
		"attempts":         func(config *Config) { config.MaxAttempts = 4 },
		"concurrency":      func(config *Config) { config.MaxConcurrent = 21 },
		"response bytes":   func(config *Config) { config.MaxResponseBytes = 0 },
		"request timeout":  func(config *Config) { config.RequestTimeout = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.S3.Object = secretObject
			mutate(&config)
			_, err := newVerifier(config, &testResolver{}, nil, nil)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v", err)
			}
			if strings.Contains(err.Error(), secretEndpoint) || strings.Contains(err.Error(), secretObject) {
				t.Fatalf("error leaked endpoint or object: %q", err)
			}
		})
	}
}

func TestResolvePinsPublicAddressesAndRejectsRebindingAnswers(t *testing.T) {
	resolver := &testResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700:4700::1111")},
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")},
	}}
	target, err := resolveProbe(t.Context(), validTestConfig().S3, resolver)
	if err != nil || len(target.addresses) != 2 || target.serverName != "objects.example.test" {
		t.Fatalf("first resolution = %#v, %v", target, err)
	}
	if _, err := resolveProbe(t.Context(), validTestConfig().S3, resolver); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("rebound resolution error = %v", err)
	}
}

func TestResolveRejectsEveryNonPublicAddressClass(t *testing.T) {
	blocked := []string{
		"0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.168.0.1", "198.18.0.1", "224.0.0.1", "240.0.0.1",
		"::", "::1", "64:ff9b::7f00:1", "64:ff9b:1::1", "100::1", "2001:2::1", "2001:db8::1", "2002::1",
		"3fff::1", "5f00::1", "fc00::1", "fe80::1", "fec0::1", "ff00::1",
	}
	for _, address := range blocked {
		t.Run(address, func(t *testing.T) {
			resolver := &testResolver{answers: [][]netip.Addr{{netip.MustParseAddr(address)}}}
			if _, err := resolveProbe(t.Context(), validTestConfig().S3, resolver); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("resolve %s error = %v", address, err)
			}
		})
	}
}

func TestPinnedTransportDisablesProxyRedirectsAndUnexpectedDialTargets(t *testing.T) {
	target := resolvedProbe{
		serverName: "objects.example.test", port: "443",
		addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
	}
	var gotAddress string
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		gotAddress = address
		return nil, errors.New("stop after observing address")
	}
	client := newPinnedClient(validTestConfig(), target, dial)
	transport, ok := client.Transport.(*boundedTransport)
	if !ok || transport.base.Proxy != nil || !transport.base.DisableKeepAlives ||
		transport.base.MaxConnsPerHost != validTestConfig().MaxConcurrent ||
		transport.base.TLSClientConfig.ServerName != target.serverName {
		t.Fatalf("unsafe transport = %#v", client.Transport)
	}
	if !errors.Is(client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) {
		t.Fatal("redirects were not disabled")
	}
	_, _ = transport.base.DialContext(t.Context(), "tcp", "objects.example.test:443")
	if gotAddress != "8.8.8.8:443" {
		t.Fatalf("dialed %q", gotAddress)
	}
	if _, err := transport.base.DialContext(t.Context(), "tcp", "127.0.0.1:443"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("unexpected dial target error = %v", err)
	}
}

func TestClassifyIsStableAndRedactsProviderFailures(t *testing.T) {
	secret := "provider-raw-secret"
	tests := []struct {
		err  error
		code string
	}{
		{nil, ResultAccepted},
		{errors.Join(ErrCredentialRejected, errors.New(secret)), ResultCredentialRejected},
		{errors.Join(ErrProviderUnavailable, errors.New(secret)), ResultProviderUnavailable},
		{errors.Join(ErrInvalidConfiguration, errors.New(secret)), ResultInvalidConfiguration},
	}
	for _, test := range tests {
		result := Classify(test.err)
		if result.Code != test.code {
			t.Fatalf("Classify() = %#v", result)
		}
		mapped := publicError(test.err)
		if mapped != nil && strings.Contains(mapped.Error(), secret) {
			t.Fatalf("public error leaked provider detail: %q", mapped)
		}
	}
	if !errors.Is(publicError(ErrCredentialRejected), originauthcontrol.ErrVerificationRejected) {
		t.Fatal("credential rejection did not map to control contract")
	}
}
