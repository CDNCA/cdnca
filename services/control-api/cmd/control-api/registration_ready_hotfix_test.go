package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

type recordingHumanVerifier struct{ calls int }

func (verifier *recordingHumanVerifier) Verify(context.Context, accountregistrationchallenge.HumanVerification) error {
	verifier.calls++
	return nil
}

// the Turnstile flow checks the built-in image
// CAPTCHA until Turnstile is configured, then Turnstile only.
func TestRegistrationHumanVerifierFallsBackUntilTurnstileIsConfigured(t *testing.T) {
	turnstile, captcha := &recordingHumanVerifier{}, &recordingHumanVerifier{}
	ready, readyErr := false, error(nil)
	verifier := registrationHumanVerifier{turnstile: turnstile, fallback: captcha,
		ready: func(context.Context) (bool, error) { return ready, readyErr }}
	check := func() error {
		return verifier.Verify(t.Context(), accountregistrationchallenge.HumanVerification{Token: "t"})
	}
	if err := check(); err != nil || captcha.calls != 1 || turnstile.calls != 0 {
		t.Fatalf("not configured: err=%v captcha=%d turnstile=%d", err, captcha.calls, turnstile.calls)
	}
	ready = true
	if err := check(); err != nil || captcha.calls != 1 || turnstile.calls != 1 {
		t.Fatalf("configured: err=%v captcha=%d turnstile=%d", err, captcha.calls, turnstile.calls)
	}
	readyErr = errors.New("database down")
	if err := check(); !errors.Is(err, accountregistrationchallenge.ErrHumanUnavailable) {
		t.Fatalf("unreadable configuration = %v", err)
	}
	// no fallback wired: Turnstile only, as before
	only := registrationHumanVerifier{turnstile: turnstile}
	if err := only.Verify(t.Context(), accountregistrationchallenge.HumanVerification{}); err != nil || turnstile.calls != 2 {
		t.Fatalf("turnstile only: err=%v calls=%d", err, turnstile.calls)
	}
}

// The KYC credentials saved on the settings page apply to the next KYC
// request without restarting control-api; clearing them falls back to the
// environment; an unchanged revision does not decrypt again.
func TestKYCPageCredentialsApplyWithoutRestart(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		seen = append(seen, request.Header.Get("Authorization"))
		mu.Unlock()
		http.Error(writer, "test", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	envKey, envHMAC := []byte("environment-kyc-api-key"), bytes.Repeat([]byte{1}, 32)
	// the provider only accepts a public host name on 443: dial the test server for it
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client.Transport = transport
	inner, err := identityverificationhttp.NewHTTPSKYCProvider(identityverificationhttp.HTTPSKYCProviderConfig{
		Name: "kyc", Endpoint: "https://example.com", APIKey: envKey, CallbackKeyID: "key-1", CallbackHMACKey: envHMAC,
		CallbackMaxAge: time.Minute, RequestTimeout: 5 * time.Second,
	}, client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	revision, reads := int64(3), 0
	var page systemusersettings.IdentityVerificationRuntime
	provider := newKYCPageCredentialProvider(inner, nil, nil,
		identityVerificationProviderEnvironment{ProviderAPIKey: envKey, CallbackHMACKey: envHMAC}, revision)
	provider.revisionOf = func(context.Context) (int64, error) { return revision, nil }
	provider.page = func(context.Context) (systemusersettings.IdentityVerificationRuntime, error) {
		reads++
		return systemusersettings.IdentityVerificationRuntime{KYCAPIKey: bytes.Clone(page.KYCAPIKey),
			KYCCallbackHMAC: bytes.Clone(page.KYCCallbackHMAC)}, nil
	}
	defer provider.Close()
	create := func() string {
		t.Helper()
		_, _ = provider.CreateSession(t.Context(), identityverificationhttp.ProviderSessionCreate{
			LocalSessionID: uuid.New(), TenantScopeID: uuid.New(), ActorUserID: uuid.New(),
			Kind: identityverification.KindPersonalInitial, ProviderRequestID: "request-1", ExpiresAt: time.Now().Add(time.Hour)})
		mu.Lock()
		defer mu.Unlock()
		return seen[len(seen)-1]
	}
	if got := create(); got != "Bearer environment-kyc-api-key" || reads != 0 {
		t.Fatalf("start: %q reads=%d", got, reads)
	}
	// saved on the page (revision 4): the next request uses it
	page = systemusersettings.IdentityVerificationRuntime{KYCAPIKey: []byte("page-kyc-api-key-0001"),
		KYCCallbackHMAC: []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 48)))}
	revision = 4
	if got := create(); got != "Bearer page-kyc-api-key-0001" || reads != 1 {
		t.Fatalf("after the page: %q reads=%d", got, reads)
	}
	if got := create(); got != "Bearer page-kyc-api-key-0001" || reads != 1 {
		t.Fatalf("unchanged revision decrypted again: %q reads=%d", got, reads)
	}
	// cleared on the page: back to the environment
	page, revision = systemusersettings.IdentityVerificationRuntime{}, 5
	if got := create(); got != "Bearer environment-kyc-api-key" || reads != 2 {
		t.Fatalf("after clearing: %q reads=%d", got, reads)
	}
}
