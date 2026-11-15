package identityverificationhttp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIAM10KYCProviderEndpointRejectsSSRFAndUnsafePaths(t *testing.T) {
	for _, endpoint := range []string{
		"http://kyc.example.test", "https://127.0.0.1", "https://[::1]",
		"https://user:pass@kyc.example.test", "https://kyc.example.test/path",
		"https://kyc.example.test?secret=value", "https://localhost",
	} {
		if _, err := validateKYCProviderEndpoint(endpoint); err == nil {
			t.Errorf("unsafe endpoint %q was accepted", endpoint)
		}
	}
	parsed, err := validateKYCProviderEndpoint("https://kyc.example.test:443")
	if err != nil || parsed.String() != "https://kyc.example.test:443" {
		t.Fatalf("valid endpoint=(%v,%v)", parsed, err)
	}
}

func TestIAM10HTTPSProviderVerifiesSignatureTimestampAndNonce(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC)
	provider, err := NewHTTPSKYCProvider(HTTPSKYCProviderConfig{
		Name: "trusted-kyc", Endpoint: "https://kyc.example.test", APIKey: []byte("outbound-api-key"),
		CallbackKeyID: "callback-key-1", CallbackHMACKey: key,
		CallbackMaxAge: 5 * time.Minute, CallbackFutureSkew: 30 * time.Second,
	}, http.DefaultClient, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	body := []byte(`{"event_id":"event-1","session_id":"` + uuid.NewString() +
		`","external_session_id":"external-1","state":"processing","occurred_at":"2026-08-08T10:59:00Z"}`)
	timestamp := "1786186800"
	nonce := "nonce-0000000000000001"
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(timestamp + "\n" + nonce + "\n"))
	_, _ = mac.Write(body)
	headers := http.Header{
		"X-KYC-Timestamp": []string{timestamp}, "X-KYC-Nonce": []string{nonce},
		"X-KYC-Key-ID":    []string{"callback-key-1"},
		"X-KYC-Signature": []string{base64.StdEncoding.EncodeToString(mac.Sum(nil))},
		"Content-Type":    []string{"application/json"},
	}
	verified, err := provider.VerifyCallback(t.Context(), ProviderCallbackEnvelope{Provider: "trusted-kyc", Header: headers, Body: body})
	payloadDigest := sha256Digest(body)
	if err != nil || verified.EventID != "event-1" || verified.Nonce != nonce ||
		hex.EncodeToString(verified.PayloadSHA256[:]) != hex.EncodeToString(payloadDigest[:]) {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
	headers.Set("X-KYC-Signature", base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)))
	if _, err := provider.VerifyCallback(t.Context(), ProviderCallbackEnvelope{Provider: "trusted-kyc", Header: headers, Body: body}); err == nil {
		t.Fatal("invalid callback signature was accepted")
	}
}

// Without credentials the provider is still mounted; its calls answer "not
// configured" and saving the keys later makes it work without a restart.
func TestHTTPSProviderWithoutCredentialsAnswersNotConfigured(t *testing.T) {
	now := time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC)
	provider, err := NewHTTPSKYCProvider(HTTPSKYCProviderConfig{
		Name: "trusted-kyc", Endpoint: "https://kyc.example.test", CallbackKeyID: "callback-key-1",
		CallbackMaxAge: 5 * time.Minute, CallbackFutureSkew: 30 * time.Second,
	}, http.DefaultClient, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if !provider.Configured() || provider.CredentialsReady() {
		t.Fatalf("configured=%v ready=%v", provider.Configured(), provider.CredentialsReady())
	}
	if _, err := provider.CreateSession(t.Context(), ProviderSessionCreate{}); !errors.Is(err, ErrProviderNotConfigured) {
		t.Fatalf("CreateSession err=%v", err)
	}
	if _, err := provider.VerifyCallback(t.Context(), ProviderCallbackEnvelope{}); !errors.Is(err, ErrProviderNotConfigured) {
		t.Fatalf("VerifyCallback err=%v", err)
	}
	if provider.SetCredentials([]byte("short"), nil) == nil {
		t.Fatal("half-set credentials accepted")
	}
	if err := provider.SetCredentials([]byte("outbound-api-key"), []byte("0123456789abcdef0123456789abcdef")); err != nil || !provider.CredentialsReady() {
		t.Fatalf("set err=%v ready=%v", err, provider.CredentialsReady())
	}
	if err := provider.SetCredentials(nil, nil); err != nil || provider.CredentialsReady() {
		t.Fatalf("clear err=%v ready=%v", err, provider.CredentialsReady())
	}
}

func sha256Digest(value []byte) [sha256.Size]byte { return sha256.Sum256(value) }
