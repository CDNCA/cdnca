package main

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// the KYC API key and callback signing key saved on
// the system settings page replace IDENTITY_VERIFICATION_KYC_API_KEY /
// _CALLBACK_HMAC_BASE64; the environment is the fallback, and the provider
// workflow needs both in the end.
func TestMergeIdentityVerificationPageCredentials(t *testing.T) {
	envKey := []byte("environment-kyc-api-key")
	envHMAC := bytes.Repeat([]byte{1}, 32)
	pageHMAC := bytes.Repeat([]byte{2}, 48)
	environment := func() identityVerificationProviderEnvironment {
		return identityVerificationProviderEnvironment{Enabled: true, ProviderAPIKey: bytes.Clone(envKey), CallbackHMACKey: bytes.Clone(envHMAC)}
	}

	// nothing saved on the page: the environment stays
	kept := environment()
	if err := mergeIdentityVerificationPageCredentials(&kept, systemusersettings.IdentityVerificationRuntime{}); err != nil ||
		!bytes.Equal(kept.ProviderAPIKey, envKey) || !bytes.Equal(kept.CallbackHMACKey, envHMAC) {
		t.Fatalf("fallback=(%q,%v)", kept.ProviderAPIKey, err)
	}

	// saved on the page: the page wins, the copies are cleared
	page := systemusersettings.IdentityVerificationRuntime{KYCAPIKey: []byte("page-kyc-api-key-0001"),
		KYCCallbackHMAC: []byte(base64.StdEncoding.EncodeToString(pageHMAC))}
	replaced := environment()
	if err := mergeIdentityVerificationPageCredentials(&replaced, page); err != nil ||
		string(replaced.ProviderAPIKey) != "page-kyc-api-key-0001" || !bytes.Equal(replaced.CallbackHMACKey, pageHMAC) {
		t.Fatalf("page first=(%q,%v)", replaced.ProviderAPIKey, err)
	}
	if !bytes.Equal(page.KYCAPIKey, make([]byte, len(page.KYCAPIKey))) {
		t.Fatal("page API key copy not cleared")
	}

	// only the page provides them: the environment may leave both out
	pageOnly := identityVerificationProviderEnvironment{Enabled: true}
	if err := mergeIdentityVerificationPageCredentials(&pageOnly, systemusersettings.IdentityVerificationRuntime{
		KYCAPIKey: []byte("page-kyc-api-key-0001"), KYCCallbackHMAC: []byte(base64.StdEncoding.EncodeToString(pageHMAC))}); err != nil {
		t.Fatalf("page only: %v", err)
	}

	// a key missing everywhere is no error: the provider stays mounted and
	// answers "not configured" (both keys or neither go to the provider)
	missing := identityVerificationProviderEnvironment{Enabled: true, CallbackHMACKey: bytes.Clone(envHMAC)}
	if err := mergeIdentityVerificationPageCredentials(&missing, systemusersettings.IdentityVerificationRuntime{}); err != nil {
		t.Fatalf("missing API key: %v", err)
	}
	if apiKey, hmac := effectiveKYCCredentials(missing); apiKey != nil || hmac != nil {
		t.Fatalf("half-set credentials reached the provider: %q %q", apiKey, hmac)
	}
	if apiKey, hmac := effectiveKYCCredentials(kept); !bytes.Equal(apiKey, envKey) || !bytes.Equal(hmac, envHMAC) {
		t.Fatal("complete credentials were dropped")
	}
	// a broken saved callback key is refused
	broken := environment()
	if err := mergeIdentityVerificationPageCredentials(&broken, systemusersettings.IdentityVerificationRuntime{KYCCallbackHMAC: []byte("not base64")}); err == nil {
		t.Fatal("invalid page callback key accepted")
	}
	// the provider workflow disabled: nothing to merge
	off := identityVerificationProviderEnvironment{}
	if err := mergeIdentityVerificationPageCredentials(&off, systemusersettings.IdentityVerificationRuntime{}); err != nil || off.ProviderAPIKey != nil {
		t.Fatalf("disabled=(%+v,%v)", off, err)
	}
}

// The environment loader no longer requires the two KYC credentials (they may
// be saved on the page) but still validates them when present.
func TestLoadIdentityVerificationProviderEnvironmentCredentialsOptional(t *testing.T) {
	base := []string{
		identityVerificationKYCProviderNameEnv + "=kyc-test", identityVerificationKYCEndpointEnv + "=https://kyc.example.com",
		identityVerificationKYCCallbackKeyIDEnv + "=kyc-key-1", identityVerificationObjectEndpointEnv + "=https://s3.example.com",
		identityVerificationObjectRegionEnv + "=us-east-1", identityVerificationObjectBucketEnv + "=kyc-bucket",
		identityVerificationObjectAccessKeyEnv + "=access-key", identityVerificationObjectSecretKeyEnv + "=object-secret-key",
		identityVerificationObjectKMSKeyEnv + "=kms-key-1",
	}
	loaded, err := loadIdentityVerificationProviderEnvironment(base)
	if err != nil || !loaded.Enabled || len(loaded.ProviderAPIKey) != 0 || len(loaded.CallbackHMACKey) != 0 {
		t.Fatalf("without credentials=(%+v,%v)", loaded.Enabled, err)
	}
	if _, err := loadIdentityVerificationProviderEnvironment(append(base, identityVerificationKYCCallbackHMACEnv+"=short")); err == nil {
		t.Fatal("invalid environment callback key accepted")
	}
	if _, err := loadIdentityVerificationProviderEnvironment(append(base, identityVerificationKYCAPIKeyEnv+"=short")); err == nil {
		t.Fatal("short environment API key accepted")
	}
}
