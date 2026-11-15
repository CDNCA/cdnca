package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

var kycTestHMAC = bytes.Repeat([]byte{2}, 48)

// completeKYCPage is a KYC provider configuration saved entirely on the page.
func completeKYCPage() systemusersettings.IdentityVerificationRuntime {
	return systemusersettings.IdentityVerificationRuntime{
		KYCProviderName: "page-kyc", KYCEndpoint: "https://kyc.page.example", KYCCallbackKeyID: "page-callback-1",
		ObjectEndpoint: "https://s3.page.example", ObjectRegion: "eu-west-1", ObjectBucket: "page-bucket", ObjectKMSKeyID: "page-kms-1",
		KYCAPIKey: []byte("page-kyc-api-key-0001"), KYCCallbackHMAC: []byte(base64.StdEncoding.EncodeToString(kycTestHMAC)),
		ObjectAccessKey: []byte("PAGEACCESSKEY"), ObjectSecretKey: []byte("page-object-secret"),
	}
}

// Every KYC provider value saved on the page wins; a value
// not saved there comes from IDENTITY_VERIFICATION_*; the provider is
// configured only when all required values are present.
func TestMergeKYCProviderConfigPageFirstEnvironmentFallback(t *testing.T) {
	environment := identityVerificationProviderEnvironment{ProviderName: "env-kyc", ProviderEndpoint: "https://kyc.env.example",
		ObjectRegion: "us-east-1", ObjectPrefix: "env-prefix", ObjectSessionToken: []byte("env-session-token")}
	page := completeKYCPage()
	page.KYCProviderName, page.ObjectRegion = "", ""
	merged, err := mergeKYCProviderConfig(environment, page)
	if err != nil || !merged.complete() {
		t.Fatalf("merged=(%v,%v)", merged.complete(), err)
	}
	defer merged.clear()
	if merged.ProviderName != "env-kyc" || merged.ProviderEndpoint != "https://kyc.page.example" || merged.ObjectRegion != "us-east-1" ||
		merged.ObjectPrefix != "env-prefix" || merged.ObjectBucket != "page-bucket" || string(merged.ObjectSessionToken) != "env-session-token" ||
		string(merged.ProviderAPIKey) != "page-kyc-api-key-0001" || !bytes.Equal(merged.CallbackHMACKey, kycTestHMAC) ||
		string(merged.ObjectAccessKey) != "PAGEACCESSKEY" || merged.ObjectKMSKeyID != "page-kms-1" {
		t.Fatalf("merged=%+v", merged)
	}
	// the inputs are not aliased: clearing the result leaves the environment
	merged.clear()
	if string(environment.ObjectSessionToken) != "env-session-token" {
		t.Fatal("merge aliased the environment fallback")
	}

	// a required value missing on both sides: not configured, no error
	incomplete := completeKYCPage()
	incomplete.ObjectBucket = ""
	if merged, err := mergeKYCProviderConfig(identityVerificationProviderEnvironment{}, incomplete); err != nil || merged.complete() {
		t.Fatalf("incomplete=(%v,%v)", merged.complete(), err)
	}
	// nothing anywhere
	if merged, err := mergeKYCProviderConfig(identityVerificationProviderEnvironment{}, systemusersettings.IdentityVerificationRuntime{}); err != nil || merged.complete() {
		t.Fatalf("empty=(%v,%v)", merged.complete(), err)
	}
	// a broken saved callback key is refused
	broken := completeKYCPage()
	broken.KYCCallbackHMAC = []byte("not base64")
	if _, err := mergeKYCProviderConfig(identityVerificationProviderEnvironment{}, broken); err == nil {
		t.Fatal("invalid page callback key accepted")
	}
}

// The environment may now hold only part of the provider configuration (the
// page completes it); present values are still checked.
func TestLoadIdentityVerificationProviderEnvironmentPartial(t *testing.T) {
	base := []string{
		identityVerificationKYCProviderNameEnv + "=kyc-test", identityVerificationKYCEndpointEnv + "=https://kyc.example.com",
		identityVerificationKYCCallbackKeyIDEnv + "=kyc-key-1", identityVerificationObjectEndpointEnv + "=https://s3.example.com",
		identityVerificationObjectRegionEnv + "=us-east-1", identityVerificationObjectBucketEnv + "=kyc-bucket",
		identityVerificationObjectAccessKeyEnv + "=access-key", identityVerificationObjectSecretKeyEnv + "=object-secret-key",
		identityVerificationObjectKMSKeyEnv + "=kms-key-1",
	}
	partial, err := loadIdentityVerificationProviderEnvironment(base[:2])
	if err != nil || partial.Enabled || partial.ProviderEndpoint != "https://kyc.example.com" {
		t.Fatalf("partial=(%+v,%v)", partial, err)
	}
	// Enabled (the issuer must run) without the two KYC keys, as before; the
	// provider still needs them from the page
	withoutKeys, err := loadIdentityVerificationProviderEnvironment(base)
	if err != nil || !withoutKeys.Enabled || withoutKeys.complete() {
		t.Fatalf("without the KYC keys=(%v,%v,%v)", withoutKeys.Enabled, withoutKeys.complete(), err)
	}
	complete, err := loadIdentityVerificationProviderEnvironment(append(base, identityVerificationKYCAPIKeyEnv+"=env-kyc-api-key-0001",
		identityVerificationKYCCallbackHMACEnv+"="+base64.StdEncoding.EncodeToString(kycTestHMAC)))
	if err != nil || !complete.Enabled || !complete.complete() {
		t.Fatalf("complete=(%v,%v)", complete.Enabled, err)
	}
	for name, entry := range map[string]string{
		"callback key": identityVerificationKYCCallbackHMACEnv + "=short",
		"api key":      identityVerificationKYCAPIKeyEnv + "=short",
		"access key":   identityVerificationObjectAccessKeyEnv + "=a",
	} {
		if _, err := loadIdentityVerificationProviderEnvironment(append([]string{base[0]}, entry)); err == nil {
			t.Fatalf("invalid environment %s accepted", name)
		}
	}
}

type kycPageSource struct {
	revision int64
	page     systemusersettings.IdentityVerificationRuntime
	reads    int
	fail     error
	handed   []systemusersettings.IdentityVerificationRuntime
}

func (source *kycPageSource) runtime(environment identityVerificationProviderEnvironment) *kycPageRuntime {
	return newKYCPageRuntime(environment,
		func(context.Context) (int64, error) { return source.revision, source.fail },
		func(context.Context) (systemusersettings.IdentityVerificationRuntime, error) {
			source.reads++
			page := source.page
			page.KYCAPIKey, page.KYCCallbackHMAC = bytes.Clone(page.KYCAPIKey), bytes.Clone(page.KYCCallbackHMAC)
			page.ObjectAccessKey, page.ObjectSecretKey = bytes.Clone(page.ObjectAccessKey), bytes.Clone(page.ObjectSecretKey)
			source.handed = append(source.handed, page)
			return page, nil
		}, http.DefaultClient, time.Now)
}

// Saving the page applies on the next request (revision change), without a
// restart; until the configuration is complete the provider answers "not
// configured"; clearing the page falls back to the environment.
func TestKYCPageRuntimeHotReload(t *testing.T) {
	source := &kycPageSource{}
	runtime := source.runtime(identityVerificationProviderEnvironment{})
	defer runtime.Close()
	provider, objects := runtime.Provider(), runtime.Objects()
	ctx := t.Context()
	if !provider.Configured() || provider.Name() != "" || !objects.Configured() {
		t.Fatal("the page runtime must mount before it is configured")
	}
	if err := provider.EnsureCredentials(ctx); !errors.Is(err, identityverificationhttp.ErrProviderNotConfigured) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := objects.EncryptionKeyID(ctx); !errors.Is(err, identityverificationhttp.ErrProviderNotConfigured) {
		t.Fatalf("empty key ID: %v", err)
	}
	if _, err := objects.PresignPut(ctx, identityverificationhttp.PrivateObjectPresignRequest{}); !errors.Is(err, identityverificationhttp.ErrProviderNotConfigured) {
		t.Fatalf("empty presign: %v", err)
	}
	if _, err := provider.VerifyCallback(ctx, identityverificationhttp.ProviderCallbackEnvelope{}); !errors.Is(err, identityverificationhttp.ErrProviderNotConfigured) {
		t.Fatalf("empty callback: %v", err)
	}

	// saved on the page
	source.revision, source.page = 1, completeKYCPage()
	if err := provider.EnsureCredentials(ctx); err != nil || provider.Name() != "page-kyc" {
		t.Fatalf("saved: %v name=%q", err, provider.Name())
	}
	if keyID, err := objects.EncryptionKeyID(ctx); err != nil || keyID != "page-kms-1" {
		t.Fatalf("key ID=(%q,%v)", keyID, err)
	}
	for _, handed := range source.handed {
		if !bytes.Equal(handed.KYCAPIKey, make([]byte, len(handed.KYCAPIKey))) ||
			!bytes.Equal(handed.ObjectSecretKey, make([]byte, len(handed.ObjectSecretKey))) {
			t.Fatal("page secret copies not cleared")
		}
	}
	reads := source.reads
	_ = provider.EnsureCredentials(ctx)
	_, _ = objects.EncryptionKeyID(ctx)
	if source.reads != reads {
		t.Fatal("an unchanged revision read the page again")
	}

	// changed on the page
	source.revision = 2
	source.page.KYCProviderName, source.page.ObjectKMSKeyID = "page-kyc-2", "page-kms-2"
	if err := provider.EnsureCredentials(ctx); err != nil || provider.Name() != "page-kyc-2" {
		t.Fatalf("changed: %v name=%q", err, provider.Name())
	}
	if keyID, _ := objects.EncryptionKeyID(ctx); keyID != "page-kms-2" {
		t.Fatalf("changed key ID=%q", keyID)
	}

	// incomplete again
	source.revision = 3
	source.page.ObjectSecretKey = nil
	if err := provider.EnsureCredentials(ctx); !errors.Is(err, identityverificationhttp.ErrProviderNotConfigured) || provider.Name() != "" {
		t.Fatalf("incomplete: %v name=%q", err, provider.Name())
	}

	// the settings cannot be read: unavailable, not "not configured"
	source.revision, source.fail = 4, errors.New("database down")
	if err := provider.EnsureCredentials(ctx); !errors.Is(err, identityverificationhttp.ErrProviderUnavailable) {
		t.Fatalf("settings unreadable: %v", err)
	}
}

// Values the page does not hold come from the environment (complete there:
// configured without anything saved on the page).
func TestKYCPageRuntimeEnvironmentFallback(t *testing.T) {
	environment := identityVerificationProviderEnvironment{Enabled: true, ProviderName: "env-kyc", ProviderEndpoint: "https://kyc.env.example",
		ProviderAPIKey: []byte("env-kyc-api-key-0001"), CallbackKeyID: "env-callback-1", CallbackHMACKey: bytes.Clone(kycTestHMAC),
		ObjectEndpoint: "https://s3.env.example", ObjectRegion: "us-east-1", ObjectBucket: "env-bucket",
		ObjectAccessKey: []byte("ENVACCESSKEY"), ObjectSecretKey: []byte("env-object-secret"), ObjectKMSKeyID: "env-kms-1"}
	source := &kycPageSource{}
	runtime := source.runtime(environment)
	defer runtime.Close()
	environment.clear() // the runtime keeps its own copy
	if err := runtime.Provider().EnsureCredentials(t.Context()); err != nil || runtime.Provider().Name() != "env-kyc" {
		t.Fatalf("environment only: %v", err)
	}
	source.revision = 1
	source.page = systemusersettings.IdentityVerificationRuntime{ObjectKMSKeyID: "page-kms-1"}
	if keyID, err := runtime.Objects().EncryptionKeyID(t.Context()); err != nil || keyID != "page-kms-1" || runtime.Provider().Name() != "env-kyc" {
		t.Fatalf("page overrides one value: (%q,%v)", keyID, err)
	}
}

// With no IDENTITY_VERIFICATION_KYC_* / _OBJECT_* at all the provider
// workflow is still mounted, on the page runtime (it answers "not
// configured" until the page is complete).
func TestIdentityVerificationRuntimeMountsProviderWithoutEnvironment(t *testing.T) {
	for _, name := range []string{identityVerificationKYCProviderNameEnv, identityVerificationKYCEndpointEnv,
		identityVerificationKYCAPIKeyEnv, identityVerificationKYCCallbackKeyIDEnv, identityVerificationKYCCallbackHMACEnv,
		identityVerificationObjectEndpointEnv, identityVerificationObjectRegionEnv, identityVerificationObjectBucketEnv,
		identityVerificationObjectPrefixEnv, identityVerificationObjectAccessKeyEnv, identityVerificationObjectSecretKeyEnv,
		identityVerificationObjectSessionTokenEnv, identityVerificationObjectKMSKeyEnv, identityVerificationIssuerEnabledEnv} {
		t.Setenv(name, "")
	}
	configured := configuredRuntimeTestDependencies(t)
	config, err := loadIdentityVerificationRuntimeConfigFromEnv(identityVerificationRuntimeEnvironment(bytes.Repeat([]byte{0x63}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	var mounted identityverificationhttp.ProductionRuntimeDependencies
	var providerConfig identityverificationhttp.ProviderWorkflowConfig
	runtime, err := openAndClearIdentityVerificationProductionRuntime(t.Context(), &config, identityVerificationProductionDependencies{
		Pool: configured.Pool, Identity: configured.Identity, IAM: configured.IAM, Clock: time.Now,
		NewEvidenceSource: func(context.Context, identityVerificationEvidenceSourceParameters) (identityVerificationEvidenceSource, error) {
			return &identityVerificationEvidenceSourceStub{}, nil
		},
		NewRuntime: func(runtimeConfig identityverificationhttp.ProductionRuntimeConfig,
			dependencies identityverificationhttp.ProductionRuntimeDependencies) (identityVerificationWorkerRuntime, error) {
			mounted, providerConfig = dependencies, runtimeConfig.Runtime.Provider
			providerConfig.TokenKey = bytes.Clone(providerConfig.TokenKey)
			return &identityVerificationWorkerRuntimeStub{handler: http.NotFoundHandler()}, nil
		},
	})
	if err != nil || runtime == nil {
		t.Fatalf("open=(%v,%v)", runtime, err)
	}
	defer runtime.Close()
	if len(providerConfig.TokenKey) == 0 || providerConfig.KindEnabled == nil {
		t.Fatal("provider workflow not mounted without the environment")
	}
	if _, ok := mounted.KYCProvider.(*kycPageProvider); !ok {
		t.Fatalf("KYC provider = %T", mounted.KYCProvider)
	}
	if _, ok := mounted.PrivateObjects.(*kycPageObjects); !ok {
		t.Fatalf("private objects = %T", mounted.PrivateObjects)
	}
	if runtime.IssuerRuntime() != nil {
		t.Fatal("the issuer started without its environment")
	}
}
