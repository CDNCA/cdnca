package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The KYC provider and its private object store are built
// from the system settings page ("认证与支付") with IDENTITY_VERIFICATION_* as
// the per-value fallback, and rebuilt when the settings revision changes, so a
// save applies without restarting control-api. With nothing configured
// anywhere the provider workflow is still mounted and answers
// identity_verification_not_configured.

// complete reports whether every value the provider and the object store
// need is present (the object prefix and session token are optional).
func (config identityVerificationProviderEnvironment) complete() bool {
	return config.ProviderName != "" && config.ProviderEndpoint != "" && len(config.ProviderAPIKey) != 0 &&
		config.CallbackKeyID != "" && len(config.CallbackHMACKey) != 0 && config.ObjectEndpoint != "" &&
		config.ObjectRegion != "" && config.ObjectBucket != "" && len(config.ObjectAccessKey) != 0 &&
		len(config.ObjectSecretKey) != 0 && config.ObjectKMSKeyID != ""
}

// mergeKYCProviderConfig takes each value from the page when saved there and
// from the environment otherwise (complete() tells whether it is usable). The
// result holds its own copies of the secrets (the caller clears it).
func mergeKYCProviderConfig(environment identityVerificationProviderEnvironment,
	page systemusersettings.IdentityVerificationRuntime,
) (identityVerificationProviderEnvironment, error) {
	text := func(pageValue, environmentValue string) string {
		if pageValue != "" {
			return pageValue
		}
		return environmentValue
	}
	secret := func(pageValue, environmentValue []byte) []byte {
		if len(pageValue) != 0 {
			return bytes.Clone(pageValue)
		}
		return bytes.Clone(environmentValue)
	}
	result := identityVerificationProviderEnvironment{
		ProviderName:       text(page.KYCProviderName, environment.ProviderName),
		ProviderEndpoint:   text(page.KYCEndpoint, environment.ProviderEndpoint),
		ProviderAPIKey:     secret(page.KYCAPIKey, environment.ProviderAPIKey),
		CallbackKeyID:      text(page.KYCCallbackKeyID, environment.CallbackKeyID),
		ObjectEndpoint:     text(page.ObjectEndpoint, environment.ObjectEndpoint),
		ObjectRegion:       text(page.ObjectRegion, environment.ObjectRegion),
		ObjectBucket:       text(page.ObjectBucket, environment.ObjectBucket),
		ObjectPrefix:       text(page.ObjectPrefix, environment.ObjectPrefix),
		ObjectAccessKey:    secret(page.ObjectAccessKey, environment.ObjectAccessKey),
		ObjectSecretKey:    secret(page.ObjectSecretKey, environment.ObjectSecretKey),
		ObjectSessionToken: secret(page.ObjectSessionToken, environment.ObjectSessionToken),
		ObjectKMSKeyID:     text(page.ObjectKMSKeyID, environment.ObjectKMSKeyID),
	}
	if len(page.KYCCallbackHMAC) != 0 {
		decoded, err := decodeIdentityVerificationCallbackHMAC(string(page.KYCCallbackHMAC))
		if err != nil {
			result.clear()
			return identityVerificationProviderEnvironment{}, errors.New("the KYC callback signing key saved on the system settings page is invalid")
		}
		result.CallbackHMACKey = decoded
	} else {
		result.CallbackHMACKey = bytes.Clone(environment.CallbackHMACKey)
	}
	return result, nil
}

// buildKYCProvider builds the HTTPS KYC provider and the S3 private object
// store of a complete configuration.
func buildKYCProvider(config identityVerificationProviderEnvironment, client *http.Client, now func() time.Time,
) (*identityverificationhttp.HTTPSKYCProvider, identityverificationhttp.PrivateObjectStore, error) {
	if !config.complete() {
		return nil, nil, identityverificationhttp.ErrProviderNotConfigured
	}
	provider, err := identityverificationhttp.NewHTTPSKYCProvider(identityverificationhttp.HTTPSKYCProviderConfig{
		Name: config.ProviderName, Endpoint: config.ProviderEndpoint, APIKey: config.ProviderAPIKey,
		CallbackKeyID: config.CallbackKeyID, CallbackHMACKey: config.CallbackHMACKey,
		CallbackMaxAge: 5 * time.Minute, CallbackFutureSkew: 30 * time.Second, RequestTimeout: 15 * time.Second,
	}, client, now)
	if err != nil {
		return nil, nil, errors.New("initialize identity verification KYC provider")
	}
	accessKey, secretKey, sessionToken := string(config.ObjectAccessKey), string(config.ObjectSecretKey), string(config.ObjectSessionToken)
	objects, err := identityverificationhttp.NewS3PrivateObjectStore(identityverificationhttp.S3PrivateObjectStoreConfig{
		Endpoint: config.ObjectEndpoint, Region: config.ObjectRegion, Bucket: config.ObjectBucket, Prefix: config.ObjectPrefix,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey, SessionToken: sessionToken,
				Source: "identity-verification-runtime"}, nil
		}),
		RequestTimeout: 15 * time.Second, MaxAttempts: 3,
	}, client, now)
	if err != nil {
		provider.Close()
		return nil, nil, errors.New("initialize identity verification private object store")
	}
	return provider, objects, nil
}

// kycPageRuntime holds the provider and object store of the current
// settings revision (nil: not configured).
type kycPageRuntime struct {
	revisionOf  func(context.Context) (int64, error)
	page        func(context.Context) (systemusersettings.IdentityVerificationRuntime, error)
	environment identityVerificationProviderEnvironment
	client      *http.Client
	now         func() time.Time

	mu       sync.Mutex
	loaded   bool
	revision int64
	// buildErr: the configuration of this revision could not be built
	buildErr error
	provider *identityverificationhttp.HTTPSKYCProvider
	objects  identityverificationhttp.PrivateObjectStore
	keyID    string
	closed   bool
}

func newKYCPageRuntime(environment identityVerificationProviderEnvironment,
	revisionOf func(context.Context) (int64, error),
	page func(context.Context) (systemusersettings.IdentityVerificationRuntime, error),
	client *http.Client, now func() time.Time,
) *kycPageRuntime {
	fallback, _ := mergeKYCProviderConfig(environment, systemusersettings.IdentityVerificationRuntime{})
	return &kycPageRuntime{revisionOf: revisionOf, page: page, environment: fallback, client: client, now: now}
}

func newKYCSettingsPageRuntime(environment identityVerificationProviderEnvironment, pool *pgxpool.Pool,
	settings *systemusersettings.Service, client *http.Client, now func() time.Time,
) *kycPageRuntime {
	return newKYCPageRuntime(environment, func(ctx context.Context) (int64, error) { return kycSettingsRevision(ctx, pool) },
		settings.IdentityVerificationRuntime, client, now)
}

// kycSettingsRevision is the platform user settings revision (0: never saved).
func kycSettingsRevision(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var revision int64
	err := pool.QueryRow(ctx, `SELECT coalesce(max(revision),0) FROM platform_system_user_settings`).Scan(&revision)
	return revision, err
}

// current refreshes on a revision change and returns the provider and store
// (ErrProviderNotConfigured while the configuration is incomplete).
func (runtime *kycPageRuntime) current(ctx context.Context) (*identityverificationhttp.HTTPSKYCProvider,
	identityverificationhttp.PrivateObjectStore, string, error) {
	if ctx == nil {
		return nil, nil, "", identityverificationhttp.ErrProviderUnavailable
	}
	revision, err := runtime.revisionOf(ctx)
	if err != nil {
		return nil, nil, "", identityverificationhttp.ErrProviderUnavailable
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		return nil, nil, "", identityverificationhttp.ErrProviderUnavailable
	}
	if !runtime.loaded || revision != runtime.revision {
		if err := runtime.reload(ctx, revision); err != nil {
			return nil, nil, "", err
		}
	}
	if runtime.buildErr != nil {
		return nil, nil, "", runtime.buildErr
	}
	if runtime.provider == nil {
		return nil, nil, "", identityverificationhttp.ErrProviderNotConfigured
	}
	return runtime.provider, runtime.objects, runtime.keyID, nil
}

// reload rebuilds from the page of revision (caller holds mu). A settings
// read failure is retried on the next call; a configuration that cannot be
// built is remembered for its revision.
func (runtime *kycPageRuntime) reload(ctx context.Context, revision int64) error {
	page, err := runtime.page(ctx)
	defer page.Clear()
	if err != nil {
		return identityverificationhttp.ErrProviderUnavailable
	}
	// Calls already holding the previous provider finish with it; it is
	// dropped, not closed.
	runtime.provider, runtime.objects, runtime.keyID, runtime.buildErr = nil, nil, "", nil
	runtime.loaded, runtime.revision = true, revision
	config, err := mergeKYCProviderConfig(runtime.environment, page)
	defer config.clear()
	if err != nil {
		runtime.buildErr = identityverificationhttp.ErrProviderUnavailable
		return nil
	}
	if !config.complete() {
		return nil
	}
	provider, objects, err := buildKYCProvider(config, runtime.client, runtime.now)
	if err != nil {
		runtime.buildErr = identityverificationhttp.ErrProviderUnavailable
		return nil
	}
	runtime.provider, runtime.objects, runtime.keyID = provider, objects, config.ObjectKMSKeyID
	return nil
}

func (runtime *kycPageRuntime) name() string {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.provider == nil || runtime.closed {
		return ""
	}
	return runtime.provider.Name()
}

func (runtime *kycPageRuntime) Close() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.provider != nil {
		runtime.provider.Close()
	}
	runtime.provider, runtime.objects, runtime.closed = nil, nil, true
	runtime.environment.clear()
}

func (runtime *kycPageRuntime) Provider() *kycPageProvider { return &kycPageProvider{runtime: runtime} }
func (runtime *kycPageRuntime) Objects() *kycPageObjects   { return &kycPageObjects{runtime: runtime} }

// kycPageProvider is the identityverificationhttp.KYCProvider of the page
// runtime.
type kycPageProvider struct{ runtime *kycPageRuntime }

func (provider *kycPageProvider) Configured() bool {
	provider.runtime.mu.Lock()
	defer provider.runtime.mu.Unlock()
	return !provider.runtime.closed
}
func (provider *kycPageProvider) Name() string { return provider.runtime.name() }
func (provider *kycPageProvider) Close()       { provider.runtime.Close() }

// EnsureCredentials picks up the page configuration saved since the last call
// and refuses with "not configured" while it is incomplete. The provider
// workflow calls it before it writes anything.
func (provider *kycPageProvider) EnsureCredentials(ctx context.Context) error {
	_, _, _, err := provider.runtime.current(ctx)
	return err
}

func (provider *kycPageProvider) CreateSession(ctx context.Context,
	request identityverificationhttp.ProviderSessionCreate) (identityverificationhttp.ProviderSessionCreated, error) {
	current, _, _, err := provider.runtime.current(ctx)
	if err != nil {
		return identityverificationhttp.ProviderSessionCreated{}, err
	}
	return current.CreateSession(ctx, request)
}

func (provider *kycPageProvider) VerifyCallback(ctx context.Context,
	envelope identityverificationhttp.ProviderCallbackEnvelope) (identityverificationhttp.VerifiedProviderCallback, error) {
	current, _, _, err := provider.runtime.current(ctx)
	if err != nil {
		return identityverificationhttp.VerifiedProviderCallback{}, err
	}
	return current.VerifyCallback(ctx, envelope)
}

// kycPageObjects is the identityverificationhttp.PrivateObjectStore of the
// page runtime; it also supplies the KMS key ID of new uploads.
type kycPageObjects struct{ runtime *kycPageRuntime }

func (objects *kycPageObjects) Configured() bool {
	objects.runtime.mu.Lock()
	defer objects.runtime.mu.Unlock()
	return !objects.runtime.closed
}

func (objects *kycPageObjects) EncryptionKeyID(ctx context.Context) (string, error) {
	_, _, keyID, err := objects.runtime.current(ctx)
	return keyID, err
}

func (objects *kycPageObjects) PresignPut(ctx context.Context,
	request identityverificationhttp.PrivateObjectPresignRequest) (identityverificationhttp.PrivateObjectPresignResult, error) {
	_, store, _, err := objects.runtime.current(ctx)
	if err != nil {
		return identityverificationhttp.PrivateObjectPresignResult{}, err
	}
	return store.PresignPut(ctx, request)
}

func (objects *kycPageObjects) Stat(ctx context.Context, objectKey string) (identityverificationhttp.PrivateObjectReference, error) {
	_, store, _, err := objects.runtime.current(ctx)
	if err != nil {
		return identityverificationhttp.PrivateObjectReference{}, err
	}
	return store.Stat(ctx, objectKey)
}

func (objects *kycPageObjects) Delete(ctx context.Context,
	reference identityverificationhttp.PrivateObjectReference) (identityverificationhttp.PrivateObjectDeleteReceipt, error) {
	_, store, _, err := objects.runtime.current(ctx)
	if err != nil {
		return identityverificationhttp.PrivateObjectDeleteReceipt{}, err
	}
	return store.Delete(ctx, reference)
}
