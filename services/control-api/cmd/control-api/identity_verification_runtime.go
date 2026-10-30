package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	identityVerificationEnabledEnv                 = "IDENTITY_VERIFICATION_RUNTIME_ENABLED"
	identityVerificationCursorKeyBase64Env         = "IDENTITY_VERIFICATION_CURSOR_KEY_BASE64"
	identityVerificationResolverNameEnv            = "IDENTITY_VERIFICATION_RESOLVER_NAME"
	identityVerificationReviewTTLEnv               = "IDENTITY_VERIFICATION_REVIEW_TTL"
	identityVerificationRetentionPeriodEnv         = "IDENTITY_VERIFICATION_RETENTION_PERIOD"
	identityVerificationWorkerEnabledEnv           = "IDENTITY_VERIFICATION_SETTLEMENT_WORKER_ENABLED"
	identityVerificationSettlementLeaseDurationEnv = "IDENTITY_VERIFICATION_SETTLEMENT_LEASE_DURATION"
	identityVerificationSettlementRetryDelayEnv    = "IDENTITY_VERIFICATION_SETTLEMENT_RETRY_DELAY"
	identityVerificationSettlementMaxAttemptsEnv   = "IDENTITY_VERIFICATION_SETTLEMENT_MAX_ATTEMPTS"
	identityVerificationWorkerIdlePollEnv          = "IDENTITY_VERIFICATION_SETTLEMENT_WORKER_IDLE_POLL"
	identityVerificationWorkerErrorBackoffEnv      = "IDENTITY_VERIFICATION_SETTLEMENT_WORKER_ERROR_BACKOFF"
	identityVerificationKYCProviderNameEnv         = "IDENTITY_VERIFICATION_KYC_PROVIDER_NAME"
	identityVerificationKYCEndpointEnv             = "IDENTITY_VERIFICATION_KYC_ENDPOINT"
	identityVerificationKYCAPIKeyEnv               = "IDENTITY_VERIFICATION_KYC_API_KEY"
	identityVerificationKYCCallbackKeyIDEnv        = "IDENTITY_VERIFICATION_KYC_CALLBACK_KEY_ID"
	identityVerificationKYCCallbackHMACEnv         = "IDENTITY_VERIFICATION_KYC_CALLBACK_HMAC_BASE64"
	identityVerificationObjectEndpointEnv          = "IDENTITY_VERIFICATION_OBJECT_ENDPOINT"
	identityVerificationObjectRegionEnv            = "IDENTITY_VERIFICATION_OBJECT_REGION"
	identityVerificationObjectBucketEnv            = "IDENTITY_VERIFICATION_OBJECT_BUCKET"
	identityVerificationObjectPrefixEnv            = "IDENTITY_VERIFICATION_OBJECT_PREFIX"
	identityVerificationObjectAccessKeyEnv         = "IDENTITY_VERIFICATION_OBJECT_ACCESS_KEY_ID"
	identityVerificationObjectSecretKeyEnv         = "IDENTITY_VERIFICATION_OBJECT_SECRET_ACCESS_KEY"
	identityVerificationObjectSessionTokenEnv      = "IDENTITY_VERIFICATION_OBJECT_SESSION_TOKEN"
	identityVerificationObjectKMSKeyEnv            = "IDENTITY_VERIFICATION_OBJECT_KMS_KEY_ID"

	identityVerificationCursorKeyMinBytes = 32
	identityVerificationCursorKeyMaxBytes = 128
	identityVerificationReadinessTimeout  = 2 * time.Second
)

var identityVerificationResolverNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

var identityVerificationEnvironmentNames = []string{
	identityVerificationEnabledEnv,
	identityVerificationCursorKeyBase64Env,
	identityVerificationResolverNameEnv,
	identityVerificationReviewTTLEnv,
	identityVerificationRetentionPeriodEnv,
	identityVerificationWorkerEnabledEnv,
	identityVerificationSettlementLeaseDurationEnv,
	identityVerificationSettlementRetryDelayEnv,
	identityVerificationSettlementMaxAttemptsEnv,
	identityVerificationWorkerIdlePollEnv,
	identityVerificationWorkerErrorBackoffEnv,
	identityVerificationKYCProviderNameEnv,
	identityVerificationKYCEndpointEnv,
	identityVerificationKYCAPIKeyEnv,
	identityVerificationKYCCallbackKeyIDEnv,
	identityVerificationKYCCallbackHMACEnv,
	identityVerificationObjectEndpointEnv,
	identityVerificationObjectRegionEnv,
	identityVerificationObjectBucketEnv,
	identityVerificationObjectPrefixEnv,
	identityVerificationObjectAccessKeyEnv,
	identityVerificationObjectSecretKeyEnv,
	identityVerificationObjectSessionTokenEnv,
	identityVerificationObjectKMSKeyEnv,
	identityVerificationIssuerEnabledEnv,
	identityVerificationIssuerListenAddressEnv,
	identityVerificationIssuerServerCertEnv,
	identityVerificationIssuerServerKeyEnv,
	identityVerificationIssuerClientCAEnv,
	identityVerificationIssuerIdentitiesEnv,
	identityVerificationIssuerKMSEndpointEnv,
}

type identityVerificationEvidenceSource interface {
	identityverificationhttp.RuntimeEvidenceSource
	Ready(context.Context) error
	Close()
}

type identityVerificationWorkerRuntime interface {
	Handler() http.Handler
	Run(context.Context) error
	Ready() error
	Close() error
}

type identityVerificationRuntimeRunner interface {
	Run(context.Context) error
}

type identityVerificationEvidenceSourceParameters struct {
	Pool    *pgxpool.Pool
	Auditor identityverification.AuditAppender
	Config  identityverificationhttp.PostgresRuntimeEvidenceSourceConfig
}

type identityVerificationProductionDependencies struct {
	Pool           *pgxpool.Pool
	Identity       *identity.Service
	IAM            *iamlock.Authorizer
	Clock          identityverification.Clock
	PrivateObjects identityverificationhttp.PrivateObjectStore
	KYCProvider    identityverificationhttp.KYCProvider

	NewEvidenceSource func(context.Context, identityVerificationEvidenceSourceParameters) (identityVerificationEvidenceSource, error)
	NewRuntime        func(identityverificationhttp.ProductionRuntimeConfig, identityverificationhttp.ProductionRuntimeDependencies) (identityVerificationWorkerRuntime, error)
}

type identityVerificationProviderEnvironment struct {
	Enabled            bool
	ProviderName       string
	ProviderEndpoint   string
	ProviderAPIKey     []byte
	CallbackKeyID      string
	CallbackHMACKey    []byte
	ObjectEndpoint     string
	ObjectRegion       string
	ObjectBucket       string
	ObjectPrefix       string
	ObjectAccessKey    []byte
	ObjectSecretKey    []byte
	ObjectSessionToken []byte
	ObjectKMSKeyID     string
}

func (config *identityVerificationProviderEnvironment) clear() {
	if config == nil {
		return
	}
	clear(config.ProviderAPIKey)
	clear(config.CallbackHMACKey)
	clear(config.ObjectAccessKey)
	clear(config.ObjectSecretKey)
	clear(config.ObjectSessionToken)
	*config = identityVerificationProviderEnvironment{}
}

type identityVerificationProductionRuntime struct {
	worker identityVerificationWorkerRuntime
	source identityVerificationEvidenceSource
	issuer *identityVerificationIssuerRuntime

	closeOnce sync.Once
	closeErr  error
}

func loadIdentityVerificationRuntimeConfigFromEnv(environment []string) (identityVerificationRuntimeConfig, error) {
	values := make(map[string]string, len(identityVerificationEnvironmentNames))
	duplicates := make(map[string]bool, len(identityVerificationEnvironmentNames))
	known := make(map[string]struct{}, len(identityVerificationEnvironmentNames))
	for _, name := range identityVerificationEnvironmentNames {
		known[name] = struct{}{}
	}
	unknown := make([]string, 0)
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, exists := known[name]; exists {
			if _, duplicate := values[name]; duplicate {
				duplicates[name] = true
			}
			values[name] = value
			continue
		}
		if strings.HasPrefix(name, "IDENTITY_VERIFICATION_") {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) != 0 {
		sort.Strings(unknown)
		return identityVerificationRuntimeConfig{}, errors.New("unsupported identity verification environment variable: " + unknown[0])
	}
	for _, name := range identityVerificationEnvironmentNames {
		if duplicates[name] {
			return identityVerificationRuntimeConfig{}, errors.New(name + " must be defined exactly once")
		}
	}
	enabled, err := identityVerificationBool(identityVerificationEnabledEnv, values[identityVerificationEnabledEnv])
	if err != nil || !enabled {
		return identityVerificationRuntimeConfig{}, err
	}
	workerEnabled, err := identityVerificationBool(identityVerificationWorkerEnabledEnv,
		values[identityVerificationWorkerEnabledEnv])
	if err != nil {
		return identityVerificationRuntimeConfig{}, err
	}
	if !workerEnabled {
		return identityVerificationRuntimeConfig{}, errors.New(identityVerificationWorkerEnabledEnv +
			" must be true when identity verification is enabled")
	}
	resolverName := values[identityVerificationResolverNameEnv]
	if !identityVerificationResolverNamePattern.MatchString(resolverName) {
		return identityVerificationRuntimeConfig{}, errors.New(identityVerificationResolverNameEnv + " is required and invalid")
	}
	reviewTTL, err := identityVerificationDuration(values, identityVerificationReviewTTLEnv, 72*time.Hour)
	if err != nil {
		return identityVerificationRuntimeConfig{}, err
	}
	retentionPeriod, err := identityVerificationDuration(values, identityVerificationRetentionPeriodEnv,
		6*365*24*time.Hour)
	if err != nil {
		return identityVerificationRuntimeConfig{}, err
	}
	leaseDuration, err := identityVerificationDuration(values,
		identityVerificationSettlementLeaseDurationEnv, time.Minute)
	if err != nil {
		return identityVerificationRuntimeConfig{}, err
	}
	retryDelay, err := identityVerificationDuration(values,
		identityVerificationSettlementRetryDelayEnv, time.Minute)
	if err != nil {
		return identityVerificationRuntimeConfig{}, err
	}
	idlePoll, err := identityVerificationDuration(values,
		identityVerificationWorkerIdlePollEnv, 250*time.Millisecond)
	if err != nil {
		return identityVerificationRuntimeConfig{}, err
	}
	errorBackoff, err := identityVerificationDuration(values,
		identityVerificationWorkerErrorBackoffEnv, time.Second)
	if err != nil {
		return identityVerificationRuntimeConfig{}, err
	}
	maxAttempts, err := identityVerificationPositiveInt(values,
		identityVerificationSettlementMaxAttemptsEnv, 8, 1000)
	if err != nil {
		return identityVerificationRuntimeConfig{}, err
	}
	encodedKey, exists := values[identityVerificationCursorKeyBase64Env]
	if !exists || encodedKey == "" {
		return identityVerificationRuntimeConfig{}, errors.New(identityVerificationCursorKeyBase64Env +
			" is required when identity verification is enabled")
	}
	destination := make([]byte, identityVerificationBase64DecodedLength(encodedKey))
	cursorKey, err := decodeRuntimeCursorKey(identityVerificationCursorKeyBase64Env, encodedKey, destination)
	if err != nil || len(cursorKey) < identityVerificationCursorKeyMinBytes ||
		len(cursorKey) > identityVerificationCursorKeyMaxBytes {
		clear(destination)
		return identityVerificationRuntimeConfig{}, errors.New(identityVerificationCursorKeyBase64Env +
			" must encode 32 to 128 bytes using canonical padded base64")
	}
	return identityVerificationRuntimeConfig{
		cursorRuntimeConfig: cursorRuntimeConfig{Enabled: true, CursorKey: cursorKey},
		ResolverName:        resolverName, ReviewTTL: reviewTTL, RetentionPeriod: retentionPeriod,
		WorkerEnabled: workerEnabled,
		Settlement: identityverification.SettlementWorkerConfig{
			LeaseDuration: leaseDuration, RetryDelay: retryDelay, MaxAttempts: maxAttempts,
		},
		WorkerIdlePoll: idlePoll, WorkerErrorBackoff: errorBackoff,
	}, nil
}

func loadIdentityVerificationProviderEnvironment(environment []string) (identityVerificationProviderEnvironment, error) {
	names := []string{identityVerificationKYCProviderNameEnv, identityVerificationKYCEndpointEnv,
		identityVerificationKYCAPIKeyEnv, identityVerificationKYCCallbackKeyIDEnv,
		identityVerificationKYCCallbackHMACEnv, identityVerificationObjectEndpointEnv,
		identityVerificationObjectRegionEnv, identityVerificationObjectBucketEnv,
		identityVerificationObjectPrefixEnv, identityVerificationObjectAccessKeyEnv,
		identityVerificationObjectSecretKeyEnv, identityVerificationObjectSessionTokenEnv,
		identityVerificationObjectKMSKeyEnv}
	known := make(map[string]struct{}, len(names))
	for _, name := range names {
		known[name] = struct{}{}
	}
	values := make(map[string]string, len(names))
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, ok := known[name]; !ok {
			continue
		}
		if _, duplicate := values[name]; duplicate {
			return identityVerificationProviderEnvironment{}, errors.New(name + " must be defined exactly once")
		}
		values[name] = value
	}
	configured := false
	for _, name := range names {
		if values[name] != "" {
			configured = true
			break
		}
	}
	if !configured {
		return identityVerificationProviderEnvironment{}, nil
	}
	required := []string{identityVerificationKYCProviderNameEnv, identityVerificationKYCEndpointEnv,
		identityVerificationKYCAPIKeyEnv, identityVerificationKYCCallbackKeyIDEnv,
		identityVerificationKYCCallbackHMACEnv, identityVerificationObjectEndpointEnv,
		identityVerificationObjectRegionEnv, identityVerificationObjectBucketEnv,
		identityVerificationObjectAccessKeyEnv, identityVerificationObjectSecretKeyEnv,
		identityVerificationObjectKMSKeyEnv}
	for _, name := range required {
		if values[name] == "" {
			return identityVerificationProviderEnvironment{}, errors.New(name + " is required for provider workflow")
		}
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(values[identityVerificationKYCCallbackHMACEnv])
	if err != nil || len(decoded) < 32 || len(decoded) > 128 ||
		base64.StdEncoding.EncodeToString(decoded) != values[identityVerificationKYCCallbackHMACEnv] {
		clear(decoded)
		return identityVerificationProviderEnvironment{}, errors.New(identityVerificationKYCCallbackHMACEnv + " must encode 32 to 128 bytes using canonical padded base64")
	}
	result := identityVerificationProviderEnvironment{Enabled: true,
		ProviderName:     values[identityVerificationKYCProviderNameEnv],
		ProviderEndpoint: values[identityVerificationKYCEndpointEnv],
		ProviderAPIKey:   []byte(values[identityVerificationKYCAPIKeyEnv]),
		CallbackKeyID:    values[identityVerificationKYCCallbackKeyIDEnv], CallbackHMACKey: decoded,
		ObjectEndpoint: values[identityVerificationObjectEndpointEnv],
		ObjectRegion:   values[identityVerificationObjectRegionEnv], ObjectBucket: values[identityVerificationObjectBucketEnv],
		ObjectPrefix:       values[identityVerificationObjectPrefixEnv],
		ObjectAccessKey:    []byte(values[identityVerificationObjectAccessKeyEnv]),
		ObjectSecretKey:    []byte(values[identityVerificationObjectSecretKeyEnv]),
		ObjectSessionToken: []byte(values[identityVerificationObjectSessionTokenEnv]),
		ObjectKMSKeyID:     values[identityVerificationObjectKMSKeyEnv]}
	if len(result.ProviderAPIKey) < 16 || len(result.ProviderAPIKey) > 512 ||
		len(result.ObjectAccessKey) < 3 || len(result.ObjectAccessKey) > 256 ||
		len(result.ObjectSecretKey) < 8 || len(result.ObjectSecretKey) > 512 ||
		len(result.ObjectSessionToken) > 4096 {
		result.clear()
		return identityVerificationProviderEnvironment{}, errors.New("identity verification provider credentials are invalid")
	}
	return result, nil
}

func identityVerificationBase64DecodedLength(encoded string) int {
	return len(encoded) / 4 * 3
}

func identityVerificationBool(name, value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "", "false":
		return false, nil
	default:
		return false, errors.New(name + " must be true or false")
	}
}

func identityVerificationDuration(values map[string]string, name string, fallback time.Duration) (time.Duration, error) {
	raw := values[name]
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, errors.New(name + " must be a positive Go duration")
	}
	return value, nil
}

func identityVerificationPositiveInt(values map[string]string, name string, fallback, maximum int) (int, error) {
	raw := values[name]
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum || strconv.Itoa(value) != raw {
		return 0, errors.New(name + " must be a canonical positive integer no greater than " + strconv.Itoa(maximum))
	}
	return value, nil
}

func openAndClearIdentityVerificationProductionRuntime(
	ctx context.Context,
	config *identityVerificationRuntimeConfig,
	dependencies identityVerificationProductionDependencies,
) (*identityVerificationProductionRuntime, error) {
	if config == nil {
		return nil, errors.New("identity verification runtime configuration is unavailable")
	}
	defer config.clearSecrets()
	return openIdentityVerificationProductionRuntime(ctx, *config, dependencies)
}

func openIdentityVerificationProductionRuntime(
	ctx context.Context,
	config identityVerificationRuntimeConfig,
	dependencies identityVerificationProductionDependencies,
) (*identityVerificationProductionRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if !config.WorkerEnabled || !identityVerificationProductionDependenciesConfigured(ctx, dependencies) ||
		!identityVerificationResolverNamePattern.MatchString(config.ResolverName) ||
		len(config.CursorKey) < identityVerificationCursorKeyMinBytes ||
		len(config.CursorKey) > identityVerificationCursorKeyMaxBytes || config.ReviewTTL <= 0 ||
		config.RetentionPeriod <= 0 || config.Settlement.LeaseDuration <= 0 ||
		config.Settlement.RetryDelay <= 0 || config.Settlement.MaxAttempts < 1 ||
		config.WorkerIdlePoll <= 0 || config.WorkerErrorBackoff <= 0 {
		return nil, errors.New("identity verification production runtime configuration is incomplete")
	}
	newEvidenceSource := dependencies.NewEvidenceSource
	if newEvidenceSource == nil {
		newEvidenceSource = func(ctx context.Context,
			parameters identityVerificationEvidenceSourceParameters,
		) (identityVerificationEvidenceSource, error) {
			return identityverificationhttp.NewPostgresRuntimeEvidenceSource(ctx, parameters.Pool,
				parameters.Auditor, parameters.Config)
		}
	}
	newRuntime := dependencies.NewRuntime
	if newRuntime == nil {
		newRuntime = func(config identityverificationhttp.ProductionRuntimeConfig,
			dependencies identityverificationhttp.ProductionRuntimeDependencies,
		) (identityVerificationWorkerRuntime, error) {
			return identityverificationhttp.NewProductionRuntime(config, dependencies)
		}
	}
	issueTokenHash := sha256.New()
	_, _ = issueTokenHash.Write([]byte("cdnca.identity-verification.evidence-issue-token-key.v1\x00"))
	_, _ = issueTokenHash.Write(config.CursorKey)
	issueTokenKey := issueTokenHash.Sum(nil)
	defer clear(issueTokenKey)
	source, err := newEvidenceSource(ctx, identityVerificationEvidenceSourceParameters{
		Pool: dependencies.Pool, Auditor: audit.New(dependencies.Pool),
		Config: identityverificationhttp.PostgresRuntimeEvidenceSourceConfig{
			ResolverName: config.ResolverName, IssueTokenKey: issueTokenKey, Clock: dependencies.Clock,
		},
	})
	if err != nil || nilRuntimeDependency(source) {
		if !nilRuntimeDependency(source) {
			source.Close()
		}
		return nil, errors.New("initialize identity verification durable evidence source")
	}
	providerEnvironment, err := loadIdentityVerificationProviderEnvironment(os.Environ())
	if err != nil {
		source.Close()
		return nil, err
	}
	defer providerEnvironment.clear()
	privateObjects, kycProvider := dependencies.PrivateObjects, dependencies.KYCProvider
	providerConfig := identityverificationhttp.ProviderWorkflowConfig{}
	var issuerRuntime *identityVerificationIssuerRuntime
	if providerEnvironment.Enabled {
		if nilRuntimeDependency(privateObjects) {
			objectAccessKey := string(providerEnvironment.ObjectAccessKey)
			objectSecretKey := string(providerEnvironment.ObjectSecretKey)
			objectSessionToken := string(providerEnvironment.ObjectSessionToken)
			privateObjects, err = identityverificationhttp.NewS3PrivateObjectStore(
				identityverificationhttp.S3PrivateObjectStoreConfig{
					Endpoint: providerEnvironment.ObjectEndpoint, Region: providerEnvironment.ObjectRegion,
					Bucket: providerEnvironment.ObjectBucket, Prefix: providerEnvironment.ObjectPrefix,
					Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
						return aws.Credentials{AccessKeyID: objectAccessKey, SecretAccessKey: objectSecretKey,
							SessionToken: objectSessionToken, Source: "identity-verification-runtime"}, nil
					}),
					RequestTimeout: 15 * time.Second, MaxAttempts: 3,
				}, http.DefaultClient, dependencies.Clock)
			if err != nil {
				source.Close()
				return nil, errors.New("initialize identity verification private object store")
			}
		}
		if nilRuntimeDependency(kycProvider) {
			kycProvider, err = identityverificationhttp.NewHTTPSKYCProvider(
				identityverificationhttp.HTTPSKYCProviderConfig{
					Name: providerEnvironment.ProviderName, Endpoint: providerEnvironment.ProviderEndpoint,
					APIKey: providerEnvironment.ProviderAPIKey, CallbackKeyID: providerEnvironment.CallbackKeyID,
					CallbackHMACKey: providerEnvironment.CallbackHMACKey,
					CallbackMaxAge:  5 * time.Minute, CallbackFutureSkew: 30 * time.Second,
					RequestTimeout: 15 * time.Second,
				}, http.DefaultClient, dependencies.Clock)
			if err != nil {
				source.Close()
				return nil, errors.New("initialize identity verification KYC provider")
			}
		}
		tokenHash := sha256.New()
		_, _ = tokenHash.Write([]byte("cdnca.identity-verification.provider-token-key.v1\x00"))
		_, _ = tokenHash.Write(config.CursorKey)
		tokenKey := tokenHash.Sum(nil)
		providerConfig = identityverificationhttp.ProviderWorkflowConfig{
			Clock: dependencies.Clock, TokenKey: tokenKey, ResolverName: config.ResolverName,
			EncryptionKeyID: providerEnvironment.ObjectKMSKeyID, SessionTTL: 30 * time.Minute,
			UploadTTL: 15 * time.Minute, RetentionPeriod: config.RetentionPeriod,
			CallbackMaxAge: 5 * time.Minute, CallbackFutureSkew: 30 * time.Second,
			EraseLeaseDuration: time.Minute, EraseRetryDelay: 5 * time.Minute,
		}
		defer clear(tokenKey)
	}
	issuerRuntime, err = openIdentityVerificationIssuerRuntime(ctx, dependencies.Pool, providerEnvironment,
		dependencies.Clock, source)
	if err != nil {
		source.Close()
		if !nilRuntimeDependency(kycProvider) {
			kycProvider.Close()
		}
		return nil, err
	}
	cursorKey := bytes.Clone(config.CursorKey)
	worker, err := newRuntime(identityverificationhttp.ProductionRuntimeConfig{
		Runtime: identityverificationhttp.RuntimeConfig{
			Enabled: true,
			Core: identityverification.Config{
				ReviewTTL: config.ReviewTTL, RetentionPeriod: config.RetentionPeriod,
			},
			Service:            identityverificationhttp.ServiceConfig{CursorKey: cursorKey},
			Provider:           providerConfig,
			Settlement:         config.Settlement,
			WorkerIdlePoll:     config.WorkerIdlePoll,
			WorkerErrorBackoff: config.WorkerErrorBackoff,
		},
		Evidence: identityverificationhttp.RuntimeEvidenceConfig{ResolverName: config.ResolverName},
	}, identityverificationhttp.ProductionRuntimeDependencies{
		Pool: dependencies.Pool, Identity: dependencies.Identity, IAM: dependencies.IAM,
		EvidenceSource: source, PrivateObjects: privateObjects, KYCProvider: kycProvider,
		Clock: dependencies.Clock,
	})
	clear(cursorKey)
	if err != nil || nilRuntimeDependency(worker) {
		if !nilRuntimeDependency(worker) {
			_ = worker.Close()
		}
		source.Close()
		if !nilRuntimeDependency(kycProvider) {
			kycProvider.Close()
		}
		if issuerRuntime != nil {
			_ = issuerRuntime.Close()
		}
		return nil, errors.New("initialize identity verification settlement worker runtime")
	}
	if handler := worker.Handler(); nilRuntimeDependency(handler) {
		_ = worker.Close()
		source.Close()
		if issuerRuntime != nil {
			_ = issuerRuntime.Close()
		}
		return nil, errors.New("initialize identity verification HTTP handler")
	}
	return &identityVerificationProductionRuntime{worker: worker, source: source, issuer: issuerRuntime}, nil
}

func identityVerificationProductionDependenciesConfigured(ctx context.Context,
	dependencies identityVerificationProductionDependencies,
) (configured bool) {
	if ctx == nil || ctx.Err() != nil || dependencies.Pool == nil ||
		nilRuntimeDependency(dependencies.Identity) || nilRuntimeDependency(dependencies.IAM) ||
		dependencies.Clock == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return dependencies.Pool.Config() != nil && dependencies.Identity.Configured() &&
		dependencies.IAM.Configured() && !dependencies.Clock().IsZero()
}

func (runtime *identityVerificationProductionRuntime) HandlerFactory() httpapi.MountedHandlerFactory {
	if runtime == nil || nilRuntimeDependency(runtime.worker) {
		return nil
	}
	return func() (http.Handler, error) {
		handler := runtime.worker.Handler()
		if nilRuntimeDependency(handler) {
			return nil, errors.New("identity verification HTTP handler is unavailable")
		}
		return handler, nil
	}
}

func (runtime *identityVerificationProductionRuntime) Run(ctx context.Context) error {
	if runtime == nil || nilRuntimeDependency(runtime.worker) || ctx == nil {
		return errors.New("identity verification settlement worker runtime is unavailable")
	}
	if runtime.issuer == nil {
		return runtime.worker.Run(ctx)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- runtime.worker.Run(runCtx) }()
	go func() { results <- runtime.issuer.Run(runCtx) }()
	for range 2 {
		err := <-results
		if runCtx.Err() != nil {
			continue
		}
		if err == nil {
			err = errors.New("identity verification production runtime stopped unexpectedly")
		}
		cancel()
		_ = runtime.issuer.Close()
		<-results
		return err
	}
	return ctx.Err()
}

func (runtime *identityVerificationProductionRuntime) Ready() error {
	if runtime == nil || nilRuntimeDependency(runtime.worker) || nilRuntimeDependency(runtime.source) {
		return errors.New("identity verification production runtime is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityVerificationReadinessTimeout)
	defer cancel()
	if err := runtime.source.Ready(ctx); err != nil {
		return errors.New("identity verification durable evidence source is unavailable")
	}
	if err := runtime.worker.Ready(); err != nil {
		return errors.New("identity verification settlement worker is unavailable")
	}
	if runtime.issuer != nil {
		if err := runtime.issuer.Ready(); err != nil {
			return errors.New("identity verification issuer is unavailable")
		}
	}
	return nil
}

func (runtime *identityVerificationProductionRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.closeOnce.Do(func() {
		if !nilRuntimeDependency(runtime.worker) {
			runtime.closeErr = runtime.worker.Close()
		}
		if runtime.issuer != nil {
			runtime.closeErr = errors.Join(runtime.closeErr, runtime.issuer.Close())
		}
		if !nilRuntimeDependency(runtime.source) {
			runtime.source.Close()
		}
	})
	return runtime.closeErr
}

func (runtime *identityVerificationProductionRuntime) IssuerRuntime() *identityVerificationIssuerRuntime {
	if runtime == nil {
		return nil
	}
	return runtime.issuer
}

func loadIdentityVerificationRuntimeConfig() (identityVerificationRuntimeConfig, error) {
	return loadIdentityVerificationRuntimeConfigFromEnv(os.Environ())
}
