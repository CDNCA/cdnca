package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmecacredentials"
	"github.com/cdnca/cdnca/services/control-api/internal/acmedispatch"
	"github.com/cdnca/cdnca/services/control-api/internal/acmehttp01"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	maximumACMEDNSHandleVerifyOnlyKeys      = 16
	maximumACMEDNSHandleVerifyOnlyJSONBytes = 16 * 1024
)

type acmeRuntimeProviders struct {
	http01         acmeworker.HTTP01Provider
	dns01          acmeworker.DNS01Provider
	issuerOverride acmeruntime.Issuer
}

// directoryRoutedIssuer sends a request to the issuer of its directory (an
// EAB CA's worker) or to fallback (the installation's directory and its
// backup failover).
type directoryRoutedIssuer struct {
	fallback    acmeruntime.Issuer
	byDirectory map[string]acmeruntime.Issuer
}

func (i *directoryRoutedIssuer) Issue(ctx context.Context, request acmeworker.IssueRequest) (acmeworker.IssueResult, error) {
	if issuer, ok := i.byDirectory[request.DirectoryURL]; ok {
		return issuer.Issue(ctx, request)
	}
	return i.fallback.Issue(ctx, request)
}

type requestBoundCAEndpoint struct {
	directoryURL string
	issuer       acmeworker.CertificateIssuer
}

type requestBoundCAFailoverIssuer struct {
	config    acmeworker.CAFailoverConfig
	endpoints []requestBoundCAEndpoint
}

func (i *requestBoundCAFailoverIssuer) Issue(
	ctx context.Context,
	request acmeworker.IssueRequest,
) (acmeworker.IssueResult, error) {
	if i == nil || request.AccountKeyRef == "" {
		return acmeworker.IssueResult{}, &acmeworker.Error{Code: acmeworker.CodeInvalidInput}
	}
	endpoints := make([]acmeworker.CAEndpoint, len(i.endpoints))
	for index, endpoint := range i.endpoints {
		endpoints[index] = acmeworker.CAEndpoint{
			DirectoryURL: endpoint.directoryURL, AccountKeyRef: request.AccountKeyRef,
			Issuer: endpoint.issuer,
		}
	}
	issuer, err := acmeworker.NewCAFailoverIssuer(i.config, endpoints)
	if err != nil {
		return acmeworker.IssueResult{}, err
	}
	return issuer.Issue(ctx, request)
}

func newConfiguredACMEIssuer(
	cfg config.Config,
	primary acmeworker.CertificateIssuer,
	backup acmeworker.CertificateIssuer,
	facts acmeworker.CAPolicyFactStore,
	probe acmeworker.CADirectoryProbe,
) (acmeworker.CertificateIssuer, error) {
	if cfg.ACMEBackupDirectoryURL == "" {
		return primary, nil
	}
	policy := acmeworker.DefaultCAFailoverConfig()
	policy.Facts = facts
	policy.Probe = probe
	policy.BackoffBase = cfg.ACMERetryBase
	policy.BackoffMaximum = cfg.ACMERetryMaximum
	policy.MaxRetryAfter = cfg.ACMERetryMaximum
	issuer := &requestBoundCAFailoverIssuer{
		config: policy,
		endpoints: []requestBoundCAEndpoint{
			{directoryURL: cfg.ACMEDirectoryURL, issuer: primary},
			{directoryURL: cfg.ACMEBackupDirectoryURL, issuer: backup},
		},
	}
	if primary == nil || backup == nil || facts == nil || probe == nil {
		return nil, &acmeworker.Error{Code: acmeworker.CodeInvalidInput}
	}
	return issuer, nil
}

// acmeAuthoritativeTXTChecker makes DNS-01 wait for every authoritative
// name server of the zone (FX05②). It discovers the zone through the DNS
// reconcile bootstrap resolvers the installer writes; without them the
// worker keeps checking the provider API only.
func acmeAuthoritativeTXTChecker(lookup accountRecoveryEnvLookup) (*dnspropagation.AuthoritativeTXT, error) {
	if raw, found := lookup("DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS"); !found || raw == "" {
		return nil, nil
	}
	bootstrap, err := parseDNSPropagationResolvers(lookup, "DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS")
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	source, err := dnspropagation.NewWireSource(dnspropagation.WireSourceConfig{
		Bootstrap: bootstrap, DialContext: dialer.DialContext, QueryTimeout: 5 * time.Second,
		MaximumResponseBytes: 4096, Now: time.Now, FamilyAvailable: dnspropagation.LocalAddressFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return dnspropagation.NewAuthoritativeTXT(source)
}

type nodeAggregateRequiredHTTP01Provider struct{}

var _ acmeworker.HTTP01Provider = nodeAggregateRequiredHTTP01Provider{}

func (nodeAggregateRequiredHTTP01Provider) Publish(context.Context, acmeworker.ChallengeIdentity) error {
	return &acmeworker.Error{Code: acmeworker.CodeHTTP01NodeAggregateRequired}
}

func (nodeAggregateRequiredHTTP01Provider) Delete(context.Context, acmeworker.ChallengeIdentity) error {
	return &acmeworker.Error{Code: acmeworker.CodeHTTP01NodeAggregateRequired}
}

type acmeRunnable interface {
	Run(context.Context) error
	Ready() error
}

type acmeProcessRuntime struct {
	issuance acmeRunnable
	renewal  acmeRunnable
	cleanup  acmeRunnable
	// http01 delivers HTTP-01 tokens to the nodes (nil: HTTP-01 refused).
	http01 *acmeHTTP01NodeRuntime
	active atomic.Bool
	closed atomic.Bool
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func newACMEProcessRuntime(
	issuance acmeRunnable,
	renewal acmeRunnable,
	cleanup acmeRunnable,
) (*acmeProcessRuntime, error) {
	if issuance == nil || renewal == nil || cleanup == nil {
		return nil, errors.New("ACME process runtime requires issuance, renewal, and terminal cleanup loops")
	}
	return &acmeProcessRuntime{issuance: issuance, renewal: renewal, cleanup: cleanup}, nil
}

func openConfiguredACMEProcessRuntime(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
) (*acmeProcessRuntime, error) {
	if !cfg.ACMERuntimeEnabled {
		return nil, nil
	}
	if ctx == nil || pool == nil {
		return nil, errors.New("ACME runtime dependencies are not configured")
	}
	http01, err := openACMEHTTP01NodeRuntime(ctx, cfg, pool, os.Environ(), nats.Connect)
	if err != nil {
		return nil, err
	}
	var http01Provider acmeworker.HTTP01Provider = nodeAggregateRequiredHTTP01Provider{}
	if http01 != nil {
		http01Provider = http01.provider
	}
	components, err := openConfiguredACMERuntimeComponentsWithProviders(
		ctx, cfg, pool, acmeRuntimeProviders{http01: http01Provider},
	)
	if err != nil {
		if http01 != nil {
			_ = http01.Close()
		}
		return nil, err
	}
	renewalConfig := acmeRenewalSchedulerConfig(cfg)
	renewal, err := acmeworker.NewRenewalScheduler(dnsacme.NewStore(pool), renewalConfig)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME renewal scheduler", err: err}
	}
	runtime, err := newACMEProcessRuntime(components.issuance, renewal, components.cleanup)
	if err != nil {
		if http01 != nil {
			_ = http01.Close()
		}
		return nil, runtimeStageError{stage: "configure ACME process runtime", err: err}
	}
	runtime.http01 = http01
	return runtime, nil
}

func acmeRenewalSchedulerConfig(cfg config.Config) acmeworker.RenewalSchedulerConfig {
	renewalConfig := acmeworker.DefaultRenewalSchedulerConfig()
	renewalConfig.LeaseDuration = cfg.ACMELeaseDuration
	renewalConfig.RetryMaximum = cfg.ACMERetryMaximum
	renewalConfig.PollInterval = cfg.ACMEPollInterval
	renewalConfig.ErrorBackoffMin = cfg.ACMEErrorBackoffMin
	renewalConfig.ErrorBackoffMax = cfg.ACMEErrorBackoffMax
	return renewalConfig
}

func (r *acmeProcessRuntime) Run(ctx context.Context) error {
	if r == nil || ctx == nil || r.issuance == nil || r.renewal == nil || r.closed.Load() ||
		!r.active.CompareAndSwap(false, true) {
		return errors.New("ACME process runtime is not runnable")
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.mu.Lock()
	if r.closed.Load() {
		r.mu.Unlock()
		cancel()
		r.active.Store(false)
		return errors.New("ACME process runtime is closed")
	}
	r.cancel = cancel
	r.done = done
	r.mu.Unlock()
	defer func() {
		cancel()
		r.mu.Lock()
		if r.done == done {
			r.cancel = nil
			r.done = nil
		}
		r.mu.Unlock()
		r.active.Store(false)
		close(done)
	}()

	loops := []acmeRunnable{r.issuance, r.renewal}
	if r.cleanup != nil {
		loops = append(loops, r.cleanup)
	}
	if r.http01 != nil {
		loops = append(loops, r.http01.runtime)
	}
	results := make(chan error, len(loops))
	for _, loop := range loops {
		go func(loop acmeRunnable) { results <- loop.Run(runCtx) }(loop)
	}
	first := <-results
	cancel()
	for range len(loops) - 1 {
		<-results
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first == nil {
		return errors.New("ACME process runtime loop stopped unexpectedly")
	}
	return first
}

func (r *acmeProcessRuntime) Ready() error {
	if r == nil || !r.active.Load() {
		return errors.New("ACME process runtime is not active")
	}
	if err := r.issuance.Ready(); err != nil {
		return err
	}
	if err := r.renewal.Ready(); err != nil {
		return err
	}
	if r.cleanup != nil {
		if err := r.cleanup.Ready(); err != nil {
			return err
		}
	}
	if r.http01 != nil {
		return r.http01.runtime.Ready()
	}
	return nil
}

// ArtifactStore serves the HTTP-01 node overlay artifacts to the gateway
// (nil while HTTP-01 is refused).
func (r *acmeProcessRuntime) ArtifactStore() acmehttp01.FetchStore {
	if r == nil || r.http01 == nil {
		return nil
	}
	return r.http01.artifacts
}

func (r *acmeProcessRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closed.Store(true)
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	if r.http01 != nil {
		return r.http01.Close()
	}
	return nil
}

func openConfiguredACMERuntime(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
) (*acmeruntime.Runner, error) {
	return openConfiguredACMERuntimeWithProviders(
		ctx, cfg, pool, acmeRuntimeProviders{},
	)
}

func openConfiguredACMERuntimeWithProviders(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	providers acmeRuntimeProviders,
) (*acmeruntime.Runner, error) {
	components, err := openConfiguredACMERuntimeComponentsWithProviders(ctx, cfg, pool, providers)
	if err != nil || components == nil {
		return nil, err
	}
	return components.issuance, nil
}

func openConfiguredACMERuntimeComponentsWithProviders(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	providers acmeRuntimeProviders,
) (*acmeRuntimeComponents, error) {
	if !cfg.ACMERuntimeEnabled {
		return nil, nil
	}
	if pool == nil {
		return nil, errors.New("ACME runtime database is not configured")
	}
	if ctx == nil {
		return nil, errors.New("ACME runtime startup context is not configured")
	}
	activeCredentialKey := dnsacme.CredentialKey{
		ID: cfg.DNSCredentialKeyID, Material: append([]byte(nil), cfg.DNSCredentialKey...),
	}
	previousCredentialKeys := make([]dnsacme.CredentialKey, 0, 1)
	if cfg.DNSCredentialPreviousKeyID != "" || len(cfg.DNSCredentialPreviousKey) != 0 {
		previousCredentialKeys = append(previousCredentialKeys, dnsacme.CredentialKey{
			ID: cfg.DNSCredentialPreviousKeyID, Material: append([]byte(nil), cfg.DNSCredentialPreviousKey...),
		})
	}
	credentialCipher, err := dnsacme.NewAESGCMCredentialKeyring(activeCredentialKey, previousCredentialKeys...)
	clear(activeCredentialKey.Material)
	for index := range previousCredentialKeys {
		clear(previousCredentialKeys[index].Material)
	}
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME DNS credential cipher", err: err}
	}
	handleKeyring, err := loadACMEDNSHandleKeyring()
	if err != nil {
		return nil, err
	}
	startupCtx, cancel := context.WithTimeout(ctx, cfg.ACMESettleTimeout)
	defer cancel()
	dns01, err := dnsproviderremote.Open(
		startupCtx,
		dnsproviderremotesource.New(pool, credentialCipher),
		handleKeyring,
	)
	if err != nil {
		return nil, runtimeStageError{stage: "open ACME DNS-01 provider", err: err}
	}
	providers.dns01 = dns01
	return openACMERuntimeComponents(cfg, pool, providers)
}

type acmeRuntimeComponents struct {
	issuance *acmeruntime.Runner
	cleanup  *acmeworker.TerminalCleanupRunner
}

func openACMERuntime(
	cfg config.Config,
	pool *pgxpool.Pool,
	providers acmeRuntimeProviders,
) (*acmeruntime.Runner, error) {
	components, err := openACMERuntimeComponents(cfg, pool, providers)
	if err != nil || components == nil {
		return nil, err
	}
	return components.issuance, nil
}

func openACMERuntimeComponents(
	cfg config.Config,
	pool *pgxpool.Pool,
	providers acmeRuntimeProviders,
) (*acmeRuntimeComponents, error) {
	if !cfg.ACMERuntimeEnabled {
		return nil, nil
	}
	if pool == nil {
		return nil, errors.New("ACME runtime database is not configured")
	}
	if providers.http01 == nil {
		return nil, errors.New("ACME runtime HTTP-01 provider is not configured")
	}
	if providers.dns01 == nil {
		return nil, errors.New("ACME runtime DNS-01 provider is not configured")
	}

	keys, err := newConfiguredACMEKeyStore(pool, cfg)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME key store", err: err}
	}
	accounts, err := acmeruntime.NewAccountStore(pool, true)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME account store", err: err}
	}
	operations, err := acmeworker.NewPGOperationStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME operation store", err: err}
	}
	enveloper, err := newConfiguredACMECertificateEnveloper(cfg)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME certificate envelope", err: err}
	}
	assets, err := certificateasset.NewStore(pool, enveloper)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME certificate asset store", err: err}
	}
	certificates, err := acmedispatch.NewCertificateStore(
		pool, operations, assets, acmedispatch.NewPGKeyMaterialLoader(),
	)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME certificate store", err: err}
	}

	authoritative, err := acmeAuthoritativeTXTChecker(os.LookupEnv)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME authoritative TXT check", err: err}
	}
	dependencies := acmeworker.Dependencies{
		Signers: keys, Accounts: accounts, HTTP01: providers.http01,
		DNS01: providers.dns01, Certificates: certificates,
		Operations: operations,
	}
	if authoritative != nil {
		dependencies.AuthoritativeTXT = authoritative
	}
	// ACME External Account Binding (ZeroSSL, Google Trust Services): the
	// credentials are sealed with the DNS credential keyring.
	eabCipher, err := newConfiguredDNSCredentialCipher(cfg)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME EAB cipher", err: err}
	}
	eab, err := acmecacredentials.NewResolver(pool, eabCipher)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME EAB", err: err}
	}
	dependencies.EAB = eab
	newWorker := func(directoryURL string) (*acmeworker.Worker, error) {
		workerConfig := acmeworker.DefaultConfig(directoryURL)
		workerConfig.LeaseDuration = cfg.ACMELeaseDuration
		workerConfig.HTTP01PublishTimeout = acmeHTTP01PublishTimeout
		return acmeworker.New(workerConfig, dependencies)
	}
	worker, err := newWorker(cfg.ACMEDirectoryURL)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME issuer", err: err}
	}
	var issuer acmeruntime.Issuer = worker
	if cfg.ACMEBackupDirectoryURL != "" {
		backup, backupErr := newWorker(cfg.ACMEBackupDirectoryURL)
		if backupErr != nil {
			return nil, runtimeStageError{stage: "configure ACME backup issuer", err: backupErr}
		}
		probe, probeErr := acmeworker.NewHTTPDirectoryProbe(&http.Client{
			Timeout: cfg.ACMESettleTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}, cfg.ACMERetryMaximum)
		if probeErr != nil {
			return nil, runtimeStageError{stage: "configure ACME CA probe", err: probeErr}
		}
		issuer, err = newConfiguredACMEIssuer(
			cfg, worker, backup, dnsacme.NewStore(pool), probe,
		)
		if err != nil {
			return nil, runtimeStageError{stage: "configure ACME CA failover", err: err}
		}
	}
	// Orders for an EAB CA (系统设置 > 网站默认 > 证书 > 签发机构) go to that
	// CA's own worker; everything else keeps the installation's directory
	// with its backup failover.
	eabIssuers := map[string]acmeruntime.Issuer{}
	for _, ca := range []string{acmecacredentials.CAZeroSSL, acmecacredentials.CAGoogleTrust} {
		directory := acmecacredentials.Directory(ca)
		if directory == cfg.ACMEDirectoryURL || directory == cfg.ACMEBackupDirectoryURL {
			continue
		}
		caWorker, caErr := newWorker(directory)
		if caErr != nil {
			return nil, runtimeStageError{stage: "configure ACME " + ca + " issuer", err: caErr}
		}
		eabIssuers[directory] = caWorker
	}
	issuer = &directoryRoutedIssuer{fallback: issuer, byDirectory: eabIssuers}
	if providers.issuerOverride != nil {
		issuer = providers.issuerOverride
	}
	dispatchConfig := acmeruntime.DefaultConfig(cfg.ACMEDirectoryURL, cfg.ACMEContacts)
	dispatchConfig.LeaseDuration = cfg.ACMELeaseDuration
	dispatchConfig.SettleTimeout = cfg.ACMESettleTimeout
	dispatchConfig.RetryBase = cfg.ACMERetryBase
	dispatchConfig.RetryMaximum = cfg.ACMERetryMaximum
	dispatchConfig.MaxAttempts = cfg.ACMEMaxAttempts
	dispatcher, err := acmeruntime.NewDispatcher(pool, issuer, keys, dispatchConfig)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME dispatcher", err: err}
	}
	routed := make([]string, 0, len(eabIssuers))
	for directory := range eabIssuers {
		routed = append(routed, directory)
	}
	dispatcher.SelectDirectories(func(ctx context.Context, tx pgx.Tx, orderIssuer *string, defaultDirectory string) (string, error) {
		// The order's own CA (CERT-04) first; older orders use the platform default.
		if orderIssuer != nil {
			return eab.DirectoryForIssuer(ctx, tx, *orderIssuer, defaultDirectory)
		}
		issuerName, err := systemconfig.LoadDefaultCertificateIssuer(ctx, tx)
		if err != nil {
			return "", err
		}
		return eab.DirectoryForIssuer(ctx, tx, issuerName, defaultDirectory)
	}, routed)
	// A failed renewal tells the certificate's owner (certificate.renew_failed).
	notices, err := notification.NewStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME renewal failure notices", err: err}
	}
	dispatcher.EnableRenewalFailureNotices(notices)
	issuance, err := acmeruntime.NewRunner(dispatcher, acmeruntime.RunnerConfig{
		PollInterval: cfg.ACMEPollInterval, ErrorBackoffMin: cfg.ACMEErrorBackoffMin,
		ErrorBackoffMax: cfg.ACMEErrorBackoffMax,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME runtime", err: err}
	}
	cleanupConfig := acmeworker.DefaultTerminalCleanupRunnerConfig()
	cleanupConfig.PollInterval = cfg.ACMEPollInterval
	cleanupConfig.ErrorBackoffMin = cfg.ACMEErrorBackoffMin
	cleanupConfig.ErrorBackoffMax = cfg.ACMEErrorBackoffMax
	cleanup, err := acmeworker.NewTerminalCleanupRunner(worker, cleanupConfig)
	if err != nil {
		return nil, runtimeStageError{stage: "configure ACME terminal cleanup runtime", err: err}
	}
	return &acmeRuntimeComponents{issuance: issuance, cleanup: cleanup}, nil
}

type acmeDNSHandleVerificationKey struct {
	ID        string `json:"id"`
	KeyBase64 string `json:"key_base64"`
}

func loadACMEDNSHandleKeyring() (*dnsproviderremote.HandleKeyring, error) {
	active := dnsproviderremote.HandleKey{
		ID: os.Getenv("ACME_DNS_HANDLE_ACTIVE_KEY_ID"),
	}
	var ok bool
	active.Secret, ok = decodeACMEDNSHandleSecret(os.Getenv("ACME_DNS_HANDLE_ACTIVE_KEY_BASE64"))
	if !ok {
		return nil, errors.New("ACME_DNS_HANDLE_ACTIVE_KEY_BASE64 must encode exactly 32 bytes")
	}
	defer clear(active.Secret)

	var verifyOnly []dnsproviderremote.HandleKey
	rawVerifyOnly, configured := os.LookupEnv("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON")
	if configured {
		var encoded []acmeDNSHandleVerificationKey
		if len(rawVerifyOnly) > maximumACMEDNSHandleVerifyOnlyJSONBytes {
			return nil, errors.New("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON exceeds the configured limit")
		}
		decoder := json.NewDecoder(strings.NewReader(rawVerifyOnly))
		decoder.DisallowUnknownFields()
		if rawVerifyOnly == "" || decoder.Decode(&encoded) != nil || encoded == nil {
			return nil, errors.New("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON must be a JSON array")
		}
		if len(encoded) > maximumACMEDNSHandleVerifyOnlyKeys {
			return nil, errors.New("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON contains too many keys")
		}
		if err := ensureACMEDNSHandleJSONEnd(decoder); err != nil {
			return nil, err
		}
		verifyOnly = make([]dnsproviderremote.HandleKey, 0, len(encoded))
		for _, item := range encoded {
			secret, valid := decodeACMEDNSHandleSecret(item.KeyBase64)
			if !valid {
				clearACMEDNSHandleKeys(verifyOnly)
				return nil, errors.New("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON contains an invalid key")
			}
			verifyOnly = append(verifyOnly, dnsproviderremote.HandleKey{ID: item.ID, Secret: secret})
		}
		defer clearACMEDNSHandleKeys(verifyOnly)
	}

	keyring, err := dnsproviderremote.NewHandleKeyring(active, verifyOnly...)
	if err != nil {
		return nil, errors.New("ACME DNS handle key IDs must be valid and unique")
	}
	return keyring, nil
}

func decodeACMEDNSHandleSecret(value string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}

func ensureACMEDNSHandleJSONEnd(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON must contain one JSON array")
	}
	return nil
}

func clearACMEDNSHandleKeys(keys []dnsproviderremote.HandleKey) {
	for index := range keys {
		clear(keys[index].Secret)
	}
}

type acmePrivateKeyEnveloper struct {
	keyID  string
	aead   cipher.AEAD
	random io.Reader
}

type acmeEnvelopeMetadata struct {
	Schema string          `json:"schema"`
	Kind   string          `json:"kind"`
	Source json.RawMessage `json:"source,omitempty"`
}

func newConfiguredACMECertificateEnveloper(
	cfg config.Config,
) (*certificateasset.AESGCMPrivateKeyEnvelopeKeyring, error) {
	active := certificateasset.PrivateKeyWrappingKey{
		ID: cfg.ACMEWrappingKeyID, Material: append([]byte(nil), cfg.ACMEWrappingKey...),
	}
	previousSource, err := configuredACMEPreviousWrappingKeys()
	if err != nil {
		clear(active.Material)
		return nil, err
	}
	previous := make([]certificateasset.PrivateKeyWrappingKey, len(previousSource))
	for index := range previousSource {
		previous[index] = certificateasset.PrivateKeyWrappingKey{
			ID: previousSource[index].ID, Material: append([]byte(nil), previousSource[index].Key...),
		}
	}
	enveloper, err := certificateasset.NewAESGCMPrivateKeyEnvelopeKeyring(active, previous...)
	clear(active.Material)
	for index := range previousSource {
		clear(previousSource[index].Key)
	}
	for index := range previous {
		clear(previous[index].Material)
	}
	return enveloper, err
}

func newACMEPrivateKeyEnveloper(keyID string, key []byte) (*acmePrivateKeyEnveloper, error) {
	if keyID == "" || len(keyID) > 128 || len(key) != 32 {
		return nil, certificateasset.ErrEnvelopeUnavailable
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, certificateasset.ErrEnvelopeUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, certificateasset.ErrEnvelopeUnavailable
	}
	return &acmePrivateKeyEnveloper{keyID: keyID, aead: aead, random: rand.Reader}, nil
}

func (e *acmePrivateKeyEnveloper) Seal(
	_ context.Context,
	request certificateasset.PrivateKeySealRequest,
) (certificateasset.PrivateKeyEnvelope, error) {
	return e.seal(request.Context, request.PlaintextPKCS8, acmeEnvelopeMetadata{
		Schema: "cdnca.acme-certificate-envelope.v1", Kind: "pkcs8",
	})
}

func (e *acmePrivateKeyEnveloper) SealOpaque(
	_ context.Context,
	request certificateasset.OpaquePrivateKeySealRequest,
) (certificateasset.PrivateKeyEnvelope, error) {
	if !json.Valid(request.Metadata) {
		return certificateasset.PrivateKeyEnvelope{}, certificateasset.ErrEnvelopeUnavailable
	}
	return e.seal(request.Context, request.WrappedKeyMaterial, acmeEnvelopeMetadata{
		Schema: "cdnca.acme-certificate-envelope.v1", Kind: "opaque_wrapped",
		Source: append(json.RawMessage(nil), request.Metadata...),
	})
}

func (e *acmePrivateKeyEnveloper) Unseal(
	_ context.Context,
	request certificateasset.PrivateKeyUnsealRequest,
) ([]byte, error) {
	metadata, err := decodeACMEEnvelopeMetadata(request.Envelope.Metadata)
	if err != nil || e == nil || request.Envelope.KeyID != e.keyID ||
		len(request.Envelope.Nonce) != e.aead.NonceSize() || len(request.Envelope.Ciphertext) < e.aead.Overhead() {
		return nil, certificateasset.ErrEnvelopeUnavailable
	}
	aad, err := acmeEnvelopeAAD(request.Context, request.Envelope.KeyID, request.Envelope.Metadata)
	if err != nil {
		return nil, certificateasset.ErrEnvelopeUnavailable
	}
	plaintext, err := e.aead.Open(nil, request.Envelope.Nonce, request.Envelope.Ciphertext, aad)
	if err != nil || len(plaintext) == 0 || (metadata.Kind != "pkcs8" && metadata.Kind != "opaque_wrapped") {
		return nil, certificateasset.ErrEnvelopeUnavailable
	}
	return plaintext, nil
}

func (e *acmePrivateKeyEnveloper) Rewrap(
	ctx context.Context,
	request certificateasset.PrivateKeyRewrapRequest,
) (certificateasset.PrivateKeyEnvelope, error) {
	if e == nil || request.TargetKeyID != e.keyID {
		return certificateasset.PrivateKeyEnvelope{}, certificateasset.ErrEnvelopeUnavailable
	}
	metadata, err := decodeACMEEnvelopeMetadata(request.Envelope.Metadata)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, certificateasset.ErrEnvelopeUnavailable
	}
	plaintext, err := e.Unseal(ctx, certificateasset.PrivateKeyUnsealRequest{
		Context: request.Context, Envelope: request.Envelope,
	})
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	defer zeroACMEBytes(plaintext)
	return e.seal(request.Context, plaintext, metadata)
}

func (e *acmePrivateKeyEnveloper) seal(
	contextValue certificateasset.PrivateKeyEnvelopeContext,
	plaintext []byte,
	metadata acmeEnvelopeMetadata,
) (certificateasset.PrivateKeyEnvelope, error) {
	if e == nil || e.aead == nil || e.random == nil || len(plaintext) == 0 || len(plaintext) > 128*1024 {
		return certificateasset.PrivateKeyEnvelope{}, certificateasset.ErrEnvelopeUnavailable
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil || len(encodedMetadata) > 4096 {
		return certificateasset.PrivateKeyEnvelope{}, certificateasset.ErrEnvelopeUnavailable
	}
	aad, err := acmeEnvelopeAAD(contextValue, e.keyID, encodedMetadata)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, certificateasset.ErrEnvelopeUnavailable
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(e.random, nonce); err != nil {
		return certificateasset.PrivateKeyEnvelope{}, certificateasset.ErrEnvelopeUnavailable
	}
	return certificateasset.PrivateKeyEnvelope{
		KeyID: e.keyID, Ciphertext: e.aead.Seal(nil, nonce, plaintext, aad),
		Nonce: nonce, Metadata: encodedMetadata,
	}, nil
}

func acmeEnvelopeAAD(
	contextValue certificateasset.PrivateKeyEnvelopeContext,
	keyID string,
	metadata json.RawMessage,
) ([]byte, error) {
	canonicalContext, err := contextValue.CanonicalAAD()
	if err != nil || keyID == "" || !json.Valid(metadata) {
		return nil, certificateasset.ErrEnvelopeUnavailable
	}
	metadataDigest := sha256.Sum256(metadata)
	return json.Marshal(struct {
		Schema         string          `json:"schema"`
		KeyID          string          `json:"key_id"`
		Context        json.RawMessage `json:"context"`
		MetadataSHA256 [32]byte        `json:"metadata_sha256"`
	}{
		Schema: "cdnca.acme-certificate-envelope-aad.v1", KeyID: keyID,
		Context: canonicalContext, MetadataSHA256: metadataDigest,
	})
}

func decodeACMEEnvelopeMetadata(value json.RawMessage) (acmeEnvelopeMetadata, error) {
	var metadata acmeEnvelopeMetadata
	if err := json.Unmarshal(value, &metadata); err != nil ||
		metadata.Schema != "cdnca.acme-certificate-envelope.v1" ||
		(metadata.Kind != "pkcs8" && metadata.Kind != "opaque_wrapped") ||
		(metadata.Kind == "opaque_wrapped" && !json.Valid(metadata.Source)) {
		return acmeEnvelopeMetadata{}, certificateasset.ErrEnvelopeUnavailable
	}
	return metadata, nil
}

func zeroACMEBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
