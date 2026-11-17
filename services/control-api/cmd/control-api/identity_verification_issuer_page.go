package main

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationissuerhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// The evidence issuer is built from the system settings
// page ("认证与支付 → 实名认证") with IDENTITY_VERIFICATION_ISSUER_* as the
// per-value fallback, and rebuilt when the settings revision changes, so a save
// applies without restarting control-api.
//
//   - It is on when the environment or the page turns it on (the page cannot
//     turn off an issuer the environment declares) and serves only when every
//     value is present, including the object store keys and region its KMS
//     client uses (page first, then environment, as for the provider).
//   - An issuer the environment declares must come up at start (as before);
//     when a page override breaks it, the environment alone is used so
//     control-api still starts and the page can be corrected. Its readiness and
//     an unexpected listener stop count as before.
//   - One only the page turns on never fails the start or readiness; a failure
//     is retried on the next poll.
//   - A save that cannot be built keeps the running listener.

const identityVerificationIssuerPollInterval = 3 * time.Second

// identityVerificationIssuerConfig is the issuer of one settings revision.
type identityVerificationIssuerConfig struct {
	listener    identityverificationissuerhttp.ListenerConfig
	identities  []identityverificationissuerhttp.WorkloadIdentity
	kmsEndpoint string
	region      string
	credentials aws.Credentials
	// pageOverrides: at least one issuer value comes from the page
	pageOverrides bool
}

func (config identityVerificationIssuerConfig) complete() bool {
	listener := config.listener
	return listener.ListenAddress != "" &&
		(listener.ServerCertificateFile != "" || len(listener.ServerCertificatePEM) != 0) &&
		(listener.ServerPrivateKeyFile != "" || len(listener.ServerPrivateKeyPEM) != 0) &&
		(listener.ClientCAFile != "" || len(listener.ClientCAPEM) != 0) &&
		len(config.identities) != 0 && config.region != "" &&
		config.credentials.AccessKeyID != "" && config.credentials.SecretAccessKey != ""
}

func (config *identityVerificationIssuerConfig) clear() {
	clear(config.listener.ServerPrivateKeyPEM)
	*config = identityVerificationIssuerConfig{}
}

// mergeKYCIssuerConfig takes each issuer value from the page when saved there
// and from the environment otherwise; provider is the merged provider
// configuration whose object store keys and region the KMS client uses. It
// reports whether the issuer is turned on; the result holds its own copies.
func mergeKYCIssuerConfig(environment identityVerificationIssuerEnvironment,
	page systemusersettings.IdentityVerificationRuntime, provider identityVerificationProviderEnvironment,
) (identityVerificationIssuerConfig, bool, error) {
	text := func(pageValue, environmentValue string) string {
		if pageValue != "" {
			return pageValue
		}
		return environmentValue
	}
	result := identityVerificationIssuerConfig{
		listener:    identityverificationissuerhttp.ListenerConfig{ListenAddress: text(page.IssuerListenAddress, environment.ListenAddress)},
		identities:  environment.WorkloadIdentities,
		kmsEndpoint: text(page.IssuerKMSEndpoint, environment.KMSEndpoint),
		region:      provider.ObjectRegion,
		credentials: aws.Credentials{AccessKeyID: string(provider.ObjectAccessKey), SecretAccessKey: string(provider.ObjectSecretKey),
			SessionToken: string(provider.ObjectSessionToken), Source: "identity-verification-issuer"},
		pageOverrides: page.IssuerListenAddress != "" || page.IssuerServerCertificate != "" || len(page.IssuerServerPrivateKey) != 0 ||
			page.IssuerClientCA != "" || page.IssuerWorkloadIdentities != "" || page.IssuerKMSEndpoint != "",
	}
	if page.IssuerServerCertificate != "" {
		result.listener.ServerCertificatePEM = []byte(page.IssuerServerCertificate)
	} else {
		result.listener.ServerCertificateFile = environment.ServerCertificate
	}
	if len(page.IssuerServerPrivateKey) != 0 {
		result.listener.ServerPrivateKeyPEM = append([]byte(nil), page.IssuerServerPrivateKey...)
	} else {
		result.listener.ServerPrivateKeyFile = environment.ServerPrivateKey
	}
	if page.IssuerClientCA != "" {
		result.listener.ClientCAPEM = []byte(page.IssuerClientCA)
	} else {
		result.listener.ClientCAFile = environment.ClientCA
	}
	if page.IssuerWorkloadIdentities != "" {
		identities, err := parseIdentityVerificationIssuerIdentities(page.IssuerWorkloadIdentities)
		if err != nil {
			result.clear()
			return identityVerificationIssuerConfig{}, false, errors.New("the issuer workload identities saved on the system settings page are invalid")
		}
		result.identities = identities
	}
	return result, environment.Enabled || page.IssuerEnabled, nil
}

// identityVerificationIssuerSupervisor runs the issuer listener of the
// current settings revision.
type identityVerificationIssuerSupervisor struct {
	environment identityVerificationIssuerEnvironment
	provider    identityVerificationProviderEnvironment
	revisionOf  func(context.Context) (int64, error)
	page        func(context.Context) (systemusersettings.IdentityVerificationRuntime, error)
	clock       identityverificationissuerhttp.Clock
	newHandler  func(identityVerificationIssuerConfig) (http.Handler, error)
	poll        time.Duration
	base        context.Context
	cancel      context.CancelFunc
	stopped     chan error

	mu       sync.Mutex
	loaded   bool
	revision int64
	current  *identityverificationissuerhttp.Listener
	config   identityVerificationIssuerConfig
	handler  http.Handler
	err      error
	closed   bool
}

func newIdentityVerificationIssuerSupervisor(environment identityVerificationIssuerEnvironment,
	provider identityVerificationProviderEnvironment,
	revisionOf func(context.Context) (int64, error),
	page func(context.Context) (systemusersettings.IdentityVerificationRuntime, error),
	clock identityverificationissuerhttp.Clock,
	newHandler func(identityVerificationIssuerConfig) (http.Handler, error),
) *identityVerificationIssuerSupervisor {
	// own copies: the caller clears the provider environment when it returns
	fallback, _ := mergeKYCProviderConfig(provider, systemusersettings.IdentityVerificationRuntime{})
	base, cancel := context.WithCancel(context.Background())
	return &identityVerificationIssuerSupervisor{environment: environment, provider: fallback, revisionOf: revisionOf,
		page: page, clock: clock, newHandler: newHandler, poll: identityVerificationIssuerPollInterval,
		base: base, cancel: cancel, stopped: make(chan error, 1)}
}

// refresh rebuilds the issuer when the settings revision changed (or the
// issuer should serve but does not).
func (supervisor *identityVerificationIssuerSupervisor) refresh(ctx context.Context) {
	revision, err := supervisor.revisionOf(ctx)
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.closed {
		return
	}
	if err != nil {
		supervisor.err = errors.New("read the identity verification settings revision")
		return
	}
	if supervisor.loaded && revision == supervisor.revision && (supervisor.current != nil || supervisor.err == nil) {
		return
	}
	page, err := supervisor.page(ctx)
	defer page.Clear()
	if err != nil {
		supervisor.err = errors.New("read the identity verification issuer settings")
		return
	}
	supervisor.loaded, supervisor.revision, supervisor.err = true, revision, nil
	provider, err := mergeKYCProviderConfig(supervisor.provider, page)
	defer provider.clear()
	var config identityVerificationIssuerConfig
	enabled := false
	if err == nil {
		config, enabled, err = mergeKYCIssuerConfig(supervisor.environment, page, provider)
	}
	if err == nil && (!enabled || !config.complete()) {
		// turned off or not complete: nothing is issued
		config.clear()
		supervisor.stopCurrent()
		if enabled && supervisor.environment.Enabled {
			supervisor.err = errors.New("identity verification issuer configuration is incomplete")
		}
		return
	}
	if err == nil {
		err = supervisor.start(config)
	}
	if err == nil {
		return
	}
	supervisor.err = err
	if supervisor.current == nil && supervisor.environment.Enabled && (config.pageOverrides || config.listener.ListenAddress == "") {
		// the declared issuer comes up from the environment alone
		fallback, _, _ := mergeKYCIssuerConfig(supervisor.environment, systemusersettings.IdentityVerificationRuntime{}, supervisor.provider)
		if fallback.complete() {
			if fallbackErr := supervisor.start(fallback); fallbackErr != nil {
				supervisor.err = errors.Join(err, fallbackErr)
			}
		}
	}
	config.clear()
}

// start serves config in place of the current listener (caller holds mu).
// config is kept on success; on failure the current listener keeps serving.
func (supervisor *identityVerificationIssuerSupervisor) start(config identityVerificationIssuerConfig) error {
	if supervisor.current != nil && reflect.DeepEqual(config, supervisor.config) {
		config.clear()
		return nil
	}
	listenerConfig := config.listener
	listenerConfig.Clock = supervisor.clock
	if err := identityverificationissuerhttp.CheckListenerConfig(listenerConfig); err != nil {
		return errors.New("initialize identity verification issuer mTLS listener")
	}
	handler, err := supervisor.newHandler(config)
	if err != nil {
		return err
	}
	previous, previousConfig, previousHandler := supervisor.current, supervisor.config, supervisor.handler
	if previous != nil {
		_ = previous.Close()
		supervisor.current = nil
	}
	listener, err := identityverificationissuerhttp.NewListener(supervisor.base, listenerConfig, handler)
	if err != nil {
		if previous != nil {
			previousListener := previousConfig.listener
			previousListener.Clock = supervisor.clock
			if restored, restoreErr := identityverificationissuerhttp.NewListener(supervisor.base, previousListener, previousHandler); restoreErr == nil {
				supervisor.serve(restored, previousConfig, previousHandler)
				return errors.New("initialize identity verification issuer mTLS listener")
			}
			previousConfig.clear()
		}
		return errors.New("initialize identity verification issuer mTLS listener")
	}
	previousConfig.clear()
	supervisor.serve(listener, config, handler)
	return nil
}

// serve runs listener as the current one (caller holds mu).
func (supervisor *identityVerificationIssuerSupervisor) serve(listener *identityverificationissuerhttp.Listener,
	config identityVerificationIssuerConfig, handler http.Handler) {
	supervisor.current, supervisor.config, supervisor.handler = listener, config, handler
	go func() {
		// nil after Close (a rebuild or shutdown); an error is an unexpected stop
		err := listener.Run(supervisor.base)
		if err == nil || supervisor.base.Err() != nil {
			return
		}
		supervisor.mu.Lock()
		if supervisor.current == listener {
			supervisor.current, supervisor.err = nil, errors.New("identity verification issuer mTLS listener stopped")
		}
		supervisor.mu.Unlock()
		select {
		case supervisor.stopped <- err:
		default:
		}
	}()
}

// stopCurrent closes the current listener (caller holds mu).
func (supervisor *identityVerificationIssuerSupervisor) stopCurrent() {
	if supervisor.current != nil {
		_ = supervisor.current.Close()
	}
	supervisor.current, supervisor.handler = nil, nil
	supervisor.config.clear()
}

// Run polls the settings revision until ctx ends. An unexpected stop of an
// issuer the environment declares ends it with that error (as before).
func (supervisor *identityVerificationIssuerSupervisor) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("identity verification issuer runtime is unavailable")
	}
	defer supervisor.Close()
	ticker := time.NewTicker(supervisor.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-supervisor.stopped:
			if supervisor.environment.Enabled {
				return errors.Join(identityverificationissuerhttp.ErrListenerStopped, err)
			}
		case <-ticker.C:
			supervisor.refresh(ctx)
		}
	}
}

// Ready counts only an issuer the environment declares.
func (supervisor *identityVerificationIssuerSupervisor) Ready() error {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if !supervisor.environment.Enabled {
		return nil
	}
	if supervisor.current == nil || supervisor.closed {
		return errors.New("identity verification issuer runtime is unavailable")
	}
	return supervisor.current.Ready()
}

func (supervisor *identityVerificationIssuerSupervisor) Close() {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.closed {
		return
	}
	supervisor.closed = true
	supervisor.cancel()
	supervisor.stopCurrent()
	supervisor.provider.clear()
}

func (supervisor *identityVerificationIssuerSupervisor) address() string {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.current == nil {
		return ""
	}
	return supervisor.current.Address()
}

func (supervisor *identityVerificationIssuerSupervisor) lastError() error {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.err
}
