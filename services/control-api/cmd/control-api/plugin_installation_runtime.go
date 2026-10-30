package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/plugininstallation"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimecomposition"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func buildPluginInstallationHandlerFactory(ctx context.Context, cfg config.Config, pool *pgxpool.Pool,
	identityService *identity.Service, trust *entitlementguard.TrustStore,
) (httpapi.MountedHandlerFactory, error) {
	runtime, err := buildPluginInstallationRuntime(ctx, cfg, pool, identityService, trust)
	if err != nil || runtime == nil {
		return nil, err
	}
	return runtime.handler, nil
}

func (runtime *pluginInstallationRuntime) handlerFactory() httpapi.MountedHandlerFactory {
	if runtime == nil {
		return nil
	}
	return runtime.handler
}

// pluginInstallationRuntime is the plugin installation wiring shared by the tenant HTTP handler and the plugin
// security advisory sync.
type pluginInstallationRuntime struct {
	handler httpapi.MountedHandlerFactory
	// license is the installation mTLS client and provider URL, shared with
	// the plugin security advisory sync (marketsubscribehttp).
	licenseHTTP    *http.Client
	providerURL    string
	installationID uuid.UUID
}

func buildPluginInstallationRuntime(ctx context.Context, cfg config.Config, pool *pgxpool.Pool,
	identityService *identity.Service, trust *entitlementguard.TrustStore,
) (*pluginInstallationRuntime, error) {
	if cfg.LicenseServiceURL == "" || strings.TrimSpace(os.Getenv("PLUGIN_RUNTIME_PROVIDER_URL")) == "" {
		return nil, nil
	}
	if ctx == nil || pool == nil || identityService == nil || trust == nil {
		return nil, errors.New("plugin installation runtime dependencies are incomplete")
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errors.New("plugin installation runtime requires a canonical control installation UUID")
	}
	installationKey, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load plugin installation proof key: %w", err)
	}
	defer clear(installationKey)
	environment, err := loadPluginInstallationRuntimeEnvironment()
	if err != nil {
		return nil, err
	}
	now := func() time.Time { return time.Now().UTC() }
	credentials, err := pluginruntimecomposition.NewCertificateManager(
		pluginruntimecomposition.CertificateManagerConfig{
			BaseURL: cfg.LicenseServiceURL, InstallationID: installationID,
			ActivationPrivateKey: installationKey, CertificateFile: environment.certificateFile,
			PrivateKeyFile: environment.privateKeyFile, RuntimeCAFile: environment.licenseCAFile,
			StateFile: environment.stateFile, BootstrapServerCAFile: environment.bootstrapCAFile,
			Now: now, Timeout: 5 * time.Second, MaxBodyBytes: 64 << 10,
		})
	if err != nil {
		return nil, fmt.Errorf("initialize plugin installation mTLS credentials: %w", err)
	}
	initial, err := credentials.Ensure(ctx)
	if err != nil {
		return nil, fmt.Errorf("load plugin installation mTLS credentials: %w", err)
	}
	defer clear(initial.PrivateKey)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: initial.RootCAs, Certificates: []tls.Certificate{initial.TLSCertificate},
		GetClientCertificate: credentials.GetClientCertificate,
	}
	dial, err := pluginRuntimeDialer(environment.providerURL)
	if err != nil {
		return nil, fmt.Errorf("plugin installation runtime: %w", err)
	}
	httpClient := &http.Client{Transport: &http.Transport{
		Proxy: nil, DialContext: dial, ForceAttemptHTTP2: true, DisableCompression: true, TLSClientConfig: tlsConfig,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 5 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("plugin installation activation redirects are forbidden")
	}}
	activation, err := plugininstallation.NewActivationClient(plugininstallation.ActivationClientConfig{
		BaseURL: environment.providerURL, HTTP: httpClient, InstallationID: installationID,
		PrivateKey: installationKey, Trust: trust, Now: now,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize plugin installation activation client: %w", err)
	}
	repository, err := plugininstallation.NewPostgresRepository(pool, now)
	if err != nil {
		return nil, fmt.Errorf("initialize plugin installation repository: %w", err)
	}
	domain, err := plugininstallation.NewProductionDomain(repository, activation)
	if err != nil {
		return nil, fmt.Errorf("initialize plugin installation domain: %w", err)
	}
	return &pluginInstallationRuntime{handler: func() (http.Handler, error) {
		return plugininstallation.NewHandler(plugininstallation.HandlerDependencies{
			AuthenticateSession: identityService.AuthenticateSession,
			Domain:              domain,
		})
	}, licenseHTTP: httpClient, providerURL: environment.providerURL, installationID: installationID}, nil
}

type pluginInstallationRuntimeEnvironment struct {
	providerURL     string
	certificateFile string
	privateKeyFile  string
	licenseCAFile   string
	stateFile       string
	bootstrapCAFile string
}

func loadPluginInstallationRuntimeEnvironment() (pluginInstallationRuntimeEnvironment, error) {
	read := func(name string) (string, error) {
		value, found := os.LookupEnv(name)
		if !found || value == "" || value != strings.TrimSpace(value) {
			return "", fmt.Errorf("%s is required for plugin installation runtime", name)
		}
		return value, nil
	}
	providerURL, err := read("PLUGIN_RUNTIME_PROVIDER_URL")
	if err != nil {
		return pluginInstallationRuntimeEnvironment{}, err
	}
	certificateFile, err := read("PLUGIN_RUNTIME_CLIENT_CERT_FILE")
	if err != nil {
		return pluginInstallationRuntimeEnvironment{}, err
	}
	privateKeyFile, err := read("PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE")
	if err != nil {
		return pluginInstallationRuntimeEnvironment{}, err
	}
	licenseCAFile, err := read("PLUGIN_RUNTIME_LICENSE_CA_FILE")
	if err != nil {
		return pluginInstallationRuntimeEnvironment{}, err
	}
	stateFile, err := read("PLUGIN_RUNTIME_CLIENT_STATE_FILE")
	if err != nil {
		return pluginInstallationRuntimeEnvironment{}, err
	}
	bootstrapCAFile, found := os.LookupEnv("PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE")
	if found && bootstrapCAFile != strings.TrimSpace(bootstrapCAFile) {
		return pluginInstallationRuntimeEnvironment{}, errors.New(
			"PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE must not contain surrounding whitespace")
	}
	return pluginInstallationRuntimeEnvironment{providerURL: providerURL, certificateFile: certificateFile,
		privateKeyFile: privateKeyFile, licenseCAFile: licenseCAFile, stateFile: stateFile,
		bootstrapCAFile: bootstrapCAFile}, nil
}
