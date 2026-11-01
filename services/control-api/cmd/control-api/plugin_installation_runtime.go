package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
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
	dial, err := pluginRuntimeDialer(environment.providerURL)
	if err != nil {
		return nil, fmt.Errorf("plugin installation runtime: %w", err)
	}
	// 安装客户端证书不可用（授权端不可达、签发被拒）只降级插件安装与安全公告同步，不让主控起不来：
	// 传输层在首次请求时才取证书，失败按请求失败返回，下次请求再试。
	transport := &lazyInstallationTransport{credentials: credentials, build: func(roots *x509.CertPool) http.RoundTripper {
		return &http.Transport{
			Proxy: nil, DialContext: dial, ForceAttemptHTTP2: true, DisableCompression: true,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots,
				GetClientCertificate: credentials.GetClientCertificate},
			TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
			// 50 s < 9448 IdleTimeout 60 s: keep the tunnelled mTLS connection
			// between calls.
			MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 50 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
		}
	}}
	if err := transport.prepare(ctx); err != nil {
		slog.Warn("plugin installation runtime degraded: installation mTLS credential unavailable; retrying on use",
			"error", err)
	}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
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

// lazyInstallationTransport 在第一次成功取到安装客户端证书时才建 mTLS 传输层（根证书来自该凭据），之后复用；
// 取证书失败时本次请求失败、不缓存失败，下次请求重试。客户端证书每次握手仍从证书管理器取（到期前自动续签）。
type lazyInstallationTransport struct {
	credentials *pluginruntimecomposition.CertificateManager
	build       func(*x509.CertPool) http.RoundTripper
	mu          sync.Mutex
	ready       http.RoundTripper
}

func (lazy *lazyInstallationTransport) prepare(ctx context.Context) error {
	lazy.mu.Lock()
	defer lazy.mu.Unlock()
	if lazy.ready != nil {
		return nil
	}
	initial, err := lazy.credentials.Ensure(ctx)
	if err != nil {
		return fmt.Errorf("load plugin installation mTLS credentials: %w", err)
	}
	clear(initial.PrivateKey)
	lazy.ready = lazy.build(initial.RootCAs)
	return nil
}

func (lazy *lazyInstallationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := lazy.prepare(request.Context()); err != nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, err
	}
	return lazy.ready.RoundTrip(request)
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
