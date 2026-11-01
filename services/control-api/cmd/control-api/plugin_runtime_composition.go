package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimecomposition"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginworkloadidentity"
	"github.com/google/uuid"
)

type pluginRuntimeCompositionEnvironment struct {
	ProviderURL           string
	ProjectionURL         string
	ClientCertFile        string
	ClientKeyFile         string
	LicenseCAFile         string
	ClientStateFile       string
	BootstrapServerCAFile string
}

func loadPluginRuntimeCompositionEnvironment() (pluginRuntimeCompositionEnvironment, error) {
	names := []string{"PLUGIN_RUNTIME_PROVIDER_URL", "PLUGIN_RUNTIME_PROJECTION_URL", "PLUGIN_RUNTIME_CLIENT_CERT_FILE",
		"PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE", "PLUGIN_RUNTIME_LICENSE_CA_FILE", "PLUGIN_RUNTIME_CLIENT_STATE_FILE"}
	values := make([]string, len(names))
	for index, name := range names {
		value, found := os.LookupEnv(name)
		if !found || value == "" || value != strings.TrimSpace(value) {
			return pluginRuntimeCompositionEnvironment{}, fmt.Errorf("%s is required for plugin runtime composition", name)
		}
		values[index] = value
	}
	paths := values[2:]
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return pluginRuntimeCompositionEnvironment{}, errors.New("plugin runtime TLS paths must be absolute and clean")
		}
	}
	seen := map[string]bool{}
	directory := filepath.Dir(paths[0])
	for _, path := range paths {
		if seen[path] || filepath.Dir(path) != directory {
			return pluginRuntimeCompositionEnvironment{}, errors.New("plugin runtime credential paths must be distinct and colocated")
		}
		seen[path] = true
	}
	bootstrapCA, found := os.LookupEnv("PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE")
	if found && bootstrapCA != "" {
		if !filepath.IsAbs(bootstrapCA) || filepath.Clean(bootstrapCA) != bootstrapCA {
			return pluginRuntimeCompositionEnvironment{}, errors.New("plugin runtime bootstrap CA path must be absolute and clean")
		}
	}
	return pluginRuntimeCompositionEnvironment{ProviderURL: values[0], ProjectionURL: values[1],
		ClientCertFile: values[2], ClientKeyFile: values[3], LicenseCAFile: values[4], ClientStateFile: values[5], BootstrapServerCAFile: bootstrapCA}, nil
}

func newPluginRuntimeWebhookDeliverer(cfg config.Config, trust *entitlementguard.TrustStore,
	secrets pluginwebhook.V2SecretProvider) (*deferredPluginWebhookDeliverer, error) {
	if trust == nil || secrets == nil {
		return nil, errors.New("plugin runtime composition requires trust and webhook secrets")
	}
	delegate, err := pluginwebhook.NewV2HTTPSender(pluginwebhook.DefaultHTTPSenderConfig(), secrets)
	if err != nil {
		return nil, fmt.Errorf("initialize plugin webhook sender: %w", err)
	}
	return newAuthorizedPluginWebhookDeliverer(cfg, trust, delegate)
}

// newAuthorizedPluginWebhookDeliverer wraps delegate with the license runtime gate: every delivery first resolves a
// signed runtime projection and a workload authorization from the platform license service over mTLS.
func newAuthorizedPluginWebhookDeliverer(cfg config.Config, trust *entitlementguard.TrustStore,
	delegate pluginruntimecomposition.V2Deliverer) (*deferredPluginWebhookDeliverer, error) {
	if trust == nil || delegate == nil {
		return nil, errors.New("plugin runtime composition requires trust and a webhook sender")
	}
	environment, err := loadPluginRuntimeCompositionEnvironment()
	if err != nil {
		return nil, err
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errors.New("plugin runtime composition requires a canonical control installation UUID")
	}
	installationKey, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load plugin runtime installation key: %w", err)
	}
	defer clear(installationKey)
	now := func() time.Time { return time.Now().UTC() }
	certificateManager, err := pluginruntimecomposition.NewCertificateManager(pluginruntimecomposition.CertificateManagerConfig{
		BaseURL: cfg.LicenseServiceURL, InstallationID: installationID, ActivationPrivateKey: installationKey,
		CertificateFile: environment.ClientCertFile, PrivateKeyFile: environment.ClientKeyFile,
		RuntimeCAFile: environment.LicenseCAFile, StateFile: environment.ClientStateFile,
		BootstrapServerCAFile: environment.BootstrapServerCAFile, Now: now, Timeout: 5 * time.Second, MaxBodyBytes: 64 << 10,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize plugin runtime certificate manager: %w", err)
	}
	// 延后构建要用安装证明私钥：留一份进程内副本（构建成功后清掉；provider 自己另存一份）。
	retainedKey := append(ed25519.PrivateKey(nil), installationKey...)
	deferred := &deferredPluginWebhookDeliverer{build: func(ctx context.Context) (*pluginruntimecomposition.WebhookDeliverer, error) {
		deliverer, err := buildAuthorizedPluginWebhookDeliverer(ctx, trust, delegate, environment, installationID, retainedKey, certificateManager)
		if err == nil {
			clear(retainedKey)
		}
		return deliverer, err
	}}
	// 安装客户端证书不可用只让插件 webhook 投递按可重试失败延后，不让主控起不来；每次投递时再试构建。
	// 其余构建错误（拨号/配置）仍在启动时报错。
	if _, err := deferred.ready(context.Background()); err != nil && !errors.Is(err, errInstallationCredentialUnavailable) {
		return nil, err
	} else if err != nil {
		slog.Warn("plugin webhook delivery degraded: plugin runtime credential unavailable; retrying on delivery", "error", err)
	}
	return deferred, nil
}

// errInstallationCredentialUnavailable 标记"安装客户端证书暂时取不到"：只降级插件相关功能，不阻止主控启动。
var errInstallationCredentialUnavailable = errors.New("installation mTLS credential unavailable")

// deferredPluginWebhookDeliverer 把授权投递器的构建（需要安装客户端证书）推迟到第一次成功；构建前每次投递
// 都先重试构建，失败返回可重试的 runtime_authorization_unavailable（不放行、不丢投递）。
type deferredPluginWebhookDeliverer struct {
	build     func(context.Context) (*pluginruntimecomposition.WebhookDeliverer, error)
	mu        sync.Mutex
	deliverer *pluginruntimecomposition.WebhookDeliverer
}

func (deferred *deferredPluginWebhookDeliverer) ready(ctx context.Context) (*pluginruntimecomposition.WebhookDeliverer, error) {
	deferred.mu.Lock()
	defer deferred.mu.Unlock()
	if deferred.deliverer != nil {
		return deferred.deliverer, nil
	}
	deliverer, err := deferred.build(ctx)
	if err != nil {
		return nil, err
	}
	deferred.deliverer = deliverer
	return deliverer, nil
}

func (deferred *deferredPluginWebhookDeliverer) Deliver(ctx context.Context, item pluginwebhook.QueueItem, attempt uint64) pluginwebhook.SendResult {
	deliverer, err := deferred.ready(ctx)
	if err != nil {
		return pluginwebhook.SendResult{Code: "runtime_authorization_unavailable", Retryable: true}
	}
	return deliverer.Deliver(ctx, item, attempt)
}

func (deferred *deferredPluginWebhookDeliverer) DeliverV2(ctx context.Context, item pluginwebhook.QueueItem, attempt uint64,
	secret []byte) pluginwebhook.SendResult {
	deliverer, err := deferred.ready(ctx)
	if err != nil {
		return pluginwebhook.SendResult{Code: "runtime_authorization_unavailable", Retryable: true}
	}
	return deliverer.DeliverV2(ctx, item, attempt, secret)
}

func buildAuthorizedPluginWebhookDeliverer(ctx context.Context, trust *entitlementguard.TrustStore,
	delegate pluginruntimecomposition.V2Deliverer, environment pluginRuntimeCompositionEnvironment, installationID uuid.UUID,
	installationKey ed25519.PrivateKey, certificateManager *pluginruntimecomposition.CertificateManager,
) (*pluginruntimecomposition.WebhookDeliverer, error) {
	now := func() time.Time { return time.Now().UTC() }
	initialCredential, err := certificateManager.Ensure(ctx)
	if err != nil {
		return nil, fmt.Errorf("bootstrap plugin runtime certificate: %w: %w", errInstallationCredentialUnavailable, err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: initialCredential.RootCAs, Certificates: []tls.Certificate{initialCredential.TLSCertificate},
		GetClientCertificate: certificateManager.GetClientCertificate}
	clear(initialCredential.PrivateKey)
	if key, ok := initialCredential.TLSCertificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(key)
	}
	providerDial, err := pluginRuntimeDialer(environment.ProviderURL)
	if err != nil {
		return nil, err
	}
	projectionDial, err := pluginRuntimeDialer(environment.ProjectionURL)
	if err != nil {
		return nil, err
	}
	verifier := pluginruntimeauth.Verifier{Trust: trust, Now: now}
	provider, err := pluginruntimeprovider.New(pluginruntimeprovider.Config{
		BaseURL: environment.ProviderURL, TLSConfig: tlsConfig.Clone(), InstallationID: installationID,
		InstallationPrivateKey: installationKey, Verifier: verifier, Now: now,
		Timeout: 5 * time.Second, MaxBodyBytes: 64 << 10, CacheCapacity: 1024, DialContext: providerDial,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize plugin runtime authorization provider: %w", err)
	}
	workloadAuthorizer, err := pluginworkloadidentity.NewAuthorizer(pluginworkloadidentity.Config{
		Provider: provider, Verifier: verifier, Now: now,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize plugin workload authorizer: %w", err)
	}
	projection, err := pluginruntimecomposition.NewProjectionClient(pluginruntimecomposition.ProjectionClientConfig{
		BaseURL: environment.ProjectionURL, Credentials: certificateManager, InstallationID: installationID,
		Trust: trust, Now: now, Timeout: 5 * time.Second, MaxBodyBytes: 64 << 10, DialContext: projectionDial,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize plugin runtime projection client: %w", err)
	}
	deliverer, err := pluginruntimecomposition.NewWebhookDeliverer(pluginruntimecomposition.WebhookDelivererConfig{
		InstallationID: installationID, Projection: projection, Authorizer: workloadAuthorizer,
		Delegate: delegate, Now: now,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize authorized plugin webhook deliverer: %w", err)
	}
	return deliverer, nil
}
