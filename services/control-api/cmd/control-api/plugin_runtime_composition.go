package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	secrets pluginwebhook.V2SecretProvider) (*pluginruntimecomposition.WebhookDeliverer, error) {
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
	delegate pluginruntimecomposition.V2Deliverer) (*pluginruntimecomposition.WebhookDeliverer, error) {
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
	initialCredential, err := certificateManager.Ensure(context.Background())
	if err != nil {
		return nil, fmt.Errorf("bootstrap plugin runtime certificate: %w", err)
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
