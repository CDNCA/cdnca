package dnsacme

import (
	"context"
	"errors"
	"regexp"
	"sync"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
)

// Third-party DNS provider plugins (PA-22): provider type "plugin" with the
// single credential plugin_id. Choosing one as the DNS provider is allowed
// only while the plugin is usable (its installation contract passed for the
// current version and an administrator enabled it); the plugin's verify
// action must then answer through the signed protocol.
const (
	ProviderTypePlugin    = "plugin"
	PluginCredentialField = "plugin_id"
)

// ErrProviderPluginNotUsable: the chosen DNS plugin has not passed its
// installation contract or is not enabled.
var ErrProviderPluginNotUsable = errors.New("the DNS provider plugin has not passed its contract or is not enabled")

var pluginProviderIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)

func validPluginProviderID(value string) bool {
	return len(value) <= 128 && pluginProviderIDPattern.MatchString(value)
}

// PluginProviderClients returns a client of a usable plugin
// (pluginproviders.Service).
type PluginProviderClients interface {
	Client(ctx context.Context, pluginID, kind string) (*pluginprovider.Client, error)
}

var dnsPluginClients struct {
	mu      sync.RWMutex
	clients PluginProviderClients
}

// SetPluginProviderClients installs the plugin client source used to
// verify a DNS plugin when it is chosen (nil: plugins cannot be chosen).
func SetPluginProviderClients(clients PluginProviderClients) {
	dnsPluginClients.mu.Lock()
	defer dnsPluginClients.mu.Unlock()
	dnsPluginClients.clients = clients
}

func verifyDNSPlugin(ctx context.Context, pluginID string) error {
	dnsPluginClients.mu.RLock()
	clients := dnsPluginClients.clients
	dnsPluginClients.mu.RUnlock()
	if clients == nil {
		return ErrProviderVerificationUnavailable
	}
	client, err := clients.Client(ctx, pluginID, pluginprovider.KindDNS)
	if err != nil {
		return ErrProviderPluginNotUsable
	}
	err = client.Call(ctx, pluginprovider.KindDNS, "verify",
		pluginprovider.RequestHeader{Protocol: pluginprovider.Protocol}, nil)
	switch pluginprovider.CodeOf(err) {
	case "":
		if err != nil {
			return ErrProviderVerificationUnavailable
		}
		return nil
	case pluginprovider.CodeUnauthorized:
		return ErrProviderCredentialsRejected
	case pluginprovider.CodeBadResponseSignature, pluginprovider.CodeInvalidResponse:
		return ErrProviderVerificationInvalidResponse
	case pluginprovider.CodeRateLimited:
		return ErrProviderVerificationRateLimited
	case pluginprovider.CodeTimeout:
		return ErrProviderVerificationTimeout
	default:
		return ErrProviderVerificationUnavailable
	}
}
