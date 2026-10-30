package dnsproviderremote

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
	"github.com/google/uuid"
)

// Third-party DNS provider plugins (PA-22): provider type "plugin", the one
// credential field names the plugin. The record calls go through the same
// customHTTPProvider logic as the custom HTTP endpoint; the client speaks
// cdnca.provider/v1 to the plugin. A plugin is called only while it is
// usable (active, contract passed, enabled): PluginClients enforces that on
// every call, so disabling or withdrawing a plugin stops DNS writes at once.

// PluginCredentialField is the only credential of provider type plugin.
const PluginCredentialField = "plugin_id"

// ProviderTypePlugin is the dns_providers.provider_type of DNS plugins.
const ProviderTypePlugin = providerPlugin

var pluginIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)

func validPluginID(value string) bool { return len(value) <= 128 && pluginIDPattern.MatchString(value) }

// PluginClients returns a cdnca.provider/v1 client of a usable plugin for
// kind (pluginproviders.Service.Client).
type PluginClients interface {
	Client(ctx context.Context, pluginID, kind string) (*pluginprovider.Client, error)
}

var pluginClients struct {
	mu      sync.RWMutex
	clients PluginClients
}

// SetPluginClients installs the process-wide plugin client source (nil:
// provider type plugin is unavailable).
func SetPluginClients(clients PluginClients) {
	pluginClients.mu.Lock()
	defer pluginClients.mu.Unlock()
	pluginClients.clients = clients
}

func pluginRecordClientFor(config ProviderConfig) (recordClient, error) {
	pluginClients.mu.RLock()
	clients := pluginClients.clients
	pluginClients.mu.RUnlock()
	pluginID := config.Credentials[PluginCredentialField]
	if clients == nil || !validPluginID(pluginID) {
		return nil, failure(CodeUnavailable, true)
	}
	return &pluginRecordClient{clients: clients, pluginID: pluginID}, nil
}

// pluginRecordClient resolves the plugin on every call (the plugin may be
// disabled between calls) and maps protocol errors to dnscustomhttp's.
type pluginRecordClient struct {
	clients  PluginClients
	pluginID string
}

func (client *pluginRecordClient) call(ctx context.Context, action string, request, result any) error {
	resolved, err := client.clients.Client(ctx, client.pluginID, pluginprovider.KindDNS)
	if err != nil {
		return dnscustomhttp.ErrUnavailable
	}
	return pluginRecordError(resolved.Call(ctx, pluginprovider.KindDNS, action, request, result))
}

func pluginRecordError(err error) error {
	if err == nil {
		return nil
	}
	var callErr *pluginprovider.Error
	if !errors.As(err, &callErr) {
		return dnscustomhttp.ErrUnavailable
	}
	switch callErr.Code {
	case "not_found":
		return dnscustomhttp.ErrNotFound
	case pluginprovider.CodeUnauthorized:
		return dnscustomhttp.ErrUnauthorized
	case pluginprovider.CodeRateLimited, "quota_exceeded":
		return dnscustomhttp.ErrRateLimited
	case pluginprovider.CodeTimeout:
		return dnscustomhttp.ErrTimeout
	case pluginprovider.CodeUnavailable, pluginprovider.CodeBlockedAddress:
		return dnscustomhttp.ErrUnavailable
	case pluginprovider.CodeInvalidResponse, pluginprovider.CodeBadResponseSignature:
		return dnscustomhttp.ErrMalformed
	}
	if callErr.Remote {
		return dnscustomhttp.Rejected(callErr.Code)
	}
	return dnscustomhttp.ErrMalformed
}

func header() pluginprovider.RequestHeader {
	return pluginprovider.RequestHeader{Protocol: pluginprovider.Protocol}
}

func (client *pluginRecordClient) ListRecords(ctx context.Context, zone, name string) ([]dnscustomhttp.Record, error) {
	var response pluginprovider.DNSListResponse
	if err := client.call(ctx, "list_records", pluginprovider.DNSListRequest{RequestHeader: header(), Zone: zone, Name: name},
		&response); err != nil {
		return nil, err
	}
	records := make([]dnscustomhttp.Record, 0, len(response.Records))
	seen := map[string]bool{}
	for _, record := range response.Records {
		record.Name = strings.ToLower(strings.TrimSuffix(record.Name, "."))
		record.Type = strings.ToUpper(record.Type)
		if record.ID == "" || len(record.ID) > 256 || seen[record.ID] || record.Name == "" || len(record.Value) > 4096 ||
			record.TTL == 0 {
			return nil, dnscustomhttp.ErrMalformed
		}
		seen[record.ID] = true
		records = append(records, dnscustomhttp.Record{ID: record.ID, Name: record.Name, Type: record.Type,
			Value: record.Value, TTL: record.TTL, Line: record.Line})
	}
	return records, nil
}

func wireRecord(record dnscustomhttp.Record) pluginprovider.DNSRecord {
	return pluginprovider.DNSRecord{ID: record.ID, Name: record.Name, Type: record.Type, Value: record.Value,
		TTL: record.TTL, Line: record.Line}
}

func (client *pluginRecordClient) CreateRecord(ctx context.Context, zone string, record dnscustomhttp.Record) (string, error) {
	record.ID = ""
	var response pluginprovider.DNSCreateResponse
	if err := client.call(ctx, "create_record", pluginprovider.DNSWriteRequest{RequestHeader: header(), Zone: zone,
		Record: wireRecord(record), IdempotencyKey: uuid.NewString()}, &response); err != nil {
		return "", err
	}
	if response.ID == "" || len(response.ID) > 256 {
		return "", dnscustomhttp.ErrMalformed
	}
	return response.ID, nil
}

func (client *pluginRecordClient) UpdateRecord(ctx context.Context, zone string, record dnscustomhttp.Record) error {
	if record.ID == "" {
		return dnscustomhttp.ErrInvalidCredentials
	}
	return client.call(ctx, "update_record", pluginprovider.DNSWriteRequest{RequestHeader: header(), Zone: zone,
		Record: wireRecord(record), IdempotencyKey: uuid.NewString()}, nil)
}

func (client *pluginRecordClient) DeleteRecord(ctx context.Context, zone, id string) error {
	if id == "" {
		return dnscustomhttp.ErrInvalidCredentials
	}
	return client.call(ctx, "delete_record", pluginprovider.DNSDeleteRequest{RequestHeader: header(), Zone: zone, ID: id,
		IdempotencyKey: uuid.NewString()}, nil)
}

func (client *pluginRecordClient) Close() {}
