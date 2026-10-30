package dnsproviderremote

import (
	"context"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// HubRemote is the provider boundary of 用户端「域名解析」(ADR 0020 §3): the
// tenant's own DNS accounts, A/AAAA/CNAME/TXT, read live from the provider.
// It shares every adapter with reconcile; only the record types differ
// (reconcile, site CNAME and 清除CDN无关解析 stay A/AAAA/CNAME).
type HubRemote interface {
	// HostedDomains lists the domains the account hosts. Custom HTTP and
	// plugin providers have no domain list (CodeUnsupported).
	HostedDomains(ctx context.Context, providerType string, credentials map[string]string) ([]string, error)
	// ListHubRecords lists the A/AAAA/CNAME/TXT records of the zone
	// (owner "" = whole zone) and how many listed records of those types
	// could not be represented (wildcard owners and the like) and were left out.
	ListHubRecords(ctx context.Context, config ProviderConfig, owner string) ([]ZoneRecord, int, error)
	Lookup(ctx context.Context, config ProviderConfig, operation dnscheck.ProviderOperation) (ReconcileLookup, error)
	Mutate(ctx context.Context, config ProviderConfig, operation dnscheck.ProviderOperation) (string, error)
}

type hubRemote struct{ remote *providerReconcileRemote }

func NewHubRemote() HubRemote {
	return hubRemote{remote: &providerReconcileRemote{adapter: newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)}}
}

// HubTXTWritable is the TXT text a member may write: 1-255 bytes, no control
// characters, no double quote or backslash (each adapter writes it as one
// character-string; Huawei quotes it).
func HubTXTWritable(value string) bool {
	return value != "" && len(value) <= 255 && value == strings.TrimSpace(value) &&
		!containsControl(value) && !strings.ContainsAny(value, "\"\\")
}

// HubRecordTypeSupported: TXT needs the provider's DNS-01 TXT support; A,
// AAAA and CNAME follow the reconcile capability.
func HubRecordTypeSupported(providerType string, recordType dnscheck.RecordType) bool {
	capability, ok := providerCapabilityFor(providerType)
	if !ok {
		return false
	}
	if recordType == dnscheck.RecordTXT {
		return capability.DNS01TXT
	}
	return capability.supportsReconcileType(recordType)
}

// HubSupportsWeight reports per-record weight support (DNSPod only).
func HubSupportsWeight(providerType string) bool {
	capability, ok := providerCapabilityFor(providerType)
	return ok && capability.Weight
}

func (hub hubRemote) HostedDomains(ctx context.Context, providerType string, credentials map[string]string) ([]string, error) {
	if hub.remote == nil || hub.remote.adapter == nil || ctx == nil {
		return nil, failure(CodeSourceUnavailable, true)
	}
	providerType = strings.TrimSpace(providerType)
	if !supportedProvider(providerType) || providerType == providerCustomHTTP || providerType == providerPlugin {
		return nil, failure(CodeUnsupported, false)
	}
	if credentials == nil {
		return nil, failure(CodeInvalidInput, false)
	}
	if err := validateCredentials(providerType, credentials); err != nil {
		return nil, err
	}
	raw, err := hub.remote.hostedDomains(ctx, ProviderConfig{ProviderType: providerType, Credentials: credentials})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(raw))
	domains := make([]string, 0, len(raw))
	for _, name := range raw {
		domain := canonicalDNSName(name, false)
		if domain == "" {
			return nil, malformedProviderResponse()
		}
		if _, duplicate := seen[domain]; !duplicate {
			seen[domain] = struct{}{}
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

func (hub hubRemote) ListHubRecords(ctx context.Context, config ProviderConfig, owner string) ([]ZoneRecord, int, error) {
	return hub.remote.listZoneRecords(ctx, config, owner, hubRecordType, true)
}

func (hub hubRemote) Lookup(ctx context.Context, config ProviderConfig, operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	return hub.remote.lookup(ctx, config, operation, true)
}

func (hub hubRemote) Mutate(ctx context.Context, config ProviderConfig, operation dnscheck.ProviderOperation) (string, error) {
	return hub.remote.mutate(ctx, config, operation, true)
}
