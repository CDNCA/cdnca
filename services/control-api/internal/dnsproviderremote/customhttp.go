package dnsproviderremote

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
)

// customHTTPProvider is the "自定义 HTTP 接口" provider: the
// operator's own DNS behind a signed HTTPS endpoint
// (dnscustomhttp). Lines are the unified names; the endpoint maps them.
// The same record logic serves third-party DNS plugins (PA-22, provider
// type plugin): only the record client differs.
type customHTTPProvider struct {
	adapter *Adapter
	// providerType is providerCustomHTTP or providerPlugin.
	providerType string
}

// recordClient is the record API both endpoint kinds share; errors are
// dnscustomhttp sentinels.
type recordClient interface {
	ListRecords(ctx context.Context, zone, name string) ([]dnscustomhttp.Record, error)
	CreateRecord(ctx context.Context, zone string, record dnscustomhttp.Record) (string, error)
	UpdateRecord(ctx context.Context, zone string, record dnscustomhttp.Record) error
	DeleteRecord(ctx context.Context, zone, id string) error
	Close()
}

func newRecordProvider(adapter *Adapter, providerType string) *customHTTPProvider {
	return &customHTTPProvider{adapter: adapter, providerType: providerType}
}

func (p *customHTTPProvider) kind() string {
	if p.providerType == "" {
		return providerCustomHTTP
	}
	return p.providerType
}

func (p *customHTTPProvider) client(config ProviderConfig) (recordClient, error) {
	if p.kind() == providerPlugin {
		return pluginRecordClientFor(config)
	}
	options := dnscustomhttp.Options{Now: p.adapter.now}
	if p.adapter.customHTTP != nil {
		options = *p.adapter.customHTTP
		if options.Now == nil {
			options.Now = p.adapter.now
		}
	}
	client, err := dnscustomhttp.New(config.Credentials, options)
	if err != nil {
		return nil, failure(CodeInvalidInput, false)
	}
	return client, nil
}

// customHTTPFailure maps client errors to the adapter's stable codes.
func customHTTPFailure(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return failure(CodeCancelled, false)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, dnscustomhttp.ErrTimeout):
		return failure(CodeTimeout, true)
	case errors.Is(err, dnscustomhttp.ErrUnauthorized):
		return failure(CodeCredentialsRejected, false)
	case errors.Is(err, dnscustomhttp.ErrRateLimited):
		return failure(CodeRateLimited, true)
	case errors.Is(err, dnscustomhttp.ErrNotFound):
		return failure(CodeRecordNotFound, false)
	case errors.Is(err, dnscustomhttp.ErrUnavailable), errors.Is(err, dnscustomhttp.ErrBlockedAddress):
		return failure(CodeUnavailable, true)
	case errors.Is(err, dnscustomhttp.ErrRejected):
		return failure(CodeRecordMismatch, false)
	default:
		return malformedProviderResponse()
	}
}

func customHTTPLine(line string) string {
	if defaultReconcileLine(line) {
		return LineDefault
	}
	return line
}

func (p *customHTTPProvider) records(ctx context.Context, config ProviderConfig, name string) ([]reconcileRecord, error) {
	client, err := p.client(config)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	listed, err := client.ListRecords(ctx, config.ZoneName, strings.TrimSuffix(name, "."))
	if err != nil {
		return nil, customHTTPFailure(err)
	}
	records := make([]reconcileRecord, 0, len(listed))
	for _, record := range listed {
		records = append(records, reconcileRecord{ID: record.ID, Name: record.Name + ".", Type: record.Type,
			Value: record.Value, TTL: record.TTL, Line: customHTTPLine(record.Line)})
	}
	return records, nil
}

// --- DNS-01 TXT ---

func (p *customHTTPProvider) present(ctx context.Context, config ProviderConfig, owner, _ string,
	exactValue string) (recordHandle, error) {
	client, err := p.client(config)
	if err != nil {
		return recordHandle{}, err
	}
	defer client.Close()
	id, err := client.CreateRecord(ctx, config.ZoneName, dnscustomhttp.Record{Name: strings.TrimSuffix(owner, "."),
		Type: "TXT", Value: exactValue, TTL: 600, Line: LineDefault})
	if err != nil {
		return recordHandle{}, customHTTPFailure(err)
	}
	handle := recordHandle{Provider: p.kind(), Zone: config.ZoneName, ZoneID: config.ZoneName, RecordID: id, Owner: owner}
	remote, exists, err := p.get(ctx, config, handle, exactValue)
	if err != nil {
		return recordHandle{}, err
	}
	if !exists || !matchesRecord(remote, handle, exactValue) {
		return recordHandle{}, malformedProviderResponse()
	}
	return handle, nil
}

func (p *customHTTPProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, _ string,
	exactValue string) ([]recordHandle, error) {
	records, err := p.records(ctx, config, owner)
	if err != nil {
		return nil, err
	}
	candidates := make([]txtCandidate, 0, len(records))
	for _, record := range records {
		if record.Type != "TXT" {
			continue
		}
		candidates = append(candidates, txtCandidate{id: record.ID, zoneID: config.ZoneName, owner: record.Name,
			recordType: record.Type, value: record.Value})
	}
	return exactTXTHandles(p.kind(), config.ZoneName, owner, exactValue, candidates)
}

func (p *customHTTPProvider) get(ctx context.Context, config ProviderConfig, handle recordHandle,
	_ string) (remoteRecord, bool, error) {
	records, err := p.records(ctx, config, handle.Owner)
	if err != nil {
		return remoteRecord{}, false, err
	}
	for _, record := range records {
		if record.ID == handle.RecordID {
			return remoteRecord{Owner: record.Name, Type: record.Type, Value: record.Value}, true, nil
		}
	}
	return remoteRecord{}, false, nil
}

func (p *customHTTPProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	client, err := p.client(config)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.DeleteRecord(ctx, config.ZoneName, handle.RecordID); err != nil &&
		!errors.Is(err, dnscustomhttp.ErrNotFound) {
		return customHTTPFailure(err)
	}
	return nil
}

// --- A/AAAA/CNAME reconcile ---

func (p *customHTTPProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	records, err := p.records(ctx, config, operation.Name)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	kept := make([]reconcileRecord, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.Type != typeName {
			continue
		}
		normalized, err := normalizeReconcileRecord(record)
		if err != nil {
			return ReconcileLookup{}, err
		}
		if _, duplicate := seen[normalized.ID]; duplicate {
			return ReconcileLookup{}, failure(CodeRecordMismatch, false)
		}
		seen[normalized.ID] = struct{}{}
		kept = append(kept, normalized)
	}
	if operation.Action == dnscheck.ProviderCreate {
		kept = recordsOnLine(kept, operation.Line)
	}
	return lookupRecord(kept, operation, fmt.Sprintf("%s:records=%d", p.kind(), len(kept))), nil
}

func (p *customHTTPProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	client, err := p.client(config)
	if err != nil {
		return "", err
	}
	defer client.Close()
	if operation.Action == dnscheck.ProviderDelete {
		if err := client.DeleteRecord(ctx, config.ZoneName, operation.RecordID); err != nil &&
			!errors.Is(err, dnscustomhttp.ErrNotFound) {
			return "", customHTTPFailure(err)
		}
		return operation.RecordID, nil
	}
	typeName, _ := reconcileRecordType(operation.Type)
	record := dnscustomhttp.Record{Name: strings.TrimSuffix(operation.Name, "."), Type: typeName,
		Value: reconcileProviderValue(operation.Type, operation.Value), TTL: operation.TTL, Line: customHTTPLine(operation.Line)}
	if operation.Action == dnscheck.ProviderUpdate {
		record.ID = operation.RecordID
		if err := client.UpdateRecord(ctx, config.ZoneName, record); err != nil {
			return "", customHTTPFailure(err)
		}
		return operation.RecordID, nil
	}
	id, err := client.CreateRecord(ctx, config.ZoneName, record)
	if err != nil {
		return "", customHTTPFailure(err)
	}
	return id, nil
}

func (p *customHTTPProvider) listRecords(ctx context.Context, config ProviderConfig, owner, relative string) ([]reconcileRecord, error) {
	name := ""
	if relative != "" {
		name = owner
	}
	return p.records(ctx, config, name)
}
