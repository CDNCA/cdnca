package dnsproviderremote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// Namesilo API, per https://www.namesilo.com/api-reference (operations
// dns/dns-list-records, dns-add-record, dns-update-record, dns-delete-record,
// domains/list-domains and the response code table), read 2026-11-05:
//   - GET https://www.namesilo.com/api/<operation>?version=1&type=json&key=<key>
//     ("All operations *MUST* be invoked via GET method"); the answer is
//     {request:{operation,ip}, reply:{code, detail, ...}} with code 300 on
//     success (110 invalid key, 113 IP not allowed, 200 domain not active or
//     not this user's, 280 DNS modification error, 400 a request is still
//     processing).
//   - dnsListRecords lists every record of the domain (no paging):
//     resource_record [{record_id, type, host (FQDN), value, ttl, distance}].
//   - dnsAddRecord rrtype/rrhost (relative, "" = apex)/rrvalue/rrttl answers
//     record_id; dnsUpdateRecord rrid/rrhost/rrvalue/rrttl answers a NEW
//     record_id ("Any successful updates will result in a new record_id");
//     dnsDeleteRecord rrid.
//
// The JSON form is converted from XML: numbers may come as strings and a
// one-element list as a bare object; both are accepted. No line field:
// default line only. No documented TTL floor or rate limit (see
// providerTTLFloors; HTTP 429 and code 400 are retried).
const providerNamesilo = "namesilo"

type namesiloProvider struct{ adapter *Adapter }

type namesiloReply struct {
	Code           *stringID       `json:"code"`
	RecordID       stringID        `json:"record_id"`
	ResourceRecord json.RawMessage `json:"resource_record"`
	Domains        json.RawMessage `json:"domains"`
	Pager          *struct {
		Total dnsPodNumber `json:"total"`
	} `json:"pager"`
}

type namesiloRecord struct {
	RecordID stringID     `json:"record_id"`
	Type     string       `json:"type"`
	Host     string       `json:"host"`
	Value    string       `json:"value"`
	TTL      dnsPodNumber `json:"ttl"`
}

// namesiloList decodes a list the XML conversion may flatten: absent/null
// = none, an object = one element.
func namesiloList[T any](raw json.RawMessage) ([]T, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] == '{' {
		var one T
		if err := decodeJSON(trimmed, &one); err != nil {
			return nil, err
		}
		return []T{one}, nil
	}
	var many []T
	if err := decodeJSON(trimmed, &many); err != nil {
		return nil, err
	}
	return many, nil
}

// request sends one operation. The key travels in the query (the only
// documented form); responses and errors never carry the URL.
func (p *namesiloProvider) request(ctx context.Context, config ProviderConfig, operation string,
	parameters url.Values) (namesiloReply, error) {
	query := url.Values{"version": {"1"}, "type": {"json"}, "key": {config.Credentials["key"]}}
	for name, values := range parameters {
		query[name] = values
	}
	response, err := p.adapter.http.do(ctx, http.MethodGet, p.adapter.endpoints.namesilo,
		"/api/"+operation+"?"+query.Encode(), nil, nil)
	if err != nil {
		return namesiloReply{}, err
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return namesiloReply{}, err
	}
	var envelope struct {
		Reply *namesiloReply `json:"reply"`
	}
	if response.status != http.StatusOK || decodeJSON(response.body, &envelope) != nil || envelope.Reply == nil ||
		envelope.Reply.Code == nil {
		return namesiloReply{}, malformedProviderResponse()
	}
	switch string(*envelope.Reply.Code) {
	case "300":
		return *envelope.Reply, nil
	case "109", "110", "111", "112", "113", "120":
		return namesiloReply{}, failure(CodeCredentialsRejected, false)
	case "400":
		return namesiloReply{}, rateLimitFailure(response.header.Get("Retry-After"), p.adapter.now())
	case "115", "201":
		return namesiloReply{}, failure(CodeUnavailable, true)
	case "200":
		return namesiloReply{}, failure(CodeZoneNotHosted, false)
	case "280":
		// DNS modification error (unknown rrid, duplicate, invalid value).
		return namesiloReply{}, failure(CodeRecordMismatch, false)
	case "108", "114", "267":
		return namesiloReply{}, failure(CodeInvalidInput, false)
	default:
		return namesiloReply{}, malformedProviderResponse()
	}
}

// listZone lists every record of the domain. Hosts are FQDNs; a host outside
// the zone is refused. Owners are left for normalizeReconcileRecord to
// validate (a wildcard owner is skipped by tolerant listings).
func (p *namesiloProvider) listZone(ctx context.Context, config ProviderConfig) ([]reconcileRecord, error) {
	reply, err := p.request(ctx, config, "dnsListRecords", url.Values{"domain": {config.ZoneName}})
	if err != nil {
		return nil, err
	}
	records, err := namesiloList[namesiloRecord](reply.ResourceRecord)
	if err != nil || len(records) > recoveryMaxItems {
		return nil, malformedProviderResponse()
	}
	result := make([]reconcileRecord, 0, len(records))
	seen := make(map[string]struct{})
	for _, record := range records {
		host := strings.ToLower(strings.TrimSuffix(record.Host, "."))
		if !validReference(string(record.RecordID), 256) || host != config.ZoneName && !strings.HasSuffix(host, "."+config.ZoneName) {
			return nil, malformedProviderResponse()
		}
		if _, duplicate := seen[string(record.RecordID)]; duplicate {
			return nil, failure(CodeRecordMismatch, false)
		}
		seen[string(record.RecordID)] = struct{}{}
		recordType := strings.ToUpper(record.Type)
		value := record.Value
		if recordType == "TXT" {
			value = unquoteTXT(value)
		}
		result = append(result, reconcileRecord{ID: string(record.RecordID), Name: host + ".", Type: recordType,
			Value: value, TTL: record.TTL.value, Line: LineDefault, Page: 1})
	}
	return result, nil
}

func (p *namesiloProvider) listRecords(ctx context.Context, config ProviderConfig) ([]reconcileRecord, error) {
	return p.listZone(ctx, config)
}

func namesiloHost(relative string) string {
	if relative == "@" {
		return ""
	}
	return relative
}

func (p *namesiloProvider) present(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) (recordHandle, error) {
	reply, err := p.request(ctx, config, "dnsAddRecord", url.Values{"domain": {config.ZoneName}, "rrtype": {"TXT"},
		"rrhost": {namesiloHost(relative)}, "rrvalue": {exactValue},
		"rrttl": {fmt.Sprint(ProviderMinTTL(providerNamesilo))}})
	if err != nil {
		return recordHandle{}, err
	}
	if !validReference(string(reply.RecordID), 256) {
		return recordHandle{}, malformedProviderResponse()
	}
	handle := recordHandle{Provider: providerNamesilo, Zone: config.ZoneName, ZoneID: config.ZoneName,
		RecordID: string(reply.RecordID), Owner: owner}
	remote, exists, err := p.get(ctx, config, handle, exactValue)
	if err != nil {
		return recordHandle{}, err
	}
	if !exists {
		return recordHandle{}, failure(CodeUnavailable, true)
	}
	if !matchesRecord(remote, handle, exactValue) {
		return recordHandle{}, malformedProviderResponse()
	}
	return handle, nil
}

func (p *namesiloProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, _ string,
	exactValue string) ([]recordHandle, error) {
	records, err := p.listZone(ctx, config)
	if err != nil {
		return nil, err
	}
	matches := make([]recordHandle, 0, 1)
	for _, record := range records {
		if record.Name == owner && record.Type == "TXT" && record.Value == exactValue {
			matches = append(matches, recordHandle{Version: 1, Provider: providerNamesilo, Zone: config.ZoneName,
				ZoneID: config.ZoneName, RecordID: record.ID, Owner: owner})
		}
	}
	return matches, nil
}

func (p *namesiloProvider) get(ctx context.Context, config ProviderConfig, handle recordHandle,
	_ string) (remoteRecord, bool, error) {
	if handle.ZoneID != config.ZoneName {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	records, err := p.listZone(ctx, config)
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

func (p *namesiloProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	if handle.ZoneID != config.ZoneName {
		return failure(CodeRecordMismatch, false)
	}
	return p.deleteRecord(ctx, config, handle.RecordID)
}

// deleteRecord removes one record. Code 280 is success when the record is
// no longer listed (already deleted).
func (p *namesiloProvider) deleteRecord(ctx context.Context, config ProviderConfig, recordID string) error {
	_, err := p.request(ctx, config, "dnsDeleteRecord", url.Values{"domain": {config.ZoneName}, "rrid": {recordID}})
	if !isCode(err, CodeRecordMismatch) {
		return err
	}
	records, listErr := p.listZone(ctx, config)
	if listErr != nil {
		return listErr
	}
	for _, record := range records {
		if record.ID == recordID {
			return err
		}
	}
	return nil
}

func (p *namesiloProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	records, err := p.listZone(ctx, config)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	effective := providerOperation(providerNamesilo, operation)
	converted := make([]reconcileRecord, 0, 1)
	seen := make(map[string]struct{})
	for _, record := range records {
		target := operation.Action != dnscheck.ProviderCreate && record.ID == operation.RecordID
		if !target && (canonicalDNSName(record.Name, true) != operation.Name || record.Type != typeName) {
			continue
		}
		if _, known := zoneRecordType(record.Type); !known && record.Type != "TXT" {
			result := lookupRecord(nil, effective, "namesilo:record-type-changed")
			result.Conflict, result.TargetComplete, result.RecordID = true, false, operation.RecordID
			return result, nil
		}
		converted, err = appendReconcilePage(converted, []reconcileRecord{record}, seen)
		if err != nil {
			return ReconcileLookup{}, err
		}
	}
	evidence := fmt.Sprintf("namesilo:total=%d", len(records))
	result := lookupRecord(converted, effective, evidence)
	if operation.Action == dnscheck.ProviderUpdate && result.Conflict {
		// dnsUpdateRecord gives the record a new record_id: once the old ID is
		// gone, the one record now holding the target is the update's result.
		var targets []reconcileRecord
		for _, record := range converted {
			if record.ID == operation.RecordID {
				return result, nil
			}
			if recordMatchesOperation(record, effective) {
				targets = append(targets, record)
			}
		}
		if len(targets) == 1 {
			result.Conflict, result.TargetComplete, result.RecordID = false, true, targets[0].ID
		}
	}
	return result, nil
}

func (p *namesiloProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	if operation.Action == dnscheck.ProviderDelete {
		return operation.RecordID, p.deleteRecord(ctx, config, operation.RecordID)
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	written := providerOperation(providerNamesilo, operation)
	parameters := url.Values{"domain": {config.ZoneName}, "rrhost": {namesiloHost(relative)},
		"rrvalue": {reconcileProviderValue(operation.Type, operation.Value)}, "rrttl": {fmt.Sprint(written.TTL)}}
	name := "dnsAddRecord"
	if operation.Action == dnscheck.ProviderUpdate {
		name = "dnsUpdateRecord"
		parameters.Set("rrid", operation.RecordID)
	} else {
		parameters.Set("rrtype", typeName)
	}
	reply, err := p.request(ctx, config, name, parameters)
	if err != nil {
		return "", err
	}
	if !validReference(string(reply.RecordID), 256) {
		return "", malformedProviderResponse()
	}
	return string(reply.RecordID), nil
}

// domainPage lists the account's domains (listDomains page/pageSize).
func (p *namesiloProvider) domainPage(ctx context.Context, config ProviderConfig,
	size int) func(int) ([]string, int, error) {
	return func(page int) ([]string, int, error) {
		reply, err := p.request(ctx, config, "listDomains", url.Values{"page": {fmt.Sprint(page)},
			"pageSize": {fmt.Sprint(size)}})
		if err != nil {
			return nil, 0, err
		}
		type domainEntry struct {
			Domain string `json:"domain"`
		}
		entries, err := namesiloList[domainEntry](reply.Domains)
		if err != nil {
			return nil, 0, malformedProviderResponse()
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Domain)
		}
		total := (page-1)*size + len(names)
		if reply.Pager != nil {
			total = int(reply.Pager.Total.value)
		}
		return names, total, nil
	}
}
