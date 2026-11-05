package dnsproviderremote

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// GoDaddy Domains API v1, per https://developer.godaddy.com/openapi/domains-v1.json
// (OpenAPI 3.1.1, read 2026-11-05) and the guides under
// https://developer.godaddy.com/docs/api-users/ (auth, rate-limits,
// troubleshoot/dns), read 2026-11-05:
//   - Authorization "sso-key KEY:SECRET" ("supported for Domains v1/v2",
//     scheduled for deprecation; v3 takes only personal access tokens).
//   - GET /v1/domains/{domain}/records[?offset&limit] lists the zone (the
//     description: "Optionally filter by record type and name");
//     GET|PUT|DELETE /v1/domains/{domain}/records/{type}/{name} read, replace
//     and delete one record set; PATCH /v1/domains/{domain}/records appends.
//     Names are relative to the domain, "@" is the apex.
//   - 401/403 credentials refused (403 also for an account not eligible for
//     the API), 404 domain not found, 409 "not eligible to have its records
//     changed", 422 invalid record, 429 ErrorLimit {retryAfterSec} with a
//     RateLimit-Reset header ("600 per ~23-minute window"); TTL >= 600.
//
// v1 records carry no ID: a record is (type, name, data). The adapter names
// a single-value set "TYPE/name" and each value of a multi-value set
// "TYPE/name/h<digest>"; update and delete rewrite the set by value, as for
// Huawei record sets. No line field: default line only.
const (
	providerGoDaddy = "godaddy"
	goDaddyPageSize = 500
)

type goDaddyProvider struct{ adapter *Adapter }

type goDaddyRecord struct {
	Data string `json:"data"`
	Name string `json:"name,omitempty"`
	TTL  uint32 `json:"ttl,omitempty"`
	Type string `json:"type,omitempty"`
}

func goDaddyValueKey(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("h%x", digest[:8])
}

// goDaddyRecordID names one value of the (type, name) set of size values.
func goDaddyRecordID(recordType, relative, value string, values int) string {
	id := recordType + "/" + relative
	if values > 1 {
		id += "/" + goDaddyValueKey(value)
	}
	return id
}

// splitGoDaddyRecordID returns the type, relative name and value key ("" =
// the single value) of a record ID. DNS names hold no "/".
func splitGoDaddyRecordID(recordID string) (string, string, string, bool) {
	parts := strings.Split(recordID, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	if len(parts) == 2 {
		return parts[0], parts[1], "", true
	}
	return parts[0], parts[1], parts[2], parts[2] != ""
}

func goDaddyOwner(relative, zone string) string {
	return ownerFromRelative(strings.ToLower(relative), zone)
}

// goDaddyValue is a record's data in canonical form (CNAME with the root
// dot, TXT unquoted).
func goDaddyValue(recordType, data string) string {
	switch recordType {
	case "CNAME":
		if canonical := canonicalDNSName(data, true); canonical != "" {
			return canonical
		}
	case "TXT":
		return unquoteTXT(data)
	}
	return data
}

func (p *goDaddyProvider) setPath(config ProviderConfig, recordType, relative string) string {
	return "/v1/domains/" + url.PathEscape(config.ZoneName) + "/records/" + url.PathEscape(recordType) + "/" +
		url.PathEscape(relative)
}

// recordSet reads the (type, name) set; [] when it does not exist. The
// spec's 404 here is "Resource not found" (set or domain): it reads as an
// empty set, and a write to a domain the account lacks fails with its own 404.
func (p *goDaddyProvider) recordSet(ctx context.Context, config ProviderConfig, recordType,
	relative string) ([]goDaddyRecord, error) {
	response, err := p.request(ctx, config, http.MethodGet, p.setPath(config, recordType, relative), nil)
	if isCode(err, CodeZoneNotHosted) {
		return []goDaddyRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var records []goDaddyRecord
	if response.status != http.StatusOK || decodeJSON(response.body, &records) != nil || records == nil ||
		len(records) > recoveryMaxItems {
		return nil, malformedProviderResponse()
	}
	for _, record := range records {
		if record.Type != "" && !strings.EqualFold(record.Type, recordType) ||
			record.Name != "" && !strings.EqualFold(record.Name, relative) {
			return nil, malformedProviderResponse()
		}
	}
	return records, nil
}

// writeSet replaces the (type, name) set, or deletes it when values is empty.
func (p *goDaddyProvider) writeSet(ctx context.Context, config ProviderConfig, recordType, relative string,
	values []goDaddyRecord) error {
	path := p.setPath(config, recordType, relative)
	if len(values) == 0 {
		response, err := p.request(ctx, config, http.MethodDelete, path, nil)
		if isCode(err, CodeZoneNotHosted) {
			// 404 "Domain not found" after a successful read: already gone.
			return nil
		}
		if err != nil {
			return err
		}
		if response.status != http.StatusNoContent && response.status != http.StatusOK {
			return malformedProviderResponse()
		}
		return nil
	}
	body := make([]goDaddyRecord, 0, len(values))
	for _, value := range values {
		body = append(body, goDaddyRecord{Data: value.Data, TTL: value.TTL})
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return malformedProviderResponse()
	}
	response, err := p.request(ctx, config, http.MethodPut, path, payload)
	if err != nil {
		return err
	}
	if response.status != http.StatusOK && response.status != http.StatusNoContent {
		return malformedProviderResponse()
	}
	return nil
}

// appendRecord adds one record to the zone (PATCH, existing kept).
func (p *goDaddyProvider) appendRecord(ctx context.Context, config ProviderConfig, record goDaddyRecord) error {
	payload, err := json.Marshal([]goDaddyRecord{record})
	if err != nil {
		return malformedProviderResponse()
	}
	response, err := p.request(ctx, config, http.MethodPatch, "/v1/domains/"+url.PathEscape(config.ZoneName)+"/records", payload)
	if err != nil {
		return err
	}
	if response.status != http.StatusOK && response.status != http.StatusNoContent {
		return malformedProviderResponse()
	}
	return nil
}

// listZone pages the zone (offset/limit). A page shorter than the limit is
// the last; a repeated record means the server ignored paging.
func (p *goDaddyProvider) listZone(ctx context.Context, config ProviderConfig) ([]reconcileRecord, int, error) {
	raw := make([]goDaddyRecord, 0, goDaddyPageSize)
	seen := make(map[string]struct{})
	pages := 0
	for page := 1; ; page++ {
		if page > recoveryMaxPages {
			return nil, 0, malformedProviderResponse()
		}
		query := url.Values{"offset": {strconv.Itoa((page - 1) * goDaddyPageSize)}, "limit": {strconv.Itoa(goDaddyPageSize)}}
		response, err := p.request(ctx, config, http.MethodGet, "/v1/domains/"+url.PathEscape(config.ZoneName)+"/records?"+
			query.Encode(), nil)
		if err != nil {
			return nil, 0, err
		}
		var records []goDaddyRecord
		if response.status != http.StatusOK || decodeJSON(response.body, &records) != nil || records == nil {
			return nil, 0, malformedProviderResponse()
		}
		pages = page
		for _, record := range records {
			if record.Type == "" || record.Name == "" {
				return nil, 0, malformedProviderResponse()
			}
			key := strings.ToUpper(record.Type) + "\x00" + strings.ToLower(record.Name) + "\x00" + record.Data
			if _, duplicate := seen[key]; duplicate {
				return nil, 0, failure(CodeRecordMismatch, false)
			}
			seen[key] = struct{}{}
			raw = append(raw, record)
		}
		if len(raw) > recoveryMaxItems {
			return nil, 0, malformedProviderResponse()
		}
		if len(records) < goDaddyPageSize {
			break
		}
	}
	sizes := make(map[string]int)
	for _, record := range raw {
		sizes[strings.ToUpper(record.Type)+"/"+strings.ToLower(record.Name)]++
	}
	result := make([]reconcileRecord, 0, len(raw))
	for _, record := range raw {
		recordType, relative := strings.ToUpper(record.Type), strings.ToLower(record.Name)
		result = append(result, reconcileRecord{
			ID:   goDaddyRecordID(recordType, relative, record.Data, sizes[recordType+"/"+relative]),
			Name: goDaddyOwner(relative, config.ZoneName), Type: recordType, Value: goDaddyValue(recordType, record.Data),
			TTL: record.TTL, Line: LineDefault, Page: 1,
		})
	}
	return result, pages, nil
}

// listRecords returns the whole zone; ListZoneRecords filters the owner.
func (p *goDaddyProvider) listRecords(ctx context.Context, config ProviderConfig) ([]reconcileRecord, error) {
	records, _, err := p.listZone(ctx, config)
	return records, err
}

func (p *goDaddyProvider) present(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) (recordHandle, error) {
	if err := p.appendRecord(ctx, config, goDaddyRecord{Data: exactValue, Name: relative, TTL: ProviderMinTTL(providerGoDaddy),
		Type: "TXT"}); err != nil {
		return recordHandle{}, err
	}
	// The TXT handle always names the value: concurrent challenges of one
	// owner share the set.
	handle := recordHandle{Provider: providerGoDaddy, Zone: config.ZoneName, ZoneID: config.ZoneName,
		RecordID: "TXT/" + relative + "/" + goDaddyValueKey(exactValue), Owner: owner}
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

func (p *goDaddyProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) ([]recordHandle, error) {
	records, err := p.recordSet(ctx, config, "TXT", relative)
	if err != nil {
		return nil, err
	}
	matches := make([]recordHandle, 0, 1)
	for _, record := range records {
		if unquoteTXT(record.Data) == exactValue {
			matches = append(matches, recordHandle{Version: 1, Provider: providerGoDaddy, Zone: config.ZoneName,
				ZoneID: config.ZoneName, RecordID: "TXT/" + relative + "/" + goDaddyValueKey(exactValue), Owner: owner})
		}
	}
	return matches, nil
}

// findValue returns the index of the set value the key names (key "" = the
// set's only value), or -1.
func goDaddyFindValue(records []goDaddyRecord, recordType, key string) int {
	if key == "" {
		if len(records) == 1 {
			return 0
		}
		return -1
	}
	for index, record := range records {
		if goDaddyValueKey(goDaddyValue(recordType, record.Data)) == key || goDaddyValueKey(record.Data) == key {
			return index
		}
	}
	return -1
}

func (p *goDaddyProvider) get(ctx context.Context, config ProviderConfig, handle recordHandle,
	_ string) (remoteRecord, bool, error) {
	recordType, relative, key, ok := splitGoDaddyRecordID(handle.RecordID)
	if !ok || handle.ZoneID != config.ZoneName {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	records, err := p.recordSet(ctx, config, recordType, relative)
	if err != nil {
		return remoteRecord{}, false, err
	}
	index := goDaddyFindValue(records, recordType, key)
	if index < 0 {
		return remoteRecord{}, false, nil
	}
	return remoteRecord{Owner: goDaddyOwner(relative, config.ZoneName), Type: recordType,
		Value: goDaddyValue(recordType, records[index].Data)}, true, nil
}

// delete removes the handle's value from its set; an absent value is success.
func (p *goDaddyProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	recordType, relative, key, ok := splitGoDaddyRecordID(handle.RecordID)
	if !ok || handle.ZoneID != config.ZoneName {
		return failure(CodeRecordMismatch, false)
	}
	records, err := p.recordSet(ctx, config, recordType, relative)
	if err != nil {
		return err
	}
	index := goDaddyFindValue(records, recordType, key)
	if index < 0 {
		return nil
	}
	return p.writeSet(ctx, config, recordType, relative, slices.Delete(records, index, index+1))
}

func (p *goDaddyProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	if operation.Action != dnscheck.ProviderCreate {
		idType, idName, _, ok := splitGoDaddyRecordID(operation.RecordID)
		if !ok || idType != typeName || idName != relative {
			// The record ID names another set: the record changed name or type.
			result := lookupRecord(nil, providerOperation(providerGoDaddy, operation), "godaddy:record-moved")
			result.Conflict, result.TargetComplete, result.RecordID = true, false, operation.RecordID
			return result, nil
		}
	}
	records, err := p.recordSet(ctx, config, typeName, relative)
	if err != nil {
		return ReconcileLookup{}, err
	}
	effective := providerOperation(providerGoDaddy, operation)
	converted := make([]reconcileRecord, 0, len(records))
	for _, record := range records {
		value := goDaddyValue(typeName, record.Data)
		id := goDaddyRecordID(typeName, relative, record.Data, len(records))
		if operation.Action != dnscheck.ProviderCreate {
			// Update and delete address one value of the set by the
			// operation's record ID, whatever form it had.
			if value != operation.Value && (operation.Action != dnscheck.ProviderUpdate || value != operation.PreviousValue) {
				continue
			}
			id = operation.RecordID
		}
		converted = append(converted, reconcileRecord{ID: id, Name: goDaddyOwner(relative, config.ZoneName),
			Type: typeName, Value: value, TTL: record.TTL, Line: LineDefault, Page: 1})
	}
	if operation.Action == dnscheck.ProviderUpdate && len(converted) > 1 {
		// The set already holds the new value next to the previous one: the
		// update still has to drop the previous value.
		converted = slices.DeleteFunc(converted, func(record reconcileRecord) bool {
			return record.Value != operation.PreviousValue
		})
	}
	normalized, err := appendReconcilePage(nil, converted, make(map[string]struct{}))
	if err != nil {
		return ReconcileLookup{}, err
	}
	return lookupRecord(normalized, effective, fmt.Sprintf("godaddy:set=%s/%s:values=%d", typeName, relative, len(records))), nil
}

func (p *goDaddyProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	written := providerOperation(providerGoDaddy, operation)
	records, err := p.recordSet(ctx, config, typeName, relative)
	if err != nil {
		return "", err
	}
	data := reconcileProviderValue(operation.Type, operation.Value)
	switch operation.Action {
	case dnscheck.ProviderCreate:
		if operation.Type == dnscheck.RecordCNAME && len(records) > 0 {
			return "", failure(CodeRecordMismatch, false)
		}
		if err := p.appendRecord(ctx, config, goDaddyRecord{Data: data, Name: relative, TTL: written.TTL, Type: typeName}); err != nil {
			return "", err
		}
		return goDaddyRecordID(typeName, relative, data, len(records)+1), nil
	case dnscheck.ProviderUpdate:
		kept := make([]goDaddyRecord, 0, len(records))
		found := false
		for _, record := range records {
			value := goDaddyValue(typeName, record.Data)
			if value == operation.PreviousValue {
				found = true
				continue
			}
			if value != operation.Value {
				kept = append(kept, record)
			}
		}
		if !found {
			return "", failure(CodeRecordMismatch, false)
		}
		kept = append(kept, goDaddyRecord{Data: data, TTL: written.TTL})
		return operation.RecordID, p.writeSet(ctx, config, typeName, relative, kept)
	default:
		kept := slices.DeleteFunc(slices.Clone(records), func(record goDaddyRecord) bool {
			return goDaddyValue(typeName, record.Data) == operation.Value
		})
		if len(kept) == len(records) {
			return operation.RecordID, nil
		}
		return operation.RecordID, p.writeSet(ctx, config, typeName, relative, kept)
	}
}

// request sends one call with "sso-key KEY:SECRET". Error bodies
// ({code, message, fields}) are never retained.
func (p *goDaddyProvider) request(ctx context.Context, config ProviderConfig, method, path string,
	payload []byte) (httpResponse, error) {
	credentials := providerCredentials(config, "api_key", "api_secret")
	headers := make(http.Header)
	headers.Set("Authorization", "sso-key "+credentials[0]+":"+credentials[1])
	if len(payload) > 0 {
		headers.Set("Content-Type", "application/json")
	}
	response, err := p.adapter.http.do(ctx, method, p.adapter.endpoints.godaddy, path, payload, headers)
	if err != nil {
		return httpResponse{}, err
	}
	now := p.adapter.now()
	switch response.status {
	case http.StatusTooManyRequests:
		retry := rateLimitFailure(response.header.Get("Retry-After"), now)
		if retry.RetryAfter == 0 {
			retry.RetryAfter = goDaddyRetryAfter(response)
		}
		return httpResponse{}, retry
	case http.StatusNotFound:
		return httpResponse{}, failure(CodeZoneNotHosted, false)
	case http.StatusConflict:
		return httpResponse{}, failure(CodeUnsupported, false)
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return httpResponse{}, failure(CodeInvalidInput, false)
	}
	if err := classifyHTTP(response, now); err != nil {
		return httpResponse{}, err
	}
	return response, nil
}

// goDaddyRetryAfter reads ErrorLimit.retryAfterSec, else RateLimit-Reset
// (seconds until the window resets).
func goDaddyRetryAfter(response httpResponse) time.Duration {
	var body struct {
		RetryAfterSec *uint64 `json:"retryAfterSec"`
	}
	seconds := uint64(0)
	if decodeJSON(response.body, &body) == nil && body.RetryAfterSec != nil {
		seconds = *body.RetryAfterSec
	} else if reset, err := strconv.ParseUint(strings.TrimSpace(response.header.Get("RateLimit-Reset")), 10, 64); err == nil {
		seconds = reset
	}
	return time.Duration(min(seconds, uint64(maxRetryAfter/time.Second))) * time.Second
}

// domainPage lists the account's domains (GET /v1/domains limit + marker).
func (p *goDaddyProvider) domainPage(ctx context.Context, config ProviderConfig,
	size int) func(int) ([]string, int, error) {
	marker := ""
	return func(page int) ([]string, int, error) {
		query := url.Values{"limit": {strconv.Itoa(size)}}
		if marker != "" {
			query.Set("marker", marker)
		}
		response, err := p.request(ctx, config, http.MethodGet, "/v1/domains?"+query.Encode(), nil)
		if err != nil {
			return nil, 0, err
		}
		var domains []struct {
			Domain string `json:"domain"`
		}
		if response.status != http.StatusOK || decodeJSON(response.body, &domains) != nil {
			return nil, 0, malformedProviderResponse()
		}
		names := make([]string, 0, len(domains))
		for _, domain := range domains {
			names = append(names, domain.Domain)
		}
		if len(names) > 0 {
			marker = names[len(names)-1]
		}
		// GoDaddy reports no total: a full page means more may follow.
		total := (page-1)*size + len(names)
		if len(names) == size {
			total += size
		}
		return names, total, nil
	}
}
