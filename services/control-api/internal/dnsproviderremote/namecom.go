package dnsproviderremote

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// name.com Core API (OpenAPI namecom.api.yaml, info.version 1.36.0; the v4
// API at /v4 is deprecated). Basic authentication with the account username
// and an API token; production api.name.com, sandbox api.dev.name.com
// (username suffixed "-test"). The record list has no host/type filter, so
// every lookup pages the whole zone (perPage <= 1000) and filters here.
// Records carry no line field: only the default line exists.
const (
	providerNameCom = "namecom"

	// NameComMinTTL is the lowest TTL name.com accepts ("name.com allows a
	// minimum TTL of 300, or 5 minutes").
	NameComMinTTL     = 300
	nameComPageSize   = recoveryPageSize
	nameComRecordPath = "/core/v1/domains/"
)

// ProviderMinTTL is the lowest record TTL the adapter can write for the
// provider type; requested TTLs below it are written as this value (see
// EffectiveTTL). Only name.com has a floor the platform's TTLs can fall
// under (attack escalation level D asks for 60 seconds).
func ProviderMinTTL(providerType string) uint32 {
	if providerType == providerNameCom {
		return NameComMinTTL
	}
	return 1
}

// EffectiveTTL is the TTL a record written with the requested TTL carries
// at the provider, and whether the provider floor raised it (ttl_clamped).
func EffectiveTTL(providerType string, requested uint32) (uint32, bool) {
	if minimum := ProviderMinTTL(providerType); requested > 0 && requested < minimum {
		return minimum, true
	}
	return requested, false
}

type nameComProvider struct{ adapter *Adapter }

type nameComRecord struct {
	ID         stringID `json:"id"`
	DomainName string   `json:"domainName"`
	Host       *string  `json:"host"`
	FQDN       string   `json:"fqdn"`
	Type       *string  `json:"type"`
	Answer     string   `json:"answer"`
	TTL        uint32   `json:"ttl"`
	Priority   uint32   `json:"priority"`
}

type nameComRecordPage struct {
	Records    []nameComRecord `json:"records"`
	TotalCount *int            `json:"totalCount"`
	From       *int            `json:"from"`
	To         *int            `json:"to"`
	NextPage   *int            `json:"nextPage"`
	LastPage   *int            `json:"lastPage"`
}

// owner is the record's canonical owner name; fqdn is authoritative when
// present (it always ends in "."), else host relative to the zone.
func (record nameComRecord) owner(zone string) string {
	if record.FQDN != "" {
		return canonicalDNSName(record.FQDN, true)
	}
	host := ""
	if record.Host != nil {
		host = *record.Host
	}
	if host == "" {
		host = "@"
	}
	return ownerFromRelative(host, zone)
}

func (record nameComRecord) recordType() string {
	if record.Type == nil {
		return ""
	}
	return strings.ToUpper(*record.Type)
}

func (record nameComRecord) inZone(zone string) bool {
	return record.DomainName == "" || canonicalDNSName(record.DomainName, false) == zone
}

func (p *nameComProvider) recordsPath(config ProviderConfig) string {
	return nameComRecordPath + url.PathEscape(config.ZoneName) + "/records"
}

func (p *nameComProvider) recordPath(config ProviderConfig, recordID string) string {
	return p.recordsPath(config) + "/" + url.PathEscape(recordID)
}

// listZone pages through every record of the zone, checking that pages are
// contiguous (from/to/totalCount/nextPage) and record IDs unique.
func (p *nameComProvider) listZone(ctx context.Context, config ProviderConfig) ([]nameComRecord, int, error) {
	records := make([]nameComRecord, 0, nameComPageSize)
	seen := make(map[string]struct{})
	total := -1
	for page := 1; page <= recoveryMaxPages; page++ {
		query := url.Values{"perPage": {strconv.Itoa(nameComPageSize)}, "page": {strconv.Itoa(page)}}
		response, err := p.request(ctx, config, http.MethodGet, p.recordsPath(config)+"?"+query.Encode(), nil)
		if err != nil {
			return nil, 0, err
		}
		if response.status != http.StatusOK {
			return nil, 0, malformedProviderResponse()
		}
		var body nameComRecordPage
		if decodeJSON(response.body, &body) != nil || body.Records == nil || body.TotalCount == nil ||
			*body.TotalCount < 0 || *body.TotalCount > recoveryMaxItems || total >= 0 && total != *body.TotalCount {
			return nil, 0, malformedProviderResponse()
		}
		total = *body.TotalCount
		totalPages, pageErr := validateNumberedRecoveryPage(total, page, nameComPageSize, len(body.Records))
		if pageErr != nil {
			return nil, 0, malformedProviderResponse()
		}
		if len(body.Records) > 0 && (body.From == nil || body.To == nil ||
			*body.From != (page-1)*nameComPageSize+1 || *body.To != *body.From+len(body.Records)-1) {
			return nil, 0, malformedProviderResponse()
		}
		last := page == totalPages
		if last != (body.NextPage == nil) || !last && *body.NextPage != page+1 {
			return nil, 0, malformedProviderResponse()
		}
		for _, record := range body.Records {
			id := string(record.ID)
			if !validReference(id, 256) || !record.inZone(config.ZoneName) || record.owner(config.ZoneName) == "" {
				return nil, 0, malformedProviderResponse()
			}
			if _, duplicate := seen[id]; duplicate {
				return nil, 0, failure(CodeRecordMismatch, false)
			}
			seen[id] = struct{}{}
			records = append(records, record)
		}
		if last {
			return records, totalPages, nil
		}
	}
	return nil, 0, malformedProviderResponse()
}

// getRecord reads one record; a 404 is an absent record.
func (p *nameComProvider) getRecord(ctx context.Context, config ProviderConfig, recordID string) (nameComRecord, bool, error) {
	response, err := p.request(ctx, config, http.MethodGet, p.recordPath(config, recordID), nil)
	if err != nil {
		return nameComRecord{}, false, err
	}
	if response.status == http.StatusNotFound {
		return nameComRecord{}, false, nil
	}
	var record nameComRecord
	if response.status != http.StatusOK || decodeJSON(response.body, &record) != nil ||
		string(record.ID) != recordID || !record.inZone(config.ZoneName) || record.owner(config.ZoneName) == "" {
		return nameComRecord{}, false, malformedProviderResponse()
	}
	return record, true, nil
}

// deleteRecord removes one record; a 404 (already gone) is success.
func (p *nameComProvider) deleteRecord(ctx context.Context, config ProviderConfig, recordID string) error {
	response, err := p.request(ctx, config, http.MethodDelete, p.recordPath(config, recordID), nil)
	if err != nil {
		return err
	}
	if response.status != http.StatusNoContent && response.status != http.StatusOK &&
		response.status != http.StatusNotFound {
		return malformedProviderResponse()
	}
	return nil
}

// writeRecord creates (recordID "") or fully replaces a record and returns
// the record the provider answered with.
func (p *nameComProvider) writeRecord(ctx context.Context, config ProviderConfig, recordID, host, recordType,
	answer string, ttl uint32) (nameComRecord, error) {
	payload, err := json.Marshal(struct {
		Host   string `json:"host"`
		Type   string `json:"type"`
		Answer string `json:"answer"`
		TTL    uint32 `json:"ttl"`
	}{Host: host, Type: recordType, Answer: answer, TTL: ttl})
	if err != nil {
		return nameComRecord{}, malformedProviderResponse()
	}
	method, path := http.MethodPost, p.recordsPath(config)
	if recordID != "" {
		method, path = http.MethodPut, p.recordPath(config, recordID)
	}
	response, err := p.request(ctx, config, method, path, payload)
	if err != nil {
		return nameComRecord{}, err
	}
	var record nameComRecord
	if response.status != http.StatusOK || decodeJSON(response.body, &record) != nil ||
		!validReference(string(record.ID), 256) || recordID != "" && string(record.ID) != recordID ||
		!record.inZone(config.ZoneName) {
		return nameComRecord{}, malformedProviderResponse()
	}
	return record, nil
}

func (p *nameComProvider) present(
	ctx context.Context,
	config ProviderConfig,
	owner string,
	relative string,
	exactValue string,
) (recordHandle, error) {
	created, err := p.writeRecord(ctx, config, "", relative, "TXT", exactValue, NameComMinTTL)
	if err != nil {
		return recordHandle{}, err
	}
	handle := recordHandle{
		Provider: providerNameCom, Zone: config.ZoneName, ZoneID: config.ZoneName,
		RecordID: string(created.ID), Owner: owner,
	}
	// Read back what was written before the handle is trusted.
	remote, exists, err := p.get(ctx, config, handle, exactValue)
	if err != nil {
		return recordHandle{}, err
	}
	if !exists || !matchesRecord(remote, handle, exactValue) {
		return recordHandle{}, malformedProviderResponse()
	}
	return handle, nil
}

func (p *nameComProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, _ string,
	exactValue string) ([]recordHandle, error) {
	records, _, err := p.listZone(ctx, config)
	if err != nil {
		return nil, err
	}
	matches := make([]recordHandle, 0, 1)
	for _, record := range records {
		if record.owner(config.ZoneName) != owner || record.recordType() != "TXT" || record.Answer != exactValue {
			continue
		}
		matches = append(matches, recordHandle{
			Version: 1, Provider: providerNameCom, Zone: config.ZoneName, ZoneID: config.ZoneName,
			RecordID: string(record.ID), Owner: owner,
		})
		if len(matches) > 1 {
			return matches, nil
		}
	}
	return matches, nil
}

func (p *nameComProvider) get(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
	_ string,
) (remoteRecord, bool, error) {
	if handle.ZoneID != config.ZoneName {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	record, exists, err := p.getRecord(ctx, config, handle.RecordID)
	if err != nil || !exists {
		return remoteRecord{}, false, err
	}
	return remoteRecord{Owner: record.owner(config.ZoneName), Type: record.recordType(), Value: record.Answer}, true, nil
}

func (p *nameComProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	if handle.ZoneID != config.ZoneName {
		return failure(CodeRecordMismatch, false)
	}
	return p.deleteRecord(ctx, config, handle.RecordID)
}

func nameComReconcileRecord(record nameComRecord, zone string) reconcileRecord {
	recordType := record.recordType()
	switch recordType {
	case "A", "AAAA", "CNAME", "TXT":
	default:
		recordType = "OTHER"
	}
	return reconcileRecord{
		ID: string(record.ID), Name: record.owner(zone), Type: recordType, Value: record.Answer,
		TTL: record.TTL, Line: LineDefault,
	}
}

// listRecords returns the whole zone; ListZoneRecords filters the owner.
func (provider *nameComProvider) listRecords(ctx context.Context, config ProviderConfig) ([]reconcileRecord, error) {
	records, _, err := provider.listZone(ctx, config)
	if err != nil {
		return nil, err
	}
	converted := make([]reconcileRecord, 0, len(records))
	for _, record := range records {
		converted = append(converted, nameComReconcileRecord(record, config.ZoneName))
	}
	return converted, nil
}

// nameComOperation is the operation as name.com stores it: the TTL raised
// to the provider floor. Lookups compare records with it, so a record
// written at 300 for a requested 60 reads back as the target.
func nameComOperation(operation dnscheck.ProviderOperation) dnscheck.ProviderOperation {
	operation.TTL, _ = EffectiveTTL(providerNameCom, operation.TTL)
	if operation.Action == dnscheck.ProviderUpdate {
		operation.PreviousTTL, _ = EffectiveTTL(providerNameCom, operation.PreviousTTL)
	}
	return operation
}

func (provider *nameComProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	records, pages, err := provider.listZone(ctx, config)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	effective := nameComOperation(operation)
	converted := make([]reconcileRecord, 0, len(records))
	seen := make(map[string]struct{})
	for _, record := range records {
		target := operation.Action != dnscheck.ProviderCreate && string(record.ID) == operation.RecordID
		if !target && (record.owner(config.ZoneName) != operation.Name || record.recordType() != typeName) {
			continue
		}
		candidate := nameComReconcileRecord(record, config.ZoneName)
		if candidate.Type == "OTHER" {
			// The operation's record ID now names a record of another type.
			result := lookupRecord(nil, effective, "namecom:record-type-changed")
			result.Conflict, result.TargetComplete, result.RecordID = true, false, operation.RecordID
			return result, nil
		}
		converted, err = appendReconcilePage(converted, []reconcileRecord{candidate}, seen)
		if err != nil {
			return ReconcileLookup{}, err
		}
	}
	return lookupRecord(converted, effective,
		fmt.Sprintf("namecom:pages=%d:total=%d:size=%d", pages, len(records), nameComPageSize)), nil
}

func (provider *nameComProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	if operation.Action == dnscheck.ProviderDelete {
		return operation.RecordID, provider.deleteRecord(ctx, config, operation.RecordID)
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	if relative == "@" {
		relative = ""
	}
	typeName, _ := reconcileRecordType(operation.Type)
	recordID := ""
	if operation.Action == dnscheck.ProviderUpdate {
		recordID = operation.RecordID
	}
	written := nameComOperation(operation)
	record, err := provider.writeRecord(ctx, config, recordID, relative, typeName,
		reconcileProviderValue(operation.Type, operation.Value), written.TTL)
	if err != nil {
		return "", err
	}
	return string(record.ID), nil
}

// request sends one authenticated call. Errors map from the HTTP status
// (the body is {message, details} and is never retained); 429 carries
// X-RateLimit-Reset (Unix seconds), not Retry-After. A 404 is returned to
// the caller, which knows whether absence is expected.
func (p *nameComProvider) request(
	ctx context.Context,
	config ProviderConfig,
	method string,
	path string,
	payload []byte,
) (httpResponse, error) {
	headers := make(http.Header)
	credentials := providerCredentials(config, "username", "api_token")
	headers.Set("Authorization", "Basic "+basicAuth(credentials[0], credentials[1]))
	if len(payload) > 0 {
		headers.Set("Content-Type", "application/json")
	}
	response, err := p.adapter.http.do(ctx, method, p.adapter.endpoints.namecom, path, payload, headers)
	if err != nil {
		return httpResponse{}, err
	}
	now := p.adapter.now()
	if response.status == http.StatusTooManyRequests {
		retry := rateLimitFailure(response.header.Get("Retry-After"), now)
		if retry.RetryAfter == 0 {
			retry.RetryAfter = nameComRateLimitReset(response.header.Get("X-RateLimit-Reset"), now)
		}
		return httpResponse{}, retry
	}
	if err := classifyHTTP(response, now); err != nil {
		return httpResponse{}, err
	}
	return response, nil
}

func nameComRateLimitReset(raw string, now time.Time) time.Duration {
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	delay := time.Unix(seconds, 0).Sub(now)
	if delay <= 0 {
		return 0
	}
	return min(delay, maxRetryAfter)
}
