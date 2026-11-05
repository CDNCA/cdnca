package dnsproviderremote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// ClouDNS HTTP API (read 2026-11-05): https://www.cloudns.net/wiki/article/41/
// (overview, limits 20 req/s, 600/min, 36000/h per IP), records.json
// /wiki/article/57/, add-record.json /58/, delete-record.json /59/,
// mod-record.json /60/, list-zones.json /50/, login/login.json /45/.
// Every call is a POST form with a sub-user's sub-auth-id + auth-password
// (SUB_AUTH_ID / AUTH_PASSWORD in the provider form). Refusals are HTTP 200
// {"status":"Failed","statusDescription":...}, rate limiting included
// ("Request blocked. <ip> is sending more than 20 requests per second", as
// dnscontrol providers/cloudns/api.go records it; not in the official docs).
// records.json answers a map keyed by record id, [] when empty; the zone apex
// host is "". TTLs come only from a fixed list. GeoDNS (a location per record)
// is not carrier lines: the adapter writes the default line only, and a
// record with a GeoDNS location or disabled (status 0) reads as a foreign line
// so it never counts as the platform's record.
const (
	providerClouDNS = "cloudns"

	// ClouDNSMinTTL is the lowest TTL in ClouDNS's list (article 58).
	ClouDNSMinTTL   = 60
	clouDNSPageSize = 100
)

// clouDNSTTLs is the full TTL list of add-record / mod-record.
var clouDNSTTLs = []uint32{60, 300, 900, 1800, 3600, 21600, 43200, 86400, 172800, 259200, 604800, 1209600, 2592000}

var clouDNSSubAuthIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// clouDNSAllowedTTL rounds down to the list (at least 60).
func clouDNSAllowedTTL(ttl uint32) uint32 {
	allowed := clouDNSTTLs[0]
	for _, value := range clouDNSTTLs {
		if value <= ttl {
			allowed = value
		}
	}
	return allowed
}

type clouDNSProvider struct{ adapter *Adapter }

type clouDNSRecord struct {
	ID         stringID        `json:"id"`
	Type       string          `json:"type"`
	Host       string          `json:"host"`
	Record     string          `json:"record"`
	TTL        stringID        `json:"ttl"`
	Status     json.RawMessage `json:"status"`
	GeoDNSCode string          `json:"geodns-location-code"`
}

func (record clouDNSRecord) owner(zone string) string {
	host := strings.ToLower(record.Host)
	if host == "" || host == "@" {
		return zone + "."
	}
	return ownerFromRelative(host, zone)
}

func (record clouDNSRecord) recordType() string { return strings.ToUpper(record.Type) }

// line: disabled and GeoDNS records are not the default-line answer.
func (record clouDNSRecord) line() string {
	if strings.Trim(string(record.Status), `"`) == "0" {
		return providerClouDNS + ":inactive"
	}
	if record.GeoDNSCode != "" {
		return providerClouDNS + ":geodns:" + record.GeoDNSCode
	}
	return LineDefault
}

// clouDNSHost is the host parameter for a relative name ("" at the apex).
func clouDNSHost(relative string) string {
	if relative == "@" {
		return ""
	}
	return relative
}

// request sends one form call and returns the body of a non-refused answer.
func (p *clouDNSProvider) request(ctx context.Context, config ProviderConfig, path string, form url.Values) ([]byte, error) {
	credentials := providerCredentials(config, "sub_auth_id", "auth_password")
	form.Set("sub-auth-id", credentials[0])
	form.Set("auth-password", credentials[1])
	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.adapter.http.do(ctx, http.MethodPost, p.adapter.endpoints.cloudns, path, []byte(form.Encode()), headers)
	if err != nil {
		return nil, err
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return nil, err
	}
	if response.status != http.StatusOK {
		return nil, malformedProviderResponse()
	}
	if err := clouDNSFailure(response.body); err != nil {
		return nil, err
	}
	return response.body, nil
}

// clouDNSFailure maps a {"status":"Failed"} answer; other bodies pass.
func clouDNSFailure(body []byte) error {
	var envelope struct {
		Status      json.RawMessage `json:"status"`
		Description string          `json:"statusDescription"`
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(trimmed, &envelope) != nil {
		return nil
	}
	var status string
	if json.Unmarshal(envelope.Status, &status) != nil {
		return nil
	}
	if status == "Success" {
		return nil
	}
	if status != "Failed" {
		return malformedProviderResponse()
	}
	description := envelope.Description
	switch {
	case strings.HasPrefix(description, "Invalid authentication"):
		return failure(CodeCredentialsRejected, false)
	case strings.HasPrefix(description, "Request blocked.") && strings.Contains(description, "is sending more than"):
		return &Error{Code: CodeRateLimited, RetryAfter: time.Second, Temporary: true}
	case description == "Missing domain-name":
		return failure(CodeZoneNotHosted, false)
	case description == "Invalid record-id param.":
		return failure(CodeRecordNotFound, false)
	}
	// Invalid TTL / value / type: the write was refused, not lost.
	return failure(CodeInvalidInput, false)
}

func decodeClouDNSRecords(body []byte) ([]clouDNSRecord, error) {
	if bytes.Equal(bytes.TrimSpace(body), []byte("[]")) {
		return nil, nil
	}
	var raw map[string]clouDNSRecord
	if decodeJSON(body, &raw) != nil {
		return nil, malformedProviderResponse()
	}
	records := make([]clouDNSRecord, 0, len(raw))
	for key, record := range raw {
		if record.ID == "" {
			record.ID = stringID(key)
		}
		if string(record.ID) != key || !validReference(key, 256) || record.Type == "" {
			return nil, malformedProviderResponse()
		}
		records = append(records, record)
	}
	sort.Slice(records, func(left, right int) bool { return records[left].ID < records[right].ID })
	return records, nil
}

// listZone pages records.json (host/type filters optional) until a short
// page; a page repeating a record id is refused.
func (p *clouDNSProvider) listZone(ctx context.Context, config ProviderConfig, host, recordType string) ([]clouDNSRecord, int, error) {
	records := make([]clouDNSRecord, 0, clouDNSPageSize)
	seen := make(map[string]struct{})
	for page := 1; page <= recoveryMaxPages; page++ {
		form := url.Values{"domain-name": {config.ZoneName}, "rows-per-page": {strconv.Itoa(clouDNSPageSize)},
			"page": {strconv.Itoa(page)}}
		if host != "" {
			form.Set("host", host)
		}
		if recordType != "" {
			form.Set("type", recordType)
		}
		body, err := p.request(ctx, config, "/dns/records.json", form)
		if err != nil {
			return nil, 0, err
		}
		pageRecords, err := decodeClouDNSRecords(body)
		if err != nil || len(pageRecords) > clouDNSPageSize {
			return nil, 0, malformedProviderResponse()
		}
		for _, record := range pageRecords {
			if _, duplicate := seen[string(record.ID)]; duplicate {
				return nil, 0, failure(CodeRecordMismatch, false)
			}
			seen[string(record.ID)] = struct{}{}
			records = append(records, record)
		}
		if len(pageRecords) < clouDNSPageSize {
			return records, page, nil
		}
	}
	return nil, 0, malformedProviderResponse()
}

// addRecord creates a record; the id comes from "data" when ClouDNS gives
// one (the docs show no success body), "" otherwise.
func (p *clouDNSProvider) addRecord(ctx context.Context, config ProviderConfig, host, recordType, value string,
	ttl uint32) (string, error) {
	body, err := p.request(ctx, config, "/dns/add-record.json", url.Values{
		"domain-name": {config.ZoneName}, "record-type": {recordType}, "host": {host}, "record": {value},
		"ttl": {strconv.FormatUint(uint64(ttl), 10)},
	})
	if err != nil {
		return "", err
	}
	var created struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if decodeJSON(body, &created) != nil || created.Status != "Success" {
		return "", malformedProviderResponse()
	}
	var data struct {
		ID stringID `json:"id"`
	}
	if len(created.Data) > 0 && json.Unmarshal(created.Data, &data) == nil && validReference(string(data.ID), 256) {
		return string(data.ID), nil
	}
	return "", nil
}

// deleteRecord removes one record; an unknown record id is already gone.
func (p *clouDNSProvider) deleteRecord(ctx context.Context, config ProviderConfig, recordID string) error {
	_, err := p.request(ctx, config, "/dns/delete-record.json", url.Values{
		"domain-name": {config.ZoneName}, "record-id": {recordID},
	})
	if isCode(err, CodeRecordNotFound) {
		return nil
	}
	return err
}
func clouDNSReconcileRecord(record clouDNSRecord, zone string) reconcileRecord {
	recordType := record.recordType()
	switch recordType {
	case "A", "AAAA", "CNAME", "TXT":
	default:
		recordType = "OTHER"
	}
	ttl, _ := strconv.ParseUint(string(record.TTL), 10, 32)
	return reconcileRecord{
		ID: string(record.ID), Name: record.owner(zone), Type: recordType, Value: record.Record,
		TTL: uint32(ttl), Line: record.line(),
	}
}

func (p *clouDNSProvider) present(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) (recordHandle, error) {
	recordID, err := p.addRecord(ctx, config, clouDNSHost(relative), "TXT", exactValue, ClouDNSMinTTL)
	if err != nil {
		return recordHandle{}, err
	}
	// Read back what was written (and find the id when add-record gave none).
	matches, err := p.lookupTXT(ctx, config, owner, relative, exactValue)
	if err != nil {
		return recordHandle{}, err
	}
	if len(matches) != 1 || recordID != "" && matches[0].RecordID != recordID {
		return recordHandle{}, malformedProviderResponse()
	}
	return matches[0], nil
}

func (p *clouDNSProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) ([]recordHandle, error) {
	records, _, err := p.listZone(ctx, config, clouDNSHost(relative), "TXT")
	if err != nil {
		return nil, err
	}
	matches := make([]recordHandle, 0, 1)
	for _, record := range records {
		if record.owner(config.ZoneName) != owner || record.recordType() != "TXT" || unquoteTXT(record.Record) != exactValue {
			continue
		}
		matches = append(matches, recordHandle{
			Version: 1, Provider: providerClouDNS, Zone: config.ZoneName, ZoneID: config.ZoneName,
			RecordID: string(record.ID), Owner: owner,
		})
	}
	return matches, nil
}

// get lists the owner's TXT records (records.json has no id filter).
func (p *clouDNSProvider) get(ctx context.Context, config ProviderConfig, handle recordHandle, _ string) (remoteRecord, bool, error) {
	if handle.ZoneID != config.ZoneName {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	_, relative, err := ownerAndRelative(handle.Owner, config.ZoneName)
	if err != nil {
		return remoteRecord{}, false, err
	}
	records, _, err := p.listZone(ctx, config, clouDNSHost(relative), "TXT")
	if err != nil {
		return remoteRecord{}, false, err
	}
	for _, record := range records {
		if string(record.ID) == handle.RecordID {
			return remoteRecord{Owner: record.owner(config.ZoneName), Type: record.recordType(),
				Value: unquoteTXT(record.Record)}, true, nil
		}
	}
	return remoteRecord{}, false, nil
}

func (p *clouDNSProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	if handle.ZoneID != config.ZoneName {
		return failure(CodeRecordMismatch, false)
	}
	return p.deleteRecord(ctx, config, handle.RecordID)
}

// listRecords lists one owner (relative) or the whole zone ("").
func (p *clouDNSProvider) listRecords(ctx context.Context, config ProviderConfig, relative string) ([]reconcileRecord, error) {
	host := ""
	if relative != "" {
		host = clouDNSHost(relative)
	}
	records, _, err := p.listZone(ctx, config, host, "")
	if err != nil {
		return nil, err
	}
	converted := make([]reconcileRecord, 0, len(records))
	for _, record := range records {
		if relative == "@" && record.Host != "" && record.Host != "@" {
			continue
		}
		converted = append(converted, clouDNSReconcileRecord(record, config.ZoneName))
	}
	return converted, nil
}

// reconcileLookup: a create lists the owner and type; an update or delete
// lists the whole zone, so a record whose host or type changed is still
// found by its id (and reads as a conflict rather than as absent).
func (p *clouDNSProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	host, recordType := "", ""
	if operation.Action == dnscheck.ProviderCreate && relative != "@" {
		host, recordType = clouDNSHost(relative), typeName
	}
	records, pages, err := p.listZone(ctx, config, host, recordType)
	if err != nil {
		return ReconcileLookup{}, err
	}
	effective := providerOperation(providerClouDNS, operation)
	converted := make([]reconcileRecord, 0, len(records))
	seen := make(map[string]struct{})
	for _, record := range records {
		target := operation.Action != dnscheck.ProviderCreate && string(record.ID) == operation.RecordID
		if !target && (record.owner(config.ZoneName) != operation.Name || record.recordType() != typeName) {
			continue
		}
		candidate := clouDNSReconcileRecord(record, config.ZoneName)
		if candidate.Type == "OTHER" {
			result := lookupRecord(nil, effective, "cloudns:record-type-changed")
			result.Conflict, result.TargetComplete, result.RecordID = true, false, operation.RecordID
			return result, nil
		}
		converted, err = appendReconcilePage(converted, []reconcileRecord{candidate}, seen)
		if err != nil {
			return ReconcileLookup{}, err
		}
	}
	return lookupRecord(converted, effective,
		fmt.Sprintf("cloudns:pages=%d:total=%d:size=%d:host=%t", pages, len(records), clouDNSPageSize, host != "")), nil
}

// reconcileMutate: mod-record cannot change a record's type (article 60);
// reconcile updates keep the type. A create returns "" when add-record gave
// no id: the post-mutation lookup supplies it.
func (p *clouDNSProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	if operation.Action == dnscheck.ProviderDelete {
		return operation.RecordID, p.deleteRecord(ctx, config, operation.RecordID)
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	written := providerOperation(providerClouDNS, operation)
	value := reconcileProviderValue(operation.Type, operation.Value)
	if operation.Action == dnscheck.ProviderCreate {
		return p.addRecord(ctx, config, clouDNSHost(relative), typeName, value, written.TTL)
	}
	_, err = p.request(ctx, config, "/dns/mod-record.json", url.Values{
		"domain-name": {config.ZoneName}, "record-id": {operation.RecordID}, "host": {clouDNSHost(relative)},
		"record": {value}, "ttl": {strconv.FormatUint(uint64(written.TTL), 10)},
	})
	if err != nil {
		return "", err
	}
	return operation.RecordID, nil
}

// zoneNames lists one page of the account's zones (list-zones.json).
func (p *clouDNSProvider) zoneNames(ctx context.Context, config ProviderConfig, page, pageSize int) ([]string, error) {
	body, err := p.request(ctx, config, "/dns/list-zones.json", url.Values{
		"page": {strconv.Itoa(page)}, "rows-per-page": {strconv.Itoa(pageSize)},
	})
	if err != nil {
		return nil, err
	}
	var zones []struct {
		Name string `json:"name"`
	}
	if decodeJSON(body, &zones) != nil {
		return nil, malformedProviderResponse()
	}
	names := make([]string, 0, len(zones))
	for _, zone := range zones {
		names = append(names, zone.Name)
	}
	return names, nil
}
