package dnsproviderremote

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// DNSPod.com (international) legacy API, per https://docs.dnspod.com/api-legacy/
// (info.html, domains.html, records.html) and https://docs.dnspod.com/api/
// (common-request-parameters, get-record-list, User.Detail), read 2026-11-05:
// POST https://api.dnspod.com/<Method> with the form fields login_token
// ("ID,Token"), format=json and error_on_empty; every answer carries
// status.code ("1" = success; -1 login failed, -2 "API used too frequently",
// -7/-8/85 refused, -99 not ready). Record methods take domain_id, not the
// domain name (unlike dnsapi.cn), so each call resolves it first with
// Domain.Info?domain=. Record.List pages with offset/length (at most 500 per
// call) and reports info.record_total. Lines are "default" plus country /
// continent lines; carrier lines exist only on the Enterprise plan and are
// not written: the adapter writes the default line only.
const (
	providerDNSPodCom    = "dnspod_com"
	dnsPodComDefaultLine = "default"
)

type dnsPodComProvider struct{ adapter *Adapter }

func (p *dnsPodComProvider) request(ctx context.Context, config ProviderConfig, method string,
	parameters url.Values) (dnsPodEnvelope, error) {
	credentials := providerCredentials(config, "dp_id", "dp_key")
	form := url.Values{
		"error_on_empty": {"no"}, "format": {"json"}, "lang": {"en"},
		"login_token": {credentials[0] + "," + credentials[1]},
	}
	for name, values := range parameters {
		for _, value := range values {
			form.Add(name, value)
		}
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.adapter.http.do(ctx, http.MethodPost, p.adapter.endpoints.dnspodcom, "/"+method,
		[]byte(form.Encode()), headers)
	if err != nil {
		return dnsPodEnvelope{}, err
	}
	var envelope dnsPodEnvelope
	decoded := decodeJSON(response.body, &envelope) == nil && envelope.Status != nil && envelope.Status.Code != ""
	if decoded {
		if err := dnsPodComStatusFailure(method, envelope.Status.Code, response, p.adapter); err != nil {
			return dnsPodEnvelope{}, err
		}
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return dnsPodEnvelope{}, err
	}
	if !decoded || envelope.Status.Code != "1" || response.status != http.StatusOK {
		return dnsPodEnvelope{}, malformedProviderResponse()
	}
	return envelope, nil
}

// dnsPodComStatusFailure maps the documented common and method codes.
func dnsPodComStatusFailure(method, code string, response httpResponse, adapter *Adapter) error {
	switch code {
	case "-1", "-7", "-8", "85":
		return failure(CodeCredentialsRejected, false)
	case "-2":
		return rateLimitFailure(response.header.Get("Retry-After"), adapter.now())
	case "-99":
		return failure(CodeUnavailable, true)
	}
	switch {
	// Domain.Info 6 "Invalid domain id" / 8 "no permit"; Domain.List 9
	// "Empty result"; Record.* 6 "Invalid domain id".
	case method == "Domain.Info" && (code == "6" || code == "8"), method == "Domain.List" && code == "9",
		strings.HasPrefix(method, "Record.") && code == "6":
		return failure(CodeZoneNotHosted, false)
	// Record.List 10 "Empty result"; Record.Info/Modify/Remove 8 "Invalid record id".
	case method == "Record.List" && code == "10",
		(method == "Record.Info" || method == "Record.Modify" || method == "Record.Remove") && code == "8":
		return failure(CodeRecordNotFound, false)
	}
	return nil
}

// domainID resolves the hosted domain's domain_id.
func (p *dnsPodComProvider) domainID(ctx context.Context, config ProviderConfig) (string, error) {
	envelope, err := p.request(ctx, config, "Domain.Info", url.Values{"domain": {config.ZoneName}})
	if err != nil {
		return "", err
	}
	var domain struct {
		ID       stringID `json:"id"`
		Name     string   `json:"name"`
		Punycode string   `json:"punycode"`
	}
	if decodeJSON(envelope.Domain, &domain) != nil || !validReference(string(domain.ID), 256) {
		return "", malformedProviderResponse()
	}
	name := domain.Punycode
	if name == "" {
		name = domain.Name
	}
	if canonicalDNSName(name, false) != config.ZoneName {
		return "", malformedProviderResponse()
	}
	return string(domain.ID), nil
}

// dnsPodComLine reads a record line: "default"/"Default" is the default
// line; any other (country, continent, carrier) line stays foreign.
func dnsPodComLine(line string) string {
	if strings.EqualFold(line, dnsPodComDefaultLine) || line == LineDefault {
		return LineDefault
	}
	return providerDNSPodCom + ":" + line
}

// listZone pages Record.List of the domain until info.record_total.
func (p *dnsPodComProvider) listZone(ctx context.Context, config ProviderConfig, domainID string) ([]reconcileRecord, int, error) {
	result := make([]reconcileRecord, 0, recoveryPageSize)
	seen := make(map[string]struct{})
	for page := 1; page <= recoveryMaxPages; page++ {
		envelope, err := p.request(ctx, config, "Record.List", url.Values{"domain_id": {domainID},
			"offset": {strconv.Itoa((page - 1) * recoveryPageSize)}, "length": {strconv.Itoa(recoveryPageSize)}})
		if isCode(err, CodeRecordNotFound) && page == 1 {
			return result, page, nil
		}
		if err != nil {
			return nil, 0, err
		}
		var info struct {
			RecordTotal *dnsPodNumber `json:"record_total"`
		}
		var raw []json.RawMessage
		if decodeJSON(envelope.Info, &info) != nil || info.RecordTotal == nil || decodeJSON(envelope.Records, &raw) != nil {
			return nil, 0, malformedProviderResponse()
		}
		totalPages, err := validateNumberedRecoveryPage(int(info.RecordTotal.value), page, recoveryPageSize, len(raw))
		if err != nil {
			return nil, 0, err
		}
		for _, item := range raw {
			record, err := decodeDNSPodRecord(item)
			if err != nil || record.Line == "" {
				return nil, 0, malformedProviderResponse()
			}
			if _, duplicate := seen[record.ID]; duplicate {
				return nil, 0, failure(CodeRecordMismatch, false)
			}
			seen[record.ID] = struct{}{}
			record.Name = ownerFromRelative(strings.ToLower(record.Name), config.ZoneName)
			record.Type = strings.ToUpper(record.Type)
			record.Line, record.Page = dnsPodComLine(record.Line), page
			result = append(result, record)
		}
		if page == totalPages {
			return result, page, nil
		}
	}
	return nil, 0, malformedProviderResponse()
}

// listRecords returns the whole zone; ListZoneRecords filters the owner.
func (p *dnsPodComProvider) listRecords(ctx context.Context, config ProviderConfig) ([]reconcileRecord, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return nil, err
	}
	records, _, err := p.listZone(ctx, config, domainID)
	return records, err
}

func (p *dnsPodComProvider) present(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) (recordHandle, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return recordHandle{}, err
	}
	envelope, err := p.request(ctx, config, "Record.Create", url.Values{
		"domain_id": {domainID}, "sub_domain": {relative}, "record_type": {"TXT"},
		"record_line": {dnsPodComDefaultLine}, "value": {exactValue}, "ttl": {strconv.Itoa(int(ProviderMinTTL(providerDNSPodCom)))},
	})
	if err != nil {
		return recordHandle{}, err
	}
	var created dnsPodCreatedRecord
	if decodeJSON(envelope.Record, &created) != nil || !validReference(string(created.ID), 256) {
		return recordHandle{}, malformedProviderResponse()
	}
	handle := recordHandle{Provider: providerDNSPodCom, Zone: config.ZoneName, ZoneID: domainID,
		RecordID: string(created.ID), Owner: owner}
	// Read back what was written before the handle is trusted; a record
	// not readable yet is retried later (RecoverTXT finds it).
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

func (p *dnsPodComProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, _ string,
	exactValue string) ([]recordHandle, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return nil, err
	}
	records, _, err := p.listZone(ctx, config, domainID)
	if err != nil {
		return nil, err
	}
	matches := make([]recordHandle, 0, 1)
	for _, record := range records {
		if canonicalDNSName(record.Name, true) != owner || record.Type != "TXT" || unquoteTXT(record.Value) != exactValue {
			continue
		}
		matches = append(matches, recordHandle{Version: 1, Provider: providerDNSPodCom, Zone: config.ZoneName,
			ZoneID: domainID, RecordID: record.ID, Owner: owner})
	}
	return matches, nil
}

// get reads one record by the handle's domain_id; Record.Info code 8 is an
// absent record.
func (p *dnsPodComProvider) get(ctx context.Context, config ProviderConfig, handle recordHandle,
	_ string) (remoteRecord, bool, error) {
	envelope, err := p.request(ctx, config, "Record.Info", url.Values{
		"domain_id": {handle.ZoneID}, "record_id": {handle.RecordID}})
	if isCode(err, CodeRecordNotFound) {
		return remoteRecord{}, false, nil
	}
	if err != nil {
		return remoteRecord{}, false, err
	}
	domain, err := decodeDNSPodDomain(envelope.Domain)
	if err != nil || string(domain.ID) != handle.ZoneID || canonicalDNSName(domain.Name, false) != handle.Zone {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	record, err := decodeDNSPodRecord(envelope.Record)
	if err != nil || record.ID != handle.RecordID {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	return remoteRecord{Owner: ownerFromRelative(strings.ToLower(record.Name), handle.Zone),
		Type: strings.ToUpper(record.Type), Value: unquoteTXT(record.Value)}, true, nil
}

// delete removes one record; an already removed record (code 8) is success.
func (p *dnsPodComProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	_, err := p.request(ctx, config, "Record.Remove", url.Values{
		"domain_id": {handle.ZoneID}, "record_id": {handle.RecordID}})
	if isCode(err, CodeRecordNotFound) {
		return nil
	}
	return err
}

func (p *dnsPodComProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return ReconcileLookup{}, err
	}
	records, pages, err := p.listZone(ctx, config, domainID)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	effective := providerOperation(providerDNSPodCom, operation)
	converted := make([]reconcileRecord, 0, 1)
	seen := make(map[string]struct{})
	for _, record := range records {
		target := operation.Action != dnscheck.ProviderCreate && record.ID == operation.RecordID
		if !target && (canonicalDNSName(record.Name, true) != operation.Name || record.Type != typeName ||
			operation.Action == dnscheck.ProviderCreate && !sameLine(record.Line, operation.Line)) {
			// Other lines of the owner are independent record sets.
			continue
		}
		if _, known := zoneRecordType(record.Type); !known && record.Type != "TXT" {
			// The operation's record ID now names a record of another type.
			result := lookupRecord(nil, effective, "dnspod_com:record-type-changed")
			result.Conflict, result.TargetComplete, result.RecordID = true, false, operation.RecordID
			return result, nil
		}
		converted, err = appendReconcilePage(converted, []reconcileRecord{record}, seen, record.Page)
		if err != nil {
			return ReconcileLookup{}, err
		}
	}
	return lookupRecord(converted, effective,
		fmt.Sprintf("dnspod_com:domain=%s:pages=%d:total=%d", domainID, pages, len(records))), nil
}

func (p *dnsPodComProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return "", err
	}
	if operation.Action == dnscheck.ProviderDelete {
		return operation.RecordID, p.delete(ctx, config, recordHandle{ZoneID: domainID, RecordID: operation.RecordID})
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	written := providerOperation(providerDNSPodCom, operation)
	parameters := url.Values{
		"domain_id": {domainID}, "sub_domain": {relative}, "record_type": {typeName},
		"record_line": {dnsPodComDefaultLine}, "value": {reconcileProviderValue(operation.Type, operation.Value)},
		"ttl": {strconv.FormatUint(uint64(written.TTL), 10)},
	}
	method := "Record.Create"
	if operation.Action == dnscheck.ProviderUpdate {
		method = "Record.Modify"
		parameters.Set("record_id", operation.RecordID)
	}
	envelope, err := p.request(ctx, config, method, parameters)
	if err != nil {
		return "", err
	}
	var record dnsPodCreatedRecord
	if decodeJSON(envelope.Record, &record) != nil || !validReference(string(record.ID), 256) ||
		operation.Action == dnscheck.ProviderUpdate && string(record.ID) != operation.RecordID {
		return "", malformedProviderResponse()
	}
	return string(record.ID), nil
}

// domainPage lists the account's domains (Domain.List offset/length).
func (p *dnsPodComProvider) domainPage(ctx context.Context, config ProviderConfig,
	size int) func(int) ([]string, int, error) {
	return func(page int) ([]string, int, error) {
		envelope, err := p.request(ctx, config, "Domain.List", url.Values{"type": {"all"},
			"offset": {strconv.Itoa((page - 1) * size)}, "length": {strconv.Itoa(size)}})
		if err != nil {
			return nil, 0, err
		}
		var info struct {
			DomainTotal *dnsPodNumber `json:"domain_total"`
		}
		var domains []struct {
			Name     string `json:"name"`
			Punycode string `json:"punycode"`
		}
		if decodeJSON(envelope.Info, &info) != nil || info.DomainTotal == nil || decodeJSON(envelope.Domains, &domains) != nil {
			return nil, 0, malformedProviderResponse()
		}
		names := make([]string, 0, len(domains))
		for _, domain := range domains {
			if domain.Punycode != "" {
				names = append(names, domain.Punycode)
			} else {
				names = append(names, domain.Name)
			}
		}
		return names, int(info.DomainTotal.value), nil
	}
}
