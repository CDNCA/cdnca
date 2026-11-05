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

// JD Cloud DNS (云解析) OpenAPI v2, service domainservice (read 2026-11-05):
// https://docs.jdcloud.com/cn/jd-cloud-dns/api/overview, describedomains,
// describeresourcerecord, createresourcerecord, modifyresourcerecord,
// deleteresourcerecord, describeviewtree, diffv1v2_external (v2 replaces the
// v1 clouddnsservice service), common error codes
// /cn/common-declaration/api/error-codes, and jdcloud-sdk-go
// services/domainservice. Requests are signed with JDCLOUD2-HMAC-SHA256
// (jdcloud_signer.go) for region cn-north-1, service domainservice.
//
// Lines: viewValue -1 默认, 1 电信, 2 联通, 3 移动, 4 境外 (the top-level
// lines of 解析线路 /cn/jd-cloud-dns/parsed-route; the IDs are not in the
// official docs: they come from the open-source dnsmgr
// app/lib/DnsHelper.php line_name and match describeViewTree's basic tree).
// The free plan has the 10 domestic lines only: a refused overseas write is
// CodeLineNotInPlan. Lowest TTL: free 120, enterprise 60, premium 1
// (price-overview); the adapter writes at least 120 (any plan accepts it).
const (
	providerJDCloud = "jdcloud"

	JDCloudMinTTL      = 120
	jdCloudRegion      = "cn-north-1"
	jdCloudService     = "domainservice"
	jdCloudPageSize    = recoveryPageSize
	jdCloudDefaultView = -1
)

type jdCloudProvider struct{ adapter *Adapter }

type jdCloudRecord struct {
	ID              stringID `json:"id"`
	HostRecord      string   `json:"hostRecord"`
	HostValue       string   `json:"hostValue"`
	TTL             uint32   `json:"ttl"`
	Type            string   `json:"type"`
	ViewValue       []int64  `json:"viewValue"`
	ResolvingStatus string   `json:"resolvingStatus"`
}

func (record jdCloudRecord) owner(zone string) string {
	host := strings.ToLower(record.HostRecord)
	if host == "" || host == "@" {
		return zone + "."
	}
	return ownerFromRelative(host, zone)
}

func (record jdCloudRecord) recordType() string { return strings.ToUpper(record.Type) }

// line: the last view ID is the record's line; a paused record (状态 4) is
// not the line's answer.
func (record jdCloudRecord) line() string {
	if record.ResolvingStatus == "4" {
		return providerJDCloud + ":paused"
	}
	view := int64(jdCloudDefaultView)
	if len(record.ViewValue) > 0 {
		view = record.ViewValue[len(record.ViewValue)-1]
	}
	return unifiedLine(providerJDCloud, strconv.FormatInt(view, 10))
}

func jdCloudView(line string) (int, error) {
	code, ok := providerLineCode(providerJDCloud, line)
	if !ok {
		return 0, failure(CodeUnsupported, false)
	}
	return strconv.Atoi(code)
}

type jdCloudEnvelope struct {
	RequestID string `json:"requestId"`
	Error     *struct {
		Code   int    `json:"code"`
		Status string `json:"status"`
	} `json:"error"`
	Result json.RawMessage `json:"result"`
}

// request signs and sends one call; path is below /v2/regions/cn-north-1.
func (p *jdCloudProvider) request(ctx context.Context, config ProviderConfig, method, path string, query url.Values,
	payload any) (json.RawMessage, error) {
	var body []byte
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, malformedProviderResponse()
		}
		body = encoded
	}
	fullPath := "/v2/regions/" + jdCloudRegion + path
	credentials := providerCredentials(config, "access_key_id", "access_key_secret")
	at := p.adapter.now()
	signed := map[string]string{
		"content-type": "application/json", "host": p.adapter.endpoints.jdcloud.host,
		"x-jdcloud-date": at.UTC().Format(jdCloudTimeLayout), "x-jdcloud-nonce": p.adapter.nonce(),
	}
	headers := make(http.Header)
	for name, value := range signed {
		if name != "host" {
			headers.Set(name, value)
		}
	}
	headers.Set("x-jdcloud-algorithm", jdCloudAlgorithm)
	headers.Set("Authorization", JDCloudSignature(credentials[0], credentials[1], jdCloudRegion, jdCloudService,
		method, fullPath, query, signed, body, at))
	pathAndQuery := fullPath
	if encoded := jdCloudCanonicalQuery(query); encoded != "" {
		pathAndQuery += "?" + encoded
	}
	response, err := p.adapter.http.do(ctx, method, p.adapter.endpoints.jdcloud, pathAndQuery, body, headers)
	if err != nil {
		return nil, err
	}
	var envelope jdCloudEnvelope
	decoded := decodeJSON(response.body, &envelope) == nil
	code := response.status
	if decoded && envelope.Error != nil && envelope.Error.Code != 0 {
		code = envelope.Error.Code
	}
	switch {
	case code == http.StatusNotFound:
		return nil, failure(CodeRecordNotFound, false)
	case code == http.StatusBadRequest || code == http.StatusConflict:
		return nil, failure(CodeInvalidInput, false)
	}
	response.status = code
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return nil, err
	}
	if response.status != http.StatusOK || !decoded {
		return nil, malformedProviderResponse()
	}
	return envelope.Result, nil
}

type jdCloudPage struct {
	TotalCount *int `json:"totalCount"`
	TotalPage  *int `json:"totalPage"`
}

// jdCloudPageCount checks a page against the reported totals.
func jdCloudPageCount(page jdCloudPage, pageNumber, pageSize, count int) (int, error) {
	if page.TotalCount == nil || *page.TotalCount < 0 || *page.TotalCount > recoveryMaxItems || pageSize < 1 || pageNumber < 1 {
		return 0, malformedProviderResponse()
	}
	totalPages := max(1, (*page.TotalCount+pageSize-1)/pageSize)
	reported := totalPages
	if page.TotalPage != nil {
		reported = max(1, *page.TotalPage)
	}
	expected := min(pageSize, *page.TotalCount-(pageNumber-1)*pageSize)
	if pageNumber > totalPages || reported != totalPages || count != max(0, expected) {
		return 0, malformedProviderResponse()
	}
	return totalPages, nil
}

// domainID finds the zone among the account's domains (describeDomains,
// domainName is a %keyword% match: compared exactly here).
func (p *jdCloudProvider) domainID(ctx context.Context, config ProviderConfig) (string, error) {
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		domains, totalPages, err := p.domains(ctx, config, pageNumber, jdCloudPageSize, config.ZoneName)
		if err != nil {
			return "", err
		}
		for _, domain := range domains {
			if canonicalDNSName(domain.DomainName, false) == config.ZoneName && validReference(string(domain.ID), 64) {
				return string(domain.ID), nil
			}
		}
		if pageNumber >= totalPages {
			return "", failure(CodeZoneNotHosted, false)
		}
	}
	return "", malformedProviderResponse()
}

type jdCloudDomain struct {
	ID         stringID `json:"id"`
	DomainName string   `json:"domainName"`
}

func (p *jdCloudProvider) domains(ctx context.Context, config ProviderConfig, pageNumber, pageSize int,
	keyword string) ([]jdCloudDomain, int, error) {
	query := url.Values{"pageNumber": {strconv.Itoa(pageNumber)}, "pageSize": {strconv.Itoa(pageSize)}}
	if keyword != "" {
		query.Set("domainName", keyword)
	}
	result, err := p.request(ctx, config, http.MethodGet, "/domain", query, nil)
	if err != nil {
		return nil, 0, err
	}
	var page struct {
		jdCloudPage
		DataList []jdCloudDomain `json:"dataList"`
	}
	if decodeJSON(result, &page) != nil {
		return nil, 0, malformedProviderResponse()
	}
	totalPages, err := jdCloudPageCount(page.jdCloudPage, pageNumber, pageSize, len(page.DataList))
	if err != nil {
		return nil, 0, err
	}
	return page.DataList, totalPages, nil
}

// zoneNames lists one page of the account's domains.
func (p *jdCloudProvider) zoneNames(ctx context.Context, config ProviderConfig, page, pageSize int) ([]string, error) {
	domains, _, err := p.domains(ctx, config, page, pageSize, "")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(domains))
	for _, domain := range domains {
		names = append(names, domain.DomainName)
	}
	return names, nil
}

// listZone pages describeResourceRecord; search is a %keyword% host match
// ("" lists the whole zone).
func (p *jdCloudProvider) listZone(ctx context.Context, config ProviderConfig, domainID, search string) ([]jdCloudRecord, int, error) {
	records := make([]jdCloudRecord, 0, jdCloudPageSize)
	seen := make(map[string]struct{})
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		query := url.Values{"pageNumber": {strconv.Itoa(pageNumber)}, "pageSize": {strconv.Itoa(jdCloudPageSize)}}
		if search != "" {
			query.Set("search", search)
		}
		result, err := p.request(ctx, config, http.MethodGet, "/domain/"+domainID+"/ResourceRecord", query, nil)
		if err != nil {
			return nil, 0, err
		}
		var page struct {
			jdCloudPage
			DataList []jdCloudRecord `json:"dataList"`
		}
		if decodeJSON(result, &page) != nil {
			return nil, 0, malformedProviderResponse()
		}
		totalPages, err := jdCloudPageCount(page.jdCloudPage, pageNumber, jdCloudPageSize, len(page.DataList))
		if err != nil {
			return nil, 0, err
		}
		for _, record := range page.DataList {
			if !validReference(string(record.ID), 256) || record.Type == "" {
				return nil, 0, malformedProviderResponse()
			}
			if _, duplicate := seen[string(record.ID)]; duplicate {
				return nil, 0, failure(CodeRecordMismatch, false)
			}
			seen[string(record.ID)] = struct{}{}
			records = append(records, record)
		}
		if pageNumber == totalPages {
			return records, totalPages, nil
		}
	}
	return nil, 0, malformedProviderResponse()
}
func jdCloudReconcileRecord(record jdCloudRecord, zone string) reconcileRecord {
	recordType := record.recordType()
	switch recordType {
	case "A", "AAAA", "CNAME", "TXT":
	default:
		recordType = "OTHER"
	}
	return reconcileRecord{ID: string(record.ID), Name: record.owner(zone), Type: recordType, Value: record.HostValue,
		TTL: record.TTL, Line: record.line()}
}

func jdCloudSearch(relative string) string {
	if relative == "@" {
		return ""
	}
	return relative
}

// createRecord adds one record (createResourceRecord) and returns its id.
func (p *jdCloudProvider) createRecord(ctx context.Context, config ProviderConfig, domainID, host, recordType, value string,
	ttl uint32, view int) (string, error) {
	result, err := p.request(ctx, config, http.MethodPost, "/domain/"+domainID+"/ResourceRecord", nil, map[string]any{
		"req": map[string]any{"hostRecord": host, "hostValue": value, "ttl": ttl, "type": recordType, "viewValue": view},
	})
	if err != nil {
		return "", err
	}
	var created struct {
		DataList struct {
			ID stringID `json:"id"`
		} `json:"dataList"`
	}
	if decodeJSON(result, &created) != nil || !validReference(string(created.DataList.ID), 256) {
		return "", malformedProviderResponse()
	}
	return string(created.DataList.ID), nil
}

// deleteRecord removes one record; 404 is already gone.
func (p *jdCloudProvider) deleteRecord(ctx context.Context, config ProviderConfig, domainID, recordID string) error {
	_, err := p.request(ctx, config, http.MethodDelete, "/domain/"+domainID+"/ResourceRecord/"+recordID, nil, nil)
	if isCode(err, CodeRecordNotFound) {
		return nil
	}
	return err
}

// jdCloudLineRefusal: a refused write on a non-default line is the plan
// lacking the line (the free plan has no 境外).
func jdCloudLineRefusal(err error, line string) error {
	if isCode(err, CodeInvalidInput) && !defaultReconcileLine(line) {
		return failure(CodeLineNotInPlan, false)
	}
	return err
}

func (p *jdCloudProvider) present(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) (recordHandle, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return recordHandle{}, err
	}
	recordID, err := p.createRecord(ctx, config, domainID, relative, "TXT", exactValue, JDCloudMinTTL, jdCloudDefaultView)
	if err != nil {
		return recordHandle{}, err
	}
	handle := recordHandle{Provider: providerJDCloud, Zone: config.ZoneName, ZoneID: domainID, RecordID: recordID, Owner: owner}
	remote, exists, err := p.get(ctx, config, handle, exactValue)
	if err != nil {
		return recordHandle{}, err
	}
	if !exists || !matchesRecord(remote, handle, exactValue) {
		return recordHandle{}, malformedProviderResponse()
	}
	return handle, nil
}

func (p *jdCloudProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) ([]recordHandle, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return nil, err
	}
	records, _, err := p.listZone(ctx, config, domainID, jdCloudSearch(relative))
	if err != nil {
		return nil, err
	}
	matches := make([]recordHandle, 0, 1)
	for _, record := range records {
		if record.owner(config.ZoneName) == owner && record.recordType() == "TXT" && unquoteTXT(record.HostValue) == exactValue {
			matches = append(matches, recordHandle{Version: 1, Provider: providerJDCloud, Zone: config.ZoneName,
				ZoneID: domainID, RecordID: string(record.ID), Owner: owner})
		}
	}
	return matches, nil
}

// get lists the owner's records (no single-record read in v2).
func (p *jdCloudProvider) get(ctx context.Context, config ProviderConfig, handle recordHandle, _ string) (remoteRecord, bool, error) {
	_, relative, err := ownerAndRelative(handle.Owner, config.ZoneName)
	if err != nil {
		return remoteRecord{}, false, err
	}
	records, _, err := p.listZone(ctx, config, handle.ZoneID, jdCloudSearch(relative))
	if err != nil {
		return remoteRecord{}, false, err
	}
	for _, record := range records {
		if string(record.ID) == handle.RecordID {
			return remoteRecord{Owner: record.owner(config.ZoneName), Type: record.recordType(),
				Value: unquoteTXT(record.HostValue)}, true, nil
		}
	}
	return remoteRecord{}, false, nil
}

func (p *jdCloudProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	return p.deleteRecord(ctx, config, handle.ZoneID, handle.RecordID)
}

func (p *jdCloudProvider) listRecords(ctx context.Context, config ProviderConfig, relative string) ([]reconcileRecord, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return nil, err
	}
	records, _, err := p.listZone(ctx, config, domainID, jdCloudSearch(relative))
	if err != nil {
		return nil, err
	}
	converted := make([]reconcileRecord, 0, len(records))
	for _, record := range records {
		converted = append(converted, jdCloudReconcileRecord(record, config.ZoneName))
	}
	return converted, nil
}

// reconcileLookup: a create searches the owner's host; an update or delete
// lists the whole zone so a record whose host or type changed is still found
// by its id. A create on one line ignores other lines' records (independent
// record sets) but not paused records of the owner.
func (p *jdCloudProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return ReconcileLookup{}, err
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	search := ""
	if operation.Action == dnscheck.ProviderCreate {
		search = jdCloudSearch(relative)
	}
	records, pages, err := p.listZone(ctx, config, domainID, search)
	if err != nil {
		return ReconcileLookup{}, err
	}
	effective := providerOperation(providerJDCloud, operation)
	converted := make([]reconcileRecord, 0, len(records))
	seen := make(map[string]struct{})
	for _, record := range records {
		target := operation.Action != dnscheck.ProviderCreate && string(record.ID) == operation.RecordID
		if !target && (record.owner(config.ZoneName) != operation.Name || record.recordType() != typeName) {
			continue
		}
		candidate := jdCloudReconcileRecord(record, config.ZoneName)
		if candidate.Type == "OTHER" {
			result := lookupRecord(nil, effective, "jdcloud:record-type-changed")
			result.Conflict, result.TargetComplete, result.RecordID = true, false, operation.RecordID
			return result, nil
		}
		if operation.Action == dnscheck.ProviderCreate && candidate.Line != providerJDCloud+":paused" &&
			!sameLine(candidate.Line, operation.Line) {
			continue
		}
		converted, err = appendReconcilePage(converted, []reconcileRecord{candidate}, seen)
		if err != nil {
			return ReconcileLookup{}, err
		}
	}
	return lookupRecord(converted, effective,
		fmt.Sprintf("jdcloud:domain=%s:pages=%d:total=%d:search=%t", domainID, pages, len(records), search != "")), nil
}

func (p *jdCloudProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return "", err
	}
	if operation.Action == dnscheck.ProviderDelete {
		return operation.RecordID, p.deleteRecord(ctx, config, domainID, operation.RecordID)
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	view, err := jdCloudView(operation.Line)
	if err != nil {
		return "", err
	}
	written := providerOperation(providerJDCloud, operation)
	value := reconcileProviderValue(operation.Type, operation.Value)
	if operation.Action == dnscheck.ProviderCreate {
		recordID, err := p.createRecord(ctx, config, domainID, relative, typeName, value, written.TTL, view)
		return recordID, jdCloudLineRefusal(err, operation.Line)
	}
	_, err = p.request(ctx, config, http.MethodPut, "/domain/"+domainID+"/ResourceRecord/"+operation.RecordID, nil,
		map[string]any{"req": map[string]any{"domainName": config.ZoneName, "hostRecord": relative, "hostValue": value,
			"ttl": written.TTL, "type": typeName, "viewValue": view}})
	if err != nil {
		return "", jdCloudLineRefusal(err, operation.Line)
	}
	return operation.RecordID, nil
}
