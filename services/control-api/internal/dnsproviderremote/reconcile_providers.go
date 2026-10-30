package dnsproviderremote

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

type providerReconcileRemote struct{ adapter *Adapter }

func NewReconcileRemote() ReconcileRemote {
	return &providerReconcileRemote{adapter: newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)}
}

func (remote *providerReconcileRemote) Lookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	return remote.lookup(ctx, config, operation, false)
}

func (remote *providerReconcileRemote) lookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation, hub bool) (ReconcileLookup, error) {
	if remote == nil || remote.adapter == nil {
		return ReconcileLookup{}, failure(CodeSourceUnavailable, true)
	}
	config, err := validatedReconcileConfigFor(config, operation, hub)
	if err != nil {
		return ReconcileLookup{}, err
	}
	switch config.ProviderType {
	case providerCloudflare:
		return (&cloudflareProvider{adapter: remote.adapter}).reconcileLookup(ctx, config, operation)
	case providerAliyun:
		return (&aliyunProvider{adapter: remote.adapter}).reconcileLookup(ctx, config, operation)
	case providerHuawei:
		return (&huaweiProvider{adapter: remote.adapter}).reconcileLookup(ctx, config, operation)
	case providerDNSPodCN:
		return (&dnsPodProvider{adapter: remote.adapter}).reconcileLookup(ctx, config, operation)
	case providerDNSCom:
		return (&dnsComProvider{adapter: remote.adapter}).reconcileLookup(ctx, config, operation)
	case providerDNSLA:
		return (&dnsLAProvider{adapter: remote.adapter}).reconcileLookup(ctx, config, operation)
	case providerNameCom:
		return (&nameComProvider{adapter: remote.adapter}).reconcileLookup(ctx, config, operation)
	case providerCustomHTTP, providerPlugin:
		return newRecordProvider(remote.adapter, config.ProviderType).reconcileLookup(ctx, config, operation)
	default:
		return ReconcileLookup{}, failure(CodeUnsupported, false)
	}
}

func (remote *providerReconcileRemote) Mutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	return remote.mutate(ctx, config, operation, false)
}

func (remote *providerReconcileRemote) mutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation, hub bool) (string, error) {
	if remote == nil || remote.adapter == nil {
		return "", failure(CodeSourceUnavailable, true)
	}
	config, err := validatedReconcileConfigFor(config, operation, hub)
	if err != nil {
		return "", err
	}
	switch config.ProviderType {
	case providerCloudflare:
		return (&cloudflareProvider{adapter: remote.adapter}).reconcileMutate(ctx, config, operation)
	case providerAliyun:
		return (&aliyunProvider{adapter: remote.adapter}).reconcileMutate(ctx, config, operation)
	case providerHuawei:
		return (&huaweiProvider{adapter: remote.adapter}).reconcileMutate(ctx, config, operation)
	case providerDNSPodCN:
		return (&dnsPodProvider{adapter: remote.adapter}).reconcileMutate(ctx, config, operation)
	case providerDNSCom:
		return (&dnsComProvider{adapter: remote.adapter}).reconcileMutate(ctx, config, operation)
	case providerDNSLA:
		return (&dnsLAProvider{adapter: remote.adapter}).reconcileMutate(ctx, config, operation)
	case providerNameCom:
		return (&nameComProvider{adapter: remote.adapter}).reconcileMutate(ctx, config, operation)
	case providerCustomHTTP, providerPlugin:
		return newRecordProvider(remote.adapter, config.ProviderType).reconcileMutate(ctx, config, operation)
	default:
		return "", failure(CodeUnsupported, false)
	}
}

type reconcileRecord struct {
	ID     string
	Name   string
	Type   string
	Value  string
	TTL    uint32
	Line   string
	Weight uint32
	Page   int
}

func appendReconcilePage(records, page []reconcileRecord, seen map[string]struct{}, pageNumber ...int) ([]reconcileRecord, error) {
	pageIndex := 1
	if len(pageNumber) == 1 && pageNumber[0] > 0 {
		pageIndex = pageNumber[0]
	}
	for _, record := range page {
		record, err := normalizeReconcileRecord(record)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[record.ID]; duplicate {
			return nil, failure(CodeRecordMismatch, false)
		}
		seen[record.ID] = struct{}{}
		record.Page = pageIndex
		records = append(records, record)
	}
	return records, nil
}

func normalizeReconcileRecord(record reconcileRecord) (reconcileRecord, error) {
	canonicalName := canonicalDNSName(record.Name, true)
	if record.Type == "TXT" {
		// TXT text is free-form (spaces, quotes from the provider's wire form):
		// only the outer quoting is removed (ADR 0020 §3.3, dns hub).
		record.Value = unquoteTXT(record.Value)
		if !validReference(record.ID, 256) || canonicalName == "" || !validCanonicalReconcileValue(dnscheck.RecordTXT, record.Value) ||
			record.TTL == 0 || record.TTL > 7*24*60*60 {
			return reconcileRecord{}, malformedProviderResponse()
		}
		record.Name = canonicalName
		return record, nil
	}
	if !validReference(record.ID, 256) || canonicalName == "" || record.Value == "" ||
		record.Value != strings.TrimSpace(record.Value) || record.TTL == 0 || record.TTL > 7*24*60*60 {
		return reconcileRecord{}, malformedProviderResponse()
	}
	switch record.Type {
	case "A":
		if !validCanonicalReconcileValue(dnscheck.RecordA, record.Value) {
			return reconcileRecord{}, malformedProviderResponse()
		}
	case "AAAA":
		if !validCanonicalReconcileValue(dnscheck.RecordAAAA, record.Value) {
			return reconcileRecord{}, malformedProviderResponse()
		}
	case "CNAME":
		canonicalValue := canonicalDNSName(record.Value, true)
		if canonicalValue == "" {
			return reconcileRecord{}, malformedProviderResponse()
		}
		record.Value = canonicalValue
	default:
		return reconcileRecord{}, malformedProviderResponse()
	}
	record.Name = canonicalName
	return record, nil
}

func reconcileRecordType(recordType dnscheck.RecordType) (string, bool) {
	switch recordType {
	case dnscheck.RecordA:
		return "A", true
	case dnscheck.RecordAAAA:
		return "AAAA", true
	case dnscheck.RecordCNAME:
		return "CNAME", true
	case dnscheck.RecordTXT:
		return "TXT", true
	default:
		return "", false
	}
}

// unquoteTXT removes the quoting some providers (Huawei, Cloudflare) put
// around TXT text: "a" -> a, "a" "b" -> ab.
func unquoteTXT(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	return strings.ReplaceAll(value[1:len(value)-1], `" "`, "")
}

// huaweiWireValue is the record value as Huawei stores it: TXT text quoted.
func huaweiWireValue(recordType dnscheck.RecordType, value string) string {
	if recordType == dnscheck.RecordTXT {
		return strconv.Quote(value)
	}
	return reconcileProviderValue(recordType, value)
}

func reconcileProviderValue(recordType dnscheck.RecordType, value string) string {
	if recordType == dnscheck.RecordCNAME {
		return strings.TrimSuffix(value, ".")
	}
	return value
}

func validCanonicalReconcileValue(recordType dnscheck.RecordType, value string) bool {
	switch recordType {
	case dnscheck.RecordA:
		address, err := netip.ParseAddr(value)
		return err == nil && address.Is4() && address.String() == value
	case dnscheck.RecordAAAA:
		address, err := netip.ParseAddr(value)
		return err == nil && address.Is6() && !address.Is4In6() && address.String() == value
	case dnscheck.RecordCNAME:
		return canonicalDNSName(value, true) == value
	case dnscheck.RecordTXT:
		// Read side: anything a provider may hold. HubTXTWritable is the
		// stricter write rule.
		return value != "" && len(value) <= 4096 && !containsControl(value)
	default:
		return false
	}
}

func validateProviderReconcileOperation(config ProviderConfig, operation dnscheck.ProviderOperation) error {
	_, err := validatedReconcileConfig(config, operation)
	return err
}

// validatedReconcileConfig checks the operation against the zone and returns
// the config the provider is called with (ZoneName = the hosted apex).
func validatedReconcileConfig(config ProviderConfig, operation dnscheck.ProviderOperation) (ProviderConfig, error) {
	return validatedReconcileConfigFor(config, operation, false)
}

// validatedReconcileConfigFor: hub (用户端域名解析) also writes TXT through
// every adapter; reconcile and site CNAME paths stay A/AAAA/CNAME.
func validatedReconcileConfigFor(config ProviderConfig, operation dnscheck.ProviderOperation, hub bool) (ProviderConfig, error) {
	validated, _, err := validateConfig(config, operation.Name)
	if err != nil || validated.ProviderType != config.ProviderType ||
		canonicalDNSName(config.ZoneName, false) != config.ZoneName {
		return ProviderConfig{}, failure(CodeInvalidInput, false)
	}
	capability, ok := providerCapabilityFor(validated.ProviderType)
	if hub && operation.Type == dnscheck.RecordTXT && ok && capability.DNS01TXT {
		// New text must be writable; a delete (and an update's previous
		// value) addresses whatever text the record already holds.
		if operation.Action != dnscheck.ProviderDelete && !HubTXTWritable(operation.Value) {
			return ProviderConfig{}, failure(CodeInvalidInput, false)
		}
	} else if !ok || !capability.supportsReconcileType(operation.Type) {
		return ProviderConfig{}, failure(CodeUnsupported, false)
	}
	if operation.Action != dnscheck.ProviderCreate && operation.Action != dnscheck.ProviderUpdate &&
		operation.Action != dnscheck.ProviderDelete || operation.TTL == 0 || operation.TTL > 7*24*60*60 {
		return ProviderConfig{}, failure(CodeInvalidInput, false)
	}
	if operation.Action != dnscheck.ProviderCreate && !validReference(operation.RecordID, 256) {
		return ProviderConfig{}, failure(CodeInvalidInput, false)
	}
	if !validReconcileLineWeight(operation.Line, operation.Weight) ||
		!validReconcileLineWeight(operation.PreviousLine, operation.PreviousWeight) {
		return ProviderConfig{}, failure(CodeInvalidInput, false)
	}
	if !capability.Line && (!defaultReconcileLine(operation.Line) || !defaultReconcileLine(operation.PreviousLine)) ||
		!capability.Weight && (operation.Weight != 0 || operation.PreviousWeight != 0) {
		return ProviderConfig{}, failure(CodeUnsupported, false)
	}
	// A delete only matches the record's current line, which may be a
	// provider line outside the unified enum; creates and updates must write
	// a line the adapter maps.
	if capability.Line && operation.Action != dnscheck.ProviderDelete && !writableLine(validated.ProviderType, operation.Line) {
		return ProviderConfig{}, failure(CodeUnsupported, false)
	}
	// DNS.COM opens lines by the configured plan tier.
	if validated.ProviderType == providerDNSCom && operation.Action != dnscheck.ProviderDelete &&
		!dnsComPlanAllows(validated, operation.Line) {
		return ProviderConfig{}, failure(CodeLineNotInPlan, false)
	}
	// Huawei record sets cannot change line (line_id is immutable): moving a
	// value to another line is a delete plus a create.
	if validated.ProviderType == providerHuawei && operation.Action == dnscheck.ProviderUpdate &&
		!sameLine(operation.Line, operation.PreviousLine) {
		return ProviderConfig{}, failure(CodeUnsupported, false)
	}
	if !validCanonicalReconcileValue(operation.Type, operation.Value) {
		return ProviderConfig{}, failure(CodeInvalidInput, false)
	}
	if operation.Action == dnscheck.ProviderUpdate &&
		(!validCanonicalReconcileValue(operation.Type, operation.PreviousValue) ||
			operation.PreviousTTL == 0 || operation.PreviousTTL > 7*24*60*60) {
		return ProviderConfig{}, failure(CodeInvalidInput, false)
	}
	return validated, nil
}

func (capability ProviderCapability) supportsReconcileType(recordType dnscheck.RecordType) bool {
	switch recordType {
	case dnscheck.RecordA:
		return capability.ReconcileA
	case dnscheck.RecordAAAA:
		return capability.ReconcileAAAA
	case dnscheck.RecordCNAME:
		return capability.ReconcileCNAME
	default:
		return false
	}
}

func recordMatchesOperation(record reconcileRecord, operation dnscheck.ProviderOperation) bool {
	wantType, ok := reconcileRecordType(operation.Type)
	if !ok || canonicalDNSName(record.Name, true) != operation.Name || record.Type != wantType || record.TTL != operation.TTL {
		return false
	}
	value := record.Value
	if operation.Type == dnscheck.RecordCNAME {
		value = canonicalDNSName(value, true)
	}
	return value == operation.Value && reconcileRoutingMatches(record.Line, record.Weight, operation.Line, operation.Weight)
}

func lookupRecord(records []reconcileRecord, operation dnscheck.ProviderOperation, evidence ...string) ReconcileLookup {
	result := ReconcileLookup{SnapshotDigest: reconcileLookupDigest(records, operation, evidence)}
	typeName, _ := reconcileRecordType(operation.Type)
	if operation.Action == dnscheck.ProviderCreate {
		var desired []reconcileRecord
		competing := false
		for _, record := range records {
			if record.Name != operation.Name || record.Type != typeName {
				continue
			}
			if recordMatchesOperation(record, operation) {
				desired = append(desired, record)
			} else if operation.Type == dnscheck.RecordCNAME || record.Value == operation.Value {
				// Another A/AAAA value of the owner is a sibling in the RRset;
				// a second CNAME target, or this value with other attributes, competes.
				competing = true
			}
		}
		if len(desired) > 1 {
			result.Ambiguous = true
		} else if len(desired) == 1 && !competing {
			result.TargetComplete, result.RecordID = true, desired[0].ID
		} else if competing {
			result.Conflict = true
		}
		return result
	}
	matches := make([]reconcileRecord, 0, 1)
	for _, record := range records {
		if record.ID == operation.RecordID {
			matches = append(matches, record)
		}
	}
	if len(matches) > 1 {
		result.Ambiguous = true
		return result
	}
	if len(matches) == 0 {
		if operation.Action == dnscheck.ProviderDelete {
			result.TargetComplete, result.RecordID = true, operation.RecordID
		} else {
			result.Conflict = true
		}
		return result
	}
	record := matches[0]
	result.RecordID = record.ID
	if record.Name != operation.Name || record.Type != typeName {
		result.Conflict = true
		return result
	}
	if recordMatchesOperation(record, operation) {
		if operation.Action == dnscheck.ProviderUpdate {
			result.TargetComplete = true
		} else {
			result.RecordID = ""
		}
		return result
	}
	if operation.Action == dnscheck.ProviderUpdate && record.Value == operation.PreviousValue && record.TTL == operation.PreviousTTL &&
		reconcileRoutingMatches(record.Line, record.Weight, operation.PreviousLine, operation.PreviousWeight) {
		result.RecordID = ""
		return result
	}
	result.Conflict = true
	return result
}

func reconcileLookupDigest(records []reconcileRecord, operation dnscheck.ProviderOperation, evidence []string) [sha256.Size]byte {
	canonicalRecords := append([]reconcileRecord(nil), records...)
	sort.Slice(canonicalRecords, func(left, right int) bool {
		first, second := canonicalRecords[left], canonicalRecords[right]
		if first.Page != second.Page {
			return first.Page < second.Page
		}
		if first.ID != second.ID {
			return first.ID < second.ID
		}
		if first.Name != second.Name {
			return first.Name < second.Name
		}
		if first.Type != second.Type {
			return first.Type < second.Type
		}
		if first.Value != second.Value {
			return first.Value < second.Value
		}
		if first.TTL != second.TTL {
			return first.TTL < second.TTL
		}
		if first.Line != second.Line {
			return first.Line < second.Line
		}
		return first.Weight < second.Weight
	})
	payload, err := json.Marshal(struct {
		Version   string
		Operation dnscheck.ProviderOperation
		Records   []reconcileRecord
		Evidence  []string
	}{Version: "cdnca:dns-provider-snapshot:v1", Operation: operation, Records: canonicalRecords, Evidence: evidence})
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(payload)
}

func validReconcileLineWeight(line string, weight uint32) bool {
	return weight <= 100 && len(line) <= 64 && line == strings.TrimSpace(line) && !strings.ContainsAny(line, "\r\n\x00")
}

func defaultReconcileLine(line string) bool {
	return line == "" || line == "默认" || line == "default"
}

func reconcileRoutingMatches(recordLine string, recordWeight uint32, operationLine string, operationWeight uint32) bool {
	return sameLine(recordLine, operationLine) && recordWeight == operationWeight
}

func dnsPodOperationLine(line string) string {
	if line == "" || line == "default" {
		return "默认"
	}
	return line
}

// decodeDNSPodReconcileRecord is decodeDNSPodRecord for reconcile: the line
// is part of the record identity, so it must be present.
func decodeDNSPodReconcileRecord(raw json.RawMessage) (reconcileRecord, error) {
	record, err := decodeDNSPodRecord(raw)
	if err != nil || record.Line == "" {
		return reconcileRecord{}, malformedProviderResponse()
	}
	return record, nil
}

func (provider *cloudflareProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	zoneID, err := provider.zoneID(ctx, config)
	if err != nil {
		return ReconcileLookup{}, err
	}
	if operation.Action != dnscheck.ProviderCreate {
		response, err := provider.adapter.http.do(ctx, http.MethodGet, provider.adapter.endpoints.cloudflare,
			"/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(operation.RecordID), nil,
			cloudflareHeaders(config.Credentials["api_token"]))
		if err != nil {
			return ReconcileLookup{}, err
		}
		if response.status == http.StatusNotFound {
			if err := cloudflareKnownResponseError(response, provider.adapter.now()); err != nil {
				return ReconcileLookup{}, err
			}
			return lookupRecord(nil, operation, "cloudflare:record:not-found"), nil
		}
		if err := cloudflareResponseError(response, provider.adapter.now()); err != nil {
			return ReconcileLookup{}, err
		}
		envelope, err := decodeCloudflareEnvelope(response, provider.adapter.now())
		if err != nil {
			return ReconcileLookup{}, err
		}
		var record struct {
			ID      string `json:"id"`
			ZoneID  string `json:"zone_id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Content string `json:"content"`
			TTL     uint32 `json:"ttl"`
		}
		if err := decodeJSON(envelope.Result, &record); err != nil || !cloudflareRecordInZone(record.ZoneID, zoneID) {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		records, err := appendReconcilePage(nil, []reconcileRecord{{
			ID: record.ID, Name: record.Name, Type: record.Type, Value: record.Content, TTL: record.TTL,
		}}, make(map[string]struct{}))
		if err != nil {
			return ReconcileLookup{}, err
		}
		return lookupRecord(records, operation, "cloudflare:record:"+zoneID), nil
	}
	typeName, _ := reconcileRecordType(operation.Type)
	converted := make([]reconcileRecord, 0, recoveryPageSize)
	seen := make(map[string]struct{})
	total := -1
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		query := url.Values{
			"name": {operation.Name}, "type": {typeName}, "page": {strconv.Itoa(pageNumber)},
			"per_page": {strconv.Itoa(recoveryPageSize)},
		}
		response, err := provider.adapter.http.do(ctx, http.MethodGet, provider.adapter.endpoints.cloudflare,
			"/zones/"+url.PathEscape(zoneID)+"/dns_records?"+query.Encode(), nil,
			cloudflareHeaders(config.Credentials["api_token"]))
		if err != nil {
			return ReconcileLookup{}, err
		}
		if err := cloudflareResponseError(response, provider.adapter.now()); err != nil {
			return ReconcileLookup{}, err
		}
		envelope, err := decodeCloudflareEnvelope(response, provider.adapter.now())
		if err != nil {
			return ReconcileLookup{}, err
		}
		var metadata struct {
			ResultInfo *struct {
				Page       *int `json:"page"`
				PerPage    *int `json:"per_page"`
				Count      *int `json:"count"`
				TotalCount *int `json:"total_count"`
				TotalPages *int `json:"total_pages"`
			} `json:"result_info"`
		}
		var records []struct {
			ID      string `json:"id"`
			ZoneID  string `json:"zone_id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Content string `json:"content"`
			TTL     uint32 `json:"ttl"`
		}
		if decodeJSON(response.body, &metadata) != nil || metadata.ResultInfo == nil ||
			metadata.ResultInfo.Page == nil || metadata.ResultInfo.PerPage == nil || metadata.ResultInfo.Count == nil ||
			metadata.ResultInfo.TotalCount == nil || metadata.ResultInfo.TotalPages == nil ||
			decodeJSON(envelope.Result, &records) != nil || *metadata.ResultInfo.Page != pageNumber ||
			*metadata.ResultInfo.Count != len(records) {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		totalPages, pageErr := validateNumberedRecoveryPage(*metadata.ResultInfo.TotalCount, pageNumber,
			*metadata.ResultInfo.PerPage, len(records))
		reportedPages := *metadata.ResultInfo.TotalPages
		if *metadata.ResultInfo.TotalCount == 0 && reportedPages == 0 {
			reportedPages = 1
		}
		if pageErr != nil || reportedPages != totalPages || total >= 0 && total != *metadata.ResultInfo.TotalCount {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		total = *metadata.ResultInfo.TotalCount
		pageRecords := make([]reconcileRecord, 0, len(records))
		for _, record := range records {
			if !cloudflareRecordInZone(record.ZoneID, zoneID) {
				return ReconcileLookup{}, malformedProviderResponse()
			}
			pageRecords = append(pageRecords, reconcileRecord{
				ID: record.ID, Name: record.Name, Type: record.Type, Value: record.Content, TTL: record.TTL,
			})
		}
		converted, err = appendReconcilePage(converted, pageRecords, seen, pageNumber)
		if err != nil {
			return ReconcileLookup{}, err
		}
		if pageNumber == totalPages {
			return lookupRecord(converted, operation, fmt.Sprintf("cloudflare:pages=%d:total=%d:size=%d", totalPages, total, *metadata.ResultInfo.PerPage)), nil
		}
	}
	return ReconcileLookup{}, malformedProviderResponse()
}

func (provider *cloudflareProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	zoneID, err := provider.zoneID(ctx, config)
	if err != nil {
		return "", err
	}
	if operation.Action == dnscheck.ProviderDelete {
		err := provider.delete(ctx, config, recordHandle{ZoneID: zoneID, RecordID: operation.RecordID})
		return operation.RecordID, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	payload, err := json.Marshal(map[string]any{
		"type": typeName, "name": operation.Name, "content": reconcileProviderValue(operation.Type, operation.Value), "ttl": operation.TTL,
	})
	if err != nil {
		return "", malformedProviderResponse()
	}
	method, path := http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records"
	if operation.Action == dnscheck.ProviderUpdate {
		method, path = http.MethodPut, path+"/"+url.PathEscape(operation.RecordID)
	}
	envelope, err := provider.request(ctx, method, path, config.Credentials["api_token"], payload)
	if err != nil {
		return "", err
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(envelope.Result, &created); err != nil || !validReference(created.ID, 256) {
		return "", malformedProviderResponse()
	}
	return created.ID, nil
}

func (provider *aliyunProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	if operation.Action != dnscheck.ProviderCreate {
		body, err := provider.request(ctx, config, map[string]string{"Action": "DescribeDomainRecordInfo", "RecordId": operation.RecordID})
		if isCode(err, CodeRecordNotFound) {
			return lookupRecord(nil, operation, "aliyun:record:not-found"), nil
		}
		if err != nil {
			return ReconcileLookup{}, err
		}
		var record struct {
			RecordID, RR, Type, Value, DomainName, Line string
			TTL                                         uint32
		}
		if err := decodeJSON(body, &record); err != nil || canonicalDNSName(record.DomainName, false) != config.ZoneName {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		records, err := appendReconcilePage(nil, []reconcileRecord{{
			ID: record.RecordID, Name: ownerFromRelative(record.RR, config.ZoneName),
			Type: record.Type, Value: record.Value, TTL: record.TTL, Line: aliyunLine(record.Line),
		}}, make(map[string]struct{}))
		if err != nil {
			return ReconcileLookup{}, err
		}
		return lookupRecord(records, operation, "aliyun:record:"+config.ZoneName), nil
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	records := make([]reconcileRecord, 0, recoveryPageSize)
	seen := make(map[string]struct{})
	total := -1
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		body, err := provider.request(ctx, config, map[string]string{
			"Action": "DescribeDomainRecords", "DomainName": config.ZoneName, "RRKeyWord": relative,
			"TypeKeyWord": typeName, "PageNumber": strconv.Itoa(pageNumber),
			"PageSize": strconv.Itoa(recoveryPageSize),
		})
		if err != nil {
			return ReconcileLookup{}, err
		}
		var page struct {
			TotalCount    *int `json:"TotalCount"`
			PageNumber    *int `json:"PageNumber"`
			PageSize      *int `json:"PageSize"`
			DomainRecords struct {
				Records []struct {
					RecordID, RR, Type, Value, Line string
					TTL                             uint32
				} `json:"Record"`
			} `json:"DomainRecords"`
		}
		if err := decodeJSON(body, &page); err != nil || page.TotalCount == nil || page.PageNumber == nil ||
			page.PageSize == nil || *page.PageNumber != pageNumber {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		totalPages, pageErr := validateNumberedRecoveryPage(*page.TotalCount, pageNumber, *page.PageSize,
			len(page.DomainRecords.Records))
		if pageErr != nil || total >= 0 && total != *page.TotalCount {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		total = *page.TotalCount
		pageRecords := make([]reconcileRecord, 0, len(page.DomainRecords.Records))
		for _, record := range page.DomainRecords.Records {
			pageRecords = append(pageRecords, reconcileRecord{
				ID: record.RecordID, Name: ownerFromRelative(record.RR, config.ZoneName),
				Type: record.Type, Value: record.Value, TTL: record.TTL, Line: aliyunLine(record.Line),
			})
		}
		records, err = appendReconcilePage(records, pageRecords, seen, pageNumber)
		if err != nil {
			return ReconcileLookup{}, err
		}
		if pageNumber == totalPages {
			return lookupRecord(recordsOnLine(records, operation.Line), operation,
				fmt.Sprintf("aliyun:pages=%d:total=%d:size=%d:line=%s", totalPages, total, *page.PageSize, aliyunOperationLine(operation.Line))), nil
		}
	}
	return ReconcileLookup{}, malformedProviderResponse()
}

func (provider *aliyunProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	typeName, _ := reconcileRecordType(operation.Type)
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	parameters := map[string]string{"Type": typeName, "Value": reconcileProviderValue(operation.Type, operation.Value), "TTL": strconv.FormatUint(uint64(operation.TTL), 10)}
	parameters["Line"] = aliyunOperationLine(operation.Line)
	switch operation.Action {
	case dnscheck.ProviderCreate:
		parameters["Action"], parameters["DomainName"], parameters["RR"] = "AddDomainRecord", config.ZoneName, relative
	case dnscheck.ProviderUpdate:
		parameters["Action"], parameters["RecordId"], parameters["RR"] = "UpdateDomainRecord", operation.RecordID, relative
	case dnscheck.ProviderDelete:
		parameters = map[string]string{"Action": "DeleteDomainRecord", "RecordId": operation.RecordID}
	}
	body, err := provider.request(ctx, config, parameters)
	if err != nil {
		return "", err
	}
	var result struct {
		RecordID string `json:"RecordId"`
	}
	if err := decodeJSON(body, &result); err != nil || !validReference(result.RecordID, 256) {
		return "", malformedProviderResponse()
	}
	return result.RecordID, nil
}

func (provider *huaweiProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	zoneID, err := provider.zoneID(ctx, config)
	if err != nil {
		return ReconcileLookup{}, err
	}
	records, err := provider.reconcileRecordSets(ctx, config, zoneID, operation)
	if err != nil {
		return ReconcileLookup{}, err
	}
	// Huawei keeps one record set per name and type: each value is one entry
	// sharing the set ID. Update and delete address one value of the set.
	converted := make([]reconcileRecord, 0, len(records))
	for _, record := range records {
		for _, value := range record.Records {
			if operation.Action == dnscheck.ProviderDelete && value != operation.Value ||
				operation.Action == dnscheck.ProviderUpdate && value != operation.Value && value != operation.PreviousValue {
				continue
			}
			id := record.ID
			if operation.Action != dnscheck.ProviderCreate {
				// Update and delete address one value of the set by the
				// listed ID, whatever its form (plain or <set>/<value>).
				id = operation.RecordID
			}
			converted = append(converted, reconcileRecord{
				ID: id, Name: record.Name, Type: record.Type, Value: value,
				TTL: record.TTL, Line: huaweiLine(record.Line), Page: record.Page,
			})
		}
	}
	if operation.Action == dnscheck.ProviderCreate {
		// Each line is its own record set; other lines neither match nor compete.
		converted = recordsOnLine(converted, operation.Line)
	}
	if operation.Action == dnscheck.ProviderUpdate && len(converted) > 1 {
		// The set already holds the new value next to the previous one: the
		// update still has to drop the previous value (reconcileMutate dedups).
		converted = slices.DeleteFunc(converted, func(record reconcileRecord) bool {
			return record.Value != operation.PreviousValue
		})
	}
	return lookupRecord(converted, operation,
		fmt.Sprintf("huawei:zone=%s:records=%d:values=%d", zoneID, len(records), len(converted))), nil
}

func (provider *huaweiProvider) reconcileRecordSets(ctx context.Context, config ProviderConfig, zoneID string,
	operation dnscheck.ProviderOperation) ([]huaweiRecordSet, error) {
	if operation.Action != dnscheck.ProviderCreate {
		setID, _ := splitHuaweiValueRecordID(operation.RecordID)
		path := "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets/" + url.PathEscape(setID)
		response, err := provider.requestAllowNotFound(ctx, config, http.MethodGet, path, "", nil)
		if err != nil {
			return nil, err
		}
		if response.status == http.StatusNotFound {
			return nil, nil
		}
		var record huaweiRecordSet
		if response.status != http.StatusOK || decodeJSON(response.body, &record) != nil {
			return nil, malformedProviderResponse()
		}
		record, err = normalizeHuaweiReconcileRecordSet(record, zoneID)
		if err != nil {
			return nil, err
		}
		record.Page = 1
		return []huaweiRecordSet{record}, nil
	}
	typeName, _ := reconcileRecordType(operation.Type)
	path := "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets"
	result := make([]huaweiRecordSet, 0, 1)
	seen := make(map[string]struct{})
	total := -1
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		offset := (pageNumber - 1) * recoveryPageSize
		query := url.Values{
			"limit": {strconv.Itoa(recoveryPageSize)}, "offset": {strconv.Itoa(offset)},
			"name": {operation.Name}, "type": {typeName}, "search_mode": {"equal"},
		}
		response, err := provider.request(ctx, config, http.MethodGet, path, query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		// Huawei (Designate) always lists links.self and lists links.next only
		// while more pages follow (SDK PageLink.Next is omitempty): a missing
		// next is the last page, not a malformed response. A full last page
		// may still carry next (Designate links it whenever len == limit).
		var envelope struct {
			Recordsets []huaweiRecordSet `json:"recordsets"`
			Metadata   *struct {
				TotalCount *int `json:"total_count"`
			} `json:"metadata"`
			Links *struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if response.status != http.StatusOK || decodeJSON(response.body, &envelope) != nil ||
			envelope.Metadata == nil || envelope.Metadata.TotalCount == nil || envelope.Links == nil {
			return nil, malformedProviderResponse()
		}
		totalPages, pageErr := validateNumberedRecoveryPage(*envelope.Metadata.TotalCount, pageNumber,
			recoveryPageSize, len(envelope.Recordsets))
		if pageErr != nil || total >= 0 && total != *envelope.Metadata.TotalCount ||
			pageNumber < totalPages && envelope.Links.Next == "" {
			return nil, malformedProviderResponse()
		}
		total = *envelope.Metadata.TotalCount
		for _, record := range envelope.Recordsets {
			record, err = normalizeHuaweiReconcileRecordSet(record, zoneID)
			if err != nil {
				return nil, err
			}
			if _, duplicate := seen[record.ID]; duplicate {
				return nil, failure(CodeRecordMismatch, false)
			}
			seen[record.ID] = struct{}{}
			record.Page = pageNumber
			result = append(result, record)
		}
		if pageNumber == totalPages {
			return result, nil
		}
	}
	return nil, malformedProviderResponse()
}

func normalizeHuaweiReconcileRecordSet(record huaweiRecordSet, zoneID string) (huaweiRecordSet, error) {
	if record.ZoneID != zoneID || len(record.Records) == 0 || len(record.Records) > recoveryMaxItems {
		return huaweiRecordSet{}, malformedProviderResponse()
	}
	for index, value := range record.Records {
		normalized, err := normalizeReconcileRecord(reconcileRecord{
			ID: record.ID, Name: record.Name, Type: record.Type, Value: value, TTL: record.TTL,
		})
		if err != nil {
			return huaweiRecordSet{}, err
		}
		record.Name = normalized.Name
		record.Records[index] = normalized.Value
	}
	return record, nil
}

func (provider *huaweiProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	zoneID, err := provider.zoneID(ctx, config)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	method := http.MethodPost
	path := "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets"
	values := []string{huaweiWireValue(operation.Type, operation.Value)}
	// Huawei has one record set per name and type: a create next to existing
	// values, and every update or delete, rewrites the whole set's records.
	// Create lists the owner's set; update and delete read the set by ID.
	existing, err := provider.reconcileRecordSets(ctx, config, zoneID, operation)
	if err != nil {
		return "", err
	}
	var set *huaweiRecordSet
	setID, _ := splitHuaweiValueRecordID(operation.RecordID)
	for index := range existing {
		if existing[index].Name == operation.Name && existing[index].Type == typeName &&
			(operation.Action == dnscheck.ProviderCreate && sameLine(huaweiLine(existing[index].Line), operation.Line) ||
				operation.Action != dnscheck.ProviderCreate && existing[index].ID == setID) {
			set = &existing[index]
			break
		}
	}
	if operation.Action != dnscheck.ProviderCreate && set == nil {
		if operation.Action == dnscheck.ProviderDelete {
			return operation.RecordID, nil
		}
		return "", failure(CodeRecordMismatch, false)
	}
	if set != nil {
		if operation.Type == dnscheck.RecordCNAME && operation.Action == dnscheck.ProviderCreate {
			return "", failure(CodeRecordMismatch, false)
		}
		method, path = http.MethodPut, path+"/"+url.PathEscape(set.ID)
		drop := map[string]bool{}
		switch operation.Action {
		case dnscheck.ProviderDelete:
			drop[operation.Value] = true
		case dnscheck.ProviderUpdate:
			drop[operation.PreviousValue] = true
		}
		merged := make([]string, 0, len(set.Records)+1)
		for _, value := range set.Records {
			if !drop[value] && value != operation.Value {
				merged = append(merged, huaweiWireValue(operation.Type, value))
			}
		}
		if operation.Action != dnscheck.ProviderDelete {
			merged = append(merged, values[0])
		}
		if len(merged) == 0 {
			response, deleteErr := provider.requestAllowNotFound(ctx, config, http.MethodDelete, path, "", nil)
			validStatus := response.status == http.StatusOK || response.status == http.StatusAccepted ||
				response.status == http.StatusNoContent || response.status == http.StatusNotFound
			unexpectedBody := (response.status == http.StatusOK || response.status == http.StatusAccepted) &&
				len(response.body) != 0 || response.status == http.StatusNotFound && len(response.body) != 0
			if deleteErr != nil || !validStatus || unexpectedBody {
				return "", firstError(deleteErr, malformedProviderResponse())
			}
			return operation.RecordID, nil
		}
		slices.Sort(merged)
		values = merged
	}
	body := map[string]any{"name": operation.Name, "type": typeName, "ttl": operation.TTL, "records": values}
	if line := huaweiOperationLine(operation.Line); set == nil && line != huaweiDefaultLine {
		// The line is fixed when the record set is created; UpdateRecordSets has no line.
		body["line"] = line
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", malformedProviderResponse()
	}
	response, err := provider.request(ctx, config, method, path, "", payload)
	if err != nil {
		return "", err
	}
	var record huaweiRecordSet
	if response.status != http.StatusOK && response.status != http.StatusCreated && response.status != http.StatusAccepted || decodeJSON(response.body, &record) != nil || !validReference(record.ID, 256) {
		return "", malformedProviderResponse()
	}
	if operation.Action != dnscheck.ProviderCreate {
		return operation.RecordID, nil
	}
	return record.ID, nil
}

// huaweiValueRecordID names one value of a Huawei record set. A set with
// several values lists each as "<set id>/<value>" so the values have
// distinct record IDs; a single-value set keeps the plain set ID.
func huaweiValueRecordID(setID, value string, values int) string {
	if values <= 1 {
		return setID
	}
	if strings.ContainsAny(value, "\" /") || len(value) > 128 {
		// TXT text (quoted, free-form, up to 4 KiB): a digest keeps the ID
		// short; update and delete only use the set ID and match the value.
		digest := sha256.Sum256([]byte(value))
		return setID + "/h" + fmt.Sprintf("%x", digest[:8])
	}
	return setID + "/" + value
}

// splitHuaweiValueRecordID returns the record set ID of a (possibly
// value-qualified) Huawei record ID. Values never hold "/" (A/AAAA/CNAME).
func splitHuaweiValueRecordID(recordID string) (string, string) {
	setID, value, _ := strings.Cut(recordID, "/")
	return setID, value
}

func firstError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}

func (provider *dnsPodProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	if operation.Action != dnscheck.ProviderCreate {
		envelope, err := provider.request(ctx, config, "/Record.Info", url.Values{"domain": {config.ZoneName}, "record_id": {operation.RecordID}})
		if isCode(err, CodeRecordNotFound) {
			return lookupRecord(nil, operation, "dnspod:record:not-found"), nil
		}
		if err != nil {
			return ReconcileLookup{}, err
		}
		record, err := decodeDNSPodReconcileRecord(envelope.Record)
		if err != nil {
			return ReconcileLookup{}, err
		}
		records, err := appendReconcilePage(nil, []reconcileRecord{{
			ID: record.ID, Name: ownerFromRelative(record.Name, config.ZoneName),
			Type: record.Type, Value: record.Value, TTL: record.TTL, Line: record.Line, Weight: record.Weight,
		}}, make(map[string]struct{}))
		if err != nil {
			return ReconcileLookup{}, err
		}
		return lookupRecord(records, operation, "dnspod:record:"+config.ZoneName), nil
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	converted := make([]reconcileRecord, 0, recoveryPageSize)
	seen := make(map[string]struct{})
	for pageNumber := 1; pageNumber <= recoveryMaxPages+1; pageNumber++ {
		boundaryProbe := pageNumber == recoveryMaxPages+1
		offset, length := (pageNumber-1)*recoveryPageSize, recoveryPageSize
		if boundaryProbe {
			offset, length = recoveryMaxItems, 1
		}
		credentials := providerCredentials(config, "dp_id", "dp_key")
		form := url.Values{
			"error_on_empty": {"no"}, "format": {"json"}, "lang": {"en"},
			"login_token": {credentials[0] + "," + credentials[1]}, "domain": {config.ZoneName},
			"sub_domain": {relative}, "record_type": {typeName}, "record_line": {dnsPodOperationLine(operation.Line)},
			"offset": {strconv.Itoa(offset)}, "length": {strconv.Itoa(length)},
		}
		headers := make(http.Header)
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := provider.adapter.http.do(ctx, http.MethodPost, provider.adapter.endpoints.dnspod,
			"/Record.List", []byte(form.Encode()), headers)
		if err != nil {
			return ReconcileLookup{}, err
		}
		var envelope struct {
			Status *struct {
				Code string `json:"code"`
			} `json:"status"`
			Records json.RawMessage `json:"records"`
			Info    *struct {
				RecordsNum stringID `json:"records_num"`
			} `json:"info"`
		}
		decoded := decodeJSON(response.body, &envelope) == nil && envelope.Status != nil && envelope.Status.Code != ""
		if decoded {
			switch envelope.Status.Code {
			case "-1", "-7", "-8", "85":
				return ReconcileLookup{}, failure(CodeCredentialsRejected, false)
			case "-2":
				return ReconcileLookup{}, rateLimitFailure(response.header.Get("Retry-After"), provider.adapter.now())
			case "-99":
				return ReconcileLookup{}, failure(CodeUnavailable, true)
			case "10":
				return lookupRecord(converted, operation, fmt.Sprintf("dnspod:pages=%d:count=%d:empty", pageNumber, len(converted))), nil
			}
		}
		if err := classifyHTTP(response, provider.adapter.now()); err != nil {
			return ReconcileLookup{}, err
		}
		if response.status != http.StatusOK || !decoded || envelope.Status.Code != "1" || envelope.Info == nil {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		var rawRecords []json.RawMessage
		count, countErr := strconv.Atoi(string(envelope.Info.RecordsNum))
		if decodeJSON(envelope.Records, &rawRecords) != nil || countErr != nil || count != len(rawRecords) || len(rawRecords) > length {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		records := make([]reconcileRecord, 0, len(rawRecords))
		for _, rawRecord := range rawRecords {
			record, recordErr := decodeDNSPodReconcileRecord(rawRecord)
			if recordErr != nil {
				return ReconcileLookup{}, malformedProviderResponse()
			}
			records = append(records, record)
		}
		if boundaryProbe {
			if len(records) == 0 {
				return lookupRecord(converted, operation, fmt.Sprintf("dnspod:pages=%d:count=%d:boundary", pageNumber, len(converted))), nil
			}
			return ReconcileLookup{}, malformedProviderResponse()
		}
		pageRecords := make([]reconcileRecord, 0, len(records))
		for _, record := range records {
			if record.Line != dnsPodOperationLine(operation.Line) {
				continue
			}
			pageRecords = append(pageRecords, reconcileRecord{
				ID: record.ID, Name: ownerFromRelative(record.Name, config.ZoneName),
				Type: record.Type, Value: record.Value, TTL: record.TTL, Line: record.Line, Weight: record.Weight,
			})
		}
		converted, err = appendReconcilePage(converted, pageRecords, seen, pageNumber)
		if err != nil {
			return ReconcileLookup{}, err
		}
		if len(records) < recoveryPageSize {
			return lookupRecord(converted, operation, fmt.Sprintf("dnspod:pages=%d:count=%d:short", pageNumber, len(converted))), nil
		}
	}
	return ReconcileLookup{}, malformedProviderResponse()
}

func (provider *dnsPodProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	parameters := url.Values{"domain": {config.ZoneName}}
	path := "/Record.Create"
	switch operation.Action {
	case dnscheck.ProviderCreate:
		parameters.Set("sub_domain", relative)
		parameters.Set("record_type", typeName)
		parameters.Set("record_line", dnsPodOperationLine(operation.Line))
		parameters.Set("weight", strconv.FormatUint(uint64(operation.Weight), 10))
		parameters.Set("value", reconcileProviderValue(operation.Type, operation.Value))
		parameters.Set("ttl", strconv.FormatUint(uint64(operation.TTL), 10))
	case dnscheck.ProviderUpdate:
		path = "/Record.Modify"
		parameters.Set("record_id", operation.RecordID)
		parameters.Set("sub_domain", relative)
		parameters.Set("record_type", typeName)
		parameters.Set("record_line", dnsPodOperationLine(operation.Line))
		parameters.Set("weight", strconv.FormatUint(uint64(operation.Weight), 10))
		parameters.Set("value", reconcileProviderValue(operation.Type, operation.Value))
		parameters.Set("ttl", strconv.FormatUint(uint64(operation.TTL), 10))
	case dnscheck.ProviderDelete:
		path = "/Record.Remove"
		parameters.Set("record_id", operation.RecordID)
	}
	envelope, err := provider.request(ctx, config, path, parameters)
	if err != nil {
		return "", err
	}
	if operation.Action == dnscheck.ProviderDelete {
		return operation.RecordID, nil
	}
	var record dnsPodCreatedRecord
	if err := decodeJSON(envelope.Record, &record); err != nil || !validReference(string(record.ID), 256) {
		return "", malformedProviderResponse()
	}
	return string(record.ID), nil
}

func (provider *dnsComProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	records, domainID, evidence, err := provider.reconcileRecords(ctx, config, operation)
	if err != nil {
		return ReconcileLookup{}, err
	}
	if operation.Action == dnscheck.ProviderCreate {
		records = recordsOnLine(records, operation.Line)
	}
	result := lookupRecord(records, operation, evidence)
	if operation.Action == dnscheck.ProviderCreate || result.Ambiguous || result.Conflict {
		return result, nil
	}
	targetFound := false
	for _, record := range records {
		if record.ID == operation.RecordID {
			targetFound = true
			break
		}
	}
	if !targetFound {
		return result, nil
	}
	if !validReference(domainID, 256) {
		return ReconcileLookup{}, malformedProviderResponse()
	}
	envelope, err := provider.request(ctx, config, "/api/record/getOne/", map[string]string{
		"domain": domainID, "record_id": operation.RecordID,
	})
	if err != nil {
		return ReconcileLookup{}, err
	}
	record, err := decodeDNSComRecord(envelope.Data)
	if err != nil || string(record.DomainID) != domainID || string(record.RecordID) != operation.RecordID {
		return ReconcileLookup{}, malformedProviderResponse()
	}
	lines, err := provider.recordLines(ctx, config, []string{string(record.ViewID)})
	if err != nil {
		return ReconcileLookup{}, err
	}
	exact, err := appendReconcilePage(nil, []reconcileRecord{{
		ID: string(record.RecordID), Name: ownerFromRelative(record.Record, config.ZoneName),
		Type: record.Type, Value: record.Value, TTL: record.TTL, Line: lines[0],
	}}, make(map[string]struct{}))
	if err != nil {
		return ReconcileLookup{}, err
	}
	return lookupRecord(exact, operation, evidence, "dnscom:get:"+domainID), nil
}

func (provider *dnsComProvider) reconcileRecords(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) ([]reconcileRecord, string, string, error) {
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return nil, "", "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	records := make([]reconcileRecord, 0, recoveryPageSize)
	seen := make(map[string]struct{})
	total := -1
	remoteDomainID := ""
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		envelope, err := provider.request(ctx, config, dnsComRecordListPath, map[string]string{
			"domain": config.ZoneName, "record": relative, "type": typeName,
			"page": strconv.Itoa(pageNumber), "paginate": strconv.Itoa(recoveryPageSize),
		})
		if err != nil {
			return nil, "", "", err
		}
		var page struct {
			Total *int           `json:"total"`
			List  []dnsComRecord `json:"data"`
		}
		if err := decodeJSON(envelope.Data, &page); err != nil || page.Total == nil || !dnsComListHasData(envelope.Data) {
			return nil, "", "", malformedProviderResponse()
		}
		totalPages, pageErr := validateNumberedRecoveryPage(*page.Total, pageNumber, recoveryPageSize, len(page.List))
		if pageErr != nil || total >= 0 && total != *page.Total {
			return nil, "", "", malformedProviderResponse()
		}
		total = *page.Total
		pageRecords := make([]reconcileRecord, 0, len(page.List))
		viewIDs := make([]string, 0, len(page.List))
		for _, record := range page.List {
			domainID := string(record.DomainID)
			if !validReference(domainID, 256) || remoteDomainID != "" && remoteDomainID != domainID {
				return nil, "", "", malformedProviderResponse()
			}
			remoteDomainID = domainID
			viewIDs = append(viewIDs, string(record.ViewID))
			pageRecords = append(pageRecords, reconcileRecord{
				ID: string(record.RecordID), Name: ownerFromRelative(record.Record, config.ZoneName),
				Type: record.Type, Value: record.Value, TTL: record.TTL,
			})
		}
		lines, err := provider.recordLines(ctx, config, viewIDs)
		if err != nil {
			return nil, "", "", err
		}
		for index := range pageRecords {
			pageRecords[index].Line = lines[index]
		}
		records, err = appendReconcilePage(records, pageRecords, seen, pageNumber)
		if err != nil {
			return nil, "", "", err
		}
		if pageNumber == totalPages {
			return records, remoteDomainID,
				fmt.Sprintf("dnscom:pages=%d:total=%d:size=%d:domain=%s", totalPages, total, recoveryPageSize, remoteDomainID), nil
		}
	}
	return nil, "", "", malformedProviderResponse()
}

func (provider *dnsComProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	domainID := config.ZoneName
	if operation.Action != dnscheck.ProviderCreate {
		records, discoveredDomainID, evidence, lookupErr := provider.reconcileRecords(ctx, config, operation)
		if lookupErr != nil {
			return "", lookupErr
		}
		lookup := lookupRecord(records, operation, evidence)
		if lookup.TargetComplete {
			return operation.RecordID, nil
		}
		if lookup.Ambiguous || lookup.Conflict || !validReference(discoveredDomainID, 256) {
			return "", failure(CodeRecordMismatch, false)
		}
		targetFound := false
		for _, record := range records {
			if record.ID == operation.RecordID {
				targetFound = true
				break
			}
		}
		if !targetFound {
			return "", failure(CodeRecordMismatch, false)
		}
		domainID = discoveredDomainID
	}
	parameters := map[string]string{"domain": domainID}
	path := "/api/record/create/"
	switch operation.Action {
	case dnscheck.ProviderCreate:
		parameters["record"], parameters["type"] = relative, typeName
		parameters["value"] = reconcileProviderValue(operation.Type, operation.Value)
		parameters["ttl"] = strconv.FormatUint(uint64(operation.TTL), 10)
	case dnscheck.ProviderUpdate:
		path = "/api/record/update/"
		parameters["record_id"], parameters["record"], parameters["type"] = operation.RecordID, relative, typeName
		parameters["value"] = reconcileProviderValue(operation.Type, operation.Value)
		parameters["ttl"] = strconv.FormatUint(uint64(operation.TTL), 10)
	case dnscheck.ProviderDelete:
		path = "/api/record/operate/"
		parameters["record_id"], parameters["status"] = operation.RecordID, "delete"
	}
	if operation.Action != dnscheck.ProviderDelete {
		viewID, err := provider.mutationViewID(ctx, config, operation)
		if err != nil {
			return "", err
		}
		if viewID != "" {
			parameters["view_id"] = viewID
		}
	}
	envelope, err := provider.request(ctx, config, path, parameters)
	var refusal *dnsComRefusal
	if errors.As(err, &refusal) && operation.Action != dnscheck.ProviderDelete && !defaultReconcileLine(operation.Line) {
		// The account listed the line but refused the write: its plan lacks it.
		return "", failure(CodeLineNotInPlan, false)
	}
	if err != nil {
		return "", err
	}
	if operation.Action == dnscheck.ProviderDelete {
		return operation.RecordID, nil
	}
	record, err := decodeDNSComRecord(envelope.Data)
	if err != nil || operation.Action == dnscheck.ProviderUpdate &&
		(string(record.DomainID) != domainID || string(record.RecordID) != operation.RecordID) {
		return "", malformedProviderResponse()
	}
	return string(record.RecordID), nil
}

func (provider *dnsLAProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	domainID, err := provider.domainID(ctx, config)
	if err != nil {
		return ReconcileLookup{}, err
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeNumber, ok := dnsLAType(operation.Type)
	if !ok {
		return ReconcileLookup{}, failure(CodeUnsupported, false)
	}
	typeName, _ := reconcileRecordType(operation.Type)
	records := make([]reconcileRecord, 0, recoveryPageSize)
	seen := make(map[string]struct{})
	total := -1
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		query := url.Values{
			"pageIndex": {strconv.Itoa(pageNumber)}, "pageSize": {strconv.Itoa(dnsLARecordPageSize)},
			"domainId": {domainID}, "type": {strconv.Itoa(typeNumber)}, "host": {relative},
		}
		envelope, err := provider.request(ctx, config, http.MethodGet, "/api/recordList?"+query.Encode(), nil)
		if err != nil {
			return ReconcileLookup{}, err
		}
		var page struct {
			Total   *int64        `json:"total"`
			Results []dnsLARecord `json:"results"`
		}
		if err := decodeJSON(envelope.Data, &page); err != nil || page.Total == nil || *page.Total > recoveryMaxItems {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		totalPages, pageErr := validateNumberedRecoveryPage(int(*page.Total), pageNumber,
			dnsLARecordPageSize, len(page.Results))
		if pageErr != nil || total >= 0 && total != int(*page.Total) {
			return ReconcileLookup{}, malformedProviderResponse()
		}
		total = int(*page.Total)
		pageRecords := make([]reconcileRecord, 0, len(page.Results))
		for _, record := range page.Results {
			if string(record.DomainID) != domainID || record.Type != typeNumber {
				return ReconcileLookup{}, malformedProviderResponse()
			}
			pageRecords = append(pageRecords, reconcileRecord{
				ID: string(record.ID), Name: ownerFromRelative(record.Host, config.ZoneName),
				Type: typeName, Value: record.Data, TTL: record.TTL, Line: dnsLALine(record.LineID, record.LineCode),
			})
		}
		records, err = appendReconcilePage(records, pageRecords, seen, pageNumber)
		if err != nil {
			return ReconcileLookup{}, err
		}
		if pageNumber == totalPages {
			if operation.Action == dnscheck.ProviderCreate {
				records = recordsOnLine(records, operation.Line)
			}
			return lookupRecord(records, operation, fmt.Sprintf("dnsla:pages=%d:total=%d:size=%d:domain=%s", totalPages, total, dnsLARecordPageSize, domainID)), nil
		}
	}
	return ReconcileLookup{}, malformedProviderResponse()
}

func (provider *dnsLAProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	domainID, err := provider.domainID(ctx, config)
	if err != nil {
		return "", err
	}
	_, relative, err := ownerAndRelative(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeNumber, _ := dnsLAType(operation.Type)
	if operation.Action == dnscheck.ProviderDelete {
		_, err := provider.request(ctx, config, http.MethodDelete, "/api/record?"+url.Values{"id": {operation.RecordID}}.Encode(), nil)
		return operation.RecordID, err
	}
	lineID, _ := providerLineCode(providerDNSLA, operation.Line)
	payload, err := json.Marshal(map[string]any{
		"domainId": domainID, "type": typeNumber, "host": relative,
		"data": reconcileProviderValue(operation.Type, operation.Value), "ttl": operation.TTL, "lineId": lineID,
	})
	if err != nil {
		return "", malformedProviderResponse()
	}
	method, path := http.MethodPost, "/api/record"
	if operation.Action == dnscheck.ProviderUpdate {
		method, path = http.MethodPut, "/api/record?"+url.Values{"id": {operation.RecordID}}.Encode()
	}
	envelope, err := provider.request(ctx, config, method, path, payload)
	if err != nil {
		return "", err
	}
	var created struct {
		ID stringID `json:"id"`
	}
	if err := decodeJSON(envelope.Data, &created); err != nil || !validReference(string(created.ID), 256) {
		return "", malformedProviderResponse()
	}
	return string(created.ID), nil
}

func dnsLAType(recordType dnscheck.RecordType) (int, bool) {
	switch recordType {
	case dnscheck.RecordA:
		return 1, true
	case dnscheck.RecordCNAME:
		return 5, true
	case dnscheck.RecordAAAA:
		return 28, true
	case dnscheck.RecordTXT:
		return 16, true
	default:
		return 0, false
	}
}
