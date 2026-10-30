package dnsproviderremote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// ZoneRecord is one provider A/AAAA/CNAME record value of a managed zone.
// Name is the canonical owner with a trailing dot; CNAME values too. A
// multi-value record set (Huawei) yields one ZoneRecord per value sharing ID.
type ZoneRecord struct {
	ID     string
	Name   string
	Type   dnscheck.RecordType
	Value  string
	TTL    uint32
	Line   string
	Weight uint32
}

// ZoneRecordLister lists the A/AAAA/CNAME records of a managed zone for
// 节点管理 > DNS配置 记录修复 (one owner) and 清除CDN无关解析 (whole zone).
// Other record types (NS, SOA, MX, TXT, ...) are never returned.
type ZoneRecordLister interface {
	ListZoneRecords(ctx context.Context, config ProviderConfig, owner string) ([]ZoneRecord, error)
}

func NewZoneRecordLister() ZoneRecordLister {
	return &providerReconcileRemote{adapter: newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)}
}

// ListZoneRecords lists the records of owner, or of the whole zone when owner
// is empty. Results are filtered exactly by owner here, whatever the
// provider's own (sometimes fuzzy) filter does.
func (remote *providerReconcileRemote) ListZoneRecords(ctx context.Context, config ProviderConfig, owner string) ([]ZoneRecord, error) {
	records, _, err := remote.listZoneRecords(ctx, config, owner, zoneRecordType, false)
	return records, err
}

// listZoneRecords lists the records recordTypeOf accepts. tolerant (hub)
// skips, and counts, records it cannot represent (a wildcard owner such as
// *.example.com, a value outside the type's form) instead of failing the
// whole listing.
func (remote *providerReconcileRemote) listZoneRecords(ctx context.Context, config ProviderConfig, owner string,
	recordTypeOf func(string) (dnscheck.RecordType, bool), tolerant bool) ([]ZoneRecord, int, error) {
	if remote == nil || remote.adapter == nil || ctx == nil {
		return nil, 0, failure(CodeSourceUnavailable, true)
	}
	zoneWide := owner == ""
	if zoneWide {
		owner = config.ZoneName
	}
	canonicalOwner := canonicalDNSName(owner, true)
	validated, relative, err := validateConfig(config, canonicalOwner)
	if err != nil {
		return nil, 0, err
	}
	if zoneWide {
		relative = ""
	}
	var records []reconcileRecord
	switch validated.ProviderType {
	case providerCloudflare:
		records, err = (&cloudflareProvider{adapter: remote.adapter}).listRecords(ctx, validated, canonicalOwner, relative)
	case providerAliyun:
		records, err = (&aliyunProvider{adapter: remote.adapter}).listRecords(ctx, validated, relative)
	case providerHuawei:
		records, err = (&huaweiProvider{adapter: remote.adapter}).listRecords(ctx, validated, canonicalOwner, relative)
	case providerDNSPodCN:
		records, err = (&dnsPodProvider{adapter: remote.adapter}).listRecords(ctx, validated, relative)
	case providerDNSCom:
		records, err = (&dnsComProvider{adapter: remote.adapter}).listRecords(ctx, validated, relative)
	case providerDNSLA:
		records, err = (&dnsLAProvider{adapter: remote.adapter}).listRecords(ctx, validated, relative)
	case providerNameCom:
		records, err = (&nameComProvider{adapter: remote.adapter}).listRecords(ctx, validated)
	case providerCustomHTTP, providerPlugin:
		records, err = newRecordProvider(remote.adapter, validated.ProviderType).listRecords(ctx, validated, canonicalOwner, relative)
	default:
		return nil, 0, failure(CodeUnsupported, false)
	}
	if err != nil {
		return nil, 0, err
	}
	skipped := 0
	result := make([]ZoneRecord, 0, len(records))
	for _, record := range records {
		recordType, ok := recordTypeOf(record.Type)
		if !ok {
			continue
		}
		normalized, err := normalizeReconcileRecord(record)
		if err != nil && tolerant {
			skipped++
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if relative != "" && normalized.Name != canonicalOwner {
			continue
		}
		result = append(result, ZoneRecord{ID: normalized.ID, Name: normalized.Name, Type: recordType,
			Value: normalized.Value, TTL: normalized.TTL, Line: normalized.Line, Weight: normalized.Weight})
	}
	return result, skipped, nil
}

// hubRecordType is zoneRecordType plus TXT (ADR 0020 §3.3 用户端域名解析).
func hubRecordType(name string) (dnscheck.RecordType, bool) {
	if strings.EqualFold(name, "TXT") {
		return dnscheck.RecordTXT, true
	}
	return zoneRecordType(name)
}

func zoneRecordType(name string) (dnscheck.RecordType, bool) {
	switch strings.ToUpper(name) {
	case "A":
		return dnscheck.RecordA, true
	case "AAAA":
		return dnscheck.RecordAAAA, true
	case "CNAME":
		return dnscheck.RecordCNAME, true
	default:
		return 0, false
	}
}

// collectNumberedPages walks a numbered listing (page size recoveryPageSize)
// until the reported total is reached. fetch returns the reported total, the
// number of listed items on the page (record sets for Huawei) and the values.
func collectNumberedPages(fetch func(page int) (total, items int, records []reconcileRecord, err error)) ([]reconcileRecord, error) {
	result := make([]reconcileRecord, 0, recoveryPageSize)
	known := -1
	for page := 1; page <= recoveryMaxPages; page++ {
		total, items, records, err := fetch(page)
		if err != nil {
			return nil, err
		}
		totalPages, pageErr := validateNumberedRecoveryPage(total, page, recoveryPageSize, items)
		if pageErr != nil || known >= 0 && known != total {
			return nil, malformedProviderResponse()
		}
		known = total
		result = append(result, records...)
		if page == totalPages {
			return result, nil
		}
	}
	return nil, malformedProviderResponse()
}

func (provider *cloudflareProvider) listRecords(ctx context.Context, config ProviderConfig, owner, relative string) ([]reconcileRecord, error) {
	zoneID, err := provider.zoneID(ctx, config)
	if err != nil {
		return nil, err
	}
	return collectNumberedPages(func(page int) (int, int, []reconcileRecord, error) {
		query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(recoveryPageSize)}}
		if relative != "" {
			query.Set("name", strings.TrimSuffix(owner, "."))
		}
		response, err := provider.adapter.http.do(ctx, http.MethodGet, provider.adapter.endpoints.cloudflare,
			"/zones/"+url.PathEscape(zoneID)+"/dns_records?"+query.Encode(), nil, cloudflareHeaders(config.Credentials["api_token"]))
		if err != nil {
			return 0, 0, nil, err
		}
		if err := cloudflareResponseError(response, provider.adapter.now()); err != nil {
			return 0, 0, nil, err
		}
		envelope, err := decodeCloudflareEnvelope(response, provider.adapter.now())
		if err != nil {
			return 0, 0, nil, err
		}
		var metadata struct {
			ResultInfo *struct {
				TotalCount *int `json:"total_count"`
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
		if decodeJSON(response.body, &metadata) != nil || metadata.ResultInfo == nil || metadata.ResultInfo.TotalCount == nil ||
			decodeJSON(envelope.Result, &records) != nil {
			return 0, 0, nil, malformedProviderResponse()
		}
		converted := make([]reconcileRecord, 0, len(records))
		for _, record := range records {
			if !cloudflareRecordInZone(record.ZoneID, zoneID) {
				return 0, 0, nil, malformedProviderResponse()
			}
			converted = append(converted, reconcileRecord{ID: record.ID, Name: record.Name, Type: record.Type,
				Value: record.Content, TTL: record.TTL})
		}
		return *metadata.ResultInfo.TotalCount, len(converted), converted, nil
	})
}

func (provider *aliyunProvider) listRecords(ctx context.Context, config ProviderConfig, relative string) ([]reconcileRecord, error) {
	return collectNumberedPages(func(page int) (int, int, []reconcileRecord, error) {
		parameters := map[string]string{"Action": "DescribeDomainRecords", "DomainName": config.ZoneName,
			"PageNumber": strconv.Itoa(page), "PageSize": strconv.Itoa(recoveryPageSize)}
		if relative != "" {
			parameters["RRKeyWord"] = relative
		}
		body, err := provider.request(ctx, config, parameters)
		if err != nil {
			return 0, 0, nil, err
		}
		var result struct {
			TotalCount    *int `json:"TotalCount"`
			DomainRecords struct {
				Records []struct {
					RecordID, RR, Type, Value, Line string
					TTL                             uint32
				} `json:"Record"`
			} `json:"DomainRecords"`
		}
		if decodeJSON(body, &result) != nil || result.TotalCount == nil {
			return 0, 0, nil, malformedProviderResponse()
		}
		converted := make([]reconcileRecord, 0, len(result.DomainRecords.Records))
		for _, record := range result.DomainRecords.Records {
			converted = append(converted, reconcileRecord{ID: record.RecordID, Name: ownerFromRelative(record.RR, config.ZoneName),
				Type: record.Type, Value: record.Value, TTL: record.TTL, Line: aliyunLine(record.Line)})
		}
		return *result.TotalCount, len(converted), converted, nil
	})
}

func (provider *huaweiProvider) listRecords(ctx context.Context, config ProviderConfig, owner, relative string) ([]reconcileRecord, error) {
	zoneID, err := provider.zoneID(ctx, config)
	if err != nil {
		return nil, err
	}
	path := "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets"
	return collectNumberedPages(func(page int) (int, int, []reconcileRecord, error) {
		query := url.Values{"limit": {strconv.Itoa(recoveryPageSize)}, "offset": {strconv.Itoa((page - 1) * recoveryPageSize)}}
		if relative != "" {
			query.Set("name", owner)
			query.Set("search_mode", "equal")
		}
		response, err := provider.request(ctx, config, http.MethodGet, path, query.Encode(), nil)
		if err != nil {
			return 0, 0, nil, err
		}
		var envelope struct {
			Recordsets []huaweiRecordSet `json:"recordsets"`
			Metadata   *struct {
				TotalCount *int `json:"total_count"`
			} `json:"metadata"`
		}
		if response.status != http.StatusOK || decodeJSON(response.body, &envelope) != nil ||
			envelope.Metadata == nil || envelope.Metadata.TotalCount == nil {
			return 0, 0, nil, malformedProviderResponse()
		}
		converted := make([]reconcileRecord, 0, len(envelope.Recordsets))
		for _, set := range envelope.Recordsets {
			if set.ZoneID != zoneID {
				return 0, 0, nil, malformedProviderResponse()
			}
			for _, value := range set.Records {
				converted = append(converted, reconcileRecord{ID: huaweiValueRecordID(set.ID, value, len(set.Records)),
					Name: set.Name, Type: set.Type, Value: value, TTL: set.TTL, Line: huaweiLine(set.Line)})
			}
		}
		return *envelope.Metadata.TotalCount, len(envelope.Recordsets), converted, nil
	})
}

func (provider *dnsPodProvider) listRecords(ctx context.Context, config ProviderConfig, relative string) ([]reconcileRecord, error) {
	result := make([]reconcileRecord, 0, recoveryPageSize)
	seen := make(map[string]struct{})
	for page := 0; page < recoveryMaxPages; page++ {
		parameters := url.Values{"domain": {config.ZoneName}, "offset": {strconv.Itoa(page * recoveryPageSize)},
			"length": {strconv.Itoa(recoveryPageSize)}}
		if relative != "" {
			parameters.Set("sub_domain", relative)
		}
		envelope, err := provider.request(ctx, config, "/Record.List", parameters)
		if isCode(err, CodeRecordNotFound) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		var raw []json.RawMessage
		if decodeJSON(envelope.Records, &raw) != nil || len(raw) > recoveryPageSize {
			return nil, malformedProviderResponse()
		}
		for _, item := range raw {
			record, err := decodeDNSPodReconcileRecord(item)
			if err != nil {
				return nil, err
			}
			if _, ok := hubRecordType(record.Type); !ok {
				continue
			}
			if _, duplicate := seen[record.ID]; duplicate {
				return nil, malformedProviderResponse()
			}
			seen[record.ID] = struct{}{}
			record.Name = ownerFromRelative(record.Name, config.ZoneName)
			result = append(result, record)
		}
		if len(raw) < recoveryPageSize {
			return result, nil
		}
	}
	return nil, malformedProviderResponse()
}

func (provider *dnsComProvider) listRecords(ctx context.Context, config ProviderConfig, relative string) ([]reconcileRecord, error) {
	return collectNumberedPages(func(page int) (int, int, []reconcileRecord, error) {
		parameters := map[string]string{"domain": config.ZoneName, "page": strconv.Itoa(page),
			"paginate": strconv.Itoa(recoveryPageSize)}
		if relative != "" {
			parameters["record"] = relative
		}
		envelope, err := provider.request(ctx, config, dnsComRecordListPath, parameters)
		if err != nil {
			return 0, 0, nil, err
		}
		var list struct {
			Total *int           `json:"total"`
			List  []dnsComRecord `json:"data"`
		}
		if decodeJSON(envelope.Data, &list) != nil || list.Total == nil || !dnsComListHasData(envelope.Data) {
			return 0, 0, nil, malformedProviderResponse()
		}
		viewIDs := make([]string, len(list.List))
		for index, record := range list.List {
			viewIDs[index] = string(record.ViewID)
		}
		lines, err := provider.recordLines(ctx, config, viewIDs)
		if err != nil {
			return 0, 0, nil, err
		}
		converted := make([]reconcileRecord, 0, len(list.List))
		for index, record := range list.List {
			converted = append(converted, reconcileRecord{ID: string(record.RecordID),
				Name: ownerFromRelative(record.Record, config.ZoneName), Type: record.Type, Value: record.Value, TTL: record.TTL,
				Line: lines[index]})
		}
		return *list.Total, len(list.List), converted, nil
	})
}

func (provider *dnsLAProvider) listRecords(ctx context.Context, config ProviderConfig, relative string) ([]reconcileRecord, error) {
	domainID, err := provider.domainID(ctx, config)
	if err != nil {
		return nil, err
	}
	typeNames := map[int]string{1: "A", 5: "CNAME", 16: "TXT", 28: "AAAA"}
	return collectNumberedPages(func(page int) (int, int, []reconcileRecord, error) {
		query := url.Values{"pageIndex": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(dnsLARecordPageSize)}, "domainId": {domainID}}
		if relative != "" {
			query.Set("host", relative)
		}
		envelope, err := provider.request(ctx, config, http.MethodGet, "/api/recordList?"+query.Encode(), nil)
		if err != nil {
			return 0, 0, nil, err
		}
		var list struct {
			Total   *int64        `json:"total"`
			Results []dnsLARecord `json:"results"`
		}
		if decodeJSON(envelope.Data, &list) != nil || list.Total == nil || *list.Total > recoveryMaxItems {
			return 0, 0, nil, malformedProviderResponse()
		}
		converted := make([]reconcileRecord, 0, len(list.Results))
		for _, record := range list.Results {
			if string(record.DomainID) != domainID {
				return 0, 0, nil, malformedProviderResponse()
			}
			typeName, ok := typeNames[record.Type]
			if !ok {
				typeName = "OTHER"
			}
			converted = append(converted, reconcileRecord{ID: string(record.ID), Name: ownerFromRelative(record.Host, config.ZoneName),
				Type: typeName, Value: record.Data, TTL: record.TTL, Line: dnsLALine(record.LineID, record.LineCode)})
		}
		return int(*list.Total), len(list.Results), converted, nil
	})
}
