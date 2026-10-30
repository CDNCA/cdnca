package dnsproviderremote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

const (
	recoveryPageSize = 100
	recoveryMaxPages = 100
	recoveryMaxItems = recoveryPageSize * recoveryMaxPages
)

type txtCandidate struct {
	id, zoneID, owner, recordType, value string
}

func exactTXTHandles(provider, zone, owner, exactValue string, candidates []txtCandidate) ([]recordHandle, error) {
	if len(candidates) > recoveryPageSize {
		return nil, malformedProviderResponse()
	}
	matches := make([]recordHandle, 0, 1)
	for _, candidate := range candidates {
		candidateOwner := canonicalDNSName(candidate.owner, true)
		if !validReference(candidate.id, 256) || !validReference(candidate.zoneID, 256) || candidateOwner == "" {
			return nil, malformedProviderResponse()
		}
		if candidateOwner != owner || candidate.recordType != "TXT" || candidate.value != exactValue {
			continue
		}
		matches = append(matches, recordHandle{
			Version: 1, Provider: provider, Zone: zone, ZoneID: candidate.zoneID,
			RecordID: candidate.id, Owner: owner,
		})
	}
	return matches, nil
}

func appendTXTHandles(matches []recordHandle, provider, zone, owner, exactValue string,
	candidates []txtCandidate, seen map[string]struct{}) ([]recordHandle, error) {
	pageMatches, err := exactTXTHandles(provider, zone, owner, exactValue, candidates)
	if err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		if _, ok := seen[candidate.id]; ok {
			return nil, failure(CodeRecordMismatch, false)
		}
		seen[candidate.id] = struct{}{}
	}
	matches = append(matches, pageMatches...)
	return matches, nil
}

func validateNumberedRecoveryPage(total, page, pageSize, count int) (int, error) {
	if total < 0 || total > recoveryMaxItems || page < 1 || page > recoveryMaxPages ||
		pageSize != recoveryPageSize || count < 0 || count > recoveryPageSize {
		return 0, malformedProviderResponse()
	}
	totalPages := (total + recoveryPageSize - 1) / recoveryPageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		return 0, malformedProviderResponse()
	}
	remaining := total - (page-1)*recoveryPageSize
	if remaining < 0 {
		return 0, malformedProviderResponse()
	}
	expected := min(recoveryPageSize, remaining)
	if count != expected {
		return 0, malformedProviderResponse()
	}
	return totalPages, nil
}

func (p *cloudflareProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, _ string,
	exactValue string) ([]recordHandle, error) {
	zoneID, err := p.zoneID(ctx, config)
	if err != nil {
		return nil, err
	}
	var matches []recordHandle
	seen := make(map[string]struct{})
	total := -1
	for page := 1; page <= recoveryMaxPages; page++ {
		query := url.Values{
			"type": {"TXT"}, "name": {owner}, "page": {strconv.Itoa(page)},
			"per_page": {strconv.Itoa(recoveryPageSize)},
		}
		response, err := p.adapter.http.do(ctx, http.MethodGet, p.adapter.endpoints.cloudflare,
			"/zones/"+url.PathEscape(zoneID)+"/dns_records?"+query.Encode(), nil,
			cloudflareHeaders(config.Credentials["api_token"]))
		if err != nil {
			return nil, err
		}
		if err := classifyHTTP(response, p.adapter.now()); err != nil {
			return nil, err
		}
		envelope, err := decodeCloudflareEnvelope(response, p.adapter.now())
		if err != nil {
			return nil, err
		}
		var metadata struct {
			ResultInfo *struct {
				Page       int `json:"page"`
				PerPage    int `json:"per_page"`
				Count      int `json:"count"`
				TotalCount int `json:"total_count"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		var records []cloudflareRecord
		if decodeJSON(response.body, &metadata) != nil || metadata.ResultInfo == nil ||
			decodeJSON(envelope.Result, &records) != nil || metadata.ResultInfo.Page != page ||
			metadata.ResultInfo.Count != len(records) {
			return nil, malformedProviderResponse()
		}
		if metadata.ResultInfo.TotalCount == 0 && page == 1 &&
			metadata.ResultInfo.PerPage == recoveryPageSize && len(records) == 0 &&
			metadata.ResultInfo.TotalPages == 0 {
			return nil, nil
		}
		totalPages, err := validateNumberedRecoveryPage(
			metadata.ResultInfo.TotalCount, page, metadata.ResultInfo.PerPage, len(records),
		)
		if err != nil || metadata.ResultInfo.TotalPages != totalPages || total >= 0 && total != metadata.ResultInfo.TotalCount {
			return nil, malformedProviderResponse()
		}
		total = metadata.ResultInfo.TotalCount
		candidates := make([]txtCandidate, 0, len(records))
		for _, record := range records {
			candidates = append(candidates, txtCandidate{
				id: record.ID, zoneID: record.ZoneID, owner: record.Name,
				recordType: record.Type, value: record.Content,
			})
		}
		matches, err = appendTXTHandles(matches, providerCloudflare, config.ZoneName, owner, exactValue, candidates, seen)
		if err != nil || len(matches) > 1 || page == totalPages {
			return matches, err
		}
	}
	return nil, malformedProviderResponse()
}

func (p *aliyunProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) ([]recordHandle, error) {
	var matches []recordHandle
	seen := make(map[string]struct{})
	total := -1
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		body, err := p.request(ctx, config, map[string]string{
			"Action": "DescribeDomainRecords", "DomainName": config.ZoneName, "RRKeyWord": relative,
			"TypeKeyWord": "TXT", "PageNumber": strconv.Itoa(pageNumber),
			"PageSize": strconv.Itoa(recoveryPageSize),
		})
		if err != nil {
			return nil, err
		}
		var page struct {
			TotalCount, PageNumber, PageSize int
			DomainRecords                    struct {
				Records []struct {
					RecordID, RR, Type, Value string
				} `json:"Record"`
			} `json:"DomainRecords"`
		}
		if err := decodeJSON(body, &page); err != nil || page.PageNumber != pageNumber {
			return nil, malformedProviderResponse()
		}
		totalPages, err := validateNumberedRecoveryPage(page.TotalCount, pageNumber, page.PageSize,
			len(page.DomainRecords.Records))
		if err != nil || total >= 0 && total != page.TotalCount {
			return nil, malformedProviderResponse()
		}
		total = page.TotalCount
		candidates := make([]txtCandidate, 0, len(page.DomainRecords.Records))
		for _, record := range page.DomainRecords.Records {
			candidates = append(candidates, txtCandidate{
				id: record.RecordID, zoneID: config.ZoneName,
				owner: ownerFromRelative(record.RR, config.ZoneName), recordType: record.Type, value: record.Value,
			})
		}
		matches, err = appendTXTHandles(matches, providerAliyun, config.ZoneName, owner, exactValue, candidates, seen)
		if err != nil || len(matches) > 1 || pageNumber == totalPages {
			return matches, err
		}
	}
	return nil, malformedProviderResponse()
}

func (p *huaweiProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, _ string,
	exactValue string) ([]recordHandle, error) {
	zoneID, err := p.zoneID(ctx, config)
	if err != nil {
		return nil, err
	}
	record, values, exists, err := p.recordSetByOwner(ctx, config, zoneID, owner)
	if err != nil || !exists {
		return nil, err
	}
	for _, value := range values {
		if value == exactValue {
			handle, err := newHuaweiRecordHandle(config, zoneID, owner, record.ID, exactValue, values)
			if err != nil {
				return nil, err
			}
			return []recordHandle{handle}, nil
		}
	}
	return nil, nil
}

func (p *dnsPodProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) ([]recordHandle, error) {
	var matches []recordHandle
	seen := make(map[string]struct{})
	for pageNumber := 1; pageNumber <= recoveryMaxPages+1; pageNumber++ {
		boundaryProbe := pageNumber == recoveryMaxPages+1
		offset := (pageNumber - 1) * recoveryPageSize
		length := recoveryPageSize
		if boundaryProbe {
			offset = recoveryMaxItems
			length = 1
		}
		credentials := providerCredentials(config, "dp_id", "dp_key")
		form := url.Values{
			"error_on_empty": {"no"}, "format": {"json"}, "lang": {"en"},
			"login_token": {credentials[0] + "," + credentials[1]}, "domain": {config.ZoneName},
			"sub_domain": {relative}, "record_type": {"TXT"}, "offset": {strconv.Itoa(offset)},
			"length": {strconv.Itoa(length)},
		}
		headers := make(http.Header)
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := p.adapter.http.do(ctx, http.MethodPost, p.adapter.endpoints.dnspod,
			"/Record.List", []byte(form.Encode()), headers)
		if err != nil {
			return nil, err
		}
		if err := classifyHTTP(response, p.adapter.now()); err != nil {
			return nil, err
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
		if response.status != http.StatusOK || decodeJSON(response.body, &envelope) != nil ||
			envelope.Status == nil || envelope.Status.Code == "" {
			return nil, malformedProviderResponse()
		}
		switch envelope.Status.Code {
		case "1":
			if envelope.Info == nil {
				return nil, malformedProviderResponse()
			}
		case "-1", "-7", "-8", "85":
			return nil, failure(CodeCredentialsRejected, false)
		case "-2":
			return nil, rateLimitFailure(response.header.Get("Retry-After"), p.adapter.now())
		case "-99":
			return nil, failure(CodeUnavailable, true)
		case "10":
			return matches, nil
		default:
			return nil, malformedProviderResponse()
		}
		var rawRecords []json.RawMessage
		count, countErr := strconv.Atoi(string(envelope.Info.RecordsNum))
		if decodeJSON(envelope.Records, &rawRecords) != nil || countErr != nil || count != len(rawRecords) ||
			len(rawRecords) > length {
			return nil, malformedProviderResponse()
		}
		records := make([]reconcileRecord, 0, len(rawRecords))
		for _, rawRecord := range rawRecords {
			record, err := decodeDNSPodRecord(rawRecord)
			if err != nil {
				return nil, err
			}
			records = append(records, record)
		}
		if boundaryProbe {
			if len(records) == 0 {
				return matches, nil
			}
			return nil, malformedProviderResponse()
		}
		candidates := make([]txtCandidate, 0, len(records))
		for _, record := range records {
			candidates = append(candidates, txtCandidate{
				id: string(record.ID), zoneID: config.ZoneName,
				owner: ownerFromRelative(record.Name, config.ZoneName), recordType: record.Type, value: record.Value,
			})
		}
		matches, err = appendTXTHandles(matches, providerDNSPodCN, config.ZoneName, owner, exactValue, candidates, seen)
		if err != nil || len(matches) > 1 || len(records) < recoveryPageSize {
			return matches, err
		}
	}
	return matches, nil
}

func (p *dnsComProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) ([]recordHandle, error) {
	var matches []recordHandle
	seen := make(map[string]struct{})
	total := -1
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		envelope, err := p.request(ctx, config, dnsComRecordListPath, map[string]string{
			"domain": config.ZoneName, "record": relative, "type": "TXT",
			"page": strconv.Itoa(pageNumber), "paginate": strconv.Itoa(recoveryPageSize),
		})
		if err != nil {
			return nil, err
		}
		var page struct {
			Total int            `json:"total"`
			List  []dnsComRecord `json:"data"`
		}
		if err := decodeJSON(envelope.Data, &page); err != nil || !dnsComListHasData(envelope.Data) {
			return nil, malformedProviderResponse()
		}
		totalPages, err := validateNumberedRecoveryPage(page.Total, pageNumber, recoveryPageSize, len(page.List))
		if err != nil || total >= 0 && total != page.Total {
			return nil, malformedProviderResponse()
		}
		total = page.Total
		candidates := make([]txtCandidate, 0, len(page.List))
		for _, record := range page.List {
			candidates = append(candidates, txtCandidate{
				id: string(record.RecordID), zoneID: string(record.DomainID),
				owner: ownerFromRelative(record.Record, config.ZoneName), recordType: record.Type, value: record.Value,
			})
		}
		matches, err = appendTXTHandles(matches, providerDNSCom, config.ZoneName, owner, exactValue, candidates, seen)
		if err != nil || len(matches) > 1 || pageNumber == totalPages {
			return matches, err
		}
	}
	return nil, malformedProviderResponse()
}

func (p *dnsLAProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) ([]recordHandle, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return nil, err
	}
	var matches []recordHandle
	seen := make(map[string]struct{})
	total := -1
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		query := url.Values{
			"pageIndex": {strconv.Itoa(pageNumber)}, "pageSize": {strconv.Itoa(recoveryPageSize)},
			"domainId": {domainID}, "type": {"16"}, "host": {relative}, "data": {exactValue},
		}
		envelope, err := p.request(ctx, config, http.MethodGet, "/api/recordList?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Total   *int64        `json:"total"`
			Results []dnsLARecord `json:"results"`
		}
		if err := decodeJSON(envelope.Data, &page); err != nil || page.Total == nil || *page.Total > recoveryMaxItems {
			return nil, malformedProviderResponse()
		}
		totalPages, err := validateNumberedRecoveryPage(int(*page.Total), pageNumber,
			recoveryPageSize, len(page.Results))
		if err != nil || total >= 0 && total != int(*page.Total) {
			return nil, malformedProviderResponse()
		}
		total = int(*page.Total)
		candidates := make([]txtCandidate, 0, len(page.Results))
		for _, record := range page.Results {
			recordType := ""
			if record.Type == 16 {
				recordType = "TXT"
			}
			candidates = append(candidates, txtCandidate{
				id: string(record.ID), zoneID: string(record.DomainID),
				owner: ownerFromRelative(record.Host, config.ZoneName), recordType: recordType, value: record.Data,
			})
		}
		matches, err = appendTXTHandles(matches, providerDNSLA, config.ZoneName, owner, exactValue, candidates, seen)
		if err != nil || len(matches) > 1 || pageNumber == totalPages {
			return matches, err
		}
	}
	return nil, malformedProviderResponse()
}

var _ TXTRecovery = (*Adapter)(nil)
