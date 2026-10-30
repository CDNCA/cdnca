package dnsproviderremote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

const dnsLARecordPageSize = 100

type dnsLAProvider struct{ adapter *Adapter }

type dnsLAEnvelope struct {
	Code *int            `json:"code"`
	Data json.RawMessage `json:"data"`
}

type dnsLARecord struct {
	ID       stringID `json:"id"`
	DomainID stringID `json:"domainId"`
	Host     string   `json:"host"`
	Type     int      `json:"type"`
	Data     string   `json:"data"`
	TTL      uint32   `json:"ttl"`
	// LineID is empty on the default line; LineCode names the line (tele, ...).
	LineID   string `json:"lineId"`
	LineCode string `json:"lineCode"`
}

func (p *dnsLAProvider) present(
	ctx context.Context,
	config ProviderConfig,
	owner string,
	relative string,
	exactValue string,
) (recordHandle, error) {
	domainID, err := p.domainID(ctx, config)
	if err != nil {
		return recordHandle{}, err
	}
	payload, err := json.Marshal(struct {
		DomainID string `json:"domainId"`
		Type     int    `json:"type"`
		Host     string `json:"host"`
		Data     string `json:"data"`
		TTL      int    `json:"ttl"`
	}{DomainID: domainID, Type: 16, Host: relative, Data: exactValue, TTL: 600})
	if err != nil {
		return recordHandle{}, malformedProviderResponse()
	}
	envelope, err := p.request(ctx, config, http.MethodPost, "/api/record", payload)
	if err != nil {
		return recordHandle{}, err
	}
	var created struct {
		ID stringID `json:"id"`
	}
	if err := decodeJSON(envelope.Data, &created); err != nil || !validReference(string(created.ID), 256) {
		return recordHandle{}, malformedProviderResponse()
	}
	handle := recordHandle{
		Provider: providerDNSLA, Zone: config.ZoneName, ZoneID: domainID,
		RecordID: string(created.ID), Owner: owner,
	}
	remote, exists, err := p.get(ctx, config, handle, exactValue)
	if err != nil {
		return recordHandle{}, err
	}
	if !exists || !matchesRecord(remote, handle, exactValue) {
		return recordHandle{}, malformedProviderResponse()
	}
	return handle, nil
}

func (p *dnsLAProvider) get(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
	exactValue string,
) (remoteRecord, bool, error) {
	_, relative, err := ownerAndRelative(handle.Owner, handle.Zone)
	if err != nil {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	seen := make(map[string]struct{})
	total := int64(-1)
	found := false
	for pageNumber := 1; pageNumber <= recoveryMaxPages; pageNumber++ {
		query := url.Values{
			"pageIndex": {strconv.Itoa(pageNumber)}, "pageSize": {strconv.Itoa(dnsLARecordPageSize)},
			"domainId": {handle.ZoneID}, "type": {"16"}, "host": {relative}, "data": {exactValue},
		}
		envelope, err := p.request(ctx, config, http.MethodGet, "/api/recordList?"+query.Encode(), nil)
		if err != nil {
			return remoteRecord{}, false, err
		}
		var page struct {
			Total   *int64        `json:"total"`
			Results []dnsLARecord `json:"results"`
		}
		if err := decodeJSON(envelope.Data, &page); err != nil || page.Total == nil ||
			*page.Total < 0 || *page.Total > recoveryMaxItems {
			return remoteRecord{}, false, malformedProviderResponse()
		}
		totalPages, pageErr := validateNumberedRecoveryPage(int(*page.Total), pageNumber,
			dnsLARecordPageSize, len(page.Results))
		if pageErr != nil || total >= 0 && total != *page.Total {
			return remoteRecord{}, false, malformedProviderResponse()
		}
		total = *page.Total
		for _, record := range page.Results {
			recordID := string(record.ID)
			if !validReference(recordID, 256) || string(record.DomainID) != handle.ZoneID ||
				ownerFromRelative(record.Host, handle.Zone) != handle.Owner || record.Type != 16 ||
				record.Data != exactValue || record.TTL != 600 {
				return remoteRecord{}, false, malformedProviderResponse()
			}
			if _, duplicate := seen[recordID]; duplicate {
				return remoteRecord{}, false, failure(CodeRecordMismatch, false)
			}
			seen[recordID] = struct{}{}
			found = found || recordID == handle.RecordID
		}
		if pageNumber == totalPages {
			if found {
				return remoteRecord{Owner: handle.Owner, Type: "TXT", Value: exactValue}, true, nil
			}
			return remoteRecord{}, false, nil
		}
	}
	return remoteRecord{}, false, malformedProviderResponse()
}

func (p *dnsLAProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	query := url.Values{"id": {handle.RecordID}}
	_, err := p.request(ctx, config, http.MethodDelete, "/api/record?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	return nil
}

func (p *dnsLAProvider) domainID(ctx context.Context, config ProviderConfig) (string, error) {
	query := url.Values{"domain": {config.ZoneName}}
	envelope, err := p.request(ctx, config, http.MethodGet, "/api/domain?"+query.Encode(), nil)
	if err != nil {
		return "", err
	}
	var domain struct {
		ID     stringID `json:"id"`
		Domain string   `json:"domain"`
	}
	if err := decodeJSON(envelope.Data, &domain); err != nil || !validReference(string(domain.ID), 256) ||
		canonicalDNSName(domain.Domain, false) != config.ZoneName {
		return "", malformedProviderResponse()
	}
	return string(domain.ID), nil
}

func (p *dnsLAProvider) request(
	ctx context.Context,
	config ProviderConfig,
	method string,
	path string,
	payload []byte,
) (dnsLAEnvelope, error) {
	headers := make(http.Header)
	credentials := providerCredentials(config, "api_id", "api_secret")
	headers.Set("Authorization", "Basic "+basicAuth(credentials[0], credentials[1]))
	if len(payload) > 0 {
		headers.Set("Content-Type", "application/json; charset=utf-8")
	}
	response, err := p.adapter.http.do(ctx, method, p.adapter.endpoints.dnsla, path, payload, headers)
	if err != nil {
		return dnsLAEnvelope{}, err
	}
	var envelope dnsLAEnvelope
	decoded := decodeJSON(response.body, &envelope) == nil && envelope.Code != nil
	if decoded && *envelope.Code == http.StatusInternalServerError {
		return dnsLAEnvelope{}, failure(CodeUnavailable, true)
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return dnsLAEnvelope{}, err
	}
	if response.status != http.StatusOK || !decoded {
		return dnsLAEnvelope{}, malformedProviderResponse()
	}
	if *envelope.Code != http.StatusOK {
		return dnsLAEnvelope{}, malformedProviderResponse()
	}
	return envelope, nil
}

func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}
