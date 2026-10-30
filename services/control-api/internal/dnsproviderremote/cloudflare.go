package dnsproviderremote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

type cloudflareProvider struct{ adapter *Adapter }

type cloudflareEnvelope struct {
	Success    bool            `json:"success"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       *int `json:"page"`
		PerPage    *int `json:"per_page"`
		Count      *int `json:"count"`
		TotalCount *int `json:"total_count"`
		TotalPages *int `json:"total_pages"`
	} `json:"result_info"`
	Errors []struct {
		Code int `json:"code"`
	} `json:"errors"`
}

type cloudflareRecord struct {
	ID      string `json:"id"`
	ZoneID  string `json:"zone_id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

// cloudflareRecordInZone accepts record bodies without zone_id: current
// Cloudflare responses omit it and the request path already scopes the zone.
// A present but different zone_id still marks a cross-zone answer.
func cloudflareRecordInZone(recordZoneID, zoneID string) bool {
	return recordZoneID == "" || recordZoneID == zoneID
}

func (p *cloudflareProvider) present(
	ctx context.Context,
	config ProviderConfig,
	owner string,
	_ string,
	exactValue string,
) (recordHandle, error) {
	zoneID, err := p.zoneID(ctx, config)
	if err != nil {
		return recordHandle{}, err
	}
	payload, err := json.Marshal(struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}{Type: "TXT", Name: owner, Content: exactValue, TTL: 60})
	if err != nil {
		return recordHandle{}, malformedProviderResponse()
	}
	response, err := p.request(
		ctx,
		http.MethodPost,
		"/zones/"+url.PathEscape(zoneID)+"/dns_records",
		config.Credentials["api_token"],
		payload,
	)
	if err != nil {
		return recordHandle{}, err
	}
	var record cloudflareRecord
	if err := decodeJSON(response.Result, &record); err != nil || !validReference(record.ID, 256) ||
		!cloudflareRecordInZone(record.ZoneID, zoneID) || record.Type != "TXT" ||
		canonicalDNSName(record.Name, true) != owner || record.Content != exactValue {
		return recordHandle{}, malformedProviderResponse()
	}
	return recordHandle{
		Provider: providerCloudflare, Zone: config.ZoneName, ZoneID: zoneID, RecordID: record.ID, Owner: owner,
	}, nil
}

func (p *cloudflareProvider) get(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
	_ string,
) (remoteRecord, bool, error) {
	response, err := p.adapter.http.do(
		ctx,
		http.MethodGet,
		p.adapter.endpoints.cloudflare,
		"/zones/"+url.PathEscape(handle.ZoneID)+"/dns_records/"+url.PathEscape(handle.RecordID),
		nil,
		cloudflareHeaders(config.Credentials["api_token"]),
	)
	if err != nil {
		return remoteRecord{}, false, err
	}
	if response.status == http.StatusNotFound {
		if err := cloudflare404ResponseError(response, p.adapter.now()); err != nil {
			return remoteRecord{}, false, err
		}
		return remoteRecord{}, false, nil
	}
	if err := cloudflareResponseError(response, p.adapter.now()); err != nil {
		return remoteRecord{}, false, err
	}
	envelope, err := decodeCloudflareEnvelope(response, p.adapter.now())
	if err != nil {
		return remoteRecord{}, false, err
	}
	var record cloudflareRecord
	if err := decodeJSON(envelope.Result, &record); err != nil || record.ID != handle.RecordID ||
		!cloudflareRecordInZone(record.ZoneID, handle.ZoneID) {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	return remoteRecord{Owner: record.Name, Type: record.Type, Value: record.Content}, true, nil
}

func (p *cloudflareProvider) delete(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
) error {
	response, err := p.adapter.http.do(
		ctx,
		http.MethodDelete,
		p.adapter.endpoints.cloudflare,
		"/zones/"+url.PathEscape(handle.ZoneID)+"/dns_records/"+url.PathEscape(handle.RecordID),
		nil,
		cloudflareHeaders(config.Credentials["api_token"]),
	)
	if err != nil {
		return err
	}
	if response.status == http.StatusNotFound {
		if err := cloudflare404ResponseError(response, p.adapter.now()); err != nil {
			return err
		}
		return nil
	}
	if err := cloudflareResponseError(response, p.adapter.now()); err != nil {
		return err
	}
	envelope, err := decodeCloudflareEnvelope(response, p.adapter.now())
	if err != nil {
		return err
	}
	var result struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(envelope.Result, &result); err != nil || result.ID != handle.RecordID {
		return malformedProviderResponse()
	}
	return nil
}

func (p *cloudflareProvider) zoneID(ctx context.Context, config ProviderConfig) (string, error) {
	query := url.Values{"name": {config.ZoneName}, "page": {"1"}, "per_page": {"2"}}
	response, err := p.request(
		ctx,
		http.MethodGet,
		"/zones?"+query.Encode(),
		config.Credentials["api_token"],
		nil,
	)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := decodeJSON(response.Result, &zones); err != nil || len(zones) != 1 ||
		!validReference(zones[0].ID, 256) || canonicalDNSName(zones[0].Name, false) != config.ZoneName {
		return "", malformedProviderResponse()
	}
	info := response.ResultInfo
	if info == nil {
		return zones[0].ID, nil
	}
	if info.Page == nil || info.PerPage == nil || info.Count == nil ||
		info.TotalCount == nil || info.TotalPages == nil {
		return "", malformedProviderResponse()
	}
	if *info.Page != 1 || *info.PerPage != 2 || *info.Count != len(zones) ||
		*info.TotalCount != len(zones) || *info.TotalPages != 1 {
		return "", failure(CodeRecordMismatch, false)
	}
	return zones[0].ID, nil
}

func (p *cloudflareProvider) request(
	ctx context.Context,
	method string,
	path string,
	token string,
	payload []byte,
) (cloudflareEnvelope, error) {
	headers := cloudflareHeaders(token)
	if len(payload) > 0 {
		headers.Set("Content-Type", "application/json")
	}
	response, err := p.adapter.http.do(ctx, method, p.adapter.endpoints.cloudflare, path, payload, headers)
	if err != nil {
		return cloudflareEnvelope{}, err
	}
	if err := cloudflareResponseError(response, p.adapter.now()); err != nil {
		return cloudflareEnvelope{}, err
	}
	return decodeCloudflareEnvelope(response, p.adapter.now())
}

func cloudflareResponseError(response httpResponse, now time.Time) error {
	if err := cloudflareKnownResponseError(response, now); err != nil {
		return err
	}
	return classifyHTTP(response, now)
}

func decodeCloudflareEnvelope(response httpResponse, now time.Time) (cloudflareEnvelope, error) {
	var envelope cloudflareEnvelope
	if err := decodeJSON(response.body, &envelope); err != nil {
		return cloudflareEnvelope{}, err
	}
	if err := cloudflareKnownEnvelopeError(envelope, response.header, now); err != nil {
		return cloudflareEnvelope{}, err
	}
	if response.status != http.StatusOK || !envelope.Success || len(envelope.Result) == 0 {
		return cloudflareEnvelope{}, malformedProviderResponse()
	}
	return envelope, nil
}

func cloudflareKnownResponseError(response httpResponse, now time.Time) error {
	if len(response.body) == 0 {
		return nil
	}
	var envelope cloudflareEnvelope
	if decodeJSON(response.body, &envelope) != nil {
		return nil
	}
	return cloudflareKnownEnvelopeError(envelope, response.header, now)
}

func cloudflare404ResponseError(response httpResponse, now time.Time) error {
	if len(response.body) == 0 {
		return malformedProviderResponse()
	}
	var envelope cloudflareEnvelope
	if decodeJSON(response.body, &envelope) != nil {
		return malformedProviderResponse()
	}
	if err := cloudflareKnownEnvelopeError(envelope, response.header, now); err != nil {
		return err
	}
	if len(envelope.Errors) == 1 && envelope.Errors[0].Code == 81044 {
		return nil
	}
	return malformedProviderResponse()
}

func cloudflareKnownEnvelopeError(envelope cloudflareEnvelope, header http.Header, now time.Time) error {
	rateLimited := false
	for _, providerError := range envelope.Errors {
		if providerError.Code == 9109 || providerError.Code == 10000 {
			return failure(CodeCredentialsRejected, false)
		}
		if providerError.Code == 1015 {
			rateLimited = true
		}
	}
	if rateLimited {
		return rateLimitFailure(header.Get("Retry-After"), now)
	}
	return nil
}

func cloudflareHeaders(token string) http.Header {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	return headers
}
