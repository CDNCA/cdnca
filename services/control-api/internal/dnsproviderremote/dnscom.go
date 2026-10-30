package dnsproviderremote

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type dnsComProvider struct{ adapter *Adapter }

// dnsComRecordListPath is 解析列表 (docs/12/14): paged by page + paginate,
// the records in data.data beside data.total.
const dnsComRecordListPath = "/api/record/lists/"

// dnsComListHasData reports whether a 解析列表 result carries the data key
// (null or [] is an empty page; a missing key, e.g. the old "list" shape, is
// a malformed response rather than an empty zone).
func dnsComListHasData(raw json.RawMessage) bool {
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return false
	}
	_, ok := keys["data"]
	return ok
}

type dnsComEnvelope struct {
	Code *int            `json:"code"`
	Data json.RawMessage `json:"data"`
}

type dnsComRecord struct {
	DomainID stringID       `json:"domain_id"`
	RecordID stringID       `json:"record_id"`
	Record   string         `json:"record"`
	Type     string         `json:"type"`
	Value    string         `json:"value"`
	TTL      uint32         `json:"ttl"`
	ViewID   dnsComFlexText `json:"view_id"`
}

func (p *dnsComProvider) present(
	ctx context.Context,
	config ProviderConfig,
	owner string,
	relative string,
	exactValue string,
) (recordHandle, error) {
	envelope, err := p.request(ctx, config, "/api/record/create/", map[string]string{
		"domain": config.ZoneName, "record": relative, "type": "TXT", "value": exactValue, "ttl": "600",
	})
	if err != nil {
		return recordHandle{}, err
	}
	record, err := decodeDNSComRecord(envelope.Data)
	if err != nil || record.Record != relative || record.Type != "TXT" || record.Value != exactValue || record.TTL != 600 {
		return recordHandle{}, malformedProviderResponse()
	}
	handle := recordHandle{
		Provider: providerDNSCom, Zone: config.ZoneName, ZoneID: string(record.DomainID),
		RecordID: string(record.RecordID), Owner: owner,
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

func (p *dnsComProvider) get(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
	_ string,
) (remoteRecord, bool, error) {
	envelope, err := p.request(ctx, config, "/api/record/getOne/", map[string]string{
		"domain": handle.ZoneID, "record_id": handle.RecordID,
	})
	if err != nil {
		return remoteRecord{}, false, err
	}
	record, err := decodeDNSComRecord(envelope.Data)
	if err != nil || string(record.DomainID) != handle.ZoneID || string(record.RecordID) != handle.RecordID || record.TTL != 600 {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	return remoteRecord{
		Owner: ownerFromRelative(record.Record, handle.Zone), Type: record.Type, Value: record.Value,
	}, true, nil
}

func (p *dnsComProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	_, err := p.request(ctx, config, "/api/record/operate/", map[string]string{
		"domain": handle.ZoneID, "record_id": handle.RecordID, "status": "delete",
	})
	if err != nil {
		return err
	}
	return nil
}

func (p *dnsComProvider) request(
	ctx context.Context,
	config ProviderConfig,
	path string,
	parameters map[string]string,
) (dnsComEnvelope, error) {
	credentials := providerCredentials(config, "api_key", "api_secret")
	requestParameters := make(map[string]string, len(parameters)+2)
	for name, value := range parameters {
		requestParameters[name] = value
	}
	requestParameters["api_key"] = credentials[0]
	requestParameters["timestamp"] = strconv.FormatInt(p.adapter.now().UTC().Unix(), 10)
	query := make(url.Values, len(requestParameters)+1)
	for name, value := range requestParameters {
		query.Set(name, value)
	}
	query.Set("sign", signDNSCom(requestParameters, credentials[1]))
	response, err := p.adapter.http.do(
		ctx, http.MethodGet, p.adapter.endpoints.dnscom, path+"?"+query.Encode(), nil, nil,
	)
	if err != nil {
		return dnsComEnvelope{}, err
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return dnsComEnvelope{}, err
	}
	var envelope dnsComEnvelope
	if response.status != http.StatusOK || decodeJSON(response.body, &envelope) != nil || envelope.Code == nil {
		return dnsComEnvelope{}, malformedProviderResponse()
	}
	if *envelope.Code != 0 {
		return dnsComEnvelope{}, &dnsComRefusal{cause: failure(CodeInvalidResponse, false)}
	}
	return envelope, nil
}

// dnsComRefusal is a well-formed response with a non-zero code (DNS.COM
// documents only 0 success / 1 failure). It classifies as invalid response;
// a line write refused this way is read as "line not in plan".
type dnsComRefusal struct{ cause *Error }

func (refusal *dnsComRefusal) Error() string { return refusal.cause.Error() }

func (refusal *dnsComRefusal) Unwrap() error { return refusal.cause }

func decodeDNSComRecord(raw json.RawMessage) (dnsComRecord, error) {
	var record dnsComRecord
	if err := decodeJSON(raw, &record); err != nil || !validReference(string(record.DomainID), 256) ||
		!validReference(string(record.RecordID), 256) || record.Record == "" ||
		strings.ContainsAny(record.Record, "\r\n\x00") {
		return dnsComRecord{}, malformedProviderResponse()
	}
	return record, nil
}

func signDNSCom(parameters map[string]string, secret string) string {
	keys := make([]string, 0, len(parameters))
	for name := range parameters {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, name := range keys {
		parts = append(parts, name+"="+parameters[name])
	}
	digest := md5.Sum([]byte(strings.Join(parts, "&") + secret))
	return hex.EncodeToString(digest[:])
}

func ownerFromRelative(relative, zone string) string {
	if relative == "@" {
		return zone + "."
	}
	return relative + "." + zone + "."
}
