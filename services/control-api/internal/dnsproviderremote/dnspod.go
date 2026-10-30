package dnsproviderremote

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type dnsPodProvider struct{ adapter *Adapter }

type dnsPodEnvelope struct {
	Status *struct {
		Code string `json:"code"`
	} `json:"status"`
	Domain  json.RawMessage `json:"domain"`
	Record  json.RawMessage `json:"record"`
	Records json.RawMessage `json:"records"`
	// Domain.List (zone_apex.go).
	Info    json.RawMessage `json:"info"`
	Domains json.RawMessage `json:"domains"`
}

// dnsPodDomainListPath lists the account's domains; its code 9 means the
// account has none.
const dnsPodDomainListPath = "/Domain.List"

type dnsPodDomain struct {
	ID   stringID `json:"id"`
	Name string   `json:"domain"`
}

// dnsPodRecord is one record of Record.List ("records": name/type/line) or
// Record.Info ("record": sub_domain/record_type/record_line). dnsapi.cn
// returns id, ttl and weight as strings ("ttl":"600"); numbers are accepted
// too. Both key sets are read; when a response carries both they must agree.
type dnsPodRecord struct {
	ID         stringID     `json:"id"`
	Name       string       `json:"name"`
	SubDomain  string       `json:"sub_domain"`
	Type       string       `json:"type"`
	RecordType string       `json:"record_type"`
	Line       string       `json:"line"`
	RecordLine string       `json:"record_line"`
	Value      string       `json:"value"`
	TTL        dnsPodNumber `json:"ttl"`
	Weight     dnsPodNumber `json:"weight"`
}

// dnsPodNumber is a uint32 sent as a JSON string or number ("600" or 600);
// absent, null and "" read as 0.
type dnsPodNumber struct{ value uint32 }

func (number *dnsPodNumber) UnmarshalJSON(raw []byte) error {
	text := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
	}
	if text == "" || text == "null" {
		*number = dnsPodNumber{}
		return nil
	}
	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return errors.New("invalid number")
	}
	*number = dnsPodNumber{value: uint32(value)}
	return nil
}

// dnsPodField merges the Record.List and Record.Info spellings of one field.
func dnsPodField(list, info string) (string, bool) {
	if list != "" && info != "" && list != info {
		return "", false
	}
	if list != "" {
		return list, true
	}
	return info, true
}

// Record.Info re-reads of a just-created record (variables for tests).
var (
	dnsPodCreatedInfoRetries = 4
	dnsPodCreatedInfoDelay   = 500 * time.Millisecond
)

type dnsPodCreatedRecord struct {
	ID     stringID `json:"id"`
	Name   string   `json:"name"`
	Status string   `json:"status"`
}

func (p *dnsPodProvider) present(
	ctx context.Context,
	config ProviderConfig,
	owner string,
	relative string,
	exactValue string,
) (recordHandle, error) {
	envelope, err := p.request(ctx, config, "/Record.Create", url.Values{
		"domain": {config.ZoneName}, "sub_domain": {relative}, "record_type": {"TXT"},
		"record_line": {"默认"}, "value": {exactValue}, "ttl": {"600"},
	})
	if err != nil {
		return recordHandle{}, err
	}
	var record dnsPodCreatedRecord
	// Only the ID is trusted from the create answer (as the reconcile create
	// path does); name, type, line, value and TTL are verified by Record.Info.
	if err := decodeJSON(envelope.Record, &record); err != nil || !validReference(string(record.ID), 256) {
		return recordHandle{}, malformedProviderResponse()
	}
	// A record just created may briefly read as unknown (code 8); read again
	// before giving up so the publish does not fail on a record that exists.
	var infoEnvelope dnsPodEnvelope
	for attempt := 0; ; attempt++ {
		infoEnvelope, err = p.requestWithOptions(ctx, config, "/Record.Info", url.Values{
			"domain": {config.ZoneName}, "record_id": {string(record.ID)},
		}, true)
		if !isCode(err, CodeRecordNotFound) || attempt >= dnsPodCreatedInfoRetries {
			break
		}
		select {
		case <-ctx.Done():
			return recordHandle{}, contextFailure(ctx.Err())
		case <-time.After(dnsPodCreatedInfoDelay):
		}
	}
	if isCode(err, CodeRecordNotFound) {
		return recordHandle{}, failure(CodeUnavailable, true)
	}
	if err != nil {
		return recordHandle{}, err
	}
	domain, err := decodeDNSPodDomain(infoEnvelope.Domain)
	if err != nil {
		return recordHandle{}, err
	}
	infoRecord, err := decodeDNSPodRecord(infoEnvelope.Record)
	if err != nil {
		return recordHandle{}, err
	}
	if canonicalDNSName(domain.Name, false) != config.ZoneName || string(infoRecord.ID) != string(record.ID) ||
		infoRecord.Name != relative || infoRecord.Type != "TXT" || infoRecord.Line != "默认" ||
		infoRecord.Value != exactValue || infoRecord.TTL != 600 {
		return recordHandle{}, failure(CodeRecordMismatch, false)
	}
	return recordHandle{
		Provider: providerDNSPodCN, Zone: config.ZoneName, ZoneID: config.ZoneName,
		RecordID: string(record.ID), Owner: owner,
	}, nil
}

func (p *dnsPodProvider) get(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
	_ string,
) (remoteRecord, bool, error) {
	envelope, err := p.request(ctx, config, "/Record.Info", url.Values{
		"domain": {handle.Zone}, "record_id": {handle.RecordID},
	})
	if isCode(err, CodeRecordNotFound) {
		return remoteRecord{}, false, nil
	}
	if err != nil {
		return remoteRecord{}, false, err
	}
	domain, err := decodeDNSPodDomain(envelope.Domain)
	if err != nil || canonicalDNSName(domain.Name, false) != handle.Zone {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	record, err := decodeDNSPodRecord(envelope.Record)
	if err != nil || string(record.ID) != handle.RecordID {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	if record.Line != "默认" || record.TTL != 600 {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	owner := record.Name + "." + handle.Zone + "."
	if record.Name == "@" {
		owner = handle.Zone + "."
	}
	return remoteRecord{Owner: owner, Type: record.Type, Value: record.Value}, true, nil
}

func (p *dnsPodProvider) delete(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
) error {
	_, err := p.request(ctx, config, "/Record.Remove", url.Values{
		"domain": {handle.Zone}, "record_id": {handle.RecordID},
	})
	return err
}

func (p *dnsPodProvider) request(
	ctx context.Context,
	config ProviderConfig,
	path string,
	parameters url.Values,
) (dnsPodEnvelope, error) {
	return p.requestWithOptions(ctx, config, path, parameters, false)
}

func (p *dnsPodProvider) requestWithOptions(
	ctx context.Context,
	config ProviderConfig,
	path string,
	parameters url.Values,
	allowHTTPNotFound bool,
) (dnsPodEnvelope, error) {
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
	response, err := p.adapter.http.do(
		ctx, http.MethodPost, p.adapter.endpoints.dnspod, path, []byte(form.Encode()), headers,
	)
	if err != nil {
		return dnsPodEnvelope{}, err
	}
	var envelope dnsPodEnvelope
	decoded := decodeJSON(response.body, &envelope) == nil && envelope.Status != nil && envelope.Status.Code != ""
	if decoded {
		switch envelope.Status.Code {
		case "-1", "-7", "-8", "85":
			return dnsPodEnvelope{}, failure(CodeCredentialsRejected, false)
		case "-2":
			return dnsPodEnvelope{}, rateLimitFailure(response.header.Get("Retry-After"), p.adapter.now())
		case "-99":
			return dnsPodEnvelope{}, failure(CodeUnavailable, true)
		case "10":
			return dnsPodEnvelope{}, failure(CodeRecordNotFound, false)
		case "8":
			// dnsapi.cn answers Record.Info for a deleted or unknown
			// record_id with 8 "Incorrect record ID" (checked live
			// 2026-10-27), not 10.
			if path == "/Record.Info" {
				return dnsPodEnvelope{}, failure(CodeRecordNotFound, false)
			}
		case "13":
			// 当前域名未添加解析: the account does not host this domain.
			return dnsPodEnvelope{}, failure(CodeZoneNotHosted, false)
		case "9":
			if path == dnsPodDomainListPath {
				return dnsPodEnvelope{}, failure(CodeZoneNotHosted, false)
			}
		}
	}
	if allowHTTPNotFound && response.status == http.StatusNotFound {
		return dnsPodEnvelope{}, failure(CodeUnavailable, true)
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return dnsPodEnvelope{}, err
	}
	if !decoded {
		return dnsPodEnvelope{}, malformedProviderResponse()
	}
	switch envelope.Status.Code {
	case "1":
		if response.status != http.StatusOK {
			return dnsPodEnvelope{}, malformedProviderResponse()
		}
		return envelope, nil
	}
	return dnsPodEnvelope{}, malformedProviderResponse()
}

func decodeDNSPodDomain(raw json.RawMessage) (dnsPodDomain, error) {
	var domain dnsPodDomain
	if err := decodeJSON(raw, &domain); err != nil || !validReference(string(domain.ID), 256) ||
		canonicalDNSName(domain.Name, false) == "" {
		return dnsPodDomain{}, malformedProviderResponse()
	}
	return domain, nil
}

// decodeDNSPodRecord decodes one Record.List / Record.Info record. A missing
// line stays empty so callers decide whether that is a mismatch.
func decodeDNSPodRecord(raw json.RawMessage) (reconcileRecord, error) {
	var wire dnsPodRecord
	if err := decodeJSON(raw, &wire); err != nil || !validReference(string(wire.ID), 256) {
		return reconcileRecord{}, malformedProviderResponse()
	}
	name, nameOK := dnsPodField(wire.Name, wire.SubDomain)
	recordType, typeOK := dnsPodField(wire.Type, wire.RecordType)
	line, lineOK := dnsPodField(wire.Line, wire.RecordLine)
	if !nameOK || !typeOK || !lineOK || name == "" || strings.ContainsAny(name, "\r\n\x00") ||
		wire.Weight.value > 100 {
		return reconcileRecord{}, malformedProviderResponse()
	}
	return reconcileRecord{
		ID: string(wire.ID), Name: name, Type: recordType, Value: wire.Value,
		TTL: wire.TTL.value, Line: line, Weight: wire.Weight.value,
	}, nil
}
