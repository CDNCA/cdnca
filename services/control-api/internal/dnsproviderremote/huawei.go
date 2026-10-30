package dnsproviderremote

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	huaweiTimestampLayout  = "20060102T150405Z"
	huaweiSigningAlgorithm = "SDK-HMAC-SHA256"
	huaweiRecordIDPrefix   = "hw1."
)

type huaweiProvider struct{ adapter *Adapter }

type huaweiRecordSet struct {
	ID      string   `json:"id"`
	ZoneID  string   `json:"zone_id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     uint32   `json:"ttl"`
	Records []string `json:"records"`
	// Line is the resolution line ID of a public record set; responses
	// without it are on the default line.
	Line string `json:"line"`
	Page int    `json:"-"`
}

func (p *huaweiProvider) present(
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
	record, values, exists, err := p.recordSetByOwner(ctx, config, zoneID, owner)
	if err != nil {
		return recordHandle{}, err
	}
	if exists {
		for _, value := range values {
			if value == exactValue {
				return newHuaweiRecordHandle(config, zoneID, owner, record.ID, exactValue, values)
			}
		}
		return recordHandle{}, failure(CodeRecordMismatch, false)
	}

	payload, err := json.Marshal(struct {
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		TTL     int      `json:"ttl"`
		Records []string `json:"records"`
	}{Name: owner, Type: "TXT", TTL: 300, Records: []string{strconv.Quote(exactValue)}})
	if err != nil {
		return recordHandle{}, malformedProviderResponse()
	}
	path := "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets"
	response, err := p.request(ctx, config, http.MethodPost, path, "", payload)
	if err != nil {
		return recordHandle{}, err
	}
	if response.status != http.StatusOK && response.status != http.StatusCreated && response.status != http.StatusAccepted {
		return recordHandle{}, malformedProviderResponse()
	}
	var created huaweiRecordSet
	if err := decodeJSON(response.body, &created); err != nil || !validReference(created.ID, 256) || created.ZoneID != zoneID ||
		!huaweiRecordMatchesValues(created, owner, []string{exactValue}) {
		return recordHandle{}, malformedProviderResponse()
	}
	path = "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets/" + url.PathEscape(created.ID)
	response, err = p.requestAllowNotFound(ctx, config, http.MethodGet, path, "", nil)
	if err != nil {
		return recordHandle{}, err
	}
	if response.status == http.StatusNotFound {
		return recordHandle{}, failure(CodeUnavailable, true)
	}
	if response.status != http.StatusOK {
		return recordHandle{}, malformedProviderResponse()
	}
	var observed huaweiRecordSet
	if err := decodeJSON(response.body, &observed); err != nil {
		return recordHandle{}, malformedProviderResponse()
	}
	if observed.ID != created.ID || observed.ZoneID != zoneID ||
		!huaweiRecordMatchesValues(observed, owner, []string{exactValue}) {
		return recordHandle{}, failure(CodeRecordMismatch, false)
	}
	return newHuaweiRecordHandle(config, zoneID, owner, observed.ID, exactValue, []string{exactValue})
}

func (p *huaweiProvider) get(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
	exactValue string,
) (remoteRecord, bool, error) {
	remoteID, ownDigest, _, legacy, err := decodeHuaweiRecordID(handle.RecordID)
	if err != nil {
		return remoteRecord{}, false, err
	}
	if !legacy && !digestMatches(ownDigest, exactValue) {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	listed, listedValues, exists, err := p.recordSetByOwner(ctx, config, handle.ZoneID, handle.Owner)
	if err != nil {
		return remoteRecord{}, false, err
	}
	if exists {
		if listed.ID != remoteID || legacy && len(listedValues) != 1 {
			return remoteRecord{}, false, failure(CodeRecordMismatch, false)
		}
		listedExact := false
		for _, value := range listedValues {
			if value == exactValue {
				listedExact = true
				break
			}
		}
		if !listedExact {
			return remoteRecord{}, false, nil
		}
	}
	path := "/v2.1/zones/" + url.PathEscape(handle.ZoneID) + "/recordsets/" + url.PathEscape(remoteID)
	response, err := p.requestAllowNotFound(ctx, config, http.MethodGet, path, "", nil)
	if err != nil {
		return remoteRecord{}, false, err
	}
	if response.status == http.StatusNotFound {
		if exists {
			return remoteRecord{}, false, failure(CodeUnavailable, true)
		}
		return remoteRecord{}, false, nil
	}
	if response.status != http.StatusOK {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	var record huaweiRecordSet
	if err := decodeJSON(response.body, &record); err != nil {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	values, ok := huaweiTXTValues(record.Records)
	if record.ID != remoteID || record.ZoneID != handle.ZoneID ||
		canonicalDNSName(record.Name, true) != handle.Owner || record.Type != "TXT" {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	if !ok {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	if legacy && (len(values) != 1 || values[0] != exactValue) {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	if !exists {
		return remoteRecord{}, false, failure(CodeUnavailable, true)
	}
	for _, value := range values {
		if value == exactValue {
			return remoteRecord{Owner: record.Name, Type: record.Type, Value: exactValue}, true, nil
		}
	}
	return remoteRecord{}, false, nil
}

func (p *huaweiProvider) delete(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
) error {
	remoteID, ownDigest, expectedDigest, legacy, err := decodeHuaweiRecordID(handle.RecordID)
	if err != nil {
		return err
	}
	if legacy {
		return failure(CodeRecordMismatch, false)
	}
	record, values, exists, err := p.recordSetByOwner(ctx, config, handle.ZoneID, handle.Owner)
	if err != nil {
		return err
	}
	if !exists {
		return failure(CodeUnavailable, true)
	}
	if record.ID != remoteID {
		return failure(CodeRecordMismatch, false)
	}
	if !huaweiValuesDigestMatches(expectedDigest, values) {
		return failure(CodeRecordMismatch, false)
	}
	match := -1
	for index, value := range values {
		if digestMatches(ownDigest, value) {
			match = index
			break
		}
	}
	if match < 0 {
		return failure(CodeRecordMismatch, false)
	}
	if len(values) == 2 {
		return failure(CodeRecordMismatch, false)
	}

	path := "/v2.1/zones/" + url.PathEscape(handle.ZoneID) + "/recordsets/" + url.PathEscape(remoteID)
	response, err := p.requestAllowNotFound(ctx, config, http.MethodDelete, path, "", nil)
	if err != nil {
		return err
	}
	if response.status != http.StatusOK && response.status != http.StatusAccepted &&
		response.status != http.StatusNoContent && response.status != http.StatusNotFound || len(response.body) != 0 {
		return malformedProviderResponse()
	}
	return nil
}

func (p *huaweiProvider) recordSetByOwner(
	ctx context.Context,
	config ProviderConfig,
	zoneID string,
	owner string,
) (huaweiRecordSet, []string, bool, error) {
	query := url.Values{
		"limit": {strconv.Itoa(recoveryPageSize)}, "offset": {"0"}, "name": {owner}, "type": {"TXT"},
		"search_mode": {"equal"},
	}
	path := "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets"
	response, err := p.request(ctx, config, http.MethodGet, path, query.Encode(), nil)
	if err != nil {
		return huaweiRecordSet{}, nil, false, err
	}
	var envelope struct {
		Recordsets []huaweiRecordSet `json:"recordsets"`
		Metadata   *struct {
			TotalCount int `json:"total_count"`
		} `json:"metadata"`
		Links *struct {
			Next string `json:"next"`
		} `json:"links"`
	}
	if response.status != http.StatusOK || decodeJSON(response.body, &envelope) != nil {
		return huaweiRecordSet{}, nil, false, malformedProviderResponse()
	}
	if envelope.Metadata == nil || envelope.Links == nil {
		var direct huaweiRecordSet
		if decodeJSON(response.body, &direct) == nil {
			values, valid := huaweiTXTValues(direct.Records)
			if valid && len(values) > 1 && validReference(direct.ID, 256) && direct.ZoneID == zoneID &&
				canonicalDNSName(direct.Name, true) == owner && direct.Type == "TXT" {
				return huaweiRecordSet{}, nil, false, failure(CodeRecordMismatch, false)
			}
		}
		return huaweiRecordSet{}, nil, false, malformedProviderResponse()
	}
	if envelope.Metadata.TotalCount < 0 || len(envelope.Recordsets) > recoveryPageSize {
		return huaweiRecordSet{}, nil, false, malformedProviderResponse()
	}
	if envelope.Metadata.TotalCount != len(envelope.Recordsets) || envelope.Links.Next != "" ||
		len(envelope.Recordsets) > 1 {
		return huaweiRecordSet{}, nil, false, failure(CodeRecordMismatch, false)
	}
	if len(envelope.Recordsets) == 0 {
		return huaweiRecordSet{}, nil, false, nil
	}
	record := envelope.Recordsets[0]
	values, ok := huaweiTXTValues(record.Records)
	if !ok || !validReference(record.ID, 256) || record.ZoneID != zoneID ||
		canonicalDNSName(record.Name, true) != owner || record.Type != "TXT" {
		return huaweiRecordSet{}, nil, false, failure(CodeRecordMismatch, false)
	}
	return record, values, true, nil
}

func (p *huaweiProvider) zoneID(ctx context.Context, config ProviderConfig) (string, error) {
	// search_mode defaults to fuzzy ("like"): a.example.com would match too.
	queryValues := url.Values{"limit": {"2"}, "name": {config.ZoneName + "."}, "type": {"public"}, "search_mode": {"equal"}}
	response, err := p.request(ctx, config, http.MethodGet, "/v2/zones", queryValues.Encode(), nil)
	if err != nil {
		return "", err
	}
	if response.status != http.StatusOK {
		return "", malformedProviderResponse()
	}
	var envelope struct {
		Zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"zones"`
		Metadata *struct {
			TotalCount int `json:"total_count"`
		} `json:"metadata"`
		Links *struct {
			Next string `json:"next"`
		} `json:"links"`
	}
	if err := decodeJSON(response.body, &envelope); err != nil || len(envelope.Zones) != 1 ||
		!validReference(envelope.Zones[0].ID, 256) ||
		canonicalDNSName(envelope.Zones[0].Name, false) != config.ZoneName {
		return "", malformedProviderResponse()
	}
	if (envelope.Metadata == nil) != (envelope.Links == nil) ||
		envelope.Metadata != nil && envelope.Metadata.TotalCount < 0 {
		return "", malformedProviderResponse()
	}
	if envelope.Metadata != nil &&
		(envelope.Metadata.TotalCount != len(envelope.Zones) || envelope.Links.Next != "") {
		return "", failure(CodeRecordMismatch, false)
	}
	return envelope.Zones[0].ID, nil
}

func (p *huaweiProvider) request(
	ctx context.Context,
	config ProviderConfig,
	method string,
	path string,
	query string,
	payload []byte,
) (httpResponse, error) {
	response, err := p.requestAllowNotFound(ctx, config, method, path, query, payload)
	if err != nil {
		return httpResponse{}, err
	}
	if response.status == http.StatusNotFound {
		return httpResponse{}, malformedProviderResponse()
	}
	return response, nil
}

func (p *huaweiProvider) requestAllowNotFound(
	ctx context.Context,
	config ProviderConfig,
	method string,
	path string,
	query string,
	payload []byte,
) (httpResponse, error) {
	credentials := providerCredentials(config, "access_key", "secret_key", "region", "project_id")
	endpoint, ok := p.adapter.endpoints.huawei[credentials[2]]
	if !ok {
		return httpResponse{}, failure(CodeInvalidInput, false)
	}
	timestamp := p.adapter.now().UTC().Format(huaweiTimestampLayout)
	canonicalURI := path
	if !strings.HasSuffix(canonicalURI, "/") {
		canonicalURI += "/"
	}
	headersToSign := map[string]string{
		"host": endpoint.host, "x-project-id": credentials[3], "x-sdk-date": timestamp,
	}
	authorization := signHuaweiRequest(
		method, canonicalURI, query, headersToSign, payload, credentials[0], credentials[1], timestamp,
	)
	headers := make(http.Header)
	headers.Set("Authorization", authorization)
	headers.Set("X-Project-Id", credentials[3])
	headers.Set("X-Sdk-Date", timestamp)
	if len(payload) > 0 {
		headers.Set("Content-Type", "application/json")
	}
	pathAndQuery := path
	if query != "" {
		pathAndQuery += "?" + query
	}
	response, err := p.adapter.http.do(ctx, method, endpoint, pathAndQuery, payload, headers)
	if err != nil {
		return httpResponse{}, err
	}
	if response.status == http.StatusNotFound || response.status == http.StatusNoContent {
		if len(response.body) != 0 {
			return httpResponse{}, malformedProviderResponse()
		}
		return response, nil
	}
	var providerError struct {
		ErrorCode string `json:"error_code"`
	}
	var decodeErr error
	if len(response.body) > 0 {
		decodeErr = decodeJSON(response.body, &providerError)
		if decodeErr == nil && strings.HasPrefix(providerError.ErrorCode, "APIGW.03") {
			return httpResponse{}, failure(CodeCredentialsRejected, false)
		}
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return httpResponse{}, err
	}
	if decodeErr != nil {
		return httpResponse{}, decodeErr
	}
	if len(response.body) > 0 {
		if providerError.ErrorCode != "" {
			return httpResponse{}, malformedProviderResponse()
		}
	}
	return response, nil
}

func signHuaweiRequest(
	method string,
	canonicalURI string,
	canonicalQuery string,
	headers map[string]string,
	payload []byte,
	accessKey string,
	secretKey string,
	timestamp string,
) string {
	headerNames := make([]string, 0, len(headers))
	canonicalHeaders := make(map[string]string, len(headers))
	for name, value := range headers {
		name = strings.ToLower(name)
		headerNames = append(headerNames, name)
		canonicalHeaders[name] = strings.TrimSpace(value)
	}
	sort.Strings(headerNames)
	headerLines := make([]string, 0, len(headerNames))
	for _, name := range headerNames {
		headerLines = append(headerLines, name+":"+canonicalHeaders[name])
	}
	signedHeaders := strings.Join(headerNames, ";")
	payloadDigest := sha256.Sum256(payload)
	canonicalRequest := fmt.Sprintf(
		"%s\n%s\n%s\n%s\n\n%s\n%s",
		method, canonicalURI, canonicalQuery, strings.Join(headerLines, "\n"), signedHeaders,
		hex.EncodeToString(payloadDigest[:]),
	)
	canonicalDigest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := huaweiSigningAlgorithm + "\n" + timestamp + "\n" + hex.EncodeToString(canonicalDigest[:])
	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(stringToSign))
	return fmt.Sprintf(
		"%s Access=%s, SignedHeaders=%s, Signature=%s",
		huaweiSigningAlgorithm, accessKey, signedHeaders, hex.EncodeToString(mac.Sum(nil)),
	)
}

func newHuaweiRecordHandle(
	config ProviderConfig,
	zoneID string,
	owner string,
	remoteID string,
	exactValue string,
	values []string,
) (recordHandle, error) {
	recordID, err := encodeHuaweiRecordID(remoteID, exactValue, values)
	if err != nil {
		return recordHandle{}, err
	}
	return recordHandle{
		Provider: providerHuawei, Zone: config.ZoneName, ZoneID: zoneID, RecordID: recordID, Owner: owner,
	}, nil
}

func encodeHuaweiRecordID(remoteID, exactValue string, values []string) (string, error) {
	canonical, ok := canonicalHuaweiTXTValues(values)
	if !validReference(remoteID, 256) || !validExactValue(exactValue) || !ok {
		return "", failure(CodeInvalidResponse, false)
	}
	recordID := huaweiRecordIDPrefix + base64.RawURLEncoding.EncodeToString([]byte(remoteID)) + "." +
		digestText(exactValue) + "." + digestText(strings.Join(canonical, "\x00"))
	if !validReference(recordID, 256) {
		return "", failure(CodeInvalidResponse, false)
	}
	return recordID, nil
}

func decodeHuaweiRecordID(recordID string) (remoteID, ownDigest, expectedDigest string, legacy bool, err error) {
	if !strings.HasPrefix(recordID, huaweiRecordIDPrefix) {
		if !validReference(recordID, 256) {
			return "", "", "", false, failure(CodeInvalidInput, false)
		}
		return recordID, "", "", true, nil
	}
	parts := strings.Split(recordID, ".")
	if len(parts) != 4 || parts[0] != strings.TrimSuffix(huaweiRecordIDPrefix, ".") ||
		!validDigest(parts[2]) || !validDigest(parts[3]) {
		return "", "", "", false, failure(CodeInvalidInput, false)
	}
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
	if decodeErr != nil || base64.RawURLEncoding.EncodeToString(decoded) != parts[1] ||
		!validReference(string(decoded), 256) {
		return "", "", "", false, failure(CodeInvalidInput, false)
	}
	return string(decoded), parts[2], parts[3], false, nil
}

func huaweiTXTValues(records []string) ([]string, bool) {
	values := make([]string, 0, len(records))
	for _, record := range records {
		value, err := strconv.Unquote(record)
		if err != nil {
			return nil, false
		}
		values = append(values, value)
	}
	return canonicalHuaweiTXTValues(values)
}

func canonicalHuaweiTXTValues(values []string) ([]string, bool) {
	if len(values) < 1 || len(values) > 2 {
		return nil, false
	}
	canonical := append([]string(nil), values...)
	sort.Strings(canonical)
	for index, value := range canonical {
		if !validExactValue(value) || index > 0 && canonical[index-1] == value {
			return nil, false
		}
	}
	return canonical, true
}

func huaweiValuesDigestMatches(encoded string, values []string) bool {
	canonical, ok := canonicalHuaweiTXTValues(values)
	return ok && digestMatches(encoded, strings.Join(canonical, "\x00"))
}

func huaweiRecordMatchesValues(record huaweiRecordSet, owner string, values []string) bool {
	actual, ok := huaweiTXTValues(record.Records)
	expected, expectedOK := canonicalHuaweiTXTValues(values)
	return ok && expectedOK && record.Type == "TXT" && canonicalDNSName(record.Name, true) == owner &&
		len(actual) == len(expected) && strings.Join(actual, "\x00") == strings.Join(expected, "\x00")
}
