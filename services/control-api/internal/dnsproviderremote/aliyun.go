package dnsproviderremote

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
)

const (
	aliyunAPIVersion      = "2015-01-09"
	aliyunTimestampLayout = "2006-01-02T15:04:05Z"
)

type aliyunProvider struct{ adapter *Adapter }

type aliyunMeta struct {
	RequestID string `json:"RequestId"`
	Code      string `json:"Code"`
}

func (p *aliyunProvider) present(
	ctx context.Context,
	config ProviderConfig,
	owner string,
	relative string,
	exactValue string,
) (recordHandle, error) {
	body, err := p.request(ctx, config, map[string]string{
		"Action": "AddDomainRecord", "DomainName": config.ZoneName, "RR": relative,
		"Type": "TXT", "Value": exactValue, "TTL": "60",
	})
	if err != nil {
		return recordHandle{}, err
	}
	var result struct {
		RequestID string `json:"RequestId"`
		RecordID  string `json:"RecordId"`
	}
	if err := decodeJSON(body, &result); err != nil || result.RequestID == "" || !validReference(result.RecordID, 256) {
		return recordHandle{}, malformedProviderResponse()
	}
	handle := recordHandle{
		Provider: providerAliyun, Zone: config.ZoneName, ZoneID: config.ZoneName,
		RecordID: result.RecordID, Owner: owner,
	}
	record, exists, err := p.get(ctx, config, handle, exactValue)
	if err != nil {
		return recordHandle{}, err
	}
	if !exists || !matchesRecord(record, handle, exactValue) {
		return recordHandle{}, malformedProviderResponse()
	}
	return handle, nil
}

func (p *aliyunProvider) get(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
	_ string,
) (remoteRecord, bool, error) {
	body, err := p.request(ctx, config, map[string]string{
		"Action": "DescribeDomainRecordInfo", "RecordId": handle.RecordID,
	})
	if isCode(err, CodeRecordNotFound) {
		return remoteRecord{}, false, nil
	}
	if err != nil {
		return remoteRecord{}, false, err
	}
	var result struct {
		RequestID string `json:"RequestId"`
		RecordID  string `json:"RecordId"`
		RR        string `json:"RR"`
		Type      string `json:"Type"`
		Value     string `json:"Value"`
		Domain    string `json:"DomainName"`
		TTL       uint32 `json:"TTL"`
	}
	if err := decodeJSON(body, &result); err != nil || result.RequestID == "" || result.RecordID != handle.RecordID {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	if result.TTL != 60 {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	owner, _, ownerErr := ownerAndRelative(handle.Owner, handle.Zone)
	if ownerErr != nil {
		return remoteRecord{}, false, malformedProviderResponse()
	}
	_, expectedRelative, _ := ownerAndRelative(owner, handle.Zone)
	if result.RR != expectedRelative || canonicalDNSName(result.Domain, false) != handle.Zone {
		owner = "invalid."
	}
	return remoteRecord{Owner: owner, Type: result.Type, Value: result.Value}, true, nil
}

func (p *aliyunProvider) delete(
	ctx context.Context,
	config ProviderConfig,
	handle recordHandle,
) error {
	body, err := p.request(ctx, config, map[string]string{
		"Action": "DeleteDomainRecord", "RecordId": handle.RecordID,
	})
	if isCode(err, CodeRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var result struct {
		RequestID string `json:"RequestId"`
		RecordID  string `json:"RecordId"`
	}
	if err := decodeJSON(body, &result); err != nil || result.RequestID == "" || result.RecordID != handle.RecordID {
		return malformedProviderResponse()
	}
	return nil
}

func (p *aliyunProvider) request(
	ctx context.Context,
	config ProviderConfig,
	actionParameters map[string]string,
) ([]byte, error) {
	credentials := providerCredentials(config, "access_key_id", "access_key_secret")
	nonce := p.adapter.nonce()
	if !validReference(nonce, 256) {
		return nil, failure(CodeUnavailable, true)
	}
	parameters := map[string]string{
		"AccessKeyId": credentials[0], "Format": "JSON", "SignatureMethod": "HMAC-SHA1",
		"SignatureNonce": nonce, "SignatureVersion": "1.0",
		"Timestamp": p.adapter.now().UTC().Format(aliyunTimestampLayout), "Version": aliyunAPIVersion,
	}
	for name, value := range actionParameters {
		parameters[name] = value
	}
	canonical := aliyunCanonicalQuery(parameters)
	mac := hmac.New(sha1.New, []byte(credentials[1]+"&"))
	_, _ = mac.Write([]byte("GET&%2F&" + aliyunPercentEncode(canonical)))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	response, err := p.adapter.http.do(
		ctx,
		http.MethodGet,
		p.adapter.endpoints.aliyun,
		"/?"+canonical+"&Signature="+aliyunPercentEncode(signature),
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	var meta aliyunMeta
	decodeErr := decodeJSON(response.body, &meta)
	if decodeErr == nil {
		if aliyunAuthenticationError(meta.Code) {
			return nil, failure(CodeCredentialsRejected, false)
		}
		if aliyunRateLimitError(meta.Code) {
			return nil, rateLimitFailure(response.header.Get("Retry-After"), p.adapter.now())
		}
		if meta.Code == "InvalidRecordId.NotFound" || meta.Code == "DomainRecordNotBelongToUser" {
			return nil, failure(CodeRecordNotFound, false)
		}
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return nil, err
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	if response.status != http.StatusOK || meta.Code != "" || meta.RequestID == "" {
		return nil, malformedProviderResponse()
	}
	return response.body, nil
}

func aliyunCanonicalQuery(parameters map[string]string) string {
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, aliyunPercentEncode(key)+"="+aliyunPercentEncode(parameters[key]))
	}
	return strings.Join(parts, "&")
}

func aliyunPercentEncode(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var encoded strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-_.~", rune(character)) {
			encoded.WriteByte(character)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hexadecimal[character>>4])
		encoded.WriteByte(hexadecimal[character&0x0f])
	}
	return encoded.String()
}

func aliyunAuthenticationError(code string) bool {
	switch code {
	case "Forbidden", "Forbidden.RAM", "IncompleteSignature", "NoPermission", "SignatureDoesNotMatch":
		return true
	default:
		return strings.HasPrefix(code, "InvalidAccessKeyId.") || strings.HasPrefix(code, "InvalidSecurityToken")
	}
}

func aliyunRateLimitError(code string) bool {
	return code == "Throttling" || strings.HasPrefix(code, "Throttling.")
}
