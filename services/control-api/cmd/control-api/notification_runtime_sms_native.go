package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
)

// Native template SMS providers (FX33/FX66). Both send by provider template
// code: our template id is mapped to the provider template and each of our
// variables to a provider variable name. The rendered body is never sent.
const (
	notificationSMSProviderAliyun  = "aliyun"
	notificationSMSProviderSubmail = "submail"

	aliyunSMSDefaultEndpoint  = "https://dysmsapi.aliyuncs.com/"
	submailSMSDefaultEndpoint = "https://api-v4.mysubmail.com/sms/xsend"
)

type nativeSMSTemplate struct {
	Code      string            `json:"code"`
	Variables map[string]string `json:"variables"` // our variable -> provider variable
}

type nativeSMSConfig struct {
	Provider        string
	Endpoint        string // empty = official endpoint; override for tests/proxies
	CAFile          string
	AccessKeyID     string // aliyun AccessKeyId / submail appid
	AccessKeySecret []byte // aliyun AccessKeySecret / submail appkey
	SignName        string // aliyun SignName (submail signs inside the template)
	Templates       map[string]nativeSMSTemplate
}

type nativeSMSTransport struct {
	mu     sync.Mutex
	config nativeSMSConfig
	client *http.Client
	closed bool
	now    func() time.Time
}

func newNativeSMSTransport(config nativeSMSConfig) (*nativeSMSTransport, error) {
	if config.Endpoint == "" {
		config.Endpoint = aliyunSMSDefaultEndpoint
		if config.Provider == notificationSMSProviderSubmail {
			config.Endpoint = submailSMSDefaultEndpoint
		}
	}
	if !validNativeSMSConfig(config) {
		return nil, errSMSInvalid
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, errSMSInvalid
	}
	if config.CAFile != "" {
		encoded, readErr := os.ReadFile(config.CAFile)
		if readErr != nil || !roots.AppendCertsFromPEM(encoded) {
			return nil, errSMSInvalid
		}
	}
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	config.AccessKeySecret = append([]byte(nil), config.AccessKeySecret...)
	return &nativeSMSTransport{config: config, now: time.Now, client: &http.Client{
		Transport: httpTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errSMSResponseUnknown
		},
	}}, nil
}

func validNativeSMSConfig(config nativeSMSConfig) bool {
	if config.Provider != notificationSMSProviderAliyun && config.Provider != notificationSMSProviderSubmail {
		return false
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return false
	}
	if !validNativeSMSText(config.AccessKeyID, 256) || len(config.AccessKeySecret) == 0 ||
		len(config.AccessKeySecret) > 512 || strings.ContainsAny(string(config.AccessKeySecret), "\r\n\x00") {
		return false
	}
	if config.Provider == notificationSMSProviderAliyun && !validNativeSMSText(config.SignName, 64) {
		return false
	}
	for id, template := range config.Templates {
		if !validNativeSMSText(id, 96) || !validNativeSMSText(template.Code, 64) || len(template.Variables) > notification.MaxTemplateVariables {
			return false
		}
		for ours, theirs := range template.Variables {
			if !validNativeSMSText(ours, 64) || !validNativeSMSText(theirs, 64) {
				return false
			}
		}
	}
	return true
}

func validNativeSMSText(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

// Ready only checks configuration: neither provider offers a side-effect-free
// credential probe, and a test send would bill the operator.
func (transport *nativeSMSTransport) Ready(ctx context.Context) error {
	_, _, err := transport.snapshot(ctx)
	return err
}

func (transport *nativeSMSTransport) Send(ctx context.Context, message notificationruntime.ProviderMessage) (notificationruntime.ProviderResult, error) {
	if message.OutboxID == uuid.Nil || message.Channel != notification.ChannelSMS || !validSMSContact(message.Contact) ||
		message.AttemptNumber < 1 || message.IdempotencyKey == "" {
		return nativeSMSFailure(notificationruntime.ProviderPermanentFailure, "sms_message_invalid"), nil
	}
	config, client, err := transport.snapshot(ctx)
	if err != nil {
		return notificationruntime.ProviderResult{}, err
	}
	defer clear(config.AccessKeySecret)
	template, mapped := config.Templates[message.TemplateID]
	if !mapped {
		return nativeSMSFailure(notificationruntime.ProviderPermanentFailure, "sms_template_unmapped"), nil
	}
	variables := make(map[string]string, len(template.Variables))
	for ours, theirs := range template.Variables {
		value, exists := message.Params[ours]
		if !exists {
			return nativeSMSFailure(notificationruntime.ProviderPermanentFailure, "sms_template_unmapped"), nil
		}
		variables[theirs] = value
	}
	encodedVariables, err := json.Marshal(variables)
	if err != nil {
		return nativeSMSFailure(notificationruntime.ProviderPermanentFailure, "sms_message_invalid"), nil
	}
	if config.Provider == notificationSMSProviderSubmail {
		return transport.sendSubmail(ctx, client, config, template, message, string(encodedVariables))
	}
	return transport.sendAliyun(ctx, client, config, template, message, string(encodedVariables))
}

func (transport *nativeSMSTransport) sendAliyun(ctx context.Context, client *http.Client, config nativeSMSConfig,
	template nativeSMSTemplate, message notificationruntime.ProviderMessage, templateParam string) (notificationruntime.ProviderResult, error) {
	form := url.Values{
		"AccessKeyId": {config.AccessKeyID}, "Action": {"SendSms"}, "Format": {"JSON"},
		"OutId": {message.OutboxID.String()}, "PhoneNumbers": {strings.TrimPrefix(message.Contact, "+")},
		"RegionId": {"cn-hangzhou"}, "SignName": {config.SignName}, "SignatureMethod": {"HMAC-SHA1"},
		"SignatureNonce": {uuid.NewString()}, "SignatureVersion": {"1.0"}, "TemplateCode": {template.Code},
		"TemplateParam": {templateParam}, "Timestamp": {transport.now().UTC().Format("2006-01-02T15:04:05Z")},
		"Version": {"2017-05-25"},
	}
	form.Set("Signature", aliyunSMSSignature(http.MethodPost, form, config.AccessKeySecret))
	var result struct {
		Code  string `json:"Code"`
		BizID string `json:"BizId"`
	}
	status, err := postNativeSMSForm(ctx, client, config.Endpoint, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()), &result)
	if err != nil {
		return notificationruntime.ProviderResult{}, err
	}
	switch {
	case result.Code == "OK" && validSMSDeliveryID(result.BizID):
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderAccepted, ProviderDeliveryID: result.BizID}, nil
	case result.Code == "isv.BUSINESS_LIMIT_CONTROL" || strings.HasPrefix(result.Code, "Throttling"):
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderRateLimited,
			Code: "sms_provider_rate_limited", RetryAfter: time.Minute}, nil
	case strings.HasPrefix(result.Code, "isp.") || status >= 500:
		return nativeSMSFailure(notificationruntime.ProviderTemporaryFailure, "sms_provider_unavailable"), nil
	case result.Code == "":
		return notificationruntime.ProviderResult{}, errSMSResponseUnknown
	default:
		return nativeSMSFailure(notificationruntime.ProviderPermanentFailure, "sms_provider_rejected"), nil
	}
}

func (transport *nativeSMSTransport) sendSubmail(ctx context.Context, client *http.Client, config nativeSMSConfig,
	template nativeSMSTemplate, message notificationruntime.ProviderMessage, vars string) (notificationruntime.ProviderResult, error) {
	to, domestic := strings.CutPrefix(message.Contact, "+86")
	if !domestic && strings.HasPrefix(message.Contact, "+") {
		// xsend is the domestic API; international SMS uses a separate product.
		return nativeSMSFailure(notificationruntime.ProviderPermanentFailure, "sms_destination_unsupported"), nil
	}
	signed := map[string]string{
		"appid": config.AccessKeyID, "to": to, "project": template.Code,
		"timestamp": strconv.FormatInt(transport.now().Unix(), 10), "sign_type": "md5", "sign_version": "2",
	}
	form := url.Values{"vars": {vars}, "signature": {submailSMSSignature(signed, config.AccessKeyID, config.AccessKeySecret)}}
	for key, value := range signed {
		form.Set(key, value)
	}
	var result struct {
		Status string `json:"status"`
		SendID string `json:"send_id"`
	}
	status, err := postNativeSMSForm(ctx, client, config.Endpoint, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()), &result)
	if err != nil {
		return notificationruntime.ProviderResult{}, err
	}
	switch {
	case result.Status == "success" && validSMSDeliveryID(result.SendID):
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderAccepted, ProviderDeliveryID: result.SendID}, nil
	case status >= 500:
		return nativeSMSFailure(notificationruntime.ProviderTemporaryFailure, "sms_provider_unavailable"), nil
	case result.Status == "error":
		return nativeSMSFailure(notificationruntime.ProviderPermanentFailure, "sms_provider_rejected"), nil
	default:
		return notificationruntime.ProviderResult{}, errSMSResponseUnknown
	}
}

// postNativeSMSForm returns errSMSUnavailable when the request may not have
// reached the provider, and errSMSResponseUnknown when it did but the answer
// is unreadable (the dispatch is then recorded as unknown, never retried blind).
func postNativeSMSForm(ctx context.Context, client *http.Client, endpoint, contentType string, body io.Reader, result any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return 0, errSMSInvalidMessage
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		if contextErr := smsContextError(ctx); contextErr != nil {
			return 0, contextErr
		}
		return 0, errSMSUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumSMSProviderResponseBytes+1))
	if err != nil || len(raw) > maximumSMSProviderResponseBytes {
		return response.StatusCode, errSMSResponseUnknown
	}
	if json.Unmarshal(bytes.TrimSpace(raw), result) != nil && response.StatusCode < 500 {
		return response.StatusCode, errSMSResponseUnknown
	}
	return response.StatusCode, nil
}

// aliyunSMSSignature is the RPC v1 signature: HMAC-SHA1 over
// METHOD&%2F&percentEncode(sorted canonical query), key = secret + "&".
func aliyunSMSSignature(method string, form url.Values, secret []byte) string {
	keys := make([]string, 0, len(form))
	for key := range form {
		if key != "Signature" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, aliyunPercentEncode(key)+"="+aliyunPercentEncode(form.Get(key)))
	}
	key := append(append([]byte(nil), secret...), '&')
	defer clear(key)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(method + "&" + aliyunPercentEncode("/") + "&" + aliyunPercentEncode(strings.Join(pairs, "&"))))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func aliyunPercentEncode(value string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(value))
}

// submailSMSSignature: md5(appid + appkey + sorted "k=v&..." + appid + appkey);
// with sign_version=2 the vars payload is not signed.
func submailSMSSignature(signed map[string]string, appID string, appKey []byte) string {
	keys := make([]string, 0, len(signed))
	for key := range signed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+signed[key])
	}
	wrapper := appID + string(appKey)
	sum := md5.Sum([]byte(wrapper + strings.Join(pairs, "&") + wrapper))
	return hex.EncodeToString(sum[:])
}

func nativeSMSFailure(disposition notificationruntime.ProviderDisposition, code string) notificationruntime.ProviderResult {
	return notificationruntime.ProviderResult{Disposition: disposition, Code: code}
}

func (transport *nativeSMSTransport) Close(ctx context.Context) error {
	if transport == nil {
		return nil
	}
	if ctx == nil {
		return errSMSUnavailable
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if !transport.closed {
		transport.closed = true
		clear(transport.config.AccessKeySecret)
		transport.config.AccessKeySecret = nil
		transport.client.CloseIdleConnections()
	}
	return nil
}

func (transport *nativeSMSTransport) snapshot(ctx context.Context) (nativeSMSConfig, *http.Client, error) {
	if transport == nil || ctx == nil {
		return nativeSMSConfig{}, nil, errSMSUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nativeSMSConfig{}, nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed {
		return nativeSMSConfig{}, nil, errSMSClosed
	}
	config := transport.config
	config.AccessKeySecret = append([]byte(nil), transport.config.AccessKeySecret...)
	return config, transport.client, nil
}

var _ notificationruntime.ProviderTransport = (*nativeSMSTransport)(nil)
