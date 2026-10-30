package mail

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ServiceConfig configures an official mail service sender.
//
// Aliyun DirectMail: AccessKeyID / AccessKeySecret of a RAM user allowed to
// call dm:SingleSendMail, From = a sender address verified in the DirectMail
// console (AccountName). DirectMail has no per-message reply-to: it uses the
// reply-to configured for the sender address, so Message.ReplyTo is ignored.
//
// SendGrid: AccessKeySecret = an API key with Mail Send permission
// (AccessKeyID unused), From = a verified Sender Identity.
type ServiceConfig struct {
	Provider        string
	Region          string // "" = provider default (Regions)
	AccessKeyID     string
	AccessKeySecret string
	From            string
	FromName        string
	// Endpoint overrides the region endpoint (tests); HTTPClient defaults to
	// NewHTTPClient(15s); Now defaults to time.Now; Nonce to a random id.
	Endpoint   string
	HTTPClient *http.Client
	Now        func() time.Time
	Nonce      func() string
}

// ValidServiceConfig checks a configuration without contacting anyone.
func ValidServiceConfig(config ServiceConfig) bool {
	if _, ok := Endpoint(config.Provider, config.Region); !ok || !ValidAddress(config.From) || !ValidName(config.FromName) ||
		!ValidCredential(config.AccessKeySecret, 512) {
		return false
	}
	if config.Provider == ProviderAliyun {
		return ValidCredential(config.AccessKeyID, 256)
	}
	return config.AccessKeyID == ""
}

// NewService builds the sender of an official provider.
func NewService(config ServiceConfig) (Sender, error) {
	if !ValidServiceConfig(config) {
		return nil, failure(Permanent, CodeInvalidConfig)
	}
	if config.Endpoint == "" {
		config.Endpoint, _ = Endpoint(config.Provider, config.Region)
	}
	if parsed, err := url.Parse(config.Endpoint); err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, failure(Permanent, CodeInvalidConfig)
	}
	if config.HTTPClient == nil {
		config.HTTPClient = NewHTTPClient(15 * time.Second)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Nonce == nil {
		config.Nonce = randomNonce
	}
	if config.Provider == ProviderAliyun {
		return directMail{config}, nil
	}
	return sendGrid{config}, nil
}

// post sends one request. A transport error before any answer is
// Temporary (nothing was accepted); an answer that cannot be read is Unknown.
func post(ctx context.Context, client *http.Client, request *http.Request) (int, http.Header, []byte, error) {
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, nil, ctx.Err()
		}
		return 0, nil, nil, failure(Temporary, CodeUnavailable)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return response.StatusCode, response.Header, nil, failure(Unknown, CodeResponseUnknown)
	}
	return response.StatusCode, response.Header, bytes.TrimSpace(body), nil
}

// --- Alibaba Cloud DirectMail (dm 2015-11-23 SingleSendMail, RPC v1) ---

type directMail struct{ config ServiceConfig }

func (sender directMail) Send(ctx context.Context, message Message) (Result, error) {
	if !validMessage(message) {
		return Result{}, failure(Permanent, CodeInvalidMessage)
	}
	config := sender.config
	region := config.Region
	if region == "" {
		region = Regions(ProviderAliyun)[0]
	}
	form := url.Values{
		"AccessKeyId": {config.AccessKeyID}, "AccountName": {config.From}, "Action": {"SingleSendMail"},
		"AddressType": {"1"}, "Format": {"JSON"}, "RegionId": {region}, "ReplyToAddress": {"false"},
		"SignatureMethod": {"HMAC-SHA1"}, "SignatureNonce": {config.Nonce()}, "SignatureVersion": {"1.0"},
		"Subject": {message.Subject}, "TextBody": {message.Text}, "ToAddress": {message.To},
		"Timestamp": {config.Now().UTC().Format("2006-01-02T15:04:05Z")}, "Version": {"2015-11-23"},
	}
	if message.HTML != "" {
		form.Set("HtmlBody", message.HTML)
	}
	if config.FromName != "" {
		form.Set("FromAlias", config.FromName)
	}
	form.Set("Signature", AliyunSignature(http.MethodPost, form, config.AccessKeySecret))
	request, err := http.NewRequest(http.MethodPost, config.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, failure(Permanent, CodeInvalidConfig)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	status, _, body, err := post(ctx, config.HTTPClient, request)
	if err != nil {
		return Result{}, err
	}
	var answer struct {
		EnvID string `json:"EnvId"`
		Code  string `json:"Code"`
	}
	if json.Unmarshal(body, &answer) != nil {
		if status >= 500 {
			return Result{}, failure(Temporary, CodeUnavailable)
		}
		return Result{}, failure(Unknown, CodeResponseUnknown)
	}
	if status == http.StatusOK && answer.Code == "" {
		if answer.EnvID == "" || len(answer.EnvID) > 256 {
			return Result{}, failure(Unknown, CodeResponseUnknown)
		}
		return Result{MessageID: answer.EnvID}, nil
	}
	return Result{}, directMailError(status, answer.Code)
}

// directMailError maps DirectMail error codes (API error center) to a
// disposition; anything unrecognised is a permanent rejection unless the
// status says the service failed.
func directMailError(status int, code string) *Error {
	switch {
	case strings.HasPrefix(code, "Throttling") || code == "QuotaExhausted" || strings.Contains(code, "Quota"):
		return &Error{Disposition: RateLimited, Code: CodeRateLimited, RetryAfter: time.Minute}
	case strings.HasPrefix(code, "InvalidAccessKeyId") || code == "SignatureDoesNotMatch" ||
		strings.HasPrefix(code, "Forbidden") || code == "IncompleteSignature" || code == "InvalidTimeStamp.Expired":
		return failure(Permanent, CodeCredentialRejected)
	case strings.HasPrefix(code, "InvalidMailAddress") || strings.HasPrefix(code, "InvalidSender") ||
		strings.HasPrefix(code, "InvalidFromALias") || strings.HasPrefix(code, "InvalidFromAlias") ||
		strings.HasPrefix(code, "InvalidAccountName"):
		return failure(Permanent, CodeSenderRejected)
	case strings.HasPrefix(code, "InvalidToAddress") || strings.HasPrefix(code, "InvalidReceiver"):
		return failure(Permanent, CodeRecipientRejected)
	case status >= 500 || code == "ServiceUnavailable" || code == "InternalError":
		return failure(Temporary, CodeUnavailable)
	case code == "":
		return failure(Unknown, CodeResponseUnknown)
	default:
		return failure(Permanent, CodeRejected)
	}
}

// AliyunSignature is the Alibaba Cloud RPC v1 signature: HMAC-SHA1 over
// METHOD&%2F&percentEncode(sorted canonical query), key = secret + "&".
func AliyunSignature(method string, form url.Values, secret string) string {
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
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(method + "&" + aliyunPercentEncode("/") + "&" + aliyunPercentEncode(strings.Join(pairs, "&"))))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func aliyunPercentEncode(value string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(value))
}

// --- SendGrid (v3 POST /mail/send) ---

type sendGrid struct{ config ServiceConfig }

type sendGridAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type sendGridContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (sender sendGrid) Send(ctx context.Context, message Message) (Result, error) {
	if !validMessage(message) {
		return Result{}, failure(Permanent, CodeInvalidMessage)
	}
	config := sender.config
	// text/plain must come before text/html.
	content := []sendGridContent{{Type: "text/plain", Value: message.Text}}
	if message.HTML != "" {
		content = append(content, sendGridContent{Type: "text/html", Value: message.HTML})
	}
	payload := map[string]any{
		"personalizations": []map[string]any{{"to": []sendGridAddress{{Email: message.To}}}},
		"from":             sendGridAddress{Email: config.From, Name: config.FromName},
		"subject":          message.Subject,
		"content":          content,
	}
	if message.ReplyTo != "" {
		payload["reply_to"] = sendGridAddress{Email: message.ReplyTo}
	}
	if message.ID != "" {
		payload["custom_args"] = map[string]string{"cdnca_message_id": message.ID}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Result{}, failure(Permanent, CodeInvalidMessage)
	}
	request, err := http.NewRequest(http.MethodPost, config.Endpoint, bytes.NewReader(encoded))
	if err != nil {
		return Result{}, failure(Permanent, CodeInvalidConfig)
	}
	request.Header.Set("Authorization", "Bearer "+config.AccessKeySecret)
	request.Header.Set("Content-Type", "application/json")
	status, header, _, err := post(ctx, config.HTTPClient, request)
	if err != nil {
		return Result{}, err
	}
	switch {
	case status == http.StatusAccepted || status == http.StatusOK:
		id := header.Get("X-Message-Id")
		if len(id) > 256 || strings.ContainsAny(id, "\r\n\x00") {
			id = ""
		}
		return Result{MessageID: id}, nil
	case status == http.StatusTooManyRequests:
		retry := time.Minute
		if reset, err := strconv.ParseInt(header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			if wait := time.Until(time.Unix(reset, 0)); wait > 0 && wait < time.Hour {
				retry = wait
			}
		}
		return Result{}, &Error{Disposition: RateLimited, Code: CodeRateLimited, RetryAfter: retry}
	case status == http.StatusUnauthorized:
		return Result{}, failure(Permanent, CodeCredentialRejected)
	case status == http.StatusForbidden:
		// Unverified sender identity or a key without Mail Send.
		return Result{}, failure(Permanent, CodeSenderRejected)
	case status == http.StatusRequestEntityTooLarge:
		return Result{}, failure(Permanent, CodeInvalidMessage)
	case status >= 500:
		return Result{}, failure(Temporary, CodeUnavailable)
	default:
		return Result{}, failure(Permanent, CodeRejected)
	}
}
