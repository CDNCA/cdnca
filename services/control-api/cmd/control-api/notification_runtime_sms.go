package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
)

const maximumSMSProviderResponseBytes = 8 << 10

var (
	errSMSClosed          = errors.New("notification_sms_closed")
	errSMSInvalid         = errors.New("notification_sms_invalid_config")
	errSMSInvalidMessage  = errors.New("notification_sms_invalid_message")
	errSMSNotReady        = errors.New("notification_sms_not_ready")
	errSMSResponseUnknown = errors.New("notification_sms_response_unknown")
	errSMSUnavailable     = errors.New("notification_sms_unavailable")
)

type smsHTTPSJSONTransport struct {
	mu     sync.Mutex
	config smsHTTPSJSONConfig
	client *http.Client
	closed bool
}

type smsSendRequest struct {
	To            string `json:"to"`
	Subject       string `json:"subject"`
	Body          string `json:"body"`
	ActionURL     string `json:"action_url"`
	AccessKeyID   string `json:"access_key_id,omitempty"`
	SignatureName string `json:"signature_name,omitempty"`
}

type smsSendResponse struct {
	DeliveryID string `json:"delivery_id"`
}

func newHTTPSJSONSMSTransport(config smsHTTPSJSONConfig) (*smsHTTPSJSONTransport, error) {
	if !validSMSHTTPSJSONConfig(config) {
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
	config.AuthToken = append([]byte(nil), config.AuthToken...)
	return &smsHTTPSJSONTransport{
		config: config,
		client: &http.Client{
			Transport: httpTransport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errSMSResponseUnknown
			},
		},
	}, nil
}

func (transport *smsHTTPSJSONTransport) Ready(ctx context.Context) error {
	config, client, err := transport.snapshot(ctx)
	if err != nil {
		return err
	}
	defer clear(config.AuthToken)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.ReadyEndpoint, nil)
	if err != nil {
		return errSMSNotReady
	}
	request.Header.Set("Authorization", "Bearer "+string(config.AuthToken))
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		if contextErr := smsContextError(ctx); contextErr != nil {
			return contextErr
		}
		return errSMSNotReady
	}
	defer response.Body.Close()
	_, _ = io.CopyN(io.Discard, response.Body, maximumSMSProviderResponseBytes+1)
	if response.StatusCode != http.StatusNoContent {
		return errSMSNotReady
	}
	return nil
}

func (transport *smsHTTPSJSONTransport) Send(
	ctx context.Context,
	message notificationruntime.ProviderMessage,
) (notificationruntime.ProviderResult, error) {
	if !validSMSProviderMessage(message) {
		return notificationruntime.ProviderResult{
			Disposition: notificationruntime.ProviderPermanentFailure,
			Code:        "sms_message_invalid",
		}, nil
	}
	config, client, err := transport.snapshot(ctx)
	if err != nil {
		return notificationruntime.ProviderResult{}, err
	}
	defer clear(config.AuthToken)
	payload, err := json.Marshal(smsSendRequest{
		To: message.Contact, Subject: message.Subject, Body: message.Body, ActionURL: message.ActionURL,
		AccessKeyID: config.AccessKeyID, SignatureName: config.SignatureName,
	})
	if err != nil {
		return notificationruntime.ProviderResult{}, errSMSInvalidMessage
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return notificationruntime.ProviderResult{}, errSMSInvalidMessage
	}
	request.Header.Set("Authorization", "Bearer "+string(config.AuthToken))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", message.IdempotencyKey)
	response, err := client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if contextErr := smsContextError(ctx); contextErr != nil {
			return notificationruntime.ProviderResult{}, contextErr
		}
		return notificationruntime.ProviderResult{}, errSMSUnavailable
	}
	defer response.Body.Close()

	switch {
	case response.StatusCode == http.StatusAccepted:
		return decodeSMSSuccess(response)
	case response.StatusCode == http.StatusTooManyRequests:
		_, _ = io.CopyN(io.Discard, response.Body, maximumSMSProviderResponseBytes+1)
		return notificationruntime.ProviderResult{
			Disposition: notificationruntime.ProviderRateLimited,
			Code:        "sms_provider_rate_limited",
			RetryAfter:  smsRetryAfter(response.Header.Get("Retry-After"), time.Now()),
		}, nil
	case response.StatusCode >= 500 && response.StatusCode <= 599:
		_, _ = io.CopyN(io.Discard, response.Body, maximumSMSProviderResponseBytes+1)
		return notificationruntime.ProviderResult{
			Disposition: notificationruntime.ProviderTemporaryFailure,
			Code:        "sms_provider_unavailable",
		}, nil
	case response.StatusCode >= 400 && response.StatusCode <= 499:
		_, _ = io.CopyN(io.Discard, response.Body, maximumSMSProviderResponseBytes+1)
		return notificationruntime.ProviderResult{
			Disposition: notificationruntime.ProviderPermanentFailure,
			Code:        "sms_provider_rejected",
		}, nil
	default:
		_, _ = io.CopyN(io.Discard, response.Body, maximumSMSProviderResponseBytes+1)
		return notificationruntime.ProviderResult{}, errSMSResponseUnknown
	}
}

func (transport *smsHTTPSJSONTransport) Close(ctx context.Context) error {
	if transport == nil {
		return nil
	}
	if ctx == nil {
		return errSMSUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	transport.mu.Lock()
	if transport.closed {
		transport.mu.Unlock()
		return nil
	}
	transport.closed = true
	clear(transport.config.AuthToken)
	transport.config.AuthToken = nil
	client := transport.client
	transport.mu.Unlock()
	if client != nil {
		client.CloseIdleConnections()
	}
	return nil
}

func (transport *smsHTTPSJSONTransport) snapshot(
	ctx context.Context,
) (smsHTTPSJSONConfig, *http.Client, error) {
	if transport == nil || ctx == nil {
		return smsHTTPSJSONConfig{}, nil, errSMSUnavailable
	}
	if err := ctx.Err(); err != nil {
		return smsHTTPSJSONConfig{}, nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed {
		return smsHTTPSJSONConfig{}, nil, errSMSClosed
	}
	config := transport.config
	config.AuthToken = append([]byte(nil), transport.config.AuthToken...)
	return config, transport.client, nil
}

func validSMSHTTPSJSONConfig(config smsHTTPSJSONConfig) bool {
	if len(config.AuthToken) == 0 || len(config.AuthToken) > 4096 ||
		strings.ContainsAny(string(config.AuthToken), "\r\n\x00") {
		return false
	}
	endpoint, endpointOK := canonicalSMSHTTPSURL(config.Endpoint)
	ready, readyOK := canonicalSMSHTTPSURL(config.ReadyEndpoint)
	return endpointOK && readyOK && endpoint.Scheme == ready.Scheme && endpoint.Host == ready.Host
}

func canonicalSMSHTTPSURL(raw string) (*url.URL, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path == "" || strings.TrimSpace(raw) != raw {
		return nil, false
	}
	return parsed, true
}

func validSMSProviderMessage(message notificationruntime.ProviderMessage) bool {
	if message.OutboxID == uuid.Nil || message.Channel != notification.ChannelSMS ||
		!validSMSContact(message.Contact) || message.Subject != "" ||
		message.Body == "" || len(message.Body) > notification.MaxSMSBodyBytes ||
		strings.ContainsRune(message.Body, '\x00') ||
		message.IdempotencyKey == "" || len(message.IdempotencyKey) > 256 ||
		strings.ContainsAny(message.IdempotencyKey, "\r\n\x00") || message.AttemptNumber < 1 {
		return false
	}
	if message.ActionURL == "" {
		return true
	}
	parsed, err := url.Parse(message.ActionURL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && !strings.ContainsAny(message.ActionURL, "\r\n\x00")
}

func validSMSContact(value string) bool {
	if len(value) < 6 || len(value) > 21 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if character == '+' && index == 0 {
			continue
		}
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != "+"
}

func decodeSMSSuccess(response *http.Response) (notificationruntime.ProviderResult, error) {
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return notificationruntime.ProviderResult{}, errSMSResponseUnknown
	}
	limited := io.LimitReader(response.Body, maximumSMSProviderResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) == 0 || len(raw) > maximumSMSProviderResponseBytes {
		return notificationruntime.ProviderResult{}, errSMSResponseUnknown
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result smsSendResponse
	if err := decoder.Decode(&result); err != nil {
		return notificationruntime.ProviderResult{}, errSMSResponseUnknown
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !validSMSDeliveryID(result.DeliveryID) {
		return notificationruntime.ProviderResult{}, errSMSResponseUnknown
	}
	return notificationruntime.ProviderResult{
		Disposition: notificationruntime.ProviderAccepted, ProviderDeliveryID: result.DeliveryID,
	}, nil
}

func validSMSDeliveryID(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == '\u007f' {
			return false
		}
	}
	return true
}

func smsRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil && seconds >= 1 && seconds <= 86_400 {
		return time.Duration(seconds) * time.Second
	}
	if parsed, err := http.ParseTime(value); err == nil {
		delay := parsed.Sub(now)
		if delay >= time.Second && delay <= 24*time.Hour {
			return delay.Round(time.Second)
		}
	}
	return time.Minute
}

func smsContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

var _ notificationruntime.ProviderTransport = (*smsHTTPSJSONTransport)(nil)
