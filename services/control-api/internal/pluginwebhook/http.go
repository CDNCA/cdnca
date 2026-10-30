package pluginwebhook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	HeaderDeliveryID         = "X-CDNCA-Webhook-Id"
	HeaderTimestamp          = "X-CDNCA-Webhook-Timestamp"
	HeaderContentSHA256      = "X-CDNCA-Webhook-Content-Sha256"
	HeaderSignature          = "X-CDNCA-Webhook-Signature"
	HeaderIdempotencyKey     = "X-CDNCA-Idempotency-Key"
	HeaderAttempt            = "X-CDNCA-Webhook-Attempt"
	HeaderEventIDV2          = "X-CDNCA-Webhook-Event-Id"
	HeaderDeliveryIDV2       = "X-CDNCA-Webhook-Delivery-Id"
	HeaderKeyIDV2            = "X-CDNCA-Webhook-Key-Id"
	HeaderSignatureVersionV2 = "X-CDNCA-Webhook-Signature-Version"
)

type SecretProvider interface {
	Secret(context.Context, uuid.UUID, uuid.UUID) ([]byte, error)
}

type V2SecretProvider interface {
	Secret(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) ([]byte, error)
}

type HTTPSenderConfig struct {
	RequestTimeout        time.Duration
	ConnectTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	MaxResponseBytes      int64
	MaxPreviewBytes       int
	Now                   func() time.Time
	RootCAs               *x509.CertPool
}

func DefaultHTTPSenderConfig() HTTPSenderConfig {
	return HTTPSenderConfig{
		RequestTimeout: 15 * time.Second, ConnectTimeout: 5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseBytes: 64 * 1024, MaxPreviewBytes: 2 * 1024,
		Now: func() time.Time { return time.Now().UTC() },
	}
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type HTTPSender struct {
	config    HTTPSenderConfig
	secrets   SecretProvider
	v2Secrets V2SecretProvider
	resolver  Resolver
	dial      dialContextFunc
}

func NewHTTPSender(config HTTPSenderConfig, secrets SecretProvider) (*HTTPSender, error) {
	dialer := &net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: -1}
	return newHTTPSender(config, secrets, net.DefaultResolver, dialer.DialContext)
}

func newHTTPSender(config HTTPSenderConfig, secrets SecretProvider, resolver Resolver, dial dialContextFunc) (*HTTPSender, error) {
	if secrets == nil || resolver == nil || dial == nil || !validHTTPSenderConfig(config) {
		return nil, ErrInvalidConfig
	}
	return &HTTPSender{config: config, secrets: secrets, resolver: resolver, dial: dial}, nil
}

func NewV2HTTPSender(config HTTPSenderConfig, secrets V2SecretProvider) (*HTTPSender, error) {
	dialer := &net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: -1}
	return newV2HTTPSender(config, secrets, net.DefaultResolver, dialer.DialContext)
}

func newV2HTTPSender(config HTTPSenderConfig, secrets V2SecretProvider, resolver Resolver, dial dialContextFunc) (*HTTPSender, error) {
	if secrets == nil || resolver == nil || dial == nil || !validHTTPSenderConfig(config) {
		return nil, ErrInvalidConfig
	}
	return &HTTPSender{config: config, v2Secrets: secrets, resolver: resolver, dial: dial}, nil
}

func (sender *HTTPSender) Deliver(ctx context.Context, item QueueItem, attempt uint64) SendResult {
	return sender.deliver(ctx, item, attempt, nil)
}

// DeliverV2 sends a v2 item with plaintext acquired under the runtime's
// caller-owned start transaction. The caller retains ownership of secret and
// must clear it after this synchronous call returns.
func (sender *HTTPSender) DeliverV2(ctx context.Context, item QueueItem, attempt uint64, secret []byte) SendResult {
	if item.Schema != QueueSchemaV2 || len(secret) == 0 {
		return SendResult{Code: "invalid_delivery"}
	}
	return sender.deliver(ctx, item, attempt, secret)
}

func (sender *HTTPSender) deliver(ctx context.Context, item QueueItem, attempt uint64, preparedSecret []byte) SendResult {
	if sender == nil || ctx == nil || attempt == 0 || validateQueueItem(item) != nil {
		return SendResult{Code: "invalid_delivery"}
	}
	requestCtx, cancel := context.WithTimeout(ctx, sender.config.RequestTimeout)
	defer cancel()
	body := item.RawEvent
	var err error
	if len(body) == 0 {
		body, err = json.Marshal(item.Event)
	}
	if err != nil || len(body) > MaxQueueMessageBytes || !json.Valid(body) {
		return SendResult{Code: "invalid_delivery"}
	}
	requestDigest := sha256.Sum256(body)
	withRequestMetadata := func(result SendResult) SendResult {
		result.RequestSHA256 = hex.EncodeToString(requestDigest[:])
		result.RequestBytes = len(body)
		return result
	}
	timestamp := sender.config.Now().UTC()
	target, err := resolveTarget(requestCtx, item.TargetURL, sender.resolver)
	if err != nil {
		if errors.Is(err, ErrTargetForbidden) {
			return withRequestMetadata(SendResult{Code: "target_forbidden"})
		}
		return withRequestMetadata(SendResult{Retryable: true, Code: "target_resolution"})
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, target.URL.String(), bytes.NewReader(body))
	if err != nil {
		return SendResult{Code: "invalid_delivery"}
	}
	var providedSecret []byte
	if preparedSecret != nil {
		if item.Schema != QueueSchemaV2 {
			return withRequestMetadata(SendResult{Code: "invalid_delivery"})
		}
		providedSecret = append([]byte(nil), preparedSecret...)
	} else if item.Schema == QueueSchemaV2 {
		if sender.v2Secrets == nil {
			return withRequestMetadata(SendResult{Retryable: true, Code: "secret_unavailable"})
		}
		providedSecret, err = sender.v2Secrets.Secret(requestCtx, item.TargetScopeID, item.SubscriptionID, item.SecretVersionID)
	} else {
		if sender.secrets == nil {
			return withRequestMetadata(SendResult{Retryable: true, Code: "secret_unavailable"})
		}
		tenantID, _ := uuid.Parse(item.Event.TenantID)
		installationID, _ := uuid.Parse(item.Event.InstallationID)
		providedSecret, err = sender.secrets.Secret(requestCtx, tenantID, installationID)
	}
	if err != nil {
		return withRequestMetadata(SendResult{Retryable: true, Code: "secret_unavailable"})
	}
	secret := append([]byte(nil), providedSecret...)
	clear(providedSecret)
	defer clear(secret)
	if len(secret) < MinimumSecretBytes || len(secret) > MaximumSecretBytes {
		return withRequestMetadata(SendResult{Code: "secret_invalid"})
	}
	request.Header.Set("Content-Type", "application/cloudevents+json")
	request.Header.Set("User-Agent", "CDNCA-Plugin-Webhook/1")
	if item.Schema == QueueSchemaV2 {
		signature, signErr := SignV2(secret, timestamp, target.URL.EscapedPath(), item.EventID,
			item.DeliveryID, item.SecretVersionID, body)
		if signErr != nil {
			return withRequestMetadata(SendResult{Code: "secret_invalid"})
		}
		request.Header.Set(HeaderEventIDV2, signature.EventID)
		request.Header.Set(HeaderDeliveryIDV2, signature.DeliveryID)
		request.Header.Set(HeaderTimestamp, signature.Timestamp)
		request.Header.Set(HeaderContentSHA256, signature.ContentSHA256)
		request.Header.Set(HeaderKeyIDV2, signature.SecretVersionID)
		request.Header.Set(HeaderSignatureVersionV2, signature.SignatureVersion)
		request.Header.Set(HeaderSignature, signature.Signature)
	} else {
		signature, signErr := Sign(secret, timestamp, item.DeliveryID, body)
		if signErr != nil {
			return withRequestMetadata(SendResult{Code: "secret_invalid"})
		}
		request.Header.Set(HeaderDeliveryID, signature.DeliveryID)
		request.Header.Set(HeaderTimestamp, signature.Timestamp)
		request.Header.Set(HeaderContentSHA256, signature.ContentSHA256)
		request.Header.Set(HeaderSignature, signature.Signature)
	}
	request.Header.Set(HeaderIdempotencyKey, item.IdempotencyKey)
	request.Header.Set(HeaderAttempt, strconv.FormatUint(attempt, 10))

	transport := sender.transport(target)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: sender.config.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return withRequestMetadata(classifyTransportError(err, requestCtx))
	}
	defer response.Body.Close()
	result := SendResult{
		StatusCode: response.StatusCode, ResponseHeaders: sanitizeHeaders(response.Header),
	}
	switch {
	case response.StatusCode >= 200 && response.StatusCode <= 299:
		result.Success = true
		result.Code = "delivered"
	case response.StatusCode >= 300 && response.StatusCode <= 399:
		result.Code = "redirect_forbidden"
	case response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooEarly || response.StatusCode == http.StatusTooManyRequests:
		result.Code = fmt.Sprintf("remote_%d", response.StatusCode)
		result.Retryable = true
		result.RetryAfter = parseRetryAfter(response.Header.Get("Retry-After"), timestamp)
	case response.StatusCode >= 500:
		result.Code = "remote_5xx"
		result.Retryable = true
		result.RetryAfter = parseRetryAfter(response.Header.Get("Retry-After"), timestamp)
	default:
		result.Code = fmt.Sprintf("remote_%d", response.StatusCode)
	}
	limited, readErr := io.ReadAll(io.LimitReader(response.Body, sender.config.MaxResponseBytes+1))
	complete := readErr == nil && int64(len(limited)) <= sender.config.MaxResponseBytes
	if int64(len(limited)) > sender.config.MaxResponseBytes {
		limited = limited[:sender.config.MaxResponseBytes]
	}
	result.ResponseBytes = len(limited)
	result.ResponsePreview = sanitizePreview(limited, response.Header.Get("Content-Type"), sender.config.MaxPreviewBytes)
	if complete {
		digest := sha256.Sum256(limited)
		result.ResponseSHA256 = hex.EncodeToString(digest[:])
	}
	return withRequestMetadata(result)
}

func (sender *HTTPSender) transport(target resolvedTarget) *http.Transport {
	pinnedDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || strings.TrimSuffix(host, ".") != target.Hostname || port != target.Port {
			return nil, ErrTargetForbidden
		}
		var lastErr error
		for _, pinnedAddress := range target.Addresses {
			connection, dialErr := sender.dial(ctx, "tcp", net.JoinHostPort(pinnedAddress.String(), target.Port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			return nil, ErrTargetResolution
		}
		return nil, lastErr
	}
	return &http.Transport{
		Proxy: nil, DialContext: pinnedDial, ForceAttemptHTTP2: true, DisableCompression: true,
		DisableKeepAlives: true, MaxConnsPerHost: 1,
		TLSHandshakeTimeout:   sender.config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: sender.config.ResponseHeaderTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, ServerName: target.Hostname, RootCAs: sender.config.RootCAs,
		},
	}
}

func classifyTransportError(err error, requestCtx context.Context) SendResult {
	if requestCtx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return SendResult{Retryable: true, Code: "timeout"}
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return SendResult{Retryable: true, Code: "timeout"}
	}
	var hostnameError x509.HostnameError
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	if errors.As(err, &hostnameError) || errors.As(err, &unknownAuthority) || errors.As(err, &certificateInvalid) {
		return SendResult{Code: "tls_certificate_invalid"}
	}
	var alertError tls.AlertError
	var recordHeaderError tls.RecordHeaderError
	var certificateVerificationError *tls.CertificateVerificationError
	if errors.As(err, &alertError) || errors.As(err, &recordHeaderError) || errors.As(err, &certificateVerificationError) ||
		strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		return SendResult{Code: "tls_handshake_failed"}
	}
	return SendResult{Retryable: true, Code: "transport_failed"}
}

func validHTTPSenderConfig(config HTTPSenderConfig) bool {
	return config.RequestTimeout > 0 && config.RequestTimeout <= time.Minute &&
		config.ConnectTimeout > 0 && config.ConnectTimeout <= config.RequestTimeout &&
		config.TLSHandshakeTimeout > 0 && config.TLSHandshakeTimeout <= config.RequestTimeout &&
		config.ResponseHeaderTimeout > 0 && config.ResponseHeaderTimeout <= config.RequestTimeout &&
		config.MaxResponseBytes > 0 && config.MaxResponseBytes <= 1<<20 &&
		config.MaxPreviewBytes > 0 && config.MaxPreviewBytes <= 2048 &&
		int64(config.MaxPreviewBytes) <= config.MaxResponseBytes && config.Now != nil
}
