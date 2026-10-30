// Package mail sends one system email through a built-in SMTP server or an
// official mail service (Alibaba Cloud DirectMail, SendGrid). It is shared by
// the control plane (system notifications) and the license service (operator
// and customer portal mail) so both speak to the providers the same way.
//
// Every sender returns either a Result or an *Error whose Disposition tells
// the caller whether a retry may help. Providers are never chosen implicitly:
// the caller picks exactly one sender, there is no fallback between them.
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

// Official mail service providers; each is the free official module
// ModuleCode(provider).
const (
	ProviderAliyun   = "aliyun"
	ProviderSendGrid = "sendgrid"
)

// Providers lists the official providers in display order.
var Providers = []string{ProviderAliyun, ProviderSendGrid}

// ModuleCode is the official module that grants a provider.
func ModuleCode(provider string) string { return "module.mail." + provider }

// Official reports whether provider is an official mail service.
func Official(provider string) bool {
	return provider == ProviderAliyun || provider == ProviderSendGrid
}

// Regions per provider: the first entry is the default.
var regions = map[string][]struct{ id, endpoint string }{
	ProviderAliyun: {
		{"cn-hangzhou", "https://dm.aliyuncs.com/"},
		{"ap-southeast-1", "https://dm.ap-southeast-1.aliyuncs.com/"},
		{"ap-southeast-2", "https://dm.ap-southeast-2.aliyuncs.com/"},
	},
	ProviderSendGrid: {
		{"global", "https://api.sendgrid.com/v3/mail/send"},
		{"eu", "https://api.eu.sendgrid.com/v3/mail/send"},
	},
}

// Regions returns the region ids of provider (default first).
func Regions(provider string) []string {
	ids := []string{}
	for _, region := range regions[provider] {
		ids = append(ids, region.id)
	}
	return ids
}

// Endpoint resolves provider's API endpoint for region ("" = default).
func Endpoint(provider, region string) (string, bool) {
	for index, candidate := range regions[provider] {
		if candidate.id == region || region == "" && index == 0 {
			return candidate.endpoint, true
		}
	}
	return "", false
}

// Message is one email to one recipient. Text is required; HTML is an
// optional alternative of the same content.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
	ReplyTo string
	// ID makes the Message-ID stable across retries (SMTP); optional.
	ID string
}

// Result of an accepted message.
type Result struct {
	// MessageID is the provider's id (DirectMail EnvId, SendGrid
	// X-Message-Id); empty for SMTP.
	MessageID string
}

// Sender is one configured mail transport.
type Sender interface {
	Send(context.Context, Message) (Result, error)
}

// Disposition classifies a failure for the caller's retry decision.
type Disposition int

const (
	// Permanent: retrying the same message will fail again (bad recipient,
	// rejected credentials, unverified sender).
	Permanent Disposition = iota + 1
	// Temporary: the provider could not take it now; retry later.
	Temporary
	// RateLimited: retry after RetryAfter.
	RateLimited
	// Unknown: the request may have been accepted (unreadable answer).
	Unknown
)

// Error is every send failure. Code is a stable reason for logs and pages.
type Error struct {
	Disposition Disposition
	Code        string
	RetryAfter  time.Duration
}

func (e *Error) Error() string { return "mail: " + e.Code }

// Stable failure codes.
const (
	CodeInvalidMessage     = "message_invalid"
	CodeInvalidConfig      = "config_invalid"
	CodeUnavailable        = "provider_unavailable"
	CodeRateLimited        = "provider_rate_limited"
	CodeCredentialRejected = "credential_rejected"
	CodeSenderRejected     = "sender_rejected"
	CodeRecipientRejected  = "recipient_rejected"
	CodeRejected           = "provider_rejected"
	CodeResponseUnknown    = "provider_response_unknown"
	CodeTLSRequired        = "tls_required"
)

func failure(disposition Disposition, code string) *Error {
	return &Error{Disposition: disposition, Code: code}
}

// ErrorOf returns the *Error in err (nil when err is nil or another error).
func ErrorOf(err error) *Error {
	var mailErr *Error
	if errors.As(err, &mailErr) {
		return mailErr
	}
	return nil
}

// ValidAddress accepts one bare mailbox (no display name, no CR/LF).
func ValidAddress(value string) bool {
	if value == "" || len(value) > 254 || strings.ContainsAny(value, "\r\n\x00 <>,;") {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	at := strings.LastIndexByte(value, '@')
	return err == nil && parsed.Address == value && at > 0 && at < len(value)-1
}

// ValidName accepts a sender display name (optional).
func ValidName(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 64 && !strings.ContainsAny(value, "\r\n\x00\"<>")
}

// ValidCredential accepts an access key id or secret: printable, no spaces.
func ValidCredential(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

func validMessage(message Message) bool {
	return ValidAddress(message.To) && message.Subject != "" && utf8.ValidString(message.Subject) &&
		len(message.Subject) <= 998 && !strings.ContainsAny(message.Subject, "\r\n\x00") &&
		message.Text != "" && utf8.ValidString(message.Text) && !strings.ContainsRune(message.Text, 0) &&
		utf8.ValidString(message.HTML) && !strings.ContainsRune(message.HTML, 0) &&
		(message.ReplyTo == "" || ValidAddress(message.ReplyTo)) && len(message.ID) <= 256 &&
		!strings.ContainsAny(message.ID, "\r\n\x00")
}

// NewHTTPClient is the default provider client: TLS 1.2+, no redirects
// (a redirect could carry the credential elsewhere), bounded time.
func NewHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

const maxResponseBytes = 64 << 10
