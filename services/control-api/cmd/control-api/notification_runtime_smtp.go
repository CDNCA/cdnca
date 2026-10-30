package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	errSMTPClosed      = errors.New("notification_smtp_closed")
	errSMTPUnavailable = errors.New("notification_smtp_unavailable")
	errSMTPInvalid     = errors.New("notification_smtp_invalid_message")
	errSMTPCAInvalid   = errors.New("notification_smtp_ca_invalid")
)

type smtpTLSTransport struct {
	mu     sync.Mutex
	config smtpTLSConfig
	roots  *x509.CertPool
	closed bool
	// html renders the theme email layout (PA-17); nil sends text only.
	html smtpHTMLLayout
}

// smtpHTMLLayout returns the HTML alternative for a message, or false to send
// the plain-text body alone.
type smtpHTMLLayout interface {
	Render(ctx context.Context, scopeID uuid.UUID, subject, body string) ([]byte, bool)
}

// newThemedSMTPTLSTransport adds the active theme's HTML email layout.
func newThemedSMTPTLSTransport(config smtpTLSConfig, pool *pgxpool.Pool) (*smtpTLSTransport, error) {
	transport, err := newSMTPTLSTransport(config)
	if err != nil || pool == nil {
		return transport, err
	}
	transport.html = theme.NewEmailLayout(pool)
	return transport, nil
}

func newSMTPTLSTransport(config smtpTLSConfig) (*smtpTLSTransport, error) {
	if !validSMTPAddress(config.Address) || !validSMTPServerName(config.ServerName) ||
		config.Username == "" || len(config.Password) == 0 || !validSMTPMailbox(config.From) {
		return nil, errSMTPInvalid
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, errSMTPCAInvalid
	}
	if config.CAFile != "" {
		encoded, readErr := os.ReadFile(config.CAFile)
		if readErr != nil || !roots.AppendCertsFromPEM(encoded) {
			return nil, errSMTPCAInvalid
		}
	}
	config.Password = append([]byte(nil), config.Password...)
	return &smtpTLSTransport{config: config, roots: roots}, nil
}

func (transport *smtpTLSTransport) Ready(ctx context.Context) error {
	client, cleanup, err := transport.open(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := client.Noop(); err != nil {
		return stableSMTPError(ctx)
	}
	if err := client.Quit(); err != nil {
		return stableSMTPError(ctx)
	}
	return nil
}

func (transport *smtpTLSTransport) Send(
	ctx context.Context,
	message notificationruntime.ProviderMessage,
) (notificationruntime.ProviderResult, error) {
	if !validSMTPProviderMessage(message) {
		return notificationruntime.ProviderResult{
			Disposition: notificationruntime.ProviderPermanentFailure, Code: "smtp_message_invalid",
		}, nil
	}
	client, cleanup, err := transport.open(ctx)
	if err != nil {
		return notificationruntime.ProviderResult{}, err
	}
	defer cleanup()

	transport.mu.Lock()
	from := transport.config.From
	serverName := transport.config.ServerName
	transport.mu.Unlock()
	if err := client.Mail(from); err != nil {
		return notificationruntime.ProviderResult{}, stableSMTPError(ctx)
	}
	if err := client.Rcpt(message.Contact); err != nil {
		return classifySMTPMessageError(ctx, err)
	}
	data, err := client.Data()
	if err != nil {
		return classifySMTPMessageError(ctx, err)
	}
	var html []byte
	if transport.html != nil {
		if rendered, ok := transport.html.Render(ctx, message.ScopeID, message.Subject, message.Body); ok {
			html = rendered
		}
	}
	payload := buildSMTPMessage(from, serverName, message, html)
	if _, err := data.Write([]byte(payload)); err != nil {
		_ = data.Close()
		return notificationruntime.ProviderResult{}, stableSMTPError(ctx)
	}
	if err := data.Close(); err != nil {
		return classifySMTPMessageError(ctx, err)
	}
	_ = client.Quit()
	return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderAccepted}, nil
}

func (transport *smtpTLSTransport) Close(ctx context.Context) error {
	if transport == nil {
		return nil
	}
	if ctx == nil {
		return errSMTPUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed {
		return nil
	}
	transport.closed = true
	clear(transport.config.Password)
	transport.config.Password = nil
	return nil
}

func (transport *smtpTLSTransport) open(ctx context.Context) (*smtp.Client, func(), error) {
	if transport == nil || ctx == nil {
		return nil, nil, errSMTPUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	transport.mu.Lock()
	if transport.closed {
		transport.mu.Unlock()
		return nil, nil, errSMTPClosed
	}
	config := transport.config
	config.Password = append([]byte(nil), transport.config.Password...)
	roots := transport.roots
	transport.mu.Unlock()

	minimumTLSVersion := uint16(tls.VersionTLS12)
	if config.StartTLS {
		minimumTLSVersion = tls.VersionTLS13
	}
	tlsConfig := &tls.Config{
		ServerName: config.ServerName, RootCAs: roots, MinVersion: minimumTLSVersion,
	}
	var connection net.Conn
	var err error
	if config.StartTLS {
		connection, err = new(net.Dialer).DialContext(ctx, "tcp", config.Address)
	} else {
		connection, err = (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", config.Address)
	}
	if err != nil {
		clear(config.Password)
		return nil, nil, stableSMTPError(ctx)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	client, err := smtp.NewClient(connection, config.ServerName)
	if err != nil {
		stopCancellation()
		_ = connection.Close()
		clear(config.Password)
		return nil, nil, stableSMTPError(ctx)
	}
	cleanup := func() {
		stopCancellation()
		_ = client.Close()
		_ = connection.Close()
		clear(config.Password)
	}
	if config.StartTLS {
		if supported, _ := client.Extension("STARTTLS"); !supported {
			cleanup()
			return nil, nil, errSMTPUnavailable
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			cleanup()
			return nil, nil, stableSMTPError(ctx)
		}
		state, ok := client.TLSConnectionState()
		if !ok || !state.HandshakeComplete || state.Version < tls.VersionTLS13 {
			cleanup()
			return nil, nil, errSMTPUnavailable
		}
	}
	if supported, _ := client.Extension("AUTH"); !supported {
		cleanup()
		return nil, nil, errSMTPUnavailable
	}
	auth := smtp.PlainAuth("", config.Username, string(config.Password), config.ServerName)
	if err := client.Auth(auth); err != nil {
		cleanup()
		return nil, nil, stableSMTPError(ctx)
	}
	return client, cleanup, nil
}

func classifySMTPMessageError(
	ctx context.Context,
	err error,
) (notificationruntime.ProviderResult, error) {
	if contextErr := smtpContextError(ctx); contextErr != nil {
		return notificationruntime.ProviderResult{}, contextErr
	}
	var protocolError *textproto.Error
	if !errors.As(err, &protocolError) {
		return notificationruntime.ProviderResult{}, errSMTPUnavailable
	}
	switch {
	case protocolError.Code >= 400 && protocolError.Code < 500:
		return notificationruntime.ProviderResult{
			Disposition: notificationruntime.ProviderTemporaryFailure, Code: "smtp_temporary",
		}, nil
	case protocolError.Code >= 500 && protocolError.Code < 600:
		return notificationruntime.ProviderResult{
			Disposition: notificationruntime.ProviderPermanentFailure, Code: "smtp_rejected",
		}, nil
	default:
		return notificationruntime.ProviderResult{}, errSMTPUnavailable
	}
}

func stableSMTPError(ctx context.Context) error {
	if err := smtpContextError(ctx); err != nil {
		return err
	}
	return errSMTPUnavailable
}

func smtpContextError(ctx context.Context) error {
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

func validSMTPProviderMessage(message notificationruntime.ProviderMessage) bool {
	if message.OutboxID == uuid.Nil || message.Channel != notification.ChannelEmail ||
		!validSMTPMailbox(message.Contact) || message.Subject == "" || message.Body == "" ||
		strings.ContainsAny(message.Subject, "\r\n\x00") ||
		message.IdempotencyKey == "" || len(message.IdempotencyKey) > 256 ||
		strings.ContainsAny(message.IdempotencyKey, "\r\n\x00") || message.AttemptNumber < 1 {
		return false
	}
	if message.ActionURL == "" {
		return true
	}
	parsed, err := url.Parse(message.ActionURL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		!strings.ContainsAny(message.ActionURL, "\r\n\x00")
}

func buildSMTPMessage(from, serverName string, message notificationruntime.ProviderMessage, html []byte) string {
	digest := sha256.Sum256([]byte(message.IdempotencyKey))
	body := strings.ReplaceAll(strings.ReplaceAll(message.Body, "\r\n", "\n"), "\r", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")
	if message.ActionURL != "" {
		body += "\r\n\r\n" + message.ActionURL
	}
	headers := fmt.Sprintf(
		"From: <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <cdnca-%x@%s>\r\nMIME-Version: 1.0\r\n",
		from, message.Contact, foldedSMTPSubject(message.Subject), time.Now().UTC().Format(time.RFC1123Z), digest, serverName,
	)
	trailer := fmt.Sprintf("X-CDNCA-Idempotency-Key: %s\r\n", message.IdempotencyKey)
	if len(html) == 0 {
		return headers + "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n" +
			trailer + "\r\n" + quotedPrintable([]byte(body)) + "\r\n"
	}
	// The boundary derives from the idempotency key, so a retry is byte-stable;
	// quoted-printable output never contains "--cdnca-alt-".
	boundary := fmt.Sprintf("cdnca-alt-%x", digest[:12])
	return headers + "Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n" + trailer + "\r\n" +
		"--" + boundary + "\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		quotedPrintable([]byte(body)) + "\r\n" +
		"--" + boundary + "\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		quotedPrintable(html) + "\r\n--" + boundary + "--\r\n"
}

func quotedPrintable(body []byte) string {
	var encoded strings.Builder
	encoder := quotedprintable.NewWriter(&encoded)
	_, _ = encoder.Write(body)
	_ = encoder.Close()
	return encoded.String()
}

func foldedSMTPSubject(subject string) string {
	encoded := mime.QEncoding.Encode("UTF-8", subject)
	if !strings.HasPrefix(encoded, "=?") {
		return encoded
	}
	words := strings.Fields(encoded)
	var folded strings.Builder
	lineBytes := len("Subject: ")
	for index, word := range words {
		if index > 0 {
			if lineBytes+1+len(word) > 78 {
				folded.WriteString("\r\n ")
				lineBytes = 1
			} else {
				folded.WriteByte(' ')
				lineBytes++
			}
		}
		folded.WriteString(word)
		lineBytes += len(word)
	}
	return folded.String()
}

var _ notificationruntime.ProviderTransport = (*smtpTLSTransport)(nil)
