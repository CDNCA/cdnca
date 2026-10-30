package mail

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// TLS modes of an SMTP server. There is no plaintext mode.
const (
	// TLSImplicit connects with TLS from the first byte (usually port 465).
	TLSImplicit = "tls"
	// TLSStartTLS connects in plaintext and must upgrade with STARTTLS
	// before authenticating or sending (usually 587 or 25).
	TLSStartTLS = "starttls"
)

// SMTPConfig is a built-in SMTP server. Username and Password are both set
// (PLAIN auth over TLS) or both empty (no auth).
type SMTPConfig struct {
	Host     string
	Port     int
	TLS      string
	Username string
	Password string
	From     string
	FromName string
	// RootCAs overrides the system roots (tests); Timeout defaults to 15s.
	RootCAs *x509.CertPool
	Timeout time.Duration
}

// ValidSMTPConfig checks a configuration without connecting.
func ValidSMTPConfig(config SMTPConfig) bool {
	return validHost(config.Host) && config.Port >= 1 && config.Port <= 65535 &&
		(config.TLS == TLSImplicit || config.TLS == TLSStartTLS) && ValidAddress(config.From) && ValidName(config.FromName) &&
		(config.Username == "") == (config.Password == "") && len(config.Username) <= 256 && len(config.Password) <= 1024 &&
		!strings.ContainsAny(config.Username+config.Password, "\r\n\x00")
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

// NewSMTP builds the SMTP sender.
func NewSMTP(config SMTPConfig) (Sender, error) {
	if !ValidSMTPConfig(config) {
		return nil, failure(Permanent, CodeInvalidConfig)
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}
	return smtpSender{config}, nil
}

type smtpSender struct{ config SMTPConfig }

func (sender smtpSender) Send(ctx context.Context, message Message) (Result, error) {
	if !validMessage(message) {
		return Result{}, failure(Permanent, CodeInvalidMessage)
	}
	config := sender.config
	deadline := time.Now().Add(config.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	tlsConfig := &tls.Config{ServerName: config.Host, RootCAs: config.RootCAs, MinVersion: tls.VersionTLS12}
	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	dialer := &net.Dialer{Deadline: deadline}
	var connection net.Conn
	var err error
	if config.TLS == TLSImplicit {
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", address)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return Result{}, contextOr(ctx, failure(Temporary, CodeUnavailable))
	}
	defer connection.Close()
	_ = connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	client, err := smtp.NewClient(connection, config.Host)
	if err != nil {
		return Result{}, contextOr(ctx, failure(Temporary, CodeUnavailable))
	}
	defer client.Close()
	if config.TLS == TLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return Result{}, failure(Permanent, CodeTLSRequired)
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return Result{}, contextOr(ctx, failure(Permanent, CodeTLSRequired))
		}
	}
	if state, ok := client.TLSConnectionState(); !ok || !state.HandshakeComplete {
		return Result{}, failure(Permanent, CodeTLSRequired)
	}
	if config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", config.Username, config.Password, config.Host)); err != nil {
			return Result{}, contextOr(ctx, smtpReplyError(err, CodeCredentialRejected))
		}
	}
	if err := client.Mail(config.From); err != nil {
		return Result{}, contextOr(ctx, smtpReplyError(err, CodeSenderRejected))
	}
	if err := client.Rcpt(message.To); err != nil {
		return Result{}, contextOr(ctx, smtpReplyError(err, CodeRecipientRejected))
	}
	writer, err := client.Data()
	if err != nil {
		return Result{}, contextOr(ctx, smtpReplyError(err, CodeRejected))
	}
	if _, err := writer.Write([]byte(BuildMIME(config.From, config.FromName, config.Host, message, time.Now()))); err != nil {
		_ = writer.Close()
		return Result{}, contextOr(ctx, failure(Unknown, CodeResponseUnknown))
	}
	if err := writer.Close(); err != nil {
		// The server saw the whole message: a missing answer may mean it took it.
		var reply *textproto.Error
		if errors.As(err, &reply) {
			return Result{}, smtpReplyError(err, CodeRejected)
		}
		return Result{}, contextOr(ctx, failure(Unknown, CodeResponseUnknown))
	}
	_ = client.Quit()
	return Result{}, nil
}

// smtpReplyError: 4xx is temporary, 5xx permanent with code; no reply at
// all is a connection failure (temporary).
func smtpReplyError(err error, permanentCode string) *Error {
	var reply *textproto.Error
	switch {
	case !errors.As(err, &reply):
		return failure(Temporary, CodeUnavailable)
	case reply.Code == 421 || reply.Code == 450 || reply.Code == 451 || reply.Code == 452:
		return failure(Temporary, CodeUnavailable)
	case reply.Code >= 400 && reply.Code < 500:
		return failure(Temporary, CodeRejected)
	default:
		return failure(Permanent, permanentCode)
	}
}

func contextOr(ctx context.Context, err *Error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// BuildMIME renders the message: text/plain alone, or multipart/alternative
// with the HTML part. A non-empty Message.ID makes Message-ID and the
// boundary stable so a retry is byte-identical apart from Date.
func BuildMIME(from, fromName, host string, message Message, now time.Time) string {
	seed := message.ID
	if seed == "" {
		seed = randomNonce()
	}
	digest := sha256.Sum256([]byte(seed))
	fromHeader := "<" + from + ">"
	if fromName != "" {
		name := mime.QEncoding.Encode("UTF-8", fromName)
		if name == fromName {
			// ASCII: a quoted-string (ValidName excludes '"' and CR/LF).
			name = `"` + strings.ReplaceAll(fromName, `\`, `\\`) + `"`
		}
		fromHeader = name + " " + fromHeader
	}
	headers := fmt.Sprintf("From: %s\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <cdnca-%x@%s>\r\nMIME-Version: 1.0\r\n",
		fromHeader, message.To, mime.QEncoding.Encode("UTF-8", message.Subject), now.UTC().Format(time.RFC1123Z), digest[:16], host)
	if message.ReplyTo != "" {
		headers += "Reply-To: <" + message.ReplyTo + ">\r\n"
	}
	text := quotedPrintable(normalizeLines(message.Text))
	if message.HTML == "" {
		return headers + "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + text + "\r\n"
	}
	// Quoted-printable output never contains "--cdnca-alt-".
	boundary := fmt.Sprintf("cdnca-alt-%x", digest[16:28])
	return headers + "Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n" +
		"--" + boundary + "\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		text + "\r\n--" + boundary + "\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		quotedPrintable(normalizeLines(message.HTML)) + "\r\n--" + boundary + "--\r\n"
}

func normalizeLines(value string) string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")
	return strings.ReplaceAll(value, "\n", "\r\n")
}

func quotedPrintable(value string) string {
	var encoded strings.Builder
	writer := quotedprintable.NewWriter(&encoded)
	_, _ = writer.Write([]byte(value))
	_ = writer.Close()
	return encoded.String()
}

func randomNonce() string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	return hex.EncodeToString(value[:])
}
