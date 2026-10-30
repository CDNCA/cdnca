package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/tls"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
)

func TestSMTPTLSTransportAuthenticatesAndSendsStableIdempotencyHeader(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	transport, err := newSMTPTLSTransport(server.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Ready(t.Context()); err != nil {
		t.Fatalf("Ready() = %v", err)
	}
	result, err := transport.Send(t.Context(), notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: "账户恢复", Body: "请使用以下链接", ActionURL: "https://control.example.test/reset#opaque",
		IdempotencyKey: "notification-v1-0123456789abcdef", AttemptNumber: 1,
	})
	if err != nil || result.Disposition != notificationruntime.ProviderAccepted {
		t.Fatalf("Send() = (%+v, %v)", result, err)
	}
	messages := server.messages()
	if len(messages) != 1 || !strings.Contains(messages[0], "X-CDNCA-Idempotency-Key: notification-v1-0123456789abcdef\r\n") ||
		!strings.Contains(messages[0], "https://control.example.test/reset#opaque") ||
		strings.Contains(messages[0], "Bcc:") {
		t.Fatalf("SMTP message contract = %q", messages)
	}
	if err := transport.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Send(t.Context(), notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: "subject", Body: "body", IdempotencyKey: "notification-v1-after-close", AttemptNumber: 1,
	}); err == nil || err.Error() != "notification_smtp_closed" {
		t.Fatalf("Send() after Close = %v", err)
	}
}

func TestSMTPSTARTTLSTransportUpgradesBeforeAuthenticationAndDelivery(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{startTLS: true, advertiseStartTLS: true})
	transport, err := newSMTPTLSTransport(server.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Ready(t.Context()); err != nil {
		t.Fatalf("Ready() = %v", err)
	}
	result, err := transport.Send(t.Context(), notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: "注册验证码", Body: "验证码如下", IdempotencyKey: "registration-starttls-1", AttemptNumber: 1,
	})
	if err != nil || result.Disposition != notificationruntime.ProviderAccepted {
		t.Fatalf("Send() = (%+v, %v)", result, err)
	}
	commands := server.commands()
	var startTLS, auth, mail int
	for _, command := range commands {
		switch {
		case command.line == "STARTTLS":
			startTLS++
			if command.tls {
				t.Fatal("STARTTLS command was not sent on the plaintext SMTP connection")
			}
		case strings.HasPrefix(command.line, "AUTH "):
			auth++
			if !command.tls {
				t.Fatalf("AUTH was sent before STARTTLS: %#v", commands)
			}
		case strings.HasPrefix(command.line, "MAIL FROM:"):
			mail++
			if !command.tls {
				t.Fatalf("MAIL was sent before STARTTLS: %#v", commands)
			}
		}
	}
	if startTLS != 2 || auth != 2 || mail != 1 || len(server.messages()) != 1 {
		t.Fatalf("STARTTLS command sequence = %#v messages=%d", commands, len(server.messages()))
	}
}

func TestSMTPSTARTTLSTransportFailsClosedWithoutTLS13OrVerifiedPeer(t *testing.T) {
	tests := []struct {
		name      string
		server    smtpTestServerConfig
		mutate    func(*smtpTLSConfig)
		foreignCA bool
	}{
		{name: "missing capability", server: smtpTestServerConfig{startTLS: true}},
		{name: "TLS 1.2 only", server: smtpTestServerConfig{
			startTLS: true, advertiseStartTLS: true, tlsMaxVersion: tls.VersionTLS12,
		}},
		{name: "wrong server name", server: smtpTestServerConfig{startTLS: true, advertiseStartTLS: true},
			mutate: func(config *smtpTLSConfig) { config.ServerName = "wrong.example.test" }},
		{name: "untrusted certificate", server: smtpTestServerConfig{startTLS: true, advertiseStartTLS: true},
			foreignCA: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newSMTPTestServer(t, test.server)
			config := server.clientConfig()
			if test.foreignCA {
				foreign := newSMTPTestServer(t, smtpTestServerConfig{})
				config.CAFile = foreign.caFile
			}
			if test.mutate != nil {
				test.mutate(&config)
			}
			transport, err := newSMTPTLSTransport(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := transport.Ready(t.Context()); !errors.Is(err, errSMTPUnavailable) {
				t.Fatalf("Ready() = %v", err)
			}
			for _, command := range server.commands() {
				if !command.tls && (strings.HasPrefix(command.line, "AUTH ") || strings.HasPrefix(command.line, "MAIL FROM:")) {
					t.Fatalf("plaintext downgrade sent %q: %#v", command.line, server.commands())
				}
			}
		})
	}
}

func TestSMTPTLSTransportQuotedPrintableEncodesMaximumMultilingualSingleLine(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	transport, err := newSMTPTLSTransport(server.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	body := "." + strings.Repeat("界", (64*1024-1)/len("界"))
	if len(body) != 64*1024 {
		t.Fatalf("test body bytes = %d", len(body))
	}
	message := notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: strings.Repeat("维护通知", 40), Body: body,
		ActionURL:      "https://control.example.test/announcements/current",
		IdempotencyKey: "notification-v1-quoted-printable", AttemptNumber: 1,
	}
	result, err := transport.Send(t.Context(), message)
	if err != nil || result.Disposition != notificationruntime.ProviderAccepted {
		t.Fatalf("Send() = (%+v, %v)", result, err)
	}
	messages, wireMessages := server.messages(), server.wireMessages()
	if len(messages) != 1 || len(wireMessages) != 1 {
		t.Fatalf("SMTP messages = %d delivered / %d wire", len(messages), len(wireMessages))
	}
	parsed, err := mail.ReadMessage(strings.NewReader(messages[0]))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatalf("transfer encoding = %q", parsed.Header.Get("Content-Transfer-Encoding"))
	}
	decodedBody, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
	if err != nil {
		t.Fatal(err)
	}
	wantBody := body + "\r\n\r\n" + message.ActionURL + "\r\n"
	if string(decodedBody) != wantBody {
		t.Fatalf("decoded body bytes = %d, want %d", len(decodedBody), len(wantBody))
	}
	decodedSubject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil || decodedSubject != message.Subject {
		t.Fatalf("decoded subject = %q, %v", decodedSubject, err)
	}
	for _, line := range strings.Split(wireMessages[0], "\r\n") {
		if len(line) > 998 {
			t.Fatalf("SMTP wire line bytes = %d", len(line))
		}
	}
	if !strings.Contains(wireMessages[0], "\r\n\r\n..") {
		t.Fatal("SMTP DATA did not dot-stuff the leading body dot")
	}
	if strings.Contains(wireMessages[0], body) {
		t.Fatal("SMTP DATA contains the raw 64 KiB body line")
	}
}

func TestSMTPTLSTransportClassifiesSMTPResponses(t *testing.T) {
	for _, test := range []struct {
		name        string
		code        int
		disposition notificationruntime.ProviderDisposition
		stableCode  string
	}{
		{name: "temporary", code: 450, disposition: notificationruntime.ProviderTemporaryFailure, stableCode: "smtp_temporary"},
		{name: "nonstandard rate limit", code: 429, disposition: notificationruntime.ProviderTemporaryFailure, stableCode: "smtp_temporary"},
		{name: "permanent", code: 550, disposition: notificationruntime.ProviderPermanentFailure, stableCode: "smtp_rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newSMTPTestServer(t, smtpTestServerConfig{recipientCode: test.code})
			transport, err := newSMTPTLSTransport(server.clientConfig())
			if err != nil {
				t.Fatal(err)
			}
			result, err := transport.Send(t.Context(), notificationruntime.ProviderMessage{
				OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
				Subject: "subject", Body: "body", IdempotencyKey: "notification-v1-classify", AttemptNumber: 1,
			})
			if err != nil || result.Disposition != test.disposition || result.Code != test.stableCode || result.RetryAfter != 0 {
				t.Fatalf("classified response = (%+v, %v)", result, err)
			}
		})
	}
}

func TestSMTPTLSTransportHonorsContextTimeout(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{stallGreeting: true})
	transport, err := newSMTPTLSTransport(server.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, sendErr := transport.Send(ctx, notificationruntime.ProviderMessage{
			OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
			Subject: "subject", Body: "body", IdempotencyKey: "notification-v1-timeout", AttemptNumber: 1,
		})
		result <- sendErr
	}()
	select {
	case <-server.connectionAccepted:
	case <-time.After(time.Second):
		t.Fatal("SMTP test server did not accept the timed request")
	}
	select {
	case err = <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timed Send() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed Send() did not return")
	}
	select {
	case <-server.connectionClosed:
	case <-time.After(time.Second):
		t.Fatal("timed Send() left the SMTP connection open")
	}
	if active := server.activeConnections(); active != 0 {
		t.Fatalf("timed Send() active_connections=%d", active)
	}
}

func TestSMTPContextErrorRecognizesElapsedDeadlineBeforeContextErr(t *testing.T) {
	ctx := smtpElapsedDeadlineContext{
		Context:  context.Background(),
		deadline: time.Now().Add(-time.Millisecond),
	}
	if err := smtpContextError(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("smtpContextError() = %v", err)
	}
}

type smtpElapsedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (ctx smtpElapsedDeadlineContext) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

type smtpTestServerConfig struct {
	recipientCode     int
	stallGreeting     bool
	startTLS          bool
	advertiseStartTLS bool
	tlsMaxVersion     uint16
}

type smtpTestCommand struct {
	line string
	tls  bool
}

type smtpTestServer struct {
	listener           net.Listener
	caFile             string
	certificate        tls.Certificate
	config             smtpTestServerConfig
	connectionAccepted chan struct{}
	connectionClosed   chan struct{}
	acceptDone         chan struct{}
	connectionWait     sync.WaitGroup
	mu                 sync.Mutex
	received           []string
	receivedWire       []string
	receivedCommands   []smtpTestCommand
	connections        map[net.Conn]struct{}
}

func newSMTPTestServer(t *testing.T, config smtpTestServerConfig) *smtpTestServer {
	t.Helper()
	certificate, caPEM := smtpTestCertificate(t)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
		MaxVersion: config.tlsMaxVersion,
	}
	var listener net.Listener
	var err error
	if config.startTLS {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		listener, err = tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	}
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "smtp-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server := &smtpTestServer{
		listener: listener, caFile: caFile, certificate: certificate, config: config,
		connectionAccepted: make(chan struct{}, 16), connectionClosed: make(chan struct{}, 16),
		acceptDone: make(chan struct{}), connections: make(map[net.Conn]struct{}),
	}
	go server.serve()
	t.Cleanup(func() { server.close(t) })
	return server
}

func (server *smtpTestServer) clientConfig() smtpTLSConfig {
	return smtpTLSConfig{
		Address: server.listener.Addr().String(), ServerName: "localhost", Username: "mailer",
		Password: []byte("smtp-password"), From: "notifications@example.test", CAFile: server.caFile,
		StartTLS: server.config.startTLS,
	}
}

func (server *smtpTestServer) commands() []smtpTestCommand {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]smtpTestCommand(nil), server.receivedCommands...)
}

func (server *smtpTestServer) messages() []string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]string(nil), server.received...)
}

func (server *smtpTestServer) wireMessages() []string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]string(nil), server.receivedWire...)
}

func (server *smtpTestServer) activeConnections() int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.connections)
}

func (server *smtpTestServer) serve() {
	defer close(server.acceptDone)
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.mu.Lock()
		server.connections[connection] = struct{}{}
		server.mu.Unlock()
		server.connectionWait.Add(1)
		select {
		case server.connectionAccepted <- struct{}{}:
		default:
		}
		go func() {
			defer server.connectionWait.Done()
			server.serveConnection(connection)
		}()
	}
}

func (server *smtpTestServer) serveConnection(connection net.Conn) {
	defer func() {
		_ = connection.Close()
		server.mu.Lock()
		delete(server.connections, connection)
		server.mu.Unlock()
		select {
		case server.connectionClosed <- struct{}{}:
		default:
		}
	}()
	if server.config.stallGreeting {
		_, _ = bufio.NewReader(connection).ReadString('\n')
		return
	}
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	tlsActive := !server.config.startTLS
	writeSMTPTestLine(writer, "220 localhost ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimSpace(line)
		server.mu.Lock()
		server.receivedCommands = append(server.receivedCommands, smtpTestCommand{line: command, tls: tlsActive})
		server.mu.Unlock()
		switch {
		case strings.HasPrefix(command, "EHLO "):
			if server.config.startTLS && !tlsActive && server.config.advertiseStartTLS {
				_, _ = writer.WriteString("250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
			} else {
				_, _ = writer.WriteString("250-localhost\r\n250 AUTH PLAIN\r\n")
			}
			_ = writer.Flush()
		case command == "STARTTLS":
			if !server.config.startTLS || tlsActive || !server.config.advertiseStartTLS {
				writeSMTPTestLine(writer, "454 TLS unavailable")
				continue
			}
			writeSMTPTestLine(writer, "220 ready to start TLS")
			tlsConnection := tls.Server(connection, &tls.Config{
				Certificates: []tls.Certificate{server.certificate}, MinVersion: tls.VersionTLS12,
				MaxVersion: server.config.tlsMaxVersion,
			})
			if err := tlsConnection.Handshake(); err != nil {
				return
			}
			reader = bufio.NewReader(tlsConnection)
			writer = bufio.NewWriter(tlsConnection)
			tlsActive = true
		case strings.HasPrefix(command, "AUTH PLAIN "):
			encoded := strings.TrimPrefix(command, "AUTH PLAIN ")
			decoded, _ := base64.StdEncoding.DecodeString(encoded)
			if string(decoded) != "\x00mailer\x00smtp-password" {
				writeSMTPTestLine(writer, "535 authentication failed")
				continue
			}
			writeSMTPTestLine(writer, "235 authenticated")
		case strings.HasPrefix(command, "MAIL FROM:"):
			writeSMTPTestLine(writer, "250 sender accepted")
		case strings.HasPrefix(command, "RCPT TO:"):
			code := server.config.recipientCode
			if code == 0 {
				code = 250
			}
			writeSMTPTestLine(writer, fmt.Sprintf("%d recipient response hidden", code))
		case command == "NOOP":
			writeSMTPTestLine(writer, "250 ready")
		case command == "DATA":
			writeSMTPTestLine(writer, "354 send data")
			var message strings.Builder
			var wireMessage strings.Builder
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == ".\r\n" {
					break
				}
				wireMessage.WriteString(line)
				if strings.HasPrefix(line, "..") {
					line = line[1:]
				}
				message.WriteString(line)
			}
			server.mu.Lock()
			server.received = append(server.received, message.String())
			server.receivedWire = append(server.receivedWire, wireMessage.String())
			server.mu.Unlock()
			writeSMTPTestLine(writer, "250 queued")
		case command == "QUIT":
			writeSMTPTestLine(writer, "221 bye")
			return
		default:
			writeSMTPTestLine(writer, "500 unsupported")
		}
	}
}

func (server *smtpTestServer) close(t *testing.T) {
	t.Helper()
	_ = server.listener.Close()
	select {
	case <-server.acceptDone:
	case <-time.After(time.Second):
		t.Error("SMTP test server accept loop did not stop")
	}
	server.mu.Lock()
	connections := make([]net.Conn, 0, len(server.connections))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	server.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	done := make(chan struct{})
	go func() {
		server.connectionWait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("SMTP test server connection goroutines did not stop")
	}
}

func writeSMTPTestLine(writer *bufio.Writer, line string) {
	_, _ = writer.WriteString(line + "\r\n")
	_ = writer.Flush()
}

func smtpTestCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certificatePEM
}
