package pluginwebhook

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type staticSecrets struct{ secret []byte }

func (provider staticSecrets) Secret(context.Context, uuid.UUID, uuid.UUID) ([]byte, error) {
	return append([]byte(nil), provider.secret...), nil
}

type v2SecretLookup struct {
	target, subscription, secretVersion uuid.UUID
}

type staticV2Secrets struct {
	secret  []byte
	lookups chan v2SecretLookup
}

func (provider staticV2Secrets) Secret(_ context.Context, target, subscription, secretVersion uuid.UUID) ([]byte, error) {
	provider.lookups <- v2SecretLookup{target: target, subscription: subscription, secretVersion: secretVersion}
	return append([]byte(nil), provider.secret...), nil
}

func TestHTTPSenderPinsDNSPreservesTLSServerNameAndSignsBody(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	var received atomic.Int64
	serverAddress, roots, closeServer := startWebhookTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		headers := SignatureHeaders{
			Timestamp: request.Header.Get(HeaderTimestamp), DeliveryID: request.Header.Get(HeaderDeliveryID),
			ContentSHA256: request.Header.Get(HeaderContentSHA256), Signature: request.Header.Get(HeaderSignature),
		}
		if err := Verify(secret, time.Now(), time.Minute, headers, body); err != nil {
			t.Errorf("verify request: %v", err)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.Header.Get(HeaderIdempotencyKey) == "" || request.Header.Get(HeaderAttempt) != "1" {
			t.Errorf("headers = %#v", request.Header)
		}
		received.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true,"token":"must-redact"}`))
	}))
	defer closeServer()

	config := DefaultHTTPSenderConfig()
	config.RootCAs = roots
	sender, err := newHTTPSender(config, staticSecrets{secret: secret}, staticResolver{
		addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
	}, redirectDialer(serverAddress))
	if err != nil {
		t.Fatal(err)
	}
	item := testQueueItem(t, "success", "https://hooks.example.com/events")
	target, err := resolveTarget(context.Background(), item.TargetURL, sender.resolver)
	if err != nil {
		t.Fatal(err)
	}
	if sender.transport(target).Proxy != nil {
		t.Fatal("HTTP proxy must be disabled")
	}
	result := sender.Deliver(context.Background(), item, 1)
	if !result.Success || result.Code != "delivered" || result.StatusCode != http.StatusOK || received.Load() != 1 {
		t.Fatalf("result=%#v received=%d", result, received.Load())
	}
	if result.ResponsePreview == "" || result.ResponsePreview == `{"ok":true,"token":"must-redact"}` {
		t.Fatalf("response preview = %q", result.ResponsePreview)
	}
}

func TestHTTPSenderV2SendsCanonicalBytesExactHeadersAndIndependentHMAC(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	lookup := make(chan v2SecretLookup, 2)
	var received atomic.Int64
	var firstSignature, firstTimestamp string
	item, body := testV2QueueItem(t, "https://hooks.example.com/v1/events")
	serverAddress, roots, closeServer := startWebhookTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestBody, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(requestBody, body) {
			t.Errorf("body = %q want exact %q", requestBody, body)
		}
		digest := sha256.Sum256(body)
		timestamp := request.Header.Get(HeaderTimestamp)
		payload := strings.Join([]string{
			"cdnca.webhook.signature/v2", "POST", request.URL.EscapedPath(), timestamp,
			item.EventID.String(), item.DeliveryID.String(), item.SecretVersionID.String(), hex.EncodeToString(digest[:]),
		}, "\n")
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(payload))
		wantSignature := "v2=" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if request.Header.Get("Content-Type") != "application/cloudevents+json" ||
			request.Header.Get(HeaderEventIDV2) != item.EventID.String() ||
			request.Header.Get(HeaderDeliveryIDV2) != item.DeliveryID.String() ||
			request.Header.Get(HeaderContentSHA256) != hex.EncodeToString(digest[:]) ||
			request.Header.Get(HeaderKeyIDV2) != item.SecretVersionID.String() ||
			request.Header.Get(HeaderSignatureVersionV2) != "v2" ||
			request.Header.Get(HeaderSignature) != wantSignature ||
			request.Header.Get(HeaderIdempotencyKey) != item.IdempotencyKey ||
			request.Header.Get(HeaderAttempt) != strconv.FormatInt(received.Load()+1, 10) ||
			request.Header.Get(HeaderDeliveryID) != "" {
			t.Errorf("v2 headers = %#v", request.Header)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if received.Load() == 0 {
			firstSignature, firstTimestamp = wantSignature, timestamp
		} else if firstSignature == wantSignature || firstTimestamp == timestamp {
			t.Error("second attempt did not receive a fresh timestamp/signature")
		}
		received.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer closeServer()

	item.TargetURL = "https://hooks.example.com/v1/events"
	var clock atomic.Int64
	config := DefaultHTTPSenderConfig()
	config.RootCAs = roots
	config.Now = func() time.Time { return time.Unix(1704067200+clock.Add(1), 0).UTC() }
	sender, err := newV2HTTPSender(config, staticV2Secrets{secret: secret, lookups: lookup}, staticResolver{
		addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
	}, redirectDialer(serverAddress))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := uint64(1); attempt <= 2; attempt++ {
		result := sender.Deliver(context.Background(), item, attempt)
		if !result.Success || result.StatusCode != http.StatusNoContent {
			t.Fatalf("attempt %d result = %#v", attempt, result)
		}
		got := <-lookup
		if got.target != item.TargetScopeID || got.subscription != item.SubscriptionID || got.secretVersion != item.SecretVersionID {
			t.Fatalf("secret lookup = %#v", got)
		}
	}
	preparedSecret := append([]byte(nil), secret...)
	result := sender.DeliverV2(context.Background(), item, 3, preparedSecret)
	if !result.Success || result.StatusCode != http.StatusNoContent || !bytes.Equal(preparedSecret, secret) {
		t.Fatalf("prepared attempt result = %#v secret_changed=%t", result, !bytes.Equal(preparedSecret, secret))
	}
	select {
	case got := <-lookup:
		t.Fatalf("prepared attempt performed a second secret lookup: %#v", got)
	default:
	}
	clear(preparedSecret)
	if received.Load() != 3 {
		t.Fatalf("received = %d", received.Load())
	}
}

func TestHTTPSenderRejectsRedirectSlowAndReboundTargets(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	serverAddress, roots, closeServer := startWebhookTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/redirect":
			writer.Header().Set("Location", "https://127.0.0.1/private")
			writer.WriteHeader(http.StatusFound)
		case "/slow":
			time.Sleep(500 * time.Millisecond)
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer closeServer()
	config := DefaultHTTPSenderConfig()
	config.RootCAs = roots
	config.MaxResponseBytes = 1024
	config.MaxPreviewBytes = 128
	config.RequestTimeout = 200 * time.Millisecond
	config.ConnectTimeout = 100 * time.Millisecond
	config.TLSHandshakeTimeout = 100 * time.Millisecond
	config.ResponseHeaderTimeout = 150 * time.Millisecond
	resolver := &sequenceResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")}, {netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	sender, err := newHTTPSender(config, staticSecrets{secret: secret}, resolver, redirectDialer(serverAddress))
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "https://hooks.example.com"
	tests := []struct {
		path string
		code string
	}{
		{"/redirect", "redirect_forbidden"},
		{"/slow", "timeout"},
		{"/never-dialed", "target_forbidden"},
	}
	for index, test := range tests {
		result := sender.Deliver(context.Background(), testQueueItem(t, "failure-"+strconv.Itoa(index), baseURL+test.path), 1)
		if result.Code != test.code {
			t.Fatalf("path %s result = %#v", test.path, result)
		}
	}
	if resolver.index.Load() != int64(len(tests)) {
		t.Fatalf("DNS lookups = %d want %d", resolver.index.Load(), len(tests))
	}
}

func TestHTTPSenderSettlesFromStatusWhenDiagnosticBodyIsIncompleteOrOversized(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	serverAddress, roots, closeServer := startWebhookTLSServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/partial-success":
			connection, buffered, err := writer.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\npartial")
			_ = buffered.Flush()
			_ = connection.Close()
		case "/oversized-success":
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(bytes.Repeat([]byte("s"), 1025))
		case "/oversized-retry":
			writer.Header().Set("Retry-After", "120")
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write(bytes.Repeat([]byte("r"), 1025))
		}
	}))
	defer closeServer()

	config := DefaultHTTPSenderConfig()
	config.RootCAs = roots
	config.MaxResponseBytes = 1024
	config.MaxPreviewBytes = 128
	sender, err := newHTTPSender(config, staticSecrets{secret: secret}, staticResolver{
		addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
	}, redirectDialer(serverAddress))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path       string
		success    bool
		retryable  bool
		code       string
		statusCode int
		retryAfter time.Duration
	}{
		{path: "/partial-success", success: true, code: "delivered", statusCode: http.StatusOK},
		{path: "/oversized-success", success: true, code: "delivered", statusCode: http.StatusOK},
		{path: "/oversized-retry", retryable: true, code: "remote_5xx", statusCode: http.StatusServiceUnavailable, retryAfter: 120 * time.Second},
	}
	for index, test := range tests {
		result := sender.Deliver(context.Background(), testQueueItem(t, "diagnostic-body-"+strconv.Itoa(index),
			"https://hooks.example.com"+test.path), 1)
		if result.Success != test.success || result.Retryable != test.retryable || result.Code != test.code ||
			result.StatusCode != test.statusCode || result.RetryAfter != test.retryAfter {
			t.Fatalf("path %s result = %#v", test.path, result)
		}
		if result.ResponseSHA256 != "" || result.ResponseBytes < 0 || result.ResponseBytes > int(config.MaxResponseBytes) ||
			len(result.ResponsePreview) > config.MaxPreviewBytes {
			t.Fatalf("path %s diagnostic metadata is not bounded: %#v", test.path, result)
		}
	}
}

func TestHTTPSenderTreatsTLSProtocolAndNonTLSRecordsAsPermanent(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	legacyAddress, _, closeLegacy := startWebhookServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), &tls.Config{
		MaxVersion: tls.VersionTLS11,
	})
	defer closeLegacy()
	plainAddress, closePlain := startWebhookPlainServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer closePlain()
	config := DefaultHTTPSenderConfig()
	config.RequestTimeout = time.Second
	config.ConnectTimeout = time.Second
	config.TLSHandshakeTimeout = time.Second
	config.ResponseHeaderTimeout = time.Second
	resolver := staticResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	for _, test := range []struct {
		name    string
		address string
	}{
		{name: "tls protocol", address: legacyAddress},
		{name: "non tls record", address: plainAddress},
	} {
		t.Run(test.name, func(t *testing.T) {
			sender, err := newHTTPSender(config, staticSecrets{secret: secret}, resolver, redirectDialer(test.address))
			if err != nil {
				t.Fatal(err)
			}
			result := sender.Deliver(context.Background(), testQueueItem(t, strings.ReplaceAll(test.name, " ", "-"), "https://hooks.example.com/events"), 1)
			if result.Retryable || result.Code != "tls_handshake_failed" {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

type sequenceResolver struct {
	answers [][]netip.Addr
	index   atomic.Int64
}

func (resolver *sequenceResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	index := int(resolver.index.Add(1) - 1)
	if index >= len(resolver.answers) {
		return nil, nil
	}
	return resolver.answers[index], nil
}

func testQueueItem(t *testing.T, eventID, targetURL string) QueueItem {
	t.Helper()
	item, err := newQueueItem(PublishRequest{
		TenantID: testTenantID, InstallationID: testInstallationID, EventID: eventID,
		EventType: "io.cdnca.site.v1.updated", TargetURL: targetURL,
		OccurredAt: time.Now().UTC(), Data: []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func testV2QueueItem(t *testing.T, targetURL string) (QueueItem, []byte) {
	t.Helper()
	targetScopeID := uuid.MustParse("018cc251-f400-7def-8000-000000000020")
	tenantID := uuid.MustParse("018cc251-f400-7def-8000-000000000021")
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000022")
	secretVersionID := uuid.MustParse("018cc251-f400-7def-8000-000000000023")
	eventID := uuid.MustParse("018cc251-f400-7def-8000-000000000024")
	deliveryID := uuid.MustParse("018cc251-f400-7def-8000-000000000025")
	body, err := json.Marshal(canonicalEventV2{
		SpecVersion: CloudEventsV1, ID: eventID, Source: "/control-plane/plugin-webhooks",
		Type: "io.cdnca.webhook.v1.test", Subject: "webhook_subscription/" + subscriptionID.String(),
		Time: time.Date(2026, 7, 29, 8, 0, 0, 123456000, time.UTC), DataContentType: "application/json",
		DataSchema: "https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json",
		TenantID:   tenantID, RequestID: "request-http-v2", Sequence: 1,
		Data: struct {
			SubscriptionID uuid.UUID `json:"subscription_id"`
			Test           bool      `json:"test"`
		}{SubscriptionID: subscriptionID, Test: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err := NewV2QueueItem(body, V2QueueIdentity{
		TargetScopeID: targetScopeID, TenantID: tenantID, SubscriptionID: subscriptionID,
		SecretVersionID: secretVersionID, EventID: eventID, DeliveryID: deliveryID,
	}, "plugin-webhook-v2-"+strings.Repeat("a", 64), targetURL)
	if err != nil {
		t.Fatal(err)
	}
	return item, body
}

func redirectDialer(serverAddress string) dialContextFunc {
	dialer := &net.Dialer{Timeout: time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, serverAddress)
	}
}

func serverPort(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func startWebhookTLSServer(t *testing.T, handler http.Handler) (string, *x509.CertPool, func()) {
	return startWebhookServer(t, handler, &tls.Config{MinVersion: tls.VersionTLS12})
}

func startWebhookServer(t *testing.T, handler http.Handler, tlsConfig *tls.Config) (string, *x509.CertPool, func()) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hooks.example.com"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"hooks.example.com"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.Certificates = []tls.Certificate{certificate}
	tlsListener := tls.NewListener(listener, tlsConfig)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		_ = server.Serve(tlsListener)
		close(done)
	}()
	roots := x509.NewCertPool()
	parsedCertificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsedCertificate)
	return listener.Addr().String(), roots, func() {
		_ = server.Close()
		<-done
	}
}

func startWebhookPlainServer(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(done)
	}()
	return listener.Addr().String(), func() {
		_ = server.Close()
		<-done
	}
}
