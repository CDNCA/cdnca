package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
)

func TestHTTPSJSONSMSTransportReadinessAndStableIdempotentRequest(t *testing.T) {
	const authToken = "sms-provider-auth-secret"
	type capturedRequest struct {
		Authorization string
		Idempotency   string
		Body          string
	}
	var mu sync.Mutex
	var captured []capturedRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+authToken {
			t.Errorf("authorization header is not the configured bearer credential")
		}
		switch request.URL.Path {
		case "/ready":
			if request.Method != http.MethodGet || request.Header.Get("Idempotency-Key") != "" {
				t.Errorf("readiness request = %s headers=%v", request.Method, request.Header)
			}
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/messages":
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" || request.URL.RawQuery != "" {
				t.Errorf("send request = %s %s headers=%v", request.Method, request.URL.String(), request.Header)
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			captured = append(captured, capturedRequest{
				Authorization: request.Header.Get("Authorization"),
				Idempotency:   request.Header.Get("Idempotency-Key"),
				Body:          string(body),
			})
			mu.Unlock()
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusAccepted)
			_, _ = writer.Write([]byte(`{"delivery_id":"sms-delivery-42"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	config := smsTestConfig(t, server, authToken)
	config.AccessKeyID = "sms-access-id"
	config.SignatureName = "CDNCA"
	transport, err := newHTTPSJSONSMSTransport(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Ready(t.Context()); err != nil {
		t.Fatalf("Ready() = %v", err)
	}
	message := notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelSMS, Contact: "+8613900000000",
		Body: "请使用安全链接", ActionURL: "https://control.example.test/reset#opaque",
		IdempotencyKey: "notification-v1-stable-sms", AttemptNumber: 1,
	}
	first, err := transport.Send(t.Context(), message)
	if err != nil || first.Disposition != notificationruntime.ProviderAccepted ||
		first.ProviderDeliveryID != "sms-delivery-42" {
		t.Fatalf("first Send() = (%+v, %v)", first, err)
	}
	message.AttemptNumber = 2
	second, err := transport.Send(t.Context(), message)
	if err != nil || second != first {
		t.Fatalf("retry Send() = (%+v, %v), first=%+v", second, err, first)
	}

	mu.Lock()
	requests := append([]capturedRequest(nil), captured...)
	mu.Unlock()
	if len(requests) != 2 || requests[0].Idempotency != message.IdempotencyKey ||
		requests[1].Idempotency != message.IdempotencyKey || requests[0].Body != requests[1].Body {
		t.Fatalf("stable requests = %+v", requests)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(requests[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	wantBody := map[string]string{
		"to": message.Contact, "subject": message.Subject, "body": message.Body, "action_url": message.ActionURL,
		"access_key_id": "sms-access-id", "signature_name": "CDNCA",
	}
	if !reflect.DeepEqual(body, wantBody) || strings.Contains(requests[0].Body, authToken) {
		t.Fatalf("SMS body = %#v", body)
	}
}

func TestHTTPSJSONSMSTransportClassifiesProviderResponses(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      int
		retryAfter  string
		disposition notificationruntime.ProviderDisposition
		code        string
		wantAfter   time.Duration
	}{
		{name: "rate limited", status: http.StatusTooManyRequests, retryAfter: "37", disposition: notificationruntime.ProviderRateLimited, code: "sms_provider_rate_limited", wantAfter: 37 * time.Second},
		{name: "temporary", status: http.StatusServiceUnavailable, disposition: notificationruntime.ProviderTemporaryFailure, code: "sms_provider_unavailable"},
		{name: "permanent", status: http.StatusBadRequest, disposition: notificationruntime.ProviderPermanentFailure, code: "sms_provider_rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if test.retryAfter != "" {
					writer.Header().Set("Retry-After", test.retryAfter)
				}
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(`{"error":"provider-private-detail"}`))
			}))
			defer server.Close()
			transport, err := newHTTPSJSONSMSTransport(smsTestConfig(t, server, "auth-secret"))
			if err != nil {
				t.Fatal(err)
			}
			result, err := transport.Send(t.Context(), validSMSProviderTestMessage())
			if err != nil || result.Disposition != test.disposition || result.Code != test.code ||
				result.RetryAfter != test.wantAfter || strings.Contains(result.Code, "provider-private-detail") {
				t.Fatalf("classified response = (%+v, %v)", result, err)
			}
		})
	}
}

func TestHTTPSJSONSMSTransportUnknownTimeoutReadyAndSecretLifecycle(t *testing.T) {
	const authToken = "sms-auth-secret-must-not-leak"
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ready":
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(authToken))
		case "/v1/messages":
			select {
			case <-request.Context().Done():
			case <-release:
			}
		}
	}))
	defer func() {
		close(release)
		server.Close()
	}()
	transport, err := newHTTPSJSONSMSTransport(smsTestConfig(t, server, authToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Ready(t.Context()); err == nil || err.Error() != "notification_sms_not_ready" || strings.Contains(err.Error(), authToken) {
		t.Fatalf("Ready() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := transport.Send(ctx, validSMSProviderTestMessage()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed Send() error = %v", err)
	}
	if err := transport.Close(t.Context()); err != nil || len(transport.config.AuthToken) != 0 {
		t.Fatalf("Close() error=%v retained_secret=%t", err, len(transport.config.AuthToken) != 0)
	}
	if _, err := transport.Send(t.Context(), validSMSProviderTestMessage()); err == nil || err.Error() != "notification_sms_closed" {
		t.Fatalf("Send() after Close = %v", err)
	}
}

func validSMSProviderTestMessage() notificationruntime.ProviderMessage {
	return notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelSMS, Contact: "+8613900000000",
		Body: "请使用安全链接", ActionURL: "https://control.example.test/reset#opaque",
		IdempotencyKey: "notification-v1-sms-test", AttemptNumber: 1,
	}
}

func smsTestConfig(t *testing.T, server *httptest.Server, authToken string) smsHTTPSJSONConfig {
	t.Helper()
	certificate := server.Certificate()
	caFile := filepath.Join(t.TempDir(), "sms-provider-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return smsHTTPSJSONConfig{
		Endpoint: server.URL + "/v1/messages", ReadyEndpoint: server.URL + "/ready",
		AuthToken: []byte(authToken), CAFile: caFile,
	}
}
