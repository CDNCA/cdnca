package notificationruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

type tlsTestTransport struct {
	client   *http.Client
	endpoint string
}

func (t *tlsTestTransport) Ready(context.Context) error { return nil }

func (t *tlsTestTransport) Send(ctx context.Context, message ProviderMessage) (ProviderResult, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return ProviderResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return ProviderResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", message.IdempotencyKey)
	response, err := t.client.Do(request)
	if err != nil {
		return ProviderResult{}, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusAccepted:
		return ProviderResult{Disposition: ProviderAccepted}, nil
	case http.StatusTooManyRequests:
		seconds, err := strconv.Atoi(response.Header.Get("Retry-After"))
		if err != nil || seconds < 1 {
			return ProviderResult{}, errors.New("invalid retry after")
		}
		return ProviderResult{
			Disposition: ProviderRateLimited, Code: "provider_rate_limited",
			RetryAfter: time.Duration(seconds) * time.Second,
		}, nil
	default:
		return ProviderResult{Disposition: ProviderTemporaryFailure, Code: "provider_unavailable"}, nil
	}
}

func (t *tlsTestTransport) Close(context.Context) error { return nil }

func TestProviderTransportContractWithTLSServerAndRetryAfter(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || request.Header.Get("Idempotency-Key") != "notification-v1-tls" {
			http.Error(writer, "contract rejected", http.StatusBadRequest)
			return
		}
		calls++
		if calls == 1 {
			writer.Header().Set("Retry-After", "7")
			writer.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	transport := &tlsTestTransport{client: server.Client(), endpoint: server.URL}
	sender := newRecoverySender(map[notification.Channel]ProviderTransport{
		notification.ChannelEmail: transport,
	}, time.Second)
	delivery := accountrecovery.RecoveryDelivery{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: "subject", Body: "body", RecoveryURL: "https://control.example.test/reset#token=secret",
		IdempotencyKey: "notification-v1-tls", AttemptNumber: 1,
	}
	first := sender.SendRecovery(context.Background(), delivery)
	if first.Failure == nil || first.Failure.Class != notification.FailureTemporary ||
		first.Failure.Code != "provider_rate_limited" || first.Failure.RetryAfter != 7*time.Second {
		t.Fatalf("TLS rate limit result = %+v", first)
	}
	delivery.AttemptNumber++
	second := sender.SendRecovery(context.Background(), delivery)
	if second.Failure != nil || calls != 2 {
		t.Fatalf("TLS accepted result=%+v calls=%d", second, calls)
	}
}
