package domaineventfanout

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/domaineventsource"
	"github.com/google/uuid"
)

func TestWebhookDataAddsDeliveryFieldsToContractPayload(t *testing.T) {
	subscription := uuid.New()
	payload := []byte(`{"attempt":1,"deployment_id":"` + uuid.NewString() + `","node_id":"` + uuid.NewString() +
		`","rollout_id":"` + uuid.NewString() + `","state":"healthy","transition_sequence":2}`)
	data, err := webhookData(payload, subscription, 7)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !domaineventsource.ValidWebhookData(domaineventsource.DeploymentStatusChangedType, subscription.String(), decoded) ||
		string(decoded["subject_sequence"]) != "7" {
		t.Fatalf("webhook data invalid: %s", data)
	}
}

func TestWebhookDataRejectsReservedOrInvalidSourcePayload(t *testing.T) {
	for _, payload := range []string{`[]`, `null`, `{"subscription_id":"x"}`, `{"subject_sequence":1}`, `{`} {
		if _, err := webhookData([]byte(payload), uuid.New(), 1); err == nil {
			t.Fatalf("payload %s accepted", payload)
		}
	}
	if _, err := webhookData([]byte(`{}`), uuid.New(), 0); err == nil {
		t.Fatal("zero subject sequence accepted")
	}
}

func TestSanitizeErrorBoundsReceiptErrors(t *testing.T) {
	if got := sanitizeError(errors.New(strings.Repeat("x", maxReceiptError+100))); len(got) != maxReceiptError {
		t.Fatalf("error length = %d, want %d", len(got), maxReceiptError)
	}
	if got := sanitizeError(nil); got != "fanout_failed" {
		t.Fatalf("nil error = %q", got)
	}
}

func TestFanoutConfigBounds(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty config = %v", err)
	}
	if defaultLeaseDuration <= 0 || defaultRetryDelay <= 0 || time.Minute <= 0 {
		t.Fatal("invalid default durations")
	}
}

func TestWorkerKeepsSourceLeaseAndReceiptTransitionsDurable(t *testing.T) {
	body, err := os.ReadFile("worker.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"FOR UPDATE OF outbox SKIP LOCKED",
		"delivery_state='leased'",
		"lease_expired",
		"lease_expires_at <= clock_timestamp()",
		"domain_event_fanout_receipts_368",
		"ON CONFLICT (source_id,subscription_id) DO NOTHING",
		"contract.required_permission = ANY(installation.approved_scopes)",
		"earlier.subject_sequence < outbox.subject_sequence",
		"subscription.created_at <= $4",
		"subscription.site_ids IS NULL OR",
		"status='published'",
		"status='failed'",
		"RequestID:      source.id.String()",
	} {
		if !strings.Contains(string(body), marker) {
			t.Errorf("worker missing durable fanout marker %q", marker)
		}
	}
	if strings.Contains(string(body), "last_error=$2") {
		t.Fatal("source publication must not retain receipt error in migration-367 last_error field")
	}
}
