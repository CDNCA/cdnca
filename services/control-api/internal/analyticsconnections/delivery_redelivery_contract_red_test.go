package analyticsconnections

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDeliveryMetadataContractRequiresBrokerAuthorityAndSettlementCapabilities(t *testing.T) {
	valid := redeliveryContractDelivery(t)
	if err := ValidateDeliveryMetadata(valid); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
	if _, err := ValidateDelivery(validConnectionsDelivery()); err != nil {
		t.Fatalf("baseline delivery compatibility regressed: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Delivery)
	}{
		{name: "missing version", mutate: func(delivery *Delivery) { delivery.MetadataVersion = 0 }},
		{name: "unknown version", mutate: func(delivery *Delivery) { delivery.MetadataVersion++ }},
		{name: "missing attempt", mutate: func(delivery *Delivery) { delivery.Attempt = 0 }},
		{name: "missing max deliver", mutate: func(delivery *Delivery) { delivery.MaxDeliver = 0 }},
		{name: "attempt exceeds max deliver", mutate: func(delivery *Delivery) { delivery.Attempt = delivery.MaxDeliver + 1 }},
		{name: "missing stream", mutate: func(delivery *Delivery) { delivery.Stream = "" }},
		{name: "missing durable", mutate: func(delivery *Delivery) { delivery.Durable = "" }},
		{name: "missing stream sequence", mutate: func(delivery *Delivery) { delivery.StreamSequence = 0 }},
		{name: "missing consumer sequence", mutate: func(delivery *Delivery) { delivery.ConsumerSequence = 0 }},
		{name: "missing ack", mutate: func(delivery *Delivery) { delivery.Ack = nil }},
		{name: "missing nak", mutate: func(delivery *Delivery) { delivery.Nak = nil }},
		{name: "missing term", mutate: func(delivery *Delivery) { delivery.Term = nil }},
		{name: "unknown reason", mutate: func(delivery *Delivery) {
			delivery.FailureReason = DeliveryFailureReason("backend said password=secret")
		}},
		{name: "payload cannot forge attempt", mutate: func(delivery *Delivery) {
			delivery.Attempt = 0
			delivery.Payload = []byte(`{"metadata_version":1,"attempt":2,"max_deliver":4}`)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			delivery := valid
			test.mutate(&delivery)
			if err := ValidateDeliveryMetadata(delivery); !errors.Is(err, ErrInvalidDelivery) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestDeadLetterContractIsSecretSafeAndUsesBrokerIdentity(t *testing.T) {
	delivery := redeliveryContractDelivery(t)
	delivery.FailureReason = DeliveryFailureMaxDeliver
	delivery.Payload = []byte("authorization=Bearer secret-token; cookie=session-secret; X-API-Key=secret-key")
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewDeadLetterEnvelope(delivery, receipt)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-token", "session-secret", "secret-key", "authorization", "cookie", "api-key"} {
		if strings.Contains(strings.ToLower(string(encoded)), secret) {
			t.Fatalf("dead letter leaked %q: %s", secret, encoded)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"payload", "headers", "raw_payload", "raw_headers"} {
		if _, exists := fields[forbidden]; exists {
			t.Fatalf("dead letter exposed %q: %s", forbidden, encoded)
		}
	}
	if envelope.MetadataVersion != DeliveryMetadataVersion || envelope.Attempt != 2 || envelope.MaxDeliver != 4 ||
		envelope.Stream != delivery.Stream || envelope.Durable != delivery.Durable ||
		envelope.StreamSequence != delivery.StreamSequence || envelope.ConsumerSequence != delivery.ConsumerSequence ||
		envelope.FailureReason != DeliveryFailureMaxDeliver || envelope.PayloadSHA256 == "" ||
		envelope.CanonicalEventSHA256 == "" || envelope.EvidenceSHA256 == "" {
		t.Fatalf("incomplete dead letter envelope: %#v", envelope)
	}

	first, err := NewDeadLetterReceipt(envelope)
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	replayed := envelope
	replayed.ConsumerSequence++
	second, err := NewDeadLetterReceipt(replayed)
	if err != nil {
		t.Fatalf("redelivery receipt: %v", err)
	}
	if first.DeadLetterID == "" || first.DeadLetterID != second.DeadLetterID {
		t.Fatalf("consumer sequence entered identity: first=%#v second=%#v", first, second)
	}
	if first.EnvelopeSHA256 == second.EnvelopeSHA256 {
		t.Fatal("consumer sequence was not retained as audit evidence")
	}
	differentReason := envelope
	differentReason.FailureReason = DeliveryFailureReceiptConflict
	third, err := NewDeadLetterReceipt(differentReason)
	if err != nil {
		t.Fatalf("different reason receipt: %v", err)
	}
	if first.DeadLetterID == third.DeadLetterID {
		t.Fatal("failure reason was omitted from dead letter identity")
	}
}

func TestDeadLetterContractRejectsUnstableOrMismatchedFacts(t *testing.T) {
	delivery := redeliveryContractDelivery(t)
	delivery.FailureReason = DeliveryFailureClickHouseUnavailable
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Delivery, *Receipt)
	}{
		{name: "missing failure reason", mutate: func(delivery *Delivery, _ *Receipt) { delivery.FailureReason = DeliveryFailureNone }},
		{name: "unknown failure reason", mutate: func(delivery *Delivery, _ *Receipt) {
			delivery.FailureReason = DeliveryFailureReason("raw backend failure")
		}},
		{name: "stream mismatch", mutate: func(delivery *Delivery, _ *Receipt) { delivery.Stream = "OTHER" }},
		{name: "stream sequence mismatch", mutate: func(delivery *Delivery, _ *Receipt) { delivery.StreamSequence++ }},
		{name: "consumer sequence mismatch", mutate: func(delivery *Delivery, _ *Receipt) { delivery.ConsumerSequence++ }},
		{name: "receipt identity mismatch", mutate: func(_ *Delivery, receipt *Receipt) { receipt.ReceiptID = "other-receipt" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidateDelivery := delivery
			candidateReceipt := receipt
			test.mutate(&candidateDelivery, &candidateReceipt)
			if _, err := NewDeadLetterEnvelope(candidateDelivery, candidateReceipt); !errors.Is(err, ErrInvalidDelivery) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func redeliveryContractDelivery(t *testing.T) Delivery {
	t.Helper()
	delivery := validConnectionsDelivery()
	delivery.MetadataVersion = DeliveryMetadataVersion
	delivery.Attempt = 2
	delivery.MaxDeliver = 4
	delivery.Nak = func(context.Context, time.Duration) error { return nil }
	delivery.Term = func(context.Context) error { return nil }
	return delivery
}
