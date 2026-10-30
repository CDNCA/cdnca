package analyticsconnections

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type deadLetterStoreJetStreamStub struct {
	info     *nats.StreamInfo
	messages map[uint64]*nats.RawStreamMsg
}

func (stub *deadLetterStoreJetStreamStub) StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error) {
	return stub.info, nil
}

func (stub *deadLetterStoreJetStreamStub) GetMsg(_ string, sequence uint64, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	message, ok := stub.messages[sequence]
	if !ok {
		return nil, nats.ErrMsgNotFound
	}
	return message, nil
}

func TestNATSDlqReceiptStoreReadsDurableIdentityAndBounds(t *testing.T) {
	first := validDeadLetterRawMessage(t, 3, 11, DeliveryFailureMaxDeliver)
	second := validDeadLetterRawMessage(t, 4, 12, DeliveryFailureReceiptConflict)
	first.Time = time.Date(2026, 8, 7, 12, 1, 2, 3e6, time.UTC)
	second.Time = first.Time.Add(time.Second)
	stub := &deadLetterStoreJetStreamStub{
		info:     &nats.StreamInfo{Config: nats.StreamConfig{Name: connectionsDeadLetterStream, Subjects: []string{connectionsDeadLetterSubject}}, State: nats.StreamState{FirstSeq: 3, LastSeq: 4, Msgs: 2}},
		messages: map[uint64]*nats.RawStreamMsg{3: first, 4: second},
	}
	store, err := NewNATSDlqReceiptStore(stub, time.Second)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	page, err := store.ListDeadLetters(context.Background(), DeadLetterQuery{Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page) != 2 || page[0].DeadLetterSequence != 3 || page[1].DeadLetterSequence != 4 {
		t.Fatalf("page = %#v", page)
	}
	if page[0].Stream != "CONNECTIONS_INGEST_V1" || page[0].SourceStream != "CONNECTIONS_INGEST_V1" ||
		page[0].DeadLetterStream != connectionsDeadLetterStream ||
		page[0].SourceStreamSequence != 11 || page[0].Attempt != 4 || page[0].MaxDeliver != 4 ||
		page[0].FailureReason != DeliveryFailureMaxDeliver || page[0].MessageID == "" ||
		page[0].CreatedAt.IsZero() || !page[0].SettledAt.Equal(page[0].CreatedAt) {
		t.Fatalf("durable identity = %#v", page[0])
	}
	if page[0].PayloadSHA256 == "" || page[0].CanonicalEventSHA256 == "" || page[0].EvidenceSHA256 == "" {
		t.Fatalf("digest-only evidence missing = %#v", page[0])
	}
	encoded, err := json.Marshal(page[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"authorization", "cookie", "secret-token"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("raw payload leaked %q: %s", forbidden, encoded)
		}
	}
	byID, err := store.GetDeadLetter(context.Background(), page[0].DeadLetterID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if byID.DeadLetterID != page[0].DeadLetterID || byID.MessageID != page[0].MessageID {
		t.Fatalf("get identity = %#v", byID)
	}

	if _, err := store.ListDeadLetters(context.Background(), DeadLetterQuery{AfterSequence: 3, Limit: 1}); err != nil {
		t.Fatalf("bounded continuation: %v", err)
	}
	if _, err := store.ListDeadLetters(context.Background(), DeadLetterQuery{Limit: 0}); !errors.Is(err, ErrDeadLetterReceiptInvalidRequest) {
		t.Fatalf("invalid limit error = %v", err)
	}
}

func TestNATSDlqReceiptStoreRejectsMessageIDAndEnvelopeConflicts(t *testing.T) {
	message := validDeadLetterRawMessage(t, 3, 11, DeliveryFailureMaxDeliver)
	stub := &deadLetterStoreJetStreamStub{
		info:     &nats.StreamInfo{Config: nats.StreamConfig{Name: connectionsDeadLetterStream, Subjects: []string{connectionsDeadLetterSubject}}, State: nats.StreamState{FirstSeq: 3, LastSeq: 3, Msgs: 1}},
		messages: map[uint64]*nats.RawStreamMsg{3: message},
	}
	store, err := NewNATSDlqReceiptStore(stub, time.Second)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	message.Header.Set(nats.MsgIdHdr, "wrong")
	if _, err := store.ListDeadLetters(context.Background(), DeadLetterQuery{Limit: 1}); !errors.Is(err, ErrDeadLetterReceiptConflict) {
		t.Fatalf("message id drift error = %v", err)
	}

	message = validDeadLetterRawMessage(t, 3, 11, DeliveryFailureMaxDeliver)
	var envelope DeadLetterEnvelope
	if err := json.Unmarshal(message.Data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.StreamSequence++
	message.Data, _ = json.Marshal(envelope)
	stub.messages[3] = message
	if _, err := store.ListDeadLetters(context.Background(), DeadLetterQuery{Limit: 1}); !errors.Is(err, ErrDeadLetterReceiptConflict) {
		t.Fatalf("envelope drift error = %v", err)
	}
}

func TestNATSDlqReceiptStoreExposesPoisonAsDigestOnly(t *testing.T) {
	delivery := runtimeRedeliveryDelivery(t, 4, 4)
	delivery.FailureReason = DeliveryFailureInvalid
	payload := []byte(`{"metadata_version":1,"stream":"CONNECTIONS_INGEST_V1","durable":"control_api_connections","stream_sequence":11,"consumer_sequence":9,"attempt":4,"max_deliver":4,"failure_reason":"invalid_delivery","payload_sha256":"47f9e3105e9949e88e223f79ad649eb8f35d0b70821131ab26e07e9ea2774955"}`)
	identity := DeadLetterIdentityDigest(delivery.Stream, delivery.StreamSequence, delivery.FailureReason)
	message := &nats.RawStreamMsg{
		Subject: connectionsDeadLetterSubject, Sequence: 3,
		Header: nats.Header{nats.MsgIdHdr: []string{hex.EncodeToString(identity[:])}}, Data: payload,
		Time: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
	}
	stub := &deadLetterStoreJetStreamStub{
		info:     &nats.StreamInfo{Config: nats.StreamConfig{Name: connectionsDeadLetterStream, Subjects: []string{connectionsDeadLetterSubject}}, State: nats.StreamState{FirstSeq: 3, LastSeq: 3, Msgs: 1}},
		messages: map[uint64]*nats.RawStreamMsg{3: message},
	}
	store, err := NewNATSDlqReceiptStore(stub, time.Second)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	receipts, err := store.ListDeadLetters(context.Background(), DeadLetterQuery{Limit: 1})
	if err != nil {
		t.Fatalf("list poison: %v", err)
	}
	if len(receipts) != 1 || !receipts[0].Poison || receipts[0].TenantID != "" || receipts[0].PayloadSHA256 == "" {
		t.Fatalf("poison receipt = %#v", receipts)
	}
}

func validDeadLetterRawMessage(t *testing.T, deadLetterSequence, sourceSequence uint64, reason DeliveryFailureReason) *nats.RawStreamMsg {
	t.Helper()
	delivery := runtimeRedeliveryDelivery(t, 4, 4)
	delivery.StreamSequence = sourceSequence
	delivery.PubAck.Sequence = sourceSequence
	delivery.FailureReason = reason
	receipt, err := ValidateDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := deadLetterMessage(delivery, receipt)
	if err != nil {
		t.Fatal(err)
	}
	identity := DeadLetterIdentityDigest(delivery.Stream, sourceSequence, reason)
	return &nats.RawStreamMsg{
		Subject:  connectionsDeadLetterSubject,
		Sequence: deadLetterSequence,
		Header:   nats.Header{nats.MsgIdHdr: []string{hex.EncodeToString(identity[:])}},
		Data:     payload,
		Time:     time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
	}
}
