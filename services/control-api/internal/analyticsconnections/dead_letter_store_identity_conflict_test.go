package analyticsconnections

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSDlqReceiptStoreDetailRejectsConflictingDurableIdentity(t *testing.T) {
	first := validDeadLetterRawMessage(t, 3, 11, DeliveryFailureMaxDeliver)
	conflicting := validDeadLetterRawMessage(t, 4, 11, DeliveryFailureMaxDeliver)
	var envelope DeadLetterEnvelope
	if err := json.Unmarshal(conflicting.Data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.TenantID = "22222222-2222-2222-2222-222222222222"
	conflicting.Data, _ = json.Marshal(envelope)
	conflicting.Time = first.Time.Add(time.Second)

	store := newDeadLetterIdentityStore(t, first, conflicting)
	if _, err := store.GetDeadLetter(context.Background(), first.Header.Get(nats.MsgIdHdr)); !errors.Is(err, ErrDeadLetterReceiptConflict) {
		t.Fatalf("conflicting durable identity error = %v, want %v", err, ErrDeadLetterReceiptConflict)
	}
}

func TestNATSDlqReceiptStoreDetailAcceptsEquivalentReplay(t *testing.T) {
	first := validDeadLetterRawMessage(t, 3, 11, DeliveryFailureMaxDeliver)
	replay := validDeadLetterRawMessage(t, 4, 11, DeliveryFailureMaxDeliver)
	replay.Time = first.Time.Add(time.Second)

	store := newDeadLetterIdentityStore(t, first, replay)
	receipt, err := store.GetDeadLetter(context.Background(), first.Header.Get(nats.MsgIdHdr))
	if err != nil {
		t.Fatalf("equivalent replay: %v", err)
	}
	if receipt.DeadLetterID != first.Header.Get(nats.MsgIdHdr) || receipt.DeadLetterSequence != first.Sequence {
		t.Fatalf("receipt = %#v, want first equivalent fact", receipt)
	}
}

func newDeadLetterIdentityStore(t *testing.T, messages ...*nats.RawStreamMsg) *NATSDlqReceiptStore {
	t.Helper()
	bySequence := make(map[uint64]*nats.RawStreamMsg, len(messages))
	for _, message := range messages {
		bySequence[message.Sequence] = message
	}
	stub := &deadLetterStoreJetStreamStub{
		info: &nats.StreamInfo{
			Config: nats.StreamConfig{Name: connectionsDeadLetterStream, Subjects: []string{connectionsDeadLetterSubject}},
			State:  nats.StreamState{FirstSeq: messages[0].Sequence, LastSeq: messages[len(messages)-1].Sequence, Msgs: uint64(len(messages))},
		},
		messages: bySequence,
	}
	store, err := NewNATSDlqReceiptStore(stub, time.Second)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}
