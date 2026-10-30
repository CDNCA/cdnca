package analyticsconnections

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSDlqReceiptStoreFillsTenantPageAcrossInterleavedRecords(t *testing.T) {
	first := validDeadLetterRawMessage(t, 3, 11, DeliveryFailureMaxDeliver)
	other := validDeadLetterRawMessage(t, 4, 12, DeliveryFailureMaxDeliver)
	var otherEnvelope DeadLetterEnvelope
	if err := json.Unmarshal(other.Data, &otherEnvelope); err != nil {
		t.Fatal(err)
	}
	otherEnvelope.TenantID = "99999999-9999-9999-9999-999999999999"
	other.Data, _ = json.Marshal(otherEnvelope)
	third := validDeadLetterRawMessage(t, 5, 13, DeliveryFailureMaxDeliver)
	stub := &deadLetterStoreJetStreamStub{
		info: &nats.StreamInfo{
			Config: nats.StreamConfig{Name: connectionsDeadLetterStream, Subjects: []string{connectionsDeadLetterSubject}},
			State:  nats.StreamState{FirstSeq: 3, LastSeq: 5, Msgs: 3},
		},
		messages: map[uint64]*nats.RawStreamMsg{3: first, 4: other, 5: third},
	}
	store, err := NewNATSDlqReceiptStore(stub, time.Second)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	page, err := store.ListDeadLetters(context.Background(), DeadLetterQuery{
		TenantID: "11111111-1111-1111-1111-111111111111", Limit: 2,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page) != 2 || page[0].DeadLetterSequence != 3 || page[1].DeadLetterSequence != 5 {
		t.Fatalf("tenant page = %#v, want source sequences 3 and 5", page)
	}
}

func TestNATSDlqReceiptStoreContinuesSparseTenantPageAfterScanLimit(t *testing.T) {
	const targetSequence = uint64(MaximumDeadLetterScan + 1)
	target := validDeadLetterRawMessage(t, targetSequence, targetSequence, DeliveryFailureMaxDeliver)
	stub := &deadLetterStoreJetStreamStub{
		info: &nats.StreamInfo{
			Config: nats.StreamConfig{Name: connectionsDeadLetterStream, Subjects: []string{connectionsDeadLetterSubject}},
			State:  nats.StreamState{FirstSeq: 1, LastSeq: targetSequence, Msgs: 1},
		},
		messages: map[uint64]*nats.RawStreamMsg{targetSequence: target},
	}
	store, err := NewNATSDlqReceiptStore(stub, time.Second)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	pagedStore, ok := any(store).(interface {
		ListDeadLettersPage(context.Context, DeadLetterQuery) ([]DeadLetterReceiptView, uint64, error)
	})
	if !ok {
		t.Fatal("NATSDlqReceiptStore does not expose bounded scan continuation")
	}

	firstPage, next, err := pagedStore.ListDeadLettersPage(context.Background(), DeadLetterQuery{
		TenantID: "11111111-1111-1111-1111-111111111111", Limit: 1,
	})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(firstPage) != 0 || next != MaximumDeadLetterScan {
		t.Fatalf("first page = %#v, next = %d; want empty page and next %d", firstPage, next, MaximumDeadLetterScan)
	}

	secondPage, next, err := pagedStore.ListDeadLettersPage(context.Background(), DeadLetterQuery{
		TenantID: "11111111-1111-1111-1111-111111111111", AfterSequence: next, Limit: 1,
	})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(secondPage) != 1 || secondPage[0].DeadLetterSequence != targetSequence || next != 0 {
		t.Fatalf("second page = %#v, next = %d; want sequence %d and terminal cursor", secondPage, next, targetSequence)
	}
}
