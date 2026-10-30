package analyticsconnections

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type deadLetterTenantScopeJetStream struct {
	streamInfoCalls int
	getMsgCalls     int
}

func (stub *deadLetterTenantScopeJetStream) StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error) {
	stub.streamInfoCalls++
	return &nats.StreamInfo{
		Config: nats.StreamConfig{Name: connectionsDeadLetterStream, Subjects: []string{connectionsDeadLetterSubject}},
	}, nil
}

func (stub *deadLetterTenantScopeJetStream) GetMsg(string, uint64, ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	stub.getMsgCalls++
	return nil, nats.ErrMsgNotFound
}

func TestDeadLetterListRejectsInvalidTenantBeforeJetStream(t *testing.T) {
	for _, tenantID := range []string{
		"not-a-uuid",
		"11111111-1111-1111-1111-AAAAAAAAAAAA",
		"00000000-0000-0000-0000-000000000000",
	} {
		t.Run(tenantID, func(t *testing.T) {
			t.Run("list", func(t *testing.T) {
				jetstream := &deadLetterTenantScopeJetStream{}
				store := &NATSDlqReceiptStore{jetstream: jetstream, operationTimeout: time.Second}
				rows, err := store.ListDeadLetters(context.Background(), DeadLetterQuery{TenantID: tenantID, Limit: 1})
				if !errors.Is(err, ErrDeadLetterReceiptInvalidRequest) || rows != nil {
					t.Fatalf("ListDeadLetters() = %#v, %v", rows, err)
				}
				if jetstream.streamInfoCalls != 0 || jetstream.getMsgCalls != 0 {
					t.Fatalf("JetStream calls = StreamInfo %d, GetMsg %d; want 0, 0", jetstream.streamInfoCalls, jetstream.getMsgCalls)
				}
			})
			t.Run("page", func(t *testing.T) {
				jetstream := &deadLetterTenantScopeJetStream{}
				store := &NATSDlqReceiptStore{jetstream: jetstream, operationTimeout: time.Second}
				rows, cursor, err := store.ListDeadLettersPage(context.Background(), DeadLetterQuery{TenantID: tenantID, Limit: 1})
				if !errors.Is(err, ErrDeadLetterReceiptInvalidRequest) || rows != nil || cursor != 0 {
					t.Fatalf("ListDeadLettersPage() = %#v, %d, %v", rows, cursor, err)
				}
				if jetstream.streamInfoCalls != 0 || jetstream.getMsgCalls != 0 {
					t.Fatalf("JetStream calls = StreamInfo %d, GetMsg %d; want 0, 0", jetstream.streamInfoCalls, jetstream.getMsgCalls)
				}
			})
		})
	}
}

func TestDeadLetterListAllowsGlobalAndCanonicalTenantScope(t *testing.T) {
	for _, tenantID := range []string{"", "11111111-1111-1111-1111-111111111111"} {
		jetstream := &deadLetterTenantScopeJetStream{}
		store := &NATSDlqReceiptStore{jetstream: jetstream, operationTimeout: time.Second}
		rows, cursor, err := store.ListDeadLettersPage(context.Background(), DeadLetterQuery{TenantID: tenantID, Limit: 1})
		if err != nil || len(rows) != 0 || cursor != 0 {
			t.Fatalf("tenant %q page = %#v, %d, %v", tenantID, rows, cursor, err)
		}
		if jetstream.streamInfoCalls != 1 || jetstream.getMsgCalls != 0 {
			t.Fatalf("tenant %q JetStream calls = StreamInfo %d, GetMsg %d", tenantID, jetstream.streamInfoCalls, jetstream.getMsgCalls)
		}
	}
}
