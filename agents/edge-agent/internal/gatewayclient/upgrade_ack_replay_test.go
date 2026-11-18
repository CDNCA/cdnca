package gatewayclient

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The session ended after the claimed ACK was persisted but before
// its receipt was confirmed. The Gateway replays every unconfirmed ACK at session start
// (gateway.go listUpgradeStatusAcks); the status had already left the pending outbox, so
// the agent stopped with "upgrade status acknowledgement does not match the durable outbox".
func TestClientAcceptsReplayedUpgradeStatusAckIdempotently(t *testing.T) {
	runtime := &durableReceiptUpgradeRuntime{upgradeOrderingRuntime: newUpgradeOrderingRuntime()}
	if err := runtime.AcceptCommand(context.Background(), []byte("command")); err != nil {
		t.Fatal(err)
	}
	client := &Client{upgrades: runtime}
	status := runtime.status
	ack := &agentv1.UpgradeStatusAck{
		StatusEventId: status.Status.StatusID, CommandId: status.Status.CommandID,
		StatusRevision: status.Status.StatusRevision, StatusSha256: mustDecodeHex(t, status.SHA256),
		PersistedTime:   timestamppb.New(time.Unix(100, 0).UTC()),
		PublishedStream: edgeUpgradeStatusStream, PublishedSequence: 41,
	}
	accepted, receipt, err := client.persistUpgradeStatusAcknowledgement(context.Background(), ack)
	if err != nil || !accepted || receipt == nil {
		t.Fatalf("first ACK = (%t, %#v, %v)", accepted, receipt, err)
	}

	// Replayed before the receipt was confirmed: the session start already sent the
	// pending receipt, so none is sent again (a second confirmation would not match).
	replayAccepted, replayReceipt, err := client.persistUpgradeStatusAcknowledgement(context.Background(), proto.Clone(ack).(*agentv1.UpgradeStatusAck))
	if err != nil || replayAccepted != accepted || replayReceipt != nil {
		t.Fatalf("replayed unconfirmed ACK = (%t, %#v, %v), want (%t, nil, nil)", replayAccepted, replayReceipt, err, accepted)
	}
	if pending, err := client.pendingUpgradeStatusAcknowledgements(context.Background()); err != nil || len(pending) != 1 ||
		!proto.Equal(pending[0], receipt) {
		t.Fatalf("pending receipts after replay = (%#v, %v), want the original receipt", pending, err)
	}

	// A replay that differs from the durable ACK still fails closed.
	conflicting := proto.Clone(ack).(*agentv1.UpgradeStatusAck)
	conflicting.PersistedTime = timestamppb.New(time.Unix(101, 0).UTC())
	if _, _, err := client.persistUpgradeStatusAcknowledgement(context.Background(), conflicting); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("conflicting replayed ACK error = %v, want ErrInvalidMessage", err)
	}

	// Replayed after confirmation: nothing is left to confirm, so no receipt is sent.
	if confirmed, err := client.confirmUpgradeStatusAcknowledgement(context.Background(), receipt); err != nil || !confirmed {
		t.Fatalf("confirmation = (%t, %v)", confirmed, err)
	}
	_, confirmedReceipt, err := client.persistUpgradeStatusAcknowledgement(context.Background(), proto.Clone(ack).(*agentv1.UpgradeStatusAck))
	if err != nil || confirmedReceipt != nil {
		t.Fatalf("replayed confirmed ACK = (%#v, %v), want (nil, nil)", confirmedReceipt, err)
	}
}
