package edgeoutbox

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// fix-cfgflow2 §3: a queued or retrying APPLY that a newer deployment of the
// same node and scope replaced (or whose deployment already ended) is closed
// at the sender, not published; the node's revision gate stays the backstop.
func TestPublishBatchClosesSupersededCommandWithoutPublishing(t *testing.T) {
	stale := validClaim(t)
	stale.superseded = true
	current := validClaim(t)
	current.outboxID = uuid.New()
	store := &fakeStore{commands: []claimedCommand{stale, current}}
	messages := &fakeMessages{ack: publishAck{stream: DefaultConfig().Stream}}
	publisher := testPublisher(t, store, messages)

	result, err := publisher.PublishBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result != (BatchResult{Claimed: 2, Published: 1, Superseded: 1}) {
		t.Fatalf("result = %+v", result)
	}
	if len(messages.calls) != 1 || messages.calls[0].messageID != current.commandEventID.String() {
		t.Fatalf("publish calls = %+v", messages.calls)
	}
	if len(store.superseded) != 1 || store.superseded[0] != stale.outboxID || len(store.failed) != 0 {
		t.Fatalf("closed=%v failed=%v", store.superseded, store.failed)
	}
}
