//go:build integration

package gateway

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// TestNATSSignerTrustBusKeepsNewestBundleAndPublishesReceipts checks the JetStream semantics the gateway relies on for signer trust:
// the bus creates its streams idempotently, a node that was offline receives only the newest bundle, a superseded
// in-flight delivery can still be settled, and receipts land on the status stream with the event ID as dedupe key.
func TestNATSSignerTrustBusKeepsNewestBundleAndPublishesReceipts(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	config := DefaultNATSSignerTrustBusConfig()
	config.CommandStream, config.StatusStream = "EDGE_SIGNER_TRUST_COMMANDS_"+suffix, "EDGE_SIGNER_TRUST_STATUS_"+suffix
	config.CommandSubjectPrefix = "cdnca.test.signer-trust." + suffix + ".commands"
	config.StatusSubjectPrefix = "cdnca.test.signer-trust." + suffix + ".status"
	config.ConsumerPrefix = "signer_trust_" + suffix
	config.OperationTimeout = 200 * time.Millisecond
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(config.CommandStream); _ = js.DeleteStream(config.StatusStream) }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bus, err := NewNATSSignerTrustBus(ctx, connection, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNATSSignerTrustBus(ctx, connection, config); err != nil {
		t.Fatalf("second gateway instance must bind the existing streams: %v", err)
	}
	nodeID := "01990000-0000-7000-8000-000000000007"
	publish := func(revision uint64) *agentv1.EdgeSignerTrustBundle {
		bundle := testSignerTrustBundle(t, nodeID, revision)
		payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(bundle)
		message := nats.NewMsg(config.CommandSubjectPrefix + "." + nodeID)
		message.Data = payload
		message.Header.Set(nats.MsgIdHdr, bundle.Event.EventId)
		if _, err := js.PublishMsg(message, nats.ExpectStream(config.CommandStream)); err != nil {
			t.Fatal(err)
		}
		return bundle
	}
	publish(1)
	publish(2)
	newest := publish(3)
	subscription, err := bus.SubscribeSignerTrust(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	delivery, err := subscription.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := delivery.Bundle(); got.Revision != 3 || got.Event.EventId != newest.Event.EventId {
		t.Fatalf("delivered revision %d, want only the newest bundle", got.Revision)
	}
	// A newer bundle replaces the in-flight one; settling the superseded delivery must still succeed.
	newer := publish(4)
	receipt := testSignerTrustReceipt(t, newest, 3)
	publication, err := bus.PublishSignerTrustReceipt(ctx, nodeID, receipt)
	if err != nil || publication.Stream != config.StatusStream || publication.Sequence == 0 {
		t.Fatalf("publication = %+v err=%v", publication, err)
	}
	if replay, err := bus.PublishSignerTrustReceipt(ctx, nodeID, receipt); err != nil || !replay.Replayed {
		t.Fatalf("receipt replay = %+v err=%v", replay, err)
	}
	if err := delivery.Ack(ctx); err != nil {
		t.Fatalf("ack superseded delivery: %v", err)
	}
	next, err := subscription.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := next.Bundle(); got.Event.EventId != newer.Event.EventId {
		t.Fatalf("next revision %d, want the newer bundle", got.Revision)
	}
	if err := next.Ack(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := js.StreamInfo(config.CommandStream)
	if err != nil || info.State.Msgs != 0 {
		t.Fatalf("command stream state = %+v err=%v, want empty after settlement", info.State, err)
	}
	status, err := js.StreamInfo(config.StatusStream)
	if err != nil || status.State.Msgs != 1 {
		t.Fatalf("status stream state = %+v err=%v", status.State, err)
	}
}
