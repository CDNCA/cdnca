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

// TestNATSSiteDropBusResendsNewestSnapshotPerSession checks the JetStream
// semantics the gateway relies on for site drop: streams are created
// idempotently (a second gateway or a restart binds them), every new session
// (reconnect, gateway restart) starts from the node's newest snapshot even
// after it was delivered, later snapshots reach a live session, other nodes'
// snapshots never do, and receipts land on the receipt stream deduplicated by
// event ID.
func TestNATSSiteDropBusResendsNewestSnapshotPerSession(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	config := DefaultNATSSiteDropBusConfig()
	config.CommandStream, config.ReceiptStream = "SITE_DROP_COMMANDS_"+suffix, "SITE_DROP_RECEIPTS_"+suffix
	config.CommandSubjectPrefix = "cdnca.test.site-drop." + suffix + ".commands"
	config.ReceiptSubjectPrefix = "cdnca.test.site-drop." + suffix + ".receipts"
	config.OperationTimeout = 200 * time.Millisecond
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(config.CommandStream); _ = js.DeleteStream(config.ReceiptStream) }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bus, err := NewNATSSiteDropBus(ctx, connection, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNATSSiteDropBus(ctx, connection, config); err != nil {
		t.Fatalf("second gateway instance must bind the existing streams: %v", err)
	}
	nodeID, otherNode := "01990000-0000-7000-8000-000000000057", "01990000-0000-7000-8000-000000000058"
	publish := func(node string, revision uint64) *agentv1.SiteDropCommand {
		command := testSiteDropCommand(t, node, revision)
		payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(command)
		message := nats.NewMsg(config.CommandSubjectPrefix + "." + node)
		message.Data = payload
		message.Header.Set(nats.MsgIdHdr, command.Event.EventId)
		if _, err := js.PublishMsg(message, nats.ExpectStream(config.CommandStream)); err != nil {
			t.Fatal(err)
		}
		return command
	}
	next := func(subscription SiteDropSubscription) *agentv1.SiteDropCommand {
		t.Helper()
		nextCtx, nextCancel := context.WithTimeout(ctx, 3*time.Second)
		defer nextCancel()
		command, err := subscription.Next(nextCtx)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	publish(nodeID, 1)
	newest := publish(nodeID, 2)
	publish(otherNode, 1)
	// A malformed publication is skipped.
	if _, err := js.Publish(config.CommandSubjectPrefix+"."+nodeID, []byte{0xff}, nats.ExpectStream(config.CommandStream)); err != nil {
		t.Fatal(err)
	}
	newest = publish(nodeID, 3)
	for session := range 2 {
		subscription, err := bus.SubscribeSiteDrops(ctx, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if got := next(subscription); !proto.Equal(got, newest) {
			t.Fatalf("session %d started from revision %d, want %d", session, got.Revision, newest.Revision)
		}
		if session == 1 {
			live := publish(nodeID, 4)
			if got := next(subscription); !proto.Equal(got, live) {
				t.Fatalf("live session got revision %d, want 4", got.Revision)
			}
			short, shortCancel := context.WithTimeout(ctx, 500*time.Millisecond)
			if extra, err := subscription.Next(short); err == nil {
				t.Fatalf("unexpected snapshot %v (another node's or a repeat)", extra)
			}
			shortCancel()
		}
		_ = subscription.Close()
	}
	info, err := js.StreamInfo(config.CommandStream)
	if err != nil || info.State.Msgs != 2 {
		t.Fatalf("command stream keeps %v messages (want the newest per node): %v", info, err)
	}
	receipt := notSupportedSiteDropReceipt(newest, time.Now())
	first, err := bus.PublishSiteDropReceipt(ctx, nodeID, receipt)
	if err != nil || first.Stream != config.ReceiptStream || first.Sequence == 0 {
		t.Fatalf("publish receipt = %+v %v", first, err)
	}
	again, err := bus.PublishSiteDropReceipt(ctx, nodeID, receipt)
	if err != nil || !again.Replayed || again.Sequence != first.Sequence {
		t.Fatalf("replayed receipt = %+v %v", again, err)
	}
	if _, err := bus.PublishSiteDropReceipt(ctx, otherNode, receipt); err == nil {
		t.Fatal("receipt published under another node")
	}
}

// TestNATSSiteDropGatewayRestartResendsToAgent: the production Connect
// service over the production NATS bus with a stand-in Agent (mTLS gRPC
// client). Each gateway instance (a restart creates a new one binding the
// same streams) hands the connecting SITE_DROP v1 Agent the current
// snapshot; its receipt reaches the receipt stream.
func TestNATSSiteDropGatewayRestartResendsToAgent(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	config := DefaultNATSSiteDropBusConfig()
	config.CommandStream, config.ReceiptStream = "SITE_DROP_COMMANDS_"+suffix, "SITE_DROP_RECEIPTS_"+suffix
	config.CommandSubjectPrefix = "cdnca.test.site-drop." + suffix + ".commands"
	config.ReceiptSubjectPrefix = "cdnca.test.site-drop." + suffix + ".receipts"
	config.OperationTimeout = 200 * time.Millisecond
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(config.CommandStream); _ = js.DeleteStream(config.ReceiptStream) }()
	if _, err := NewNATSSiteDropBus(t.Context(), connection, config); err != nil {
		t.Fatal(err)
	}
	command := testSiteDropCommand(t, testNodeID, 6)
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if _, err := js.Publish(config.CommandSubjectPrefix+"."+testNodeID, payload, nats.ExpectStream(config.CommandStream)); err != nil {
		t.Fatal(err)
	}
	features := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: 1}}
	for instance := range 2 {
		bus, err := NewNATSSiteDropBus(t.Context(), connection, config)
		if err != nil {
			t.Fatal(err)
		}
		stream, _, hello := connectSiteDropSession(t, bus, features)
		if !siteDropCapabilityEnabled(hello) {
			t.Fatalf("instance %d did not enable SITE_DROP", instance)
		}
		response, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if delivered := response.GetSiteDropCommand(); delivered == nil || !proto.Equal(delivered, command) {
			t.Fatalf("instance %d delivered %v", instance, response.Payload)
		}
		sendSiteDropReceiptRequest(t, stream, 2, testSiteDropReceipt(command))
		eventually(t, 5*time.Second, func() bool {
			info, err := js.StreamInfo(config.ReceiptStream)
			return err == nil && info.State.Msgs == uint64(2*instance+1)
		}, "receipt did not reach the receipt stream")
		// The session survives the receipt: a newer snapshot still arrives.
		newer := testSiteDropCommand(t, testNodeID, command.Revision+1)
		encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(newer)
		if _, err := js.Publish(config.CommandSubjectPrefix+"."+testNodeID, encoded, nats.ExpectStream(config.CommandStream)); err != nil {
			t.Fatal(err)
		}
		response, err = stream.Recv()
		if err != nil || !proto.Equal(response.GetSiteDropCommand(), newer) {
			t.Fatalf("instance %d after receipt: %v %v", instance, response, err)
		}
		sendSiteDropReceiptRequest(t, stream, 3, testSiteDropReceipt(newer))
		eventually(t, 5*time.Second, func() bool {
			info, err := js.StreamInfo(config.ReceiptStream)
			return err == nil && info.State.Msgs == uint64(2*instance+2)
		}, "second receipt did not reach the receipt stream")
		command = newer
		_ = stream.CloseSend()
	}
}
