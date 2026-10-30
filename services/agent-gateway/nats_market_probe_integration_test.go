//go:build integration

package gateway

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// TestNATSMarketProbeBusRequestReply checks the core NATS semantics control-api
// relies on: no live session means no responder, a subscribed session receives
// the decoded command and its reply reaches the requester, a refusal is an
// empty reply, and closing the subscription removes the responder again.
func TestNATSMarketProbeBusRequestReply(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	gatewayConnection := connectIntegrationNATS(t, natsURL)
	defer gatewayConnection.Close()
	controlConnection := connectIntegrationNATS(t, natsURL)
	defer controlConnection.Close()
	bus, err := NewNATSMarketProbeBus(gatewayConnection)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.NewString()
	command := testMarketProbeCommand(nodeID)
	payload, err := proto.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	request := func() (*nats.Msg, error) {
		return controlConnection.Request(marketprobe.Subject(nodeID), payload, 2*time.Second)
	}
	if _, err := request(); !errors.Is(err, nats.ErrNoResponders) {
		t.Fatalf("offline node: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	subscription, err := bus.SubscribeMarketProbes(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := gatewayConnection.Flush(); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		message *nats.Msg
		err     error
	}
	answers := make(chan answer, 2)
	go func() { message, err := request(); answers <- answer{message, err} }()
	received := <-subscription.Requests()
	if !proto.Equal(received.Command(), command) {
		t.Fatalf("decoded %v", received.Command())
	}
	result := testMarketProbeResult(command)
	if err := received.Reply(result); err != nil {
		t.Fatal(err)
	}
	got := <-answers
	var decoded agentv1.MarketProbeResult
	if got.err != nil || proto.Unmarshal(got.message.Data, &decoded) != nil || !proto.Equal(&decoded, result) {
		t.Fatalf("reply %v %v", got.message, got.err)
	}
	go func() { message, err := request(); answers <- answer{message, err} }()
	refused := <-subscription.Requests()
	if err := refused.Reply(nil); err != nil {
		t.Fatal(err)
	}
	if got := <-answers; got.err != nil || len(got.message.Data) != 0 {
		t.Fatalf("refusal %v %v", got.message, got.err)
	}
	// Garbage is refused by the bus itself and never reaches the session.
	message, err := controlConnection.Request(marketprobe.Subject(nodeID), []byte{0xff, 0xff}, 2*time.Second)
	if err != nil || len(message.Data) != 0 {
		t.Fatalf("garbage %v %v", message, err)
	}
	if err := subscription.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gatewayConnection.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := request(); !errors.Is(err, nats.ErrNoResponders) {
		t.Fatalf("after close: %v", err)
	}
	if _, err := bus.SubscribeMarketProbes(ctx, "not-a-node"); err == nil {
		t.Fatal("invalid node ID subscribed")
	}
}
