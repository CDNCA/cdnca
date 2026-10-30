//go:build integration

package gateway

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// Round trip over a real JetStream: control-api publishes a part, the gateway delivers it to the node session,
// the node's receipt lands on the receipt stream before the part is acknowledged (work queue empties), an
// unsettled part is redelivered to the next session, and a report retry is deduplicated by node/scope/seq.
func TestAutoDefenseNATSRoundTrip(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	config := DefaultNATSAutoDefenseBusConfig()
	config.CommandStream, config.ReceiptStream, config.ReportStream = "ADC_"+suffix, "ADR_"+suffix, "ADP_"+suffix
	config.CommandSubjectPrefix = "cdnca.test." + suffix + ".commands"
	config.ReceiptSubjectPrefix = "cdnca.test." + suffix + ".receipts"
	config.ReportSubjectPrefix = "cdnca.test." + suffix + ".reports"
	config.ConsumerPrefix = "autodefense_" + suffix
	config.AckWait = 500 * time.Millisecond
	config.OperationTimeout = time.Second

	connection := connectIntegrationNATS(t, natsURL)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bus, err := NewNATSAutoDefenseBus(ctx, connection, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []string{config.CommandStream, config.ReceiptStream, config.ReportStream} {
		name := stream
		t.Cleanup(func() { _ = js.DeleteStream(name) })
	}
	// Recreating the bus verifies the existing streams instead of failing.
	if _, err := NewNATSAutoDefenseBus(ctx, connection, config); err != nil {
		t.Fatalf("verify existing streams: %v", err)
	}

	publishPart := func(command *agentv1.AutoDefenseCommand) {
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := js.Publish(config.CommandSubjectPrefix+"."+testNodeID, payload, nats.ExpectStream(config.CommandStream)); err != nil {
			t.Fatal(err)
		}
	}
	first := testAutoDefenseCommand(t, testNodeID, 1)
	publishPart(first)

	// Session 1 takes the part and drops without a receipt.
	subscription, err := bus.SubscribeAutoDefense(ctx, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := subscription.Next(ctx)
	if err != nil || !proto.Equal(delivery.Command(), first) {
		t.Fatalf("first delivery: %v", err)
	}
	if err := validateAutoDefenseCommand(delivery.Command(), testNodeID); err != nil {
		t.Fatalf("delivered part does not bind: %v", err)
	}
	if err := delivery.Nak(ctx); err != nil {
		t.Fatal(err)
	}
	_ = subscription.Close()

	// Session 2 gets the same part again, settles it with a receipt, then the part is acknowledged.
	subscription, err = bus.SubscribeAutoDefense(ctx, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	delivery, err = subscription.Next(ctx)
	if err != nil || delivery.Command().Event.EventId != first.Event.EventId {
		t.Fatalf("redelivery: %v", err)
	}
	receipt := testAutoDefenseReceipt(first)
	if err := validateAutoDefenseReceipt(receipt, delivery.Command(), testNodeID); err != nil {
		t.Fatal(err)
	}
	publication, err := bus.PublishAutoDefenseReceipt(ctx, testNodeID, receipt)
	if err != nil || publication.Stream != config.ReceiptStream || publication.Sequence == 0 {
		t.Fatalf("receipt publication = %+v %v", publication, err)
	}
	if replay, err := bus.PublishAutoDefenseReceipt(ctx, testNodeID, receipt); err != nil || !replay.Replayed {
		t.Fatalf("receipt retry not deduplicated: %+v %v", replay, err)
	}
	if err := delivery.Ack(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := js.StreamInfo(config.CommandStream)
	if err != nil || info.State.Msgs != 0 {
		t.Fatalf("command stream after ack: %+v %v", info, err)
	}
	receipts, err := js.SubscribeSync(config.ReceiptSubjectPrefix+".*", nats.BindStream(config.ReceiptStream), nats.DeliverAll())
	if err != nil {
		t.Fatal(err)
	}
	defer receipts.Unsubscribe()
	message, err := receipts.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	stored := &agentv1.AutoDefenseReceipt{}
	if err := proto.Unmarshal(message.Data, stored); err != nil || !proto.Equal(stored, receipt) ||
		message.Subject != config.ReceiptSubjectPrefix+"."+testNodeID {
		t.Fatalf("stored receipt %s: %v", message.Subject, err)
	}

	// A malformed publication is terminated, the next valid part still arrives.
	if _, err := js.Publish(config.CommandSubjectPrefix+"."+testNodeID, []byte{0xff, 0x01}, nats.ExpectStream(config.CommandStream)); err != nil {
		t.Fatal(err)
	}
	second := testAutoDefenseCommand(t, testNodeID, 2)
	publishPart(second)
	delivery, err = subscription.Next(ctx)
	if err != nil || delivery.Command().Event.EventId != second.Event.EventId {
		t.Fatalf("after malformed: %v", err)
	}
	if err := delivery.Ack(ctx); err != nil {
		t.Fatal(err)
	}

	// Reports: idempotent by node/scope/seq.
	report := testAutoDefenseReport(t, testNodeID, 11, "z=9")
	key, err := autoDefenseReportKey(report, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	for attempt, wantReplay := range []bool{false, true} {
		publication, err := bus.PublishAutoDefenseReport(ctx, testNodeID, key, report.ReportJson)
		if err != nil || publication.Stream != config.ReportStream || publication.Replayed != wantReplay {
			t.Fatalf("report attempt %d = %+v %v", attempt, publication, err)
		}
	}
	info, err = js.StreamInfo(config.ReportStream)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("report stream: %+v %v", info, err)
	}
	stored2, err := js.GetLastMsg(config.ReportStream, config.ReportSubjectPrefix+"."+testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := autodefense.DecodeReport(stored2.Data); err != nil || decoded.Seq != 11 {
		t.Fatalf("stored report: %v", err)
	}
}

// Full gateway round trip on JetStream: control-api publishes a part, a real mTLS Connect session (deployments
// paused) delivers it, the node's receipt is on the receipt stream, the part leaves the work queue only then,
// and a node report reaches the report stream.
func TestAutoDefenseGatewaySessionNATSRoundTrip(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	config := DefaultNATSAutoDefenseBusConfig()
	config.CommandStream, config.ReceiptStream, config.ReportStream = "ADC_"+suffix, "ADR_"+suffix, "ADP_"+suffix
	config.CommandSubjectPrefix = "cdnca.test." + suffix + ".commands"
	config.ReceiptSubjectPrefix = "cdnca.test." + suffix + ".receipts"
	config.ReportSubjectPrefix = "cdnca.test." + suffix + ".reports"
	config.ConsumerPrefix = "autodefense_" + suffix
	config.OperationTimeout = time.Second
	connection := connectIntegrationNATS(t, natsURL)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	bus, err := NewNATSAutoDefenseBus(context.Background(), connection, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []string{config.CommandStream, config.ReceiptStream, config.ReportStream} {
		name := stream
		t.Cleanup(func() { _ = js.DeleteStream(name) })
	}
	command := testAutoDefenseCommand(t, testNodeID, 1)
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if _, err := js.Publish(config.CommandSubjectPrefix+"."+testNodeID, payload, nats.ExpectStream(config.CommandStream)); err != nil {
		t.Fatal(err)
	}
	stream, _, _, ctx := connectAutoDefenseSession(t, bus, autoDefenseFeatures())
	response, err := stream.Recv()
	if err != nil || !proto.Equal(response.GetAutoDefenseCommand(), command) {
		t.Fatalf("delivered %v %v", response, err)
	}
	if info, err := js.StreamInfo(config.CommandStream); err != nil || info.State.Msgs != 1 {
		t.Fatalf("part left the queue before its receipt: %+v %v", info, err)
	}
	receipt := testAutoDefenseReceipt(command)
	sendAutoDefense(t, stream, 2, &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_AutoDefenseReceipt{AutoDefenseReceipt: receipt}})
	sendAutoDefense(t, stream, 3, &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_AutoDefenseReport{
		AutoDefenseReport: testAutoDefenseReport(t, testNodeID, 1, "z=9")}})
	for {
		commands, _ := js.StreamInfo(config.CommandStream)
		receipts, _ := js.StreamInfo(config.ReceiptStream)
		reports, _ := js.StreamInfo(config.ReportStream)
		if commands != nil && receipts != nil && reports != nil &&
			commands.State.Msgs == 0 && receipts.State.Msgs == 1 && reports.State.Msgs == 1 {
			break
		}
		select {
		case <-ctx.Done():
			_, recvErr := stream.Recv()
			t.Fatalf("session: %v; streams: commands=%v receipts=%v reports=%v", recvErr, commands.State.Msgs, receipts.State.Msgs, reports.State.Msgs)
		case <-time.After(20 * time.Millisecond):
		}
	}
	stored, err := js.GetLastMsg(config.ReceiptStream, config.ReceiptSubjectPrefix+"."+testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	got := &agentv1.AutoDefenseReceipt{}
	if err := proto.Unmarshal(stored.Data, got); err != nil || !proto.Equal(got, receipt) {
		t.Fatalf("stored receipt: %v", err)
	}
}
