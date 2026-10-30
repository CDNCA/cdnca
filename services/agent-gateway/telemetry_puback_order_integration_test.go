//go:build integration

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type observedPubAckPublisher struct {
	inner    *NATSTelemetryPublisher
	js       nats.JetStreamContext
	stream   string
	observed atomic.Bool
}

func (publisher *observedPubAckPublisher) Publish(ctx context.Context, publication TelemetryPublication) (TelemetryPublishResult, error) {
	result, err := publisher.inner.Publish(ctx, publication)
	if err != nil {
		return result, err
	}
	stored, err := publisher.js.GetLastMsg(publisher.stream, TelemetryIngestSubjectPrefix+"."+publication.NodeID)
	if err != nil || stored.Sequence == 0 || stored.Header.Get(nats.MsgIdHdr) != publication.MessageID {
		return TelemetryPublishResult{}, fmt.Errorf("PubAck returned before durable message became observable")
	}
	publisher.observed.Store(true)
	return result, nil
}

func (publisher *observedPubAckPublisher) Check(ctx context.Context) error {
	return publisher.inner.Check(ctx)
}

type pubAckOrderStream struct {
	*telemetryTestStream
	pubAckObserved  *atomic.Bool
	ackBeforePubAck atomic.Bool
}

func (stream *pubAckOrderStream) Send(response *agentv1.StreamTelemetryResponse) error {
	if response.GetAck() != nil && !stream.pubAckObserved.Load() {
		stream.ackBeforePubAck.Store(true)
	}
	return stream.telemetryTestStream.Send(response)
}

func TestOBSUsageARealPubAckPrecedesAgentRPCAcknowledgement(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ANALYTICS_ORDER_TEST_" + suffix
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := addAuthoritativeTelemetryTestStream(js, streamName); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(streamName) }()

	config := DefaultNATSTelemetryPublisherConfig()
	config.Stream = streamName
	config.OperationTimeout = time.Second
	inner, err := NewNATSTelemetryPublisher(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &observedPubAckPublisher{inner: inner, js: js, stream: streamName}
	gateway := newTelemetryGateway(t,
		&telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}}}, publisher)
	base := &telemetryTestStream{ctx: authenticatedTestContext(t), requests: []*agentv1.StreamTelemetryRequest{
		telemetryHelloRequest(0, 1), telemetryBatchRequest(telemetryBatch(t, 1, 1), 2),
	}}
	stream := &pubAckOrderStream{telemetryTestStream: base, pubAckObserved: &publisher.observed}
	if err := gateway.StreamTelemetry(stream); err != nil {
		t.Fatal(err)
	}
	if stream.ackBeforePubAck.Load() || !publisher.observed.Load() || len(base.responses) != 2 || base.responses[1].GetAck() == nil {
		t.Fatalf("durable ordering violated: puback=%v ack_before_puback=%v responses=%+v",
			publisher.observed.Load(), stream.ackBeforePubAck.Load(), base.responses)
	}
}
