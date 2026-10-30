package telemetryclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testNodeID   = "018f47a2-5b9c-7d31-8a60-104c9c0b717f"
	testTenantID = "018f47a2-5b9c-7d31-8a60-104c9c0b7180"
	testSiteID   = "018f47a2-5b9c-7d31-8a60-104c9c0b7181"
	testConfigID = "018f47a2-5b9c-7d31-8a60-104c9c0b7182"
)

func TestMessageAndBatchIdentityBindsSiteConfigTuple(t *testing.T) {
	identity := func(siteID, configID string) (string, string) {
		messageID := telemetryMessageID(testNodeID, testTenantID, siteID, configID,
			"access.v1", "event-first", "event-last")
		return messageID, batchID([]Record{{
			MessageID: messageID, FirstSequence: 41, LastSequence: 42, LastEventID: "event-last",
		}})
	}

	messageID, batchID := identity(testSiteID, testConfigID)
	replayedMessageID, replayedBatchID := identity(testSiteID, testConfigID)
	if replayedMessageID != messageID || replayedBatchID != batchID {
		t.Fatal("exact replay changed stable message or batch identity")
	}
	for name, tuple := range map[string]struct{ siteID, configID string }{
		"site":   {siteID: "018f47a2-5b9c-7d31-8a60-104c9c0b7183", configID: testConfigID},
		"config": {siteID: testSiteID, configID: "018f47a2-5b9c-7d31-8a60-104c9c0b7184"},
	} {
		changedMessageID, changedBatchID := identity(tuple.siteID, tuple.configID)
		if changedMessageID == messageID || changedBatchID == batchID {
			t.Fatalf("%s authority did not change stable message and batch identity", name)
		}
	}
}

type fixedCursor struct {
	sequence uint64
	calls    atomic.Int32
}

func (c *fixedCursor) AcknowledgedSequence(context.Context) (uint64, error) {
	c.calls.Add(1)
	return c.sequence, nil
}

type testGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	handle func(grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error
}

func (g *testGateway) StreamTelemetry(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
	return g.handle(stream)
}

type bufDialer struct {
	listener *bufconn.Listener
}

type bufConnection struct {
	connection *grpc.ClientConn
}

func (c *bufConnection) Client() agentv1.AgentGatewayServiceClient {
	return agentv1.NewAgentGatewayServiceClient(c.connection)
}

func (c *bufConnection) Close() error { return c.connection.Close() }

func (d *bufDialer) Dial(ctx context.Context) (Connection, error) {
	connection, err := grpc.DialContext(ctx, "passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return d.listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	return &bufConnection{connection: connection}, nil
}

func TestClientMapsPartialAndDuplicateAcknowledgements(t *testing.T) {
	cursor := &fixedCursor{sequence: 7}
	bootID := uuid.NewString()
	var receivedHello *agentv1.TelemetryClientHello
	var receivedBatch *agentv1.TelemetryBatch
	dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		receivedHello = request.GetHello()
		if err := stream.Send(validGatewayHello(1, 2)); err != nil {
			return err
		}
		request, err = stream.Recv()
		if err != nil {
			return err
		}
		receivedBatch = request.GetBatch()
		first := receivedBatch.Records[0]
		response := ackResponse(2, receivedBatch.BatchId, 1, 1, first)
		response.GetAck().RetryAfterDuration = durationpb.New(25 * time.Millisecond)
		return stream.Send(response)
	})
	defer cleanup()
	client := newTestClient(t, cursor, bootID, dialer)
	ack, err := client.Send(context.Background(), Batch{Records: []Record{testRecord(8), testRecord(9)}})
	if !errors.Is(err, ErrPartialAcknowledged) || ack.Accepted != 1 || RetryAfter(err) != 25*time.Millisecond {
		t.Fatalf("partial Send() = %+v, %v", ack, err)
	}
	if receivedHello == nil || receivedHello.BootId != bootID || receivedHello.LastDurableAcknowledgedSequence != 7 {
		t.Fatalf("telemetry hello = %+v", receivedHello)
	}
	if receivedBatch == nil || len(receivedBatch.Records) != 2 || receivedBatch.FirstSequence != 8 || receivedBatch.LastSequence != 9 {
		t.Fatalf("telemetry batch = %+v", receivedBatch)
	}

	dialer, cleanup = startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(validGatewayHello(1, 2)); err != nil {
			return err
		}
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		batch := request.GetBatch()
		last := batch.Records[len(batch.Records)-1]
		return stream.Send(ackResponse(2, batch.BatchId, uint32(len(batch.Records)), uint32(len(batch.Records)), last))
	})
	defer cleanup()
	client = newTestClient(t, cursor, bootID, dialer)
	ack, err = client.Send(context.Background(), Batch{Records: []Record{testRecord(8), testRecord(9)}})
	if err != nil || ack.Accepted != 2 {
		t.Fatalf("duplicate Send() = %+v, %v", ack, err)
	}
}

func TestClientReconnectsUnknownResultWithStableBatch(t *testing.T) {
	cursor := &fixedCursor{sequence: 20}
	var sessions atomic.Int32
	var mu sync.Mutex
	var batchIDs []string
	dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
		session := sessions.Add(1)
		hello, err := stream.Recv()
		if err != nil {
			return err
		}
		if hello.GetHello().LastDurableAcknowledgedSequence != 20 {
			return status.Error(codes.InvalidArgument, "cursor changed")
		}
		if err := stream.Send(validGatewayHello(1, 1)); err != nil {
			return err
		}
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		batch := request.GetBatch()
		mu.Lock()
		batchIDs = append(batchIDs, batch.BatchId)
		mu.Unlock()
		if session == 1 {
			return status.Error(codes.Unavailable, "unknown publish result")
		}
		return stream.Send(ackResponse(2, batch.BatchId, 1, 1, batch.Records[0]))
	})
	defer cleanup()
	client := newTestClient(t, cursor, uuid.NewString(), dialer)
	client.jitter = func(time.Duration) time.Duration { return 0 }
	ack, err := client.Send(context.Background(), Batch{Records: []Record{testRecord(21)}})
	if err != nil || ack.Accepted != 1 || cursor.calls.Load() < 2 {
		t.Fatalf("reconnect Send() = %+v, %v, cursor calls=%d", ack, err, cursor.calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(batchIDs) != 2 || batchIDs[0] != batchIDs[1] {
		t.Fatalf("retransmitted batch IDs = %v", batchIDs)
	}
}

func TestClientRejectsVersionAndHonorsBackpressureAndCancellation(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
			if _, err := stream.Recv(); err != nil {
				return err
			}
			return stream.Send(validGatewayHello(2, 1))
		})
		defer cleanup()
		client := newTestClient(t, &fixedCursor{}, uuid.NewString(), dialer)
		if _, err := client.Send(context.Background(), Batch{Records: []Record{testRecord(1)}}); !errors.Is(err, ErrPermanentProtocol) {
			t.Fatalf("version error = %v", err)
		}
	})

	t.Run("unsafe gateway metadata", func(t *testing.T) {
		dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
			if _, err := stream.Recv(); err != nil {
				return err
			}
			response := validGatewayHello(1, 1)
			response.GetHello().GatewayVersion = "test\nunsafe"
			return stream.Send(response)
		})
		defer cleanup()
		client := newTestClient(t, &fixedCursor{}, uuid.NewString(), dialer)
		if _, err := client.Send(context.Background(), Batch{Records: []Record{testRecord(1)}}); !errors.Is(err, ErrPermanentProtocol) {
			t.Fatalf("metadata error = %v", err)
		}
	})

	t.Run("backpressure", func(t *testing.T) {
		dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(validGatewayHello(1, 1)); err != nil {
				return err
			}
			request, err := stream.Recv()
			if err != nil {
				return err
			}
			return stream.Send(&agentv1.StreamTelemetryResponse{
				Stream: responseMetadata(2),
				Payload: &agentv1.StreamTelemetryResponse_Ack{Ack: &agentv1.TelemetryAck{
					BatchId: request.GetBatch().BatchId, AcceptedTime: timestamppb.Now(), RetryAfterDuration: durationpb.New(50 * time.Millisecond),
				}},
			})
		})
		defer cleanup()
		client := newTestClient(t, &fixedCursor{}, uuid.NewString(), dialer)
		_, err := client.Send(context.Background(), Batch{Records: []Record{testRecord(1)}})
		if !errors.Is(err, ErrBackpressure) || RetryAfter(err) != 50*time.Millisecond {
			t.Fatalf("backpressure error = %v, retry=%s", err, RetryAfter(err))
		}
	})

	t.Run("cancel", func(t *testing.T) {
		dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(validGatewayHello(1, 1)); err != nil {
				return err
			}
			if _, err := stream.Recv(); err != nil {
				return err
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		})
		defer cleanup()
		client := newTestClient(t, &fixedCursor{}, uuid.NewString(), dialer)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		if _, err := client.Send(ctx, Batch{Records: []Record{testRecord(1)}}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error = %v", err)
		}
	})
}

type captureSender struct {
	batch Batch
	ack   SendAck
	err   error
}

func (s *captureSender) Send(_ context.Context, batch Batch) (SendAck, error) {
	s.batch = batch
	return s.ack, s.err
}

func TestPublisherValidatesAndDropsEventSpoolSubject(t *testing.T) {
	sender := &captureSender{ack: SendAck{Accepted: 1}}
	publisher, err := NewPublisher(testNodeID, sender)
	if err != nil {
		t.Fatal(err)
	}
	publication := testPublication(t)
	ack, err := publisher.Publish(context.Background(), []eventspool.Publication{publication})
	if err != nil || ack.Acknowledged != 1 || len(sender.batch.Records) != 1 {
		t.Fatalf("Publish() = %+v, %v, batch=%+v", ack, err, sender.batch)
	}
	if sender.batch.Records[0].Kind != "access.v1" || string(sender.batch.Records[0].Payload) != string(publication.Payload) {
		t.Fatalf("adapted record = %+v", sender.batch.Records[0])
	}
	publication.Subject = "attacker.chosen.subject"
	if _, err := publisher.Publish(context.Background(), []eventspool.Publication{publication}); !errors.Is(err, ErrInvalidPublication) {
		t.Fatalf("forged subject error = %v", err)
	}
	for field, forged := range map[string]string{"node_id": uuid.NewString(), "tenant_id": "forged-tenant"} {
		publication = testPublication(t)
		var envelope map[string]any
		if err := json.Unmarshal(publication.Payload, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope[field] = forged
		publication.Payload, err = json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.Publish(context.Background(), []eventspool.Publication{publication}); !errors.Is(err, ErrInvalidPublication) {
			t.Fatalf("forged %s error = %v", field, err)
		}
	}
	for _, field := range []string{"site_id", "config_version_id"} {
		publication = testPublication(t)
		var envelope map[string]any
		if err := json.Unmarshal(publication.Payload, &envelope); err != nil {
			t.Fatal(err)
		}
		events, ok := envelope["events"].([]any)
		if !ok || len(events) != 1 {
			t.Fatal("test publication events are invalid")
		}
		event, ok := events[0].(map[string]any)
		if !ok {
			t.Fatal("test publication event is invalid")
		}
		event[field] = uuid.NewString()
		publication.Payload, err = json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.Publish(context.Background(), []eventspool.Publication{publication}); !errors.Is(err, ErrInvalidPublication) {
			t.Fatalf("forged %s error = %v", field, err)
		}
	}
	publication = testPublication(t)
	publication.MessageID = "msg_" + strings.Repeat("0", 64)
	var envelope map[string]any
	if err := json.Unmarshal(publication.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["message_id"] = publication.MessageID
	publication.Payload, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background(), []eventspool.Publication{publication}); !errors.Is(err, ErrInvalidPublication) {
		t.Fatalf("non-deterministic message ID error = %v", err)
	}
}

func newTestClient(t *testing.T, cursor DurableCursor, bootID string, dialer Dialer) *Client {
	t.Helper()
	config := DefaultConfig()
	config.NodeID = testNodeID
	config.BootID = bootID
	config.Cursor = cursor
	config.HandshakeTimeout = time.Second
	config.AckTimeout = time.Second
	config.InitialBackoff = time.Millisecond
	config.MaximumBackoff = 100 * time.Millisecond
	client, err := New(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func startGateway(t *testing.T, handler func(grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error) (Dialer, func()) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, &testGateway{handle: handler})
	go func() { _ = server.Serve(listener) }()
	return &bufDialer{listener: listener}, func() {
		server.Stop()
		_ = listener.Close()
	}
}

func validGatewayHello(major uint32, records uint32) *agentv1.StreamTelemetryResponse {
	return &agentv1.StreamTelemetryResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.StreamTelemetryResponse_Hello{Hello: &agentv1.TelemetryGatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: major}, GatewayVersion: "test",
			ServerTime: timestamppb.Now(), MaximumRecordsPerBatch: records,
			MaximumRecordBytes: 1 << 20, MaximumBatchBytes: 4 << 20, MaximumInflightBatches: 1,
		}},
	}
}

func ackResponse(sequence uint64, batchID string, accepted, duplicate uint32, last *agentv1.TelemetryRecord) *agentv1.StreamTelemetryResponse {
	return &agentv1.StreamTelemetryResponse{
		Stream: responseMetadata(sequence),
		Payload: &agentv1.StreamTelemetryResponse_Ack{Ack: &agentv1.TelemetryAck{
			BatchId: batchID, AcceptedRecordCount: accepted, DuplicateRecordCount: duplicate,
			AcceptedThroughSequence: last.LastSequence, AcceptedThroughMessageId: last.MessageId,
			AcceptedThroughEventId: last.LastEventId, AcceptedTime: timestamppb.Now(),
		}},
	}
}

func responseMetadata(sequence uint64) *commonv1.StreamMetadata {
	return &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: sequence, SentTime: timestamppb.Now()}
}

func testRecord(sequence uint64) Record {
	return Record{
		Kind: "access.v1", MessageID: "msg_" + uuid.NewString(), FirstSequence: sequence, LastSequence: sequence,
		LastEventID: uuid.NewString(), EventCount: 1, Payload: []byte(`{"schema_version":1}`),
	}
}

func testPublication(t *testing.T) eventspool.Publication {
	t.Helper()
	eventID := uuid.NewString()
	messageID := telemetryMessageID(testNodeID, testTenantID, testSiteID, testConfigID, "access.v1", eventID, eventID)
	payload, err := json.Marshal(map[string]any{
		"schema_version": 1, "type": "access.v1", "message_id": messageID,
		"produced_at": time.Now().UTC(), "tenant_id": testTenantID, "node_id": testNodeID,
		"events": []map[string]any{{"event_id": eventID, "site_id": testSiteID, "config_version_id": testConfigID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return eventspool.Publication{
		Subject: analyticsSubjectPrefix + testNodeID, MessageID: messageID, Payload: payload,
		FirstSequence: 1, LastSequence: 1, LastEventID: eventID, EventCount: 1,
	}
}
