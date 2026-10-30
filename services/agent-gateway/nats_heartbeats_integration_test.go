//go:build integration

package gateway

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestJetStreamHeartbeatDurabilityDeduplicationAndRecovery(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "AGENT_HEARTBEATS_" + suffix
	subjectPrefix := "cdnca.test." + suffix + ".heartbeats"

	firstConnection := connectIntegrationNATS(t, natsURL)
	defer firstConnection.Close()
	secondConnection := connectIntegrationNATS(t, natsURL)
	defer secondConnection.Close()
	js, err := secondConnection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name:       streamName,
		Subjects:   []string{subjectPrefix + ".>"},
		Retention:  nats.LimitsPolicy,
		Storage:    nats.FileStorage,
		Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(streamName) }()

	busConfig := DefaultNATSCommandBusConfig()
	busConfig.HeartbeatStream = streamName
	busConfig.HeartbeatSubjectPrefix = subjectPrefix
	busConfig.OperationTimeout = time.Second
	firstBus, err := NewNATSCommandBus(firstConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	secondBus, err := NewNATSCommandBus(secondConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}

	heartbeatRequest := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())
	heartbeat := heartbeatRequest.GetHeartbeat()
	var observationMu sync.Mutex
	persistedBeforeAck := false
	firstGateway := newHeartbeatGateway(t, firstBus, nil)
	requests, stream, done := startHeartbeatSession(t, firstGateway, func(stream *heartbeatTestStream) {
		stream.onSend = func() {
			info, infoErr := js.StreamInfo(streamName)
			observationMu.Lock()
			persistedBeforeAck = infoErr == nil && info.State.Msgs == 1
			observationMu.Unlock()
		}
	})
	requests <- connectReceive{request: heartbeatRequest}
	requests <- connectReceive{err: context.Canceled}
	assertHeartbeatAck(t, stream, heartbeat.Event.EventId)
	if err := <-done; status.Code(err) != codes.Canceled {
		t.Fatalf("first heartbeat session = %v, want Canceled after ACK", err)
	}
	observationMu.Lock()
	observed := persistedBeforeAck
	observationMu.Unlock()
	if !observed {
		t.Fatal("Gateway sent HeartbeatAck before JetStream reported the persisted message")
	}

	expectedPayload, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	storedMessage, err := js.GetLastMsg(streamName, subjectPrefix+"."+testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if storedMessage.Header.Get(nats.MsgIdHdr) != heartbeat.Event.EventId {
		t.Fatalf("stored Nats-Msg-Id = %q", storedMessage.Header.Get(nats.MsgIdHdr))
	}
	if string(storedMessage.Data) != string(expectedPayload) {
		t.Fatal("stored heartbeat is not the deterministic protobuf payload")
	}
	decoded := new(agentv1.Heartbeat)
	if err := proto.Unmarshal(storedMessage.Data, decoded); err != nil || !proto.Equal(decoded, heartbeat) {
		t.Fatalf("stored heartbeat changed: decode=%v equal=%t", err, proto.Equal(decoded, heartbeat))
	}

	secondGateway := newHeartbeatGateway(t, secondBus, nil)
	requests, stream, done = startHeartbeatSession(t, secondGateway, nil)
	requests <- connectReceive{request: proto.Clone(heartbeatRequest).(*agentv1.ConnectRequest)}
	requests <- connectReceive{err: context.Canceled}
	assertHeartbeatAck(t, stream, heartbeat.Event.EventId)
	if err := <-done; status.Code(err) != codes.Canceled {
		t.Fatalf("duplicate heartbeat session = %v, want Canceled after ACK", err)
	}
	eventually(t, time.Second, func() bool {
		info, err := js.StreamInfo(streamName)
		return err == nil && info.State.Msgs == 1
	}, "two Gateways did not deduplicate the heartbeat event")

	retryRequest := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())
	firstConnection.Close()
	closedGateway := newHeartbeatGateway(t, firstBus, nil)
	requests, stream, done = startHeartbeatSession(t, closedGateway, nil)
	requests <- connectReceive{request: retryRequest}
	if err := <-done; status.Code(err) != codes.Unavailable {
		t.Fatalf("closed NATS heartbeat session = %v, want Unavailable", err)
	}
	assertNoHeartbeatAck(t, stream)
	info, err := js.StreamInfo(streamName)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("failed publication changed stream: info=%+v err=%v", info, err)
	}

	recoveryConnection := connectIntegrationNATS(t, natsURL)
	defer recoveryConnection.Close()
	recoveryBus, err := NewNATSCommandBus(recoveryConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	recoveryGateway := newHeartbeatGateway(t, recoveryBus, nil)
	requests, stream, done = startHeartbeatSession(t, recoveryGateway, nil)
	requests <- connectReceive{request: proto.Clone(retryRequest).(*agentv1.ConnectRequest)}
	requests <- connectReceive{err: context.Canceled}
	assertHeartbeatAck(t, stream, retryRequest.GetHeartbeat().Event.EventId)
	if err := <-done; status.Code(err) != codes.Canceled {
		t.Fatalf("recovered heartbeat session = %v, want Canceled after ACK", err)
	}
	eventually(t, time.Second, func() bool {
		info, err := js.StreamInfo(streamName)
		return err == nil && info.State.Msgs == 2
	}, "retransmitted heartbeat was not persisted after NATS recovery")

	wrongStreamConfig := busConfig
	wrongStreamConfig.HeartbeatStream = "WRONG_HEARTBEAT_" + suffix
	wrongStreamBus, err := NewNATSCommandBus(secondConnection, wrongStreamConfig)
	if err != nil {
		t.Fatal(err)
	}
	wrongStreamGateway := newHeartbeatGateway(t, wrongStreamBus, nil)
	wrongStreamRequest := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())
	requests, stream, done = startHeartbeatSession(t, wrongStreamGateway, nil)
	requests <- connectReceive{request: wrongStreamRequest}
	if err := <-done; status.Code(err) != codes.Unavailable {
		t.Fatalf("wrong stream heartbeat session = %v, want Unavailable", err)
	}
	assertNoHeartbeatAck(t, stream)
	info, err = js.StreamInfo(streamName)
	if err != nil || info.State.Msgs != 2 {
		t.Fatalf("wrong expected stream changed stream: info=%+v err=%v", info, err)
	}

	if err := secondBus.PersistHeartbeat(context.Background(), strings.ToUpper(testNodeID), heartbeat); err == nil {
		t.Fatal("NATS heartbeat sink accepted a non-canonical node UUID")
	}
	limitedConfig := busConfig
	limitedConfig.MaxHeartbeatBytes = 1
	limitedBus, err := NewNATSCommandBus(secondConnection, limitedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := limitedBus.PersistHeartbeat(context.Background(), testNodeID, heartbeat); err == nil {
		t.Fatal("NATS heartbeat sink accepted a payload over its byte limit")
	}
}

func assertHeartbeatAck(t *testing.T, stream *heartbeatTestStream, eventID string) {
	t.Helper()
	select {
	case response := <-stream.sent:
		if response.GetHeartbeatAck() == nil || response.GetHeartbeatAck().HeartbeatEventId != eventID {
			t.Fatalf("heartbeat response = %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HeartbeatAck")
	}
}
