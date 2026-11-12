package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

// shortSessionGateway 每个会话在握手后 sessionLife 即断开，心跳间隔故意设得很长，
// 用来证明首个心跳不依赖心跳 ticker。
type shortSessionGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	sessionLife time.Duration
	mu          sync.Mutex
	sessions    []*shortSession
}

type shortSession struct {
	connectedAt time.Time
	endedAt     time.Time
	firstBeatAt time.Time
}

func (g *shortSessionGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	session := &shortSession{connectedAt: time.Now()}
	g.mu.Lock()
	g.sessions = append(g.sessions, session)
	epoch := uint64(len(g.sessions))
	g.mu.Unlock()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetHello() == nil {
		return errors.New("missing hello")
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion:   &commonv1.ProtocolVersion{Major: 1},
			GatewayVersion:            "test",
			SessionId:                 uuid.NewString(),
			SessionEpoch:              epoch,
			ServerTime:                timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(time.Hour),
			OfflineAfterDuration:      durationpb.New(2 * time.Hour),
			MaximumArtifactChunkBytes: 64 << 10,
			MessageIdReplayWindow:     128,
		}},
	}); err != nil {
		return err
	}
	deadline := time.NewTimer(g.sessionLife)
	defer deadline.Stop()
	received := make(chan *agentv1.ConnectRequest)
	go func() {
		for {
			request, err := stream.Recv()
			if err != nil {
				close(received)
				return
			}
			received <- request
		}
	}()
	responseSequence := uint64(1)
	for {
		select {
		case <-deadline.C:
			g.mu.Lock()
			session.endedAt = time.Now()
			g.mu.Unlock()
			return errors.New("session closed by test")
		case request, ok := <-received:
			if !ok {
				return nil
			}
			if heartbeat := request.GetHeartbeat(); heartbeat != nil {
				g.mu.Lock()
				if session.firstBeatAt.IsZero() {
					session.firstBeatAt = time.Now()
				}
				g.mu.Unlock()
				responseSequence++
				_ = stream.Send(&agentv1.ConnectResponse{
					Stream: responseMetadata(responseSequence),
					Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
						HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: epoch, ReceivedTime: timestamppb.Now(),
					}},
				})
			}
		}
	}
}

// 会话建立后立即发首个心跳；短会话断开后重连等待不随次数翻倍。
func TestReconnectSendsImmediateHeartbeatAndResetsBackoffAfterEstablishedSession(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &shortSessionGateway{sessionLife: 150 * time.Millisecond}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	manager, err := deployment.NewManager(filepath.Join(root, "deployment"), testPrechecker{}, &testRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(root, "gateway-journal"))
	config.InitialBackoff = 250 * time.Millisecond
	config.MaximumBackoff = 30 * time.Second
	client, err := New(config, &bufDialer{listener: listener}, manager, trust)
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(d time.Duration) time.Duration { return d }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	const wantSessions = 5
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		gateway.mu.Lock()
		n := len(gateway.sessions)
		ended := n > 0 && !gateway.sessions[n-1].endedAt.IsZero()
		gateway.mu.Unlock()
		if n >= wantSessions && ended {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if len(gateway.sessions) < wantSessions {
		t.Fatalf("sessions = %d, want >= %d", len(gateway.sessions), wantSessions)
	}
	for i, s := range gateway.sessions[:wantSessions] {
		if s.firstBeatAt.IsZero() || s.firstBeatAt.Sub(s.connectedAt) > time.Second {
			t.Errorf("session %d: first heartbeat %v after connect, want within 1s", i, s.firstBeatAt.Sub(s.connectedAt))
		}
		if i == 0 {
			continue
		}
		prev := gateway.sessions[i-1]
		if wait := s.connectedAt.Sub(prev.endedAt); wait > time.Second {
			t.Errorf("session %d: reconnect waited %v after previous session ended, want <= 1s", i, wait)
		}
	}
}
