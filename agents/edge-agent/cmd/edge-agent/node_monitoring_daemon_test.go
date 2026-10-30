package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDaemonNodeMonitoringUsesSingleBridgeAcrossActivationAndRestart(t *testing.T) {
	for _, preactivated := range []bool{false, true} {
		name := "cold"
		if preactivated {
			name = "persisted"
		}
		t.Run(name, func(t *testing.T) {
			gateway := &daemonNodeMonitoringGateway{
				requests:  make(chan *agentv1.ConnectRequest, 128),
				artifacts: make(chan *agentv1.NodeMonitoringArtifact, 1),
			}
			config := newDaemonNodeMonitoringConfig(t, gateway)
			payload, err := json.Marshal(nodemonitoring.Config{
				SchemaVersion: nodemonitoring.SchemaVersion, ConfigRevision: 7, PortMode: "default",
				ProbeIntervalMS: 60_000, ProbeTimeoutMS: 100, FailureThreshold: 3, RecoveryThreshold: 3,
			})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(payload)
			artifact := &agentv1.NodeMonitoringArtifact{
				Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
				Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: config.NodeID,
				ConfigRevision: 7, PublicationSequence: 7, CanonicalConfigJson: payload, ConfigSha256: digest[:],
			}
			if preactivated {
				bridge, _, err := assembleNodeMonitoring(config.NodeMonitoring, config.NodeID)
				if err != nil {
					t.Fatal(err)
				}
				if err := bridge.ApplyArtifact(t.Context(), artifact); err != nil {
					t.Fatal(err)
				}
			}
			var previousSequence uint64
			for restart := 0; restart < 2; restart++ {
				timeouts, err := config.validate()
				if err != nil {
					t.Fatal(err)
				}
				client, err := assembleClient(config, timeouts, uuid.NewString())
				if err != nil {
					t.Fatal(err)
				}
				daemon := client.(*daemonClient)
				// The unrelated challenge verifier owns a fixed port. Keep this test
				// isolated while retaining the real daemon/client/monitoring assembly.
				daemon.challengeVerifier = nil
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- daemon.Run(ctx) }()
				stopped := false
				t.Cleanup(func() {
					cancel()
					if !stopped {
						select {
						case <-done:
						case <-time.After(3 * time.Second):
							t.Error("monitoring daemon did not stop")
						}
					}
					if err := daemon.Close(); err != nil {
						t.Error(err)
					}
				})

				cold := !preactivated && restart == 0
				heartbeats, applied := 0, !cold
				var report *agentv1.NodeMonitoringReport
				deadline := time.NewTimer(3 * time.Second)
				for report == nil || heartbeats < 3 || !applied {
					select {
					case err := <-done:
						stopped = true
						t.Fatalf("restart %d: daemon stopped before monitoring became ready: %v", restart, err)
					case <-deadline.C:
						t.Fatalf("restart %d: timed out waiting for heartbeat/config/report", restart)
					case request := <-gateway.requests:
						if request.GetHeartbeat() != nil {
							heartbeats++
							if cold && heartbeats == 3 {
								gateway.artifacts <- artifact
							}
						}
						if status := request.GetNodeMonitoringApplyStatus(); status != nil {
							if status.State != agentv1.NodeMonitoringApplyState_NODE_MONITORING_APPLY_STATE_APPLIED || status.ActiveConfigRevision != 7 {
								t.Fatalf("unexpected monitoring apply result: %v", status)
							}
							applied = true
						}
						if value := request.GetNodeMonitoringReport(); value != nil {
							if cold && heartbeats < 3 {
								t.Fatal("monitoring reported before receiving its active configuration")
							}
							if report != nil && value.Event.EventId != report.Event.EventId {
								t.Fatal("multiple monitoring loops sampled within one interval")
							}
							report = value
						}
					}
				}
				deadline.Stop()
				var metric nodemonitoring.MetricReport
				if err := json.Unmarshal(report.PayloadJson, &metric); err != nil || report.ConfigRevision != 7 ||
					report.PublicationSequence != previousSequence+1 ||
					metric.ActiveConfigRevision != 7 || metric.ProbesTotal != 1 || !metric.ProbeSucceeded {
					t.Fatalf("restart %d: invalid first real runtime report: %v, %v", restart, metric, err)
				}
				// A replay has the same event ID; a second runner creates a new one.
				quiet := time.NewTimer(300 * time.Millisecond)
			observe:
				for {
					select {
					case request := <-gateway.requests:
						if value := request.GetNodeMonitoringReport(); value != nil && value.Event.EventId != report.Event.EventId {
							t.Fatal("multiple monitoring loops sampled within one interval")
						}
					case err := <-done:
						stopped = true
						t.Fatalf("daemon stopped after activation: %v", err)
					case <-quiet.C:
						break observe
					}
				}
				previousSequence = report.PublicationSequence
				// Restart only once the report's ACK is durable: the next instance
				// then starts with an empty outbox and reports the next sequence.
				waitNodeMonitoringOutboxEmpty(t, config, done)
				cancel()
				select {
				case err := <-done:
					stopped = true
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("daemon shutdown: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("daemon did not stop before restart")
				}
				if err := daemon.Close(); err != nil {
					t.Fatal(err)
				}
				// The next instance uses the same state and journal, without sending
				// another artifact. Once the old session's handler has returned it
				// forwards nothing more; then drop what it already forwarded, so a
				// late request of the old session is never read as the new one's.
				gateway.sessions.Wait()
				for len(gateway.requests) != 0 {
					<-gateway.requests
				}
			}
		})
	}
}

// waitNodeMonitoringOutboxEmpty waits until the running daemon's persisted
// node monitoring outbox holds no unacknowledged report.
func waitNodeMonitoringOutboxEmpty(t *testing.T, config fileConfig, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		carrier, err := gatewayclient.NewNodeMonitoringBridge(config.NodeMonitoring.StateDir, config.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		if len(carrier.Pending()) == 0 {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("daemon stopped before the report was acknowledged: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("node monitoring report was not acknowledged")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type daemonNodeMonitoringGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	requests  chan *agentv1.ConnectRequest
	artifacts chan *agentv1.NodeMonitoringArtifact
	// sessions counts running Connect handlers (one per agent session).
	sessions sync.WaitGroup
}

func (gateway *daemonNodeMonitoringGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	gateway.sessions.Add(1)
	defer gateway.sessions.Done()
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := request.GetHello()
	if hello == nil {
		return errors.New("missing agent hello")
	}
	if err := stream.Send(&agentv1.ConnectResponse{Stream: daemonStage2StreamMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "monitoring-test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(30 * time.Millisecond), OfflineAfterDuration: durationpb.New(2 * time.Second),
			MaximumArtifactChunkBytes: 1 << 20, MessageIdReplayWindow: 128,
			EnabledCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING, ApiVersion: 1}},
		}}}); err != nil {
		return err
	}
	sequence := uint64(1)
	acknowledged := make(map[string]*agentv1.NodeMonitoringAck)
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		select {
		case gateway.requests <- request:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		response := &agentv1.ConnectResponse{}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			response.Payload = &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
				HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: 1, ReceivedTime: timestamppb.Now(),
			}}
		} else if report := request.GetNodeMonitoringReport(); report != nil {
			ack := acknowledged[report.Event.EventId]
			if ack == nil {
				ack = &agentv1.NodeMonitoringAck{
					EventId: report.Event.EventId, NodeId: report.NodeId, ConfigRevision: report.ConfigRevision,
					PublicationSequence: report.PublicationSequence, PublishedStream: "NODE_MONITORING_STATUS",
					PublishedSequence: report.PublicationSequence, AcceptedTime: timestamppb.Now(),
				}
				acknowledged[report.Event.EventId] = ack
			}
			response.Payload = &agentv1.ConnectResponse_NodeMonitoringAck{NodeMonitoringAck: proto.Clone(ack).(*agentv1.NodeMonitoringAck)}
		}
		if response.Payload != nil {
			sequence++
			response.Stream = daemonStage2StreamMetadata(sequence)
			if err := stream.Send(response); err != nil {
				return err
			}
			if response.GetNodeMonitoringAck() != nil {
				// A retransmitted report receives the Gateway's exact cached ACK.
				// Send a duplicate deterministically, including under fast heartbeats.
				sequence++
				response.Stream = daemonStage2StreamMetadata(sequence)
				if err := stream.Send(response); err != nil {
					return err
				}
			}
		}
		select {
		case artifact := <-gateway.artifacts:
			sequence++
			if err := stream.Send(&agentv1.ConnectResponse{Stream: daemonStage2StreamMetadata(sequence),
				Payload: &agentv1.ConnectResponse_NodeMonitoringArtifact{NodeMonitoringArtifact: artifact}}); err != nil {
				return err
			}
		default:
		}
	}
}

func newDaemonNodeMonitoringConfig(t *testing.T, gateway *daemonNodeMonitoringGateway) fileConfig {
	t.Helper()
	root := secureConfigTempDir(t)
	securityDir := filepath.Join(root, "security")
	if err := os.Mkdir(securityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM, publicKeyPEM := testSecurityMaterial(t)
	certificateBlock, _ := pem.Decode(certificatePEM)
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(privateKeyPEM)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"gateway.internal"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, certificate, key.(ed25519.PrivateKey).Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certPool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCertificate}, PrivateKey: key}},
	})))
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("monitoring test Gateway did not stop")
		}
	})

	trust, err := json.Marshal(map[string]any{"version": 1,
		"keys": []map[string]string{{"key_id": "artifact-key", "public_key_pem": string(publicKeyPEM)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := validFileConfig()
	config.ArtifactTrustFile = writeTestFile(t, securityDir, "trust.json", trust, 0o400)
	config.Gateway.RootCAFile = writeTestFile(t, securityDir, "ca.pem", certificatePEM, 0o600)
	config.Gateway.ClientCertificate = writeTestFile(t, securityDir, "client.pem", certificatePEM, 0o600)
	config.Gateway.ClientPrivateKeyFile = writeTestFile(t, securityDir, "client-key.pem", privateKeyPEM, 0o600)
	config.Gateway.Address = listener.Addr().String()
	config.DeploymentRoot = filepath.Join(root, "deployment")
	config.JournalDir = filepath.Join(root, "journal")
	config.CertificateRuntime.StateRoot = filepath.Join(root, "certificates")
	config.OpenResty.Binary = trueBinary(t)
	config.NodeMonitoring = nodeMonitoringSettings{Enabled: true, StateDir: filepath.Join(root, "monitoring"),
		DefaultPort: uint16(listener.Addr().(*net.TCPAddr).Port)}
	if err := os.Mkdir(config.NodeMonitoring.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return config
}
