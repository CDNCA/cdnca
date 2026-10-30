package main

// PoC Gateway. Serves the real agent.v1.AgentGatewayService Connect and
// StreamTelemetry streams (protocol subset: hello, heartbeat/ack, one
// deployment command + status, telemetry batch/ack) on three entrances:
//
//   :19444  direct mTLS (production shape, RequireAndVerifyClientCert)
//   :19445  TLS without client certificate, for a CDN that terminates TLS and
//           re-encrypts to origin with gRPC over HTTP/2; node identity comes
//           from the Ed25519-signed headers (auth.go)
//   :19446  HTTPS WebSocket /agent/v1/tunnel; headers are checked before the
//           upgrade and the tunnel carries the unchanged inner mTLS gRPC
//           connection, so the node identity is still the client certificate
//   :8443   one shared gateway port (sharedport.go): direct gRPC mTLS and the
//           WebSocket tunnel on the same port, no master nginx in between;
//           a CDN may sit in front and pull from this same port

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type identityKey struct{}

type gatewayStats struct {
	Sessions        atomic.Int64 `json:"-"`
	Heartbeats      atomic.Int64 `json:"-"`
	Commands        atomic.Int64 `json:"-"`
	Statuses        atomic.Int64 `json:"-"`
	TelemetryBatchs atomic.Int64 `json:"-"`
	Rejected        atomic.Int64 `json:"-"`
}

type pocGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	name      string
	heartbeat time.Duration
	stats     gatewayStats
	mu        sync.Mutex
	peers     map[string]string // entrance -> last forwarded-for / peer
}

func nodeIDFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil || len(cert.URIs) != 1 {
		return "", errors.New("client certificate must contain exactly one URI SAN")
	}
	uri := cert.URIs[0]
	if uri.Scheme != "spiffe" || uri.Host != "cdn-platform" || len(uri.Path) <= len("/node/") || uri.Path[:6] != "/node/" {
		return "", errors.New("client certificate URI SAN is not a node identity")
	}
	id := uri.Path[6:]
	if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
		return "", errors.New("node identity is invalid")
	}
	return id, nil
}

// authenticatedNode mirrors services/agent-gateway/identity.go: verified TLS
// client certificate first; otherwise the identity the header interceptor
// attached (CDN entrance).
func authenticatedNode(ctx context.Context) (string, string, error) {
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.VerifiedChains) > 0 {
			id, err := nodeIDFromCertificate(info.State.VerifiedChains[0][0])
			return id, "mtls", err
		}
	}
	if id, ok := ctx.Value(identityKey{}).(string); ok && id != "" {
		return id, "signed-header", nil
	}
	return "", "", status.Error(codes.Unauthenticated, "verified node identity required")
}

func (g *pocGateway) recordPeer(ctx context.Context, entrance string) {
	value := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get("x-forwarded-for")) > 0 {
		value = "xff=" + md.Get("x-forwarded-for")[0]
	}
	if p, ok := peer.FromContext(ctx); ok {
		value += " peer=" + p.Addr.String()
	}
	g.mu.Lock()
	g.peers[entrance] = value
	g.mu.Unlock()
}

func meta(sequence uint64) *commonv1.StreamMetadata {
	return &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: sequence}
}

func (g *pocGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	nodeID, via, err := authenticatedNode(stream.Context())
	if err != nil {
		g.stats.Rejected.Add(1)
		return err
	}
	g.recordPeer(stream.Context(), via)
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || hello.NodeId != nodeID {
		g.stats.Rejected.Add(1)
		return status.Error(codes.Unauthenticated, "AgentHello node identity does not match the authenticated node")
	}
	g.stats.Sessions.Add(1)
	sequence := uint64(1)
	send := func(response *agentv1.ConnectResponse) error {
		response.Stream = meta(sequence)
		sequence++
		return stream.Send(response)
	}
	epoch := uint64(time.Now().UnixNano())
	if err := send(&agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
		SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "poc-" + g.name,
		SessionId: uuid.NewString(), SessionEpoch: epoch, ServerTime: timestamppb.Now(),
		HeartbeatIntervalDuration: durationpb.New(g.heartbeat), OfflineAfterDuration: durationpb.New(3 * g.heartbeat),
	}}}); err != nil {
		return err
	}
	commandSent := false
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		switch payload := request.Payload.(type) {
		case *agentv1.ConnectRequest_Heartbeat:
			g.stats.Heartbeats.Add(1)
			if err := send(&agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
				HeartbeatEventId: payload.Heartbeat.GetEvent().GetEventId(), SessionEpoch: epoch, ReceivedTime: timestamppb.Now()}}}); err != nil {
				return err
			}
			if !commandSent {
				commandSent = true
				g.stats.Commands.Add(1)
				if err := send(&agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_DeploymentCommand{DeploymentCommand: &agentv1.DeploymentCommand{
					Event:        &commonv1.EventMetadata{EventId: uuid.NewString(), OccurredTime: timestamppb.Now()},
					DeploymentId: uuid.NewString(), Attempt: 1, RolloutId: uuid.NewString(), ConfigVersionId: uuid.NewString()}}}); err != nil {
					return err
				}
			}
		case *agentv1.ConnectRequest_DeploymentStatus:
			g.stats.Statuses.Add(1)
		default:
			return status.Error(codes.InvalidArgument, "unexpected payload in PoC")
		}
	}
}

func (g *pocGateway) StreamTelemetry(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
	if _, _, err := authenticatedNode(stream.Context()); err != nil {
		g.stats.Rejected.Add(1)
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetHello() == nil {
		return status.Error(codes.FailedPrecondition, "telemetry hello required")
	}
	sequence := uint64(1)
	if err := stream.Send(&agentv1.StreamTelemetryResponse{Stream: meta(sequence), Payload: &agentv1.StreamTelemetryResponse_Hello{Hello: &agentv1.TelemetryGatewayHello{
		SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "poc-" + g.name, ServerTime: timestamppb.Now(),
		MaximumRecordsPerBatch: 64, MaximumRecordBytes: 1 << 20, MaximumBatchBytes: 4 << 20, MaximumInflightBatches: 1}}}); err != nil {
		return err
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		batch := request.GetBatch()
		if batch == nil {
			return status.Error(codes.InvalidArgument, "telemetry batch required")
		}
		g.stats.TelemetryBatchs.Add(1)
		sequence++
		if err := stream.Send(&agentv1.StreamTelemetryResponse{Stream: meta(sequence), Payload: &agentv1.StreamTelemetryResponse_Ack{Ack: &agentv1.TelemetryAck{
			BatchId: batch.BatchId, AcceptedRecordCount: uint32(len(batch.Records)), AcceptedThroughSequence: batch.LastSequence, AcceptedTime: timestamppb.Now()}}}); err != nil {
			return err
		}
	}
}

func (g *pocGateway) headerAuth(verifier *tokenVerifier) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		cert, auth := md.Get(headerNodeCert), md.Get(headerNodeAuth)
		if len(cert) != 1 || len(auth) != 1 {
			g.stats.Rejected.Add(1)
			return status.Error(codes.Unauthenticated, "signed node headers required")
		}
		nodeID, err := verifier.verify(cert[0], auth[0], info.FullMethod, time.Now())
		if err != nil {
			g.stats.Rejected.Add(1)
			log.Printf("[%s] reject %s: %v", g.name, info.FullMethod, err)
			return status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(srv, &identityStream{ServerStream: stream, ctx: context.WithValue(stream.Context(), identityKey{}, nodeID)})
	}
}

// recordDirect notes the TCP peer of direct gRPC sessions on the shared port.
func (g *pocGateway) recordDirect(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if p, ok := peer.FromContext(stream.Context()); ok && info.FullMethod == agentv1.AgentGatewayService_Connect_FullMethodName {
		g.mu.Lock()
		g.peers["shared-grpc"] = "real_ip=" + p.Addr.String() + " source=tcp"
		g.mu.Unlock()
	}
	return handler(srv, stream)
}

type identityStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *identityStream) Context() context.Context { return s.ctx }

func loadPool(path string) (*x509.CertPool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(content) {
		return nil, fmt.Errorf("%s has no certificate", path)
	}
	return pool, nil
}

func runGateway(dir, name, mtlsAddr, grpcAddr, wsAddr, sharedAddr, trusted, statsFile string, heartbeat time.Duration) error {
	ranges, err := parseTrusted(trusted)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway-key.pem"))
	if err != nil {
		return err
	}
	nodeCAs, err := loadPool(filepath.Join(dir, "node-ca.pem"))
	if err != nil {
		return err
	}
	g := &pocGateway{name: name, heartbeat: heartbeat, peers: map[string]string{}}
	keepaliveOptions := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second}),
	}
	mtlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: nodeCAs, ClientAuth: tls.RequireAndVerifyClientCert}
	mtlsServer := grpc.NewServer(append(keepaliveOptions, grpc.Creds(credentials.NewTLS(mtlsConfig)))...)
	agentv1.RegisterAgentGatewayServiceServer(mtlsServer, g)

	verifier := &tokenVerifier{audience: "cdnca-gateway", nodeCAs: nodeCAs, nonces: &nonceCache{seen: map[string]time.Time{}}}
	originConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}}
	headerServer := grpc.NewServer(append(keepaliveOptions, grpc.Creds(credentials.NewTLS(originConfig)), grpc.StreamInterceptor(g.headerAuth(verifier)))...)
	agentv1.RegisterAgentGatewayServiceServer(headerServer, g)

	errs := make(chan error, 4)
	if mtlsAddr != "" {
		listener, err := net.Listen("tcp", mtlsAddr)
		if err != nil {
			return err
		}
		go func() { errs <- mtlsServer.Serve(listener) }()
	}
	if grpcAddr != "" {
		listener, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			return err
		}
		go func() { errs <- headerServer.Serve(listener) }()
	}
	if wsAddr != "" || sharedAddr != "" {
		tunnel := newChanListener(&net.TCPAddr{IP: net.IPv4zero})
		go func() { errs <- mtlsServer.Serve(tunnel) }()
		upgrader := websocket.Upgrader{ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10}
		tunnelHandler := func(entrance string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if _, err := verifier.verify(r.Header.Get(headerNodeCert), r.Header.Get(headerNodeAuth), "/agent/v1/tunnel", time.Now()); err != nil {
					g.stats.Rejected.Add(1)
					log.Printf("[%s] reject tunnel (%s): %v", name, entrance, err)
					http.Error(w, "unauthenticated", http.StatusUnauthorized)
					return
				}
				key := entrance
				if label := r.Header.Get("Cdnca-Poc-Label"); label != "" {
					key += ":" + label
				}
				// Shared port: forwarded headers count only from trusted CDN
				// back-to-origin ranges (realip.go); a direct node cannot
				// forge its address.
				value := "xff=" + r.Header.Get("X-Forwarded-For") + " peer=" + r.RemoteAddr
				if entrance == "shared-tunnel" {
					ip, source := clientIP(r.RemoteAddr, r.Header, ranges)
					value = "real_ip=" + ip + " source=" + source + " " + value
				}
				g.mu.Lock()
				g.peers[key] = value
				g.mu.Unlock()
				ws, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				select {
				case tunnel.conns <- &wsConn{ws: ws}:
				case <-tunnel.done:
					ws.Close()
				}
			}
		}
		if wsAddr != "" {
			mux := http.NewServeMux()
			mux.HandleFunc("/agent/v1/tunnel", tunnelHandler("ws-upgrade"))
			server := &http.Server{Addr: wsAddr, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}}
			go func() { errs <- server.ListenAndServeTLS("", "") }()
		}
		if sharedAddr != "" {
			// Default shape: the gateway listens on its own port; direct
			// gRPC mTLS and the tunnel share it (selected after the TLS
			// handshake by ALPN + client certificate).
			mux := http.NewServeMux()
			mux.HandleFunc("/agent/v1/tunnel", tunnelHandler("shared-tunnel"))
			sharedGRPC := grpc.NewServer(append(keepaliveOptions, grpc.Creds(preTLS{}), grpc.StreamInterceptor(g.recordDirect))...)
			agentv1.RegisterAgentGatewayServiceServer(sharedGRPC, g)
			if err := serveSharedPort(name, sharedAddr, certificate, nodeCAs, sharedGRPC, mux, errs); err != nil {
				return err
			}
		}
	}
	if statsFile != "" {
		go func() {
			for range time.Tick(time.Second) {
				g.mu.Lock()
				peers := make(map[string]string, len(g.peers))
				for k, v := range g.peers {
					peers[k] = v
				}
				g.mu.Unlock()
				content, _ := json.Marshal(map[string]any{"gateway": name, "sessions": g.stats.Sessions.Load(), "heartbeats": g.stats.Heartbeats.Load(),
					"commands": g.stats.Commands.Load(), "statuses": g.stats.Statuses.Load(), "telemetry_batches": g.stats.TelemetryBatchs.Load(),
					"rejected": g.stats.Rejected.Load(), "peers": peers})
				_ = os.WriteFile(statsFile, content, 0o600)
			}
		}()
	}
	log.Printf("[%s] gateway up mtls=%s grpc-origin=%s ws-origin=%s shared=%s heartbeat=%s", name, mtlsAddr, grpcAddr, wsAddr, sharedAddr, heartbeat)
	return <-errs
}
