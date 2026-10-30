package main

// PoC Agent. Endpoints are tried in order; a session ends when a stream fails
// or a heartbeat ack is late (3 x interval, like OfflineAfter), then the
// next endpoint is tried. Endpoint form: <mode>=<host:port>, mode one of
//   mtls  direct mTLS gRPC (production shape)
//   grpc  TLS gRPC to a CDN that terminates TLS; Ed25519 signed headers per stream
//   ws    HTTPS WebSocket via a CDN; inner unchanged mTLS gRPC over the tunnel
//   tunnel  WebSocket tunnel to the gateway's own port (directly or through
//         a CDN pulling from that port); outer and inner TLS name are the
//         gateway name, inner unchanged mTLS gRPC
//   nocert  direct gRPC without a client certificate (negative case)
//   grpc-unsigned  like grpc without the signed headers (negative case)

import (
	"context"
	"crypto/ed25519"
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
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type endpoint struct{ mode, address string }

// PoC-only tunnel upgrade extras: a scenario label for the gateway stats and a
// forged X-Forwarded-For to show the master nginx ignores untrusted values.
var tunnelLabel, tunnelForgedXFF string

type sessionResult struct {
	Endpoint      string  `json:"endpoint"`
	Established   bool    `json:"established"`
	Heartbeats    int     `json:"heartbeat_acks"`
	Commands      int     `json:"commands"`
	TelemetryAcks int     `json:"telemetry_acks"`
	StartedUnix   float64 `json:"started_unix"`
	Seconds       float64 `json:"seconds"`
	End           string  `json:"end"`
}

type agentIdentity struct {
	leaf        *x509.Certificate
	key         ed25519.PrivateKey
	certificate tls.Certificate
	roots       *x509.CertPool
}

func loadAgentIdentity(dir string) (agentIdentity, error) {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(dir, "node.pem"), filepath.Join(dir, "node-key.pem"))
	if err != nil {
		return agentIdentity{}, err
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return agentIdentity{}, err
	}
	key, ok := certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return agentIdentity{}, errors.New("node key is not Ed25519")
	}
	roots, err := loadPool(filepath.Join(dir, "root-ca.pem"))
	if err != nil {
		return agentIdentity{}, err
	}
	return agentIdentity{leaf: leaf, key: key, certificate: certificate, roots: roots}, nil
}

func parseEndpoints(value string) ([]endpoint, error) {
	var result []endpoint
	for _, item := range strings.Split(value, ",") {
		mode, address, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || (mode != "mtls" && mode != "grpc" && mode != "grpc-unsigned" && mode != "ws" && mode != "tunnel" && mode != "nocert") || address == "" {
			return nil, fmt.Errorf("invalid endpoint %q", item)
		}
		result = append(result, endpoint{mode, address})
	}
	return result, nil
}

func (id agentIdentity) dial(ctx context.Context, ep endpoint) (*grpc.ClientConn, error) {
	options := []grpc.DialOption{grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 10 * time.Second}), grpc.WithBlock(), grpc.WithReturnConnectionError()}
	serverName := "gateway.poc.test"
	switch ep.mode {
	case "nocert":
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: id.roots})))
		return grpc.DialContext(ctx, ep.address, options...)
	case "mtls":
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: id.roots, Certificates: []tls.Certificate{id.certificate}})))
		return grpc.DialContext(ctx, ep.address, options...)
	case "grpc", "grpc-unsigned":
		// Public CDN certificate: verified against the edge name, no client certificate.
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: "cdn.poc.test", RootCAs: id.roots})))
		return grpc.DialContext(ctx, ep.address, options...)
	case "ws", "tunnel":
		// ws: dedicated CDN name in front of the gateway origin.
		// tunnel: the gateway name itself; the gateway port answers directly,
		// or a CDN serving the same name pulls from that port.
		outerName := "cdn.poc.test"
		if ep.mode == "tunnel" {
			outerName = serverName
		}
		inner := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: id.roots, Certificates: []tls.Certificate{id.certificate}}
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(inner)), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			certHeader, authHeader, err := nodeToken(id.leaf, id.key, "cdnca-gateway", "/agent/v1/tunnel", time.Now())
			if err != nil {
				return nil, err
			}
			header := http.Header{headerNodeCert: {certHeader}, headerNodeAuth: {authHeader}}
			if tunnelLabel != "" {
				header.Set("Cdnca-Poc-Label", tunnelLabel)
			}
			if tunnelForgedXFF != "" {
				header.Set("X-Forwarded-For", tunnelForgedXFF)
			}
			dialer := websocket.Dialer{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: outerName, RootCAs: id.roots}, HandshakeTimeout: 10 * time.Second}
			ws, response, err := dialer.DialContext(ctx, "wss://"+ep.address+"/agent/v1/tunnel", header)
			if err != nil {
				if response != nil {
					return nil, fmt.Errorf("websocket upgrade: %s: %w", response.Status, err)
				}
				return nil, err
			}
			return &wsConn{ws: ws}, nil
		}))
		return grpc.DialContext(ctx, "passthrough:///gateway.poc.test", options...)
	}
	return nil, errors.New("unknown mode")
}

func (id agentIdentity) streamContext(ctx context.Context, ep endpoint, method string) (context.Context, error) {
	if ep.mode != "grpc" {
		return ctx, nil
	}
	certHeader, authHeader, err := nodeToken(id.leaf, id.key, "cdnca-gateway", method, time.Now())
	if err != nil {
		return nil, err
	}
	return metadata.AppendToOutgoingContext(ctx, strings.ToLower(headerNodeCert), certHeader, strings.ToLower(headerNodeAuth), authHeader), nil
}

func requestMeta(sequence uint64) *commonv1.StreamMetadata {
	return &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: sequence}
}

func (id agentIdentity) runSession(parent context.Context, ep endpoint, heartbeat time.Duration, until time.Time) (result sessionResult) {
	result = sessionResult{Endpoint: ep.mode + "=" + ep.address, StartedUnix: float64(time.Now().UnixMilli()) / 1000}
	started := time.Now()
	defer func() { result.Seconds = time.Since(started).Seconds() }()
	dialCtx, cancel := context.WithTimeout(parent, 10*time.Second)
	connection, err := id.dial(dialCtx, ep)
	cancel()
	if err != nil {
		result.End = "dial: " + err.Error()
		return result
	}
	defer connection.Close()
	ctx, cancelSession := context.WithDeadline(parent, until)
	defer cancelSession()
	client := agentv1.NewAgentGatewayServiceClient(connection)
	nodeID, _ := nodeIDFromCertificate(id.leaf)

	connectCtx, err := id.streamContext(ctx, ep, agentv1.AgentGatewayService_Connect_FullMethodName)
	if err != nil {
		result.End = err.Error()
		return result
	}
	stream, err := client.Connect(connectCtx)
	if err != nil {
		result.End = "connect: " + err.Error()
		return result
	}
	sequence := uint64(1)
	send := func(request *agentv1.ConnectRequest) error {
		request.Stream = requestMeta(sequence)
		sequence++
		return stream.Send(request)
	}
	if err := send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Hello{Hello: &agentv1.AgentHello{NodeId: nodeID, BootId: uuid.NewString()}}}); err != nil {
		result.End = "hello send: " + err.Error()
		return result
	}
	first, err := stream.Recv()
	if err != nil || first.GetHello() == nil {
		result.End = fmt.Sprintf("hello recv: %v", err)
		return result
	}
	result.Established = true

	telemetryDone := make(chan string, 1)
	go func() {
		telemetryCtx, err := id.streamContext(ctx, ep, agentv1.AgentGatewayService_StreamTelemetry_FullMethodName)
		if err != nil {
			telemetryDone <- err.Error()
			return
		}
		telemetry, err := client.StreamTelemetry(telemetryCtx)
		if err != nil {
			telemetryDone <- err.Error()
			return
		}
		if err := telemetry.Send(&agentv1.StreamTelemetryRequest{Stream: requestMeta(1), Payload: &agentv1.StreamTelemetryRequest_Hello{Hello: &agentv1.TelemetryClientHello{BootId: uuid.NewString()}}}); err != nil {
			telemetryDone <- err.Error()
			return
		}
		if response, err := telemetry.Recv(); err != nil || response.GetHello() == nil {
			telemetryDone <- fmt.Sprintf("telemetry hello: %v", err)
			return
		}
		for index := uint64(1); index <= 3; index++ {
			if err := telemetry.Send(&agentv1.StreamTelemetryRequest{Stream: requestMeta(index + 1), Payload: &agentv1.StreamTelemetryRequest_Batch{Batch: &agentv1.TelemetryBatch{
				BatchId: uuid.NewString(), FirstSequence: index, LastSequence: index,
				Records: []*agentv1.TelemetryRecord{{MessageId: uuid.NewString(), FirstSequence: index, LastSequence: index}}}}}); err != nil {
				telemetryDone <- err.Error()
				return
			}
			if response, err := telemetry.Recv(); err != nil || response.GetAck() == nil {
				telemetryDone <- fmt.Sprintf("telemetry ack: %v", err)
				return
			}
			result.TelemetryAcks++
		}
		_ = telemetry.CloseSend()
		telemetryDone <- ""
	}()

	responses := make(chan *agentv1.ConnectResponse)
	recvErr := make(chan error, 1)
	go func() {
		for {
			response, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			responses <- response
		}
	}()
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	lastAck := time.Now()
	sendHeartbeat := func() error {
		return send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{
			Event: &commonv1.EventMetadata{EventId: uuid.NewString(), OccurredTime: timestamppb.Now()}, HeartbeatSequence: sequence}}})
	}
	if err := sendHeartbeat(); err != nil {
		result.End = "heartbeat send: " + err.Error()
		return result
	}
	for {
		select {
		case <-ctx.Done():
			result.End = "deadline"
			if parent.Err() != nil {
				result.End = "stopped"
			}
			<-telemetryDoneOrTimeout(telemetryDone)
			return result
		case message := <-telemetryDone:
			if message != "" {
				result.End = "telemetry: " + message
				return result
			}
			telemetryDone = nil
		case err := <-recvErr:
			result.End = "recv: " + err.Error()
			return result
		case response := <-responses:
			switch payload := response.Payload.(type) {
			case *agentv1.ConnectResponse_HeartbeatAck:
				result.Heartbeats++
				lastAck = time.Now()
			case *agentv1.ConnectResponse_DeploymentCommand:
				result.Commands++
				if err := send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: &agentv1.DeploymentStatus{
					Event: &commonv1.EventMetadata{EventId: uuid.NewString(), OccurredTime: timestamppb.Now()}, DeploymentId: payload.DeploymentCommand.DeploymentId,
					Attempt: payload.DeploymentCommand.Attempt, ConfigVersionId: payload.DeploymentCommand.ConfigVersionId,
					State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY}}}); err != nil {
					result.End = "status send: " + err.Error()
					return result
				}
			}
		case <-ticker.C:
			if time.Since(lastAck) >= 3*heartbeat {
				result.End = "heartbeat ack timed out"
				return result
			}
			if err := sendHeartbeat(); err != nil {
				result.End = "heartbeat send: " + err.Error()
				return result
			}
		}
	}
}

func telemetryDoneOrTimeout(done chan string) <-chan string {
	if done == nil {
		closed := make(chan string)
		close(closed)
		return closed
	}
	out := make(chan string, 1)
	go func() {
		select {
		case message := <-done:
			out <- message
		case <-time.After(2 * time.Second):
			out <- "timeout"
		}
	}()
	return out
}

// runAgent loops over endpoints until total elapses. Each session is capped at
// sessionLimit so a run also exercises reconnects.
func runAgent(dir, endpointList string, heartbeat, total, sessionLimit time.Duration, resultFile string) error {
	id, err := loadAgentIdentity(dir)
	if err != nil {
		return err
	}
	endpoints, err := parseEndpoints(endpointList)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()
	var results []sessionResult
	index := 0
	for ctx.Err() == nil {
		ep := endpoints[index%len(endpoints)]
		until := time.Now().Add(sessionLimit)
		result := id.runSession(ctx, ep, heartbeat, until)
		log.Printf("session %s started=%.1f established=%v heartbeat_acks=%d commands=%d telemetry_acks=%d %.1fs end=%s", result.Endpoint, result.StartedUnix, result.Established, result.Heartbeats, result.Commands, result.TelemetryAcks, result.Seconds, result.End)
		results = append(results, result)
		if resultFile != "" {
			content, _ := json.MarshalIndent(results, "", "  ")
			_ = os.WriteFile(resultFile, content, 0o600)
		}
		if result.End != "deadline" {
			index++ // failed: move to the next endpoint
			select {
			case <-ctx.Done():
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	return nil
}

// node-install-defaults as the control plane serves it (ADR 0013 §4.5): the
// node is installed with --control-plane only; gateway addresses and the
// preferred transport per address come from here. Each address expands to
// [preferred, other] on the same port, so a wrong preference costs one
// failed attempt instead of an outage.
type installDefaults struct {
	GatewayEndpoints []struct {
		Address    string `json:"address"`
		ServerName string `json:"server_name"`
		Prefer     string `json:"prefer"` // grpc | tunnel
	} `json:"gateway_endpoints"`
}

func endpointsFromControl(dir, control string) (string, error) {
	roots, err := loadPool(filepath.Join(dir, "root-ca.pem"))
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "console.poc.test", RootCAs: roots}}}
	response, err := client.Get(strings.TrimRight(control, "/") + "/downloads/node-install-defaults")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var defaults installDefaults
	if err := json.NewDecoder(response.Body).Decode(&defaults); err != nil {
		return "", err
	}
	var list []string
	for _, ep := range defaults.GatewayEndpoints {
		if ep.Prefer == "tunnel" {
			list = append(list, "tunnel="+ep.Address, "mtls="+ep.Address)
		} else {
			list = append(list, "mtls="+ep.Address, "tunnel="+ep.Address)
		}
	}
	if len(list) == 0 {
		return "", errors.New("node-install-defaults has no gateway_endpoints")
	}
	log.Printf("endpoints from %s: %s", control, strings.Join(list, ","))
	return strings.Join(list, ","), nil
}

// runControl serves node-install-defaults over HTTPS (the management name).
func runControl(dir, listen, defaultsFile string) error {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(dir, "console.pem"), filepath.Join(dir, "console-key.pem"))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/downloads/node-install-defaults", func(w http.ResponseWriter, r *http.Request) {
		content, err := os.ReadFile(defaultsFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(content)
	})
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}}
	return server.ListenAndServeTLS("", "")
}
