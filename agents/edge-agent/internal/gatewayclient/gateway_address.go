package gatewayclient

// Signed Gateway address change (CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE v1,
// ConnectResponse 31 / ConnectRequest 28). The control plane signs cdnca.gateway-address-change/v1 for
// one node (libs/edgeconfig/gatewayaddr); the Gateway relays it. The node:
//  1. checks the carrier and the signature (edge publication key), the node,
//     the expiry and that the revision is newer than the last one handled;
//  2. answers PROBING, then dials the new address with mTLS (gateway CA and
//     the new server name) and sends an authenticated Connect hello; the
//     Gateway must answer a valid GatewayHello (its identity, this node's
//     authorization);
//  3. on success writes the new address as the active endpoint and reconnects;
//     the next session gets the same document again and answers SWITCHED on
//     the new address. On failure the old address stays and it answers FAILED
//     with the reason.
// The outcome per revision is persisted, so a replay is answered without a
// second probe; a retry is a new revision.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/gatewayaddr"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	gatewayAddressAPIVersion uint32 = 1
	gatewayAddressStateFile         = "gateway-address-change.json"
)

var (
	errGatewayAddressDial      = errors.New("gateway address probe could not complete the mTLS handshake")
	errGatewayAddressHandshake = errors.New("gateway address probe was not accepted by the Gateway")
)

// GatewayAddressProber dials address with mTLS (server name verified) and
// completes an authenticated Connect hello. It wraps a TCP/TLS failure in
// errGatewayAddressDial and a refused session in errGatewayAddressHandshake.
type GatewayAddressProber interface {
	ProbeAddress(ctx context.Context, address, serverName string) error
}

// GatewayAddressStore is the active endpoint record (FileGatewayEndpointStateStore).
type GatewayAddressStore interface {
	Active() GatewayEndpointState
	ChangeAddress(address, serverName string) error
}

type gatewayAddressState struct {
	Revision       uint64 `json:"revision"`
	DocumentSHA256 string `json:"document_sha256"`
	State          string `json:"state"`
	ErrorCode      string `json:"error_code,omitempty"`
}

type GatewayAddressRuntime struct {
	mu        sync.Mutex
	nodeID    string
	trusted   gatewayaddr.TrustedKeyFunc
	store     GatewayAddressStore
	directory string
	prober    GatewayAddressProber
	timeout   time.Duration
	now       func() time.Time
	last      gatewayAddressState
}

// NewGatewayAddressRuntime loads the last handled revision from directory
// (the gateway endpoint journal directory).
func NewGatewayAddressRuntime(nodeID string, trusted gatewayaddr.TrustedKeyFunc, store GatewayAddressStore, directory string,
	prober GatewayAddressProber, timeout time.Duration, now func() time.Time) (*GatewayAddressRuntime, error) {
	if !canonicalUUID(nodeID) || trusted == nil || store == nil || prober == nil || timeout <= 0 || now == nil {
		return nil, fmt.Errorf("%w: gateway address change runtime is incomplete", ErrInvalidConfiguration)
	}
	if err := validateSecureDirectory(directory, true); err != nil {
		return nil, err
	}
	runtime := &GatewayAddressRuntime{nodeID: nodeID, trusted: trusted, store: store, directory: directory,
		prober: prober, timeout: timeout, now: now}
	raw, err := readSecureRegularFile(filepath.Join(directory, gatewayAddressStateFile), false)
	switch {
	case err == nil:
		if json.Unmarshal(raw, &runtime.last) != nil || runtime.last.Revision == 0 {
			return nil, fmt.Errorf("%w: stored gateway address change state is invalid", ErrInvalidConfiguration)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	return runtime, nil
}

// WithGatewayAddressChange advertises CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE v1.
func WithGatewayAddressChange(runtime *GatewayAddressRuntime) ClientOption {
	return func(client *Client) error {
		if runtime == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.gatewayAddress = runtime
		return nil
	}
}

// ConfigureGatewayAddressChange sets the runtime after New (the prober needs the client).
func (c *Client) ConfigureGatewayAddressChange(runtime *GatewayAddressRuntime) error {
	if c == nil || runtime == nil {
		return ErrInvalidConfiguration
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.running || c.closed || c.gatewayAddress != nil {
		return fmt.Errorf("%w: gateway address change runtime cannot be changed", ErrInvalidConfiguration)
	}
	c.gatewayAddress = runtime
	return nil
}

func negotiateGatewayAddressChangeV1(gateway *agentv1.GatewayHello, runtime *GatewayAddressRuntime) (bool, error) {
	enabled := false
	for _, capability := range gateway.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE {
			continue
		}
		if enabled || capability.ApiVersion != gatewayAddressAPIVersion {
			return false, fmt.Errorf("%w: gateway address change capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && runtime == nil {
		return false, fmt.Errorf("%w: Gateway enabled gateway address change that was not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

// Handle answers one command through send (PROBING before the probe, then the
// outcome). switched: the active endpoint now names the new address and the
// caller must reconnect. An error is a carrier the Gateway must never have
// relayed (the session ends).
func (r *GatewayAddressRuntime) Handle(ctx context.Context, command *agentv1.GatewayAddressChangeCommand,
	send func(*agentv1.GatewayAddressChangeReceipt) error) (bool, error) {
	if r == nil || ctx == nil || send == nil || command == nil || command.NodeId != r.nodeID || command.Revision == 0 ||
		command.Event == nil || !canonicalUUID(command.Event.EventId) || len(command.DocumentJson) == 0 {
		return false, fmt.Errorf("%w: gateway address change carrier is invalid", ErrInvalidMessage)
	}
	digest := sha256.Sum256(command.DocumentJson)
	if !bytes.Equal(digest[:], command.DocumentSha256) {
		return false, fmt.Errorf("%w: gateway address change digest mismatch", ErrInvalidMessage)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	answer := func(state, code string) error {
		active := r.store.Active()
		return send(r.receipt(command, digest[:], state, code, active))
	}
	digestHex := hex.EncodeToString(digest[:])
	if r.last.Revision == command.Revision && r.last.DocumentSHA256 == digestHex {
		return false, answer(r.last.State, r.last.ErrorCode)
	}
	change, err := gatewayaddr.Open(command.DocumentJson, r.nodeID, r.trusted)
	switch {
	case errors.Is(err, gatewayaddr.ErrUntrusted):
		return false, answer(gatewayaddr.StateFailed, gatewayaddr.ErrorUntrusted)
	case errors.Is(err, gatewayaddr.ErrWrongNode):
		return false, answer(gatewayaddr.StateFailed, gatewayaddr.ErrorWrongNode)
	case err != nil || change.Revision != command.Revision:
		return false, answer(gatewayaddr.StateFailed, gatewayaddr.ErrorInvalid)
	case change.Revision <= r.last.Revision:
		return false, answer(gatewayaddr.StateFailed, gatewayaddr.ErrorStale)
	case change.Expired(r.now()):
		return false, answer(gatewayaddr.StateFailed, gatewayaddr.ErrorExpired)
	}
	settle := func(state, code string) (bool, error) {
		r.record(gatewayAddressState{Revision: change.Revision, DocumentSHA256: digestHex, State: state, ErrorCode: code})
		return state == gatewayaddr.StateSwitched, answer(state, code)
	}
	if r.store.Active().TransitionID != "" {
		return settle(gatewayaddr.StateFailed, gatewayaddr.ErrorBusy)
	}
	if err := answer(gatewayaddr.StateProbing, ""); err != nil {
		return false, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, r.timeout)
	err = r.prober.ProbeAddress(probeCtx, change.Address, change.ServerName)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err() // the session ended; the replay probes again
		}
		code := gatewayaddr.ErrorDial
		if errors.Is(err, errGatewayAddressHandshake) {
			code = gatewayaddr.ErrorHandshake
		}
		return settle(gatewayaddr.StateFailed, code)
	}
	if err := r.store.ChangeAddress(change.Address, change.ServerName); err != nil {
		if errors.Is(err, ErrCommandConflict) {
			return settle(gatewayaddr.StateFailed, gatewayaddr.ErrorBusy)
		}
		return settle(gatewayaddr.StateFailed, gatewayaddr.ErrorPersist)
	}
	// Recorded switched; the PROBING receipt already went out on the old
	// address, the SWITCHED one is sent on the new session's replay (it is
	// the proof the new address works). The caller reconnects.
	r.record(gatewayAddressState{Revision: change.Revision, DocumentSHA256: digestHex, State: gatewayaddr.StateSwitched})
	return true, nil
}

// record persists the outcome; a write failure keeps it in memory (a restart
// then probes the same revision again, which is harmless).
func (r *GatewayAddressRuntime) record(state gatewayAddressState) {
	r.last = state
	encoded, err := json.Marshal(state)
	if err == nil {
		err = writeSecureFileAtomic(r.directory, gatewayAddressStateFile, encoded)
	}
	if err != nil {
		slog.Warn("persist gateway address change state failed", "error", err)
	}
}

func writeSecureFileAtomic(directory, name string, content []byte) error {
	temporary, err := os.CreateTemp(directory, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), filepath.Join(directory, name)); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func (r *GatewayAddressRuntime) receipt(command *agentv1.GatewayAddressChangeCommand, digest []byte, state, code string,
	active GatewayEndpointState) *agentv1.GatewayAddressChangeReceipt {
	namespace := uuid.MustParse(r.nodeID)
	return &agentv1.GatewayAddressChangeReceipt{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte(fmt.Sprintf("gateway-address-receipt/%s/%s/%s", command.Event.EventId, state, code))).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("gateway-address-receipt-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(r.now().UTC()),
		},
		NodeId: r.nodeID, CommandEventId: command.Event.EventId, Revision: command.Revision,
		DocumentSha256: append([]byte(nil), digest...), State: state, ErrorCode: code,
		ActiveAddress: active.Address, ActiveServerName: active.ServerName,
	}
}

func sendGatewayAddressChangeReceipt(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, receipt *agentv1.GatewayAddressChangeReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_GatewayAddressChangeReceipt{GatewayAddressChangeReceipt: receipt}})
}

// clientAddressProber is the production prober: the node's own mTLS dialer
// settings with the new address and server name, then a Connect hello the
// Gateway must answer with a valid GatewayHello.
type clientAddressProber struct {
	client  *Client
	factory *EndpointMTLSDialerFactory
}

func NewClientAddressProber(client *Client, factory *EndpointMTLSDialerFactory) (GatewayAddressProber, error) {
	if client == nil || factory == nil {
		return nil, fmt.Errorf("%w: gateway address prober dependencies are required", ErrInvalidConfiguration)
	}
	return &clientAddressProber{client: client, factory: factory}, nil
}

func (p *clientAddressProber) ProbeAddress(ctx context.Context, address, serverName string) error {
	dialer, err := p.factory.New(GatewayEndpointState{Address: address, ServerName: serverName})
	if err != nil {
		return errors.Join(errGatewayAddressDial, err)
	}
	connection, err := dialer.Dial(ctx)
	if err != nil {
		return errors.Join(errGatewayAddressDial, err)
	}
	defer connection.Close()
	if err := p.client.probeGatewayHello(ctx, connection.Client()); err != nil {
		return errors.Join(errGatewayAddressHandshake, err)
	}
	return nil
}

// probeGatewayHello sends this node's hello and checks the GatewayHello; the
// stream is then cancelled (the probe never holds the session).
func (c *Client) probeGatewayHello(ctx context.Context, gateway agentv1.AgentGatewayServiceClient) error {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := gateway.Connect(probeCtx, grpc.WaitForReady(false))
	if err != nil {
		return err
	}
	hello, err := c.agentHello()
	if err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(1, c.now()), Payload: &agentv1.ConnectRequest_Hello{Hello: hello}}); err != nil {
		return err
	}
	response, err := stream.Recv()
	if err != nil {
		return err
	}
	if err := validateResponseEnvelope(response, 1); err != nil {
		return err
	}
	return validateGatewayHello(response.GetHello(), c.config)
}
