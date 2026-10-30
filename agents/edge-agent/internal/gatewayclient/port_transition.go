package gatewayclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const gatewayPortTransitionAPIVersion uint32 = 1

var (
	ErrPortTransitionIdentityMismatch   = errors.New("gateway port transition changed the node identity")
	errGatewayEndpointSwitched          = errors.New("gateway endpoint switched")
	ErrPortTransitionPersistenceUnknown = errors.New("gateway endpoint persistence outcome is unknown")
)

type GatewayEndpointState struct {
	TransitionID      string `json:"transition_id,omitempty"`
	Address           string `json:"address"`
	ServerName        string `json:"server_name"`
	Revision          uint64 `json:"revision"`
	LastCommandSHA256 string `json:"last_command_sha256,omitempty"`
	LastStatus        string `json:"last_status,omitempty"`
}

type GatewayEndpointStateStore interface {
	Active() GatewayEndpointState
	Stage(GatewayEndpointState) error
	Activate(GatewayEndpointState) error
	Finalize(GatewayEndpointState) error
	Rollback(GatewayEndpointState) error
	RecordFailure(GatewayEndpointState) error
	Recover() error
}

type GatewayCandidateDialer interface {
	Probe(context.Context, GatewayEndpointState, string) error
}

type PortTransitionRuntime struct {
	mu                 sync.Mutex
	persistenceUnknown bool
	store              GatewayEndpointStateStore
	dialer             GatewayCandidateDialer
	certificateSHA     string
	now                func() time.Time
}

func NewPortTransitionRuntime(store GatewayEndpointStateStore, dialer GatewayCandidateDialer, certificateSHA string, now func() time.Time) *PortTransitionRuntime {
	return &PortTransitionRuntime{store: store, dialer: dialer, certificateSHA: certificateSHA, now: now}
}

func (r *PortTransitionRuntime) Proof() *agentv1.GatewayPortTransitionProof {
	if r == nil || r.store == nil {
		return nil
	}
	active := r.store.Active()
	if active.TransitionID == "" || active.Revision == 0 {
		return nil
	}
	return &agentv1.GatewayPortTransitionProof{TransitionId: active.TransitionID, Revision: active.Revision,
		ActiveEndpoint: &agentv1.GatewayEndpoint{Address: active.Address, ServerName: active.ServerName}}
}

func WithPortTransitionRuntime(runtime *PortTransitionRuntime) ClientOption {
	return func(client *Client) error {
		if runtime == nil || runtime.store == nil || runtime.dialer == nil {
			return fmt.Errorf("%w: gateway port transition runtime is required", ErrInvalidConfiguration)
		}
		client.portTransition = runtime
		return nil
	}
}

func (c *Client) ConfigurePortTransition(runtime *PortTransitionRuntime) error {
	if c == nil || runtime == nil || runtime.store == nil || runtime.dialer == nil {
		return fmt.Errorf("%w: gateway port transition runtime is required", ErrInvalidConfiguration)
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.running || c.closed || c.portTransition != nil {
		return fmt.Errorf("%w: gateway port transition runtime cannot be changed", ErrInvalidConfiguration)
	}
	c.portTransition = runtime
	return nil
}

func (c *Client) probePortTransition(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, state GatewayEndpointState) error {
	if c == nil || gateway == nil || ctx == nil || !validGatewayEndpointStateFields(state) || state.TransitionID == "" {
		return fmt.Errorf("%w: gateway endpoint probe is invalid", ErrInvalidConfiguration)
	}
	probeCtx, cancel := context.WithTimeout(ctx, c.config.HandshakeTimeout)
	defer cancel()
	stream, err := gateway.Connect(probeCtx, grpc.WaitForReady(false))
	if err != nil { return err }
	hello, err := c.agentHello()
	if err != nil { return err }
	hello.GatewayPortTransitionProof = &agentv1.GatewayPortTransitionProof{TransitionId: state.TransitionID, Revision: state.Revision,
		ActiveEndpoint: &agentv1.GatewayEndpoint{Address: state.Address, ServerName: state.ServerName}}
	if err := stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(1, c.now()), Payload: &agentv1.ConnectRequest_Hello{Hello: hello}}); err != nil {
		return err
	}
	response, err := stream.Recv()
	if err != nil { return err }
	if err := validateResponseEnvelope(response, 1); err != nil { return err }
	if err := validateGatewayHello(response.GetHello(), c.config); err != nil { return err }
	enabled, err := negotiateGatewayPortTransitionV1(response.GetHello(), hello.Capabilities)
	if err != nil { return err }
	if !enabled { return fmt.Errorf("%w: Gateway did not confirm port transition capability", ErrInvalidMessage) }
	return nil
}

func negotiateGatewayPortTransitionV1(gateway *agentv1.GatewayHello, local *agentv1.AgentCapabilities) (bool, error) {
	localV1, err := singleCapabilityV1(local.GetFeatures(), agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION, "local gateway port transition")
	if err != nil { return false, err }
	gatewayV1, err := singleCapabilityV1(gateway.GetEnabledCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION, "Gateway port transition")
	if err != nil { return false, err }
	if gatewayV1 && !localV1 {
		return false, fmt.Errorf("%w: Gateway enabled an unadvertised port transition capability", ErrInvalidMessage)
	}
	return gatewayV1 && localV1, nil
}

func sendGatewayPortTransitionStatus(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, status *agentv1.GatewayPortTransitionStatus, now time.Time) error {
	if status == nil { return fmt.Errorf("%w: gateway port transition status is missing", ErrInvalidMessage) }
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_GatewayPortTransitionStatus{GatewayPortTransitionStatus: status}})
}

func (r *PortTransitionRuntime) Apply(ctx context.Context, command *agentv1.GatewayPortTransitionCommand) (*agentv1.GatewayPortTransitionStatus, error) {
	if r == nil || r.store == nil || r.dialer == nil || r.now == nil || ctx == nil || command == nil || cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return nil, fmt.Errorf("%w: invalid gateway port transition", ErrInvalidMessage)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.persistenceUnknown {
		if err := r.store.Recover(); err != nil {
			return nil, err
		}
		r.persistenceUnknown = false
	}
	active := r.store.Active()
	previous, err := r.storedStatus(active)
	if err != nil {
		return nil, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	commandSHA := hex.EncodeToString(digest[:])
	if previous != nil && active.LastCommandSHA256 == commandSHA {
		if previous.CertificateSha256 != r.certificateSHA {
			return nil, ErrPortTransitionIdentityMismatch
		}
		if previous.State == agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FAILED {
			return previous, fmt.Errorf("gateway port transition failed: %s", previous.ErrorCode)
		}
		return previous, nil
	}
	validationState := active
	if previous != nil && previous.State == agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FAILED &&
		command.Action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK &&
		previous.TransitionId == command.TransitionId && previous.NodeId == command.NodeId &&
		previous.CertificateSha256 == r.certificateSHA && active.Address == command.GetOldEndpoint().GetAddress() {
		// A failed switch never left the old endpoint, but rollback still closes the operation.
		validationState.TransitionID = command.TransitionId
		validationState.Address = command.GetNewEndpoint().GetAddress()
	}
	if validateAgentPortTransition(command, validationState, r.certificateSHA, r.now()) != nil {
		return nil, fmt.Errorf("%w: invalid gateway port transition", ErrInvalidMessage)
	}
	statusRevision := uint64(1)
	if command.Action != agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH {
		// Legacy switched states predate receipts and have already emitted revision 1.
		statusRevision = 2
		if previous != nil {
			if previous.TransitionId != command.TransitionId || previous.CertificateSha256 != r.certificateSHA || previous.StatusRevision == ^uint64(0) {
				return nil, fmt.Errorf("%w: gateway port transition status conflicts with active state", ErrInvalidMessage)
			}
			statusRevision = previous.StatusRevision + 1
		}
	}
	status := &agentv1.GatewayPortTransitionStatus{Schema: command.Schema, TransitionId: command.TransitionId,
		NodeId: command.NodeId, Revision: command.Revision, StatusRevision: statusRevision, ActiveEndpoint: agentGatewayEndpoint(command.OldEndpoint),
		CertificateSha256: r.certificateSHA}
	status.Event = &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: command.GetEvent().GetRequestId(),
		OccurredTime: timestamppb.New(r.now().UTC()), CausationId: optionalString(command.GetEvent().GetEventId()),
		CorrelationId: command.GetEvent().GetCorrelationId(), Traceparent: command.GetEvent().GetTraceparent(), TaskId: optionalString(command.TransitionId)}
	switch command.Action {
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE:
		status.State = agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FINALIZED
		status.ActiveEndpoint = agentGatewayEndpoint(command.NewEndpoint)
		active := GatewayEndpointState{Address: command.NewEndpoint.Address, ServerName: command.NewEndpoint.ServerName, Revision: command.Revision}
		if err := recordPortTransitionStatus(&active, commandSHA, status); err != nil {
			return nil, err
		}
		if err := r.store.Finalize(active); err != nil {
			r.persistenceUnknown = errors.Is(err, ErrPortTransitionPersistenceUnknown)
			return nil, err
		}
		return status, nil
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK:
		status.State = agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_ROLLED_BACK
		status.ErrorCode = "operator_rollback"
		active := GatewayEndpointState{Address: command.OldEndpoint.Address, ServerName: command.OldEndpoint.ServerName, Revision: command.Revision}
		if err := recordPortTransitionStatus(&active, commandSHA, status); err != nil {
			return nil, err
		}
		if err := r.store.Rollback(active); err != nil {
			r.persistenceUnknown = errors.Is(err, ErrPortTransitionPersistenceUnknown)
			return nil, err
		}
		return status, nil
	}
	status.State = agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED
	status.ActiveEndpoint = agentGatewayEndpoint(command.NewEndpoint)
	candidate := GatewayEndpointState{TransitionID: command.TransitionId, Address: command.NewEndpoint.Address,
		ServerName: command.NewEndpoint.ServerName, Revision: command.Revision}
	if err := recordPortTransitionStatus(&candidate, commandSHA, status); err != nil {
		return nil, err
	}
	if err := r.store.Stage(candidate); err != nil {
		return r.recordFailure(active, commandSHA, status, "candidate_stage_failed", err)
	}
	if err := r.dialer.Probe(ctx, candidate, r.certificateSHA); err != nil {
		return r.recordFailure(active, commandSHA, status, "candidate_dial_failed", err)
	}
	if err := r.store.Activate(candidate); err != nil {
		if errors.Is(err, ErrPortTransitionPersistenceUnknown) {
			r.persistenceUnknown = true
			return nil, err
		}
		return r.recordFailure(active, commandSHA, status, "candidate_activate_failed", err)
	}
	return status, nil
}

func (r *PortTransitionRuntime) recordFailure(active GatewayEndpointState, commandSHA string, status *agentv1.GatewayPortTransitionStatus, code string, cause error) (*agentv1.GatewayPortTransitionStatus, error) {
	status.State = agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FAILED
	status.ActiveEndpoint = &agentv1.GatewayEndpoint{Address: active.Address, ServerName: active.ServerName}
	status.ErrorCode = code
	active.Revision = status.Revision
	active.TransitionID = ""
	if err := recordPortTransitionStatus(&active, commandSHA, status); err != nil {
		return nil, err
	}
	if err := r.store.RecordFailure(active); err != nil {
		r.persistenceUnknown = errors.Is(err, ErrPortTransitionPersistenceUnknown)
		return nil, err
	}
	return status, cause
}

func recordPortTransitionStatus(state *GatewayEndpointState, commandSHA string, status *agentv1.GatewayPortTransitionStatus) error {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(status)
	if err != nil {
		return err
	}
	state.LastCommandSHA256 = commandSHA
	state.LastStatus = base64.StdEncoding.EncodeToString(encoded)
	return nil
}

func (r *PortTransitionRuntime) storedStatus(active GatewayEndpointState) (*agentv1.GatewayPortTransitionStatus, error) {
	if active.LastCommandSHA256 == "" && active.LastStatus == "" {
		return nil, nil
	}
	encoded, err := base64.StdEncoding.DecodeString(active.LastStatus)
	status := new(agentv1.GatewayPortTransitionStatus)
	if err != nil || !validAgentPortTransitionSHA(active.LastCommandSHA256) || len(encoded) == 0 || len(encoded) > 64<<10 ||
		proto.Unmarshal(encoded, status) != nil || cacheControlMessageHasUnknown(status.ProtoReflect()) ||
		status.Schema != agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1 ||
		!validAgentPortTransitionEvent(status.Event) || !canonicalUUID(status.TransitionId) || !canonicalUUID(status.NodeId) ||
		status.Revision != active.Revision || status.StatusRevision == 0 || !validAgentPortTransitionSHA(status.CertificateSha256) ||
		status.GetActiveEndpoint().GetAddress() != active.Address || status.GetActiveEndpoint().GetServerName() != active.ServerName {
		return nil, fmt.Errorf("%w: invalid stored gateway port transition status", ErrInvalidMessage)
	}
	switch status.State {
	case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FAILED:
		if active.TransitionID == "" && (status.ErrorCode == "candidate_stage_failed" || status.ErrorCode == "candidate_dial_failed" || status.ErrorCode == "candidate_activate_failed") {
			return status, nil
		}
	case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED:
		if active.TransitionID == status.TransitionId && status.ErrorCode == "" {
			return status, nil
		}
	case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FINALIZED:
		if active.TransitionID == "" && status.ErrorCode == "" {
			return status, nil
		}
	case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_ROLLED_BACK:
		if active.TransitionID == "" && status.ErrorCode == "operator_rollback" {
			return status, nil
		}
	}
	return nil, fmt.Errorf("%w: gateway port transition status conflicts with stored endpoint", ErrInvalidMessage)
}

func agentGatewayEndpoint(value *agentv1.GatewayEndpoint) *agentv1.GatewayEndpoint {
	if value == nil { return nil }
	return &agentv1.GatewayEndpoint{Address: value.Address, ServerName: value.ServerName}
}

func validateAgentPortTransition(command *agentv1.GatewayPortTransitionCommand, active GatewayEndpointState, certificateSHA string, now time.Time) error {
	if command == nil || command.Schema != agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1 ||
		!validAgentPortTransitionEvent(command.Event) || !canonicalUUID(command.TransitionId) ||
		!canonicalUUID(command.NodeId) || command.NewEndpoint == nil || command.OldEndpoint == nil ||
		command.NewEndpoint.ServerName != active.ServerName || command.OldEndpoint.ServerName != active.ServerName ||
		!validAgentGatewayEndpoint(command.NewEndpoint) || !validAgentGatewayEndpoint(command.OldEndpoint) ||
		command.CompatibilityDeadline == nil || command.RollbackDeadline == nil ||
		command.CompatibilityDeadline.CheckValid() != nil || command.RollbackDeadline.CheckValid() != nil ||
		!command.RollbackDeadline.AsTime().After(command.CompatibilityDeadline.AsTime()) ||
		command.CertificateSha256 != certificateSHA || !validAgentPortTransitionSHA(certificateSHA) {
		return ErrInvalidMessage
	}
	switch command.Action {
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH:
		if command.Revision <= active.Revision || active.Address != command.OldEndpoint.Address || command.NewEndpoint.Address == active.Address ||
			active.ServerName != command.OldEndpoint.ServerName || !command.CompatibilityDeadline.AsTime().After(now) {
			return ErrInvalidMessage
		}
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE,
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK:
		if command.Revision != active.Revision || active.TransitionID != command.TransitionId ||
			active.Address != command.NewEndpoint.Address || active.ServerName != command.NewEndpoint.ServerName ||
			now.After(command.RollbackDeadline.AsTime()) {
			return ErrInvalidMessage
		}
	default:
		return ErrInvalidMessage
	}
	return nil
}

func validAgentPortTransitionEvent(event *commonv1.EventMetadata) bool {
	return event != nil && canonicalUUID(event.EventId) && canonicalUUID(event.RequestId) &&
		event.OccurredTime != nil && event.OccurredTime.CheckValid() == nil && canonicalUUID(event.CorrelationId) &&
		(event.TaskId == nil || canonicalUUID(*event.TaskId)) && boundedMetadata(event.Traceparent, false)
}

func validAgentGatewayEndpoint(value *agentv1.GatewayEndpoint) bool {
	if value == nil || value.Address == "" || value.ServerName == "" || value.Address != strings.TrimSpace(value.Address) || value.ServerName != strings.TrimSpace(value.ServerName) {
		return false
	}
	_, _, err := net.SplitHostPort(value.Address)
	return err == nil
}

func validAgentPortTransitionSHA(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
