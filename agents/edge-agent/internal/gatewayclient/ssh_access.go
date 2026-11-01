package gatewayclient

// "Only the controller may SSH" (node-ssh-tab, CAPABILITY_NAME_SSH_ACCESS v1,
// ConnectResponse 32 / ConnectRequest 29). The control plane sends the
// node's wanted state as revision (operation apply) and, once it reached
// sshd through the new rules, a confirm of that revision. The node applies
// with a rollback timer (internal/sshaccess); unless confirmed in time the
// table is removed and the node reports reverted without being asked (that
// report is queued while no session is up and sent on the next one).

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/sshaccess"
	contract "github.com/cdnca/cdnca/libs/edgeconfig/sshaccess"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SSHAccessManager is internal/sshaccess.Manager.
type SSHAccessManager interface {
	Apply(context.Context, sshaccess.Policy) (sshaccess.State, error)
	Confirm(revision uint64) (sshaccess.State, error)
	State() sshaccess.State
}

// SSHAccessRuntime answers SSH access commands and carries rollback reports.
type SSHAccessRuntime struct {
	nodeID  string
	manager SSHAccessManager
	now     func() time.Time

	mu       sync.Mutex
	reverted []*agentv1.SSHAccessReceipt
	signal   chan struct{}
}

// NewSSHAccessRuntime wraps manager for nodeID.
func NewSSHAccessRuntime(nodeID string, manager SSHAccessManager, now func() time.Time) (*SSHAccessRuntime, error) {
	if !canonicalUUID(nodeID) || manager == nil || now == nil {
		return nil, fmt.Errorf("%w: SSH access runtime is incomplete", ErrInvalidConfiguration)
	}
	return &SSHAccessRuntime{nodeID: nodeID, manager: manager, now: now, signal: make(chan struct{}, 1)}, nil
}

// WithSSHAccess advertises CAPABILITY_NAME_SSH_ACCESS v1.
func WithSSHAccess(runtime *SSHAccessRuntime) ClientOption {
	return func(client *Client) error {
		if runtime == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.sshAccess = runtime
		return nil
	}
}

func negotiateSSHAccessV1(gateway *agentv1.GatewayHello, runtime *SSHAccessRuntime) (bool, error) {
	enabled := false
	for _, capability := range gateway.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS {
			continue
		}
		if enabled || capability.ApiVersion != contract.APIVersion {
			return false, fmt.Errorf("%w: SSH access capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && runtime == nil {
		return false, fmt.Errorf("%w: Gateway enabled SSH access that was not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

// Reverted is the rollback callback (sshaccess.Manager.OnRevert).
func (r *SSHAccessRuntime) Reverted(state sshaccess.State) {
	receipt := r.receipt("", state.Policy.Revision, contract.StateReverted, contract.FailureConfirmationTimeout)
	r.mu.Lock()
	// Only the newest report matters; keep a short queue against a burst.
	if len(r.reverted) >= 8 {
		r.reverted = r.reverted[1:]
	}
	r.reverted = append(r.reverted, receipt)
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

// pendingReports is signalled when a rollback report waits.
func (r *SSHAccessRuntime) pendingReports() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.signal
}

// takeReports drains the queued rollback reports.
func (r *SSHAccessRuntime) takeReports() []*agentv1.SSHAccessReceipt {
	r.mu.Lock()
	defer r.mu.Unlock()
	reports := r.reverted
	r.reverted = nil
	return reports
}

// requeue puts reports back (the session ended before they were sent).
func (r *SSHAccessRuntime) requeue(reports []*agentv1.SSHAccessReceipt) {
	if len(reports) == 0 {
		return
	}
	r.mu.Lock()
	r.reverted = append(reports, r.reverted...)
	if len(r.reverted) > 8 {
		r.reverted = r.reverted[len(r.reverted)-8:]
	}
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

// Handle answers one command. An error is a carrier the Gateway must never
// have relayed (the session ends); a refused policy is a failed receipt.
func (r *SSHAccessRuntime) Handle(ctx context.Context, command *agentv1.SSHAccessCommand) (*agentv1.SSHAccessReceipt, error) {
	if r == nil || command == nil || command.NodeId != r.nodeID || command.Revision == 0 || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) || !contract.ValidOperation(command.Operation) {
		return nil, fmt.Errorf("%w: SSH access carrier is invalid", ErrInvalidMessage)
	}
	if command.Operation == contract.OperationConfirm {
		state, err := r.manager.Confirm(command.Revision)
		if err != nil {
			return r.receiptFor(command, state, contract.FailureUnknownRevision), nil
		}
		return r.receiptFor(command, state, ""), nil
	}
	if command.SshPort == 0 || command.SshPort > 65535 {
		return r.receipt(command.Event.EventId, command.Revision, contract.StateFailed, contract.FailureInvalidPolicy), nil
	}
	state, err := r.manager.Apply(ctx, sshaccess.Policy{Revision: command.Revision, Enabled: command.Enabled,
		SSHPort: uint16(command.SshPort), CIDRs: append([]string(nil), command.Cidrs...)})
	switch {
	case errors.Is(err, sshaccess.ErrInvalidPolicy):
		return r.receipt(command.Event.EventId, command.Revision, contract.StateFailed, contract.FailureInvalidPolicy), nil
	case errors.Is(err, sshaccess.ErrStaleRevision):
		return r.receipt(command.Event.EventId, command.Revision, contract.StateFailed, contract.FailureStaleRevision), nil
	case err != nil:
		code := state.FailureCode
		if code == "" || !contract.ValidFailureCode(code) {
			code = "apply_failed"
		}
		return r.receipt(command.Event.EventId, command.Revision, contract.StateFailed, code), nil
	}
	return r.receiptFor(command, state, ""), nil
}

// receiptFor reports state for command's revision (a repeated revision is
// answered with what the node holds).
func (r *SSHAccessRuntime) receiptFor(command *agentv1.SSHAccessCommand, state sshaccess.State, refused string) *agentv1.SSHAccessReceipt {
	switch {
	case state.Policy.Revision != command.Revision:
		code := refused
		if code == "" {
			code = contract.FailureUnknownRevision
		}
		return r.receipt(command.Event.EventId, command.Revision, contract.StateFailed, code)
	case state.Reverted:
		return r.receipt(command.Event.EventId, command.Revision, contract.StateReverted, nonEmpty(state.FailureCode, contract.FailureConfirmationTimeout))
	case state.FailureCode != "":
		return r.receipt(command.Event.EventId, command.Revision, contract.StateFailed, state.FailureCode)
	case state.Confirmed:
		return r.receipt(command.Event.EventId, command.Revision, contract.StateConfirmed, "")
	case state.Applied:
		return r.receipt(command.Event.EventId, command.Revision, contract.StateApplied, "")
	}
	return r.receipt(command.Event.EventId, command.Revision, contract.StateFailed, nonEmpty(refused, "apply_failed"))
}

func nonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func (r *SSHAccessRuntime) receipt(commandEventID string, revision uint64, state, code string) *agentv1.SSHAccessReceipt {
	namespace := uuid.MustParse(r.nodeID)
	key := fmt.Sprintf("ssh-access-receipt/%s/%d/%s/%s", commandEventID, revision, state, code)
	if commandEventID == "" {
		key += "/" + r.now().UTC().Format(time.RFC3339Nano) // each rollback report is its own event
	}
	return &agentv1.SSHAccessReceipt{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte(key)).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("ssh-access-receipt-request/"+key)).String(),
			OccurredTime: timestamppb.New(r.now().UTC()),
		},
		NodeId: r.nodeID, CommandEventId: commandEventID, Revision: revision, State: state, FailureCode: code,
	}
}

func sendSSHAccessReceipt(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, receipt *agentv1.SSHAccessReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_SshAccessReceipt{SshAccessReceipt: receipt}})
}
