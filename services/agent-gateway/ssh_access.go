package gateway

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sshaccess"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// "Only the controller may SSH" delivery (node-ssh-tab, CAPABILITY_NAME_SSH_ACCESS
// v1, ConnectResponse 32 / ConnectRequest 29). control-api publishes the
// node's newest command (apply a revision, or confirm it); the command
// stream keeps one per node and every session starts from it (the node
// answers a repeated revision with its current state). Receipts answer a
// command or report the node's rollback timer reverting a revision, so the
// gateway relays every valid receipt of the session's node without binding
// it to a pending command. A node without the capability is answered
// not_supported by the gateway.

type SSHAccessPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

// SSHAccessBus is the gateway side of the SSH access streams.
type SSHAccessBus interface {
	SubscribeSSHAccess(context.Context, string) (SSHAccessSubscription, error)
	PublishSSHAccessReceipt(context.Context, string, *agentv1.SSHAccessReceipt) (SSHAccessPublication, error)
}

// SSHAccessSubscription yields the node's newest command first, then newer ones.
type SSHAccessSubscription interface {
	Next(context.Context) (*agentv1.SSHAccessCommand, error)
	Close() error
}

// ConfigureSSHAccess enables SSH access delivery.
func (g *Gateway) ConfigureSSHAccess(bus SSHAccessBus) error {
	if g == nil || bus == nil || g.sshAccess != nil {
		return fmt.Errorf("SSH access bus is invalid or already configured")
	}
	g.sshAccess = bus
	return nil
}

func sshAccessCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS {
			continue
		}
		if seen || capability.ApiVersion != sshaccess.APIVersion {
			return false, fmt.Errorf("SSH access capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

type sshAccessReceive struct {
	command *agentv1.SSHAccessCommand
	err     error
}

type sessionSSHAccess struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription SSHAccessSubscription
	next         chan sshAccessReceive
}

func (g *Gateway) startSessionSSHAccess(ctx context.Context, nodeID string) (*sessionSSHAccess, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := g.sshAccess.SubscribeSSHAccess(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, status.Error(codes.Unavailable, "could not subscribe to SSH access commands")
	}
	return &sessionSSHAccess{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (session *sessionSSHAccess) receive() <-chan sshAccessReceive {
	if session == nil {
		return nil
	}
	if session.next == nil {
		next := make(chan sshAccessReceive, 1)
		session.next = next
		go func() {
			command, err := session.subscription.Next(session.ctx)
			next <- sshAccessReceive{command: command, err: err}
		}()
	}
	return session.next
}

func (session *sessionSSHAccess) stop() {
	if session == nil {
		return
	}
	session.cancel()
	_ = session.subscription.Close()
}

func validateSSHAccessCommand(command *agentv1.SSHAccessCommand, nodeID string) error {
	if command == nil || proto.Size(command) > sshaccess.MaxCarrierBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) ||
		command.NodeId != nodeID || command.Revision == 0 || !sshaccess.ValidOperation(command.Operation) ||
		command.Event == nil || command.Event.OccurredTime == nil || !validEventMetadata(command.Event, command.Event.OccurredTime) {
		return fmt.Errorf("SSH access command is invalid")
	}
	if command.Operation == sshaccess.OperationConfirm {
		if command.Enabled || command.SshPort != 0 || len(command.Cidrs) != 0 {
			return fmt.Errorf("SSH access confirm carries a policy")
		}
		return nil
	}
	if command.SshPort == 0 || command.SshPort > 65535 || len(command.Cidrs) > sshaccess.MaxCIDRs ||
		command.Enabled != (len(command.Cidrs) > 0) {
		return fmt.Errorf("SSH access policy is invalid")
	}
	for _, cidr := range command.Cidrs {
		if prefix, err := netip.ParsePrefix(cidr); err != nil || prefix != prefix.Masked() || prefix.String() != cidr {
			return fmt.Errorf("SSH access network is invalid")
		}
	}
	return nil
}

func validateSSHAccessReceipt(receipt *agentv1.SSHAccessReceipt, nodeID string) error {
	if receipt == nil || proto.Size(receipt) > sshaccess.MaxCarrierBytes || cacheControlMessageHasUnknown(receipt.ProtoReflect()) ||
		receipt.NodeId != nodeID || receipt.Revision == 0 || !sshaccess.ValidState(receipt.State) ||
		!sshaccess.ValidFailureCode(receipt.FailureCode) || (receipt.State == sshaccess.StateFailed) && receipt.FailureCode == "" ||
		(receipt.State == sshaccess.StateApplied || receipt.State == sshaccess.StateConfirmed) && receipt.FailureCode != "" ||
		receipt.CommandEventId != "" && uuid.Validate(receipt.CommandEventId) != nil ||
		receipt.Event == nil || receipt.Event.OccurredTime == nil || !validEventMetadata(receipt.Event, receipt.Event.OccurredTime) {
		return fmt.Errorf("SSH access receipt is invalid")
	}
	return nil
}

// notSupportedSSHAccessReceipt answers a command for a node that did not
// declare SSH_ACCESS v1 (identity follows the command's).
func notSupportedSSHAccessReceipt(command *agentv1.SSHAccessCommand, now time.Time) *agentv1.SSHAccessReceipt {
	namespace := uuid.MustParse(command.NodeId)
	return &agentv1.SSHAccessReceipt{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("ssh-access-not-supported/"+command.Event.EventId)).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("ssh-access-not-supported-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Revision: command.Revision,
		State: sshaccess.StateFailed, FailureCode: sshaccess.FailureNotSupported,
	}
}

func (g *Gateway) publishSSHAccessReceipt(ctx context.Context, nodeID string, receipt *agentv1.SSHAccessReceipt) error {
	if err := validateSSHAccessReceipt(receipt, nodeID); err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	defer cancel()
	publication, err := g.sshAccess.PublishSSHAccessReceipt(operationCtx, nodeID, proto.Clone(receipt).(*agentv1.SSHAccessReceipt))
	if err != nil || publication.Sequence == 0 {
		return status.Error(codes.Unavailable, "SSH access receipt could not be published")
	}
	return nil
}
