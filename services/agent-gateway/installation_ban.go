package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/installationban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const installationBanAPIVersion = contract.APIVersion

// Installation ban commands (CAPABILITY_NAME_INSTALLATION_BAN_TICKET v1, ADR 0014 LIC-BAN-05) follow the signer
// trust delivery pattern: one durable pull consumer per node, at most one command in flight per session, and the
// delivery is acknowledged only after the Agent's receipt is durably published. control-api republishes until the
// node reports the latest revision. Delivery does not depend on the authorization snapshot allowing deployments:
// a ban or its lift must reach a node whose deployments are paused.

type InstallationBanPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

type InstallationBanBus interface {
	SubscribeInstallationBan(context.Context, string) (InstallationBanSubscription, error)
	PublishInstallationBanReceipt(context.Context, string, *agentv1.InstallationBanReceipt) (InstallationBanPublication, error)
}

type InstallationBanSubscription interface {
	Next(context.Context) (InstallationBanDelivery, error)
	Close() error
}

type InstallationBanDelivery interface {
	Command() *agentv1.InstallationBanCommand
	Ack(context.Context) error
	Nak(context.Context) error
}

func (g *Gateway) ConfigureInstallationBan(bus InstallationBanBus) error {
	if g == nil || bus == nil || g.installationBan != nil {
		return fmt.Errorf("installation ban bus is invalid or already configured")
	}
	g.installationBan = bus
	return nil
}

func installationBanCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET {
			continue
		}
		if seen || capability.ApiVersion != installationBanAPIVersion {
			return false, fmt.Errorf("installation ban capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

type installationBanReceive struct {
	delivery InstallationBanDelivery
	err      error
}

// sessionInstallationBan is the installation ban state of one Connect session.
type sessionInstallationBan struct {
	ctx            context.Context
	cancel         context.CancelFunc
	subscription   InstallationBanSubscription
	next           chan installationBanReceive
	pending        InstallationBanDelivery
	pendingCommand *agentv1.InstallationBanCommand
}

func (g *Gateway) startSessionInstallationBan(ctx context.Context, nodeID string) (*sessionInstallationBan, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := g.installationBan.SubscribeInstallationBan(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, status.Error(codes.Unavailable, "could not subscribe to installation ban commands")
	}
	return &sessionInstallationBan{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

// receive returns the channel to select on, or nil while a bundle is awaiting its receipt.
func (session *sessionInstallationBan) receive() <-chan installationBanReceive {
	if session == nil || session.pending != nil {
		return nil
	}
	if session.next == nil {
		next := make(chan installationBanReceive, 1)
		session.next = next
		go func() {
			delivery, err := session.subscription.Next(session.ctx)
			next <- installationBanReceive{delivery: delivery, err: err}
		}()
	}
	return session.next
}

// stop returns any in-flight bundle for redelivery and closes the subscription.
func (session *sessionInstallationBan) stop(timeout time.Duration) {
	if session == nil {
		return
	}
	if session.pending != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_ = session.pending.Nak(ctx)
		cancel()
		session.pending, session.pendingCommand = nil, nil
	}
	session.cancel()
	_ = session.subscription.Close()
	if session.next != nil {
		select {
		case received := <-session.next:
			if received.delivery != nil {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				_ = received.delivery.Nak(ctx)
				cancel()
			}
		case <-time.After(timeout):
		}
	}
}

func validateInstallationBanCommand(command *agentv1.InstallationBanCommand, nodeID string) error {
	if command == nil || proto.Size(command) > contract.MaxCarrierBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) ||
		command.NodeId != nodeID || command.Revision == 0 || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) || !canonicalUUID(command.Event.RequestId) ||
		command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil ||
		(len(command.NoticeJson) == 0 && len(command.TicketJson) == 0) ||
		!boundDocument(command.NoticeJson, command.NoticeSha256) || !boundDocument(command.TicketJson, command.TicketSha256) {
		return fmt.Errorf("installation ban command is invalid")
	}
	return nil
}

// boundDocument: absent (both empty) or the digest of the exact bytes.
func boundDocument(document, digest []byte) bool {
	if len(document) == 0 {
		return len(digest) == 0
	}
	sum := sha256.Sum256(document)
	return len(document) <= contract.MaxDocumentBytes && bytes.Equal(sum[:], digest)
}

func validateInstallationBanReceipt(receipt *agentv1.InstallationBanReceipt, command *agentv1.InstallationBanCommand, nodeID string) error {
	if receipt == nil || command == nil || proto.Size(receipt) > contract.MaxCarrierBytes ||
		cacheControlMessageHasUnknown(receipt.ProtoReflect()) || receipt.NodeId != nodeID ||
		receipt.CommandEventId != command.Event.GetEventId() || receipt.Revision != command.Revision ||
		!contract.Statuses[receipt.Status] || len(receipt.Reason) > contract.MaxReasonBytes || receipt.Event == nil ||
		!canonicalUUID(receipt.Event.EventId) || !canonicalUUID(receipt.Event.RequestId) ||
		receipt.Event.OccurredTime == nil || receipt.Event.OccurredTime.CheckValid() != nil ||
		!validInstallationBanTicketTimes(receipt) {
		return fmt.Errorf("installation ban receipt is invalid")
	}
	return nil
}

// validInstallationBanTicketTimes: the held ticket's times (PF09) are both
// unset (no ticket yet) or both valid with not_after after issued.
func validInstallationBanTicketTimes(receipt *agentv1.InstallationBanReceipt) bool {
	issued, notAfter := receipt.TicketIssuedTime, receipt.TicketNotAfterTime
	if issued == nil || notAfter == nil {
		return issued == nil && notAfter == nil
	}
	return issued.CheckValid() == nil && notAfter.CheckValid() == nil && notAfter.AsTime().After(issued.AsTime())
}

// settleInstallationBanReceipt publishes a validated receipt and only then acknowledges the bundle delivery.
func (g *Gateway) settleInstallationBanReceipt(ctx context.Context, session *sessionInstallationBan, nodeID string,
	receipt *agentv1.InstallationBanReceipt,
) error {
	if err := validateInstallationBanReceipt(receipt, session.pendingCommand, nodeID); err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	defer cancel()
	publication, err := g.installationBan.PublishInstallationBanReceipt(operationCtx, nodeID, proto.Clone(receipt).(*agentv1.InstallationBanReceipt))
	if err != nil || publication.Stream != contract.StatusStream || publication.Sequence == 0 {
		return status.Error(codes.Unavailable, "installation ban receipt could not be published")
	}
	if err := session.pending.Ack(operationCtx); err != nil {
		return status.Error(codes.Unavailable, "installation ban command disposition failed")
	}
	session.pending, session.pendingCommand = nil, nil
	return nil
}
