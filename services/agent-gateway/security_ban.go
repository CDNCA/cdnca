package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Security ban list delivery (ConnectResponse 25 /
// ConnectRequest 22): control-api publishes one signed snapshot per node,
// the gateway binds the carrier to the snapshot (node, revision, digest) and
// relays it; the node's SecurityBanStatus is published back before the
// snapshot's delivery is acknowledged. No capability of its own: a node that
// declares CAPABILITY_NAME_WAF v2 (WAF challenge / ban actions) applies ban
// lists. The gateway never verifies the signature (the Agent does).

// securityBanWAFVersion is the WAF API version that carries ban lists.
const securityBanWAFVersion = 2

type SecurityBanPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

// SecurityBanBus is the gateway side of the ban list streams.
type SecurityBanBus interface {
	SubscribeSecurityBans(context.Context, string) (SecurityBanSubscription, error)
	PublishSecurityBanStatus(context.Context, string, *agentv1.SecurityBanStatus) (SecurityBanPublication, error)
}

type SecurityBanSubscription interface {
	Next(context.Context) (SecurityBanDelivery, error)
	Close() error
}

type SecurityBanDelivery interface {
	Command() *agentv1.SecurityBanCommand
	Ack(context.Context) error
	Nak(context.Context) error
}

// ConfigureSecurityBans enables ban list delivery.
func (g *Gateway) ConfigureSecurityBans(bus SecurityBanBus) error {
	if g == nil || bus == nil || g.securityBans != nil {
		return fmt.Errorf("security ban bus is invalid or already configured")
	}
	g.securityBans = bus
	return nil
}

// securityBanCapableFromFeatures: the agent declared WAF v2 or later.
func securityBanCapableFromFeatures(features []*agentv1.Capability) bool {
	for _, capability := range features {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_WAF &&
			capability.ApiVersion >= securityBanWAFVersion {
			return true
		}
	}
	return false
}

type securityBanReceive struct {
	delivery SecurityBanDelivery
	err      error
}

type sessionSecurityBans struct {
	ctx            context.Context
	cancel         context.CancelFunc
	subscription   SecurityBanSubscription
	next           chan securityBanReceive
	pending        SecurityBanDelivery
	pendingCommand *agentv1.SecurityBanCommand
}

func (g *Gateway) startSessionSecurityBans(ctx context.Context, nodeID string) (*sessionSecurityBans, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := g.securityBans.SubscribeSecurityBans(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, status.Error(codes.Unavailable, "could not subscribe to security ban lists")
	}
	return &sessionSecurityBans{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

// receive is nil while a snapshot waits for its status (one in flight).
func (session *sessionSecurityBans) receive() <-chan securityBanReceive {
	if session == nil || session.pending != nil {
		return nil
	}
	if session.next == nil {
		next := make(chan securityBanReceive, 1)
		session.next = next
		go func() {
			delivery, err := session.subscription.Next(session.ctx)
			next <- securityBanReceive{delivery: delivery, err: err}
		}()
	}
	return session.next
}

func (session *sessionSecurityBans) stop(timeout time.Duration) {
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

func validEventMetadata(event interface {
	GetEventId() string
	GetRequestId() string
}, occurred interface{ CheckValid() error }) bool {
	return canonicalUUID(event.GetEventId()) && canonicalUUID(event.GetRequestId()) && occurred != nil && occurred.CheckValid() == nil
}

func validateSecurityBanCommand(command *agentv1.SecurityBanCommand, nodeID string) error {
	if command == nil || proto.Size(command) > securityban.MaxCarrierBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) ||
		command.NodeId != nodeID || command.Revision == 0 || len(command.ListSha256) != sha256.Size || command.Event == nil ||
		command.Event.OccurredTime == nil || !validEventMetadata(command.Event, command.Event.OccurredTime) {
		return fmt.Errorf("security ban command is invalid")
	}
	digest := sha256.Sum256(command.ListJson)
	routeNode, routeRevision, err := securityban.Route(command.ListJson)
	if !bytes.Equal(digest[:], command.ListSha256) || err != nil || routeNode != nodeID || routeRevision != command.Revision {
		return fmt.Errorf("security ban command binding is invalid")
	}
	return nil
}

func validateSecurityBanStatus(report *agentv1.SecurityBanStatus, command *agentv1.SecurityBanCommand, nodeID string) error {
	if report == nil || command == nil || proto.Size(report) > 4096 || cacheControlMessageHasUnknown(report.ProtoReflect()) ||
		report.NodeId != nodeID || report.CommandEventId != command.Event.GetEventId() || report.Revision != command.Revision ||
		!bytes.Equal(report.ListSha256, command.ListSha256) || report.Event == nil || report.Event.OccurredTime == nil ||
		!validEventMetadata(report.Event, report.Event.OccurredTime) || report.Applied != (report.ErrorCode == "") ||
		len(report.ErrorCode) > 64 {
		return fmt.Errorf("security ban status is invalid")
	}
	return nil
}

func (g *Gateway) settleSecurityBanStatus(ctx context.Context, session *sessionSecurityBans, nodeID string,
	report *agentv1.SecurityBanStatus,
) error {
	if err := validateSecurityBanStatus(report, session.pendingCommand, nodeID); err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	defer cancel()
	publication, err := g.securityBans.PublishSecurityBanStatus(operationCtx, nodeID, proto.Clone(report).(*agentv1.SecurityBanStatus))
	if err != nil || publication.Stream != securityban.StatusStream || publication.Sequence == 0 {
		return status.Error(codes.Unavailable, "security ban status could not be published")
	}
	if err := session.pending.Ack(operationCtx); err != nil {
		return status.Error(codes.Unavailable, "security ban command disposition failed")
	}
	session.pending, session.pendingCommand = nil, nil
	return nil
}
