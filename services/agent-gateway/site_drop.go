package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Site drop list delivery (攻击自动升级 D 级, CAPABILITY_NAME_SITE_DROP v1,
// ConnectResponse 29 / ConnectRequest 26). control-api publishes one signed
// full snapshot per node (internal/escalate/sitedrop.go); the command stream
// keeps the newest snapshot per node, and every session starts from it, so a
// gateway restart or a reconnect hands the node the current list again.
// The gateway binds the carrier (node, revision, digest) and relays it; the
// node's SiteDropReceipt is published back. A node that did not declare the
// capability gets nothing: the gateway answers not_supported in its place so
// control-api can mark it. The gateway never verifies the signature.

const siteDropAPIVersion = 1

type SiteDropPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

// SiteDropBus is the gateway side of the site drop streams.
type SiteDropBus interface {
	SubscribeSiteDrops(context.Context, string) (SiteDropSubscription, error)
	PublishSiteDropReceipt(context.Context, string, *agentv1.SiteDropReceipt) (SiteDropPublication, error)
}

// SiteDropSubscription yields the node's current snapshot first, then newer ones.
type SiteDropSubscription interface {
	Next(context.Context) (*agentv1.SiteDropCommand, error)
	Close() error
}

// ConfigureSiteDrops enables site drop list delivery.
func (g *Gateway) ConfigureSiteDrops(bus SiteDropBus) error {
	if g == nil || bus == nil || g.siteDrops != nil {
		return fmt.Errorf("site drop bus is invalid or already configured")
	}
	g.siteDrops = bus
	return nil
}

func siteDropCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP {
			continue
		}
		if seen || capability.ApiVersion != siteDropAPIVersion {
			return false, fmt.Errorf("site drop capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

type siteDropReceive struct {
	command *agentv1.SiteDropCommand
	err     error
}

type sessionSiteDrops struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription SiteDropSubscription
	next         chan siteDropReceive
	pending      *agentv1.SiteDropCommand
}

func (g *Gateway) startSessionSiteDrops(ctx context.Context, nodeID string) (*sessionSiteDrops, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := g.siteDrops.SubscribeSiteDrops(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, status.Error(codes.Unavailable, "could not subscribe to site drop lists")
	}
	return &sessionSiteDrops{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

// receive is nil while a snapshot waits for its receipt (one in flight).
func (session *sessionSiteDrops) receive() <-chan siteDropReceive {
	if session == nil || session.pending != nil {
		return nil
	}
	if session.next == nil {
		next := make(chan siteDropReceive, 1)
		session.next = next
		go func() {
			command, err := session.subscription.Next(session.ctx)
			next <- siteDropReceive{command: command, err: err}
		}()
	}
	return session.next
}

// stop needs no disposition: nothing is acknowledged, the next session
// starts again from the node's newest snapshot.
func (session *sessionSiteDrops) stop() {
	if session == nil {
		return
	}
	session.cancel()
	_ = session.subscription.Close()
}

func validateSiteDropCommand(command *agentv1.SiteDropCommand, nodeID string) error {
	if command == nil || proto.Size(command) > sitedrop.MaxCarrierBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) ||
		command.NodeId != nodeID || command.Revision == 0 || len(command.ListSha256) != sha256.Size || command.Event == nil ||
		command.Event.OccurredTime == nil || !validEventMetadata(command.Event, command.Event.OccurredTime) {
		return fmt.Errorf("site drop command is invalid")
	}
	digest := sha256.Sum256(command.ListJson)
	routeNode, routeRevision, err := sitedrop.Route(command.ListJson)
	if !bytes.Equal(digest[:], command.ListSha256) || err != nil || routeNode != nodeID || routeRevision != command.Revision {
		return fmt.Errorf("site drop command binding is invalid")
	}
	return nil
}

func validateSiteDropReceipt(receipt *agentv1.SiteDropReceipt, command *agentv1.SiteDropCommand, nodeID string) error {
	if receipt == nil || command == nil || proto.Size(receipt) > sitedrop.MaxCarrierBytes ||
		cacheControlMessageHasUnknown(receipt.ProtoReflect()) || receipt.NodeId != nodeID ||
		receipt.CommandEventId != command.Event.GetEventId() || receipt.Revision != command.Revision ||
		!bytes.Equal(receipt.ListSha256, command.ListSha256) || receipt.Event == nil || receipt.Event.OccurredTime == nil ||
		!validEventMetadata(receipt.Event, receipt.Event.OccurredTime) || receipt.Applied != (receipt.ErrorCode == "") ||
		len(receipt.ErrorCode) > 64 || len(receipt.Rejected) > sitedrop.MaxSites {
		return fmt.Errorf("site drop receipt is invalid")
	}
	return nil
}

// notSupportedSiteDropReceipt answers a snapshot for a node that did not
// declare SITE_DROP v1. The event identity follows the command's, so a
// republished snapshot is answered again and a replay is deduplicated.
func notSupportedSiteDropReceipt(command *agentv1.SiteDropCommand, now time.Time) *agentv1.SiteDropReceipt {
	namespace := uuid.MustParse(command.NodeId)
	return &agentv1.SiteDropReceipt{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("site-drop-not-supported/"+command.Event.EventId)).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("site-drop-not-supported-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Revision: command.Revision,
		ListSha256: append([]byte(nil), command.ListSha256...), ErrorCode: sitedrop.ErrorNotSupported,
	}
}

func (g *Gateway) publishSiteDropReceipt(ctx context.Context, nodeID string, receipt *agentv1.SiteDropReceipt) error {
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	defer cancel()
	publication, err := g.siteDrops.PublishSiteDropReceipt(operationCtx, nodeID, proto.Clone(receipt).(*agentv1.SiteDropReceipt))
	// The bus checks the acknowledgement names its configured receipt stream.
	if err != nil || publication.Sequence == 0 {
		return status.Error(codes.Unavailable, "site drop receipt could not be published")
	}
	return nil
}

func (g *Gateway) settleSiteDropReceipt(ctx context.Context, session *sessionSiteDrops, nodeID string,
	receipt *agentv1.SiteDropReceipt,
) error {
	if err := validateSiteDropReceipt(receipt, session.pending, nodeID); err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if err := g.publishSiteDropReceipt(ctx, nodeID, receipt); err != nil {
		return err
	}
	session.pending = nil
	return nil
}
