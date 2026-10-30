package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/gatewayaddr"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Gateway address change delivery (fix-nodegw, CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE
// v1, ConnectResponse 31 / ConnectRequest 28). control-api publishes one
// signed document per node; the command stream keeps the newest per node and
// every session starts from it, so the node that switched gets it again on
// the new address and answers SWITCHED there. The gateway binds the carrier
// (node, revision, digest) and relays receipts (probing, then the outcome);
// it never verifies the signature. A node without the capability is answered
// not_supported by the gateway.

const gatewayAddressAPIVersion = 1

type GatewayAddressPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

// GatewayAddressBus is the gateway side of the address change streams.
type GatewayAddressBus interface {
	SubscribeGatewayAddressChanges(context.Context, string) (GatewayAddressSubscription, error)
	PublishGatewayAddressReceipt(context.Context, string, *agentv1.GatewayAddressChangeReceipt) (GatewayAddressPublication, error)
}

// GatewayAddressSubscription yields the node's current document first, then newer ones.
type GatewayAddressSubscription interface {
	Next(context.Context) (*agentv1.GatewayAddressChangeCommand, error)
	Close() error
}

// ConfigureGatewayAddressChanges enables address change delivery.
func (g *Gateway) ConfigureGatewayAddressChanges(bus GatewayAddressBus) error {
	if g == nil || bus == nil || g.gatewayAddresses != nil {
		return fmt.Errorf("gateway address bus is invalid or already configured")
	}
	g.gatewayAddresses = bus
	return nil
}

func gatewayAddressCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE {
			continue
		}
		if seen || capability.ApiVersion != gatewayAddressAPIVersion {
			return false, fmt.Errorf("gateway address change capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

type gatewayAddressReceive struct {
	command *agentv1.GatewayAddressChangeCommand
	err     error
}

type sessionGatewayAddresses struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription GatewayAddressSubscription
	next         chan gatewayAddressReceive
	pending      *agentv1.GatewayAddressChangeCommand
}

func (g *Gateway) startSessionGatewayAddresses(ctx context.Context, nodeID string) (*sessionGatewayAddresses, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := g.gatewayAddresses.SubscribeGatewayAddressChanges(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, status.Error(codes.Unavailable, "could not subscribe to gateway address changes")
	}
	return &sessionGatewayAddresses{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

// receive is nil while a document waits for its final receipt (one in flight).
func (session *sessionGatewayAddresses) receive() <-chan gatewayAddressReceive {
	if session == nil || session.pending != nil {
		return nil
	}
	if session.next == nil {
		next := make(chan gatewayAddressReceive, 1)
		session.next = next
		go func() {
			command, err := session.subscription.Next(session.ctx)
			next <- gatewayAddressReceive{command: command, err: err}
		}()
	}
	return session.next
}

func (session *sessionGatewayAddresses) stop() {
	if session == nil {
		return
	}
	session.cancel()
	_ = session.subscription.Close()
}

func validateGatewayAddressCommand(command *agentv1.GatewayAddressChangeCommand, nodeID string) error {
	if command == nil || proto.Size(command) > gatewayaddr.MaxCarrierBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) ||
		command.NodeId != nodeID || command.Revision == 0 || len(command.DocumentSha256) != sha256.Size || command.Event == nil ||
		command.Event.OccurredTime == nil || !validEventMetadata(command.Event, command.Event.OccurredTime) {
		return fmt.Errorf("gateway address change command is invalid")
	}
	digest := sha256.Sum256(command.DocumentJson)
	routeNode, routeRevision, err := gatewayaddr.Route(command.DocumentJson)
	if !bytes.Equal(digest[:], command.DocumentSha256) || err != nil || routeNode != nodeID || routeRevision != command.Revision {
		return fmt.Errorf("gateway address change command binding is invalid")
	}
	return nil
}

var gatewayAddressReceiptStates = map[string]bool{gatewayaddr.StateProbing: true, gatewayaddr.StateSwitched: true, gatewayaddr.StateFailed: true}

func validateGatewayAddressReceipt(receipt *agentv1.GatewayAddressChangeReceipt, command *agentv1.GatewayAddressChangeCommand, nodeID string) error {
	if receipt == nil || command == nil || proto.Size(receipt) > gatewayaddr.MaxCarrierBytes ||
		cacheControlMessageHasUnknown(receipt.ProtoReflect()) || receipt.NodeId != nodeID ||
		receipt.CommandEventId != command.Event.GetEventId() || receipt.Revision != command.Revision ||
		!bytes.Equal(receipt.DocumentSha256, command.DocumentSha256) || receipt.Event == nil || receipt.Event.OccurredTime == nil ||
		!validEventMetadata(receipt.Event, receipt.Event.OccurredTime) || !gatewayAddressReceiptStates[receipt.State] ||
		(receipt.State == gatewayaddr.StateFailed) != (receipt.ErrorCode != "") || len(receipt.ErrorCode) > 64 ||
		len(receipt.ActiveAddress) > 255 || len(receipt.ActiveServerName) > 253 {
		return fmt.Errorf("gateway address change receipt is invalid")
	}
	return nil
}

// notSupportedGatewayAddressReceipt answers a document for a node that did
// not declare GATEWAY_ADDRESS_CHANGE v1 (identity follows the command's).
func notSupportedGatewayAddressReceipt(command *agentv1.GatewayAddressChangeCommand, now time.Time) *agentv1.GatewayAddressChangeReceipt {
	namespace := uuid.MustParse(command.NodeId)
	return &agentv1.GatewayAddressChangeReceipt{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("gateway-address-not-supported/"+command.Event.EventId)).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("gateway-address-not-supported-request/"+command.Event.EventId)).String(),
			OccurredTime: timestamppb.New(now.UTC()),
		},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Revision: command.Revision,
		DocumentSha256: append([]byte(nil), command.DocumentSha256...), State: gatewayaddr.StateFailed,
		ErrorCode: gatewayaddr.ErrorNotSupported,
	}
}

func (g *Gateway) publishGatewayAddressReceipt(ctx context.Context, nodeID string, receipt *agentv1.GatewayAddressChangeReceipt) error {
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	defer cancel()
	publication, err := g.gatewayAddresses.PublishGatewayAddressReceipt(operationCtx, nodeID, proto.Clone(receipt).(*agentv1.GatewayAddressChangeReceipt))
	if err != nil || publication.Sequence == 0 {
		return status.Error(codes.Unavailable, "gateway address change receipt could not be published")
	}
	return nil
}

// settleGatewayAddressReceipt publishes a receipt; the document stays pending
// until a final (switched / failed) one.
func (g *Gateway) settleGatewayAddressReceipt(ctx context.Context, session *sessionGatewayAddresses, nodeID string,
	receipt *agentv1.GatewayAddressChangeReceipt,
) error {
	if err := validateGatewayAddressReceipt(receipt, session.pending, nodeID); err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if err := g.publishGatewayAddressReceipt(ctx, nodeID, receipt); err != nil {
		return err
	}
	if receipt.State != gatewayaddr.StateProbing {
		session.pending = nil
	}
	return nil
}
