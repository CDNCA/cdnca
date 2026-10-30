package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/signertrust"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const signerTrustAPIVersion = signertrust.APIVersion

// Node signer trust bundles (CAPABILITY_NAME_EDGE_SIGNER_TRUST v1) follow the node monitoring delivery pattern: one
// durable pull consumer per node, at most one bundle in flight per session, and the delivery is acknowledged only
// after the Agent's receipt is durably published. Every receipt settles the delivery; control-api republishes until
// the node reports it enforces the latest revision. Delivery does not depend on the
// authorization snapshot allowing deployments: a revocation must reach a node whose deployments are paused.

type SignerTrustPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

type SignerTrustBus interface {
	SubscribeSignerTrust(context.Context, string) (SignerTrustSubscription, error)
	PublishSignerTrustReceipt(context.Context, string, *agentv1.EdgeSignerTrustReceipt) (SignerTrustPublication, error)
}

type SignerTrustSubscription interface {
	Next(context.Context) (SignerTrustDelivery, error)
	Close() error
}

type SignerTrustDelivery interface {
	Bundle() *agentv1.EdgeSignerTrustBundle
	Ack(context.Context) error
	Nak(context.Context) error
}

func (g *Gateway) ConfigureSignerTrust(bus SignerTrustBus) error {
	if g == nil || bus == nil || g.signerTrust != nil {
		return fmt.Errorf("signer trust bus is invalid or already configured")
	}
	g.signerTrust = bus
	return nil
}

func signerTrustCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST {
			continue
		}
		if seen || capability.ApiVersion != signerTrustAPIVersion {
			return false, fmt.Errorf("edge signer trust capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

type signerTrustReceive struct {
	delivery SignerTrustDelivery
	err      error
}

// sessionSignerTrust is the signer trust state of one Connect session.
type sessionSignerTrust struct {
	ctx           context.Context
	cancel        context.CancelFunc
	subscription  SignerTrustSubscription
	next          chan signerTrustReceive
	pending       SignerTrustDelivery
	pendingBundle *agentv1.EdgeSignerTrustBundle
}

func (g *Gateway) startSessionSignerTrust(ctx context.Context, nodeID string) (*sessionSignerTrust, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := g.signerTrust.SubscribeSignerTrust(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, status.Error(codes.Unavailable, "could not subscribe to edge signer trust bundles")
	}
	return &sessionSignerTrust{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

// receive returns the channel to select on, or nil while a bundle is awaiting its receipt.
func (session *sessionSignerTrust) receive() <-chan signerTrustReceive {
	if session == nil || session.pending != nil {
		return nil
	}
	if session.next == nil {
		next := make(chan signerTrustReceive, 1)
		session.next = next
		go func() {
			delivery, err := session.subscription.Next(session.ctx)
			next <- signerTrustReceive{delivery: delivery, err: err}
		}()
	}
	return session.next
}

// stop returns any in-flight bundle for redelivery and closes the subscription.
func (session *sessionSignerTrust) stop(timeout time.Duration) {
	if session == nil {
		return
	}
	if session.pending != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_ = session.pending.Nak(ctx)
		cancel()
		session.pending, session.pendingBundle = nil, nil
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

func validateSignerTrustBundle(bundle *agentv1.EdgeSignerTrustBundle, nodeID string) error {
	if bundle == nil || proto.Size(bundle) > signertrust.MaxCarrierBytes || cacheControlMessageHasUnknown(bundle.ProtoReflect()) ||
		bundle.Schema != agentv1.EdgeSignerTrustSchema_EDGE_SIGNER_TRUST_SCHEMA_V1 || bundle.NodeId != nodeID ||
		bundle.Revision == 0 || len(bundle.BundleSha256) != sha256.Size || bundle.Event == nil ||
		!canonicalUUID(bundle.Event.EventId) || !canonicalUUID(bundle.Event.RequestId) ||
		bundle.Event.OccurredTime == nil || bundle.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("edge signer trust bundle is invalid")
	}
	digest := sha256.Sum256(bundle.BundleJson)
	route, err := signertrust.RouteBundle(bundle.BundleJson)
	if !bytes.Equal(digest[:], bundle.BundleSha256) || err != nil || route.NodeID != nodeID || route.Revision != bundle.Revision {
		return fmt.Errorf("edge signer trust bundle binding is invalid")
	}
	return nil
}

func validateSignerTrustReceipt(receipt *agentv1.EdgeSignerTrustReceipt, bundle *agentv1.EdgeSignerTrustBundle, nodeID string) error {
	if receipt == nil || bundle == nil || proto.Size(receipt) > signertrust.MaxCarrierBytes ||
		cacheControlMessageHasUnknown(receipt.ProtoReflect()) ||
		receipt.Schema != agentv1.EdgeSignerTrustSchema_EDGE_SIGNER_TRUST_SCHEMA_V1 || receipt.NodeId != nodeID ||
		receipt.BundleEventId != bundle.Event.GetEventId() || receipt.Revision != bundle.Revision ||
		!bytes.Equal(receipt.BundleSha256, bundle.BundleSha256) || receipt.Event == nil ||
		!canonicalUUID(receipt.Event.EventId) || !canonicalUUID(receipt.Event.RequestId) ||
		receipt.Event.OccurredTime == nil || receipt.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("edge signer trust receipt is invalid")
	}
	// The body's revision is what the node enforces afterwards (lower than the bundle's when it was rejected).
	body, err := signertrust.RouteReceipt(receipt.ReceiptJson)
	if err != nil || body.NodeID != nodeID || body.BundleSHA256 != hex.EncodeToString(bundle.BundleSha256) {
		return fmt.Errorf("edge signer trust receipt binding is invalid")
	}
	return nil
}

// settleSignerTrustReceipt publishes a validated receipt and only then acknowledges the bundle delivery.
func (g *Gateway) settleSignerTrustReceipt(ctx context.Context, session *sessionSignerTrust, nodeID string,
	receipt *agentv1.EdgeSignerTrustReceipt,
) error {
	if err := validateSignerTrustReceipt(receipt, session.pendingBundle, nodeID); err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	defer cancel()
	publication, err := g.signerTrust.PublishSignerTrustReceipt(operationCtx, nodeID, proto.Clone(receipt).(*agentv1.EdgeSignerTrustReceipt))
	if err != nil || publication.Stream != signertrust.StatusStream || publication.Sequence == 0 {
		return status.Error(codes.Unavailable, "edge signer trust receipt could not be published")
	}
	if err := session.pending.Ack(operationCtx); err != nil {
		return status.Error(codes.Unavailable, "edge signer trust bundle disposition failed")
	}
	session.pending, session.pendingBundle = nil, nil
	return nil
}
