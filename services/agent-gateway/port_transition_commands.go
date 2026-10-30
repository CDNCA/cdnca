package gateway

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const gatewayPortTransitionAPIVersion uint32 = 1

type PortTransitionCommandBus interface {
	SubscribePortTransitions(context.Context, string) (PortTransitionCommandSubscription, error)
	PublishPortTransitionStatus(context.Context, string, *agentv1.GatewayPortTransitionStatus) (PortTransitionStatusPublication, error)
}

type PortTransitionCommandSubscription interface {
	Next(context.Context) (PortTransitionCommandDelivery, error)
	Close() error
}

type PortTransitionCommandDelivery interface {
	Command() *agentv1.GatewayPortTransitionCommand
	Ack(context.Context) error
	Retry(context.Context, time.Duration) error
}

type PortTransitionStatusPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}
type portTransitionReceive struct {
	delivery PortTransitionCommandDelivery
	err      error
}
type sessionPortTransitionSource struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription PortTransitionCommandSubscription
	next         <-chan portTransitionReceive
}
type pendingPortTransition struct {
	command    *agentv1.GatewayPortTransitionCommand
	deliveries []PortTransitionCommandDelivery
}
type pendingPortTransitionSet map[string]*pendingPortTransition

func (p pendingPortTransitionSet) deliveryCount() int {
	count := 0
	for _, item := range p {
		count += len(item.deliveries)
	}
	return count
}

func newSessionPortTransitionSource(ctx context.Context, bus PortTransitionCommandBus, nodeID string) (*sessionPortTransitionSource, error) {
	sourceCtx, cancel := context.WithCancel(ctx)
	subscription, err := bus.SubscribePortTransitions(sourceCtx, nodeID)
	if err != nil {
		cancel()
		return nil, err
	}
	return &sessionPortTransitionSource{ctx: sourceCtx, cancel: cancel, subscription: subscription}, nil
}

func (s *sessionPortTransitionSource) arm() {
	if s == nil || s.next != nil {
		return
	}
	next := make(chan portTransitionReceive, 1)
	s.next = next
	go func() {
		delivery, err := s.subscription.Next(s.ctx)
		next <- portTransitionReceive{delivery: delivery, err: err}
	}()
}

func stopSessionPortTransitions(source *sessionPortTransitionSource, pending pendingPortTransitionSet, timeout time.Duration) {
	for key, item := range pending {
		for _, delivery := range item.deliveries {
			retryPortTransition(delivery, timeout, time.Second)
		}
		delete(pending, key)
	}
	if source == nil {
		return
	}
	source.cancel()
	_ = source.subscription.Close()
	if source.next == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case received := <-source.next:
		retryPortTransition(received.delivery, timeout, time.Second)
	case <-timer.C:
	}
}

func retryPortTransition(delivery PortTransitionCommandDelivery, timeout, delay time.Duration) {
	if delivery == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = delivery.Retry(ctx, delay)
}

func gatewayPortTransitionCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	found := false
	for _, capability := range features {
		if capability.GetName() != agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION {
			continue
		}
		if found || capability.GetApiVersion() != gatewayPortTransitionAPIVersion {
			return false, fmt.Errorf("gateway port transition capability is duplicated or unsupported")
		}
		found = true
	}
	return found, nil
}

func validatePortTransitionProof(proof *agentv1.GatewayPortTransitionProof) error {
	if proof == nil {
		return nil
	}
	if !canonicalUUID(proof.TransitionId) || proof.Revision == 0 || !validGatewayEndpoint(proof.ActiveEndpoint, false) ||
		proof.ActiveEndpoint.ListenAddress != "" || cacheControlMessageHasUnknown(proof.ProtoReflect()) {
		return ErrPortTransitionInvalid
	}
	return nil
}

func validatePortTransitionStatus(value *agentv1.GatewayPortTransitionStatus, command *agentv1.GatewayPortTransitionCommand, nodeID, certificateSHA string) error {
	if value == nil || command == nil || value.Event == nil || !canonicalUUID(value.Event.EventId) ||
		value.Event.RequestId != command.GetEvent().GetRequestId() || value.Event.GetCausationId() != command.GetEvent().GetEventId() ||
		value.Schema != command.Schema || value.TransitionId != command.TransitionId || value.NodeId != nodeID || value.NodeId != command.NodeId ||
		value.Revision != command.Revision || value.StatusRevision == 0 || value.CertificateSha256 != certificateSHA ||
		!validGatewayEndpoint(value.ActiveEndpoint, false) || cacheControlMessageHasUnknown(value.ProtoReflect()) {
		return ErrPortTransitionInvalid
	}
	switch command.Action {
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH:
		switch value.State {
		case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED:
			if value.ActiveEndpoint.Address != command.NewEndpoint.Address || value.ErrorCode != "" {
				return ErrPortTransitionConflict
			}
		case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FAILED:
			if value.ActiveEndpoint.Address != command.OldEndpoint.Address || value.ErrorCode == "" {
				return ErrPortTransitionConflict
			}
		default:
			return ErrPortTransitionInvalid
		}
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE:
		if value.State != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FINALIZED ||
			value.ActiveEndpoint.Address != command.NewEndpoint.Address || value.ErrorCode != "" {
			return ErrPortTransitionConflict
		}
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK:
		if value.State != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_ROLLED_BACK ||
			value.ActiveEndpoint.Address != command.OldEndpoint.Address || value.ErrorCode == "" {
			return ErrPortTransitionConflict
		}
	default:
		return ErrPortTransitionInvalid
	}
	return nil
}

func (g *Gateway) persistPortTransitionStatus(ctx context.Context, nodeID, certificateSHA string, value *agentv1.GatewayPortTransitionStatus, pending pendingPortTransitionSet) error {
	item := pending[value.GetTransitionId()]
	if item == nil || validatePortTransitionStatus(value, item.command, nodeID, certificateSHA) != nil {
		return status.Error(codes.FailedPrecondition, "gateway port transition status conflicts with the in-flight command")
	}
	opCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	_, err := g.portTransitions.PublishPortTransitionStatus(opCtx, nodeID, value)
	cancel()
	if err != nil {
		return status.Error(codes.Unavailable, "gateway port transition status could not be persisted")
	}
	switch item.command.Action {
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE:
		if err := g.portManager.Finalize(item.command.TransitionId, []string{nodeID}); err != nil {
			return status.Error(codes.Unavailable, "gateway old listener could not be finalized")
		}
	case agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK:
		if err := g.portManager.Rollback(item.command.TransitionId); err != nil {
			return status.Error(codes.Unavailable, "gateway candidate listener could not be rolled back")
		}
	}
	for _, delivery := range item.deliveries {
		opCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		err = delivery.Ack(opCtx)
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "gateway port transition command acknowledgement could not be persisted")
		}
	}
	delete(pending, value.TransitionId)
	return nil
}

func certificateIdentityHex(identity nodeIdentity) string {
	return hex.EncodeToString(identity.CertificateSHA256[:])
}
