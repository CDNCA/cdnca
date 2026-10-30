package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const drainControlAPIVersion uint32 = 1

type DrainCommandBus interface {
	SubscribeDrain(context.Context, string) (DrainCommandSubscription, error)
	PublishDrainStatus(context.Context, string, *agentv1.DrainStatus) (DrainStatusPublication, error)
}

type DrainCommandSubscription interface {
	Next(context.Context) (DrainCommandDelivery, error)
	Close() error
}

type DrainCommandDelivery interface {
	Command() *agentv1.DrainCommand
	Ack(context.Context) error
	Retry(context.Context, time.Duration) error
}

type DrainStatusPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

type pendingDrainCommand struct {
	command    *agentv1.DrainCommand
	deliveries []DrainCommandDelivery
}

type pendingDrainCommandSet map[string]*pendingDrainCommand

func (p pendingDrainCommandSet) deliveryCount() int {
	count := 0
	for _, command := range p {
		count += len(command.deliveries)
	}
	return count
}

type drainCommandReceive struct {
	delivery DrainCommandDelivery
	err      error
}

type sessionDrainCommandSource struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription DrainCommandSubscription
	next         <-chan drainCommandReceive
}

func newSessionDrainCommandSource(ctx context.Context, bus DrainCommandBus, nodeID string) (*sessionDrainCommandSource, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := bus.SubscribeDrain(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, err
	}
	return &sessionDrainCommandSource{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (s *sessionDrainCommandSource) arm() {
	if s.next != nil {
		return
	}
	next := make(chan drainCommandReceive, 1)
	s.next = next
	go func() {
		delivery, err := s.subscription.Next(s.ctx)
		next <- drainCommandReceive{delivery: delivery, err: err}
	}()
}

func stopSessionDrainCommands(source *sessionDrainCommandSource, pending pendingDrainCommandSet, timeout time.Duration) {
	for key, command := range pending {
		for _, delivery := range command.deliveries {
			retryDrainCommand(delivery, timeout, time.Second)
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
		retryDrainCommand(received.delivery, timeout, time.Second)
	case <-timer.C:
	}
}

func retryDrainCommand(delivery DrainCommandDelivery, timeout, delay time.Duration) {
	if delivery == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = delivery.Retry(ctx, delay)
}

func validateDrainCommand(command *agentv1.DrainCommand, nodeID string, now time.Time) error {
	if command == nil || proto.Size(command) > 1<<20 || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) || !canonicalUUID(command.Event.RequestId) ||
		command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil ||
		!validFirewallMetadata(command.Event.Traceparent) || !validFirewallMetadata(command.Event.CorrelationId) ||
		command.Event.TaskId == nil || command.Event.GetTaskId() != command.CommandId ||
		command.Schema != agentv1.DrainSchema_DRAIN_SCHEMA_V1 || !canonicalUUID(command.CommandId) ||
		command.NodeId != nodeID || !canonicalUUID(command.NodeId) || command.Revision == 0 ||
		!validDrainPlanID(command.PlanId) || len(command.CanonicalPlanJson) == 0 || len(command.PlanSha256) != sha256.Size ||
		command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil || !command.DeadlineTime.AsTime().After(now) ||
		command.DeadlineTime.AsTime().After(now.Add(25*time.Hour)) || cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return fmt.Errorf("drain command identity, deadline, or fields are invalid")
	}
	digest := sha256.Sum256(command.CanonicalPlanJson)
	if !bytes.Equal(digest[:], command.PlanSha256) {
		return fmt.Errorf("drain command digest is invalid")
	}
	return nil
}

func validDrainPlanID(value string) bool {
	return value != "" && len(value) <= 64 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, `/\\`)
}

func validateDrainStatusForCommand(value *agentv1.DrainStatus, command *agentv1.DrainCommand) error {
	if value == nil || command == nil || proto.Size(value) > 1<<20 || value.Event == nil ||
		!canonicalUUID(value.Event.EventId) || value.Event.RequestId != command.Event.RequestId ||
		value.Event.OccurredTime == nil || value.Event.OccurredTime.CheckValid() != nil ||
		value.Event.GetCausationId() != command.Event.EventId || value.Event.GetTaskId() != command.CommandId ||
		value.Schema != command.Schema || value.CommandId != command.CommandId || value.NodeId != command.NodeId ||
		value.PlanId != command.PlanId || value.Revision != command.Revision || !bytes.Equal(value.PlanSha256, command.PlanSha256) ||
		value.StatusRevision == 0 || !validFirewallMetadata(value.ErrorCode) || cacheControlMessageHasUnknown(value.ProtoReflect()) {
		return fmt.Errorf("drain status is not bound to its command")
	}
	switch value.Phase {
	case agentv1.DrainPhase_DRAIN_PHASE_PRECHECK, agentv1.DrainPhase_DRAIN_PHASE_ACTIVATE_NEW,
		agentv1.DrainPhase_DRAIN_PHASE_HEALTH_GATE, agentv1.DrainPhase_DRAIN_PHASE_DRAINING_OLD:
		if !value.Pending {
			return fmt.Errorf("nonterminal drain status is not pending")
		}
	case agentv1.DrainPhase_DRAIN_PHASE_COMPLETED:
		if value.Pending || value.Degraded || value.ErrorCode != "" || value.RemainingOldWorkers != 0 {
			return fmt.Errorf("completed drain status is inconsistent")
		}
	case agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK, agentv1.DrainPhase_DRAIN_PHASE_FAILED:
		if value.Pending || !value.Degraded || value.ErrorCode == "" {
			return fmt.Errorf("terminal degraded drain status is inconsistent")
		}
	default:
		return fmt.Errorf("drain status phase is invalid")
	}
	return nil
}

func (g *Gateway) persistDrainStatusAndAdvance(ctx context.Context, nodeID string, value *agentv1.DrainStatus, pending pendingDrainCommandSet) error {
	command := pending[value.GetCommandId()]
	if command == nil || validateDrainStatusForCommand(value, command.command) != nil {
		return status.Error(codes.FailedPrecondition, "drain status conflicts with the in-flight command")
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	_, err := g.drain.PublishDrainStatus(operationCtx, nodeID, value)
	cancel()
	if err != nil {
		return status.Error(codes.Unavailable, "drain status could not be persisted")
	}
	terminal := value.Phase == agentv1.DrainPhase_DRAIN_PHASE_COMPLETED ||
		value.Phase == agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK || value.Phase == agentv1.DrainPhase_DRAIN_PHASE_FAILED
	for _, delivery := range command.deliveries {
		operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		if terminal {
			err = delivery.Ack(operationCtx)
		} else {
			err = delivery.Retry(operationCtx, time.Second)
		}
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "drain command acknowledgement could not be persisted")
		}
	}
	delete(pending, value.CommandId)
	return nil
}

func (g *Gateway) applyDrainAuthorization(ctx context.Context, nodeID string, source *sessionDrainCommandSource,
	pending pendingDrainCommandSet, wasAllowed, isAllowed bool,
) (*sessionDrainCommandSource, error) {
	if g.drain == nil || wasAllowed == isAllowed {
		return source, nil
	}
	if !isAllowed {
		stopSessionDrainCommands(source, pending, g.config.CommandOperationTimeout)
		return nil, nil
	}
	created, err := newSessionDrainCommandSource(ctx, g.drain, nodeID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not subscribe to node drain commands")
	}
	return created, nil
}

func drainControlCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	found := false
	for _, capability := range features {
		if capability.GetName() != agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL {
			continue
		}
		if found || capability.GetApiVersion() != drainControlAPIVersion {
			return false, fmt.Errorf("drain control capability is duplicated or unsupported")
		}
		found = true
	}
	return found, nil
}
