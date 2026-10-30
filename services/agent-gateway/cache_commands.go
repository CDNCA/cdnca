package gateway

import (
	"bytes"
	"context"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CacheCommandBus interface {
	SubscribeCache(context.Context, string) (CacheCommandSubscription, error)
	PublishCacheStatus(context.Context, string, *agentv1.CacheControlStatus) error
	// PublishCacheCancelReceipt carries a node's CacheControlCancelReceipt
	// on the cache status subject (header CacheMessageKindHeader=cancel-receipt).
	PublishCacheCancelReceipt(context.Context, string, *agentv1.CacheControlCancelReceipt) error
}

type CacheCommandSubscription interface {
	Next(context.Context) (CacheCommandDelivery, error)
	Close() error
}

// CacheCommandDelivery is one message of the node's cache command subject:
// a command, or (CACHE-ADD-07, header CacheMessageKindHeader=cancel) a
// cancel of a delivered command. Exactly one of Command and Cancel is set.
type CacheCommandDelivery interface {
	Command() *agentv1.CacheControlCommand
	Cancel() *agentv1.CacheControlCancel
	Ack(context.Context) error
	Nak(context.Context) error
}

type cacheCommandKey struct {
	taskID  string
	leaseID string
	attempt uint32
}

type pendingCacheCommand struct {
	command    *agentv1.CacheControlCommand
	deliveries []CacheCommandDelivery
}

type pendingCacheCommandSet map[cacheCommandKey]*pendingCacheCommand

func (p pendingCacheCommandSet) deliveryCount() int {
	count := 0
	for _, command := range p {
		count += len(command.deliveries)
	}
	return count
}

type cacheCommandReceive struct {
	delivery CacheCommandDelivery
	err      error
}

type sessionCacheCommandSource struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription CacheCommandSubscription
	next         <-chan cacheCommandReceive
}

func newSessionCacheCommandSource(ctx context.Context, bus CacheCommandBus, nodeID string) (*sessionCacheCommandSource, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := bus.SubscribeCache(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, err
	}
	return &sessionCacheCommandSource{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (s *sessionCacheCommandSource) arm() {
	if s.next != nil {
		return
	}
	next := make(chan cacheCommandReceive, 1)
	s.next = next
	go func() {
		delivery, err := s.subscription.Next(s.ctx)
		next <- cacheCommandReceive{delivery: delivery, err: err}
	}()
}

func stopSessionCacheCommands(source *sessionCacheCommandSource, pending pendingCacheCommandSet, timeout time.Duration) {
	for key, command := range pending {
		for _, delivery := range command.deliveries {
			nakCacheCommand(delivery, timeout)
		}
		delete(pending, key)
	}
	if source == nil {
		return
	}
	source.cancel()
	_ = source.subscription.Close()
	if source.next != nil {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case result := <-source.next:
			nakCacheCommand(result.delivery, timeout)
		case <-timer.C:
		}
	}
}

func nakCacheCommand(delivery CacheCommandDelivery, timeout time.Duration) {
	if delivery == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = delivery.Nak(ctx)
}

func cacheCommandIdentity(command *agentv1.CacheControlCommand) cacheCommandKey {
	return cacheCommandKey{taskID: command.GetTaskId(), leaseID: command.GetLeaseId(), attempt: command.GetAttempt()}
}

func cacheStatusIdentity(status *agentv1.CacheControlStatus) cacheCommandKey {
	return cacheCommandKey{taskID: status.GetTaskId(), leaseID: status.GetLeaseId(), attempt: status.GetAttempt()}
}

func cacheStatusMatchesCommand(status *agentv1.CacheControlStatus, command *agentv1.CacheControlCommand) bool {
	if status == nil || command == nil || status.Event == nil || command.Event == nil ||
		status.ScopeId != command.ScopeId || status.SiteId != command.SiteId || status.NodeId != command.NodeId ||
		status.TenantId != command.TenantId ||
		status.ControlOperationId != command.ControlOperationId || status.ConfigVersionId != command.ConfigVersionId ||
		status.ConfigRevision != command.ConfigRevision || status.Action != command.Action || status.Scope != command.Scope ||
		!bytes.Equal(status.RequestDigest, command.RequestDigest) || status.Event.CausationId == nil ||
		status.Event.GetCausationId() != command.Event.EventId || status.Event.RequestId != command.Event.RequestId ||
		status.Event.Traceparent != command.Event.Traceparent || status.Event.CorrelationId != command.Event.CorrelationId {
		return false
	}
	if (status.Event.TaskId == nil) != (command.Event.TaskId == nil) {
		return false
	}
	if status.Event.TaskId != nil && status.Event.GetTaskId() != command.Event.GetTaskId() {
		return false
	}
	for index, result := range status.Results {
		if index >= len(command.Targets) || result == nil || command.Targets[index] == nil ||
			result.Index != command.Targets[index].Index || result.TargetOrdinal != command.Targets[index].TargetOrdinal ||
			!bytes.Equal(result.Sha256, command.Targets[index].Sha256) {
			return false
		}
	}
	return len(status.Results) == 0 || len(status.Results) == len(command.Targets)
}

func (g *Gateway) applyCacheAuthorization(
	ctx context.Context,
	nodeID string,
	source *sessionCacheCommandSource,
	pending pendingCacheCommandSet,
	wasAllowed bool,
	isAllowed bool,
) (*sessionCacheCommandSource, error) {
	if g.cache == nil || wasAllowed == isAllowed {
		return source, nil
	}
	if !isAllowed {
		stopSessionCacheCommands(source, pending, g.config.CommandOperationTimeout)
		return nil, nil
	}
	created, err := newSessionCacheCommandSource(ctx, g.cache, nodeID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not subscribe to node cache commands")
	}
	return created, nil
}

func (g *Gateway) persistCacheStatusAndAckCommand(ctx context.Context, nodeID string, cacheStatus *agentv1.CacheControlStatus, pending pendingCacheCommandSet) (*agentv1.CacheControlStatusAck, error) {
	if err := g.validateCacheControlStatus(cacheStatus, nodeID); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	key := cacheStatusIdentity(cacheStatus)
	command, exists := pending[key]
	if exists && !cacheStatusMatchesCommand(cacheStatus, command.command) {
		return nil, status.Error(codes.FailedPrecondition, "cache status identity conflicts with the in-flight command")
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	err := g.cache.PublishCacheStatus(operationCtx, nodeID, cacheStatus)
	cancel()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "cache status could not be persisted")
	}
	if exists {
		for len(command.deliveries) > 0 {
			delivery := command.deliveries[0]
			operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
			err = delivery.Ack(operationCtx)
			cancel()
			if err != nil {
				return nil, status.Error(codes.Unavailable, "cache command could not be acknowledged")
			}
			command.deliveries = command.deliveries[1:]
		}
		delete(pending, key)
	}
	return &agentv1.CacheControlStatusAck{
		StatusEventId: cacheStatus.Event.EventId,
		TaskId:        cacheStatus.TaskId, LeaseId: cacheStatus.LeaseId, Attempt: cacheStatus.Attempt,
		TransitionSequence: cacheStatus.TransitionSequence,
		PersistedTime:      timestamppb.New(g.now().UTC()),
	}, nil
}
