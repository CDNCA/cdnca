package gatewayclient

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// cacheControlCancelAPIVersion is CACHE_CONTROL_CANCEL v1 (fz-x3, CACHE-ADD-07).
const cacheControlCancelAPIVersion = 1

// cacheCancelRegistry joins a CacheControlCancel to the cache worker: a task
// cancelled before the worker starts it is never run, one that is running has
// its context cancelled. It is in memory only: the Gateway acknowledges the
// cancel only after the receipt, so a restarted Agent gets it again.
type cacheCancelRegistry struct {
	mu        sync.Mutex
	requested map[string]bool
	running   map[string]context.CancelFunc
}

func newCacheCancelRegistry() *cacheCancelRegistry {
	return &cacheCancelRegistry{requested: map[string]bool{}, running: map[string]context.CancelFunc{}}
}

// start returns the task context, or false when the task was cancelled
// before it started.
func (r *cacheCancelRegistry) start(ctx context.Context, key string) (context.Context, func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.requested[key] {
		return nil, func() {}, false
	}
	taskContext, cancel := context.WithCancel(ctx)
	r.running[key] = cancel
	return taskContext, func() {
		r.mu.Lock()
		delete(r.running, key)
		r.mu.Unlock()
		cancel()
	}, true
}

func (r *cacheCancelRegistry) request(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requested[key] = true
	if cancel := r.running[key]; cancel != nil {
		cancel()
	}
}

func (r *cacheCancelRegistry) cancelled(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requested[key]
}

func (r *cacheCancelRegistry) forget(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.requested, key)
}

func negotiateCacheControlCancelV1(gatewayHello *agentv1.GatewayHello, cacheTasks CacheTaskManager) (bool, error) {
	enabled := false
	for _, capability := range gatewayHello.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL {
			continue
		}
		if enabled || capability.ApiVersion != cacheControlCancelAPIVersion {
			return false, fmt.Errorf("%w: cache cancel capability is duplicated or unsupported", ErrInvalidMessage)
		}
		enabled = true
	}
	if enabled && cacheTasks == nil {
		return false, fmt.Errorf("%w: gateway enabled cache cancel that was not advertised", ErrInvalidMessage)
	}
	return enabled, nil
}

func validateCacheControlCancel(cancel *agentv1.CacheControlCancel, config Config) error {
	if cancel == nil || cancel.Event == nil || !canonicalUUID(cancel.Event.EventId) || !canonicalUUID(cancel.Event.RequestId) ||
		cancel.Event.OccurredTime == nil || cancel.Event.OccurredTime.CheckValid() != nil ||
		cacheControlMessageHasUnknown(cancel.ProtoReflect()) {
		return fmt.Errorf("%w: cache cancel event is invalid", ErrInvalidMessage)
	}
	if !canonicalUUID(cancel.CancelId) || !canonicalUUID(cancel.ScopeId) || !canonicalUUID(cancel.TenantId) ||
		!canonicalUUID(cancel.SiteId) || cancel.NodeId != config.NodeID || !canonicalUUID(cancel.ControlOperationId) ||
		!canonicalUUID(cancel.LeaseId) || cancel.Attempt == 0 || cancel.RequestedTime == nil || cancel.RequestedTime.CheckValid() != nil {
		return fmt.Errorf("%w: cache cancel identity is invalid", ErrInvalidMessage)
	}
	wantTaskID := "cc-" + cancel.ControlOperationId + "-" + cancel.NodeId + "-" + strconv.FormatUint(uint64(cancel.Attempt), 10)
	if cancel.TaskId != wantTaskID || !safeIdentifier(cancel.TaskId) {
		return fmt.Errorf("%w: cache cancel task identity is invalid", ErrInvalidMessage)
	}
	return nil
}

// cacheCancelMatches: the record holds the exact command the cancel names.
func cacheCancelMatches(record *cacheControlDurableRecord, cancel *agentv1.CacheControlCancel) bool {
	if record == nil || record.TaskID != cancel.TaskId || record.LeaseID != cancel.LeaseId || record.Attempt != cancel.Attempt {
		return false
	}
	if len(record.Command) == 0 {
		// A compacted completion keeps no command; its task_id already binds
		// the operation and node, and the lease and attempt matched.
		return record.ExecutionDone
	}
	command := cacheControlCommandFromBytes(record.Command)
	return command != nil && command.ControlOperationId == cancel.ControlOperationId && command.ScopeId == cancel.ScopeId &&
		command.TenantId == cancel.TenantId && command.SiteId == cancel.SiteId && command.NodeId == cancel.NodeId
}

// cacheCancelReceipt settles a cancel from the record's terminal status: the
// task stopped by this cancel is CANCELLED, one that ran to the end first is
// ALREADY_COMPLETED, and a task the node does not hold is NOT_RECEIVED.
func cacheCancelReceipt(cancel *agentv1.CacheControlCancel, record *cacheControlDurableRecord, at time.Time) *agentv1.CacheControlCancelReceipt {
	receipt := &agentv1.CacheControlCancelReceipt{
		CancelId: cancel.CancelId, TaskId: cancel.TaskId, NodeId: cancel.NodeId, LeaseId: cancel.LeaseId, Attempt: cancel.Attempt,
		Outcome: agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_NOT_RECEIVED, SettledTime: timestamppb.New(at.UTC()),
	}
	if cacheCancelMatches(record, cancel) && record.ExecutionDone {
		statuses, err := cacheControlStatusesFromRecord(record)
		if err == nil && len(statuses) > 0 && cacheControlTerminalState(statuses[len(statuses)-1].State) {
			terminal := statuses[len(statuses)-1]
			receipt.Outcome = agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_ALREADY_COMPLETED
			if terminal.State == agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED {
				receipt.Outcome = agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED
			}
			for _, result := range terminal.Results {
				switch {
				case result.State == agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS ||
					result.State == agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SKIPPED:
					receipt.SucceededTargets++
				case result.ResultCode == "task_cancelled":
					receipt.CancelledTargets++
				default:
					receipt.FailedTargets++
				}
			}
		}
	}
	causationID := cancel.Event.EventId
	taskID := cancel.TaskId
	receipt.Event = &commonv1.EventMetadata{
		EventId: uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("cache-cancel-receipt:%s:%d",
			cancel.CancelId, receipt.Outcome))).String(),
		RequestId: cancel.Event.RequestId, OccurredTime: timestamppb.New(at.UTC()), Traceparent: cancel.Event.Traceparent,
		CausationId: &causationID, CorrelationId: cancel.Event.CorrelationId, TaskId: &taskID,
	}
	return receipt
}

// finishCacheControlCancelled ends a task stopped by a cancel: every target
// it did not finish is failed with task_cancelled.
func (c *Client) finishCacheControlCancelled(key string, command *agentv1.CacheControlCommand, at time.Time) error {
	status := cacheControlStatusFor(command, 3, agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED, at)
	status.ErrorCode = "task_cancelled"
	status.Summary = "cache task cancelled"
	status.Results = make([]*agentv1.CacheControlTargetResult, 0, len(command.Targets))
	for _, target := range command.Targets {
		status.Results = append(status.Results, &agentv1.CacheControlTargetResult{
			Index: target.Index, TargetOrdinal: target.TargetOrdinal, Sha256: append([]byte(nil), target.Sha256...),
			State:      agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED,
			ResultCode: "task_cancelled", Attempts: 1, CompletedTime: timestamppb.New(at.UTC()),
		})
	}
	return c.cacheStore.appendStatuses(key, []*agentv1.CacheControlStatus{status}, true)
}

func sendCacheControlCancelReceipt(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, receipt *agentv1.CacheControlCancelReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now), Payload: &agentv1.ConnectRequest_CacheControlCancelReceipt{CacheControlCancelReceipt: receipt}})
}
