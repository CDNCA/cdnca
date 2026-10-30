package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maximumCacheControlTargets = 500

type CacheTaskManager interface {
	Execute(context.Context, cachetask.Task) (cachetask.Result, error)
}

func WithCacheTaskManager(manager CacheTaskManager) ClientOption {
	return func(client *Client) error {
		if manager == nil {
			return fmt.Errorf("%w: cache task manager is required", ErrInvalidConfiguration)
		}
		client.cacheTasks = manager
		return nil
	}
}

// WithCacheTaskConfig sets the node cache task configuration the manager
// runs with, so a task's budget stays within it.
func WithCacheTaskConfig(config cachetask.Config) ClientOption {
	return func(client *Client) error {
		client.cacheTaskConfig = config
		return nil
	}
}

func validateCacheControlCommand(command *agentv1.CacheControlCommand, config Config, now time.Time) error {
	if command == nil || proto.Size(command) > config.MaxCommandBytes || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) || !canonicalUUID(command.Event.RequestId) ||
		command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil ||
		!boundedMetadata(command.Event.Traceparent, false) || !boundedMetadata(command.Event.CorrelationId, false) ||
		command.Event.TaskId == nil || command.Event.GetTaskId() != command.TaskId {
		return fmt.Errorf("%w: cache command event is invalid", ErrInvalidMessage)
	}
	if cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return fmt.Errorf("%w: cache command contains unknown fields", ErrInvalidMessage)
	}
	if !canonicalUUID(command.ScopeId) || !canonicalUUID(command.TenantId) || !canonicalUUID(command.SiteId) || command.NodeId != config.NodeID ||
		!canonicalUUID(command.ControlOperationId) || !canonicalUUID(command.LeaseId) || command.Attempt == 0 ||
		!safeIdentifier(command.ConfigVersionId) || command.ConfigRevision == 0 {
		return fmt.Errorf("%w: cache command identity is invalid", ErrInvalidMessage)
	}
	wantTaskID := "cc-" + command.ControlOperationId + "-" + command.NodeId + "-" + strconv.FormatUint(uint64(command.Attempt), 10)
	if command.TaskId != wantTaskID || !safeIdentifier(command.TaskId) ||
		command.Priority != agentv1.CacheControlPriority_CACHE_CONTROL_PRIORITY_NORMAL || len(command.RequestDigest) != sha256.Size ||
		command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil || !command.DeadlineTime.AsTime().After(now) ||
		command.DeadlineTime.AsTime().After(now.Add(cachetask.DefaultConfig().MaxDeadlineHorizon)) {
		return fmt.Errorf("%w: cache command policy is invalid", ErrInvalidMessage)
	}
	if !validCacheControlActionScope(command.Action, command.Scope) || len(command.Targets) == 0 || len(command.Targets) > maximumCacheControlTargets {
		return fmt.Errorf("%w: cache command action or targets are invalid", ErrInvalidMessage)
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(command.Targets))
	seenOrdinals := make(map[uint32]struct{}, len(command.Targets))
	for index, target := range command.Targets {
		if target == nil || target.Index != uint32(index) || target.TargetOrdinal == 0 ||
			len(target.CanonicalUrl) > 16<<10 || strings.TrimSpace(target.CanonicalUrl) != target.CanonicalUrl || len(target.Sha256) != sha256.Size {
			return fmt.Errorf("%w: cache command target binding is invalid", ErrInvalidMessage)
		}
		if _, exists := seenOrdinals[target.TargetOrdinal]; exists {
			return fmt.Errorf("%w: cache command target ordinals are duplicated", ErrInvalidMessage)
		}
		seenOrdinals[target.TargetOrdinal] = struct{}{}
		digest := sha256.Sum256([]byte(target.CanonicalUrl))
		if !bytes.Equal(target.Sha256, digest[:]) {
			return fmt.Errorf("%w: cache command target digest is invalid", ErrInvalidMessage)
		}
		if command.Action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE {
			if index != 0 || target.CanonicalUrl != "" {
				return fmt.Errorf("%w: site purge target is invalid", ErrInvalidMessage)
			}
		} else if target.CanonicalUrl == "" {
			return fmt.Errorf("%w: cache command target is empty", ErrInvalidMessage)
		}
		if _, exists := seen[digest]; exists {
			return fmt.Errorf("%w: cache command targets are duplicated", ErrInvalidMessage)
		}
		seen[digest] = struct{}{}
	}
	return nil
}

func cacheControlMessageHasUnknown(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return true
	}
	hasUnknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsList() && field.Message() != nil {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if cacheControlMessageHasUnknown(list.Get(index).Message()) {
					hasUnknown = true
					return false
				}
			}
			return !hasUnknown
		}
		if field.IsMap() && field.MapValue().Message() != nil {
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				hasUnknown = cacheControlMessageHasUnknown(item.Message())
				return !hasUnknown
			})
			return !hasUnknown
		}
		if field.Message() != nil && cacheControlMessageHasUnknown(value.Message()) {
			hasUnknown = true
			return false
		}
		return true
	})
	return hasUnknown
}

func validCacheControlActionScope(action agentv1.CacheControlAction, scope agentv1.CacheControlScope) bool {
	return action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_EXACT && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL ||
		action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_PREFIX && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_DIRECTORY ||
		action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_SITE ||
		action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PREWARM && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL
}

func cacheControlDeliveredStatus(command *agentv1.CacheControlCommand, at time.Time) *agentv1.CacheControlStatus {
	return cacheControlStatusFor(command, 1, agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED, at)
}

func cacheControlRunningStatus(command *agentv1.CacheControlCommand, at time.Time) *agentv1.CacheControlStatus {
	return cacheControlStatusFor(command, 2, agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING, at)
}

func cacheControlStatusFor(command *agentv1.CacheControlCommand, sequence uint64, state agentv1.CacheControlState, at time.Time) *agentv1.CacheControlStatus {
	causationID := command.Event.EventId
	taskID := command.TaskId
	return &agentv1.CacheControlStatus{
		Event: &commonv1.EventMetadata{
			EventId:   uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("cache-control:%s:%d:%d", command.Event.EventId, sequence, state))).String(),
			RequestId: command.Event.RequestId, OccurredTime: timestamppb.New(at.UTC()), Traceparent: command.Event.Traceparent,
			CausationId: &causationID, CorrelationId: command.Event.CorrelationId, TaskId: &taskID,
		},
		TaskId: command.TaskId, ScopeId: command.ScopeId, TenantId: command.TenantId, SiteId: command.SiteId, NodeId: command.NodeId,
		ControlOperationId: command.ControlOperationId, LeaseId: command.LeaseId, Attempt: command.Attempt,
		ConfigVersionId: command.ConfigVersionId, ConfigRevision: command.ConfigRevision, Action: command.Action, Scope: command.Scope,
		State: state, TransitionSequence: sequence, RequestDigest: append([]byte(nil), command.RequestDigest...), ActiveConfigUnchanged: true,
	}
}

func cacheTaskFromCommand(command *agentv1.CacheControlCommand, configs ...cachetask.Config) (cachetask.Task, error) {
	config := cachetask.DefaultConfig()
	if len(configs) == 1 && configs[0].MaxTaskConcurrency != 0 {
		config = configs[0]
	}
	action, scope, ok := localCacheActionScope(command.Action, command.Scope)
	if !ok {
		return cachetask.Task{}, ErrInvalidMessage
	}
	targets := make([]string, 0, len(command.Targets))
	if action != cachetask.ActionPurgeSite {
		for _, target := range command.Targets {
			targets = append(targets, target.CanonicalUrl)
		}
	}
	return cachetask.Task{
		SchemaVersion: cachetask.SchemaVersion, TaskID: command.TaskId, OperationID: command.TaskId,
		TenantID: command.TenantId, SiteID: command.SiteId, Scope: scope,
		ConfigVersionID: command.ConfigVersionId, ConfigRevision: command.ConfigRevision,
		DeliveryAttempt: int(command.Attempt), Deadline: command.DeadlineTime.AsTime().UTC(),
		Budget: localCacheBudgetFor(action, config), Action: action, Targets: targets,
	}, nil
}

func localCacheActionScope(action agentv1.CacheControlAction, scope agentv1.CacheControlScope) (cachetask.Action, cachetask.Scope, bool) {
	switch {
	case action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_EXACT && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL:
		return cachetask.ActionPurgeExact, cachetask.ScopeURL, true
	case action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_PREFIX && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_DIRECTORY:
		return cachetask.ActionPurgePrefix, cachetask.ScopeDirectory, true
	case action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_SITE:
		return cachetask.ActionPurgeSite, cachetask.ScopeSite, true
	case action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PREWARM && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL:
		return cachetask.ActionPrewarm, cachetask.ScopeURL, true
	default:
		return "", "", false
	}
}

func localCacheBudget(action cachetask.Action) cachetask.ResourceBudget {
	return localCacheBudgetFor(action, cachetask.DefaultConfig())
}

// localCacheBudgetFor is a task's budget within the node's cache task
// configuration (its prewarm object/task size settings).
func localCacheBudgetFor(action cachetask.Action, config cachetask.Config) cachetask.ResourceBudget {
	budget := cachetask.ResourceBudget{
		MaxAttempts: config.MaxAttempts, InitialRetryBackoff: 250 * time.Millisecond, MaximumRetryBackoff: 30 * time.Second,
	}
	if action == cachetask.ActionPrewarm {
		budget.MaxConcurrency = config.MaxTaskConcurrency
		budget.MaxTotalBytes = config.MaxTaskBytes
		budget.MaxResourceBytes = config.MaxResponseBytes
		budget.RequestsPerSecond = config.SiteRequestsPerSecond
		budget.Burst = config.SiteBurst
		return budget
	}
	budget.MaxConcurrency = 1
	budget.MaxPurgeEntries = config.MaxPurgeEntries
	budget.MaxScanEntries = config.MaxScanEntries
	budget.MaxScanBytes = config.MaxScanBytes
	budget.MaxScanDuration = config.MaxScanDuration
	return budget
}

func (c *Client) executeCacheControlRecord(ctx context.Context, key string) error {
	record, err := c.cacheStore.record(key)
	if err != nil {
		return fmt.Errorf("load cache control record: %w", err)
	}
	if record == nil {
		return fmt.Errorf("load cache control record: record is missing")
	}
	if record.ExecutionDone {
		return nil
	}
	command := cacheControlCommandFromBytes(record.Command)
	if command == nil {
		return fmt.Errorf("durable cache control command is corrupt")
	}
	statuses, err := cacheControlStatusesFromRecord(record)
	if err != nil {
		return fmt.Errorf("load cache control statuses: %w", err)
	}
	lastSequence := record.AckedThrough
	lastState := agentv1.CacheControlState_CACHE_CONTROL_STATE_UNSPECIFIED
	if len(statuses) > 0 {
		lastSequence = statuses[len(statuses)-1].TransitionSequence
		lastState = statuses[len(statuses)-1].State
	}
	if lastSequence == 1 || lastState == agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED {
		if err := c.cacheStore.appendStatuses(key, []*agentv1.CacheControlStatus{cacheControlRunningStatus(command, c.now())}, false); err != nil {
			return err
		}
	} else if lastSequence != 2 && lastState != agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING {
		return fmt.Errorf("durable cache control state is invalid")
	} else if cacheControlPurge(command.Action) {
		// CACHEFLOW-E05: the purge already started (running is persisted)
		// but its terminal status was not; it may have deleted the objects,
		// and objects filled since are new. Purging again would delete them,
		// so the outcome is reported unknown and a retry is the user's new
		// attempt. A prewarm only fetches again and resumes (at least once).
		return c.finishCacheControlFailure(key, command, cacheOutcomeUnknownCode, c.now())
	}
	if c.cacheTasks == nil {
		return c.finishCacheControlFailure(key, command, "cache_task_unavailable", c.now())
	}
	task, err := cacheTaskFromCommand(command, c.cacheTaskConfig)
	if err != nil {
		return c.finishCacheControlFailure(key, command, "invalid_cache_task", c.now())
	}
	// CACHE-ADD-07: a task cancelled while queued never runs; a running one
	// runs in its own context, which CacheControlCancel cancels.
	cancels := c.cacheCancels
	if cancels == nil {
		cancels = newCacheCancelRegistry()
	}
	taskContext, done, start := cancels.start(ctx, key)
	if !start {
		return c.finishCacheControlCancelled(key, command, c.now())
	}
	result, err := c.cacheTasks.Execute(taskContext, task)
	done()
	if ctx.Err() != nil && !cancels.cancelled(key) {
		// CACHE-ADD-07: the worker stopped (agent shutdown), nobody
		// cancelled the task: a partial result must not be reported as a
		// cancellation. The record stays running; after restart a prewarm
		// resumes and a purge ends cache_outcome_unknown (CACHEFLOW-E05).
		return ctx.Err()
	}
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		if cancels.cancelled(key) {
			return c.finishCacheControlCancelled(key, command, c.now())
		}
		return c.finishCacheControlFailure(key, command, cacheTaskErrorCode(err), c.now())
	}
	terminal, err := cacheControlTerminalStatus(command, result, c.now())
	if err != nil {
		return c.finishCacheControlFailure(key, command, "invalid_cache_result", c.now())
	}
	return c.cacheStore.appendStatuses(key, []*agentv1.CacheControlStatus{terminal}, true)
}

// cacheOutcomeUnknownCode: a resumed purge whose effect is not known.
const cacheOutcomeUnknownCode = "cache_outcome_unknown"

func cacheControlPurge(action agentv1.CacheControlAction) bool {
	return action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_EXACT ||
		action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_PREFIX ||
		action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE
}

func (c *Client) finishCacheControlFailure(key string, command *agentv1.CacheControlCommand, code string, at time.Time) error {
	status := cacheControlStatusFor(command, 3, agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED, at)
	status.ErrorCode = code
	status.Summary = "cache task failed"
	status.Results = make([]*agentv1.CacheControlTargetResult, 0, len(command.Targets))
	for _, target := range command.Targets {
		status.Results = append(status.Results, &agentv1.CacheControlTargetResult{
			Index: target.Index, TargetOrdinal: target.TargetOrdinal, Sha256: append([]byte(nil), target.Sha256...),
			State:      agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED,
			ResultCode: "cache_task_failed", CauseCode: code, Attempts: 1, CompletedTime: timestamppb.New(at.UTC()),
		})
	}
	return c.cacheStore.appendStatuses(key, []*agentv1.CacheControlStatus{status}, true)
}

func cacheTaskErrorCode(err error) string {
	switch {
	case errors.Is(err, cachetask.ErrConflict):
		return "cache_task_conflict"
	case errors.Is(err, cachetask.ErrSiteNotFound):
		return "site_context_not_found"
	case errors.Is(err, cachetask.ErrTaskExpired):
		return "cache_task_expired"
	case errors.Is(err, cachetask.ErrTaskCapacity):
		return "cache_task_capacity"
	case errors.Is(err, cachetask.ErrInvalidTask):
		return "invalid_cache_task"
	default:
		return "cache_task_failed"
	}
}

func cacheControlTerminalStatus(command *agentv1.CacheControlCommand, result cachetask.Result, fallback time.Time) (*agentv1.CacheControlStatus, error) {
	if result.TaskID != command.TaskId || result.OperationID != command.TaskId || result.TenantID != command.TenantId ||
		result.SiteID != command.SiteId || result.ConfigVersionID != command.ConfigVersionId || result.ConfigRevision != command.ConfigRevision ||
		len(result.Items) != len(command.Targets) {
		return nil, ErrInvalidMessage
	}
	state, ok := wireCacheTaskState(result.State)
	if !ok {
		return nil, ErrInvalidMessage
	}
	completedAt := result.CompletedAt
	if completedAt.IsZero() {
		completedAt = fallback
	}
	status := cacheControlStatusFor(command, 3, state, completedAt)
	status.Results = make([]*agentv1.CacheControlTargetResult, 0, len(result.Items))
	for index, item := range result.Items {
		if item.Index != index || index >= len(command.Targets) || command.Targets[index] == nil || item.Attempts < 1 ||
			item.Affected < 0 || item.Bytes < 0 || item.CompletedAt.IsZero() {
			return nil, ErrInvalidMessage
		}
		if command.Action != agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE {
			digest, err := hex.DecodeString(item.TargetDigest)
			if err != nil || !bytes.Equal(digest, command.Targets[index].Sha256) {
				return nil, ErrInvalidMessage
			}
		}
		itemState, ok := wireCacheItemState(item.Status)
		if !ok {
			return nil, ErrInvalidMessage
		}
		wire := &agentv1.CacheControlTargetResult{
			Index: command.Targets[index].Index, TargetOrdinal: command.Targets[index].TargetOrdinal,
			Sha256: append([]byte(nil), command.Targets[index].Sha256...), State: itemState,
			ResultCode: strings.ToLower(item.Code), CauseCode: strings.ToLower(item.CauseCode),
			AffectedEntries: uint64(item.Affected), TransferredBytes: uint64(item.Bytes), Attempts: uint32(item.Attempts),
			CompletedTime: timestamppb.New(item.CompletedAt.UTC()),
		}
		if wire.ResultCode == "" || wire.CompletedTime.CheckValid() != nil {
			return nil, ErrInvalidMessage
		}
		status.Results = append(status.Results, wire)
		if itemState == agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED && status.ErrorCode == "" {
			status.ErrorCode = wire.ResultCode
		}
	}
	status.Summary = "cache task completed"
	return status, nil
}

func wireCacheTaskState(state cachetask.TaskState) (agentv1.CacheControlState, bool) {
	switch state {
	case cachetask.StateSucceeded:
		return agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED, true
	case cachetask.StatePartialFailed:
		return agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED, true
	case cachetask.StateFailed:
		return agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED, true
	case cachetask.StateCancelled:
		return agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED, true
	default:
		return agentv1.CacheControlState_CACHE_CONTROL_STATE_UNSPECIFIED, false
	}
}

func wireCacheItemState(state cachetask.ItemStatus) (agentv1.CacheControlTargetState, bool) {
	switch state {
	case cachetask.ItemSuccess:
		return agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS, true
	case cachetask.ItemSkipped:
		return agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SKIPPED, true
	case cachetask.ItemFailed:
		return agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED, true
	default:
		return agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_UNSPECIFIED, false
	}
}

func (c *Client) sendCacheControlRecordStatuses(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, record *cacheControlDurableRecord, sent map[string]struct{}, force bool) (uint64, error) {
	statuses, err := cacheControlStatusesFromRecord(record)
	if err != nil {
		return sequence, err
	}
	for _, status := range statuses {
		if _, exists := sent[status.Event.EventId]; exists && !force {
			continue
		}
		sequence++
		if err := sendCacheControlStatus(stream, sequence, status, c.now()); err != nil {
			return sequence, err
		}
		sent[status.Event.EventId] = struct{}{}
	}
	return sequence, nil
}

func sendCacheControlStatus(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, status *agentv1.CacheControlStatus, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now), Payload: &agentv1.ConnectRequest_CacheControlStatus{CacheControlStatus: status}})
}
