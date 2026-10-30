package gatewayclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCacheControlStoreRejectsConflictingRedelivery(t *testing.T) {
	directory := filepath.Join(secureTempDir(t), "cache-control")
	store, err := newCacheControlDurableStore(directory, 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	command := testCacheControlCommand()
	record, created, err := store.putCommand(command, cacheControlDeliveredStatus(command, time.Now()))
	if err != nil || !created || record == nil {
		t.Fatalf("first put record=%+v created=%t error=%v", record, created, err)
	}
	if replay, created, err := store.putCommand(command, cacheControlDeliveredStatus(command, time.Now())); err != nil || created || replay.RecordKey != record.RecordKey {
		t.Fatalf("replay record=%+v created=%t error=%v", replay, created, err)
	}
	command.RequestDigest = append([]byte(nil), command.RequestDigest...)
	command.RequestDigest[0] ^= 0xff
	if _, _, err := store.putCommand(command, cacheControlDeliveredStatus(command, time.Now())); err != ErrCommandConflict {
		t.Fatalf("conflicting redelivery error=%v", err)
	}
}

func TestCacheControlExecutionPersistsBoundTerminalAndDoesNotRepeat(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	command := testCacheControlCommand()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	manager := &fakeCacheTaskManager{execute: func(task cachetask.Task) (cachetask.Result, error) {
		if want := localCacheBudgetFor(cachetask.ActionPrewarm, cachetask.DefaultConfig()); task.Budget != want {
			t.Fatalf("task budget=%+v want local default=%+v", task.Budget, want)
		}
		return successfulCacheTaskResult(task, command.Targets[0], fixed.Add(time.Second)), nil
	}}
	store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := store.putCommand(command, cacheControlDeliveredStatus(command, fixed))
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{cacheStore: store, cacheTasks: manager, now: func() time.Time { return fixed }}
	if err := client.executeCacheControlRecord(context.Background(), record.RecordKey); err != nil {
		t.Fatal(err)
	}
	if err := client.executeCacheControlRecord(context.Background(), record.RecordKey); err != nil {
		t.Fatal(err)
	}
	if manager.calls != 1 {
		t.Fatalf("cache manager calls=%d want=1", manager.calls)
	}
	persisted, err := store.record(record.RecordKey)
	if err != nil || !persisted.ExecutionDone {
		t.Fatalf("persisted=%+v error=%v", persisted, err)
	}
	statuses, err := cacheControlStatusesFromRecord(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 3 || statuses[0].State != agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED ||
		statuses[1].State != agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING ||
		statuses[2].State != agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED {
		t.Fatalf("unexpected statuses: %+v", statuses)
	}
	terminal := statuses[2]
	if len(terminal.Results) != 1 || terminal.Results[0].TargetOrdinal != command.Targets[0].TargetOrdinal ||
		!equalBytes(terminal.Results[0].Sha256, command.Targets[0].Sha256) || terminal.Results[0].ResultCode != "prewarmed" {
		t.Fatalf("terminal result is not bound to command: %+v", terminal.Results)
	}
}

func TestCacheControlExecutionResumesPersistedRunningAfterResponseLoss(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	command := testCacheControlCommand()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := store.putCommand(command, cacheControlDeliveredStatus(command, fixed))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.appendStatuses(record.RecordKey, []*agentv1.CacheControlStatus{cacheControlRunningStatus(command, fixed)}, false); err != nil {
		t.Fatal(err)
	}
	manager := &fakeCacheTaskManager{execute: func(task cachetask.Task) (cachetask.Result, error) {
		return successfulCacheTaskResult(task, command.Targets[0], fixed.Add(time.Second)), nil
	}}
	client := &Client{cacheStore: store, cacheTasks: manager, now: func() time.Time { return fixed }}
	if err := client.executeCacheControlRecord(context.Background(), record.RecordKey); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := cacheControlStatusesFromRecord(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if manager.calls != 1 || len(statuses) != 3 || statuses[2].State != agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED {
		t.Fatalf("calls=%d statuses=%+v", manager.calls, statuses)
	}
}

func TestCacheControlCommandRunsThroughGatewayClientStreamAndDeduplicatesAcknowledgedReplay(t *testing.T) {
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	config := testClientConfig(filepath.Join(root, "journal"))
	config.Capabilities.Features = append(config.Capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 1,
	})
	command := testCacheControlCommand()
	command.NodeId = config.NodeID
	command.TaskId = "cc-" + command.ControlOperationId + "-" + command.NodeId + "-1"
	command.Event.TaskId = &command.TaskId
	command.DeadlineTime = timestamppb.New(time.Now().Add(time.Hour))
	unmatched := proto.Clone(command).(*agentv1.CacheControlCommand)
	unmatched.ControlOperationId = "77777777-7777-4777-8777-777777777777"
	unmatched.TaskId = "cc-" + unmatched.ControlOperationId + "-" + unmatched.NodeId + "-1"
	unmatched.Event.EventId = uuid.NewString()
	unmatched.Event.RequestId = uuid.NewString()
	unmatched.Event.TaskId = &unmatched.TaskId
	var replayExpired atomic.Bool
	gateway := &cacheControlGateway{
		command: command, terminal: make(chan *agentv1.CacheControlStatus, 1),
		replayAfterTerminal: true, replayDone: make(chan struct{}), beforeReplay: func() { replayExpired.Store(true) },
		afterReplayCommand: unmatched,
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	store, err := newDurableStore(config.JournalDir, config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	overlayStore, err := newOverlayDurableStore(filepath.Join(config.JournalDir, "acme-http01-overlay"), config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	cacheStore, err := newCacheControlDurableStore(filepath.Join(config.JournalDir, "cache-control"), config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	manager := &fakeCacheTaskManager{execute: func(task cachetask.Task) (cachetask.Result, error) {
		return successfulCacheTaskResult(task, command.Targets[0], time.Now().UTC()), nil
	}}
	client := &Client{
		config: config, manager: noOpManager{}, store: store, overlayStore: overlayStore, cacheStore: cacheStore,
		cacheTasks: manager, now: func() time.Time {
			if replayExpired.Load() {
				return command.DeadlineTime.AsTime().Add(time.Second)
			}
			return time.Now()
		},
	}
	connection, err := (&bufDialer{listener: listener}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.runSession(ctx, connection.Client())
		done <- err
	}()
	select {
	case terminal := <-gateway.terminal:
		if terminal.State != agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED || manager.calls != 1 {
			t.Fatalf("terminal=%+v manager calls=%d", terminal, manager.calls)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cache control terminal status was not returned")
	}
	cacheKey := cacheControlRecordKey(command.TaskId)
	deadline := time.Now().Add(2 * time.Second)
	for {
		record, err := cacheStore.record(cacheKey)
		if err != nil {
			t.Fatal(err)
		}
		if record == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("terminal cache journal was retained after durable acknowledgement: %+v", record)
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-gateway.replayDone:
	case <-time.After(3 * time.Second):
		t.Fatal("acknowledged cache command replay did not return terminal completion")
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("unmatched expired cache command error=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unmatched expired cache command was not rejected")
	}
	if got := gateway.states(); manager.calls != 1 || len(got) != 4 ||
		got[0] != agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED ||
		got[1] != agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING ||
		got[2] != agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED ||
		got[3] != agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED {
		t.Fatalf("manager calls=%d cache status states=%v", manager.calls, got)
	}
}

func TestCacheControlWorkerDoesNotBlockDeploymentOrHeartbeat(t *testing.T) {
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	config := testClientConfig(filepath.Join(root, "journal"))
	config.Capabilities.Features = append(config.Capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 1,
	})
	cacheCommand := testCacheControlCommand()
	cacheCommand.NodeId = config.NodeID
	cacheCommand.TaskId = "cc-" + cacheCommand.ControlOperationId + "-" + cacheCommand.NodeId + "-1"
	cacheCommand.Event.TaskId = &cacheCommand.TaskId
	cacheCommand.DeadlineTime = timestamppb.New(time.Now().Add(time.Hour))
	baseline := "cfg-old"
	deploymentCommand := &agentv1.DeploymentCommand{
		Event:        &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		DeploymentId: uuid.NewString(), Attempt: 1, RolloutId: uuid.NewString(), ConfigVersionId: "cfg-new",
		PreviousConfigVersionId: &baseline, Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK,
		RequiredCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1}},
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration: durationpb.New(time.Second), ObservationWindowDuration: durationpb.New(time.Second), RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
	}
	sendDeployment := make(chan struct{})
	heartbeats := make(chan struct{}, 1)
	gateway := &cacheControlGateway{
		command: cacheCommand, deploymentCommand: deploymentCommand, sendDeployment: sendDeployment,
		terminal: make(chan *agentv1.CacheControlStatus, 1), heartbeats: heartbeats,
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	store, err := newDurableStore(config.JournalDir, config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	overlayStore, err := newOverlayDurableStore(filepath.Join(config.JournalDir, "acme-http01-overlay"), config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	cacheStore, err := newCacheControlDurableStore(filepath.Join(config.JournalDir, "cache-control"), config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	cacheStarted := make(chan struct{})
	releaseCache := make(chan struct{})
	cacheManager := &fakeCacheTaskManager{execute: func(task cachetask.Task) (cachetask.Result, error) {
		close(cacheStarted)
		select {
		case <-releaseCache:
			return successfulCacheTaskResult(task, cacheCommand.Targets[0], time.Now().UTC()), nil
		case <-time.After(5 * time.Second):
			return cachetask.Result{}, context.DeadlineExceeded
		}
	}}
	deploymentProcessed := make(chan struct{}, 1)
	client := &Client{
		config: config, manager: isolationDeploymentManager{processed: deploymentProcessed}, store: store,
		overlayStore: overlayStore, cacheStore: cacheStore, cacheTasks: cacheManager, now: time.Now,
	}
	connection, err := (&bufDialer{listener: listener}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.runSession(ctx, connection.Client())
		done <- err
	}()
	select {
	case <-cacheStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("cache worker did not start")
	}
	close(sendDeployment)
	select {
	case <-deploymentProcessed:
	case <-time.After(2 * time.Second):
		t.Fatal("deployment was blocked behind cache execution")
	}
	select {
	case <-heartbeats:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat was blocked behind cache execution")
	}
	close(releaseCache)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && status.Code(err) != codes.Canceled {
		t.Fatalf("runSession error=%v", err)
	}
}

func TestCacheControlInvalidResultFailsClosed(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	command := testCacheControlCommandWithTwoTargets()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	manager := &fakeCacheTaskManager{execute: func(task cachetask.Task) (cachetask.Result, error) {
		result := successfulCacheTaskResult(task, command.Targets[0], fixed.Add(time.Second))
		result.Items[0].TargetDigest = hex.EncodeToString(make([]byte, sha256.Size))
		return result, nil
	}}
	terminal := executeCacheControlFailure(t, command, manager, fixed)
	assertCacheControlFailureContract(t, command, terminal, "invalid_cache_result", fixed)
}

func TestCacheControlUnavailableManagerProducesBoundFailure(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	command := testCacheControlCommandWithTwoTargets()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	terminal := executeCacheControlFailure(t, command, nil, fixed)
	assertCacheControlFailureContract(t, command, terminal, "cache_task_unavailable", fixed)
}

func TestCacheControlManagerErrorProducesBoundFailure(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	command := testCacheControlCommandWithTwoTargets()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	manager := &fakeCacheTaskManager{execute: func(cachetask.Task) (cachetask.Result, error) {
		return cachetask.Result{}, cachetask.ErrTaskCapacity
	}}
	terminal := executeCacheControlFailure(t, command, manager, fixed)
	assertCacheControlFailureContract(t, command, terminal, "cache_task_capacity", fixed)
}

func executeCacheControlFailure(t *testing.T, command *agentv1.CacheControlCommand, manager CacheTaskManager, fixed time.Time) *agentv1.CacheControlStatus {
	t.Helper()
	store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := store.putCommand(command, cacheControlDeliveredStatus(command, fixed))
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{cacheStore: store, cacheTasks: manager, now: func() time.Time { return fixed }}
	if err := client.executeCacheControlRecord(context.Background(), record.RecordKey); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := cacheControlStatusesFromRecord(persisted)
	if err != nil {
		t.Fatal(err)
	}
	terminal := statuses[len(statuses)-1]
	return terminal
}

func assertCacheControlFailureContract(t *testing.T, command *agentv1.CacheControlCommand, terminal *agentv1.CacheControlStatus, code string, completed time.Time) {
	t.Helper()
	if terminal.State != agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED || terminal.ErrorCode != code ||
		!terminal.ActiveConfigUnchanged || len(terminal.Results) != len(command.Targets) || len(terminal.Results) == 0 {
		t.Fatalf("invalid failure terminal: %+v", terminal)
	}
	for index, result := range terminal.Results {
		target := command.Targets[index]
		if result == nil || result.Index != uint32(index) || result.TargetOrdinal != target.TargetOrdinal ||
			!equalBytes(result.Sha256, target.Sha256) || result.State != agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED ||
			result.ResultCode != "cache_task_failed" || result.CauseCode != code || result.Attempts < 1 ||
			result.CompletedTime == nil || result.CompletedTime.CheckValid() != nil || !result.CompletedTime.AsTime().Equal(completed.UTC()) {
			t.Fatalf("invalid failure result[%d]: %+v", index, result)
		}
	}
}

func TestCacheControlStoreRejectsOutOfOrderStatus(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	command := testCacheControlCommand()
	store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := store.putCommand(command, cacheControlDeliveredStatus(command, fixed))
	if err != nil {
		t.Fatal(err)
	}
	running := cacheControlRunningStatus(command, fixed)
	if err := store.appendStatuses(record.RecordKey, []*agentv1.CacheControlStatus{running}, false); err != nil {
		t.Fatal(err)
	}
	stale := cacheControlRunningStatus(command, fixed.Add(time.Second))
	stale.Event.EventId = uuid.NewString()
	if err := store.appendStatuses(record.RecordKey, []*agentv1.CacheControlStatus{stale}, false); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("out-of-order status error=%v", err)
	}
}

func TestCacheControlStoreRejectsStateSequenceMismatchAcrossDurableBoundaries(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for _, sequence := range []uint64{2, 4} {
		t.Run(fmt.Sprintf("active terminal sequence %d", sequence), func(t *testing.T) {
			command := testCacheControlCommand()
			store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
			if err != nil {
				t.Fatal(err)
			}
			record, _, err := store.putCommand(command, cacheControlDeliveredStatus(command, fixed))
			if err != nil {
				t.Fatal(err)
			}
			wantStatuses := 1
			if sequence == 4 {
				if err := store.appendStatuses(record.RecordKey, []*agentv1.CacheControlStatus{
					cacheControlRunningStatus(command, fixed.Add(time.Second)),
				}, false); err != nil {
					t.Fatal(err)
				}
				wantStatuses = 2
			}
			terminal := cacheControlStatusFor(command, sequence,
				agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED, fixed.Add(2*time.Second))
			if err := store.appendStatuses(record.RecordKey, []*agentv1.CacheControlStatus{terminal}, true); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("mismatched terminal append error=%v", err)
			}
			persisted, err := store.record(record.RecordKey)
			if err != nil || persisted == nil || persisted.ExecutionDone || len(persisted.Statuses) != wantStatuses {
				t.Fatalf("record=%+v error=%v", persisted, err)
			}
		})
	}

	t.Run("completion terminal sequence", func(t *testing.T) {
		command := testCacheControlCommand()
		store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
		if err != nil {
			t.Fatal(err)
		}
		commandBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
		if err != nil {
			t.Fatal(err)
		}
		terminal := cacheControlStatusFor(command, 4,
			agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED, fixed.Add(2*time.Second))
		terminalBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(terminal)
		if err != nil {
			t.Fatal(err)
		}
		key := cacheControlRecordKey(command.TaskId)
		completion := &cacheControlCompletion{
			Version: cacheControlCompletionVersion, RecordKey: key, EventID: command.Event.EventId,
			TaskID: command.TaskId, LeaseID: command.LeaseId, Attempt: command.Attempt,
			CommandDigest: commandDigest(commandBytes), ExpiresAt: fixed.Add(time.Hour),
			TerminalStatus: terminalBytes, TransitionSequence: 4, StatusEventID: terminal.Event.EventId,
		}
		if err := store.validateCompletion(completion, key); err == nil {
			t.Fatal("mismatched terminal completion was accepted")
		}
	})
}

func TestCacheControlStoreCompactsAcknowledgedStatusesAndDeletesTerminal(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	command := testCacheControlCommand()
	store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	delivered := cacheControlDeliveredStatus(command, fixed)
	record, _, err := store.putCommand(command, delivered)
	if err != nil {
		t.Fatal(err)
	}
	running := cacheControlRunningStatus(command, fixed.Add(time.Second))
	terminal := cacheControlStatusFor(command, 3, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED, fixed.Add(2*time.Second))
	if err := store.appendStatuses(record.RecordKey, []*agentv1.CacheControlStatus{running, terminal}, true); err != nil {
		t.Fatal(err)
	}
	ack := func(status *agentv1.CacheControlStatus) *agentv1.CacheControlStatusAck {
		return &agentv1.CacheControlStatusAck{
			StatusEventId: status.Event.EventId, TaskId: status.TaskId, LeaseId: status.LeaseId,
			Attempt: status.Attempt, TransitionSequence: status.TransitionSequence, PersistedTime: timestamppb.New(fixed.Add(3 * time.Second)),
		}
	}
	if err := store.acknowledge(ack(delivered)); err != nil {
		t.Fatal(err)
	}
	if err := store.acknowledge(ack(delivered)); err != nil {
		t.Fatalf("idempotent acknowledgement: %v", err)
	}
	compacted, err := store.record(record.RecordKey)
	if err != nil || compacted == nil || compacted.Version != 2 || compacted.AckedThrough != 1 || len(compacted.Statuses) != 2 {
		t.Fatalf("delivered compaction record=%+v error=%v", compacted, err)
	}
	statuses, err := cacheControlStatusesFromRecord(compacted)
	if err != nil || len(statuses) != 2 || statuses[0].TransitionSequence != 2 || statuses[1].TransitionSequence != 3 {
		t.Fatalf("unacknowledged statuses=%+v error=%v", statuses, err)
	}
	if err := store.acknowledge(ack(running)); err != nil {
		t.Fatal(err)
	}
	compacted, err = store.record(record.RecordKey)
	if err != nil || compacted == nil || compacted.AckedThrough != 2 || len(compacted.Statuses) != 1 {
		t.Fatalf("running compaction record=%+v error=%v", compacted, err)
	}
	if err := store.acknowledge(ack(terminal)); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.record(record.RecordKey)
	if err != nil || deleted != nil {
		t.Fatalf("terminal acknowledged record=%+v error=%v", deleted, err)
	}
	entries, err := store.records()
	if err != nil || len(entries) != 0 {
		t.Fatalf("retained terminal records=%d error=%v", len(entries), err)
	}
}

func TestCacheControlCompletionTombstoneSurvivesRestartRejectsConflictAndExpires(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	directory := filepath.Join(secureTempDir(t), "cache-control")
	command := testCacheControlCommand()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	store, err := newCacheControlDurableStore(directory, 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return fixed }
	delivered := cacheControlDeliveredStatus(command, fixed)
	record, _, err := store.putCommand(command, delivered)
	if err != nil {
		t.Fatal(err)
	}
	running := cacheControlRunningStatus(command, fixed.Add(time.Second))
	terminal := cacheControlStatusFor(command, 3, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED, fixed.Add(2*time.Second))
	if err := store.appendStatuses(record.RecordKey, []*agentv1.CacheControlStatus{running, terminal}, true); err != nil {
		t.Fatal(err)
	}
	for _, status := range []*agentv1.CacheControlStatus{delivered, running, terminal} {
		if err := store.acknowledge(&agentv1.CacheControlStatusAck{
			StatusEventId: status.Event.EventId, TaskId: status.TaskId, LeaseId: status.LeaseId,
			Attempt: status.Attempt, TransitionSequence: status.TransitionSequence, PersistedTime: timestamppb.New(fixed.Add(3 * time.Second)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if active, err := store.record(record.RecordKey); err != nil || active != nil {
		t.Fatalf("terminal active record=%+v error=%v", active, err)
	}

	restarted, err := newCacheControlDurableStore(directory, 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return fixed.Add(30 * time.Minute) }
	replayed, created, err := restarted.putCommand(command, delivered)
	if err != nil || created || replayed == nil || !replayed.ExecutionDone {
		t.Fatalf("restarted replay record=%+v created=%t error=%v", replayed, created, err)
	}
	statuses, err := cacheControlStatusesFromRecord(replayed)
	if err != nil || len(statuses) != 1 || statuses[0].State != agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED {
		t.Fatalf("replayed terminal statuses=%+v error=%v", statuses, err)
	}
	rotatedLease := proto.Clone(command).(*agentv1.CacheControlCommand)
	rotatedLease.LeaseId = "66666666-6666-4666-8666-666666666666"
	if _, _, err := restarted.putCommand(rotatedLease, cacheControlDeliveredStatus(rotatedLease, fixed)); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("rotated lease command error=%v", err)
	}
	changedAttempt := proto.Clone(command).(*agentv1.CacheControlCommand)
	changedAttempt.Attempt++
	if _, _, err := restarted.putCommand(changedAttempt, cacheControlDeliveredStatus(changedAttempt, fixed)); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed attempt command error=%v", err)
	}
	changed := proto.Clone(command).(*agentv1.CacheControlCommand)
	changed.ConfigRevision++
	if _, _, err := restarted.putCommand(changed, cacheControlDeliveredStatus(changed, fixed)); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed command digest error=%v", err)
	}

	restarted.now = func() time.Time { return fixed.Add(time.Hour) }
	if active, err := restarted.records(); err != nil || len(active) != 0 {
		t.Fatalf("active records at command deadline=%d error=%v", len(active), err)
	}
	deadlineReplay, created, err := restarted.putCommand(command, delivered)
	if err != nil || created || deadlineReplay == nil || !deadlineReplay.ExecutionDone {
		t.Fatalf("deadline replay record=%+v created=%t error=%v", deadlineReplay, created, err)
	}

	restarted.now = func() time.Time { return fixed.Add(time.Hour + cacheControlCompletionRetention) }
	if active, err := restarted.records(); err != nil || len(active) != 0 {
		t.Fatalf("active records after completion expiry=%d error=%v", len(active), err)
	}
	createdRecord, created, err := restarted.putCommand(command, delivered)
	if err != nil || !created || createdRecord == nil || createdRecord.ExecutionDone {
		t.Fatalf("post-expiry record=%+v created=%t error=%v", createdRecord, created, err)
	}
}

func TestCacheControlStoreRejectsUnknownAcknowledgementFields(t *testing.T) {
	command := testCacheControlCommand()
	store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	delivered := cacheControlDeliveredStatus(command, time.Now())
	if _, _, err := store.putCommand(command, delivered); err != nil {
		t.Fatal(err)
	}
	ack := &agentv1.CacheControlStatusAck{
		StatusEventId: delivered.Event.EventId, TaskId: delivered.TaskId, LeaseId: delivered.LeaseId,
		Attempt: delivered.Attempt, TransitionSequence: delivered.TransitionSequence, PersistedTime: timestamppb.Now(),
	}
	ack.PersistedTime.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if err := store.acknowledge(ack); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("nested unknown acknowledgement error=%v", err)
	}
}

func TestValidateCacheControlCommandRejectsCrossNodeAndTargetTampering(t *testing.T) {
	config := DefaultConfig()
	config.NodeID = "22222222-2222-4222-8222-222222222222"
	command := testCacheControlCommand()
	if err := validateCacheControlCommand(command, config, time.Now()); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	command.NodeId = "66666666-6666-4666-8666-666666666666"
	if err := validateCacheControlCommand(command, config, time.Now()); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("cross-node command error=%v", err)
	}
	command = testCacheControlCommand()
	command.Targets[0].Sha256[0] ^= 0xff
	if err := validateCacheControlCommand(command, config, time.Now()); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("tampered target error=%v", err)
	}
}

func TestValidateCacheControlCommandAllowsSparseStableOrdinals(t *testing.T) {
	config := DefaultConfig()
	config.NodeID = "22222222-2222-4222-8222-222222222222"
	command := testCacheControlCommandWithTwoTargets()
	command.Targets[1].TargetOrdinal = 9
	if err := validateCacheControlCommand(command, config, time.Now()); err != nil {
		t.Fatalf("sparse stable ordinal rejected: %v", err)
	}
}

func TestValidateCacheControlCommandRejectsRecursiveProtobufUnknownFields(t *testing.T) {
	config := DefaultConfig()
	config.NodeID = "22222222-2222-4222-8222-222222222222"
	command := testCacheControlCommand()
	command.Targets[0].ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if err := validateCacheControlCommand(command, config, time.Now()); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("nested unknown field error=%v", err)
	}
}

func TestRemoveCacheCapabilityWithoutManager(t *testing.T) {
	features := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 1},
	}
	filtered := removeCapability(features, agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL)
	if len(filtered) != 1 || filtered[0].Name != agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE {
		t.Fatalf("unexpected filtered capabilities: %+v", filtered)
	}
}

func testCacheControlCommand() *agentv1.CacheControlCommand {
	target := "https://cache.example.test/assets/app.js"
	digest := sha256.Sum256([]byte(target))
	taskID := "cc-11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222-1"
	return &agentv1.CacheControlCommand{
		Event:   &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), TaskId: &taskID},
		TaskId:  taskID,
		ScopeId: "33333333-3333-4333-8333-333333333333", TenantId: "77777777-7777-4777-8777-777777777777", SiteId: "44444444-4444-4444-8444-444444444444",
		NodeId: "22222222-2222-4222-8222-222222222222", ControlOperationId: "11111111-1111-4111-8111-111111111111",
		LeaseId: "55555555-5555-4555-8555-555555555555", Attempt: 1,
		ConfigVersionId: "version-1", ConfigRevision: 7,
		Action:        agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PREWARM,
		Scope:         agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL,
		Priority:      agentv1.CacheControlPriority_CACHE_CONTROL_PRIORITY_NORMAL,
		RequestDigest: digest[:], DeadlineTime: timestamppb.New(time.Now().Add(time.Minute)),
		Targets: []*agentv1.CacheControlTarget{{Index: 0, TargetOrdinal: 1, CanonicalUrl: target, Sha256: digest[:]}},
	}
}

func testCacheControlCommandWithTwoTargets() *agentv1.CacheControlCommand {
	command := testCacheControlCommand()
	target := "https://cache.example.test/assets/vendor.js"
	digest := sha256.Sum256([]byte(target))
	command.Targets = append(command.Targets, &agentv1.CacheControlTarget{
		Index: 1, TargetOrdinal: 2, CanonicalUrl: target, Sha256: digest[:],
	})
	return command
}

type fakeCacheTaskManager struct {
	calls   int
	execute func(cachetask.Task) (cachetask.Result, error)
}

func (m *fakeCacheTaskManager) Execute(_ context.Context, task cachetask.Task) (cachetask.Result, error) {
	m.calls++
	return m.execute(task)
}

func successfulCacheTaskResult(task cachetask.Task, target *agentv1.CacheControlTarget, completed time.Time) cachetask.Result {
	return cachetask.Result{
		SchemaVersion: cachetask.SchemaVersion, TaskID: task.TaskID, OperationID: task.OperationID,
		TenantID: task.TenantID, SiteID: task.SiteID, Scope: task.Scope,
		ConfigVersionID: task.ConfigVersionID, ConfigRevision: task.ConfigRevision,
		State: cachetask.StateSucceeded, CompletedAt: completed,
		Items: []cachetask.ItemResult{{
			Index: 0, Target: target.CanonicalUrl, TargetDigest: hex.EncodeToString(target.Sha256),
			Status: cachetask.ItemSuccess, Code: cachetask.CodePrewarmed, Attempts: 1, CompletedAt: completed,
		}},
	}
}

func equalBytes(left, right []byte) bool {
	return string(left) == string(right)
}

type cacheControlGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	command             *agentv1.CacheControlCommand
	deploymentCommand   *agentv1.DeploymentCommand
	sendDeployment      <-chan struct{}
	heartbeats          chan<- struct{}
	terminal            chan *agentv1.CacheControlStatus
	replayAfterTerminal bool
	replayDone          chan struct{}
	beforeReplay        func()
	afterReplayCommand  *agentv1.CacheControlCommand
	mu                  sync.Mutex
	statuses            []*agentv1.CacheControlStatus
	terminalStatuses    int
}

func (g *cacheControlGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil || first.GetHello() == nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(50 * time.Millisecond), OfflineAfterDuration: durationpb.New(time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128,
		}},
	}); err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(2), Payload: &agentv1.ConnectResponse_CacheControlCommand{CacheControlCommand: g.command},
	}); err != nil {
		return err
	}
	responseSequence := uint64(2)
	if g.deploymentCommand != nil {
		select {
		case <-g.sendDeployment:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		responseSequence++
		if err := stream.Send(&agentv1.ConnectResponse{
			Stream: responseMetadata(responseSequence), Payload: &agentv1.ConnectResponse_DeploymentCommand{DeploymentCommand: g.deploymentCommand},
		}); err != nil {
			return err
		}
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if cacheStatus := request.GetCacheControlStatus(); cacheStatus != nil {
			g.mu.Lock()
			g.statuses = append(g.statuses, cacheStatus)
			if cacheControlTerminalState(cacheStatus.State) {
				g.terminalStatuses++
			}
			terminalStatuses := g.terminalStatuses
			g.mu.Unlock()
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_CacheControlStatusAck{CacheControlStatusAck: &agentv1.CacheControlStatusAck{
					StatusEventId: cacheStatus.Event.EventId, TaskId: cacheStatus.TaskId, LeaseId: cacheStatus.LeaseId,
					Attempt: cacheStatus.Attempt, TransitionSequence: cacheStatus.TransitionSequence, PersistedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
			if cacheControlTerminalState(cacheStatus.State) {
				select {
				case g.terminal <- cacheStatus:
				default:
				}
				if g.replayAfterTerminal && terminalStatuses == 1 {
					if g.beforeReplay != nil {
						g.beforeReplay()
					}
					responseSequence++
					if err := stream.Send(&agentv1.ConnectResponse{
						Stream:  responseMetadata(responseSequence),
						Payload: &agentv1.ConnectResponse_CacheControlCommand{CacheControlCommand: g.command},
					}); err != nil {
						return err
					}
				} else if terminalStatuses == 2 {
					if g.replayDone != nil {
						close(g.replayDone)
					}
					if g.afterReplayCommand != nil {
						responseSequence++
						if err := stream.Send(&agentv1.ConnectResponse{
							Stream:  responseMetadata(responseSequence),
							Payload: &agentv1.ConnectResponse_CacheControlCommand{CacheControlCommand: g.afterReplayCommand},
						}); err != nil {
							return err
						}
					}
				}
			}
			continue
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			if g.heartbeats != nil {
				select {
				case g.heartbeats <- struct{}{}:
				default:
				}
			}
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
					HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: 1, ReceivedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
		}
	}
}

type isolationDeploymentManager struct {
	processed chan<- struct{}
}

func (m isolationDeploymentManager) Process(_ context.Context, command deployment.Command) (deployment.Result, error) {
	select {
	case m.processed <- struct{}{}:
	default:
	}
	now := time.Now().UTC()
	return deployment.Result{
		DeploymentID: command.DeploymentID, Attempt: command.Attempt, Action: command.Action,
		ConfigVersionID: command.ConfigVersionID, State: deployment.StateReverted, Sequence: 3,
		Transitions: []deployment.Transition{
			{Sequence: 1, State: deployment.StateDelivered, At: now, RunningConfigUnchanged: true},
			{Sequence: 2, State: deployment.StateReverting, At: now.Add(time.Millisecond), RunningConfigUnchanged: true},
			{Sequence: 3, State: deployment.StateReverted, At: now.Add(2 * time.Millisecond), RunningConfigUnchanged: true},
		},
	}, nil
}

func (isolationDeploymentManager) Pointers() (deployment.Pointers, error) {
	return deployment.Pointers{}, nil
}

func (g *cacheControlGateway) states() []agentv1.CacheControlState {
	g.mu.Lock()
	defer g.mu.Unlock()
	states := make([]agentv1.CacheControlState, len(g.statuses))
	for index, status := range g.statuses {
		states[index] = status.State
	}
	return states
}
