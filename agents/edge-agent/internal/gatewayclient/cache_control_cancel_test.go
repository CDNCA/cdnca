package gatewayclient

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func testCacheControlCancel(command *agentv1.CacheControlCommand) *agentv1.CacheControlCancel {
	return &agentv1.CacheControlCancel{
		Event:    &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		CancelId: uuid.NewString(), TaskId: command.TaskId, ScopeId: command.ScopeId, TenantId: command.TenantId,
		SiteId: command.SiteId, NodeId: command.NodeId, ControlOperationId: command.ControlOperationId,
		LeaseId: command.LeaseId, Attempt: command.Attempt, RequestedTime: timestamppb.Now(),
	}
}

func cacheCancelFixture(t *testing.T, command *agentv1.CacheControlCommand, manager CacheTaskManager, fixed time.Time) (*Client, string) {
	t.Helper()
	store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := store.putCommand(command, cacheControlDeliveredStatus(command, fixed))
	if err != nil {
		t.Fatal(err)
	}
	return &Client{cacheStore: store, cacheTasks: manager, cacheCancels: newCacheCancelRegistry(), now: func() time.Time { return fixed }}, record.RecordKey
}

func terminalOf(t *testing.T, client *Client, key string) (*cacheControlDurableRecord, *agentv1.CacheControlStatus) {
	t.Helper()
	record, err := client.cacheStore.record(key)
	if err != nil || record == nil || !record.ExecutionDone {
		t.Fatalf("record=%+v err=%v", record, err)
	}
	statuses, err := cacheControlStatusesFromRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	return record, statuses[len(statuses)-1]
}

// A task cancelled while still queued never reaches the cache manager.
func TestCacheCancelBeforeStartNeverRunsTask(t *testing.T) {
	fixed := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	command := testCacheControlCommandWithTwoTargets()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	manager := &fakeCacheTaskManager{execute: func(cachetask.Task) (cachetask.Result, error) {
		t.Fatal("a cancelled task was executed")
		return cachetask.Result{}, nil
	}}
	client, key := cacheCancelFixture(t, command, manager, fixed)
	cancel := testCacheControlCancel(command)
	client.cacheCancels.request(key)
	if err := client.executeCacheControlRecord(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	record, terminal := terminalOf(t, client, key)
	if terminal.State != agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED || len(terminal.Results) != 2 ||
		terminal.Results[1].ResultCode != "task_cancelled" || manager.calls != 0 {
		t.Fatalf("terminal=%+v calls=%d", terminal, manager.calls)
	}
	receipt := cacheCancelReceipt(cancel, record, fixed)
	if receipt.Outcome != agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED ||
		receipt.CancelledTargets != 2 || receipt.SucceededTargets != 0 || receipt.GetEvent().GetCausationId() != cancel.Event.EventId {
		t.Fatalf("receipt=%+v", receipt)
	}
}

// A running task's context is cancelled; the targets it finished keep their
// result and the receipt counts both.
func TestCacheCancelWhileRunningStopsRemainingTargets(t *testing.T) {
	fixed := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	command := testCacheControlCommandWithTwoTargets()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	started := make(chan struct{})
	var client *Client
	var key string
	manager := &contextCacheTaskManager{execute: func(ctx context.Context, task cachetask.Task) (cachetask.Result, error) {
		close(started)
		<-ctx.Done()
		result := successfulCacheTaskResult(task, command.Targets[0], fixed)
		result.State = cachetask.StateCancelled
		result.Items = append(result.Items, cachetask.ItemResult{
			Index: 1, Target: command.Targets[1].CanonicalUrl, TargetDigest: hex.EncodeToString(command.Targets[1].Sha256),
			Status: cachetask.ItemFailed, Code: cachetask.CodeTaskCancelled, Attempts: 1, CompletedAt: fixed,
		})
		return result, nil
	}}
	client, key = cacheCancelFixture(t, command, manager, fixed)
	done := make(chan error, 1)
	go func() { done <- client.executeCacheControlRecord(context.Background(), key) }()
	<-started
	client.cacheCancels.request(key)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not stop the running task")
	}
	record, terminal := terminalOf(t, client, key)
	if terminal.State != agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED {
		t.Fatalf("terminal=%+v", terminal)
	}
	receipt := cacheCancelReceipt(testCacheControlCancel(command), record, fixed)
	if receipt.Outcome != agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED ||
		receipt.SucceededTargets != 1 || receipt.CancelledTargets != 1 {
		t.Fatalf("receipt=%+v", receipt)
	}
}

// A task that finished before the cancel is ALREADY_COMPLETED; a task the
// node never held is NOT_RECEIVED.
func TestCacheCancelReceiptOutcomes(t *testing.T) {
	fixed := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	command := testCacheControlCommand()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	manager := &fakeCacheTaskManager{execute: func(task cachetask.Task) (cachetask.Result, error) {
		return successfulCacheTaskResult(task, command.Targets[0], fixed), nil
	}}
	client, key := cacheCancelFixture(t, command, manager, fixed)
	if err := client.executeCacheControlRecord(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	record, _ := terminalOf(t, client, key)
	cancel := testCacheControlCancel(command)
	completed := cacheCancelReceipt(cancel, record, fixed)
	if completed.Outcome != agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_ALREADY_COMPLETED || completed.SucceededTargets != 1 {
		t.Fatalf("completed receipt=%+v", completed)
	}
	if missing := cacheCancelReceipt(cancel, nil, fixed); missing.Outcome != agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_NOT_RECEIVED {
		t.Fatalf("missing receipt=%+v", missing)
	}
	other := testCacheControlCancel(command)
	other.LeaseId = uuid.NewString()
	if mismatch := cacheCancelReceipt(other, record, fixed); mismatch.Outcome != agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_NOT_RECEIVED {
		t.Fatalf("other lease receipt=%+v", mismatch)
	}
	if again := cacheCancelReceipt(cancel, record, fixed.Add(time.Minute)); again.Event.EventId != completed.Event.EventId {
		t.Fatalf("a redelivered cancel changed its receipt event: %s != %s", again.Event.EventId, completed.Event.EventId)
	}
}

func TestValidateCacheControlCancelBindsNodeAndTask(t *testing.T) {
	config := Config{NodeID: "22222222-2222-4222-8222-222222222222"}
	command := testCacheControlCommand()
	if err := validateCacheControlCancel(testCacheControlCancel(command), config); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agentv1.CacheControlCancel){
		"other node":    func(c *agentv1.CacheControlCancel) { c.NodeId = uuid.NewString() },
		"task identity": func(c *agentv1.CacheControlCancel) { c.TaskId += "x" },
		"attempt":       func(c *agentv1.CacheControlCancel) { c.Attempt = 2 },
		"cancel id":     func(c *agentv1.CacheControlCancel) { c.CancelId = "x" },
		"no time":       func(c *agentv1.CacheControlCancel) { c.RequestedTime = nil },
	} {
		cancel := testCacheControlCancel(command)
		mutate(cancel)
		if err := validateCacheControlCancel(cancel, config); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
}

func TestNegotiateCacheControlCancel(t *testing.T) {
	hello := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL, ApiVersion: cacheControlCancelAPIVersion,
	}}}
	if enabled, err := negotiateCacheControlCancelV1(hello, &fakeCacheTaskManager{}); err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	if _, err := negotiateCacheControlCancelV1(hello, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unadvertised: %v", err)
	}
	hello.EnabledCapabilities[0].ApiVersion = 2
	if _, err := negotiateCacheControlCancelV1(hello, &fakeCacheTaskManager{}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unknown version: %v", err)
	}
	if enabled, err := negotiateCacheControlCancelV1(&agentv1.GatewayHello{}, &fakeCacheTaskManager{}); err != nil || enabled {
		t.Fatalf("not enabled: %v %v", enabled, err)
	}
}

// Over the stream: the Agent advertises CACHE_CONTROL_CANCEL, a cancel for
// the running task stops it, and the receipt follows its CANCELLED status.
func TestCacheCancelRunsThroughGatewayClientStream(t *testing.T) {
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	config := testClientConfig(filepath.Join(root, "journal"))
	config.Capabilities.Features = append(config.Capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 1,
	})
	command := testCacheControlCommandWithTwoTargets()
	command.NodeId = config.NodeID
	command.TaskId = "cc-" + command.ControlOperationId + "-" + command.NodeId + "-1"
	command.Event.TaskId = &command.TaskId
	command.DeadlineTime = timestamppb.New(time.Now().Add(time.Hour))
	started := make(chan struct{})
	manager := &contextCacheTaskManager{execute: func(ctx context.Context, task cachetask.Task) (cachetask.Result, error) {
		close(started)
		<-ctx.Done()
		return cachetask.Result{}, ctx.Err()
	}}
	gateway := &cacheCancelGateway{command: command, started: started, receipts: make(chan *agentv1.CacheControlCancelReceipt, 1)}
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
	client := &Client{
		config: config, manager: noOpManager{}, store: store, overlayStore: overlayStore, cacheStore: cacheStore,
		cacheTasks: manager, cacheCancels: newCacheCancelRegistry(), now: time.Now,
	}
	connection, err := (&bufDialer{listener: listener}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithCancel(context.Background())
	sessionDone := make(chan struct{})
	go func() {
		defer close(sessionDone)
		_, _ = client.runSession(ctx, connection.Client())
	}()
	defer func() {
		cancel()
		<-sessionDone
	}()
	select {
	case receipt := <-gateway.receipts:
		if receipt.Outcome != agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED ||
			receipt.CancelledTargets != 2 || receipt.CancelId != gateway.cancelID {
			t.Fatalf("receipt=%+v", receipt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel receipt was not returned")
	}
	if !gateway.advertised {
		t.Fatal("the Agent did not advertise CACHE_CONTROL_CANCEL")
	}
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if len(gateway.states) == 0 || gateway.states[len(gateway.states)-1] != agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED {
		t.Fatalf("statuses before the receipt=%v", gateway.states)
	}
}

type contextCacheTaskManager struct {
	execute func(context.Context, cachetask.Task) (cachetask.Result, error)
}

func (m *contextCacheTaskManager) Execute(ctx context.Context, task cachetask.Task) (cachetask.Result, error) {
	return m.execute(ctx, task)
}

type cacheCancelGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	command    *agentv1.CacheControlCommand
	started    <-chan struct{}
	receipts   chan *agentv1.CacheControlCancelReceipt
	cancelID   string
	advertised bool
	mu         sync.Mutex
	states     []agentv1.CacheControlState
}

func (g *cacheCancelGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil || first.GetHello() == nil {
		return err
	}
	g.advertised = hasCapability(first.GetHello().GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL)
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(50 * time.Millisecond), OfflineAfterDuration: durationpb.New(time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128,
			EnabledCapabilities: []*agentv1.Capability{{
				Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL, ApiVersion: cacheControlCancelAPIVersion,
			}},
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
	requests := make(chan *agentv1.ConnectRequest, 16)
	go func() {
		for {
			request, err := stream.Recv()
			if err != nil {
				close(requests)
				return
			}
			requests <- request
		}
	}()
	started := g.started
	for {
		select {
		case <-started:
			started = nil
			cancel := testCacheControlCancel(g.command)
			g.cancelID = cancel.CancelId
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence), Payload: &agentv1.ConnectResponse_CacheControlCancel{CacheControlCancel: cancel},
			}); err != nil {
				return err
			}
		case request, ok := <-requests:
			if !ok {
				return nil
			}
			if status := request.GetCacheControlStatus(); status != nil {
				g.mu.Lock()
				g.states = append(g.states, status.State)
				g.mu.Unlock()
				responseSequence++
				if err := stream.Send(&agentv1.ConnectResponse{
					Stream: responseMetadata(responseSequence),
					Payload: &agentv1.ConnectResponse_CacheControlStatusAck{CacheControlStatusAck: &agentv1.CacheControlStatusAck{
						StatusEventId: status.Event.EventId, TaskId: status.TaskId, LeaseId: status.LeaseId,
						Attempt: status.Attempt, TransitionSequence: status.TransitionSequence, PersistedTime: timestamppb.Now(),
					}},
				}); err != nil {
					return err
				}
			}
			if receipt := request.GetCacheControlCancelReceipt(); receipt != nil {
				g.receipts <- receipt
			}
			if heartbeat := request.GetHeartbeat(); heartbeat != nil {
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
}

// A cancel that arrives before its command (a redelivered command after a
// nak) is answered NOT_RECEIVED, and the command that follows never runs.
func TestCacheCancelBeforeCommandStopsLateCommand(t *testing.T) {
	fixed := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	command := testCacheControlCommand()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	manager := &fakeCacheTaskManager{execute: func(cachetask.Task) (cachetask.Result, error) {
		t.Fatal("a command cancelled before it arrived was executed")
		return cachetask.Result{}, nil
	}}
	client, key := cacheCancelFixture(t, command, manager, fixed)
	// Same registry state as the session after a NOT_RECEIVED cancel.
	client.cacheCancels.request(key)
	if err := client.executeCacheControlRecord(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, terminal := terminalOf(t, client, key); terminal.State != agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED || manager.calls != 0 {
		t.Fatalf("terminal=%+v calls=%d", terminal, manager.calls)
	}
}

// CACHE-ADD-07: the worker stopping (agent shutdown) is not a cancel: the
// task's partial result is not persisted as CANCELLED (the control plane
// still runs the attempt and would get a cancellation nobody asked for);
// the record stays running and resumes after the restart.
func TestCacheControlShutdownDoesNotSettleAsCancelled(t *testing.T) {
	fixed := time.Date(2026, 10, 28, 8, 0, 0, 0, time.UTC)
	command := testCacheControlCommandWithTwoTargets()
	command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
	started := make(chan struct{})
	manager := &contextCacheTaskManager{execute: func(ctx context.Context, task cachetask.Task) (cachetask.Result, error) {
		close(started)
		<-ctx.Done()
		result := successfulCacheTaskResult(task, command.Targets[0], fixed)
		result.State = cachetask.StateCancelled
		result.Items = append(result.Items, cachetask.ItemResult{
			Index: 1, Target: command.Targets[1].CanonicalUrl, TargetDigest: hex.EncodeToString(command.Targets[1].Sha256),
			Status: cachetask.ItemFailed, Code: cachetask.CodeTaskCancelled, Attempts: 1, CompletedAt: fixed,
		})
		return result, nil
	}}
	client, key := cacheCancelFixture(t, command, manager, fixed)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.executeCacheControlRecord(ctx, key) }()
	<-started
	stop()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown err=%v", err)
	}
	record, err := client.cacheStore.record(key)
	if err != nil || record == nil || record.ExecutionDone {
		t.Fatalf("record settled on shutdown: %+v %v", record, err)
	}
}
