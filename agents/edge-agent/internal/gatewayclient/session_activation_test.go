package gatewayclient

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// the first site's activation wrote the
// node's first skeleton, which made ACME_HTTP01_OVERLAY ready; the session
// reconnected to declare it while generation 1 awaited its health check, and
// the cancelled session context failed that healthy generation
// (activated -> reverting -> rollback_failed, "context canceled").

// rollbackFailedForTest marks a fake activation the way dynroute does when a
// cancelled health wait could not be compensated.
type rollbackFailedForTest struct{ err error }

func (e rollbackFailedForTest) Error() string                       { return "rollback failed: " + e.err.Error() }
func (e rollbackFailedForTest) Unwrap() error                       { return e.err }
func (e rollbackFailedForTest) RollbackFailedAfterActivation() bool { return true }

// revertedForTest marks a fake activation compensated after its context ended.
type revertedForTest struct{ err error }

func (e revertedForTest) Error() string                 { return "reverted: " + e.err.Error() }
func (e revertedForTest) Unwrap() error                 { return e.err }
func (e revertedForTest) RevertedAfterActivation() bool { return true }

// heldActivation is an activation that waits for proceed (its health
// check), or ends with its context like dynroute's WaitHealthy.
type heldActivation struct {
	started  chan struct{}
	proceed  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	calls    int
	ctxErr   error
	onCancel func(error) error // the journal error a cancelled activation reports
}

func newHeldActivation(onCancel func(error) error) *heldActivation {
	return &heldActivation{started: make(chan struct{}), proceed: make(chan struct{}), onCancel: onCancel}
}

func (h *heldActivation) wait(ctx context.Context) error {
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	h.once.Do(func() { close(h.started) })
	select {
	case <-h.proceed:
		return nil
	case <-ctx.Done():
		h.mu.Lock()
		h.ctxErr = ctx.Err()
		h.mu.Unlock()
		return h.onCancel(ctx.Err())
	}
}

func (h *heldActivation) result() (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls, h.ctxErr
}

// heldScopedRouting is scopedDynamicRouting whose apply is held.
type heldScopedRouting struct {
	*scopedDynamicRouting
	held *heldActivation
	// heldScope, when set, holds only that scope's applies.
	heldScope string
}

func (f *heldScopedRouting) ApplyDynamicRouting(ctx context.Context, deploymentID string, attempt uint32,
	release DynamicRoutingRelease) (deployment.Result, error) {
	started := time.Now()
	if f.heldScope == "" || f.heldScope == release.ConfigurationScopeID {
		if err := f.held.wait(ctx); err != nil {
			return DynamicRoutingResult(deploymentID, attempt, deployment.ActionApply, release.ConfigVersionID, started, time.Now(), err), nil
		}
	}
	return f.scopedDynamicRouting.ApplyDynamicRouting(ctx, deploymentID, attempt, release)
}

// sessionCountingGateway records, at each session's start, whether the node
// had already journaled the deployment's terminal state. The Gateway's own
// copy is no proof: the statuses sent just before a deliberate reconnect can
// be cut off by the old stream's cancellation (seen on Linux) and reach the
// Gateway from the journal on the next session (client.go runSession).
type sessionCountingGateway struct {
	*dynamicMultiGateway
	deploymentID string
	mu           sync.Mutex
	journaled    func() bool // the node's journal holds the terminal status
	sessions     []bool      // per session: terminal status journaled when it opened
}

func (g *sessionCountingGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	g.mu.Lock()
	journaled := g.journaled
	g.mu.Unlock()
	terminal := journaled != nil && journaled()
	g.mu.Lock()
	g.sessions = append(g.sessions, terminal)
	g.mu.Unlock()
	return g.dynamicMultiGateway.Connect(stream)
}

func (g *sessionCountingGateway) opened() []bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]bool(nil), g.sessions...)
}

func TestLiveCapabilityChangeWaitsForTheRunningActivation(t *testing.T) {
	h := newSiteObjectHarness(t)
	release := h.dynamicRoutingRelease(t, 1, []byte(`{"cc":1}`))
	closeGatewayClientForRestart(t, h.client)
	liveCapabilityChangeDuringActivation(t, h, "", release)
}

// A and B are queued; A finishes at once and
// its result waits in the one-slot result channel while the worker could
// already take B. B's activation is held and the capability changes during
// it: the reconnect still waits for B's terminal status.
func TestLiveCapabilityChangeWaitsForTheSecondQueuedActivation(t *testing.T) {
	h := newSiteObjectHarness(t)
	first := h.dynamicRoutingReleaseFor(t, mtScopeA, 1, []byte(`{"cc":"a"}`))
	second := h.dynamicRoutingReleaseFor(t, mtScopeB, 1, []byte(`{"cc":"b"}`))
	closeGatewayClientForRestart(t, h.client)
	liveCapabilityChangeDuringActivation(t, h, mtScopeB, first, second)
}

// liveCapabilityChangeDuringActivation delivers releases on one session;
// the activation of heldScope's (every one when "") is held while
// ACME_HTTP01_OVERLAY becomes ready. The last release is the watched one.
func liveCapabilityChangeDuringActivation(t *testing.T, h *siteObjectHarness, heldScope string, releases ...*siteObjectTestRelease) {
	t.Helper()
	release := releases[len(releases)-1]
	commands := make([]*agentv1.DeploymentCommand, len(releases))
	byID := map[string]*siteObjectTestRelease{}
	for index, item := range releases {
		commands[index], byID[item.command.DeploymentId] = item.command, item
	}
	gateway := &sessionCountingGateway{deploymentID: release.command.DeploymentId, dynamicMultiGateway: &dynamicMultiGateway{
		multiTenantGateway: &multiTenantGateway{commands: commands, holdFirst: make(chan struct{}),
			events: make(chan struct{}, 1)},
		releases: byID,
	}}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	config := h.client.config
	config.Capabilities = proto.Clone(config.Capabilities).(*agentv1.AgentCapabilities)
	for _, capability := range config.Capabilities.Features {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			capability.ApiVersion = edgeconfig.DynamicRoutingSiteRuntimeVersion
		}
	}
	store, err := objectstore.Open(filepath.Join(h.root, "dynamic-held-objects"))
	if err != nil {
		t.Fatal(err)
	}
	held := newHeldActivation(func(err error) error { return rollbackFailedForTest{err} })
	applier := &heldScopedRouting{held: held, heldScope: heldScope,
		scopedDynamicRouting: &scopedDynamicRouting{current: map[string]deployment.Pointers{}, results: map[string]deployment.Result{}}}
	consumer := &fakeACMEHTTP01Consumer{}
	fastPoll := func(client *Client) error { client.acmeHTTP01Poll = 20 * time.Millisecond; return nil }
	client, err := New(config, &bufDialer{listener: listener}, applier, h.client.trust,
		WithSiteObjectStore(store), WithDynamicRouting(applier), fastPoll, WithACMEHTTP01OverlayConsumer(consumer))
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	key := recordKey(release.command.DeploymentId, release.command.Attempt)
	gateway.mu.Lock()
	gateway.journaled = func() bool {
		record, err := client.store.record(key)
		if err != nil || record == nil || !record.ExecutionDone {
			return false
		}
		statuses, err := statusesFromRecord(record)
		return err == nil && len(statuses) > 0 &&
			statuses[len(statuses)-1].State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY
	}
	gateway.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; _ = client.Close() })

	select {
	case <-held.started:
	case <-time.After(10 * time.Second):
		t.Fatal("activation did not start")
	}
	// the activation wrote the first skeleton: the overlay capability is ready
	consumer.mu.Lock()
	consumer.ready = true
	consumer.mu.Unlock()
	time.Sleep(300 * time.Millisecond) // many readiness polls
	if sessions := gateway.opened(); len(sessions) != 1 {
		t.Fatalf("the session reconnected during the activation: %v", sessions)
	}
	close(held.proceed)

	deadline := time.After(10 * time.Second)
	for {
		// hello 由 multiTenantGateway.Connect 在它自己的锁下写入，按同一把锁读取。
		gateway.multiTenantGateway.mu.Lock()
		hello := gateway.hello
		gateway.multiTenantGateway.mu.Unlock()
		if sessions := gateway.opened(); len(sessions) >= 2 &&
			hasCapability(hello.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY) {
			if !sessions[1] {
				t.Fatalf("reconnected before the terminal status was journaled: %v", sessions)
			}
			break
		}
		select {
		case <-gateway.events:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("overlay capability not declared after the activation: sessions %v", gateway.opened())
		}
	}
	// The Gateway gets the terminal status on the old session or, replayed
	// from the journal, on the new one.
	var statuses []*agentv1.DeploymentStatus
	for {
		statuses = gateway.statusesFor(release.command.DeploymentId)
		last := statuses[len(statuses)-1]
		if terminalDeploymentState(last.State) {
			if last.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
				t.Fatalf("final state %v: %v", last.State, last.Error)
			}
			break
		}
		select {
		case <-gateway.events:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("terminal status not delivered: last state %v", last.State)
		}
	}
	for _, value := range statuses {
		if value.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED ||
			value.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING {
			t.Fatalf("healthy activation reported %v", value.State)
		}
	}
	if calls, ctxErr := held.result(); calls != 1 || ctxErr != nil {
		t.Fatalf("activation ran %d times, context error %v", calls, ctxErr)
	}
}

// heldDynamicRouting is a node-local apply that is held (heldActivation).
type heldDynamicRouting struct {
	DeploymentManager
	held *heldActivation
}

func (f *heldDynamicRouting) ApplyDynamicRouting(ctx context.Context, deploymentID string, attempt uint32,
	release DynamicRoutingRelease) (deployment.Result, error) {
	started := time.Now()
	err := f.held.wait(ctx)
	return DynamicRoutingResult(deploymentID, attempt, deployment.ActionApply, release.ConfigVersionID, started, time.Now(), err), nil
}

// A session that ends from outside (stream reset, Gateway restart) while the
// node switches does not cancel the switch: it finishes within the grace and
// its terminal state is journaled for the next session, or the grace ends it
// (compensated, journaled too). Either way the record is complete.
func TestActivationOutlivesALostSession(t *testing.T) {
	for _, test := range []struct {
		name   string
		finish bool
	}{{"finishes after the session ended", true}, {"bounded by the session loss grace", false}} {
		t.Run(test.name, func(t *testing.T) {
			held := newHeldActivation(func(err error) error { return revertedForTest{err} })
			h := newDynamicRoutingHarness(t, nil)
			closeGatewayClientForRestart(t, h.client)
			client, err := New(h.client.config, &failingDialer{}, h.manager, h.client.trust,
				WithSiteObjectStore(h.store), WithDynamicRouting(&heldDynamicRouting{DeploymentManager: h.manager, held: held}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			h.client = client
			grace := 10 * time.Second
			if !test.finish {
				grace = 150 * time.Millisecond
			}
			client.sessionLossGrace = grace
			release := h.dynamicRoutingRelease(t, 1, []byte(`{"cc":1}`))
			gateway := newSiteObjectGatewayClient(t, &siteObjectGateway{release: release})
			record, _, err := client.store.putCommand(release.command, deliveredStatus(release.command))
			if err != nil {
				t.Fatal(err)
			}
			session, endSession := context.WithCancel(t.Context())
			executed := make(chan error, 1)
			go func() { executed <- client.executeRecord(session, gateway, record.RecordKey, 1<<20) }()
			select {
			case <-held.started:
			case <-time.After(10 * time.Second):
				t.Fatal("activation did not start")
			}
			ended := time.Now()
			endSession()
			if test.finish {
				time.Sleep(50 * time.Millisecond)
				close(held.proceed)
			}
			select {
			case err := <-executed:
				if err != nil {
					t.Fatalf("executeRecord: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("activation did not end")
			}
			record, err = client.store.record(record.RecordKey)
			if err != nil {
				t.Fatal(err)
			}
			statuses, err := statusesFromRecord(record)
			if err != nil || !record.ExecutionDone || len(statuses) == 0 {
				t.Fatalf("incomplete record %+v %v", record, err)
			}
			last := statuses[len(statuses)-1].State
			calls, ctxErr := held.result()
			if calls != 1 {
				t.Fatalf("activation ran %d times", calls)
			}
			if test.finish {
				if ctxErr != nil || last != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
					t.Fatalf("state %v, activation context %v", last, ctxErr)
				}
				return
			}
			if !errors.Is(ctxErr, context.Canceled) || time.Since(ended) < grace ||
				last != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
				t.Fatalf("state %v after %v (grace %v), activation context %v", last, time.Since(ended), grace, ctxErr)
			}
		})
	}
}
