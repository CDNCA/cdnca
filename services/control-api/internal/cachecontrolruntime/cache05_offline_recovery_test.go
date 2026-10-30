package cachecontrolruntime

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestCACHE05SchedulerPresenceFailurePreventsClaimMutation(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.ClaimBatch = 2
	config.Clock = func() time.Time { return runtimeTestNow }
	scopeA, scopeB, nodeA, nodeB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	control := &cache05SchedulerControl{claims: map[uuid.UUID][]cachecontrol.Claim{
		scopeA: {claimWithIdentity(testClaim(cachecontrol.ActionPurge, cachecontrol.TargetExactURL), scopeA, nodeA)},
		scopeB: {claimWithIdentity(testClaim(cachecontrol.ActionPurge, cachecontrol.TargetExactURL), scopeB, nodeB)},
	}}
	bus := &fakeBus{}
	runtime := &Runtime{
		config: config, control: control,
		repository: &fakeRepository{scopes: []uuid.UUID{scopeA, scopeB}, nodes: []queuedNode{
			{ScopeID: scopeA, NodeID: nodeA}, {ScopeID: scopeB, NodeID: nodeB},
		}},
		leases: &cache05SchedulerLeases{online: map[uuid.UUID]bool{nodeA: true},
			failureNode: nodeB, failure: errors.New("stale presence authority")},
		bus: bus, consumer: &fakeConsumer{err: ErrNoMessage},
	}

	if _, err := runtime.RunSchedulerOnce(context.Background()); err == nil {
		t.Fatal("stale presence authority was accepted")
	}
	if control.reconcileCalls != 0 || control.claimCalls != 0 || len(bus.commands) != 0 {
		t.Fatalf("presence failure mutated scheduler state: reconcile=%d claims=%d commands=%d",
			control.reconcileCalls, control.claimCalls, len(bus.commands))
	}
}

func TestCACHE05SchedulerScansPresenceBeforeReconcileAndClaim(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.ClaimBatch = 2
	config.Clock = func() time.Time { return runtimeTestNow }
	scopeA, scopeB, nodeA, nodeB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	events := make([]string, 0, 6)
	control := &cache05SchedulerControl{events: &events, claims: map[uuid.UUID][]cachecontrol.Claim{
		scopeA: {claimWithIdentity(testClaim(cachecontrol.ActionPurge, cachecontrol.TargetExactURL), scopeA, nodeA)},
		scopeB: {claimWithIdentity(testClaim(cachecontrol.ActionPurge, cachecontrol.TargetExactURL), scopeB, nodeB)},
	}}
	runtime := &Runtime{
		config: config, control: control,
		repository: &fakeRepository{scopes: []uuid.UUID{scopeA, scopeB}, nodes: []queuedNode{
			{ScopeID: scopeA, NodeID: nodeA}, {ScopeID: scopeB, NodeID: nodeB},
		}},
		leases: &cache05SchedulerLeases{events: &events, online: map[uuid.UUID]bool{nodeA: true, nodeB: true}},
		bus:    &fakeBus{}, consumer: &fakeConsumer{err: ErrNoMessage},
	}

	result, err := runtime.RunSchedulerOnce(context.Background())
	if err != nil || result.Claimed != 2 || result.Published != 2 {
		t.Fatalf("scheduler result=%+v err=%v", result, err)
	}
	want := []string{
		"presence:" + nodeA.String(), "presence:" + nodeB.String(),
		"reconcile:" + scopeA.String(), "reconcile:" + scopeB.String(),
		"claim:" + scopeA.String(), "claim:" + scopeB.String(),
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("scheduler order=%v want=%v", events, want)
	}
}

func TestCACHE05OfflineNodeRecoversExactlyOnceWithoutStarvingOnlineTenant(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.ClaimBatch = 1
	config.Clock = func() time.Time { return runtimeTestNow }
	scopeOffline, scopeOnline, nodeOffline, nodeOnline := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	offlineClaim := claimWithIdentity(
		testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL), scopeOffline, nodeOffline)
	onlineClaim := claimWithIdentity(
		testClaim(cachecontrol.ActionPurge, cachecontrol.TargetDirectoryPrefix), scopeOnline, nodeOnline)
	control := &cache05SchedulerControl{claims: map[uuid.UUID][]cachecontrol.Claim{
		scopeOffline: {offlineClaim}, scopeOnline: {onlineClaim},
	}}
	leases := &cache05SchedulerLeases{online: map[uuid.UUID]bool{nodeOnline: true}}
	bus := &fakeBus{}
	runtime := &Runtime{
		config: config, control: control,
		repository: &fakeRepository{scopes: []uuid.UUID{scopeOffline, scopeOnline}, nodes: []queuedNode{
			{ScopeID: scopeOffline, NodeID: nodeOffline}, {ScopeID: scopeOnline, NodeID: nodeOnline},
		}},
		leases: leases, bus: bus, consumer: &fakeConsumer{err: ErrNoMessage},
	}

	first, err := runtime.RunSchedulerOnce(context.Background())
	if err != nil || first.Offline != 1 || first.Claimed != 1 || first.Published != 1 ||
		len(bus.commands) != 1 || bus.commands[0].ControlOperationId != onlineClaim.OperationID.String() {
		t.Fatalf("online tenant progress result=%+v err=%v commands=%d", first, err, len(bus.commands))
	}
	leases.online[nodeOffline] = true
	second, err := runtime.RunSchedulerOnce(context.Background())
	if err != nil || second.Claimed != 1 || second.Published != 1 || len(bus.commands) != 2 {
		t.Fatalf("offline recovery result=%+v err=%v commands=%d", second, err, len(bus.commands))
	}
	want, err := buildCommand(offlineClaim)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(bus.commands[1], want) {
		t.Fatalf("recovered command identity=%+v want=%+v", bus.commands[1], want)
	}
	third, err := runtime.RunSchedulerOnce(context.Background())
	if err != nil || third.Claimed != 0 || third.Published != 0 || len(bus.commands) != 2 {
		t.Fatalf("duplicate recovery result=%+v err=%v commands=%d", third, err, len(bus.commands))
	}
}

type cache05SchedulerControl struct {
	claims         map[uuid.UUID][]cachecontrol.Claim
	events         *[]string
	reconcileCalls int
	claimCalls     int
}

func (*cache05SchedulerControl) OpenClaims(context.Context, cachecontrol.OpenClaimsRequest) ([]cachecontrol.Claim, error) {
	return nil, nil
}

func (*cache05SchedulerControl) ResolveClaim(context.Context, cachecontrol.ClaimIdentity) (cachecontrol.Claim, error) {
	return cachecontrol.Claim{}, cachecontrol.ErrNotFound
}

func (control *cache05SchedulerControl) ReconcileExpired(_ context.Context, scopeID uuid.UUID, _ string) error {
	control.reconcileCalls++
	cache05AppendSchedulerEvent(control.events, "reconcile:"+scopeID.String())
	return nil
}

func (control *cache05SchedulerControl) Claim(_ context.Context,
	request cachecontrol.ClaimRequest,
) ([]cachecontrol.Claim, error) {
	control.claimCalls++
	cache05AppendSchedulerEvent(control.events, "claim:"+request.ScopeID.String())
	claims := control.claims[request.ScopeID]
	for index, claim := range claims {
		for _, nodeID := range request.OnlineNodeIDs {
			if claim.NodeID == nodeID {
				control.claims[request.ScopeID] = append(claims[:index], claims[index+1:]...)
				return []cachecontrol.Claim{claim}, nil
			}
		}
	}
	return nil, nil
}

func (*cache05SchedulerControl) Report(context.Context,
	cachecontrol.ReportRequest,
) (cachecontrol.ReportResult, error) {
	return cachecontrol.ReportResult{}, nil
}

type cache05SchedulerLeases struct {
	online      map[uuid.UUID]bool
	failureNode uuid.UUID
	failure     error
	events      *[]string
}

func (leases *cache05SchedulerLeases) Exists(_ context.Context, nodeID uuid.UUID) (bool, error) {
	cache05AppendSchedulerEvent(leases.events, "presence:"+nodeID.String())
	if nodeID == leases.failureNode {
		return false, leases.failure
	}
	return leases.online[nodeID], nil
}

func cache05AppendSchedulerEvent(events *[]string, event string) {
	if events != nil {
		*events = append(*events, event)
	}
}

func (control *cache05SchedulerControl) SyncCarryingNodes(context.Context, uuid.UUID, string) (int, error) { return 0, nil }
