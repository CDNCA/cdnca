package l4lineswitch

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type dnsGateStub struct {
	status DNSGateStatus
	calls  int
}

func (gate *dnsGateStub) Check(context.Context, Actor, Switch) (DNSGateStatus, error) {
	gate.calls++
	return gate.status, nil
}

// FX27: a healthy new line must not retire the old nodes' listeners while DNS
// still points clients at them.
func TestHealthGateWaitsForDNSBeforeDrainingOldNodes(t *testing.T) {
	service, store, publications, targets, drains, request := switchFixture(t)
	gate := &dnsGateStub{status: DNSGateStatus{State: DNSGateRetargetPending, Owners: 2, PendingOwners: 1}}
	service.SetDNSGate(gate)
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	publications.prepareStatus = RolloutSucceeded

	waiting, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if waiting.State != StateHealthGate || store.item.State != StateHealthGate || store.item.StateRevision != started.StateRevision ||
		drains.builds != 0 || drains.publishes != 0 || targets.activates != 0 || gate.calls != 1 {
		t.Fatalf("switch advanced before DNS: state=%s stored=%s/%d builds=%d publishes=%d activates=%d",
			waiting.State, store.item.State, store.item.StateRevision, drains.builds, drains.publishes, targets.activates)
	}
	if waiting.DNSGate == nil || waiting.DNSGate.State != DNSGateRetargetPending || waiting.DNSGate.PendingOwners != 1 {
		t.Fatalf("waiting switch does not report the DNS gate: %+v", waiting.DNSGate)
	}
	encoded, err := encodeSwitch(waiting)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodeSwitch(encoded); err != nil || decoded.DNSGate != nil {
		t.Fatalf("DNS gate status must stay out of the durable state document: %v %+v", err, decoded.DNSGate)
	}

	gate.status = DNSGateStatus{State: DNSGateReady, Owners: 2}
	draining, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || draining.State != StateDrainingOld || drains.publishes != len(draining.RetiringNodes) || targets.activates != 1 {
		t.Fatalf("switch did not drain after DNS settled: %v state=%s publishes=%d", err, draining.State, drains.publishes)
	}
}

func TestDNSGateTimeoutCompensatesWithReadableCode(t *testing.T) {
	service, store, publications, _, drains, request := switchFixture(t)
	gate := &dnsGateStub{status: DNSGateStatus{State: DNSGatePropagationWait, Owners: 1}}
	service.SetDNSGate(gate)
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	publications.prepareStatus = RolloutSucceeded
	if _, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID); err != nil {
		t.Fatal(err)
	}
	late := request.Deadline.Add(time.Second)
	service.now = func() time.Time { return late }
	compensating, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || compensating.State != StateCompensatingOld || compensating.ErrorCode != "DNS_PROPAGATION_TIMEOUT" ||
		store.item.ErrorCode != "DNS_PROPAGATION_TIMEOUT" || drains.publishes != 0 {
		t.Fatalf("DNS timeout: %v state=%s code=%s publishes=%d", err, compensating.State, compensating.ErrorCode, drains.publishes)
	}
}

// Growing a line (no retiring node) has nothing to drain and never waits.
func TestDNSGateSkippedWithoutRetiringNodes(t *testing.T) {
	service, _, publications, _, _, request := switchFixture(t)
	gate := &dnsGateStub{status: DNSGateStatus{State: DNSGateRetargetPending, Owners: 1, PendingOwners: 1}}
	service.SetDNSGate(gate)
	resolver := service.snapshots.(snapshotResolver)
	from := resolver.values[request.From.ID]
	to := resolver.values[request.To.ID]
	to.NodeIDs = append(append([]uuid.UUID(nil), from.NodeIDs...), to.NodeIDs[1]) // old nodes + newA
	resolver.values[request.To.ID] = to
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	publications.prepareStatus = RolloutSucceeded
	completed, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || completed.State != StateCompleted || gate.calls != 0 {
		t.Fatalf("expansion: %v state=%s gate calls=%d", err, completed.State, gate.calls)
	}
}
