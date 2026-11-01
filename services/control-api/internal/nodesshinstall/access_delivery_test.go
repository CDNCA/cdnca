package nodesshinstall

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/sshaccess"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func accessTarget(state string) AccessTarget {
	return AccessTarget{NodeID: uuid.New(), Host: "198.51.100.20", Enabled: true, SSHPort: 22,
		CIDRs: []string{"192.0.2.10/32"}, Revision: 2, State: state, Online: true, Capable: true}
}

func TestNextAccessAction(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	recent, old := now.Add(-10*time.Second), now.Add(-2*time.Minute)
	applied := now.Add(-time.Minute)
	expired := now.Add(-contract.RollbackWindow)
	for name, test := range map[string]struct {
		mutate func(*AccessTarget)
		want   AccessAction
	}{
		"pending, never sent":          {func(*AccessTarget) {}, AccessPublishApply},
		"pending, offline":             {func(target *AccessTarget) { target.Online = false }, AccessNone},
		"pending, node not capable":    {func(target *AccessTarget) { target.Capable = false }, AccessFailNotSupported},
		"pending, offline not capable": {func(target *AccessTarget) { target.Online, target.Capable = false, false }, AccessNone},
		"pending, sent just now": {func(target *AccessTarget) {
			target.PublishedRevision, target.PublishedOperation, target.PublishedAt = 2, contract.OperationApply, &recent
		}, AccessNone},
		"pending, older revision sent": {func(target *AccessTarget) {
			target.PublishedRevision, target.PublishedOperation, target.PublishedAt = 1, contract.OperationApply, &recent
		}, AccessPublishApply},
		"pending, unanswered": {func(target *AccessTarget) {
			target.PublishedRevision, target.PublishedOperation, target.PublishedAt = 2, contract.OperationApply, &old
		}, AccessPublishApply},
		"applied, probe": {func(target *AccessTarget) {
			target.State, target.AppliedAt, target.PublishedOperation, target.PublishedAt = AccessApplied, &applied, contract.OperationApply, &recent
		}, AccessProbeAndConfirm},
		"applied, confirm sent": {func(target *AccessTarget) {
			target.State, target.AppliedAt, target.PublishedOperation, target.PublishedAt = AccessApplied, &applied, contract.OperationConfirm, &recent
		}, AccessNone},
		"applied, confirm unanswered": {func(target *AccessTarget) {
			target.State, target.AppliedAt, target.PublishedOperation, target.PublishedAt = AccessApplied, &applied, contract.OperationConfirm, &old
		}, AccessRepublishConfirm},
		"applied, past the rollback window": {func(target *AccessTarget) {
			target.State, target.AppliedAt, target.PublishedOperation = AccessApplied, &expired, contract.OperationApply
		}, AccessNone},
		"confirmed":  {func(target *AccessTarget) { target.State = AccessConfirmed }, AccessNone},
		"reverted":   {func(target *AccessTarget) { target.State = AccessReverted }, AccessNone},
		"failed":     {func(target *AccessTarget) { target.State = AccessFailed }, AccessNone},
		"disable op": {func(target *AccessTarget) { target.Enabled, target.CIDRs = false, nil }, AccessPublishApply},
	} {
		target := accessTarget(AccessPending)
		test.mutate(&target)
		if got := NextAccessAction(target, now); got != test.want {
			t.Errorf("%s: action %d, want %d", name, got, test.want)
		}
	}
}

func TestAccessReceiptTransition(t *testing.T) {
	receipt := func(state, code string) *agentv1.SSHAccessReceipt {
		return &agentv1.SSHAccessReceipt{NodeId: uuid.NewString(), Revision: 2, State: state, FailureCode: code}
	}
	for name, test := range map[string]struct {
		current string
		enabled bool
		receipt *agentv1.SSHAccessReceipt
		want    AccessReceiptUpdate
		ok      bool
	}{
		"applied":                  {AccessPending, true, receipt(contract.StateApplied, ""), AccessReceiptUpdate{State: AccessApplied, Applied: true}, true},
		"disable applied is final": {AccessPending, false, receipt(contract.StateApplied, ""), AccessReceiptUpdate{State: AccessConfirmed, Applied: true, Confirmed: true}, true},
		"confirmed":                {AccessApplied, true, receipt(contract.StateConfirmed, ""), AccessReceiptUpdate{State: AccessConfirmed, Confirmed: true}, true},
		"reverted by timeout": {AccessApplied, true, receipt(contract.StateReverted, contract.FailureConfirmationTimeout),
			AccessReceiptUpdate{State: AccessReverted, FailureCode: contract.FailureConfirmationTimeout}, true},
		"not supported": {AccessPending, true, receipt(contract.StateFailed, contract.FailureNotSupported),
			AccessReceiptUpdate{State: AccessFailed, FailureCode: contract.FailureNotSupported}, true},
		"late applied after confirm": {AccessConfirmed, true, receipt(contract.StateApplied, ""), AccessReceiptUpdate{}, false},
		"late reverted after confirm": {AccessConfirmed, true, receipt(contract.StateReverted, contract.FailureConfirmationTimeout),
			AccessReceiptUpdate{}, false},
		"applied twice": {AccessApplied, true, receipt(contract.StateApplied, ""), AccessReceiptUpdate{}, false},
	} {
		got, ok := AccessReceiptTransition(test.current, test.enabled, test.receipt)
		if ok != test.ok || got != test.want {
			t.Errorf("%s: %+v %v, want %+v %v", name, got, ok, test.want, test.ok)
		}
	}
}

type accessStoreFake struct {
	mu        sync.Mutex
	targets   map[uuid.UUID]*AccessTarget
	enabled   map[uuid.UUID]bool
	now       func() time.Time
	reportErr error
}

func (store *accessStoreFake) DueAccess(context.Context, int) ([]AccessTarget, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := []AccessTarget{}
	for _, target := range store.targets {
		if target.State == AccessPending || target.State == AccessApplied {
			out = append(out, *target)
		}
	}
	return out, nil
}

func (store *accessStoreFake) MarkAccessPublished(_ context.Context, nodeID uuid.UUID, revision int64, operation string, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	target := store.targets[nodeID]
	if target.Revision == revision {
		target.PublishedRevision, target.PublishedOperation, target.PublishedAt = revision, operation, &at
	}
	return nil
}

func (store *accessStoreFake) FailAccess(_ context.Context, nodeID uuid.UUID, revision int64, code string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if target := store.targets[nodeID]; target.Revision == revision {
		target.State = AccessFailed
	}
	return nil
}

func (store *accessStoreFake) ReportAccess(_ context.Context, nodeID uuid.UUID, receipt *agentv1.SSHAccessReceipt) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.reportErr != nil {
		return false, store.reportErr
	}
	target := store.targets[nodeID]
	if target == nil || target.Revision != int64(receipt.Revision) {
		return false, nil
	}
	update, ok := AccessReceiptTransition(target.State, target.Enabled, receipt)
	if !ok {
		return false, nil
	}
	target.State = update.State
	if update.Applied {
		at := store.now()
		target.AppliedAt = &at
	}
	return true, nil
}

func (store *accessStoreFake) state(nodeID uuid.UUID) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.targets[nodeID].State
}

type accessTransportFake struct {
	mu        sync.Mutex
	published []*agentv1.SSHAccessCommand
}

func (transport *accessTransportFake) Publish(_ context.Context, command *agentv1.SSHAccessCommand) error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.published = append(transport.published, proto.Clone(command).(*agentv1.SSHAccessCommand))
	return nil
}
func (*accessTransportFake) NextReceipt(context.Context) (AccessReceiptDelivery, error) {
	return nil, nil
}

func (transport *accessTransportFake) operations() []string {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	out := []string{}
	for _, command := range transport.published {
		out = append(out, command.Operation)
	}
	return out
}

type accessProberFake struct {
	err   error
	calls int
}

func (prober *accessProberFake) FetchHostKey(context.Context, string, int) (string, error) {
	prober.calls++
	return "SHA256:" + "A", prober.err
}

type accessReceiptFake struct {
	receipt     *agentv1.SSHAccessReceipt
	acked, naks int
}

func (r *accessReceiptFake) Receipt() *agentv1.SSHAccessReceipt { return r.receipt }
func (r *accessReceiptFake) Ack(context.Context) error          { r.acked++; return nil }
func (r *accessReceiptFake) Nak(context.Context) error          { r.naks++; return nil }

func newAccessDeliveryFixture(t *testing.T, prober *accessProberFake) (*AccessDelivery, *accessStoreFake, *accessTransportFake, *AccessTarget, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	clock := &now
	target := accessTarget(AccessPending)
	store := &accessStoreFake{targets: map[uuid.UUID]*AccessTarget{target.NodeID: &target}, now: func() time.Time { return *clock }}
	transport := &accessTransportFake{}
	delivery, err := NewAccessDelivery(AccessDeliveryConfig{Store: store, Transport: transport, Prober: prober,
		Interval: time.Second, Now: func() time.Time { return *clock }})
	if err != nil {
		t.Fatal(err)
	}
	return delivery, store, transport, &target, clock
}

func nodeReceipt(target *AccessTarget, state, code string) *accessReceiptFake {
	return &accessReceiptFake{receipt: &agentv1.SSHAccessReceipt{NodeId: target.NodeID.String(), Revision: uint64(target.Revision),
		State: state, FailureCode: code}}
}

// pending → apply sent → applied → sshd probe ok → confirm sent → confirmed.
func TestAccessDeliveryApplyProbeConfirm(t *testing.T) {
	prober := &accessProberFake{}
	delivery, store, transport, target, _ := newAccessDeliveryFixture(t, prober)
	ctx := context.Background()
	if err := delivery.PublishOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ops := transport.operations(); len(ops) != 1 || ops[0] != contract.OperationApply {
		t.Fatalf("published %v", ops)
	}
	command := transport.published[0]
	if !command.Enabled || command.SshPort != 22 || len(command.Cidrs) != 1 || command.Revision != 2 || command.NodeId != target.NodeID.String() {
		t.Fatalf("apply command = %v", command)
	}
	if err := delivery.PublishOnce(ctx); err != nil || len(transport.operations()) != 1 {
		t.Fatalf("re-sent before the republish interval: %v", transport.operations())
	}
	applied := nodeReceipt(target, contract.StateApplied, "")
	delivery.HandleReceipt(ctx, applied)
	if applied.acked != 1 || store.state(target.NodeID) != AccessApplied {
		t.Fatalf("applied receipt: acked %d state %s", applied.acked, store.state(target.NodeID))
	}
	if err := delivery.PublishOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ops := transport.operations(); prober.calls != 1 || len(ops) != 2 || ops[1] != contract.OperationConfirm {
		t.Fatalf("probe %d, published %v", prober.calls, ops)
	}
	if confirm := transport.published[1]; confirm.Enabled || confirm.SshPort != 0 || len(confirm.Cidrs) != 0 {
		t.Fatalf("confirm carries a policy: %v", confirm)
	}
	delivery.HandleReceipt(ctx, nodeReceipt(target, contract.StateConfirmed, ""))
	if store.state(target.NodeID) != AccessConfirmed {
		t.Fatalf("state %s", store.state(target.NodeID))
	}
	if err := delivery.PublishOnce(ctx); err != nil || len(transport.operations()) != 2 {
		t.Fatalf("confirmed row acted on again: %v", transport.operations())
	}
}

// sshd unreachable through the new rules: no confirm is sent, the node's
// timer reverts and its report moves the row to reverted.
func TestAccessDeliveryProbeFailureWaitsForRollback(t *testing.T) {
	prober := &accessProberFake{err: errors.New("connection timed out")}
	delivery, store, transport, target, clock := newAccessDeliveryFixture(t, prober)
	ctx := context.Background()
	_ = delivery.PublishOnce(ctx)
	delivery.HandleReceipt(ctx, nodeReceipt(target, contract.StateApplied, ""))
	for i := 0; i < 3; i++ {
		*clock = clock.Add(time.Minute)
		if err := delivery.PublishOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ops := transport.operations(); len(ops) != 1 || prober.calls != 3 {
		t.Fatalf("published %v after %d failed probes", ops, prober.calls)
	}
	// Past the rollback window the worker stops probing.
	*clock = clock.Add(contract.RollbackWindow)
	_ = delivery.PublishOnce(ctx)
	if prober.calls != 3 {
		t.Fatalf("probed past the rollback window: %d", prober.calls)
	}
	delivery.HandleReceipt(ctx, &accessReceiptFake{receipt: &agentv1.SSHAccessReceipt{NodeId: target.NodeID.String(),
		Revision: 2, State: contract.StateReverted, FailureCode: contract.FailureConfirmationTimeout}})
	if store.state(target.NodeID) != AccessReverted {
		t.Fatalf("state %s", store.state(target.NodeID))
	}
}

// A node without SSH_ACCESS v1 is failed not_supported without a command; a
// receipt of an older revision is ignored; a store error naks the receipt.
func TestAccessDeliveryNotSupportedAndStaleReceipts(t *testing.T) {
	delivery, store, transport, target, _ := newAccessDeliveryFixture(t, &accessProberFake{})
	ctx := context.Background()
	store.targets[target.NodeID].Capable = false
	_ = delivery.PublishOnce(ctx)
	if store.state(target.NodeID) != AccessFailed || len(transport.operations()) != 0 {
		t.Fatalf("state %s, published %v", store.state(target.NodeID), transport.operations())
	}
	other, _, _, otherTarget, _ := newAccessDeliveryFixture(t, &accessProberFake{})
	stale := nodeReceipt(otherTarget, contract.StateApplied, "")
	stale.receipt.Revision = 1
	other.HandleReceipt(ctx, stale)
	if stale.acked != 1 {
		t.Fatal("stale receipt not acknowledged")
	}
	failing, failingStore, _, failingTarget, _ := newAccessDeliveryFixture(t, &accessProberFake{})
	failingStore.reportErr = errors.New("database down")
	pending := nodeReceipt(failingTarget, contract.StateApplied, "")
	failing.HandleReceipt(ctx, pending)
	if pending.naks != 1 || pending.acked != 0 {
		t.Fatalf("store error: acked %d naks %d", pending.acked, pending.naks)
	}
	bad := &accessReceiptFake{receipt: &agentv1.SSHAccessReceipt{NodeId: "x", Revision: 2, State: contract.StateApplied}}
	failing.HandleReceipt(ctx, bad)
	if bad.acked != 1 {
		t.Fatal("malformed receipt not dropped")
	}
}

func TestAccessCapableReadsSessionSnapshot(t *testing.T) {
	encode := func(features ...*agentv1.Capability) []byte {
		encoded, err := proto.Marshal(&agentv1.AgentCapabilities{Features: features})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	if !AccessCapable(encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS, ApiVersion: 1})) {
		t.Fatal("SSH_ACCESS v1 not recognised")
	}
	if AccessCapable(nil) || AccessCapable(encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: 1})) {
		t.Fatal("node without SSH_ACCESS reported capable")
	}
}
