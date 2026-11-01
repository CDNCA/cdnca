package gatewayclient

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/sshaccess"
	contract "github.com/cdnca/cdnca/libs/edgeconfig/sshaccess"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sshAccessRunnerStub struct {
	mu    sync.Mutex
	calls int
	fail  error
}

func (runner *sshAccessRunnerStub) Run(context.Context, []byte, ...string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls++
	return runner.fail
}

func newTestSSHAccessRuntime(t *testing.T, runner sshaccess.Runner) (*SSHAccessRuntime, *sshaccess.Manager, string) {
	t.Helper()
	nodeID := uuid.NewString()
	manager, err := sshaccess.NewManager(runner, filepath.Join(t.TempDir(), "state.json"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewSSHAccessRuntime(nodeID, manager, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	manager.OnRevert(runtime.Reverted)
	return runtime, manager, nodeID
}

func sshAccessCommand(nodeID string, revision uint64, operation string) *agentv1.SSHAccessCommand {
	command := &agentv1.SSHAccessCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, Operation: operation,
	}
	if operation == contract.OperationApply {
		command.Enabled, command.SshPort, command.Cidrs = true, 22, []string{"192.0.2.10/32"}
	}
	return command
}

// apply → applied, repeated apply → same state (not applied twice),
// confirm → confirmed, confirm of an unknown revision → failed.
func TestSSHAccessRuntimeApplyConfirmAndReplay(t *testing.T) {
	runner := &sshAccessRunnerStub{}
	runtime, _, nodeID := newTestSSHAccessRuntime(t, runner)
	apply := sshAccessCommand(nodeID, 3, contract.OperationApply)
	receipt, err := runtime.Handle(context.Background(), apply)
	if err != nil || receipt.State != contract.StateApplied || receipt.Revision != 3 || receipt.CommandEventId != apply.Event.EventId ||
		receipt.FailureCode != "" || runner.calls != 2 {
		t.Fatalf("apply receipt = %v, %v (nft calls %d)", receipt, err, runner.calls)
	}
	replayed, err := runtime.Handle(context.Background(), sshAccessCommand(nodeID, 3, contract.OperationApply))
	if err != nil || replayed.State != contract.StateApplied || runner.calls != 2 {
		t.Fatalf("replayed apply = %v, %v (nft calls %d)", replayed, err, runner.calls)
	}
	confirmed, err := runtime.Handle(context.Background(), sshAccessCommand(nodeID, 3, contract.OperationConfirm))
	if err != nil || confirmed.State != contract.StateConfirmed {
		t.Fatalf("confirm = %v, %v", confirmed, err)
	}
	// The command stream replays the newest command (the confirm) on reconnect.
	again, err := runtime.Handle(context.Background(), sshAccessCommand(nodeID, 3, contract.OperationConfirm))
	if err != nil || again.State != contract.StateConfirmed {
		t.Fatalf("replayed confirm = %v, %v", again, err)
	}
	unknown, err := runtime.Handle(context.Background(), sshAccessCommand(nodeID, 4, contract.OperationConfirm))
	if err != nil || unknown.State != contract.StateFailed || unknown.FailureCode != contract.FailureUnknownRevision {
		t.Fatalf("unknown confirm = %v, %v", unknown, err)
	}
	stale, err := runtime.Handle(context.Background(), sshAccessCommand(nodeID, 2, contract.OperationApply))
	if err != nil || stale.State != contract.StateFailed || stale.FailureCode != contract.FailureStaleRevision {
		t.Fatalf("stale apply = %v, %v", stale, err)
	}
}

func TestSSHAccessRuntimeRefusesBadPolicyAndReportsNftFailure(t *testing.T) {
	runtime, _, nodeID := newTestSSHAccessRuntime(t, &sshAccessRunnerStub{})
	wide := sshAccessCommand(nodeID, 1, contract.OperationApply)
	wide.Cidrs = []string{"0.0.0.0/0"}
	if receipt, err := runtime.Handle(context.Background(), wide); err != nil || receipt.State != contract.StateFailed ||
		receipt.FailureCode != contract.FailureInvalidPolicy {
		t.Fatalf("wide policy = %v, %v", receipt, err)
	}
	failing, _, failingNode := newTestSSHAccessRuntime(t, &sshAccessRunnerStub{fail: errors.New("nft")})
	if receipt, err := failing.Handle(context.Background(), sshAccessCommand(failingNode, 1, contract.OperationApply)); err != nil ||
		receipt.State != contract.StateFailed || receipt.FailureCode != "nft_check_failed" {
		t.Fatalf("nft failure = %v, %v", receipt, err)
	}
	// A carrier for another node ends the session.
	if _, err := runtime.Handle(context.Background(), sshAccessCommand(uuid.NewString(), 1, contract.OperationApply)); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("foreign carrier: %v", err)
	}
}

// An unconfirmed revision is reverted by the timer and reported without a
// command; a report that could not be sent is put back for the next session.
func TestSSHAccessRuntimeQueuesRollbackReport(t *testing.T) {
	runtime, manager, nodeID := newTestSSHAccessRuntime(t, &sshAccessRunnerStub{})
	if _, err := runtime.Handle(context.Background(), sshAccessCommand(nodeID, 7, contract.OperationApply)); err != nil {
		t.Fatal(err)
	}
	runtime.Reverted(sshaccess.State{Policy: sshaccess.Policy{Revision: 7}, Reverted: true, FailureCode: "confirmation_timeout"})
	select {
	case <-runtime.pendingReports():
	case <-time.After(time.Second):
		t.Fatal("rollback report not signalled")
	}
	reports := runtime.takeReports()
	if len(reports) != 1 || reports[0].State != contract.StateReverted || reports[0].Revision != 7 ||
		reports[0].CommandEventId != "" || reports[0].FailureCode != contract.FailureConfirmationTimeout || reports[0].NodeId != nodeID {
		t.Fatalf("reports = %v", reports)
	}
	runtime.requeue(reports)
	if again := runtime.takeReports(); len(again) != 1 || again[0].Event.EventId != reports[0].Event.EventId {
		t.Fatalf("requeued = %v", again)
	}
	_ = manager
}

func TestNegotiateSSHAccessV1(t *testing.T) {
	hello := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS, ApiVersion: 1}}}
	if _, err := negotiateSSHAccessV1(hello, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("enabled without runtime: %v", err)
	}
	runtime, _, _ := newTestSSHAccessRuntime(t, &sshAccessRunnerStub{})
	if enabled, err := negotiateSSHAccessV1(hello, runtime); err != nil || !enabled {
		t.Fatalf("negotiate = %v, %v", enabled, err)
	}
	hello.EnabledCapabilities[0].ApiVersion = 2
	if _, err := negotiateSSHAccessV1(hello, runtime); err == nil {
		t.Fatal("v2 accepted")
	}
}
