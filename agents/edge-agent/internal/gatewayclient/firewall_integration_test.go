package gatewayclient

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

type recordingFirewallManager struct {
	version firewall.FirewallVersion
	result  firewall.Result
	err     error
}

func (manager *recordingFirewallManager) Apply(_ context.Context, version firewall.FirewallVersion) (firewall.Result, error) {
	manager.version = version
	return manager.result, manager.err
}

func TestFirewallManagerHandlerMapsExactScopeOwnerAndAppliedStatus(t *testing.T) {
	command := testFirewallCommand(t)
	manager := &recordingFirewallManager{result: firewall.Result{
		TaskID: command.TaskId, TaskRevision: command.TaskRevision, IdempotencyKey: command.IdempotencyKey,
		TenantID: command.TenantId, SiteID: command.SiteId, PolicyVersion: command.PolicyVersion,
		ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion,
		State:                       firewall.StateApplied, ActivePolicyVersion: command.PolicyVersion,
	}}
	handler := newFirewallManagerHandler(manager, func() time.Time {
		return time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	})
	status, err := handler.HandleFirewallCommand(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if manager.version.TenantID != command.TenantId || manager.version.SiteID != command.SiteId ||
		manager.version.PolicyVersion != command.PolicyVersion || manager.version.ExpectedActivePolicyVersion != command.ExpectedActivePolicyVersion ||
		manager.version.TaskRevision != command.TaskRevision || manager.version.IdempotencyKey != command.IdempotencyKey ||
		len(manager.version.Entries) != 1 || manager.version.Entries[0].TenantID != command.Targets[0].TenantId ||
		manager.version.Entries[0].SiteID != command.Targets[0].SiteId || manager.version.Entries[0].Network != command.Targets[0].Cidr {
		t.Fatalf("manager version lost command binding: %+v", manager.version)
	}
	if status.State != agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED ||
		status.ActivePolicyVersion != command.PolicyVersion || status.ActivePolicyUnchanged || status.ErrorCode != "" {
		t.Fatalf("applied status=%+v", status)
	}
	config := DefaultConfig()
	if err := validateFirewallStatusForCommand(status, command, config); err != nil {
		t.Fatalf("mapped status rejected: %v", err)
	}
}

func TestFirewallManagerHandlerMapsMonotonicRecoveryAndStableFailure(t *testing.T) {
	command := testFirewallCommand(t)
	command.Operation = agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER
	command.RecoveryReason = agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_FALSE_POSITIVE
	command.ExpectedActivePolicyVersion = 8
	command.PolicyVersion = 9
	command.TaskRevision = 9
	command.CommandSha256 = mustFirewallCommandDigest(t, command)
	manager := &recordingFirewallManager{result: firewall.Result{
		TaskID: command.TaskId, TaskRevision: command.TaskRevision, IdempotencyKey: command.IdempotencyKey,
		TenantID: command.TenantId, SiteID: command.SiteId, PolicyVersion: command.PolicyVersion,
		ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion,
		State:                       firewall.StateApplied, ActivePolicyVersion: command.PolicyVersion,
	}}
	handler := newFirewallManagerHandler(manager, time.Now)
	status, err := handler.HandleFirewallCommand(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if manager.version.Operation != firewall.OperationRecover || manager.version.RecoveryReason != firewall.RecoveryReasonFalsePositive ||
		status.State != agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK || status.ActivePolicyVersion != 9 {
		t.Fatalf("recovery mapping version=%+v status=%+v", manager.version, status)
	}

	failedCommand := proto.Clone(command).(*agentv1.FirewallCommand)
	failedCommand.Operation = agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY
	failedCommand.RecoveryReason = agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE
	failedCommand.CommandSha256 = mustFirewallCommandDigest(t, failedCommand)
	manager.result = firewall.Result{
		TaskID: failedCommand.TaskId, TaskRevision: failedCommand.TaskRevision, IdempotencyKey: failedCommand.IdempotencyKey,
		TenantID: failedCommand.TenantId, SiteID: failedCommand.SiteId, PolicyVersion: failedCommand.PolicyVersion,
		ExpectedActivePolicyVersion: failedCommand.ExpectedActivePolicyVersion,
		State:                       firewall.StateFailed, ActivePolicyVersion: failedCommand.ExpectedActivePolicyVersion,
		RunningVersionUnchanged: true, ErrorCode: "CHECK_FAILED",
	}
	failed, err := handler.HandleFirewallCommand(context.Background(), failedCommand)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED || !failed.ActivePolicyUnchanged ||
		failed.ActivePolicyVersion != failedCommand.ExpectedActivePolicyVersion || failed.ErrorCode != "CHECK_FAILED" {
		t.Fatalf("failed status=%+v", failed)
	}
}
