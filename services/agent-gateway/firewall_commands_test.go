package gateway

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ FirewallCommandBus = (*NATSCommandBus)(nil)

func TestFirewallBusUsesDedicatedTypedContract(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	command := testFirewallCommand()
	if config.FirewallCommandStream == config.CommandStream || config.FirewallStatusStream == config.StatusStream {
		t.Fatal("firewall streams must not share deployment streams")
	}
	if got := firewallCommandSubject(config, testFirewallNodeID); got == config.CommandSubjectPrefix+"."+testFirewallNodeID {
		t.Fatal("firewall commands must not use the deployment subject")
	}
	firstStatusSubject := firewallStatusSubject(config, testFirewallNodeID, command.TaskId, command.CommandSha256)
	if firstStatusSubject == config.StatusSubjectPrefix+"."+testFirewallNodeID {
		t.Fatal("firewall status must not use the deployment subject")
	}
	changedDigest := append([]byte(nil), command.CommandSha256...)
	changedDigest[0] ^= 0xff
	if firstStatusSubject == firewallStatusSubject(config, testFirewallNodeID, command.TaskId, changedDigest) {
		t.Fatal("firewall status subject does not bind the full command digest")
	}
}

func TestValidateFirewallCommandBindsNodeAndDigest(t *testing.T) {
	command := testFirewallCommand()
	if err := validateFirewallCommand(command, testFirewallNodeID); err != nil {
		t.Fatalf("valid firewall command rejected: %v", err)
	}

	wrongNode := proto.Clone(command).(*agentv1.FirewallCommand)
	wrongNode.NodeId = uuid.NewString()
	if err := validateFirewallCommand(wrongNode, testFirewallNodeID); err == nil {
		t.Fatal("wrong node identity was accepted")
	}

	wrongDigest := proto.Clone(command).(*agentv1.FirewallCommand)
	wrongDigest.CommandSha256 = bytes.Repeat([]byte{0x42}, sha256.Size)
	if err := validateFirewallCommand(wrongDigest, testFirewallNodeID); err == nil {
		t.Fatal("command digest mismatch was accepted")
	}
}

func TestValidateFirewallStatusBindsCommandIdentity(t *testing.T) {
	command := testFirewallCommand()
	status := testFirewallStatus(command)
	if err := validateFirewallStatus(status, command, testFirewallNodeID); err != nil {
		t.Fatalf("valid firewall status rejected: %v", err)
	}

	status.TenantId = uuid.NewString()
	if err := validateFirewallStatus(status, command, testFirewallNodeID); err == nil {
		t.Fatal("status scope conflict was accepted")
	}

	rollbackFailed := testFirewallStatus(command)
	rollbackFailed.State = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED
	rollbackFailed.ActivePolicyVersion = 0
	rollbackFailed.ActivePolicyUnchanged = false
	rollbackFailed.ErrorCode = "ROLLBACK_FAILED"
	if err := validateFirewallStatus(rollbackFailed, command, testFirewallNodeID); err != nil {
		t.Fatalf("rollback failure with unknown active policy rejected: %v", err)
	}

	baselineCommand := proto.Clone(command).(*agentv1.FirewallCommand)
	baselineCommand.PolicyVersion = 1
	baselineCommand.ExpectedActivePolicyVersion = 0
	sealTestFirewallCommand(baselineCommand)
	baselineFailure := testFirewallStatus(baselineCommand)
	baselineFailure.State = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED
	baselineFailure.ActivePolicyVersion = 0
	baselineFailure.ActivePolicyUnchanged = true
	baselineFailure.ErrorCode = "APPLY_FAILED"
	if err := validateFirewallStatus(baselineFailure, baselineCommand, testFirewallNodeID); err != nil {
		t.Fatalf("baseline failure preserving expected active zero rejected: %v", err)
	}
}

func TestFirewallStatusPublicationIsIdempotentByDigest(t *testing.T) {
	command := testFirewallCommand()
	status := testFirewallStatus(command)
	first := firewallStatusIdentity(command)
	second := firewallStatusIdentity(command)
	if first != second {
		t.Fatal("firewall status identity is not stable")
	}
	if !firewallStatusEqual(status, proto.Clone(status).(*agentv1.FirewallStatus)) {
		t.Fatal("identical status was not recognized as replay")
	}
	replayed := proto.Clone(status).(*agentv1.FirewallStatus)
	replayed.Event.OccurredTime = timestamppb.New(status.Event.OccurredTime.AsTime().Add(time.Second))
	if !firewallStatusEqual(status, replayed) {
		t.Fatal("reconnect replay with only occurred_time drift was rejected")
	}
	replayed.Event.EventId = uuid.NewString()
	if firewallStatusEqual(status, replayed) {
		t.Fatal("reconnect replay accepted a non-time identity conflict")
	}
	changed := proto.Clone(status).(*agentv1.FirewallStatus)
	changed.ErrorCode = "different"
	if firewallStatusEqual(status, changed) {
		t.Fatal("status conflict was accepted as an idempotent replay")
	}
}

func testFirewallStatus(command *agentv1.FirewallCommand) *agentv1.FirewallStatus {
	causationID, taskID := command.Event.EventId, command.TaskId
	return &agentv1.FirewallStatus{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: command.Event.RequestId, OccurredTime: timestamppb.Now(),
			CausationId: &causationID, TaskId: &taskID,
		},
		Schema:                      command.Schema,
		TaskId:                      command.TaskId,
		TaskRevision:                command.TaskRevision,
		IdempotencyKey:              command.IdempotencyKey,
		TenantId:                    command.TenantId,
		SiteId:                      command.SiteId,
		NodeId:                      command.NodeId,
		PolicyVersion:               command.PolicyVersion,
		ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion,
		Operation:                   command.Operation,
		RecoveryReason:              command.RecoveryReason,
		CommandSha256:               append([]byte(nil), command.CommandSha256...),
		State:                       agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED,
		StatusRevision:              1,
		ActivePolicyVersion:         command.PolicyVersion,
	}
}

const testFirewallNodeID = "11111111-1111-4111-8111-111111111111"

func testFirewallCommand() *agentv1.FirewallCommand {
	taskID := "task-firewall-1"
	command := &agentv1.FirewallCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), TaskId: &taskID,
		},
		Schema:                      agentv1.FirewallSchema_FIREWALL_SCHEMA_V1,
		TaskId:                      taskID,
		TaskRevision:                2,
		IdempotencyKey:              "44444444-4444-4444-8444-444444444444",
		TenantId:                    "22222222-2222-4222-8222-222222222222",
		SiteId:                      "33333333-3333-4333-8333-333333333333",
		NodeId:                      testFirewallNodeID,
		PolicyVersion:               2,
		ExpectedActivePolicyVersion: 1,
		Operation:                   agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY,
		RecoveryReason:              agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE,
		Targets: []*agentv1.FirewallCIDRTarget{{
			Ordinal: 1, TenantId: "22222222-2222-4222-8222-222222222222", SiteId: "33333333-3333-4333-8333-333333333333",
			Action: agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY, Cidr: "192.0.2.0/24", Source: "waf", ReasonCode: "test",
		}},
		DeadlineTime: timestamppb.New(testFirewallNow()),
	}
	sealTestFirewallCommand(command)
	return command
}

func sealTestFirewallCommand(command *agentv1.FirewallCommand) {
	withoutDigest := proto.Clone(command).(*agentv1.FirewallCommand)
	withoutDigest.CommandSha256 = nil
	wire, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(withoutDigest)
	digest := sha256.Sum256(wire)
	command.CommandSha256 = digest[:]
}

func testFirewallNow() (now time.Time) {
	return time.Now().Add(time.Hour)
}
