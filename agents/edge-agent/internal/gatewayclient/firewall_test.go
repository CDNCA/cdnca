package gatewayclient

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFirewallCommandDigestBindsScopeAndCIDROwnership(t *testing.T) {
	command := testFirewallCommand(t)
	original, err := firewallCommandDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	tampered := proto.Clone(command).(*agentv1.FirewallCommand)
	tampered.Targets[0].TenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	changed, err := firewallCommandDigest(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, changed) {
		t.Fatal("CIDR ownership did not change the command identity digest")
	}
}

func TestValidateFirewallCommandRejectsInvalidCarrier(t *testing.T) {
	config := DefaultConfig()
	config.NodeID = "22222222-2222-4222-8222-222222222222"
	if err := validateFirewallCommand(testFirewallCommand(t), config, time.Now()); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	tests := map[string]func(*agentv1.FirewallCommand, *Config){
		"missing tenant scope": func(command *agentv1.FirewallCommand, _ *Config) {
			command.TenantId = ""
		},
		"wrong CIDR owner": func(command *agentv1.FirewallCommand, _ *Config) {
			command.Targets[0].SiteId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"out of order policy": func(command *agentv1.FirewallCommand, _ *Config) {
			command.ExpectedActivePolicyVersion = 6
		},
		"out of order task revision": func(command *agentv1.FirewallCommand, _ *Config) {
			command.TaskRevision = command.ExpectedActivePolicyVersion
		},
		"unknown operation": func(command *agentv1.FirewallCommand, _ *Config) {
			command.Operation = agentv1.FirewallOperation(99)
		},
		"unknown target action": func(command *agentv1.FirewallCommand, _ *Config) {
			command.Targets[0].Action = agentv1.FirewallCIDRAction(99)
		},
		"target source control": func(command *agentv1.FirewallCommand, _ *Config) {
			command.Targets[0].Source = "manual\nsecret"
		},
		"missing idempotency": func(command *agentv1.FirewallCommand, _ *Config) {
			command.IdempotencyKey = ""
		},
		"wrong node": func(command *agentv1.FirewallCommand, _ *Config) {
			command.NodeId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"unordered target": func(command *agentv1.FirewallCommand, _ *Config) {
			command.Targets[0].Ordinal = 2
		},
		"unknown nested field": func(command *agentv1.FirewallCommand, _ *Config) {
			command.Targets[0].ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		},
		"oversize": func(command *agentv1.FirewallCommand, config *Config) {
			config.MaxCommandBytes = proto.Size(command) - 1
		},
		"digest conflict": func(command *agentv1.FirewallCommand, _ *Config) {
			command.CommandSha256[0] ^= 0xff
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			local := config
			command := testFirewallCommand(t)
			mutate(command, &local)
			if name != "digest conflict" && name != "unknown nested field" && name != "oversize" {
				command.CommandSha256 = mustFirewallCommandDigest(t, command)
			}
			if err := validateFirewallCommand(command, local, time.Now()); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("validateFirewallCommand() error = %v, want ErrInvalidMessage", err)
			}
		})
	}
}

func TestDispatchFirewallCommandUsesValidatedClone(t *testing.T) {
	config := DefaultConfig()
	config.NodeID = "22222222-2222-4222-8222-222222222222"
	command := testFirewallCommand(t)
	handler := &testFirewallHandler{status: testFirewallStatus(command)}
	client := &Client{config: config, firewall: handler, now: time.Now}
	status, err := client.dispatchFirewallCommand(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if status == nil || handler.command == nil || handler.command == command || !proto.Equal(handler.command, command) {
		t.Fatalf("dispatch did not preserve an immutable command carrier: status=%+v command=%+v", status, handler.command)
	}
}

func TestValidateFirewallStatusRequiresExactCommandBinding(t *testing.T) {
	config := DefaultConfig()
	command := testFirewallCommand(t)
	status := testFirewallStatus(command)
	if err := validateFirewallStatusForCommand(status, command, config); err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	tests := map[string]func(*agentv1.FirewallStatus){
		"scope":    func(status *agentv1.FirewallStatus) { status.SiteId = uuid.NewString() },
		"task":     func(status *agentv1.FirewallStatus) { status.TaskId = "fw-other" },
		"revision": func(status *agentv1.FirewallStatus) { status.TaskRevision++ },
		"digest":   func(status *agentv1.FirewallStatus) { status.CommandSha256[0] ^= 0xff },
		"state":    func(status *agentv1.FirewallStatus) { status.State = agentv1.FirewallStatusState(99) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			invalid := proto.Clone(status).(*agentv1.FirewallStatus)
			mutate(invalid)
			if err := validateFirewallStatusForCommand(invalid, command, config); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("validateFirewallStatusForCommand() error = %v, want ErrInvalidMessage", err)
			}
		})
	}
	fields := status.ProtoReflect().Descriptor().Fields()
	for _, forbidden := range []string{"targets", "cidr", "source", "secret", "rules"} {
		if fields.ByName(protoreflect.Name(forbidden)) != nil {
			t.Fatalf("FirewallStatus exposes forbidden field %q", forbidden)
		}
	}
	unknown := proto.Clone(status).(*agentv1.FirewallStatus)
	unknown.Event.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if err := validateFirewallStatusForCommand(unknown, command, config); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("status unknown field error = %v, want ErrInvalidMessage", err)
	}
	config.MaxStatusBytes = proto.Size(status) - 1
	if err := validateFirewallStatusForCommand(status, command, config); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("oversized status error = %v, want ErrInvalidMessage", err)
	}
}

func TestFirewallRecoveryRequiresReasonAndRolledBackStatus(t *testing.T) {
	config := DefaultConfig()
	config.NodeID = "22222222-2222-4222-8222-222222222222"
	command := testFirewallCommand(t)
	command.Operation = agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER
	command.RecoveryReason = agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_FALSE_POSITIVE
	command.PolicyVersion = 9
	command.ExpectedActivePolicyVersion = 8
	command.TaskRevision = 9
	command.CommandSha256 = mustFirewallCommandDigest(t, command)
	if err := validateFirewallCommand(command, config, time.Now()); err != nil {
		t.Fatalf("valid recovery rejected: %v", err)
	}
	status := testFirewallStatus(command)
	status.State = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK
	status.ActivePolicyVersion = command.PolicyVersion
	if err := validateFirewallStatusForCommand(status, command, config); err != nil {
		t.Fatalf("valid recovery status rejected: %v", err)
	}
	command.RecoveryReason = agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE
	command.CommandSha256 = mustFirewallCommandDigest(t, command)
	if err := validateFirewallCommand(command, config, time.Now()); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("recovery without reason error = %v, want ErrInvalidMessage", err)
	}
}

func TestFirewallCommandAndStatusUseConnectOneofs(t *testing.T) {
	command := testFirewallCommand(t)
	response := &agentv1.ConnectResponse{
		Payload: &agentv1.ConnectResponse_FirewallCommand{FirewallCommand: command},
	}
	if response.GetFirewallCommand() != command {
		t.Fatal("ConnectResponse did not carry FirewallCommand")
	}
	status := testFirewallStatus(command)
	request := &agentv1.ConnectRequest{
		Payload: &agentv1.ConnectRequest_FirewallStatus{FirewallStatus: status},
	}
	if request.GetFirewallStatus() != status {
		t.Fatal("ConnectRequest did not carry FirewallStatus")
	}
}

func TestFirewallCapabilityNegotiationIsExact(t *testing.T) {
	local := &agentv1.AgentCapabilities{Features: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL, ApiVersion: 1,
	}}}
	gateway := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL, ApiVersion: 1,
	}}}
	if enabled, err := negotiateFirewallControlV1(gateway, local); err != nil || !enabled {
		t.Fatalf("valid negotiation = (%t, %v), want true", enabled, err)
	}
	gateway.EnabledCapabilities[0].ApiVersion = 2
	if _, err := negotiateFirewallControlV1(gateway, local); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("version mismatch error = %v, want ErrInvalidMessage", err)
	}
	gateway.EnabledCapabilities[0].ApiVersion = 1
	if _, err := negotiateFirewallControlV1(gateway, &agentv1.AgentCapabilities{}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unadvertised capability error = %v, want ErrInvalidMessage", err)
	}
}

func testFirewallCommand(t *testing.T) *agentv1.FirewallCommand {
	t.Helper()
	taskID := "fw-task-8"
	command := &agentv1.FirewallCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), TaskId: &taskID,
		},
		Schema: agentv1.FirewallSchema_FIREWALL_SCHEMA_V1,
		TaskId: taskID, TaskRevision: 8, IdempotencyKey: uuid.NewString(),
		TenantId:      "77777777-7777-4777-8777-777777777777",
		SiteId:        "44444444-4444-4444-8444-444444444444",
		NodeId:        "22222222-2222-4222-8222-222222222222",
		PolicyVersion: 8, ExpectedActivePolicyVersion: 7,
		Operation:      agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY,
		RecoveryReason: agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE,
		Targets: []*agentv1.FirewallCIDRTarget{{
			Ordinal:  1,
			TenantId: "77777777-7777-4777-8777-777777777777",
			SiteId:   "44444444-4444-4444-8444-444444444444",
			Action:   agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY,
			Cidr:     "198.51.100.0/24", Source: "manual", ReasonCode: "abuse",
		}},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Minute)),
	}
	command.CommandSha256 = mustFirewallCommandDigest(t, command)
	return command
}

func testFirewallStatus(command *agentv1.FirewallCommand) *agentv1.FirewallStatus {
	taskID := command.TaskId
	causationID := command.Event.EventId
	return &agentv1.FirewallStatus{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: command.Event.RequestId, OccurredTime: timestamppb.Now(),
			CausationId: &causationID, TaskId: &taskID,
		},
		Schema: command.Schema, TaskId: command.TaskId, TaskRevision: command.TaskRevision,
		IdempotencyKey: command.IdempotencyKey, TenantId: command.TenantId, SiteId: command.SiteId, NodeId: command.NodeId,
		PolicyVersion: command.PolicyVersion, ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion,
		Operation: command.Operation, RecoveryReason: command.RecoveryReason,
		CommandSha256:  append([]byte(nil), command.CommandSha256...),
		State:          agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED,
		StatusRevision: 1, ActivePolicyVersion: command.PolicyVersion,
	}
}

func mustFirewallCommandDigest(t *testing.T, command *agentv1.FirewallCommand) []byte {
	t.Helper()
	digest, err := firewallCommandDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type testFirewallHandler struct {
	command *agentv1.FirewallCommand
	status  *agentv1.FirewallStatus
}

func (handler *testFirewallHandler) HandleFirewallCommand(_ context.Context, command *agentv1.FirewallCommand) (*agentv1.FirewallStatus, error) {
	handler.command = proto.Clone(command).(*agentv1.FirewallCommand)
	return proto.Clone(handler.status).(*agentv1.FirewallStatus), nil
}
