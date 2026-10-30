package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type fakeUpgradeBus struct {
	published    []byte
	publishCount atomic.Int32
	publication  *UpgradeStatusPublication
	err          error
}

func (*fakeUpgradeBus) SubscribeUpgrade(context.Context, string) (UpgradeCommandSubscription, error) {
	return nil, errors.New("unused")
}

func (b *fakeUpgradeBus) PublishUpgradeStatus(_ context.Context, nodeID string, status []byte) (UpgradeStatusPublication, error) {
	if b.err != nil {
		return UpgradeStatusPublication{}, b.err
	}
	b.published = append([]byte(nil), status...)
	b.publishCount.Add(1)
	if b.publication != nil {
		return *b.publication, nil
	}
	return UpgradeStatusPublication{Stream: UpgradeStatusStream, Sequence: 41}, nil
}

type fakeUpgradeDelivery struct {
	command UpgradeCommandRecord
	acks    atomic.Int32
	err     error
}

func (d *fakeUpgradeDelivery) Command() UpgradeCommandRecord { return d.command }
func (d *fakeUpgradeDelivery) Ack(context.Context) error {
	d.acks.Add(1)
	return d.err
}
func (*fakeUpgradeDelivery) Nak(context.Context) error { return nil }

func TestUpgradeProtoContractFieldNumbers(t *testing.T) {
	if got := int32(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE); got != 22 {
		t.Fatalf("EDGE_UPGRADE capability = %d, want 22", got)
	}
	capability := agentv1.CapabilityName(23).Descriptor().Values().ByNumber(23)
	if capability == nil || capability.Name() != "CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK" || capability.Number() != 23 {
		t.Fatalf("EDGE_UPGRADE_STATUS_PUBACK capability = %v, want field 23", capability)
	}
	assertField := func(message protoreflect.MessageDescriptor, name protoreflect.Name, number protoreflect.FieldNumber) {
		t.Helper()
		field := message.Fields().ByName(name)
		if field == nil || field.Number() != number {
			t.Fatalf("%s.%s = %v, want field %d", message.FullName(), name, field, number)
		}
	}
	assertField((&agentv1.ConnectRequest{}).ProtoReflect().Descriptor(), "upgrade_status", 8)
	assertField((&agentv1.ConnectResponse{}).ProtoReflect().Descriptor(), "upgrade_command", 10)
	assertField((&agentv1.ConnectResponse{}).ProtoReflect().Descriptor(), "upgrade_status_ack", 11)
	ack := (&agentv1.UpgradeStatusAck{}).ProtoReflect().Descriptor()
	assertField(ack, "published_stream", 6)
	assertField(ack, "published_sequence", 7)
}

func TestGatewayUpgradeStatusPubAckCapabilityDependency(t *testing.T) {
	gateway := &Gateway{config: DefaultConfig()}
	base := &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}
	pubAck := &agentv1.Capability{Name: agentv1.CapabilityName(23), ApiVersion: 1}
	for _, test := range []struct {
		name     string
		features []*agentv1.Capability
		valid    bool
	}{
		{name: "legacy base", features: []*agentv1.Capability{base}, valid: true},
		{name: "new pair", features: []*agentv1.Capability{base, pubAck}, valid: true},
		{name: "missing base", features: []*agentv1.Capability{pubAck}},
		{name: "unsupported puback version", features: []*agentv1.Capability{base, {Name: agentv1.CapabilityName(23), ApiVersion: 2}}},
		{name: "duplicate puback", features: []*agentv1.Capability{base, pubAck, pubAck}},
	} {
		t.Run(test.name, func(t *testing.T) {
			hello := validHello(testNodeID, versionRange(1, 0), 1).GetHello()
			hello.Capabilities.Features = test.features
			err := gateway.validateHello(hello)
			if test.valid && err != nil {
				t.Fatalf("valid capability set rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid PubAck capability set accepted")
			}
		})
	}
}

func TestGatewayUpgradeCommandRequiresV2RolloutBinding(t *testing.T) {
	base := validUpgradeCommandRecord(t)
	for _, test := range []struct {
		name   string
		mutate func(*upgradeCommandWire)
	}{
		{name: "outer plan", mutate: func(command *upgradeCommandWire) {
			command.PlanID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "outer revision", mutate: func(command *upgradeCommandWire) { command.PlanRevision++ }},
		{name: "outer batch", mutate: func(command *upgradeCommandWire) {
			command.BatchID = "00000000-0000-4000-8000-000000000098"
		}},
		{name: "inner v1 downgrade", mutate: func(command *upgradeCommandWire) {
			var envelope upgradeExecutionEnvelopeWire
			if err := json.Unmarshal(command.SignedExecution, &envelope); err != nil {
				t.Fatal(err)
			}
			var execution upgradeExecutionRolloutWire
			if err := json.Unmarshal(envelope.Execution, &execution); err != nil {
				t.Fatal(err)
			}
			execution.Schema = "cdnca.upgrade.execution/v1"
			envelope.Execution, _ = json.Marshal(execution)
			command.SignedExecution, _ = json.Marshal(envelope)
			digest := sha256.Sum256(command.SignedExecution)
			command.SignedExecutionSHA256 = hex.EncodeToString(digest[:])
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var command upgradeCommandWire
			if err := json.Unmarshal(base.Encoded, &command); err != nil {
				t.Fatal(err)
			}
			test.mutate(&command)
			encoded, err := json.Marshal(command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeUpgradeCommandRecord(encoded); err == nil {
				t.Fatal("unbound or downgraded upgrade command was accepted")
			}
		})
	}
}

func TestUpgradeStatusPublishesBeforeCommandAck(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	delivery := &fakeUpgradeDelivery{command: command}
	pending := pendingUpgradeCommandSet{command.CommandID: {
		command: command, deliveries: []UpgradeCommandDelivery{delivery},
	}}
	bus := &fakeUpgradeBus{}
	gateway := &Gateway{upgrades: bus, now: func() time.Time { return time.Unix(123, 0).UTC() }}
	status := validUpgradeStatusRecord(t, command)

	ack, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID, command.InstallationID,
		status.Encoded, pending, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bus.published, status.Encoded) || delivery.acks.Load() != 1 || len(pending) != 0 {
		t.Fatalf("published=%t acks=%d pending=%d", bytes.Equal(bus.published, status.Encoded), delivery.acks.Load(), len(pending))
	}
	if ack.GetStatusEventId() != status.StatusID || ack.GetCommandId() != command.CommandID || ack.GetStatusRevision() != status.StatusRevision ||
		!bytes.Equal(ack.GetStatusSha256(), status.SHA256[:]) || ack.GetPersistedTime() == nil ||
		ack.GetPublishedStream() != UpgradeStatusStream || ack.GetPublishedSequence() != 41 {
		t.Fatalf("ack = %+v", ack)
	}
}

func TestGatewayLegacyUpgradeStatusAckOmitsPubAck(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	pending := pendingUpgradeCommandSet{command.CommandID: {
		command: command, deliveries: []UpgradeCommandDelivery{&fakeUpgradeDelivery{command: command}},
	}}
	gateway := &Gateway{upgrades: &fakeUpgradeBus{}, now: time.Now}
	status := validUpgradeStatusRecord(t, command)
	ack, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID, command.InstallationID,
		status.Encoded, pending)
	if err != nil {
		t.Fatal(err)
	}
	if ack.GetPublishedStream() != "" || ack.GetPublishedSequence() != 0 {
		t.Fatalf("legacy acknowledgement exposed PubAck metadata: %+v", ack)
	}
}

func TestGatewayRejectsInvalidUpgradeStatusPublication(t *testing.T) {
	for _, publication := range []UpgradeStatusPublication{
		{Stream: "OTHER", Sequence: 41},
		{Stream: UpgradeStatusStream},
	} {
		command := validUpgradeCommandRecord(t)
		delivery := &fakeUpgradeDelivery{command: command}
		pending := pendingUpgradeCommandSet{command.CommandID: {
			command: command, deliveries: []UpgradeCommandDelivery{delivery},
		}}
		gateway := &Gateway{upgrades: &fakeUpgradeBus{publication: &publication}, now: time.Now}
		status := validUpgradeStatusRecord(t, command)
		if _, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID,
			command.InstallationID, status.Encoded, pending, true); err == nil {
			t.Fatalf("invalid publication accepted: %+v", publication)
		}
		if delivery.acks.Load() != 0 || len(pending) != 1 {
			t.Fatalf("invalid publication changed command state: acks=%d pending=%d", delivery.acks.Load(), len(pending))
		}
	}
}

func TestUpgradeStatusPublishFailureDoesNotAckCommand(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	delivery := &fakeUpgradeDelivery{command: command}
	pending := pendingUpgradeCommandSet{command.CommandID: {command: command, deliveries: []UpgradeCommandDelivery{delivery}}}
	gateway := &Gateway{upgrades: &fakeUpgradeBus{err: errors.New("unavailable")}, now: time.Now}
	status := validUpgradeStatusRecord(t, command)
	if _, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID, command.InstallationID,
		status.Encoded, pending); err == nil {
		t.Fatal("publish failure was accepted")
	}
	if delivery.acks.Load() != 0 || len(pending) != 1 {
		t.Fatalf("acks=%d pending=%d", delivery.acks.Load(), len(pending))
	}
}

func TestUpgradeAcceptedStatusBindsInFlightRolloutMetadata(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	for _, test := range []struct {
		name   string
		mutate func(*upgradeStatusWire)
	}{
		{name: "plan id", mutate: func(status *upgradeStatusWire) {
			status.PlanID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "plan revision", mutate: func(status *upgradeStatusWire) { status.PlanRevision++ }},
		{name: "command digest", mutate: func(status *upgradeStatusWire) {
			status.CommandSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := validUpgradeStatusRecord(t, command)
			var wire upgradeStatusWire
			if err := json.Unmarshal(status.Encoded, &wire); err != nil {
				t.Fatal(err)
			}
			test.mutate(&wire)
			encoded, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			delivery := &fakeUpgradeDelivery{command: command}
			pending := pendingUpgradeCommandSet{command.CommandID: {
				command: command, deliveries: []UpgradeCommandDelivery{delivery},
			}}
			bus := &fakeUpgradeBus{}
			gateway := &Gateway{upgrades: bus, now: time.Now}
			if _, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID,
				command.InstallationID, encoded, pending); err == nil {
				t.Fatal("cross-rollout accepted status was accepted")
			}
			if bus.publishCount.Load() != 0 || delivery.acks.Load() != 0 || len(pending) != 1 {
				t.Fatalf("published=%d acks=%d pending=%d", bus.publishCount.Load(), delivery.acks.Load(), len(pending))
			}
		})
	}
}

func TestUpgradeAcceptedStatusWaitsAcrossRestartForMatchingDurableCommand(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	bus := &fakeUpgradeBus{}
	gateway := &Gateway{upgrades: bus, now: func() time.Time { return time.Unix(123, 0).UTC() }}

	ack, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID,
		command.InstallationID, status.Encoded, make(pendingUpgradeCommandSet))
	if err != nil {
		t.Fatal(err)
	}
	if ack != nil || !bytes.Equal(bus.published, status.Encoded) || bus.publishCount.Load() != 1 {
		t.Fatalf("ack=%v published=%t count=%d", ack, bytes.Equal(bus.published, status.Encoded), bus.publishCount.Load())
	}

	delivery := &fakeUpgradeDelivery{command: command}
	pending := pendingUpgradeCommandSet{command.CommandID: {command: command, deliveries: []UpgradeCommandDelivery{delivery}}}
	restarted := &Gateway{upgrades: bus, now: func() time.Time { return time.Unix(124, 0).UTC() }}
	ack, err = restarted.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID,
		command.InstallationID, status.Encoded, pending)
	if err != nil {
		t.Fatal(err)
	}
	if ack == nil || delivery.acks.Load() != 1 || len(pending) != 0 || bus.publishCount.Load() != 2 ||
		!bytes.Equal(bus.published, status.Encoded) {
		t.Fatalf("ack=%v delivery_acks=%d pending=%d publishes=%d", ack, delivery.acks.Load(), len(pending), bus.publishCount.Load())
	}
}

func TestUpgradeAcceptedStatusAckFailureRecoversWithoutLosingPendingCommand(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	delivery := &fakeUpgradeDelivery{command: command, err: errors.New("ack failed")}
	pending := pendingUpgradeCommandSet{command.CommandID: {command: command, deliveries: []UpgradeCommandDelivery{delivery}}}
	bus := &fakeUpgradeBus{}
	gateway := &Gateway{upgrades: bus, now: time.Now, config: Config{CommandOperationTimeout: time.Second}}
	status := validUpgradeStatusRecord(t, command)

	if _, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID,
		command.InstallationID, status.Encoded, pending); err == nil {
		t.Fatal("command ACK failure was accepted")
	}
	if len(pending) != 1 || len(pending[command.CommandID].deliveries) != 1 || bus.publishCount.Load() != 1 {
		t.Fatalf("pending=%d deliveries=%d publishes=%d", len(pending), len(pending[command.CommandID].deliveries), bus.publishCount.Load())
	}
	delivery.err = nil
	ack, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID,
		command.InstallationID, status.Encoded, pending)
	if err != nil || ack == nil || len(pending) != 0 || bus.publishCount.Load() != 2 {
		t.Fatalf("recovery ack=%v err=%v pending=%d publishes=%d", ack, err, len(pending), bus.publishCount.Load())
	}
}

func TestUpgradeAcceptedStatusConflictDoesNotPublish(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	conflicting := command
	conflicting.SHA256[0] ^= 0xff
	delivery := &fakeUpgradeDelivery{command: conflicting}
	pending := pendingUpgradeCommandSet{command.CommandID: {command: conflicting, deliveries: []UpgradeCommandDelivery{delivery}}}
	bus := &fakeUpgradeBus{}
	gateway := &Gateway{upgrades: bus, now: time.Now}

	if _, err := gateway.persistUpgradeStatusAndAckCommand(context.Background(), command.NodeID,
		command.InstallationID, validUpgradeStatusRecord(t, command).Encoded, pending); err == nil {
		t.Fatal("conflicting accepted status was published")
	}
	if bus.published != nil || delivery.acks.Load() != 0 {
		t.Fatalf("published=%t acks=%d", bus.published != nil, delivery.acks.Load())
	}
}

func validUpgradeCommandRecord(t *testing.T) UpgradeCommandRecord {
	t.Helper()
	wire := upgradeCommandWire{
		Schema: UpgradeCommandSchema, CommandID: "00000000-0000-4000-8000-000000000011",
		PlanID: "00000000-0000-4000-8000-000000000012", PlanRevision: 2, BatchID: "batch-1",
		InstallationID: "00000000-0000-4000-8000-000000000013", NodeID: "00000000-0000-4000-8000-000000000014",
		Action: "upgrade",
	}
	wire.BatchID = "00000000-0000-4000-8000-000000000015"
	wire.SignedExecution = gatewayUpgradeExecutionV2(t, wire.PlanID, wire.PlanRevision, wire.BatchID)
	signedDigest := sha256.Sum256(wire.SignedExecution)
	wire.SignedExecutionSHA256 = hex.EncodeToString(signedDigest[:])
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeUpgradeCommandRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func gatewayUpgradeExecutionV2(t *testing.T, planID string, revision uint64, batchID string) []byte {
	t.Helper()
	execution, err := json.Marshal(upgradeExecutionRolloutWire{
		Schema: upgradeExecutionV2Schema, PlanID: planID, PlanRevision: revision, BatchID: batchID,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(upgradeExecutionEnvelopeWire{
		ControlAlgorithm: "Ed25519", ControlKeyID: "control-1", Execution: execution,
		ControlSignature: "control-signature", EdgeAlgorithm: "Ed25519", EdgeKeyID: "edge-1",
		EdgeSignature: "edge-signature",
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func validUpgradeStatusRecord(t *testing.T, command UpgradeCommandRecord) UpgradeStatusRecord {
	t.Helper()
	wire := upgradeStatusWire{
		Schema: UpgradeStatusSchema, StatusID: "00000000-0000-4000-8000-000000000021", StatusRevision: 1,
		CommandID: command.CommandID, PlanID: command.PlanID, PlanRevision: command.PlanRevision,
		InstallationID: command.InstallationID, NodeID: command.NodeID, CommandSHA256: hex.EncodeToString(command.SHA256[:]),
		State: "accepted", ObservedAt: time.Unix(100, 0).UTC(),
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeUpgradeStatusRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
