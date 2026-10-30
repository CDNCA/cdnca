package gateway

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestUpgradeStatusReceiptContractDescriptor(t *testing.T) {
	file := agentv1.File_agent_v1_types_proto
	capabilities := file.Enums().ByName("CapabilityName").Values()
	assertEnumValue := func(name protoreflect.Name, number protoreflect.EnumNumber) {
		t.Helper()
		value := capabilities.ByName(name)
		if value == nil || value.Number() != number {
			t.Fatalf("CapabilityName.%s = %v, want %d", name, value, number)
		}
	}
	assertEnumValue("CAPABILITY_NAME_EDGE_UPGRADE", 22)
	assertEnumValue("CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK", 23)
	assertEnumValue("CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT", 24)
	assertEnumValue("CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE", 25)

	receipt := file.Messages().ByName("UpgradeStatusAckReceipt")
	if receipt == nil {
		t.Fatal("UpgradeStatusAckReceipt descriptor is missing")
	}
	type fieldContract struct {
		name        protoreflect.Name
		number      protoreflect.FieldNumber
		kind        protoreflect.Kind
		cardinality protoreflect.Cardinality
		message     protoreflect.FullName
	}
	wantFields := []fieldContract{
		{name: "status_event_id", number: 1, kind: protoreflect.StringKind, cardinality: protoreflect.Optional},
		{name: "command_id", number: 2, kind: protoreflect.StringKind, cardinality: protoreflect.Optional},
		{name: "status_revision", number: 3, kind: protoreflect.Uint64Kind, cardinality: protoreflect.Optional},
		{name: "status_sha256", number: 4, kind: protoreflect.BytesKind, cardinality: protoreflect.Optional},
		{name: "persisted_time", number: 5, kind: protoreflect.MessageKind, cardinality: protoreflect.Optional, message: "google.protobuf.Timestamp"},
		{name: "published_stream", number: 6, kind: protoreflect.StringKind, cardinality: protoreflect.Optional},
		{name: "published_sequence", number: 7, kind: protoreflect.Uint64Kind, cardinality: protoreflect.Optional},
		{name: "ack_sha256", number: 8, kind: protoreflect.BytesKind, cardinality: protoreflect.Optional},
	}
	if got := receipt.Fields().Len(); got != len(wantFields) {
		t.Fatalf("UpgradeStatusAckReceipt field count = %d, want %d", got, len(wantFields))
	}
	for _, want := range wantFields {
		field := receipt.Fields().ByName(want.name)
		if field == nil || field.Number() != want.number || field.Kind() != want.kind || field.Cardinality() != want.cardinality {
			t.Fatalf("UpgradeStatusAckReceipt.%s = %v, want field %d kind %s cardinality %s", want.name, field, want.number, want.kind, want.cardinality)
		}
		if want.message != "" && (field.Message() == nil || field.Message().FullName() != want.message) {
			t.Fatalf("UpgradeStatusAckReceipt.%s message = %v, want %s", want.name, field.Message(), want.message)
		}
	}

	request := file.Messages().ByName("ConnectRequest")
	response := file.Messages().ByName("ConnectResponse")
	assertMessageField := func(message protoreflect.MessageDescriptor, name protoreflect.Name, number protoreflect.FieldNumber, want protoreflect.MessageDescriptor) {
		t.Helper()
		payload := message.Oneofs().ByName("payload")
		if payload == nil {
			t.Fatalf("%s.payload oneof is missing", message.FullName())
		}
		field := message.Fields().ByName(name)
		if field == nil || field.Number() != number || field.Kind() != protoreflect.MessageKind || field.Message() != want || field.Cardinality() != protoreflect.Optional || field.ContainingOneof() != payload {
			t.Fatalf("%s.%s = %v, want optional field %d message %s in payload oneof", message.FullName(), name, field, number, want.FullName())
		}
	}
	upgradeStatus := file.Messages().ByName("UpgradeStatus")
	upgradeStatusAck := file.Messages().ByName("UpgradeStatusAck")
	if upgradeStatus == nil || upgradeStatusAck == nil {
		t.Fatalf("existing upgrade descriptors missing: status=%v ack=%v", upgradeStatus, upgradeStatusAck)
	}
	assertMessageField(request, "upgrade_status", 8, upgradeStatus)
	assertMessageField(response, "upgrade_status_ack", 11, upgradeStatusAck)
	assertMessageField(request, "upgrade_status_ack_receipt", 9, receipt)
	assertMessageField(response, "upgrade_status_ack_receipt", 12, receipt)
}
