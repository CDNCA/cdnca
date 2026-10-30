package agentv1_test

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// The node plugin carrier was removed (ADR 0007 §4.6, §10): capability 30, ConnectRequest 15 and ConnectResponse 18
// are reserved so they can never be reused with a different meaning.
func TestRemovedNodePluginNumbersStayReserved(t *testing.T) {
	capabilities := agentv1.CapabilityName(0).Descriptor()
	if value := capabilities.Values().ByNumber(30); value != nil {
		t.Fatalf("capability 30 is declared as %s", value.Name())
	}
	if !capabilities.ReservedRanges().Has(30) || !capabilities.ReservedNames().Has("CAPABILITY_NAME_NODE_PLUGINS") {
		t.Fatal("capability 30 / CAPABILITY_NAME_NODE_PLUGINS is not reserved")
	}
	for _, carrier := range []struct {
		message protoreflect.MessageDescriptor
		number  protoreflect.FieldNumber
		name    protoreflect.Name
	}{
		{(&agentv1.ConnectRequest{}).ProtoReflect().Descriptor(), 15, "node_plugin_receipt"},
		{(&agentv1.ConnectResponse{}).ProtoReflect().Descriptor(), 18, "node_plugin_bundle"},
	} {
		if field := carrier.message.Fields().ByNumber(carrier.number); field != nil {
			t.Fatalf("%s field %d is declared as %s", carrier.message.Name(), carrier.number, field.Name())
		}
		if !carrier.message.ReservedRanges().Has(carrier.number) || !carrier.message.ReservedNames().Has(carrier.name) {
			t.Fatalf("%s field %d / %s is not reserved", carrier.message.Name(), carrier.number, carrier.name)
		}
	}
	for _, name := range []protoreflect.FullName{"agent.v1.NodePluginBundle", "agent.v1.NodePluginReceipt",
		"agent.v1.NodePluginSchema"} {
		if _, err := protoregistry.GlobalFiles.FindDescriptorByName(name); err == nil {
			t.Fatalf("%s is still declared", name)
		}
	}
}
