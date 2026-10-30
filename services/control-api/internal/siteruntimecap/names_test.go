package siteruntimecap

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Every proto capability is either a document capability (in documentNames)
// or explicitly node only, so a new enum value cannot silently miss the
// table.
func TestEveryCapabilityIsClassified(t *testing.T) {
	inDocument := map[agentv1.CapabilityName]string{}
	for name, capability := range documentNames {
		if previous, ok := inDocument[capability]; ok {
			t.Errorf("%v is mapped by both %q and %q", capability, previous, name)
		}
		inDocument[capability] = name
		if nodeOnlyCapabilities[capability] {
			t.Errorf("%v (%q) is both a document and a node only capability", capability, name)
		}
	}
	for number, enum := range agentv1.CapabilityName_name {
		capability := agentv1.CapabilityName(number)
		if _, ok := inDocument[capability]; !ok && !nodeOnlyCapabilities[capability] {
			t.Errorf("%s is neither in documentNames nor in nodeOnlyCapabilities", enum)
		}
	}
	for capability := range nodeOnlyCapabilities {
		if _, ok := agentv1.CapabilityName_name[int32(capability)]; !ok {
			t.Errorf("node only capability %d is not a proto value", capability)
		}
	}
}

func TestNameRejectsUnknown(t *testing.T) {
	if _, ok := Name("HTTP_3"); ok {
		t.Fatal("unknown name accepted")
	}
	if got, ok := Name("http3"); !ok || got != agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC {
		t.Fatalf("http3 = %v %v", got, ok)
	}
}
