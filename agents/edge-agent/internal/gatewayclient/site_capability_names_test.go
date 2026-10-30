package gatewayclient

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// fix-l4cap contract: every document capability the control plane may write
// (siteruntimecap's documentNames is built from siteobject.
// RuntimeCapabilityNames) is a real agent.v1 enum value the agent recognises
// under the same document name.
func TestSiteRuntimeCapabilityNameCoversEveryDocumentCapability(t *testing.T) {
	seen := map[string]string{}
	for enum, document := range siteobject.RuntimeCapabilityNames {
		value, ok := agentv1.CapabilityName_value[enum]
		if !ok {
			t.Errorf("%s is not an agent.v1 CapabilityName", enum)
			continue
		}
		if previous, duplicate := seen[document]; duplicate {
			t.Errorf("document capability %q is mapped by both %s and %s", document, previous, enum)
		}
		seen[document] = enum
		got, known := siteRuntimeCapabilityName(agentv1.CapabilityName(value))
		if !known || got != document {
			t.Errorf("siteRuntimeCapabilityName(%s) = %q (known %v), want %q", enum, got, known, document)
		}
	}
	for number := range agentv1.CapabilityName_name {
		capability := agentv1.CapabilityName(number)
		if _, inTable := siteobject.RuntimeCapabilityNames[capability.String()]; inTable {
			continue
		}
		if name, known := siteRuntimeCapabilityName(capability); known {
			t.Errorf("node only %s maps to site runtime capability %q", capability, name)
		}
	}
	if name, known := siteRuntimeCapabilityName(agentv1.CapabilityName(1 << 20)); known {
		t.Errorf("undefined enum value maps to %q", name)
	}
}

// The three capabilities the agent used to miss (acc-b2: every L4 forward
// refused as "site object command capability is unknown").
func TestSiteRuntimeCapabilityNameL4AndSubscriptionLimits(t *testing.T) {
	for capability, want := range map[agentv1.CapabilityName]string{
		agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA:                 "l4_toa",
		agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION: edgeconfig.L4PackageAttributionCapability,
		agentv1.CapabilityName_CAPABILITY_NAME_SUBSCRIPTION_LIMITS:    edgeconfig.SubscriptionLimitsCapability,
	} {
		if got, known := siteRuntimeCapabilityName(capability); !known || got != want {
			t.Errorf("siteRuntimeCapabilityName(%s) = %q (known %v), want %q", capability, got, known, want)
		}
	}
}

// A L4 forward command carries L4_PACKAGE_ATTRIBUTION (with TCP_PROXY and
// SITE_RUNTIME); the site object check accepts it when the root names the
// same set.
func TestSameSiteObjectCapabilitiesAcceptsL4PackageAttribution(t *testing.T) {
	root := []siteobject.Capability{
		{Name: "site_runtime", APIVersion: 9},
		{Name: "tcp", APIVersion: 10},
		{Name: edgeconfig.L4PackageAttributionCapability, APIVersion: 1},
		{Name: "l4_toa", APIVersion: 1},
	}
	command := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 9},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 10},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA, ApiVersion: 1},
	}
	if err := sameSiteObjectCapabilities(root, command); err != nil {
		t.Fatalf("L4 command refused: %v", err)
	}
	command[2].ApiVersion = 2
	if err := sameSiteObjectCapabilities(root, command); err == nil {
		t.Fatal("L4_PACKAGE_ATTRIBUTION version mismatch accepted")
	}
}
