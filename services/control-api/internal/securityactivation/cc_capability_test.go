package securityactivation

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

// TestProofOfWorkCCReleaseKeepsCCV3: an activation of a proof-of-work CC
// policy carries CC v3 (edgepublish). Lowering it to the configured v2 would
// let 1.0.33 agents (CC v2) accept the command and fail to decode the
// challenge; rejecting it would make such policies impossible to activate.
func TestProofOfWorkCCReleaseKeepsCCV3(t *testing.T) {
	store := &Store{config: DefaultConfig()}
	base := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
	}
	with := func(version uint32) []*agentv1.Capability {
		return append(append([]*agentv1.Capability(nil), base...),
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: version})
	}
	ccVersion := func(values []*agentv1.Capability) uint32 {
		for _, value := range values {
			if value.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC {
				return value.GetApiVersion()
			}
		}
		return 0
	}
	if got := ccVersion(store.requiredSecurityCapability(with(3))); got != 3 {
		t.Fatalf("CC v3 release lowered to v%d", got)
	}
	if got := ccVersion(store.requiredSecurityCapability(with(4))); got != 4 {
		t.Fatalf("CC v4 (count_by) release lowered to v%d", got)
	}
	if got := ccVersion(store.requiredSecurityCapability(with(5))); got != 5 {
		t.Fatalf("CC v5 (auto switch) release lowered to v%d", got)
	}
	if got := ccVersion(store.requiredSecurityCapability(with(2))); got != 2 {
		t.Fatalf("CC v2 release changed to v%d", got)
	}
	for version, want := range map[uint32]bool{1: false, 2: true, 3: true, 4: true, 5: true, 6: false} {
		if got := store.requiredCapabilitiesValid(securitypolicy.KindCC, with(version)); got != want {
			t.Fatalf("CC v%d release valid=%v, want %v", version, got, want)
		}
	}
}
