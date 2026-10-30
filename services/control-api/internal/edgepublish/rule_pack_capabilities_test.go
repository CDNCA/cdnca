package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// A mounted pack using multipart_* inspect targets
// (system/waf-php-vpatch) needs WAF v5 on every target; a v4 node is refused
// with the gated WAF multipart feature, a v5 node accepted.
func TestRulePackCapabilitiesWAFMultipart(t *testing.T) {
	plain := &rulepack.CompiledPack{Requires: []string{}}
	if got := rulePackCapabilities([]*rulepack.CompiledPack{plain}); len(got) != 0 {
		t.Fatalf("plain pack needs %v", got)
	}
	multipart := &rulepack.CompiledPack{Requires: []string{rulepack.RequiresWAFMultipart}}
	required := rulePackCapabilities([]*rulepack.CompiledPack{plain, multipart, multipart})
	if len(required) != 1 || required[0].GetName() != agentv1.CapabilityName_CAPABILITY_NAME_WAF ||
		required[0].GetApiVersion() != edgeconfig.WAFMultipartAPIVersion {
		t.Fatalf("required %v", required)
	}
	v4, v5 := uuid.New(), uuid.New()
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		v4: {AgentVersion: "1.0.35-old", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 4}}},
		v5: {Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 5}}},
	}
	err := capabilityTargetsError([]uuid.UUID{v4, v5}, required, sessions)
	refusal, ok := err.(*TargetCapabilityError)
	if !ok || refusal.NodeID != v4 || refusal.Required != 5 || refusal.Advertised != 4 || len(refusal.OtherNodeIDs) != 0 {
		t.Fatalf("refusal %v", err)
	}
	if err := capabilityTargetsError([]uuid.UUID{v5}, required, sessions); err != nil {
		t.Fatalf("v5 node refused: %v", err)
	}
}
