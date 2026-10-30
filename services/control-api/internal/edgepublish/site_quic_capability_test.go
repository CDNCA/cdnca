package edgepublish

import (
	"errors"
	"slices"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// A v2 HTTPS listener serving HTTP/3 needs only the
// node's QUIC-capable OpenResty build (SITE_QUIC), not the standalone HTTP/3
// runtime's h3probe (HTTP_3). A node with SITE_QUIC and no HTTP_3 takes the
// publication; a node without SITE_QUIC is refused by name.
func TestHTTPSOnSiteRuntimeV2RequiresSiteQUICNotHTTP3(t *testing.T) {
	_, _, required, _, err := compileSiteRuntimeV2Document(siteRuntimeV2DocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	names := make([]agentv1.CapabilityName, 0, len(required))
	for _, capability := range required {
		names = append(names, capability.Name)
	}
	if !slices.Contains(names, agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC) ||
		slices.Contains(names, agentv1.CapabilityName_CAPABILITY_NAME_HTTP_3) {
		t.Fatalf("v2 HTTPS document requires %v, want SITE_QUIC and not HTTP_3", names)
	}

	withoutProbe := cloneSiteRuntimeV2Capabilities(required)
	withoutQUIC := slices.DeleteFunc(cloneSiteRuntimeV2Capabilities(required), func(capability *agentv1.Capability) bool {
		return capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC
	})
	probeless, first, second := uuid.MustParse("00000000-0000-4000-8000-000000000001"),
		uuid.MustParse("00000000-0000-4000-8000-000000000002"), uuid.MustParse("00000000-0000-4000-8000-000000000003")
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		probeless: {AgentVersion: "1.0.35", Features: withoutProbe},
		first:     {AgentVersion: "1.0.35", Features: withoutQUIC},
		second:    {AgentVersion: "1.0.35", Features: cloneSiteRuntimeV2Capabilities(withoutQUIC)},
	}
	if err := capabilityTargetsError([]uuid.UUID{probeless}, required, sessions); err != nil {
		t.Fatalf("HTTPS on a node with SITE_QUIC and no h3probe (HTTP_3): %v", err)
	}
	err = capabilityTargetsError([]uuid.UUID{probeless, first, second}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) ||
		refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC || refusal.NodeID != first ||
		len(refusal.OtherNodeIDs) != 1 || refusal.OtherNodeIDs[0] != second ||
		!strings.Contains(err.Error(), "QUIC") || strings.Contains(err.Error(), "h3probe") ||
		strings.Contains(err.Error(), probeless.String()) {
		t.Fatalf("HTTPS on nodes without SITE_QUIC = %v (%+v)", err, refusal)
	}
}
