//go:build integration

package edgepublish

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
)

// A site mounting the official PHP virtual patch pack
// (multipart_* inspect targets) is refused for a node whose agent declares
// WAF below v5, naming the node and the feature, and held for automatic
// publication; once the node declares WAF v5 the release goes out with the
// mount.
func TestWAFMultipartPackNeedsWAFV5Nodes(t *testing.T) {
	fixture := newPublishFixture(t)
	seedDynamicRoutingNode(t, fixture, fixture.nodeID)
	site := fixture.createSite(t, "php.example.test", 8080, false).Site.ID
	packs := rulepackcontrol.NewService(fixture.pool, func() time.Time { return publishTestClock })
	platform := rulepackcontrol.Actor{UserID: fixture.platformUserID, ScopeID: fixture.platformScopeID, ScopeKind: "platform"}
	tenant := rulepackcontrol.Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "tenant"}
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "security", "datasets", "rulepacks",
		"vpatch", "system-waf-php-vpatch.json"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := packs.Import(t.Context(), platform, content)
	if err != nil {
		t.Fatalf("import pack: %v", err)
	}
	if _, _, err := packs.PutOverride(t.Context(), platform, rulepackcontrol.OverrideInput{Level: rulepack.LevelPlatform,
		PackID: pack.PackID, State: rulepack.StateEnabled, AllowLower: true}); err != nil {
		t.Fatal(err)
	}
	published, err := packs.PublishSite(t.Context(), tenant, site)
	if err != nil || published.Published == nil || len(published.Published.Security.Mounts) != 1 {
		t.Fatalf("publish mounts: %+v %v", published.Published, err)
	}
	applyRulePacks(t, fixture, published.Published.Security)

	_, err = fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "vpatch-v1", fixture.nodeID, siteRuntimeV2Schema))
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != fixture.nodeID ||
		refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_WAF || refusal.Required != edgeconfig.WAFMultipartAPIVersion {
		t.Fatalf("publish to a WAF v1 node: %v", err)
	}
	var held bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM edge_capability_publication_holds
		WHERE scope_id=$1 AND refused_node_ids @> ARRAY[$2::uuid])`, fixture.scopeID, fixture.nodeID).Scan(&held); err != nil || !held {
		t.Fatalf("refused publication not held: %v %v", held, err)
	}

	// The node's agent is upgraded: WAF v5.
	features := v2DefaultNodeFeatures()
	for _, feature := range features {
		switch feature.Name {
		case agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME:
			feature.ApiVersion = edgeconfig.DynamicRoutingSiteRuntimeVersion
		case agentv1.CapabilityName_CAPABILITY_NAME_WAF:
			feature.ApiVersion = edgeconfig.WAFMultipartAPIVersion
		}
	}
	seedNodeSessionCapabilitiesForTest(t, fixture.pool, fixture.nodeID, "1.0.35-vpatch", features)
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "vpatch-v5", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("publish to a WAF v5 node: %v", err)
	}
	sites := dynamicRoutingSiteObjects(t, fixture, result.ConfigVersionID)
	assertSiteMounts(t, sites[site.String()].security, published.Published.Security)
}
