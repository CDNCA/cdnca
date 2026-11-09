//go:build integration

package edgepublish

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
)

// An older node (no SITE_SELECTION) whose key envelope grows
// past the 4096 bytes its Agent takes (100 withheld forwards) is left out of
// the release; the new node of the scope still gets it. The old node keeps
// its previous configuration, the result, the audit and a capability hold
// name it, every next publication it still cannot take does too, and once
// it declares SITE_SELECTION it gets the release again.
func TestOversizedKeyEnvelopeLeavesOnlyTheOlderNodeOut(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	nodeNew, nodeOld := scope.AddNode(t, 12), scope.AddNode(t, 12)
	scope.DeclareSiteSelection(t, nodeNew)
	scope.DeclareStreamSelection(t, nodeOld)
	shared := scope.AddStreamLineGroup(t, "198.51.100.71", nodeNew, nodeOld)
	scope.MoveSite(t, scope.SiteID, shared)
	scope.AdvanceRevision(t)
	if err := scope.PublishManually(t, "oversized-first", nodeNew, nodeOld); err != nil {
		t.Fatalf("first publication (every envelope fits): %v", err)
	}
	scope.SettleDeployments(t)
	before := scope.HeldConfigVersion(t, nodeOld)
	if before == nil {
		t.Fatal("older node runs nothing after the first publication")
	}
	if got := scope.StaleConfigurations(t, nodeOld); got != nil {
		t.Fatalf("older node marked %+v before it was left out", got)
	}

	// 100 forwards only the new node serves: the older node is withheld them.
	only := scope.AddStreamLineGroup(t, "198.51.100.72", nodeNew)
	for index := range 100 {
		scope.AddStreamOn(t, fmt.Sprintf("oversized-%03d", index), uint16(9800+index), only)
	}
	publishOversized := func(label, key string) PublishResult {
		t.Helper()
		scope.AdvanceRevision(t)
		request := scope.fixture.publishRequest(key, nodeNew)
		request.NodeIDs = []uuid.UUID{nodeNew, nodeOld}
		result, err := scope.fixture.service.Publish(t.Context(), request)
		if err != nil {
			t.Fatalf("%s: publication refused (%v), want the older node left out", label, err)
		}
		if !slices.Equal(result.KeyEnvelopeOversizedNodeIDs, []uuid.UUID{nodeOld}) {
			t.Fatalf("%s: result names %v as left out, want the older node %s", label, result.KeyEnvelopeOversizedNodeIDs, nodeOld)
		}
		if result.NodeCount != 1 {
			t.Fatalf("%s: node_count = %d, want 1", label, result.NodeCount)
		}
		if got := scope.LatestPublication(t).NodeIDs; !slices.Equal(got, []uuid.UUID{nodeNew}) {
			t.Fatalf("%s: deployments went to %v, want only the new node %s", label, got, nodeNew)
		}
		if got := len(scope.LatestNodeRelease(t, nodeNew).Streams); got != 100 {
			t.Fatalf("%s: new node serves %d forwards, want 100", label, got)
		}
		scope.SettleDeployments(t)
		if got := scope.HeldConfigVersion(t, nodeOld); got == nil || *got != *before {
			t.Fatalf("%s: older node runs %v, want its previous configuration %s", label, got, before)
		}
		entries := scope.KeyEnvelopeOversized(t)
		if len(entries) != 1 || entries[0]["node_id"] != nodeOld.String() ||
			entries[0]["limit_bytes"] != float64(siteobject.LegacyMaxKeyEnvelopeBytes) ||
			entries[0]["key_envelope_bytes"].(float64) <= float64(siteobject.LegacyMaxKeyEnvelopeBytes) {
			t.Fatalf("%s: audit key_envelope_oversized_nodes = %v", label, entries)
		}
		if hold, ok := scope.LatestHold(t); !ok || hold.SourceRevision != result.SourceRevision ||
			!slices.Equal(hold.Refused, []uuid.UUID{nodeOld}) {
			t.Fatalf("%s: capability hold = %+v (found %v), want the older node at revision %d", label, hold, ok, result.SourceRevision)
		}
		// 节点列表与详情：旧配置仍生效（the inventory read both pages use）.
		if got := scope.StaleConfigurations(t, nodeOld); len(got) != 1 || got[0].ScopeID != scope.ScopeID ||
			got[0].SourceRevision != result.SourceRevision || got[0].Reason != nodepresence.StaleReasonKeyEnvelopeOversized {
			t.Fatalf("%s: older node stale configurations = %+v, want this scope at revision %d", label, got, result.SourceRevision)
		}
		if got := scope.StaleConfigurations(t, nodeNew); got != nil {
			t.Fatalf("%s: new node marked %+v", label, got)
		}
		// The publication record keeps it (list and detail).
		if got := scope.StoredLeftOutNodes(t); !slices.Equal(got, []uuid.UUID{nodeOld}) {
			t.Fatalf("%s: stored publication names %v as left out, want the older node %s", label, got, nodeOld)
		}
		return result
	}
	publishOversized("forwards added", "oversized-second")
	// Still too large: still left out, still named.
	publishOversized("next publication", "oversized-third")
	// The system and automatic channels refuse it like a missing capability.
	scope.AdvanceRevision(t)
	published, refused := scope.PublishExcluding(t, "oversized-system", nodeNew, nodeOld)
	if _, ok := refused[nodeOld]; !slices.Equal(published, []uuid.UUID{nodeNew}) || !ok || len(refused) != 1 {
		t.Fatalf("system channel published to %v and refused %v, want only the new node, the older refused", published, refused)
	}
	if got := scope.StoredLeftOutNodes(t); !slices.Equal(got, []uuid.UUID{nodeOld}) {
		t.Fatalf("automatic/system channel: stored publication names %v as left out, want the older node %s", got, nodeOld)
	}
	scope.SettleDeployments(t)

	// Upgraded: the bitmap keeps its envelope small, it gets the release.
	scope.DeclareSiteSelection(t, nodeOld)
	scope.AdvanceRevision(t)
	request := scope.fixture.publishRequest("oversized-upgraded", nodeNew)
	request.NodeIDs = []uuid.UUID{nodeNew, nodeOld}
	result, err := scope.fixture.service.Publish(t.Context(), request)
	if err != nil {
		t.Fatalf("publication after the upgrade: %v", err)
	}
	if result.KeyEnvelopeOversizedNodeIDs != nil || scope.KeyEnvelopeOversized(t) != nil {
		t.Fatalf("after the upgrade the result names %v, the audit %v", result.KeyEnvelopeOversizedNodeIDs, scope.KeyEnvelopeOversized(t))
	}
	if got := scope.StoredLeftOutNodes(t); got != nil {
		t.Fatalf("after the upgrade the stored publication names %v as left out", got)
	}
	if got := scope.LatestPublication(t).NodeIDs; !slices.Equal(got, sortedUUIDs(nodeNew, nodeOld)) {
		t.Fatalf("after the upgrade deployments went to %v, want both nodes", got)
	}
	if got := len(scope.LatestNodeRelease(t, nodeOld).Streams); got != 0 {
		t.Fatalf("upgraded older node serves %d of the other group's forwards, want 0", got)
	}
	// Published but not yet applied: it still runs the old configuration.
	if got := scope.StaleConfigurations(t, nodeOld); len(got) != 1 {
		t.Fatalf("upgraded node before applying the release marked %+v, want still marked", got)
	}
	scope.SettleDeployments(t)
	if got := scope.StaleConfigurations(t, nodeOld); got != nil {
		t.Fatalf("upgraded node running the release still marked %+v", got)
	}
}

// StaleConfigurations is the node inventory's stale_configurations of
// nodeID (what the node list and node detail show).
func (scope *SystemRepublishScope) StaleConfigurations(t *testing.T, nodeID uuid.UUID) []nodepresence.StaleConfiguration {
	t.Helper()
	item, err := nodepresence.NewInventory(scope.Pool, nil, 0, nil, nil).Get(t.Context(), scope.ScopeID, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return item.StaleConfigurations
}

// StoredLeftOutNodes is key_envelope_oversized_node_ids of the scope's
// latest publication as both reads return it (detail and list; nil when
// none); the two must agree.
func (scope *SystemRepublishScope) StoredLeftOutNodes(t *testing.T) []uuid.UUID {
	t.Helper()
	var publicationID uuid.UUID
	if err := scope.Pool.QueryRow(t.Context(), `SELECT id FROM edge_config_publications
		WHERE configuration_scope_id=$1 ORDER BY source_revision DESC LIMIT 1`, scope.ScopeID).Scan(&publicationID); err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: scope.fixture.platformUserID, ScopeID: scope.fixture.platformScopeID, ScopeKind: ScopeKindPlatform}
	detail, err := scope.fixture.service.GetPublication(t.Context(), actor, scope.ScopeID, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	page, err := scope.fixture.service.ListPublications(t.Context(), actor, scope.ScopeID, PublicationPageRequest{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(page.Items, func(item PublishResult) bool { return item.PublicationID == publicationID })
	if index < 0 || !slices.Equal(page.Items[index].KeyEnvelopeOversizedNodeIDs, detail.KeyEnvelopeOversizedNodeIDs) ||
		!slices.Equal(page.Items[index].SiteSelectionUnsupportedNodeIDs, detail.SiteSelectionUnsupportedNodeIDs) {
		t.Fatalf("list item %d disagrees with detail %+v", index, detail)
	}
	return detail.KeyEnvelopeOversizedNodeIDs
}

func sortedUUIDs(ids ...uuid.UUID) []uuid.UUID {
	ids = slices.Clone(ids)
	slices.SortFunc(ids, compareUUID)
	return ids
}

// KeyEnvelopeOversized is the latest publication audit's
// key_envelope_oversized_nodes (nil when absent).
func (scope *SystemRepublishScope) KeyEnvelopeOversized(t *testing.T) []map[string]any {
	t.Helper()
	var raw []byte
	if err := scope.Pool.QueryRow(t.Context(), `SELECT payload->'key_envelope_oversized_nodes'
		FROM audit_events WHERE action='edge_publication.publish' AND payload->>'configuration_scope_id'=$1::uuid::text
		ORDER BY occurred_at DESC,stream_position DESC LIMIT 1`, scope.ScopeID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &entries); err != nil {
			t.Fatal(err)
		}
	}
	return entries
}
