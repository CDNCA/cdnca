//go:build integration

package edgepublish

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// DeclareNodeStorage records a new session of nodeID that also declares
// NODE_STORAGE v2 (key documents carry its storage settings and
// node_facts_at).
func (scope *SystemRepublishScope) DeclareNodeStorage(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, "1.0.35-storage", append(systemRepublishFeatures(6),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE,
			ApiVersion: siteobject.NodeStorageNodeFactsAPIVersion}))
}

// NodeSettingsRelease is what a node's deployment of a publication gives it.
type NodeSettingsRelease struct {
	ConfigVersionID uuid.UUID
	SourceRevision  int64
	NodeStorage     *siteobject.NodeStorage
	NodeFactsAt     int64
	// Members are the publication's object digests, sorted.
	Members []string
}

// NodeRelease opens nodeID's deployment of the scope's latest publication
// with its key.
func (scope *SystemRepublishScope) NodeRelease(t *testing.T, nodeID uuid.UUID) NodeSettingsRelease {
	t.Helper()
	var deploymentID uuid.UUID
	if err := scope.Pool.QueryRow(t.Context(), `SELECT deployment.id FROM node_deployments deployment
		JOIN edge_config_publications publication ON publication.rollout_id=deployment.rollout_id
		WHERE publication.configuration_scope_id=$1 AND deployment.node_id=$2
		ORDER BY publication.source_revision DESC,deployment.attempt DESC LIMIT 1`,
		scope.ScopeID, nodeID).Scan(&deploymentID); err != nil {
		t.Fatal(err)
	}
	release, err := OpenSiteObjectReleaseForTest(t.Context(), scope.Pool, deploymentID, scope.fixture.nodeKeys[nodeID])
	if err != nil {
		t.Fatal(err)
	}
	configID, err := uuid.Parse(release.Root.ConfigVersionID)
	if err != nil {
		t.Fatal(err)
	}
	result := NodeSettingsRelease{ConfigVersionID: configID, SourceRevision: release.Root.SourceRevision,
		NodeStorage: release.NodeStorage, NodeFactsAt: release.NodeFactsAt}
	for digest := range release.Members {
		result.Members = append(result.Members, digest)
	}
	slices.Sort(result.Members)
	return result
}

// PublicationKind is the latest publication's kind, content refusal and
// node settings base (migration 701).
func (scope *SystemRepublishScope) PublicationKind(t *testing.T) (string, string, *uuid.UUID) {
	t.Helper()
	var kind string
	var refusal *string
	var base *uuid.UUID
	if err := scope.Pool.QueryRow(t.Context(), `SELECT publication_kind,content_refusal,node_settings_base_config_version_id
		FROM edge_config_publications WHERE configuration_scope_id=$1 ORDER BY source_revision DESC LIMIT 1`,
		scope.ScopeID).Scan(&kind, &refusal, &base); err != nil {
		t.Fatal(err)
	}
	if refusal == nil {
		return kind, "", base
	}
	return kind, *refusal, base
}
