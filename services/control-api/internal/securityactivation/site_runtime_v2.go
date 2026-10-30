package securityactivation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sort"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A site runtime v2 candidate encrypts one artifact per target node at Start
// (migration 333, docs/architecture/security-activation-v2.md); its identity
// digest is the plaintext bundle's. v1 candidates have no node artifacts.

type candidateNodeArtifacts struct {
	bindings map[uuid.UUID]edgedeployment.NodeArtifactBinding
	digests  map[uuid.UUID][sha256.Size]byte
}

// loadCandidateNodeArtifacts returns nil for a v1 candidate.
func loadCandidateNodeArtifacts(ctx context.Context, tx pgx.Tx, candidate Candidate) (*candidateNodeArtifacts, error) {
	rows, err := tx.Query(ctx, `SELECT node_id,deployment_id,event_id,artifact_id,artifact_sha256,recipient_key_id
		FROM security_policy_activation_node_artifacts_333
		WHERE tenant_scope_id=$1 AND config_version_id=$2 ORDER BY node_id`,
		candidate.TenantScopeID, candidate.CandidateConfigVersionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &candidateNodeArtifacts{
		bindings: make(map[uuid.UUID]edgedeployment.NodeArtifactBinding),
		digests:  make(map[uuid.UUID][sha256.Size]byte),
	}
	for rows.Next() {
		binding := edgedeployment.NodeArtifactBinding{Attempt: 1, ConfigVersionID: candidate.CandidateConfigVersionID}
		var digest []byte
		if err := rows.Scan(&binding.NodeID, &binding.DeploymentID, &binding.EventID, &binding.ArtifactID,
			&digest, &binding.RecipientKeyID); err != nil {
			return nil, err
		}
		if len(digest) != sha256.Size {
			return nil, ErrConflict
		}
		result.bindings[binding.NodeID] = binding
		result.digests[binding.NodeID] = [sha256.Size]byte(digest)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result.bindings) == 0 {
		return nil, nil
	}
	targets := append(append([]uuid.UUID(nil), candidate.CanaryNodeIDs...), candidate.ExpandNodeIDs...)
	if len(targets) != len(result.bindings) {
		return nil, ErrConflict
	}
	for _, nodeID := range targets {
		if _, found := result.bindings[nodeID]; !found {
			return nil, ErrConflict
		}
	}
	return result, nil
}

// phaseBindings returns the phase nodes' bindings in node order.
func (artifacts *candidateNodeArtifacts) phaseBindings(nodes []uuid.UUID) ([]edgedeployment.NodeArtifactBinding, error) {
	sorted := append([]uuid.UUID(nil), nodes...)
	sort.Slice(sorted, func(left, right int) bool { return bytes.Compare(sorted[left][:], sorted[right][:]) < 0 })
	result := make([]edgedeployment.NodeArtifactBinding, len(sorted))
	for index, nodeID := range sorted {
		binding, found := artifacts.bindings[nodeID]
		if !found {
			return nil, ErrConflict
		}
		result[index] = binding
	}
	return result, nil
}

func (artifacts *candidateNodeArtifacts) digestMap() map[uuid.UUID][sha256.Size]byte {
	if artifacts == nil {
		return nil
	}
	return artifacts.digests
}

// recoveryCapabilities is what a rollback to configID requires: a v2 version
// its own document's capabilities (requireReleasableConfig compares them
// exactly, so a candidate's would refuse the rollback). A v1 version: the
// candidate's (unchanged v1 behavior), without site runtime for a v2
// candidate (site runtime would demand a v2 artifact).
func recoveryCapabilities(ctx context.Context, tx pgx.Tx, candidate Candidate, candidateV2 bool,
	configID uuid.UUID) ([]*agentv1.Capability, error) {
	capabilities, v2, err := edgedeployment.SiteRuntimeV2ConfigCapabilitiesTx(ctx, tx, candidate.TenantScopeID, configID)
	if err != nil {
		return nil, err
	}
	if v2 {
		return capabilities, nil
	}
	if !candidateV2 {
		return cloneCapabilities(candidate.RequiredCapabilities), nil
	}
	result := make([]*agentv1.Capability, 0, len(candidate.RequiredCapabilities))
	for _, capability := range cloneCapabilities(candidate.RequiredCapabilities) {
		if capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			result = append(result, capability)
		}
	}
	return result, nil
}
