package nodepresence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// CapabilityRegression: the node's latest healthy deployment of a scope used
// a feature its agent no longer declares. Typically the agent was rolled
// back (e.g. 1.0.34 -> 1.0.33, whose session declares tcp v3 and CC v2): the
// configuration the control plane believes is serving needs a newer agent,
// and the next publication of the scope with that feature is refused
// (edgepublish node_capability_unavailable).
type CapabilityRegression struct {
	ScopeID         uuid.UUID `json:"scope_id"`
	DeploymentID    uuid.UUID `json:"deployment_id"`
	ConfigVersionID uuid.UUID `json:"config_version_id"`
	// Feature is a stable code the console explains and suggests remedies for.
	Feature    string `json:"feature"`
	Capability string `json:"capability"`
	Required   uint32 `json:"required"`
	Declared   uint32 `json:"declared"`
	// AgentVersion is what the node's latest session declared.
	AgentVersion string `json:"agent_version"`
}

// Feature codes of capability versions only newer agents implement
// (edgepublish.gatedFeature names the same set).
const (
	FeatureCCProofOfWork         = "cc_proof_of_work"
	FeatureWAFCRSModule          = "waf_crs_module"
	FeatureL4TLSPassthrough      = "l4_tls_passthrough"
	FeatureL4AdditionalListeners = "l4_additional_listeners"
	// FeatureL4TOA: the node's kernel or OpenResty stopped passing the TOA
	// probe (L4_TOA is declared per boot, not per agent version).
	FeatureL4TOA = "l4_toa"
)

func regressionFeature(capability *agentv1.Capability) (string, bool) {
	l4 := capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY
	switch {
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC && capability.GetApiVersion() >= 3:
		return FeatureCCProofOfWork, true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE:
		return FeatureWAFCRSModule, true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA:
		return FeatureL4TOA, true
	case l4 && capability.GetApiVersion() >= 4:
		return FeatureL4TLSPassthrough, true
	case l4 && capability.GetApiVersion() >= 3:
		return FeatureL4AdditionalListeners, true
	}
	return "", false
}

// capabilityRegressions compares what a deployment command required with
// what the node declares now; only gated features count (anything else was
// already required of every agent the deployment could reach).
func capabilityRegressions(scopeID, deploymentID, configVersionID uuid.UUID, required []*agentv1.Capability,
	declared *agentv1.AgentCapabilities) []CapabilityRegression {
	have := make(map[agentv1.CapabilityName]uint32, len(declared.GetFeatures()))
	for _, capability := range declared.GetFeatures() {
		have[capability.GetName()] = max(have[capability.GetName()], capability.GetApiVersion())
	}
	var result []CapabilityRegression
	seen := map[string]bool{}
	for _, capability := range required {
		feature, gated := regressionFeature(capability)
		if !gated || have[capability.GetName()] >= capability.GetApiVersion() || seen[feature] {
			continue
		}
		seen[feature] = true
		result = append(result, CapabilityRegression{ScopeID: scopeID, DeploymentID: deploymentID,
			ConfigVersionID: configVersionID, Feature: feature, Capability: capability.GetName().String(),
			Required: capability.GetApiVersion(), Declared: have[capability.GetName()],
			AgentVersion: declared.GetAgentVersion()})
	}
	return result
}

// readCapabilityRegressions returns, for each scope of the node, the gated
// features its latest healthy deployment required that the node's latest
// session does not declare. A node without a readable session has none.
func readCapabilityRegressions(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) ([]CapabilityRegression, error) {
	var snapshot, digest []byte
	err := tx.QueryRow(ctx, `SELECT capabilities_snapshot,capabilities_sha256 FROM node_session_capabilities
		WHERE node_id=$1 ORDER BY session_epoch DESC LIMIT 1`, nodeID).Scan(&snapshot, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return []CapabilityRegression{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read node session capabilities: %w", err)
	}
	actual := sha256.Sum256(snapshot)
	declared := new(agentv1.AgentCapabilities)
	if !bytes.Equal(actual[:], digest) || proto.Unmarshal(snapshot, declared) != nil {
		return []CapabilityRegression{}, nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (configuration_scope_id) configuration_scope_id,id,config_version_id,command_bytes
		FROM node_deployments WHERE node_id=$1 AND state='healthy' AND configuration_scope_id IS NOT NULL
		ORDER BY configuration_scope_id,updated_at DESC,created_at DESC,attempt DESC`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("read latest healthy deployments: %w", err)
	}
	defer rows.Close()
	result := []CapabilityRegression{}
	for rows.Next() {
		var scopeID, deploymentID, configVersionID uuid.UUID
		var commandBytes []byte
		if err := rows.Scan(&scopeID, &deploymentID, &configVersionID, &commandBytes); err != nil {
			return nil, err
		}
		command := new(agentv1.DeploymentCommand)
		if proto.Unmarshal(commandBytes, command) != nil {
			continue
		}
		result = append(result, capabilityRegressions(scopeID, deploymentID, configVersionID,
			command.GetRequiredCapabilities(), declared)...)
	}
	return result, rows.Err()
}
