package edgedeployment

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

// NodeServesSeveralScopes reports whether the node's latest session declared
// MULTI_TENANT_RUNTIME v1 with ACTIVE_CONFIG_IDENTITY v1, the pair the gateway
// requires before it enables per-scope state (agent.v1 capability 33). Only
// such a node may hold a configuration scope next to another one; the schema
// cannot read capabilities, so every claim path asks this first.
func NodeServesSeveralScopes(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) (bool, error) {
	var snapshot, digest []byte
	err := tx.QueryRow(ctx, `SELECT capabilities_snapshot,capabilities_sha256 FROM node_session_capabilities
		WHERE node_id=$1 ORDER BY session_epoch DESC LIMIT 1`, nodeID).Scan(&snapshot, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read node session capabilities: %w", err)
	}
	actual := sha256.Sum256(snapshot)
	capabilities := new(agentv1.AgentCapabilities)
	if !bytes.Equal(actual[:], digest) || proto.Unmarshal(snapshot, capabilities) != nil {
		return false, nil
	}
	var multiTenant, activeIdentity bool
	for _, feature := range capabilities.Features {
		switch {
		case feature.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME && feature.GetApiVersion() == 1:
			multiTenant = true
		case feature.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY && feature.GetApiVersion() == 1:
			activeIdentity = true
		}
	}
	return multiTenant && activeIdentity, nil
}

// activeDeploymentConstraint names the indexes that hold a node to one
// running deployment: per (node, scope), and per node unless the agent
// queues deployments itself (migration 291).
func activeDeploymentConstraint(name string) bool {
	switch name {
	case "node_deployments_one_active_per_node_scope_288_idx", "node_deployments_one_active_unqueued_per_node_291_idx":
		return true
	}
	return false
}
