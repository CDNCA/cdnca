package edgesignertrustsync

import (
	"context"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// NodeTarget is one active node and whether its latest session declared
// CAPABILITY_NAME_EDGE_SIGNER_TRUST v1.
type NodeTarget struct {
	ID      string
	Capable bool
}

// ActiveNodes lists active nodes with the EDGE_SIGNER_TRUST version of their
// latest gateway session facts (node_session_capabilities). A node that never
// connected, or whose Agent predates the capability, is not capable.
func ActiveNodes(pool *pgxpool.Pool) func(context.Context) ([]NodeTarget, error) {
	return func(ctx context.Context) ([]NodeTarget, error) {
		rows, err := pool.Query(ctx, `SELECT node.id,
				(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=node.id
				 ORDER BY facts.session_epoch DESC LIMIT 1)
			FROM nodes node WHERE node.admin_state='active' ORDER BY node.id LIMIT 100000`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		nodes := []NodeTarget{}
		for rows.Next() {
			var id uuid.UUID
			var snapshot []byte
			if err := rows.Scan(&id, &snapshot); err != nil {
				return nil, err
			}
			nodes = append(nodes, NodeTarget{ID: id.String(), Capable: snapshotDeclaresSignerTrust(snapshot)})
		}
		return nodes, rows.Err()
	}
}

func snapshotDeclaresSignerTrust(snapshot []byte) bool {
	var capabilities agentv1.AgentCapabilities
	if len(snapshot) == 0 || proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	for _, capability := range capabilities.Features {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST && capability.GetApiVersion() == 1 {
			return true
		}
	}
	return false
}
