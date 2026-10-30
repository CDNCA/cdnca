package cachecontrol

import (
	"context"
	"fmt"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// wildcardPurgeAPIVersion is the CACHE_WILDCARD_PURGE version a node needs
// to execute a purge target whose host is "*.<suffix>" (fp-site2, user Q4).
const wildcardPurgeAPIVersion = 1

func targetsHaveWildcardHost(targets []Target) bool {
	for _, target := range targets {
		if strings.Contains(target.CanonicalURL, "://*.") {
			return true
		}
	}
	return false
}

// checkWildcardPurgeNodes refuses a wildcard purge when a target node's latest
// session does not declare CACHE_WILDCARD_PURGE: an older agent rejects the
// "*." host and the operation would fail on that node instead of up front.
func checkWildcardPurgeNodes(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) error {
	capable, err := wildcardCapableNodes(ctx, tx, nodeIDs)
	if err != nil {
		return err
	}
	if len(capable) != len(nodeIDs) {
		return ErrWildcardPurgeUnsupported
	}
	return nil
}

func declaresWildcardPurge(snapshot []byte) bool {
	var capabilities agentv1.AgentCapabilities
	if len(snapshot) == 0 || proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	for _, capability := range capabilities.GetFeatures() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CACHE_WILDCARD_PURGE &&
			capability.GetApiVersion() >= wildcardPurgeAPIVersion {
			return true
		}
	}
	return false
}

// wildcardCapableNodes keeps the nodes whose latest session declares
// CACHE_WILDCARD_PURGE, in order.
func wildcardCapableNodes(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		SELECT node.id,(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts
			WHERE facts.node_id=node.id ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM unnest($1::uuid[]) WITH ORDINALITY AS node(id,position) ORDER BY node.position`, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("read cache wildcard purge capabilities: %w", err)
	}
	defer rows.Close()
	var capable []uuid.UUID
	for rows.Next() {
		var nodeID uuid.UUID
		var snapshot []byte
		if err := rows.Scan(&nodeID, &snapshot); err != nil {
			return nil, fmt.Errorf("scan cache wildcard purge capabilities: %w", err)
		}
		if declaresWildcardPurge(snapshot) {
			capable = append(capable, nodeID)
		}
	}
	return capable, rows.Err()
}
