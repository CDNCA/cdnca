package edgepublish

import (
	"context"
	"fmt"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Per-node L4 forwards: a scope's release is one signed
// root for every target node, so each node used to run every forward of the
// scope. A forward is served by the nodes of its line groups (its own, else
// its package's; main and backup), and the node's key document, sealed for it
// alone, names the root's forwards it does not serve
// (siteobject.KeyDocument.L4WithheldStreams). The root and its signature are
// unchanged.

// streamServingNodes maps each of the release's forwards whose line groups
// resolve (at least one live group) to the nodes serving them: the enabled
// endpoints of the groups' current revisions, as systemTargetNodes selects
// the scope's targets. A forward absent from the map has no live line group
// to go by and is served by every target node, as before; a forward whose
// groups have no serving node maps to an empty set (served by none).
func streamServingNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, streams *edgeconfig.StreamRuntime,
) (map[string]map[uuid.UUID]struct{}, error) {
	if streams == nil || len(streams.StreamsV2) == 0 {
		return nil, nil
	}
	ids := make([]uuid.UUID, 0, len(streams.StreamsV2))
	for _, stream := range streams.StreamsV2 {
		id, err := uuid.Parse(stream.StreamID)
		if err != nil {
			return nil, fmt.Errorf("%w: release L4 forward id", ErrInvalidInput)
		}
		ids = append(ids, id)
	}
	rows, err := tx.Query(ctx, `
		SELECT forward.id::text,endpoint.node_id
		FROM l4_forwards forward
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=forward.scope_id
		 AND subscription.id=forward.package_subscription_id AND subscription.deleted_at IS NULL
		JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
		     COALESCE(forward.node_group_id, (subscription.product_snapshot->'spec'->>'node_group_id')::uuid),
		     COALESCE(forward.backup_node_group_id, (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid),
		     (SELECT platform_default.id FROM node_line_groups platform_default WHERE platform_default.is_platform_default AND platform_default.deleted_at IS NULL AND forward.node_group_id IS NULL AND subscription.id IS NULL))
		LEFT JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
		 AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
		 AND endpoint.enabled AND endpoint.node_id IS NOT NULL
		 AND line_group.tenant_scope_id IN (forward.scope_id,(SELECT scope_id FROM nodes WHERE id=endpoint.node_id))
		WHERE forward.scope_id=$1 AND forward.id=ANY($2::uuid[]) AND forward.deleted_at IS NULL`, scopeID, ids)
	if err != nil {
		return nil, fmt.Errorf("%w: read L4 forward line group nodes", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[string]map[uuid.UUID]struct{})
	for rows.Next() {
		var streamID string
		var nodeID *uuid.UUID
		if err := rows.Scan(&streamID, &nodeID); err != nil {
			return nil, fmt.Errorf("%w: scan L4 forward line group nodes", ErrPersistence)
		}
		nodes := result[streamID]
		if nodes == nil {
			nodes = make(map[uuid.UUID]struct{})
			result[streamID] = nodes
		}
		if nodeID != nil {
			nodes[*nodeID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate L4 forward line group nodes", ErrPersistence)
	}
	return result, nil
}

// withheldStreamsFor is what node's key document withholds: the release's
// forwards with a line group none of whose nodes is node, when the node
// declares L4_STREAM_SELECTION; else none (an older node serves them all).
func withheldStreamsFor(advertised []*agentv1.Capability, nodeID uuid.UUID, streams *edgeconfig.StreamRuntime,
	serving map[string]map[uuid.UUID]struct{}) []string {
	if streams == nil || len(serving) == 0 || !declaresL4StreamSelection(advertised) {
		return nil
	}
	var withheld []string
	for _, stream := range streams.StreamsV2 {
		nodes, resolved := serving[stream.StreamID]
		if !resolved {
			continue
		}
		if _, serves := nodes[nodeID]; !serves {
			withheld = append(withheld, stream.StreamID)
		}
	}
	sort.Strings(withheld)
	return withheld
}

func declaresL4StreamSelection(advertised []*agentv1.Capability) bool {
	for _, capability := range advertised {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION &&
			capability.GetApiVersion() >= siteobject.L4StreamSelectionAPIVersion {
			return true
		}
	}
	return false
}
