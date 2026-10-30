package edgepublish

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Automatic failure reasons the publication page explains (edgeautopublish
// terminal codes of the same names).
const (
	AutomaticFailureNoTargetNodes        = "no_target_nodes"
	AutomaticFailureNodeCapability       = "node_capability_unavailable"
	AutomaticFailureNodeArtifactsSyncing = "node_artifacts_syncing"
	// AutomaticFailureNodeScopeConflict: a target node carries another
	// tenant's configuration this one cannot share (CrossScopeConflictError);
	// the next source revision publishes again (B15).
	AutomaticFailureNodeScopeConflict = "node_scope_conflict"
)

// artifactSyncDefaultDelivery is the time one node artifact delivery is
// assumed to take before the node completed any (one distributor sweep).
const artifactSyncDefaultDelivery = time.Minute

// LatestAutomaticFailureTx is the scope's latest automatic request when it
// failed for no_target_nodes, node_capability_unavailable,
// node_artifacts_syncing or node_scope_conflict and no later publication of the scope exists. For
// node_artifacts_syncing it also reads how far the refused nodes' node
// artifact sets have arrived.
func LatestAutomaticFailureTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (*AutomaticPublicationFailure, error) {
	var failure AutomaticPublicationFailure
	err := tx.QueryRow(ctx, `SELECT state.terminal_code,request_row.source_revision,state.occurred_at
		FROM edge_automatic_publication_requests request_row
		JOIN LATERAL (SELECT state,terminal_code,occurred_at FROM edge_automatic_publication_request_state_facts
		  WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1) state ON true
		WHERE request_row.target_scope_id=$1
		  AND state.state='failed' AND state.terminal_code IN ('no_target_nodes','node_capability_unavailable','node_artifacts_syncing','node_scope_conflict')
		  AND request_row.id=(SELECT latest.id FROM edge_automatic_publication_requests latest
		    WHERE latest.target_scope_id=$1 ORDER BY latest.source_revision DESC,latest.created_at DESC,latest.id DESC LIMIT 1)
		  AND NOT EXISTS(SELECT 1 FROM edge_config_publications publication
		    WHERE publication.configuration_scope_id=$1 AND publication.source_revision>=request_row.source_revision)`,
		scopeID).Scan(&failure.Reason, &failure.SourceRevision, &failure.FailedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if failure.Reason == AutomaticFailureNodeArtifactsSyncing {
		var refused []uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT refused_node_ids FROM edge_capability_publication_holds
			WHERE scope_id=$1 AND source_revision=$2),'{}')`, scopeID, failure.SourceRevision).Scan(&refused); err != nil {
			return nil, err
		}
		if failure.ArtifactSync, err = NodeArtifactSyncProgressTx(ctx, tx, refused); err != nil {
			return nil, err
		}
	}
	return &failure, nil
}

// NodeArtifactSyncProgressTx sums, over nodeIDs (the nodes a refused
// revision is held for), the segments of each node's newest node artifact
// set it has received (a healthy delivery) against all of them, and
// estimates the minutes the slowest node still needs: its remaining segments
// plus the set, at the pace its received segments arrived (one sweep each
// before any did). nil when none of the nodes has a set yet.
func NodeArtifactSyncProgressTx(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) (*ArtifactSyncProgress, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `WITH newest AS (
			SELECT node.node_id, node_set.config_version_id FROM unnest($1::uuid[]) AS node(node_id)
			JOIN LATERAL (SELECT config_version_id FROM node_artifact_sets
			  WHERE node_id=node.node_id ORDER BY revision DESC LIMIT 1) node_set ON true),
		segments AS (
			SELECT DISTINCT newest.node_id, segment.config_version_id FROM newest
			JOIN config_versions version ON version.id=newest.config_version_id
			CROSS JOIN LATERAL jsonb_array_elements(convert_from(version.canonical_snapshot,'UTF8')::jsonb->'items') item
			CROSS JOIN LATERAL jsonb_array_elements(item->'segments') piece
			JOIN node_artifact_segments segment ON segment.sha256=piece->>'sha256')
		SELECT segments.node_id, count(*),
			count(*) FILTER (WHERE delivered.healthy_at IS NOT NULL),
			min(delivered.started_at), max(delivered.healthy_at)
		FROM segments
		LEFT JOIN LATERAL (SELECT min(deployment.created_at) AS started_at,
				max(deployment.updated_at) FILTER (WHERE deployment.state='healthy') AS healthy_at
			FROM node_deployments deployment
			WHERE deployment.node_id=segments.node_id AND deployment.config_version_id=segments.config_version_id) delivered ON true
		GROUP BY segments.node_id`, nodeIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var progress *ArtifactSyncProgress
	for rows.Next() {
		var nodeID uuid.UUID
		var total, received int
		var started, healthy *time.Time
		if err := rows.Scan(&nodeID, &total, &received, &started, &healthy); err != nil {
			return nil, err
		}
		if progress == nil {
			progress = &ArtifactSyncProgress{}
		}
		progress.ReceivedSegments += received
		progress.TotalSegments += total
		progress.RemainingMinutes = max(progress.RemainingMinutes, remainingMinutes(total, received, started, healthy))
	}
	return progress, rows.Err()
}

// remainingMinutes is the whole minutes (at least one) the node needs for
// its remaining segments and the set.
func remainingMinutes(total, received int, started, healthy *time.Time) int {
	pace := artifactSyncDefaultDelivery
	if received > 0 && started != nil && healthy != nil && healthy.After(*started) {
		pace = healthy.Sub(*started) / time.Duration(received)
	}
	remaining := time.Duration(total-received+1) * pace
	return max(1, int((remaining+time.Minute-1)/time.Minute))
}
