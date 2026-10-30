package artifactsetdist

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit actions (BATCH-PLUGIN item 10; edgestatus writes
// node.artifact_set.receipt). The resource is the node's artifact set
// (resource_id: node ID); the actor is the system (no user, no source IP).
const (
	AuditActionIssue   = "node.artifact_set.issue"
	AuditActionDeliver = "node.artifact_set.deliver"
	auditResourceType  = "node_artifact_set"
)

// auditItem is an item as audit changes show it (no segment list).
type auditItem struct {
	ArtifactID string `json:"artifact_id"`
	Version    string `json:"version"`
	Revision   uint64 `json:"revision"`
	SHA256     string `json:"sha256"`
}

func auditItems(items []artifactset.Item) []auditItem {
	result := make([]auditItem, 0, len(items))
	for _, item := range items {
		result = append(result, auditItem{ArtifactID: item.ArtifactID, Version: item.Version, Revision: item.Revision,
			SHA256: item.SHA256})
	}
	return result
}

// appliedAuditItems is what the node runs now (its applied set's items).
func appliedAuditItems(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) ([]auditItem, error) {
	rows, err := tx.Query(ctx, `SELECT artifact_id,version,item_revision,sha256 FROM node_artifact_applied_items
		WHERE node_id=$1 ORDER BY artifact_id`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("read node artifact applied items: %w", err)
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (auditItem, error) {
		var item auditItem
		var revision int64
		err := row.Scan(&item.ArtifactID, &item.Version, &revision, &item.SHA256)
		item.Revision = uint64(revision)
		return item, err
	})
	if err != nil {
		return nil, fmt.Errorf("read node artifact applied items: %w", err)
	}
	if items == nil {
		items = []auditItem{}
	}
	return items, nil
}

func (distributor *Distributor) appendAudit(ctx context.Context, tx pgx.Tx, action string, nodeID uuid.UUID,
	payload map[string]any) error {
	platformScopeID, err := distributor.platformScopeID(ctx)
	if err != nil {
		return err
	}
	payload["actor_kind"], payload["ip"], payload["node_id"] = "system", "", nodeID.String()
	if err := distributor.config.Auditor.Append(ctx, tx, audit.Event{ScopeID: platformScopeID, Action: action,
		ResourceType: auditResourceType, ResourceID: nodeID.String(), RequestID: uuid.NewString(), Result: "success",
		Payload: payload}); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}
