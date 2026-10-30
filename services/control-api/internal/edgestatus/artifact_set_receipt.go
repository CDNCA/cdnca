package edgestatus

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// nodeArtifactMediaTypes are the node-side deployment media types (PA-01,
// libs/edgeconfig/artifactset): segment objects and per-node sets. Migration
// 349 keeps them in the platform scope, one per configuration.
var nodeArtifactMediaTypes = []string{artifactset.MediaTypeSet, artifactset.MediaTypeSegment}

// recordArtifactSetReceipt checks the receipt a node artifact deployment's
// status carries and records it. Only the terminal status of a set
// deployment carries one: healthy with an applied receipt (required), failed
// with a rejected or pending receipt (absent when the node could not judge
// the set, e.g. its signature failed). The receipt must answer exactly the
// deployed set. An applied receipt replaces the node's applied items (what
// the publication gate reads); a newer receipt saying the node runs no set
// clears them; any other receipt leaves the last known good alone. Every
// recorded receipt is audited (node.artifact_set.receipt).
func (s *Store) recordArtifactSetReceipt(ctx context.Context, tx pgx.Tx, deployment lockedDeployment, envelope Envelope,
	state string, receivedAt time.Time) error {
	encoded := envelope.Status.GetArtifactSetReceipt()
	var setWire []byte
	err := tx.QueryRow(ctx, `SELECT wire_bytes FROM configuration_artifacts
		WHERE config_version_id=$1 AND media_type=$2`, deployment.configID, artifactset.MediaTypeSet).Scan(&setWire)
	if errors.Is(err, pgx.ErrNoRows) {
		if len(encoded) != 0 {
			return fmt.Errorf("%w: receipt on a segment deployment", ErrBindingConflict)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read node artifact set: %w", err)
	}
	if len(encoded) == 0 {
		if state == "healthy" {
			return fmt.Errorf("%w: healthy node artifact set without a receipt", ErrBindingConflict)
		}
		return nil
	}
	if state != "healthy" && state != "failed" {
		return fmt.Errorf("%w: receipt on a nonterminal status", ErrBindingConflict)
	}
	receipt, err := artifactset.DecodeReceipt(encoded)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidStatus, err)
	}
	set, err := artifactset.Decode(setWire)
	if err != nil {
		return fmt.Errorf("%w: stored node artifact set: %v", ErrProjectionConflict, err)
	}
	if receipt.NodeID != envelope.NodeID.String() || set.NodeID != receipt.NodeID || receipt.Revision != set.Revision ||
		receipt.SetSHA256 != artifactset.Digest(setWire) || !receiptAnswers(receipt, set) ||
		(state == "healthy") != (receipt.Result == artifactset.ResultApplied) {
		return fmt.Errorf("%w: receipt does not answer the deployed set", ErrBindingConflict)
	}
	var recorded bool
	if err := tx.QueryRow(ctx, `INSERT INTO node_artifact_set_receipts(node_id,revision,set_sha256,result,active_revision,
			receipt,deployment_id,reported_at,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
		ON CONFLICT (node_id) DO UPDATE SET revision=EXCLUDED.revision,set_sha256=EXCLUDED.set_sha256,
			result=EXCLUDED.result,active_revision=EXCLUDED.active_revision,receipt=EXCLUDED.receipt,
			deployment_id=EXCLUDED.deployment_id,reported_at=EXCLUDED.reported_at,recorded_at=EXCLUDED.recorded_at
		WHERE node_artifact_set_receipts.revision<=EXCLUDED.revision
		RETURNING true`, envelope.NodeID, int64(receipt.Revision), receipt.SetSHA256, receipt.Result,
		int64(receipt.ActiveRevision), string(encoded), envelope.DeploymentID, receipt.ReportedAt, receivedAt).Scan(&recorded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // an older revision's receipt arrived late
		}
		return fmt.Errorf("record node artifact set receipt: %w", err)
	}
	before, err := appliedItemsAudit(ctx, tx, envelope.NodeID)
	if err != nil {
		return err
	}
	switch {
	case receipt.Result == artifactset.ResultApplied:
		if err := replaceAppliedItems(ctx, tx, envelope, set, receivedAt); err != nil {
			return err
		}
	case receipt.ActiveRevision == 0:
		if _, err := tx.Exec(ctx, `DELETE FROM node_artifact_applied_items WHERE node_id=$1`, envelope.NodeID); err != nil {
			return fmt.Errorf("clear node artifact applied items: %w", err)
		}
	}
	after, err := appliedItemsAudit(ctx, tx, envelope.NodeID)
	if err != nil {
		return err
	}
	if err := s.auditReceipt(ctx, tx, deployment, envelope, receipt, before, after); err != nil {
		return err
	}
	return s.auditEngineModule(ctx, tx, deployment, envelope, set, receipt, before, after)
}

// Engine module audit actions (OWASP CRS engine extension, ADR 0007 B3):
// one event per receipt whose set holds an engine module item or changes
// the node's installed one. install: the node runs the module now (or
// removed it: after empty); install_reject: the node refused the module
// item (reason_code from the receipt, e.g. signature_invalid,
// platform_mismatch) and kept the module it had.
const (
	EngineModuleInstallAuditAction = "node.engine_module.install"
	EngineModuleRejectAuditAction  = "node.engine_module.install_reject"
)

func (s *Store) auditEngineModule(ctx context.Context, tx pgx.Tx, deployment lockedDeployment, envelope Envelope,
	set artifactset.Set, receipt artifactset.Receipt, before, after []map[string]any) error {
	engineItem := func(items []map[string]any) map[string]any {
		for _, item := range items {
			if id, _ := item["artifact_id"].(string); strings.HasPrefix(id, "engine_module/") {
				return item
			}
		}
		return nil
	}
	var setItem *artifactset.Item
	var result artifactset.ItemResult
	for index, item := range set.Items {
		if item.MediaType == artifactset.MediaTypeEngineModule {
			setItem, result = &set.Items[index], receipt.Items[index]
		}
	}
	was, now := engineItem(before), engineItem(after)
	action, outcome, reason := EngineModuleInstallAuditAction, "success", ""
	switch {
	case setItem != nil && result.Result == artifactset.ResultRejected && result.Reason != artifactset.ReasonSetRejected:
		action, outcome, reason = EngineModuleRejectAuditAction, "failure", result.Reason
	case receipt.Result == artifactset.ResultApplied && !sameItem(was, now):
	default:
		return nil
	}
	var ipv4, ipv6 *string
	if err := tx.QueryRow(ctx, `SELECT host(ipv4),host(ipv6) FROM nodes WHERE id=$1`, envelope.NodeID).Scan(&ipv4, &ipv6); err != nil &&
		!errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read node address: %w", err)
	}
	address := ""
	if ipv4 != nil {
		address = *ipv4
	} else if ipv6 != nil {
		address = *ipv6
	}
	payload := map[string]any{"actor_kind": "node", "actor_node_id": envelope.NodeID.String(), "ip": address,
		"node_id": envelope.NodeID.String(), "set_revision": receipt.Revision, "reason_code": reason,
		"deployment_id": envelope.DeploymentID.String(),
		"changes": map[string]any{"engine_module": map[string]any{"before": was, "after": now}}}
	resourceID := envelope.NodeID.String()
	if setItem != nil {
		payload["artifact_id"], payload["version"], payload["revision"], payload["sha256"] =
			setItem.ArtifactID, setItem.Version, setItem.Revision, setItem.SHA256
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: deployment.scopeID, Action: action,
		ResourceType: "node_engine_module", ResourceID: resourceID, RequestID: envelope.RequestID.String(),
		Result: outcome, Payload: payload}); err != nil {
		return fmt.Errorf("audit node engine module: %w", err)
	}
	return nil
}

func sameItem(left, right map[string]any) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left["artifact_id"] == right["artifact_id"] && left["sha256"] == right["sha256"]
}

// ArtifactSetReceiptAuditAction is the audit action of a recorded node
// artifact set receipt (actor: the node; result success when applied,
// failure with the first item's reason code otherwise).
const ArtifactSetReceiptAuditAction = "node.artifact_set.receipt"

func (s *Store) auditReceipt(ctx context.Context, tx pgx.Tx, deployment lockedDeployment, envelope Envelope,
	receipt artifactset.Receipt, before, after []map[string]any) error {
	result, reason := "success", ""
	if receipt.Result != artifactset.ResultApplied {
		result, reason = "failure", receipt.Result
		for _, item := range receipt.Items {
			if item.Reason != "" && item.Reason != artifactset.ReasonSetRejected {
				reason = item.Reason
				break
			}
		}
	}
	items := make([]map[string]any, 0, len(receipt.Items))
	for _, item := range receipt.Items {
		items = append(items, map[string]any{"artifact_id": item.ArtifactID, "version": item.Version,
			"result": item.Result, "reason": item.Reason})
	}
	payload := map[string]any{"actor_kind": "node", "actor_node_id": envelope.NodeID.String(), "ip": "",
		"node_id": envelope.NodeID.String(), "set_revision": receipt.Revision, "set_sha256": receipt.SetSHA256,
		"receipt_result": receipt.Result, "reason_code": reason, "active_revision": receipt.ActiveRevision,
		"deployment_id": envelope.DeploymentID.String(), "items": items,
		"changes": map[string]any{"applied_items": map[string]any{"before": before, "after": after}}}
	if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: deployment.scopeID, Action: ArtifactSetReceiptAuditAction,
		ResourceType: "node_artifact_set", ResourceID: envelope.NodeID.String(), RequestID: envelope.RequestID.String(),
		Result: result, Payload: payload}); err != nil {
		return fmt.Errorf("audit node artifact set receipt: %w", err)
	}
	return nil
}

// appliedItemsAudit is the node's applied items as audit changes show them.
func appliedItemsAudit(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) ([]map[string]any, error) {
	rows, err := tx.Query(ctx, `SELECT artifact_id,version,item_revision,sha256 FROM node_artifact_applied_items
		WHERE node_id=$1 ORDER BY artifact_id`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("read node artifact applied items: %w", err)
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (map[string]any, error) {
		var artifactID, version, sha string
		var revision int64
		err := row.Scan(&artifactID, &version, &revision, &sha)
		return map[string]any{"artifact_id": artifactID, "version": version, "revision": revision, "sha256": sha}, err
	})
	if err != nil {
		return nil, fmt.Errorf("read node artifact applied items: %w", err)
	}
	if items == nil {
		items = []map[string]any{}
	}
	return items, nil
}

// receiptAnswers: the receipt names exactly the set's items, in order.
func receiptAnswers(receipt artifactset.Receipt, set artifactset.Set) bool {
	if len(receipt.Items) != len(set.Items) {
		return false
	}
	for index, item := range set.Items {
		answer := receipt.Items[index]
		if answer.ArtifactID != item.ArtifactID || answer.Version != item.Version || answer.SHA256 != item.SHA256 {
			return false
		}
	}
	return true
}

// replaceAppliedItems makes the node's applied items those of set. An item
// that stays keeps announced_at (its republication was already requested).
func replaceAppliedItems(ctx context.Context, tx pgx.Tx, envelope Envelope, set artifactset.Set, at time.Time) error {
	artifactIDs := make([]string, 0, len(set.Items))
	for _, item := range set.Items {
		artifactIDs = append(artifactIDs, item.ArtifactID)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM node_artifact_applied_items WHERE node_id=$1 AND NOT artifact_id=ANY($2::text[])`,
		envelope.NodeID, artifactIDs); err != nil {
		return fmt.Errorf("remove node artifact applied items: %w", err)
	}
	for _, item := range set.Items {
		if _, err := tx.Exec(ctx, `INSERT INTO node_artifact_applied_items(node_id,artifact_id,version,item_revision,media_type,
				sha256,set_revision,applied_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (node_id,artifact_id) DO UPDATE SET version=EXCLUDED.version,item_revision=EXCLUDED.item_revision,
				media_type=EXCLUDED.media_type,sha256=EXCLUDED.sha256,set_revision=EXCLUDED.set_revision,
				applied_at=EXCLUDED.applied_at
			WHERE node_artifact_applied_items.set_revision<=EXCLUDED.set_revision`,
			envelope.NodeID, item.ArtifactID, item.Version, int64(item.Revision), item.MediaType, item.SHA256,
			int64(set.Revision), at); err != nil {
			return fmt.Errorf("record node artifact applied item: %w", err)
		}
	}
	return nil
}

// validArtifactSetReceiptShape bounds the receipt bytes a status may carry
// (decoded against the deployed set by the store).
func validArtifactSetReceiptShape(status *agentv1.DeploymentStatus) bool {
	receipt := status.GetArtifactSetReceipt()
	if len(receipt) == 0 {
		return true
	}
	terminal := status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY ||
		status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED
	return terminal && len(receipt) <= artifactset.MaxReceiptBytes
}
