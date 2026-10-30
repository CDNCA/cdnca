package cachecontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// carryingNodes are the nodes a purge/prewarm of the scope's sites goes to
// when the request names none (ge-cache I): every active node that carries
// the scope's configuration (has a current configuration version of it),
// owned by the scope or a platform node the tenant is carried on.
func carryingNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) ([]uuid.UUID, error) {
	var nodes []uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(array_agg(state.node_id ORDER BY state.node_id), '{}')
		FROM node_config_state state
		JOIN nodes node ON node.id=state.node_id AND node.admin_state='active'
		WHERE state.configuration_scope_id=$1 AND state.current_config_version_id IS NOT NULL
		  AND tenant_carries_node_287($1,state.node_id)`, scopeID).Scan(&nodes); err != nil {
		return nil, fmt.Errorf("read cache operation carrying nodes: %w", err)
	}
	return nodes, nil
}

// carryingFollowUpWindow: a node that starts carrying a site this long after
// an automatic operation was created no longer gets a follow-up (its cache
// is empty of anything the operation would purge, and a prewarm that old
// is stale).
const carryingFollowUpWindow = 24 * time.Hour

// SyncCarryingNodes gives every open automatic operation (created without
// node IDs within carryingFollowUpWindow, ge-cache I) a follow-up operation
// for the nodes that started carrying its site since: same targets, same
// actor, parent_operation_id the operation. It runs as the control
// runtime; returns how many follow-ups it created.
func (store *Store) SyncCarryingNodes(ctx context.Context, scopeID uuid.UUID, requestID string) (int, error) {
	if ctx == nil || scopeID == uuid.Nil || !validSafeText(requestID, 128) {
		return 0, ErrInvalidInput
	}
	now := store.timestamp()
	created := 0
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeWorkerScope(ctx, tx, scopeID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT parent.id,parent.tenant_id,parent.site_id,parent.action,parent.target_type,
			       parent.actor_scope_id,parent.actor_user_id,parent.max_attempts
			FROM cache_operations parent
			WHERE parent.scope_id=$1 AND parent.auto_nodes AND parent.parent_operation_id IS NULL
			  AND parent.created_at >= $2 AND parent.state IN ('queued','running','succeeded','partial_failed','failed')
			ORDER BY parent.created_at,parent.id
			FOR UPDATE OF parent`, scopeID, now.Add(-carryingFollowUpWindow))
		if err != nil {
			return fmt.Errorf("list automatic cache operations: %w", err)
		}
		type parent struct {
			id, tenantID, siteID, actorScopeID, actorUserID uuid.UUID
			action                                          Action
			targetType                                      TargetType
			maxAttempts                                     uint32
		}
		var parents []parent
		for rows.Next() {
			var item parent
			var maxAttempts int
			if err := rows.Scan(&item.id, &item.tenantID, &item.siteID, &item.action, &item.targetType,
				&item.actorScopeID, &item.actorUserID, &maxAttempts); err != nil {
				rows.Close()
				return err
			}
			item.maxAttempts = uint32(maxAttempts)
			parents = append(parents, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(parents) == 0 {
			return nil
		}
		carrying, err := carryingNodes(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		for _, item := range parents {
			var covered []uuid.UUID
			if err := tx.QueryRow(ctx, `
				SELECT COALESCE(array_agg(DISTINCT node.node_id),'{}') FROM cache_operation_nodes node
				JOIN cache_operations operation ON operation.id=node.operation_id
				WHERE operation.scope_id=$1 AND (operation.id=$2 OR operation.parent_operation_id=$2)`,
				scopeID, item.id).Scan(&covered); err != nil {
				return fmt.Errorf("read automatic cache operation nodes: %w", err)
			}
			var missing []uuid.UUID
			for _, nodeID := range carrying {
				if !slices.Contains(covered, nodeID) {
					missing = append(missing, nodeID)
				}
			}
			if len(missing) == 0 {
				continue
			}
			targets, err := loadOperationTargets(ctx, tx, scopeID, item.id)
			if err != nil {
				return err
			}
			if targetsHaveWildcardHost(targets) {
				// A node without CACHE_WILDCARD_PURGE would refuse the "*."
				// host; it gets no follow-up (it carries the site from now).
				if missing, err = wildcardCapableNodes(ctx, tx, missing); err != nil {
					return err
				}
				if len(missing) == 0 {
					continue
				}
			}
			if len(targets)*len(missing) > maxOperationItems || len(missing) > maxNodes {
				continue
			}
			// The follow-up's identity names its parent and nodes, so a rerun
			// that races another finds the same operation.
			key := followUpKey(item.id, missing)
			digest, err := digestJSON(struct {
				Parent  uuid.UUID   `json:"parent_operation_id"`
				NodeIDs []uuid.UUID `json:"node_ids"`
			}{item.id, missing})
			if err != nil {
				return err
			}
			parentID := item.id
			_, existing, err := store.insertOperation(ctx, tx, operationInsert{
				actor:    Actor{UserID: item.actorUserID, ScopeID: scopeID, ActorScopeID: item.actorScopeID},
				tenantID: item.tenantID, siteID: item.siteID, action: item.action, targetType: item.targetType,
				targets: targets, nodeIDs: missing, maxRetries: item.maxAttempts - 1,
				idempotencyKey: key, requestID: requestID, digest: digest, autoNodes: true, parent: &parentID,
			}, now)
			if err != nil {
				return err
			}
			if !existing {
				created++
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("sync cache operation carrying nodes: %w", err)
	}
	return created, nil
}

func followUpKey(parent uuid.UUID, nodes []uuid.UUID) string {
	sorted := slices.Clone(nodes)
	slices.SortFunc(sorted, func(left, right uuid.UUID) int { return strings.Compare(left.String(), right.String()) })
	parts := make([]string, len(sorted))
	for index, node := range sorted {
		parts[index] = node.String()
	}
	digest := sha256.Sum256([]byte(parent.String() + ":" + strings.Join(parts, ",")))
	return "carrying-" + hex.EncodeToString(digest[:16])
}

func loadOperationTargets(ctx context.Context, tx pgx.Tx, scopeID, operationID uuid.UUID) ([]Target, error) {
	rows, err := tx.Query(ctx, `
		SELECT ordinal,canonical_url,canonical_path FROM cache_operation_targets
		WHERE scope_id=$1 AND operation_id=$2 ORDER BY ordinal`, scopeID, operationID)
	if err != nil {
		return nil, fmt.Errorf("load cache operation targets: %w", err)
	}
	defer rows.Close()
	var targets []Target
	for rows.Next() {
		var target Target
		if err := rows.Scan(&target.Ordinal, &target.CanonicalURL, &target.CanonicalPath); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}
