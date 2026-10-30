package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func authorizeActor(ctx context.Context, tx pgx.Tx, actor Actor, tenantScopeID uuid.UUID, permission string) error {
	var actorScopeKind, actorStatus, membershipStatus, targetScopeKind string
	var permitted bool
	err := tx.QueryRow(ctx, `
		SELECT actor_scope.kind,actor.status,membership.status,target_scope.kind,
		       EXISTS (
		           SELECT 1
		           FROM role_assignments assignment
		           JOIN role_permissions permission_grant ON permission_grant.role_id=assignment.role_id
		           WHERE assignment.scope_id=$2 AND assignment.user_id=$1
		             AND permission_grant.permission_name IN ($4,'platform.admin')
		       )
		FROM users actor
		JOIN memberships membership ON membership.user_id=actor.id AND membership.scope_id=$2
		JOIN access_scopes actor_scope ON actor_scope.id=membership.scope_id
		JOIN access_scopes target_scope ON target_scope.id=$3
		WHERE actor.id=$1`, actor.UserID, actor.ScopeID, tenantScopeID, permission).Scan(
		&actorScopeKind, &actorStatus, &membershipStatus, &targetScopeKind, &permitted)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (actorScopeKind != ScopeKindPlatform ||
		targetScopeKind != ScopeKindTenant || actorStatus != "active" || membershipStatus != "active" || !permitted) {
		return ErrPermissionDenied
	}
	if err != nil {
		return fmt.Errorf("%w: authorize actor", ErrPersistence)
	}
	return nil
}

func (s *Service) resolveTarget(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedPublishRequest,
) (TargetSnapshot, [32]byte, error) {
	target, digest, err := s.resolveTargetIdentity(ctx, tx, request)
	if err != nil {
		return TargetSnapshot{}, [32]byte{}, err
	}
	if err := validateEligibleNodes(ctx, tx, request.ConfigurationScopeID, target.NodeIDs); err != nil {
		return TargetSnapshot{}, [32]byte{}, err
	}
	return target, digest, nil
}

func (s *Service) resolveTargetIdentity(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedPublishRequest,
) (TargetSnapshot, [32]byte, error) {
	target := TargetSnapshot{NodeIDs: slices.Clone(request.NodeIDs)}
	if request.TargetSnapshot != nil {
		if s.resolver == nil {
			return TargetSnapshot{}, [32]byte{}, ErrTargetSnapshotConflict
		}
		resolved, err := s.resolver.ResolveTarget(ctx, tx, request.ConfigurationScopeID, *request.TargetSnapshot)
		if err != nil {
			return TargetSnapshot{}, [32]byte{}, fmt.Errorf("%w: resolve target", ErrTargetSnapshotConflict)
		}
		if resolved.Reference != *request.TargetSnapshot {
			return TargetSnapshot{}, [32]byte{}, ErrTargetSnapshotConflict
		}
		target = resolved
	}
	if len(target.NodeIDs) == 0 || len(target.NodeIDs) > maxPublicationTargets {
		return TargetSnapshot{}, [32]byte{}, ErrInvalidInput
	}
	for _, nodeID := range target.NodeIDs {
		if nodeID == uuid.Nil {
			return TargetSnapshot{}, [32]byte{}, ErrInvalidInput
		}
	}
	sort.Slice(target.NodeIDs, func(i, j int) bool { return bytes.Compare(target.NodeIDs[i][:], target.NodeIDs[j][:]) < 0 })
	if len(slices.Compact(slices.Clone(target.NodeIDs))) != len(target.NodeIDs) {
		return TargetSnapshot{}, [32]byte{}, ErrInvalidInput
	}
	digest, err := targetSnapshotDigest(targetKind(request), target)
	if err != nil {
		return TargetSnapshot{}, [32]byte{}, err
	}
	return target, digest, nil
}

func validateEligibleNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, nodeIDs []uuid.UUID) error {
	// A node carries this scope's state and one running deployment per scope;
	// another scope on it is checked against the node's capabilities below.
	rows, err := tx.Query(ctx, `
		SELECT node.id,node.scope_id,node_scope.kind,node.admin_state,
		       COALESCE(config.reconciliation_required,false),
		       EXISTS (SELECT 1 FROM node_config_state other
		           WHERE other.node_id=node.id AND other.configuration_scope_id<>$2),
		       EXISTS (
		           SELECT 1 FROM node_deployments deployment
		           WHERE deployment.node_id=node.id
		             AND (deployment.configuration_scope_id=$2 OR NOT deployment.queued_per_scope)
		             AND deployment.state NOT IN ('healthy','failed','reverted','rollback_failed','cancelled')
		       )
		FROM nodes node
		JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		LEFT JOIN node_config_state config ON config.node_id=node.id AND config.configuration_scope_id=$2
		WHERE node.id=ANY($1::uuid[])
		ORDER BY node.id
		FOR UPDATE OF node`, nodeIDs, scopeID)
	if err != nil {
		return fmt.Errorf("%w: read target nodes", ErrPersistence)
	}
	defer rows.Close()
	seen := 0
	var shared []uuid.UUID
	for rows.Next() {
		var nodeID, nodeScopeID uuid.UUID
		var nodeScopeKind, state string
		var reconciliation, otherScopes, activeDeployment bool
		if err := rows.Scan(&nodeID, &nodeScopeID, &nodeScopeKind, &state, &reconciliation,
			&otherScopes, &activeDeployment); err != nil {
			return fmt.Errorf("%w: scan target node", ErrPersistence)
		}
		seen++
		if activeDeployment {
			return edgedeployment.ErrNodeDeploymentActive
		}
		if reconciliation {
			return edgedeployment.ErrNodeReconciliationRequired
		}
		if state != "active" || (nodeScopeKind != ScopeKindPlatform && nodeScopeID != scopeID) {
			return ErrTargetIneligible
		}
		if otherScopes {
			shared = append(shared, nodeID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate target nodes", ErrPersistence)
	}
	rows.Close()
	if seen != len(nodeIDs) {
		return ErrTargetIneligible
	}
	for _, nodeID := range shared {
		if several, err := edgedeployment.NodeServesSeveralScopes(ctx, tx, nodeID); err != nil {
			return fmt.Errorf("%w: read target node capabilities", ErrPersistence)
		} else if !several {
			return ErrTargetIneligible
		}
	}
	return nil
}

func claimEligibleNodes(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	nodeIDs []uuid.UUID,
	now time.Time,
) error {
	// validateEligibleNodes holds the node rows and checked that every node
	// may serve this scope, so a scope unclaimed here stays unclaimed until
	// the insert below.
	rows, err := tx.Query(ctx, `
		SELECT node_id,reconciliation_required
		FROM node_config_state
		WHERE node_id=ANY($1::uuid[]) AND configuration_scope_id=$2
		ORDER BY node_id
		FOR UPDATE`, nodeIDs, scopeID)
	if err != nil {
		return fmt.Errorf("%w: lock target node configuration state", ErrPersistence)
	}
	defer rows.Close()
	claimed := make(map[uuid.UUID]bool, len(nodeIDs))
	for rows.Next() {
		var nodeID uuid.UUID
		var reconciliation bool
		if err := rows.Scan(&nodeID, &reconciliation); err != nil {
			return fmt.Errorf("%w: scan target node configuration state", ErrPersistence)
		}
		claimed[nodeID] = true
		if reconciliation {
			return edgedeployment.ErrNodeReconciliationRequired
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate target node configuration state", ErrPersistence)
	}
	rows.Close()
	unclaimed := make([]uuid.UUID, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if !claimed[nodeID] {
			unclaimed = append(unclaimed, nodeID)
		}
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO node_config_state (node_id,configuration_scope_id,updated_at)
		SELECT target.node_id,$2,$3
		FROM unnest($1::uuid[]) AS target(node_id)`, unclaimed, scopeID, now)
	if err != nil {
		return fmt.Errorf("%w: claim target node configuration scope", ErrPersistence)
	}
	if command.RowsAffected() != int64(len(unclaimed)) {
		return ErrTargetIneligible
	}
	return nil
}

func targetSnapshotDigest(kind string, target TargetSnapshot) ([32]byte, error) {
	nodeIDs := make([]string, len(target.NodeIDs))
	for index, nodeID := range target.NodeIDs {
		nodeIDs[index] = nodeID.String()
	}
	encoded, err := json.Marshal(struct {
		Schema         string   `json:"schema"`
		Kind           string   `json:"kind"`
		SnapshotID     string   `json:"snapshot_id,omitempty"`
		Revision       int64    `json:"revision,omitempty"`
		ResolverSHA256 string   `json:"resolver_sha256,omitempty"`
		NodeIDs        []string `json:"node_ids"`
	}{
		Schema: canonicalTargetSchema, Kind: kind, SnapshotID: uuidString(target.Reference.ID),
		Revision: target.Reference.Revision, ResolverSHA256: digestString(target.Reference.SHA256), NodeIDs: nodeIDs,
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: encode target snapshot", ErrInvalidInput)
	}
	return sha256.Sum256(encoded), nil
}

func validEntitlementDecision(decision EntitlementDecision, now time.Time) bool {
	// Grace publishes like valid; InGrace is only
	// recorded for audit.
	return decision.Allowed && decision.LocallyVerified &&
		(decision.Status == EntitlementStatusValid && !decision.InGrace ||
			decision.Status == EntitlementStatusGrace && decision.InGrace) && decision.LeaseSerial > 0 &&
		!decision.EvaluatedAt.IsZero() && !decision.EvaluatedAt.After(now)
}

func targetKind(request normalizedPublishRequest) string {
	if request.TargetSnapshot != nil {
		return TargetKindResolver
	}
	return TargetKindExplicit
}

func cloneTargetReference(value *TargetSnapshotReference) *TargetSnapshotReference {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func uuidString(value uuid.UUID) string {
	if value == uuid.Nil {
		return ""
	}
	return value.String()
}

func digestString(value [32]byte) string {
	if value == ([32]byte{}) {
		return ""
	}
	return fmt.Sprintf("%x", value[:])
}
