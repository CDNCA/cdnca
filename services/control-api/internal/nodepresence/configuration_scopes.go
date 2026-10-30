package nodepresence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// maxScopeRejections bounds the refused publications shown per node.
const maxScopeRejections = 20

// NodeConfigurationScopes is what an administrator sees of the tenants a
// node serves (docs/architecture/multi-tenant-node-sharing.md 6.2.1): each
// configuration scope's state, its latest deployment and the agent's last
// apply result, plus publications refused for conflicting with them.
type NodeConfigurationScopes struct {
	NodeID     uuid.UUID            `json:"node_id"`
	Scopes     []ConfigurationScope `json:"scopes"`
	Rejections []ScopeRejection     `json:"rejections"`
	// CapabilityRegressions are features the node's latest healthy
	// deployments use that its agent no longer declares (an agent rollback).
	CapabilityRegressions []CapabilityRegression `json:"capability_regressions"`
}

type ConfigurationScope struct {
	ScopeID                 uuid.UUID         `json:"scope_id"`
	ScopeKind               string            `json:"scope_kind"`
	TenantID                *uuid.UUID        `json:"tenant_id"`
	TenantName              string            `json:"tenant_name"`
	CurrentConfigVersionID  *uuid.UUID        `json:"current_config_version_id"`
	PreviousConfigVersionID *uuid.UUID        `json:"previous_config_version_id"`
	ReconciliationRequired  bool              `json:"reconciliation_required"`
	UpdatedAt               time.Time         `json:"updated_at"`
	LatestDeployment        *ScopeDeployment  `json:"latest_deployment"`
	LastApply               *ScopeApplyResult `json:"last_apply"`
	// TelemetryExcluded is why the node's authorization leaves this scope's
	// telemetry out (nodeidentity.TelemetryExclusion*), empty when it is in
	// or when the Inventory has no TelemetryExclusionReader. Only a node
	// serving several scopes isolates a scope this way.
	TelemetryExcluded string `json:"telemetry_excluded"`
}

type ScopeDeployment struct {
	DeploymentID    uuid.UUID `json:"deployment_id"`
	Attempt         int32     `json:"attempt"`
	RolloutID       uuid.UUID `json:"rollout_id"`
	ConfigVersionID uuid.UUID `json:"config_version_id"`
	Action          string    `json:"action"`
	// State is the control plane's view: queued, delivered, agent_queued,
	// started, staged, ..., healthy, failed, ...
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ScopeApplyResult is the agent's last apply of the scope as reported in its
// heartbeat; superseded only ever appears here.
type ScopeApplyResult struct {
	DeploymentID    uuid.UUID  `json:"deployment_id"`
	Attempt         int32      `json:"attempt"`
	ConfigVersionID uuid.UUID  `json:"config_version_id"`
	State           string     `json:"state"`
	ErrorCode       *string    `json:"error_code"`
	FinishedAt      *time.Time `json:"finished_at"`
	ReportedAt      time.Time  `json:"reported_at"`
}

type ScopeRejection struct {
	ScopeID    uuid.UUID `json:"scope_id"`
	TenantName string    `json:"tenant_name"`
	Reason     string    `json:"reason"`
	RequestID  string    `json:"request_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

// ConfigurationScopes reads a node of the caller's scope. It is read-only.
func (i *Inventory) ConfigurationScopes(ctx context.Context, scopeID, nodeID uuid.UUID) (NodeConfigurationScopes, error) {
	result := NodeConfigurationScopes{NodeID: nodeID, Scopes: []ConfigurationScope{}, Rejections: []ScopeRejection{},
		CapabilityRegressions: []CapabilityRegression{}}
	err := pgx.BeginTxFunc(ctx, i.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			var found bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id=$1 AND id=$2)`,
				scopeID, nodeID).Scan(&found); err != nil {
				return err
			}
			if !found {
				return node.ErrNotFound
			}
			rows, err := tx.Query(ctx, `SELECT state.configuration_scope_id, scope.kind, scope.tenant_id,
					COALESCE(tenant.display_name,''), state.current_config_version_id, state.previous_config_version_id,
					state.reconciliation_required, state.updated_at,
					deployment.id, deployment.attempt, deployment.rollout_id, deployment.config_version_id,
					deployment.action, deployment.state, deployment.updated_at,
					identity.last_apply_deployment_id, identity.last_apply_attempt, identity.last_apply_config_version_id,
					identity.last_apply_state, identity.last_apply_error_code, identity.last_apply_finished_at,
					identity.updated_at
				FROM node_config_state state
				JOIN access_scopes scope ON scope.id=state.configuration_scope_id
				LEFT JOIN tenants tenant ON tenant.id=scope.tenant_id
				LEFT JOIN LATERAL (
					SELECT id, attempt, rollout_id, config_version_id, action, state, updated_at
					FROM node_deployments
					WHERE node_id=state.node_id AND configuration_scope_id=state.configuration_scope_id
					ORDER BY created_at DESC, attempt DESC LIMIT 1
				) deployment ON true
				LEFT JOIN node_presence_scope_identities identity
				  ON identity.node_id=state.node_id AND identity.configuration_scope_id=state.configuration_scope_id
				WHERE state.node_id=$1
				ORDER BY COALESCE(tenant.display_name,''), state.configuration_scope_id`, nodeID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var item ConfigurationScope
				var deploymentID, rolloutID, deploymentConfig *uuid.UUID
				var deploymentAttempt *int32
				var deploymentAction, deploymentState *string
				var deploymentUpdated *time.Time
				var applyID, applyConfig *uuid.UUID
				var applyAttempt *int32
				var applyState *string
				var applyError *string
				var applyFinished, reportedAt *time.Time
				if err := rows.Scan(&item.ScopeID, &item.ScopeKind, &item.TenantID, &item.TenantName,
					&item.CurrentConfigVersionID, &item.PreviousConfigVersionID, &item.ReconciliationRequired, &item.UpdatedAt,
					&deploymentID, &deploymentAttempt, &rolloutID, &deploymentConfig, &deploymentAction, &deploymentState,
					&deploymentUpdated, &applyID, &applyAttempt, &applyConfig, &applyState, &applyError, &applyFinished,
					&reportedAt); err != nil {
					return err
				}
				if deploymentID != nil {
					item.LatestDeployment = &ScopeDeployment{DeploymentID: *deploymentID, Attempt: *deploymentAttempt,
						RolloutID: *rolloutID, ConfigVersionID: *deploymentConfig, Action: *deploymentAction,
						State: *deploymentState, UpdatedAt: *deploymentUpdated}
				}
				if applyID != nil {
					item.LastApply = &ScopeApplyResult{DeploymentID: *applyID, Attempt: *applyAttempt,
						ConfigVersionID: *applyConfig, State: *applyState, ErrorCode: applyError,
						FinishedAt: applyFinished, ReportedAt: *reportedAt}
				}
				result.Scopes = append(result.Scopes, item)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			rows.Close()
			if i.exclusions != nil {
				excluded, err := i.exclusions(ctx, tx, nodeID, i.now())
				if err != nil {
					return err
				}
				for index := range result.Scopes {
					result.Scopes[index].TelemetryExcluded = excluded[result.Scopes[index].ScopeID]
				}
			}
			// Indexed by audit_events_node_scope_conflict_292_idx.
			rejections, err := tx.Query(ctx, `SELECT event.scope_id, COALESCE(tenant.display_name,''),
					event.payload, event.request_id, event.occurred_at
				FROM audit_events event
				JOIN access_scopes scope ON scope.id=event.scope_id
				LEFT JOIN tenants tenant ON tenant.id=scope.tenant_id
				WHERE event.action='edge_publication.node_scope_conflict' AND event.resource_type='node'
				  AND event.resource_id=$1
				ORDER BY event.occurred_at DESC, event.id DESC LIMIT $2`, nodeID.String(), maxScopeRejections)
			if err != nil {
				return err
			}
			defer rejections.Close()
			for rejections.Next() {
				var item ScopeRejection
				var payload []byte
				if err := rejections.Scan(&item.ScopeID, &item.TenantName, &payload, &item.RequestID, &item.OccurredAt); err != nil {
					return err
				}
				var body struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(payload, &body); err != nil {
					return err
				}
				item.Reason = body.Reason
				result.Rejections = append(result.Rejections, item)
			}
			if err := rejections.Err(); err != nil {
				return err
			}
			rejections.Close()
			regressions, err := readCapabilityRegressions(ctx, tx, nodeID)
			if err != nil {
				return err
			}
			result.CapabilityRegressions = regressions
			return nil
		})
	if errors.Is(err, node.ErrNotFound) {
		return NodeConfigurationScopes{}, err
	}
	if err != nil {
		return NodeConfigurationScopes{}, fmt.Errorf("read node configuration scopes: %w", err)
	}
	return result, nil
}
