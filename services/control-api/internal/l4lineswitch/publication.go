package l4lineswitch

import (
	"context"
	"errors"
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type PostgresPublicationCoordinator struct {
	pool        *pgxpool.Pool
	iam         *iamlock.Authorizer
	deployments *edgedeployment.Store
	auditor     auditAppender
}

func NewPostgresPublicationCoordinator(
	pool *pgxpool.Pool,
	iam *iamlock.Authorizer,
	deployments *edgedeployment.Store,
	auditor auditAppender,
) (*PostgresPublicationCoordinator, error) {
	if pool == nil || iam == nil || !iam.Configured() || deployments == nil {
		return nil, ErrInvalidInput
	}
	if auditor == nil {
		auditor = audit.New(pool)
	}
	return &PostgresPublicationCoordinator{pool: pool, iam: iam, deployments: deployments, auditor: auditor}, nil
}

func (coordinator *PostgresPublicationCoordinator) Prepare(
	ctx context.Context,
	actor Actor,
	value Switch,
) (Publication, error) {
	return coordinator.publish(ctx, actor, value, "prepare", value.PrepareNodes)
}

func (coordinator *PostgresPublicationCoordinator) Compensate(
	ctx context.Context,
	actor Actor,
	value Switch,
) (Publication, error) {
	return coordinator.publish(ctx, actor, value, "compensate", value.From.NodeIDs)
}

func (coordinator *PostgresPublicationCoordinator) RolloutStatus(
	ctx context.Context,
	actor Actor,
	value Switch,
	rolloutID uuid.UUID,
) (string, error) {
	if ctx == nil || coordinator == nil || !validAuthority(actor) || value.ConfigurationScopeID == uuid.Nil || rolloutID == uuid.Nil {
		return "", ErrInvalidInput
	}
	if workloadAuthority(actor) {
		return coordinator.workloadRolloutStatus(ctx, actor, value, rolloutID)
	}
	deploymentActor, err := edgedeployment.NewSessionActor(
		actor.UserID, actor.ScopeID, actor.ScopeKind, actor.SessionID, actor.Credential,
	)
	if err != nil {
		return "", ErrInvalidInput
	}
	rollout, err := coordinator.deployments.GetRollout(ctx, deploymentActor, value.ConfigurationScopeID, rolloutID)
	if err != nil {
		return "", mapDeploymentError(err)
	}
	switch rollout.State {
	case edgedeployment.RolloutStateQueued, edgedeployment.RolloutStateRunning:
		return RolloutPending, nil
	case edgedeployment.RolloutStateSucceeded:
		return RolloutSucceeded, nil
	case edgedeployment.RolloutStatePartialFailed, edgedeployment.RolloutStateFailed,
		edgedeployment.RolloutStateCancelled:
		return RolloutFailed, nil
	default:
		return "", ErrConflict
	}
}

func (coordinator *PostgresPublicationCoordinator) publish(
	ctx context.Context,
	actor Actor,
	value Switch,
	phase string,
	nodeIDs []uuid.UUID,
) (Publication, error) {
	if ctx == nil || coordinator == nil || !validAuthority(actor) || value.ID == uuid.Nil ||
		value.ConfigurationScopeID == uuid.Nil || value.ExpectedSourceRevision < 1 || len(nodeIDs) == 0 ||
		(phase != "prepare" && phase != "compensate") {
		return Publication{}, ErrInvalidInput
	}
	var result Publication
	err := pgx.BeginFunc(ctx, coordinator.pool, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, coordinator.iam, actor, value.ConfigurationScopeID, value.ID, PermissionManage); err != nil {
			return err
		}
		var sourcePublicationID, configVersionID, sourceRolloutID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id,config_version_id,rollout_id
			FROM edge_config_publications
			WHERE configuration_scope_id=$1 AND source_revision=$2 AND contract_version=1
			FOR SHARE`, value.ConfigurationScopeID, value.ExpectedSourceRevision).
			Scan(&sourcePublicationID, &configVersionID, &sourceRolloutID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("%w: load source publication", ErrPersistence)
		}
		capabilities, err := loadPublicationCapabilities(ctx, tx, value.ConfigurationScopeID, sourceRolloutID, configVersionID)
		if err != nil {
			return err
		}
		requestID := uuid.NewSHA1(value.ID, []byte(phase+":request"))
		taskID := "l4-switch-" + value.ID.String()
		rollout, err := coordinator.deployments.CreateRolloutTx(ctx, tx, edgedeployment.CreateRolloutRequest{
			ConfigurationScopeID: value.ConfigurationScopeID,
			ConfigVersionID:      configVersionID,
			Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
			NodeIDs:              nodeIDs,
			RequiredCapabilities: capabilities,
			HealthCheck: edgedeployment.HealthCheckPolicy{
				ActivationTimeout:            value.Health.ActivationTimeout,
				ObservationWindow:            value.Health.ObservationWindow,
				RequiredConsecutiveSuccesses: value.Health.RequiredConsecutiveSuccesses,
			},
			Deadline:        value.Deadline,
			IdempotencyKey:  "l4-switch." + value.ID.String() + "." + phase,
			RequestID:       requestID.String(),
			CorrelationID:   value.CorrelationID.String(),
			Traceparent:     value.Traceparent,
			TaskID:          &taskID,
			MaxAttempts:     value.MaxAttempts,
			ContractVersion: 1,
		})
		if err != nil {
			return mapDeploymentError(err)
		}
		result = Publication{ID: sourcePublicationID, RolloutID: rollout.Rollout.ID, ConfigVersionID: configVersionID}
		if rollout.Replayed {
			return nil
		}
		if err := coordinator.auditor.Append(ctx, tx, audit.Event{
			ScopeID: value.ConfigurationScopeID, ActorUserID: auditActorUserID(actor),
			Action: "l4_line_switch." + phase + "_publication", ResourceType: "l4_line_switch",
			ResourceID: value.ID.String(), RequestID: requestID.String(), Result: "success",
			Payload: map[string]any{
				"source_publication_id": sourcePublicationID.String(), "config_version_id": configVersionID.String(),
				"rollout_id": rollout.Rollout.ID.String(), "node_count": len(nodeIDs),
			},
		}); err != nil {
			return fmt.Errorf("%w: append publication audit", ErrPersistence)
		}
		return nil
	})
	return result, err
}

func (coordinator *PostgresPublicationCoordinator) workloadRolloutStatus(
	ctx context.Context,
	actor Actor,
	value Switch,
	rolloutID uuid.UUID,
) (string, error) {
	var total, succeeded, superseded, failed, cancelled int
	err := pgx.BeginTxFunc(ctx, coordinator.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, coordinator.iam, actor, value.ConfigurationScopeID, value.ID, PermissionManage); err != nil {
			return err
		}
		// An ignored old release (edgedeployment.SupersededDeploymentSQL)
		// ends its node without failing the rollout (fix-cfgflow3).
		return tx.QueryRow(ctx, `WITH latest AS (
			SELECT DISTINCT ON (deployment.node_id) deployment.node_id,deployment.state,
			       `+edgedeployment.SupersededDeploymentSQL+` AS superseded
			FROM node_deployments deployment
			JOIN rollouts rollout ON rollout.id=deployment.rollout_id
			WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2
			ORDER BY deployment.node_id,deployment.attempt DESC
		) SELECT count(*),count(*) FILTER (WHERE state='healthy'),count(*) FILTER (WHERE superseded),
			count(*) FILTER (WHERE state IN ('failed','rollback_failed') AND NOT superseded),
			count(*) FILTER (WHERE state='cancelled') FROM latest`, value.ConfigurationScopeID, rolloutID).
			Scan(&total, &succeeded, &superseded, &failed, &cancelled)
	})
	if err != nil {
		return "", fmt.Errorf("%w: read rollout status", ErrPersistence)
	}
	if total == 0 {
		return "", ErrConflict
	}
	return workloadRolloutState(total, succeeded, superseded, failed, cancelled), nil
}

// workloadRolloutState is the switch rollout's state from its nodes' latest
// deployments: an ignored old release counts as done, not failed.
func workloadRolloutState(total, succeeded, superseded, failed, cancelled int) string {
	switch {
	case succeeded+superseded == total:
		return RolloutSucceeded
	case succeeded+superseded+failed+cancelled == total:
		return RolloutFailed
	default:
		return RolloutPending
	}
}

func loadPublicationCapabilities(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, rolloutID, configVersionID uuid.UUID,
) ([]*agentv1.Capability, error) {
	var encoded []byte
	if err := tx.QueryRow(ctx, `SELECT deployment.command_bytes
		FROM node_deployments deployment
		JOIN rollouts rollout ON rollout.id=deployment.rollout_id
		WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2 AND rollout.config_version_id=$3
		  AND deployment.attempt=1 AND deployment.command_sha256=sha256(deployment.command_bytes)
		ORDER BY deployment.node_id LIMIT 1`, scopeID, rolloutID, configVersionID).Scan(&encoded); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	} else if err != nil {
		return nil, fmt.Errorf("%w: load source publication capabilities", ErrPersistence)
	}
	var command agentv1.DeploymentCommand
	if proto.Unmarshal(encoded, &command) != nil || command.RolloutId != rolloutID.String() ||
		command.ConfigVersionId != configVersionID.String() || len(command.RequiredCapabilities) == 0 {
		return nil, ErrConflict
	}
	capabilities := make([]*agentv1.Capability, len(command.RequiredCapabilities))
	for index, capability := range command.RequiredCapabilities {
		if capability == nil {
			return nil, ErrConflict
		}
		capabilities[index] = proto.Clone(capability).(*agentv1.Capability)
	}
	return capabilities, nil
}

func mapDeploymentError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, edgedeployment.ErrUnauthenticated):
		return ErrUnauthenticated
	case errors.Is(err, edgedeployment.ErrPermissionDenied):
		return ErrPermissionDenied
	case errors.Is(err, edgedeployment.ErrNotFound), errors.Is(err, edgedeployment.ErrConfigNotFound):
		return ErrNotFound
	case errors.Is(err, edgedeployment.ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	case errors.Is(err, edgedeployment.ErrNodeDeploymentActive),
		errors.Is(err, edgedeployment.ErrNodeReconciliationRequired),
		errors.Is(err, edgedeployment.ErrConfigurationScopeConflict),
		errors.Is(err, edgedeployment.ErrConfigNotReleasable):
		return ErrConflict
	default:
		return fmt.Errorf("%w: edge deployment", ErrPersistence)
	}
}
