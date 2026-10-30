package edgestatus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type Store struct {
	pool    *pgxpool.Pool
	now     func() time.Time
	auditor *audit.Log
}

type lockedDeployment struct {
	rolloutID        uuid.UUID
	nodeID           uuid.UUID
	configID         uuid.UUID
	previousConfigID *uuid.UUID
	scopeID          uuid.UUID
	action           string
	state            string
	commandBytes     []byte
	commandDigest    []byte
}

type artifactDomain uint8

const (
	artifactDomainConfiguration artifactDomain = iota + 1
	artifactDomainSecret
	// artifactDomainNodeArtifact: a platform-scope delivery of a node-side
	// artifact (IP intelligence library). It moves through the same state
	// machine but is never a node's running configuration.
	artifactDomainNodeArtifact
)

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	return NewStoreWithClock(pool, time.Now)
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time) (*Store, error) {
	if pool == nil || now == nil {
		return nil, fmt.Errorf("%w: store requires a PostgreSQL pool and clock", ErrProjectionConflict)
	}
	return &Store{pool: pool, now: now, auditor: audit.NewWithClock(pool, now)}, nil
}

func (s *Store) Project(ctx context.Context, envelope Envelope) (ProjectionResult, error) {
	if ctx == nil {
		return ProjectionResult{}, fmt.Errorf("%w: context", ErrInvalidStatus)
	}
	state, ok := stateStorageValue(envelope.Status.GetState())
	if !ok || envelope.NodeID == uuid.Nil || envelope.DeploymentID == uuid.Nil || envelope.ConfigID == uuid.Nil ||
		envelope.EventID == uuid.Nil || envelope.RequestID == uuid.Nil {
		return ProjectionResult{}, fmt.Errorf("%w: envelope", ErrInvalidStatus)
	}
	if err := verifyEnvelope(envelope); err != nil {
		return ProjectionResult{}, err
	}
	// Only a MULTI_TENANT_RUNTIME agent queues deployments, and it always
	// names the scope.
	if (state == "agent_queued" || state == "started") && envelope.Status.ConfigurationScopeId == nil {
		return ProjectionResult{}, fmt.Errorf("%w: agent queue state without configuration scope", ErrInvalidStatus)
	}
	identity, err := normalizeStatusActiveIdentity(envelope.Status)
	if err != nil {
		return ProjectionResult{}, err
	}
	receivedAt := s.now().UTC().Truncate(time.Microsecond)
	result := ProjectionResult{
		DeploymentID: envelope.DeploymentID, Attempt: envelope.Status.Attempt,
		TransitionSequence: envelope.Status.TransitionSequence, State: state, ReceivedAt: receivedAt,
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		deployment, err := lockDeployment(ctx, tx, envelope.DeploymentID, envelope.Status.Attempt)
		if err != nil {
			return err
		}
		if deployment.nodeID != envelope.NodeID || deployment.configID != envelope.ConfigID {
			return ErrBindingConflict
		}
		if err := verifyCommandBinding(deployment, envelope); err != nil {
			return err
		}
		domain, err := deriveArtifactDomain(ctx, tx, deployment, envelope.DeploymentID, envelope.Status.Attempt)
		if err != nil {
			return err
		}
		if domain == artifactDomainConfiguration {
			if err := requireTerminalConfigConvergence(deployment, state, envelope.Status, identity); err != nil {
				return err
			}
		}
		if identity != nil {
			if domain != artifactDomainConfiguration || !completesRunningConfig(deployment.action, state) {
				return ErrBindingConflict
			}
			if err := requireStatusIdentityBinding(ctx, tx, deployment, envelope, identity); err != nil {
				return err
			}
		}
		duplicate, err := findEventByID(ctx, tx, envelope.EventID, envelope.Digest)
		if err != nil {
			return err
		}
		if duplicate {
			result.Outcome = OutcomeDuplicate
			return nil
		}
		if err := rejectSequenceConflict(ctx, tx, envelope); err != nil {
			return err
		}
		var maxSequence int64
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(MAX(transition_sequence), 0)
			FROM deployment_status_events WHERE deployment_id = $1 AND attempt = $2`,
			envelope.DeploymentID, envelope.Status.Attempt).Scan(&maxSequence); err != nil {
			return fmt.Errorf("read deployment status high water: %w", err)
		}
		if maxSequence == 0 && deployment.state != "queued" {
			return ErrProjectionConflict
		}
		stale := envelope.Status.TransitionSequence <= uint64(maxSequence)
		if stale {
			if err := validateStaleEvent(ctx, tx, deployment.action, envelope, state); err != nil {
				return err
			}
		} else if !validAdvance(deployment.action, deployment.state, state) {
			return ErrInvalidTransition
		}
		if err := insertEvent(ctx, tx, envelope, state, receivedAt, domain); err != nil {
			return err
		}
		if stale {
			result.Outcome = OutcomeStale
			return nil
		}
		if domain == artifactDomainNodeArtifact {
			if err := s.recordArtifactSetReceipt(ctx, tx, deployment, envelope, state, receivedAt); err != nil {
				return err
			}
		} else if len(envelope.Status.GetArtifactSetReceipt()) != 0 {
			return fmt.Errorf("%w: node artifact set receipt on a configuration deployment", ErrBindingConflict)
		}
		if domain == artifactDomainConfiguration && state == "rollback_failed" {
			if err := requireRunningStateReconciliation(ctx, tx, deployment, envelope, receivedAt); err != nil {
				return err
			}
		}
		if domain == artifactDomainConfiguration && completesRunningConfig(deployment.action, state) {
			if err := updateRunningConfig(ctx, tx, deployment, envelope, receivedAt); err != nil {
				return err
			}
		}
		command, err := tx.Exec(ctx, `
			UPDATE node_deployments SET state = $3, updated_at = $4
			WHERE id = $1 AND attempt = $2 AND state = $5`,
			envelope.DeploymentID, envelope.Status.Attempt, state, receivedAt, deployment.state)
		if err != nil {
			return fmt.Errorf("advance node deployment: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrProjectionConflict
		}
		// A frozen node's refusal waits for redelivery (fix-stoppolicy2):
		// marked before the rollout advances, so it is no failure there.
		if domain == artifactDomainConfiguration && edgedeployment.FrozenRefusal(deployment.action, envelope.Status) {
			if _, err := tx.Exec(ctx, `INSERT INTO node_deployment_frozen_refusals(
				deployment_id,attempt,node_id,configuration_scope_id,refused_at)
				SELECT id,attempt,node_id,configuration_scope_id,clock_timestamp() FROM node_deployments
				WHERE id=$1 AND attempt=$2
				ON CONFLICT DO NOTHING`, envelope.DeploymentID, envelope.Status.Attempt); err != nil {
				return fmt.Errorf("mark frozen deployment refusal: %w", err)
			}
		}
		if err := edgedeployment.AdvanceRolloutAfterStatusTx(ctx, tx, deployment.rolloutID, receivedAt); err != nil {
			return err
		}
		// Delivered on commit: the node artifact set distributor sends the
		// node its next segment or set now instead of on its next sweep
		// (one delivery in flight per node, ADR 0007 section 4.3; O2).
		if domain == artifactDomainNodeArtifact && nodeArtifactDeliveryEnded(state) {
			if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, NodeArtifactDeliveryChannel,
				envelope.NodeID.String()); err != nil {
				return fmt.Errorf("notify node artifact delivery: %w", err)
			}
		}
		// A platform-scope delivery (node-side artifact) is no tenant's
		// deployment: it raises no tenant domain event.
		if domain != artifactDomainNodeArtifact {
			if err := enqueueDeploymentStatusEvent(ctx, tx, deployment.scopeID, envelope, deployment.rolloutID,
				state); err != nil {
				return err
			}
		}
		result.Outcome = OutcomeAdvanced
		return nil
	})
	if err != nil {
		return ProjectionResult{}, fmt.Errorf("project deployment status: %w", err)
	}
	return result, nil
}

func deriveArtifactDomain(ctx context.Context, tx pgx.Tx, deployment lockedDeployment,
	deploymentID uuid.UUID, attempt uint32,
) (artifactDomain, error) {
	query := `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE artifact.kind = 'configuration'),
		       COUNT(*) FILTER (WHERE artifact.kind = 'node_secret_bundle'),
		       COUNT(*) FILTER (WHERE artifact.kind = 'configuration' AND artifact.media_type = ANY($3::text[]))
		FROM node_deployment_artifacts binding
		JOIN configuration_artifacts artifact
		  ON artifact.config_version_id = binding.config_version_id
		 AND artifact.id = binding.artifact_id
		WHERE binding.deployment_id = $1 AND binding.deployment_attempt = $2`
	args := []any{deploymentID, attempt, nodeArtifactMediaTypes}
	if deployment.action == "rollback" {
		query = `
			SELECT COUNT(*),
			       COUNT(*) FILTER (WHERE kind = 'configuration'),
			       COUNT(*) FILTER (WHERE kind = 'node_secret_bundle'),
			       COUNT(*) FILTER (WHERE kind = 'configuration' AND media_type = ANY($2::text[]))
			FROM configuration_artifacts WHERE config_version_id = $1`
		args = []any{deployment.configID, nodeArtifactMediaTypes}
	}
	var total, configurations, secrets, nodeArtifacts int64
	if err := tx.QueryRow(ctx, query, args...).Scan(&total, &configurations, &secrets, &nodeArtifacts); err != nil {
		return 0, fmt.Errorf("derive deployment artifact domain: %w", err)
	}
	switch {
	case total > 0 && nodeArtifacts == total:
		// Migration 329 keeps these media types in the platform scope only.
		return artifactDomainNodeArtifact, nil
	case nodeArtifacts > 0:
		return 0, ErrProjectionConflict
	case total > 0 && configurations == total:
		return artifactDomainConfiguration, nil
	case total > 0 && secrets == total:
		return artifactDomainSecret, nil
	default:
		return 0, ErrProjectionConflict
	}
}

func requireRunningStateReconciliation(ctx context.Context, tx pgx.Tx, deployment lockedDeployment, envelope Envelope, now time.Time) error {
	command, err := tx.Exec(ctx, `
			UPDATE node_config_state
			SET reconciliation_required = true,
			    reconciliation_reason = 'rollback_failed',
			    reconciliation_deployment_id = $2,
			    reconciliation_deployment_attempt = $3,
			    reconciliation_requested_at = $4,
			    current_config_identity_schema = NULL,
			    current_config_artifact_sha256 = NULL,
			    revision = revision + 1,
		    updated_at = $4
		WHERE node_id = $1 AND configuration_scope_id = $5 AND NOT reconciliation_required`,
		envelope.NodeID, envelope.DeploymentID, envelope.Status.Attempt, now, deployment.scopeID)
	if err != nil {
		return fmt.Errorf("require node running state reconciliation: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrProjectionConflict
	}
	return nil
}

func validateStaleEvent(ctx context.Context, tx pgx.Tx, action string, envelope Envelope, state string) error {
	predecessor := "queued"
	if err := tx.QueryRow(ctx, `
		SELECT state FROM deployment_status_events
		WHERE deployment_id = $1 AND attempt = $2 AND transition_sequence < $3
		ORDER BY transition_sequence DESC LIMIT 1`,
		envelope.DeploymentID, envelope.Status.Attempt, envelope.Status.TransitionSequence).Scan(&predecessor); err != nil &&
		!errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read stale deployment status predecessor: %w", err)
	}
	var successor string
	if err := tx.QueryRow(ctx, `
		SELECT state FROM deployment_status_events
		WHERE deployment_id = $1 AND attempt = $2 AND transition_sequence > $3
		ORDER BY transition_sequence ASC LIMIT 1`,
		envelope.DeploymentID, envelope.Status.Attempt, envelope.Status.TransitionSequence).Scan(&successor); errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidTransition
	} else if err != nil {
		return fmt.Errorf("read stale deployment status successor: %w", err)
	}
	if !validAdvance(action, predecessor, state) || !validAdvance(action, state, successor) {
		return ErrInvalidTransition
	}
	return nil
}

func verifyEnvelope(envelope Envelope) error {
	if envelope.Status == nil || envelope.Status.Event == nil ||
		envelope.Status.DeploymentId != envelope.DeploymentID.String() ||
		envelope.Status.ConfigVersionId != envelope.ConfigID.String() ||
		envelope.Status.Event.EventId != envelope.EventID.String() ||
		envelope.Status.Event.RequestId != envelope.RequestID.String() {
		return fmt.Errorf("%w: envelope identity", ErrInvalidStatus)
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope.Status)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return fmt.Errorf("%w: envelope payload", ErrInvalidStatus)
	}
	digest := sha256.Sum256(canonical)
	if digest != envelope.Digest {
		return fmt.Errorf("%w: envelope digest", ErrInvalidStatus)
	}
	return nil
}

func lockDeployment(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, attempt uint32) (lockedDeployment, error) {
	var value lockedDeployment
	err := tx.QueryRow(ctx, `
		SELECT deployment.rollout_id,deployment.node_id, deployment.config_version_id, deployment.previous_config_version_id,
		       rollout.configuration_scope_id, deployment.action, deployment.state,
		       deployment.command_bytes, deployment.command_sha256
		FROM node_deployments deployment
		JOIN rollouts rollout ON rollout.id = deployment.rollout_id
		WHERE deployment.id = $1 AND deployment.attempt = $2
		FOR UPDATE OF deployment`, deploymentID, attempt).Scan(
		&value.rolloutID, &value.nodeID, &value.configID, &value.previousConfigID, &value.scopeID,
		&value.action, &value.state, &value.commandBytes, &value.commandDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedDeployment{}, ErrDeploymentMissing
	}
	if err != nil {
		return lockedDeployment{}, fmt.Errorf("lock node deployment: %w", err)
	}
	if value.action != "apply" && value.action != "rollback" {
		return lockedDeployment{}, ErrProjectionConflict
	}
	return value, nil
}

// CrossHostClockSkew bounds how far a node's status time (node clock) may
// precede its command's time (controller clock) before the status is taken to
// answer some other command. The two are different hosts' clocks: a
// STARTED was refused, stamped by a node clock behind the controller, sent tens
// of milliseconds after delivery. NTP keeps hosts within tens of milliseconds
// (the field node was +25.5 ms); 5 s covers a node that has not synced yet
// while staying far below the shortest deployment deadline (15 min), and the
// binding itself rests on the command's event ID, request ID and digest.
const CrossHostClockSkew = 5 * time.Second

func verifyCommandBinding(deployment lockedDeployment, envelope Envelope) error {
	digest := sha256.Sum256(deployment.commandBytes)
	if len(deployment.commandDigest) != sha256.Size || !bytes.Equal(digest[:], deployment.commandDigest) {
		return ErrProjectionConflict
	}
	command := new(agentv1.DeploymentCommand)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(deployment.commandBytes, command); err != nil || hasUnknown(command.ProtoReflect()) {
		return ErrProjectionConflict
	}
	if command.Event == nil || command.DeploymentId != envelope.DeploymentID.String() ||
		command.Attempt != envelope.Status.Attempt || command.ConfigVersionId != envelope.ConfigID.String() ||
		command.Event.RequestId != envelope.Status.Event.RequestId || envelope.Status.Event.CausationId == nil ||
		envelope.Status.Event.GetCausationId() != command.Event.EventId ||
		command.Event.Traceparent != envelope.Status.Event.Traceparent ||
		command.Event.CorrelationId != envelope.Status.Event.CorrelationId ||
		!sameOptionalString(command.Event.TaskId, envelope.Status.Event.TaskId) {
		return ErrBindingConflict
	}
	wantAction := agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY
	if deployment.action == "rollback" {
		wantAction = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	}
	if command.Action != wantAction || command.Event.OccurredTime == nil ||
		command.Event.OccurredTime.CheckValid() != nil || envelope.Status.Event.OccurredTime == nil ||
		envelope.Status.Event.OccurredTime.AsTime().Before(command.Event.OccurredTime.AsTime().Add(-CrossHostClockSkew)) {
		return ErrBindingConflict
	}
	// MULTI_TENANT_RUNTIME agents echo the scope on every status; it must be
	// the deployment's own.
	if envelope.Status.ConfigurationScopeId != nil && envelope.Status.GetConfigurationScopeId() != deployment.scopeID.String() {
		return ErrBindingConflict
	}
	return nil
}

func findEventByID(ctx context.Context, tx pgx.Tx, eventID uuid.UUID, digest [32]byte) (bool, error) {
	var persisted []byte
	err := tx.QueryRow(ctx, `SELECT payload_sha256 FROM deployment_status_events WHERE event_id = $1`, eventID).Scan(&persisted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read deployment status event: %w", err)
	}
	if !bytes.Equal(persisted, digest[:]) {
		return false, ErrPayloadConflict
	}
	return true, nil
}

func rejectSequenceConflict(ctx context.Context, tx pgx.Tx, envelope Envelope) error {
	var eventID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT event_id FROM deployment_status_events
		WHERE deployment_id = $1 AND attempt = $2 AND transition_sequence = $3`,
		envelope.DeploymentID, envelope.Status.Attempt, envelope.Status.TransitionSequence).Scan(&eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read deployment status sequence: %w", err)
	}
	return ErrPayloadConflict
}

func insertEvent(ctx context.Context, tx pgx.Tx, envelope Envelope, state string, receivedAt time.Time,
	domain artifactDomain,
) error {
	// 运行配置身份只属于 configuration 制品。证书等 node_secret_bundle 下发完成时节点同样带上
	// v1 身份能力但没有（也不可能有）配置身份；若照样记录 api_version=1，迁移 087 的触发器会以
	// “v1 healthy status requires active identity” 拒绝，状态被无限重投，下发永远停在 activated。
	identityAPIVersion := statusIdentityAPIVersion(envelope.Status)
	if domain != artifactDomainConfiguration {
		identityAPIVersion = nil
	}
	_, err := tx.Exec(ctx, `
			INSERT INTO deployment_status_events (
				id, deployment_id, event_id, attempt, transition_sequence, state,
				payload, payload_sha256, occurred_at, received_at,
				active_config_identity_api_version, active_config_identity_schema,
				active_config_version_id, active_config_artifact_sha256, error_code
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		uuid.New(), envelope.DeploymentID, envelope.EventID, envelope.Status.Attempt,
		envelope.Status.TransitionSequence, state, envelope.Payload, envelope.Digest[:],
		envelope.Status.Event.OccurredTime.AsTime(), receivedAt,
		identityAPIVersion, statusIdentitySchema(envelope.Status),
		statusIdentityConfigID(envelope.Status), statusIdentityDigest(envelope.Status),
		statusErrorCode(envelope.Status, state))
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrPayloadConflict
	}
	return fmt.Errorf("append deployment status event: %w", err)
}

// statusErrorCode is the protocol error code stored with a failed status
// (migration 564): the ignored-old-release rule reads it in SQL.
func statusErrorCode(status *agentv1.DeploymentStatus, state string) *string {
	if status.GetError() == nil || (state != "failed" && state != "rollback_failed") {
		return nil
	}
	code := status.GetError().GetCode().String()
	return &code
}

func completesRunningConfig(action, state string) bool {
	return action == "apply" && state == "healthy" || action == "rollback" && state == "reverted"
}

func updateRunningConfig(ctx context.Context, tx pgx.Tx, deployment lockedDeployment, envelope Envelope, now time.Time) error {
	var scopeID *uuid.UUID
	var currentID, previousID *uuid.UUID
	var currentSchema, previousSchema *int32
	var currentDigest, previousDigest []byte
	err := tx.QueryRow(ctx, `
			SELECT configuration_scope_id, current_config_version_id, previous_config_version_id,
			       current_config_identity_schema, current_config_artifact_sha256,
			       previous_config_identity_schema, previous_config_artifact_sha256
			FROM node_config_state WHERE node_id = $1 AND configuration_scope_id = $2 FOR UPDATE`,
		envelope.NodeID, deployment.scopeID).Scan(
		&scopeID, &currentID, &previousID, &currentSchema, &currentDigest, &previousSchema, &previousDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrProjectionConflict
	}
	if err != nil {
		return fmt.Errorf("lock node config state: %w", err)
	}
	if scopeID == nil || *scopeID != deployment.scopeID || !sameOptionalUUID(currentID, deployment.previousConfigID) {
		return ErrProjectionConflict
	}
	identity, err := normalizeStatusActiveIdentity(envelope.Status)
	if err != nil {
		return err
	}
	nextPreviousID := currentID
	nextPreviousSchema, nextPreviousDigest := currentSchema, currentDigest
	var nextCurrentSchema *int32
	var nextCurrentDigest []byte
	if deployment.action == "apply" && currentID != nil && *currentID == envelope.ConfigID {
		nextPreviousID, nextPreviousSchema, nextPreviousDigest = previousID, previousSchema, previousDigest
		if identity == nil {
			nextCurrentSchema, nextCurrentDigest = currentSchema, currentDigest
		} else {
			nextCurrentSchema, nextCurrentDigest = statusIdentityParts(identity)
		}
	} else if deployment.action == "apply" {
		nextCurrentSchema, nextCurrentDigest = statusIdentityParts(identity)
	} else if previousID != nil && *previousID == envelope.ConfigID {
		if previousSchema != nil {
			nextCurrentSchema, nextCurrentDigest = previousSchema, previousDigest
			if identity != nil && (*previousSchema != identity.Schema || !bytes.Equal(previousDigest, identity.Digest)) {
				return ErrBindingConflict
			}
		} else {
			nextCurrentSchema, nextCurrentDigest = statusIdentityParts(identity)
		}
	} else if identity != nil {
		return ErrBindingConflict
	}
	command, err := tx.Exec(ctx, `
			UPDATE node_config_state
			SET previous_config_version_id = $4,
			    current_config_version_id = $2,
			    current_config_identity_schema = $5,
			    current_config_artifact_sha256 = $6,
			    previous_config_identity_schema = $7,
			    previous_config_artifact_sha256 = $8,
			    revision = revision + 1, updated_at = $3
			WHERE node_id = $1 AND configuration_scope_id = $9`, envelope.NodeID, envelope.ConfigID, now,
		nextPreviousID, nextCurrentSchema, nextCurrentDigest, nextPreviousSchema, nextPreviousDigest, deployment.scopeID)
	if err != nil {
		return fmt.Errorf("update node running config: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrProjectionConflict
	}
	// Delivered on commit: waiters on this scope's nodes (market leaf
	// security activation) wake instead of waiting for their next tick.
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, NodeConfigCurrentChannel, deployment.scopeID.String()); err != nil {
		return fmt.Errorf("notify node running config: %w", err)
	}
	return nil
}

// NodeArtifactDeliveryChannel is the PostgreSQL notification channel a
// status projection signals, with the node ID as payload, when a node
// artifact delivery (segment or set) to that node ends.
const NodeArtifactDeliveryChannel = "cdnca_node_artifact_delivery"

func nodeArtifactDeliveryEnded(state string) bool {
	return state == "healthy" || state == "failed" || state == "reverted" || state == "rollback_failed"
}

// NodeConfigCurrentChannel is the PostgreSQL notification channel a status
// projection signals, with the configuration scope ID as payload, whenever a
// node's running configuration of that scope changes.
const NodeConfigCurrentChannel = "cdnca_node_config_current"

func requireStatusIdentityBinding(ctx context.Context, tx pgx.Tx, deployment lockedDeployment,
	envelope Envelope, identity *normalizedStatusActiveIdentity,
) error {
	query := `SELECT artifact.wire_bytes,artifact.sha256
		FROM node_deployment_artifacts binding
		JOIN configuration_artifacts artifact ON artifact.config_version_id=binding.config_version_id
			 AND artifact.id=binding.artifact_id
		JOIN config_versions version ON version.id=artifact.config_version_id
		WHERE binding.deployment_id=$1 AND binding.deployment_attempt=$2
			 AND binding.config_version_id=$3 AND version.configuration_scope_id=$4
			 AND artifact.kind='configuration' AND artifact.sha256=$5`
	args := []any{envelope.DeploymentID, envelope.Status.Attempt, identity.ConfigID, deployment.scopeID, identity.Digest}
	if deployment.action == "rollback" {
		query = `SELECT artifact.wire_bytes,artifact.sha256
			FROM configuration_artifacts artifact
			JOIN config_versions version ON version.id=artifact.config_version_id
			WHERE artifact.config_version_id=$1 AND version.configuration_scope_id=$2
				AND artifact.kind='configuration' AND artifact.sha256=$3`
		args = []any{identity.ConfigID, deployment.scopeID, identity.Digest}
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("validate deployment active identity: %w", err)
	}
	defer rows.Close()
	matched := false
	for rows.Next() {
		var wire, persisted []byte
		if err := rows.Scan(&wire, &persisted); err != nil {
			return fmt.Errorf("scan deployment active identity: %w", err)
		}
		digest := sha256.Sum256(wire)
		matched = matched || bytes.Equal(persisted, identity.Digest) && bytes.Equal(digest[:], identity.Digest)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate deployment active identity: %w", err)
	}
	if !matched {
		return ErrBindingConflict
	}
	return nil
}

func statusIdentityAPIVersion(status *agentv1.DeploymentStatus) *int32 {
	if status.ActiveConfigIdentityCapability == nil {
		return nil
	}
	value := int32(status.ActiveConfigIdentityCapability.ApiVersion)
	return &value
}

func statusIdentitySchema(status *agentv1.DeploymentStatus) *int32 {
	if status.ActiveConfigIdentity == nil {
		return nil
	}
	value := int32(status.ActiveConfigIdentity.Schema)
	return &value
}

func statusIdentityConfigID(status *agentv1.DeploymentStatus) *uuid.UUID {
	if status.ActiveConfigIdentity == nil {
		return nil
	}
	value, err := uuid.Parse(status.ActiveConfigIdentity.ConfigVersionId)
	if err != nil {
		return nil
	}
	return &value
}

func statusIdentityDigest(status *agentv1.DeploymentStatus) []byte {
	if status.ActiveConfigIdentity == nil {
		return nil
	}
	return status.ActiveConfigIdentity.ArtifactSha256
}

func statusIdentityParts(identity *normalizedStatusActiveIdentity) (*int32, []byte) {
	if identity == nil {
		return nil, nil
	}
	value := identity.Schema
	return &value, identity.Digest
}

func sameOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
