package edgedeployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Store struct {
	pool       *pgxpool.Pool
	now        func() time.Time
	auditor    auditAppender
	authorizer *iamlock.Authorizer
}

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	return NewStoreWithClock(pool, time.Now)
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time) (*Store, error) {
	return NewStoreWithClockAndAuditor(pool, now, nil)
}

func NewStoreWithClockAndAuditor(pool *pgxpool.Pool, now func() time.Time, auditor auditAppender) (*Store, error) {
	return newStoreWithClockAndAuditor(pool, now, auditor, nil)
}

func NewIAMStore(pool *pgxpool.Pool, authorizer *iamlock.Authorizer) (*Store, error) {
	return NewIAMStoreWithClock(pool, time.Now, authorizer)
}

func NewIAMStoreWithClock(
	pool *pgxpool.Pool,
	now func() time.Time,
	authorizer *iamlock.Authorizer,
) (*Store, error) {
	if err := validateIAMStoreDependencies(pool, authorizer); err != nil {
		return nil, err
	}
	return newStoreWithClockAndAuditor(pool, now, audit.New(pool), authorizer)
}

func NewIAMStoreWithClockAndAuditor(
	pool *pgxpool.Pool,
	now func() time.Time,
	auditor auditAppender,
	authorizer *iamlock.Authorizer,
) (*Store, error) {
	if auditor == nil || nilInterface(auditor) {
		return nil, fmt.Errorf("%w: edge deployment IAM store requires a usable auditor", ErrInvalidInput)
	}
	if err := validateIAMStoreDependencies(pool, authorizer); err != nil {
		return nil, err
	}
	return newStoreWithClockAndAuditor(pool, now, auditor, authorizer)
}

func validateIAMStoreDependencies(pool *pgxpool.Pool, authorizer *iamlock.Authorizer) error {
	if !configuredPool(pool) {
		return fmt.Errorf("%w: edge deployment IAM store requires a configured pool", ErrInvalidInput)
	}
	if authorizer == nil || !authorizer.Configured() {
		return fmt.Errorf("%w: edge deployment IAM store requires a configured authorizer", ErrInvalidInput)
	}
	return nil
}

func newStoreWithClockAndAuditor(
	pool *pgxpool.Pool,
	now func() time.Time,
	auditor auditAppender,
	authorizer *iamlock.Authorizer,
) (*Store, error) {
	if pool == nil || now == nil {
		return nil, fmt.Errorf("%w: edge deployment store requires a pool and clock", ErrInvalidInput)
	}
	if auditor != nil && nilInterface(auditor) {
		return nil, fmt.Errorf("%w: edge deployment store requires a usable auditor", ErrInvalidInput)
	}
	if auditor == nil {
		auditor = audit.New(pool)
	}
	return &Store{pool: pool, now: now, auditor: auditor, authorizer: authorizer}, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return reflected.IsNil()
	default:
		return false
	}
}

func configuredPool(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return pool.Config() != nil
}

func (s *Store) PersistReleasableConfig(ctx context.Context, request PersistConfigRequest) (PersistConfigResult, error) {
	configID := uuid.New()
	var result PersistConfigResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = s.PersistReleasableConfigTx(ctx, tx, configID, request)
		return err
	})
	if err != nil {
		return PersistConfigResult{}, err
	}
	return result, nil
}

func (s *Store) PersistReleasableConfigTx(ctx context.Context, tx pgx.Tx, configID uuid.UUID, request PersistConfigRequest) (PersistConfigResult, error) {
	if tx == nil || configID == uuid.Nil {
		return PersistConfigResult{}, ErrInvalidInput
	}
	normalized, err := normalizeConfigRequest(request)
	if err != nil {
		return PersistConfigResult{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	snapshotDigest := sha256.Sum256(normalized.CanonicalSnapshot)
	result := PersistConfigResult{}
	err = func() error {
		command, err := tx.Exec(ctx, `
			INSERT INTO config_versions (
				id, configuration_scope_id, canonical_snapshot, canonical_snapshot_sha256,
				generator_name, generator_version, status, idempotency_key, request_digest, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, 'building', $7, $8, $9)
			ON CONFLICT (configuration_scope_id, idempotency_key) DO NOTHING`,
			configID, normalized.ConfigurationScopeID, normalized.CanonicalSnapshot, snapshotDigest[:],
			normalized.GeneratorName, normalized.GeneratorVersion, normalized.IdempotencyKey, normalized.Digest[:], now)
		if err != nil {
			return translateConfigWriteError(err)
		}
		if command.RowsAffected() == 0 {
			existing, err := loadConfigByIdempotencyKey(ctx, tx, normalized.ConfigurationScopeID, normalized.IdempotencyKey, normalized.Digest)
			if err != nil {
				return err
			}
			if err := validateSiteRuntimeV2ConfigBinding(
				normalized.ConfigurationScopeID, existing.ID, normalized.CanonicalSnapshot, normalized.Artifacts, nil, false,
			); err != nil {
				return err
			}
			result = PersistConfigResult{ConfigVersion: existing, Replayed: true}
			return nil
		}
		if err := validateSiteRuntimeV2ConfigBinding(
			normalized.ConfigurationScopeID, configID, normalized.CanonicalSnapshot, normalized.Artifacts, nil, false,
		); err != nil {
			return err
		}

		for index, artifact := range normalized.Artifacts {
			if err := persistSigningKey(ctx, tx, artifact, now); err != nil {
				return err
			}
			kind, compression, encryption, err := artifactStorageValues(artifact)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO configuration_artifacts (
					id, config_version_id, ordinal, kind, wire_bytes, size_bytes, sha256, signature,
					signing_key_id, signature_algorithm, compression, media_type,
					encryption_algorithm, recipient_key_id, created_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ed25519', $10, $11, $12, $13, $14)`,
				artifact.ID, configID, index+1, kind, artifact.WireBytes, int64(artifact.SizeBytes), artifact.SHA256,
				artifact.Signature, artifact.SigningKeyID, compression, artifact.MediaType, encryption,
				artifact.RecipientKeyID, now); err != nil {
				return fmt.Errorf("persist configuration artifact: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE config_versions SET status = 'validating' WHERE id = $1`, configID); err != nil {
			return fmt.Errorf("advance config validation: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE config_versions SET status = 'releasable', published_at = $2 WHERE id = $1`, configID, now); err != nil {
			return fmt.Errorf("publish config version: %w", err)
		}
		result.ConfigVersion = ConfigVersion{
			ID: configID, ConfigurationScopeID: normalized.ConfigurationScopeID,
			CanonicalSnapshotSHA256: snapshotDigest, GeneratorName: normalized.GeneratorName,
			GeneratorVersion: normalized.GeneratorVersion, Artifacts: descriptorsFromInputs(normalized.Artifacts),
			CreatedAt: now, PublishedAt: now,
		}
		return nil
	}()
	if err != nil {
		return PersistConfigResult{}, fmt.Errorf("persist releasable edge config: %w", err)
	}
	return result, nil
}

func (s *Store) CreateRollout(ctx context.Context, request CreateRolloutRequest) (CreateRolloutResult, error) {
	var result CreateRolloutResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = s.CreateRolloutTx(ctx, tx, request)
		return err
	})
	if err != nil {
		return CreateRolloutResult{}, err
	}
	return result, nil
}

func (s *Store) CreateRolloutTx(ctx context.Context, tx pgx.Tx, request CreateRolloutRequest) (CreateRolloutResult, error) {
	return s.createRolloutTx(ctx, tx, request, false)
}

// CreateNodeArtifactRolloutTx delivers a node-side artifact (the IP
// intelligence library): the configuration lives in the platform scope and
// never becomes a node's running configuration. The deployment does not
// claim or read node_config_state, and it is queued per scope, so it neither
// waits for nor blocks a tenant scope's deployment on the same node
// (docs/architecture/ip-intel-artifact.md §10.3).
func (s *Store) CreateNodeArtifactRolloutTx(ctx context.Context, tx pgx.Tx, request CreateRolloutRequest) (CreateRolloutResult, error) {
	if tx == nil || request.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || len(request.NodeArtifactBindings) != 0 {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, request.ConfigurationScopeID).Scan(&kind); err != nil ||
		kind != ScopeKindPlatform {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	return s.createRolloutTx(ctx, tx, request, true)
}

func (s *Store) createRolloutTx(ctx context.Context, tx pgx.Tx, request CreateRolloutRequest, nodeArtifact bool) (CreateRolloutResult, error) {
	if tx == nil {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	normalized, err := normalizeRolloutReplayRequest(request)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(
		pg_catalog.hashtextextended('edge-rollout-idempotency:v1:' || $1::text || ':' || $2,0))`,
		normalized.ConfigurationScopeID, normalized.IdempotencyKey); err != nil {
		return CreateRolloutResult{}, fmt.Errorf("lock rollout idempotency: %w", err)
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var existing bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rollouts
		WHERE configuration_scope_id=$1 AND idempotency_key=$2)`,
		normalized.ConfigurationScopeID, normalized.IdempotencyKey).Scan(&existing); err != nil {
		return CreateRolloutResult{}, fmt.Errorf("read rollout idempotency: %w", err)
	}
	if existing {
		rollout, err := loadRolloutByIdempotencyKey(
			ctx, tx, normalized.ConfigurationScopeID, normalized.IdempotencyKey, normalized.Digest,
		)
		if err != nil {
			return CreateRolloutResult{}, err
		}
		return CreateRolloutResult{Rollout: rollout, Replayed: true}, nil
	}
	if !normalized.Deadline.After(now) {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	result := CreateRolloutResult{}
	err = func() error {
		artifacts, err := requireReleasableConfig(
			ctx, tx, normalized.ConfigurationScopeID, normalized.ConfigVersionID, normalized.RequiredCapabilities,
		)
		if err != nil {
			return err
		}
		hasEncryptedConfiguration := false
		for _, artifact := range artifacts {
			if artifact != nil && artifact.Kind == agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION &&
				artifact.EncryptionAlgorithm == agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
				hasEncryptedConfiguration = true
			}
		}
		if normalized.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY &&
			hasEncryptedConfiguration != (len(normalized.NodeArtifactBindings) != 0) {
			return ErrInvalidInput
		}
		rolloutID := uuid.New()
		strategy, canarySize, batchSize, failureThreshold, releasedCohort := "all_at_once", 0, 0, 0, 0
		finalStatus := "queued"
		var startedAt *time.Time
		if normalized.ContractVersion == 2 {
			strategy = normalized.Rollout.Strategy
			canarySize, batchSize = int(normalized.Rollout.CanarySize), int(normalized.Rollout.BatchSize)
			failureThreshold, releasedCohort = int(normalized.Rollout.FailureThreshold), -1
			if normalized.Rollout.AutoStart {
				finalStatus, releasedCohort, startedAt = "running", 0, &now
			}
		}
		command, err := tx.Exec(ctx, `
			INSERT INTO rollouts (
				id, configuration_scope_id, config_version_id, action, status,
				idempotency_key, request_digest, request_id, correlation_id, traceparent, task_id,
				activation_timeout_ms, observation_window_ms, required_consecutive_successes,
				deadline_at, created_at, revision, max_attempts, updated_at, contract_version,
				strategy,canary_size,batch_size,failure_threshold,released_cohort,started_at
			) VALUES ($1, $2, $3, $4, 'building', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 1, $16, $15, $17,
			          $18,$19,$20,$21,$22,$23)
			ON CONFLICT (configuration_scope_id, idempotency_key) DO NOTHING`,
			rolloutID, normalized.ConfigurationScopeID, normalized.ConfigVersionID, actionStorageValue(normalized.Action),
			normalized.IdempotencyKey, normalized.Digest[:], normalized.RequestUUID, normalized.CorrelationUUID,
			normalized.Traceparent, normalized.TaskID, normalized.HealthCheck.ActivationTimeout.Milliseconds(),
			normalized.HealthCheck.ObservationWindow.Milliseconds(), int64(normalized.HealthCheck.RequiredConsecutiveSuccesses),
			normalized.Deadline.UTC(), now, normalized.MaxAttempts, normalized.ContractVersion,
			strategy, canarySize, batchSize, failureThreshold, releasedCohort, startedAt)
		if err != nil {
			return fmt.Errorf("claim rollout: %w", err)
		}
		if command.RowsAffected() == 0 {
			existing, err := loadRolloutByIdempotencyKey(ctx, tx, normalized.ConfigurationScopeID, normalized.IdempotencyKey, normalized.Digest)
			if err != nil {
				return err
			}
			result = CreateRolloutResult{Rollout: existing, Replayed: true}
			return nil
		}

		result.Rollout = Rollout{
			ID: rolloutID, ConfigurationScopeID: normalized.ConfigurationScopeID,
			ConfigVersionID: normalized.ConfigVersionID, Action: normalized.Action, CreatedAt: now,
			Revision: 1, MaxAttempts: normalized.MaxAttempts, Policy: normalized.Rollout,
		}
		// Per-node encrypted artifacts: each node's command names its own
		// artifact (and a v8 release's shared root), found by ID once here.
		var byID map[string]*agentv1.ArtifactDescriptor
		var siteObjectRoot *agentv1.ArtifactDescriptor
		if len(normalized.NodeArtifactBindings) != 0 {
			byID = make(map[string]*agentv1.ArtifactDescriptor, len(artifacts))
			for _, artifact := range artifacts {
				if artifact != nil {
					byID[artifact.ArtifactId] = artifact
					if isSiteObjectRootMediaType(artifact.MediaType) {
						siteObjectRoot = artifact
					}
				}
			}
		}
		for index, nodeID := range normalized.NodeIDs {
			var binding *NodeArtifactBinding
			nodeArtifacts := artifacts
			if len(normalized.NodeArtifactBindings) != 0 {
				binding = &normalized.NodeArtifactBindings[index]
				nodeArtifacts = nil
				if siteObjectRoot != nil {
					nodeArtifacts = append(nodeArtifacts, siteObjectRoot)
				}
				if own := byID[binding.ArtifactID.String()]; own != nil {
					nodeArtifacts = append(nodeArtifacts, own)
				}
			}
			cohort, outboxStatus := 0, "pending"
			if normalized.ContractVersion == 2 {
				cohort = cohortForIndex(index, normalized.Rollout)
				if cohort > releasedCohort {
					outboxStatus = "held"
				}
			}
			create := s.createNodeDeployment
			if nodeArtifact {
				create = s.createNodeArtifactDeployment
			}
			deployment, err := create(ctx, tx, normalized, rolloutID, nodeID, binding, nodeArtifacts, cohort, outboxStatus, now)
			if err != nil {
				return err
			}
			result.Rollout.Deployments = append(result.Rollout.Deployments, deployment)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE rollouts SET status=$3,queued_at=$2,updated_at=$2 WHERE id=$1 AND status='building'`,
			rolloutID, now, finalStatus); err != nil {
			return fmt.Errorf("queue rollout: %w", err)
		}
		result.Rollout.QueuedAt = now
		return nil
	}()
	if err != nil {
		return CreateRolloutResult{}, fmt.Errorf("create edge rollout: %w", err)
	}
	return result, nil
}

func (s *Store) createNodeDeployment(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedRolloutRequest,
	rolloutID uuid.UUID,
	nodeID uuid.UUID,
	nodeArtifactBinding *NodeArtifactBinding,
	artifacts []*agentv1.ArtifactDescriptor,
	cohort int,
	outboxStatus string,
	now time.Time,
) (Deployment, error) {
	var nodeScopeID uuid.UUID
	var nodeScopeKind string
	if err := tx.QueryRow(ctx, `
		SELECT node.scope_id,scope.kind
		FROM nodes node
		JOIN access_scopes scope ON scope.id=node.scope_id
		WHERE node.id=$1
		FOR UPDATE OF node`, nodeID).Scan(&nodeScopeID, &nodeScopeKind); errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrNodeNotFound
	} else if err != nil {
		return Deployment{}, fmt.Errorf("read rollout node: %w", err)
	}
	if nodeScopeKind != ScopeKindPlatform && nodeScopeID != request.ConfigurationScopeID {
		return Deployment{}, ErrConfigurationScopeConflict
	}
	// The node row lock above serializes claims, so a scope seen unclaimed
	// here is still unclaimed when its (node, scope) row is inserted.
	var currentVersionID, previousVersionID *uuid.UUID
	var reconciliationRequired bool
	err := tx.QueryRow(ctx, `
		SELECT current_config_version_id, previous_config_version_id, reconciliation_required
		FROM node_config_state WHERE node_id = $1 AND configuration_scope_id = $2 FOR UPDATE`,
		nodeID, request.ConfigurationScopeID).Scan(&currentVersionID, &previousVersionID, &reconciliationRequired)
	claimed := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, fmt.Errorf("lock node config state: %w", err)
	}
	if reconciliationRequired {
		return Deployment{}, ErrNodeReconciliationRequired
	}
	queuesPerScope, err := NodeServesSeveralScopes(ctx, tx, nodeID)
	if err != nil {
		return Deployment{}, err
	}
	if !claimed {
		var otherScopes bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM node_config_state WHERE node_id = $1)`, nodeID).
			Scan(&otherScopes); err != nil {
			return Deployment{}, fmt.Errorf("read node configuration scopes: %w", err)
		}
		if otherScopes && !queuesPerScope {
			return Deployment{}, ErrConfigurationScopeConflict
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_config_state (node_id, configuration_scope_id, updated_at)
			VALUES ($1, $2, $3)`, nodeID, request.ConfigurationScopeID, now); err != nil {
			return Deployment{}, fmt.Errorf("claim node configuration scope: %w", err)
		}
	}
	return s.insertNodeDeployment(ctx, tx, request, rolloutID, nodeID, nodeArtifactBinding, artifacts, cohort, outboxStatus,
		now, currentVersionID, previousVersionID, queuesPerScope)
}

// createNodeArtifactDeployment is createNodeDeployment for a platform-scope
// (node-side artifact) rollout: no node_config_state, no previous version,
// queued per scope.
func (s *Store) createNodeArtifactDeployment(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedRolloutRequest,
	rolloutID uuid.UUID,
	nodeID uuid.UUID,
	nodeArtifactBinding *NodeArtifactBinding,
	artifacts []*agentv1.ArtifactDescriptor,
	cohort int,
	outboxStatus string,
	now time.Time,
) (Deployment, error) {
	if nodeArtifactBinding != nil {
		return Deployment{}, ErrInvalidInput
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM nodes WHERE id=$1 FOR UPDATE`, nodeID).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrNodeNotFound
	} else if err != nil {
		return Deployment{}, fmt.Errorf("read rollout node: %w", err)
	}
	return s.insertNodeDeployment(ctx, tx, request, rolloutID, nodeID, nil, artifacts, cohort, outboxStatus, now, nil, nil, true)
}

func (s *Store) insertNodeDeployment(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedRolloutRequest,
	rolloutID uuid.UUID,
	nodeID uuid.UUID,
	nodeArtifactBinding *NodeArtifactBinding,
	artifacts []*agentv1.ArtifactDescriptor,
	cohort int,
	outboxStatus string,
	now time.Time,
	currentVersionID, previousVersionID *uuid.UUID,
	queuesPerScope bool,
) (Deployment, error) {
	deploymentID, eventID := uuid.New(), uuid.New()
	var commandPrevious *uuid.UUID
	commandArtifacts := artifacts
	if nodeArtifactBinding != nil {
		if nodeArtifactBinding.NodeID != nodeID || nodeArtifactBinding.ConfigVersionID != request.ConfigVersionID ||
			nodeArtifactBinding.Attempt != 1 {
			return Deployment{}, ErrInvalidInput
		}
		deploymentID, eventID = nodeArtifactBinding.DeploymentID, nodeArtifactBinding.EventID
		commandArtifacts = nil
		var root *agentv1.ArtifactDescriptor
		for _, artifact := range artifacts {
			if artifact != nil && artifact.ArtifactId == nodeArtifactBinding.ArtifactID.String() {
				commandArtifacts = []*agentv1.ArtifactDescriptor{artifact}
			}
			if artifact != nil && isSiteObjectRootMediaType(artifact.MediaType) {
				root = artifact
			}
		}
		if len(commandArtifacts) != 1 || commandArtifacts[0].Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION ||
			commandArtifacts[0].EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
			commandArtifacts[0].GetRecipientKeyId() != nodeArtifactBinding.RecipientKeyID {
			return Deployment{}, ErrInvalidInput
		}
		// A site runtime v8 node runs the shared signed root with its own key
		// envelope; the agent requires [root, envelope].
		if commandArtifacts[0].MediaType == siteObjectKeyMediaType {
			if root == nil || root.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE {
				return Deployment{}, ErrInvalidInput
			}
			commandArtifacts = []*agentv1.ArtifactDescriptor{root, commandArtifacts[0]}
		}
	}
	switch request.Action {
	case agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY:
		commandPrevious = currentVersionID
	case agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK:
		if currentVersionID == nil || previousVersionID == nil || *previousVersionID != request.ConfigVersionID {
			return Deployment{}, ErrRollbackStateConflict
		}
		commandPrevious = currentVersionID
		commandArtifacts = nil
	}

	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: eventID.String(), RequestId: request.RequestUUID.String(), OccurredTime: timestamppb.New(now),
			Traceparent: request.Traceparent, CorrelationId: request.CorrelationUUID.String(), TaskId: cloneString(request.TaskID),
		},
		DeploymentId: deploymentID.String(), Attempt: 1, RolloutId: rolloutID.String(),
		ConfigVersionId: request.ConfigVersionID.String(), PreviousConfigVersionId: uuidString(commandPrevious),
		Action: request.Action, Artifacts: cloneDescriptors(commandArtifacts),
		RequiredCapabilities: cloneCapabilities(request.RequiredCapabilities),
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration:    durationpb.New(request.HealthCheck.ActivationTimeout),
			ObservationWindowDuration:    durationpb.New(request.HealthCheck.ObservationWindow),
			RequiredConsecutiveSuccesses: request.HealthCheck.RequiredConsecutiveSuccesses,
		},
		DeadlineTime: timestamppb.New(request.Deadline.UTC()),
		// MULTI_TENANT_RUNTIME agents keep state per scope and require it on
		// every configuration command, rollbacks included; others ignore it.
		ConfigurationScopeId: proto.String(request.ConfigurationScopeID.String()),
	}
	encoded, err := marshalDeploymentCommand(command)
	if err != nil {
		return Deployment{}, err
	}
	digest := sha256.Sum256(encoded)
	_, err = tx.Exec(ctx, `
		INSERT INTO node_deployments (
			id, rollout_id, node_id, attempt, config_version_id, previous_config_version_id,
			action, state, command_event_id, command_bytes, command_sha256, deadline_at, created_at, updated_at,cohort,
			queued_per_scope
		) VALUES ($1, $2, $3, 1, $4, $5, $6, 'queued', $7, $8, $9, $10, $11, $11,$12,$13)`,
		deploymentID, rolloutID, nodeID, request.ConfigVersionID, commandPrevious,
		actionStorageValue(request.Action), eventID, encoded, digest[:], request.Deadline.UTC(), now, cohort,
		queuesPerScope)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && activeDeploymentConstraint(pgErr.ConstraintName) {
			return Deployment{}, ErrNodeDeploymentActive
		}
		if errors.As(err, &pgErr) && pgErr.ConstraintName == "node_deployments_reconciliation_gate" {
			return Deployment{}, ErrNodeReconciliationRequired
		}
		return Deployment{}, fmt.Errorf("persist node deployment: %w", err)
	}
	for index, artifact := range commandArtifacts {
		artifactID, err := uuid.Parse(artifact.ArtifactId)
		if err != nil {
			return Deployment{}, fmt.Errorf("persist node artifact binding: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_deployment_artifacts (deployment_id, deployment_attempt, config_version_id, artifact_id, ordinal)
			VALUES ($1, 1, $2, $3, $4)`, deploymentID, request.ConfigVersionID, artifactID, index+1); err != nil {
			return Deployment{}, fmt.Errorf("persist node artifact binding: %w", err)
		}
	}
	if err := cancelReplacedCommands(ctx, tx, nodeID, request.ConfigurationScopeID, deploymentID, now); err != nil {
		return Deployment{}, err
	}
	subject := "cdnca.agent.commands." + nodeID.String()
	if _, err := tx.Exec(ctx, `
		INSERT INTO edge_command_outbox (
			id, deployment_id, deployment_attempt, node_id, subject, payload, payload_sha256,
			status, available_at, created_at, updated_at
		) VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $8, $8)`,
		uuid.New(), deploymentID, nodeID, subject, encoded, digest[:], outboxStatus, now); err != nil {
		return Deployment{}, fmt.Errorf("persist edge command outbox: %w", err)
	}
	return Deployment{ID: deploymentID, NodeID: nodeID, Subject: subject, CommandBytes: bytes.Clone(encoded), Command: command}, nil
}

func persistSigningKey(ctx context.Context, tx pgx.Tx, artifact ArtifactInput, now time.Time) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO artifact_signing_keys (id, algorithm, public_key, created_at)
		VALUES ($1, 'ed25519', $2, $3)
		ON CONFLICT (id) DO NOTHING`, artifact.SigningKeyID, artifact.SigningPublicKey, now); err != nil {
		return fmt.Errorf("persist artifact signing key: %w", err)
	}
	var algorithm string
	var persisted []byte
	if err := tx.QueryRow(ctx, `
		SELECT algorithm, public_key FROM artifact_signing_keys WHERE id = $1`, artifact.SigningKeyID).Scan(&algorithm, &persisted); err != nil {
		return fmt.Errorf("read artifact signing key: %w", err)
	}
	if algorithm != "ed25519" || !bytes.Equal(persisted, artifact.SigningPublicKey) {
		return ErrSigningKeyConflict
	}
	return nil
}

func requireReleasableConfig(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configID uuid.UUID,
	requiredCapabilities []*agentv1.Capability,
) ([]*agentv1.ArtifactDescriptor, error) {
	var status string
	var canonicalSnapshot []byte
	err := tx.QueryRow(ctx, `
		SELECT status,canonical_snapshot FROM config_versions
		WHERE configuration_scope_id = $1 AND id = $2`, scopeID, configID).Scan(&status, &canonicalSnapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConfigNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read rollout config version: %w", err)
	}
	if status != "releasable" {
		return nil, ErrConfigNotReleasable
	}
	artifacts, err := loadStoredArtifacts(ctx, tx, configID)
	if err != nil {
		return nil, err
	}
	if len(artifacts) == 0 {
		return nil, ErrConfigNotReleasable
	}
	if err := validateSiteRuntimeV2ConfigBinding(
		scopeID, configID, canonicalSnapshot, artifacts, requiredCapabilities, true,
	); err != nil {
		return nil, ErrConfigNotReleasable
	}
	return descriptorsFromInputs(artifacts), nil
}

func loadStoredArtifacts(ctx context.Context, tx pgx.Tx, configID uuid.UUID) ([]ArtifactInput, error) {
	rows, err := tx.Query(ctx, `
		SELECT artifact.id,artifact.kind,artifact.wire_bytes,artifact.size_bytes,artifact.sha256,
		       artifact.signature,artifact.signing_key_id,key.public_key,artifact.signature_algorithm,
		       artifact.compression,artifact.media_type,artifact.encryption_algorithm,artifact.recipient_key_id
		FROM configuration_artifacts artifact
		JOIN artifact_signing_keys key ON key.id=artifact.signing_key_id AND key.algorithm=artifact.signature_algorithm
		WHERE artifact.config_version_id=$1 ORDER BY artifact.ordinal`, configID)
	if err != nil {
		return nil, fmt.Errorf("read stored configuration artifacts: %w", err)
	}
	defer rows.Close()
	var result []ArtifactInput
	for rows.Next() {
		var input ArtifactInput
		var kind, signatureAlgorithm, compression, encryption string
		var size int64
		var signingPublicKey []byte
		if err := rows.Scan(
			&input.ID, &kind, &input.WireBytes, &size, &input.SHA256, &input.Signature,
			&input.SigningKeyID, &signingPublicKey, &signatureAlgorithm, &compression,
			&input.MediaType, &encryption, &input.RecipientKeyID,
		); err != nil {
			return nil, fmt.Errorf("scan stored configuration artifact: %w", err)
		}
		descriptor, err := descriptorFromStorage(
			input.ID, kind, size, input.SHA256, input.Signature, input.SigningKeyID,
			signatureAlgorithm, compression, input.MediaType, encryption, input.RecipientKeyID,
		)
		if err != nil {
			return nil, err
		}
		input.Kind = descriptor.Kind
		input.SigningPublicKey = ed25519.PublicKey(signingPublicKey)
		input.SizeBytes = descriptor.SizeBytes
		input.SignatureAlgorithm = descriptor.SignatureAlgorithm
		input.Compression = descriptor.Compression
		input.EncryptionAlgorithm = descriptor.EncryptionAlgorithm
		validated, err := validateArtifact(input)
		if err != nil {
			return nil, fmt.Errorf("validate stored configuration artifact: %w", err)
		}
		result = append(result, validated)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stored configuration artifacts: %w", err)
	}
	return result, nil
}

func loadConfigByIdempotencyKey(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	key string,
	digest [32]byte,
) (ConfigVersion, error) {
	var item ConfigVersion
	var persistedDigest, snapshotDigest []byte
	var status string
	err := tx.QueryRow(ctx, `
		SELECT id, canonical_snapshot_sha256, generator_name, generator_version,
		       request_digest, status, created_at, published_at
		FROM config_versions
		WHERE configuration_scope_id = $1 AND idempotency_key = $2`, scopeID, key).Scan(
		&item.ID, &snapshotDigest, &item.GeneratorName, &item.GeneratorVersion,
		&persistedDigest, &status, &item.CreatedAt, &item.PublishedAt,
	)
	if err != nil {
		return ConfigVersion{}, fmt.Errorf("read idempotent config version: %w", err)
	}
	if !bytes.Equal(persistedDigest, digest[:]) || status != "releasable" || len(snapshotDigest) != sha256.Size {
		return ConfigVersion{}, ErrIdempotencyConflict
	}
	item.ConfigurationScopeID = scopeID
	copy(item.CanonicalSnapshotSHA256[:], snapshotDigest)
	item.Artifacts, err = loadArtifactDescriptors(ctx, tx, item.ID)
	if err != nil {
		return ConfigVersion{}, err
	}
	return item, nil
}

func loadRolloutByIdempotencyKey(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	key string,
	digest [32]byte,
) (Rollout, error) {
	var item Rollout
	var persistedDigest []byte
	var action string
	var contractVersion int16
	var strategy string
	var canarySize, batchSize, failureThreshold uint32
	var startedAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT id,config_version_id,action,request_digest,created_at,queued_at,
		       revision,max_attempts,contract_version,strategy,canary_size,batch_size,failure_threshold,started_at
		FROM rollouts WHERE configuration_scope_id = $1 AND idempotency_key = $2`, scopeID, key).Scan(
		&item.ID, &item.ConfigVersionID, &action, &persistedDigest, &item.CreatedAt, &item.QueuedAt,
		&item.Revision, &item.MaxAttempts, &contractVersion, &strategy, &canarySize, &batchSize, &failureThreshold, &startedAt,
	)
	if err != nil {
		return Rollout{}, fmt.Errorf("read idempotent rollout: %w", err)
	}
	if !bytes.Equal(persistedDigest, digest[:]) {
		return Rollout{}, ErrIdempotencyConflict
	}
	item.ConfigurationScopeID = scopeID
	if contractVersion == 2 {
		item.Policy = RolloutPolicy{Strategy: strategy, CanarySize: canarySize, BatchSize: batchSize,
			FailureThreshold: failureThreshold, AutoStart: startedAt != nil}
	}
	item.Action, err = parseAction(action)
	if err != nil {
		return Rollout{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT deployment.id, deployment.node_id, outbox.subject, deployment.command_bytes
		FROM node_deployments deployment
		JOIN edge_command_outbox outbox
		  ON outbox.deployment_id = deployment.id AND outbox.deployment_attempt = deployment.attempt
		WHERE deployment.rollout_id = $1
		ORDER BY deployment.node_id`, item.ID)
	if err != nil {
		return Rollout{}, fmt.Errorf("read idempotent rollout deployments: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var deployment Deployment
		if err := rows.Scan(&deployment.ID, &deployment.NodeID, &deployment.Subject, &deployment.CommandBytes); err != nil {
			return Rollout{}, fmt.Errorf("scan idempotent rollout deployment: %w", err)
		}
		deployment.Command = new(agentv1.DeploymentCommand)
		if err := proto.Unmarshal(deployment.CommandBytes, deployment.Command); err != nil {
			return Rollout{}, fmt.Errorf("decode idempotent rollout command: %w", err)
		}
		item.Deployments = append(item.Deployments, deployment)
	}
	if err := rows.Err(); err != nil {
		return Rollout{}, fmt.Errorf("iterate idempotent rollout deployments: %w", err)
	}
	if contractVersion == 2 {
		item.Policy.CohortCount = 1
		if remaining := len(item.Deployments) - int(item.Policy.CanarySize); remaining > 0 {
			item.Policy.CohortCount += (remaining + int(item.Policy.BatchSize) - 1) / int(item.Policy.BatchSize)
		}
	}
	return item, nil
}

func loadArtifactDescriptors(ctx context.Context, tx pgx.Tx, configID uuid.UUID) ([]*agentv1.ArtifactDescriptor, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, kind, size_bytes, sha256, signature, signing_key_id,
		       signature_algorithm, compression, media_type, encryption_algorithm, recipient_key_id
		FROM configuration_artifacts WHERE config_version_id = $1 ORDER BY ordinal`, configID)
	if err != nil {
		return nil, fmt.Errorf("read configuration artifacts: %w", err)
	}
	defer rows.Close()
	var result []*agentv1.ArtifactDescriptor
	for rows.Next() {
		var id uuid.UUID
		var kind, signatureAlgorithm, compression, encryption string
		var size int64
		var sha, signature []byte
		var signingKeyID, mediaType string
		var recipientKeyID *string
		if err := rows.Scan(&id, &kind, &size, &sha, &signature, &signingKeyID, &signatureAlgorithm,
			&compression, &mediaType, &encryption, &recipientKeyID); err != nil {
			return nil, fmt.Errorf("scan configuration artifact: %w", err)
		}
		descriptor, err := descriptorFromStorage(id, kind, size, sha, signature, signingKeyID,
			signatureAlgorithm, compression, mediaType, encryption, recipientKeyID)
		if err != nil {
			return nil, err
		}
		result = append(result, descriptor)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate configuration artifacts: %w", err)
	}
	return result, nil
}

func descriptorsFromInputs(inputs []ArtifactInput) []*agentv1.ArtifactDescriptor {
	result := make([]*agentv1.ArtifactDescriptor, len(inputs))
	for index, input := range inputs {
		result[index] = &agentv1.ArtifactDescriptor{
			ArtifactId: input.ID.String(), Kind: input.Kind, SizeBytes: input.SizeBytes,
			Sha256: bytes.Clone(input.SHA256), Signature: bytes.Clone(input.Signature), SigningKeyId: input.SigningKeyID,
			SignatureAlgorithm: input.SignatureAlgorithm, Compression: input.Compression, MediaType: input.MediaType,
			EncryptionAlgorithm: input.EncryptionAlgorithm, RecipientKeyId: cloneString(input.RecipientKeyID),
		}
	}
	return result
}

func artifactStorageValues(input ArtifactInput) (string, string, string, error) {
	var kind string
	switch input.Kind {
	case agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION:
		kind = "configuration"
	case agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE:
		kind = "node_secret_bundle"
	default:
		return "", "", "", ErrInvalidInput
	}
	var compression string
	switch input.Compression {
	case agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE:
		compression = "none"
	case agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD:
		compression = "zstd"
	default:
		return "", "", "", ErrInvalidInput
	}
	var encryption string
	switch input.EncryptionAlgorithm {
	case agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE:
		encryption = "none"
	case agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM:
		encryption = "hpke_x25519_hkdf_sha256_aes_256_gcm"
	default:
		return "", "", "", ErrInvalidInput
	}
	return kind, compression, encryption, nil
}

func descriptorFromStorage(
	id uuid.UUID,
	kind string,
	size int64,
	sha, signature []byte,
	signingKeyID, signatureAlgorithm, compression, mediaType, encryption string,
	recipientKeyID *string,
) (*agentv1.ArtifactDescriptor, error) {
	descriptor := &agentv1.ArtifactDescriptor{
		ArtifactId: id.String(), SizeBytes: uint64(size), Sha256: sha, Signature: signature,
		SigningKeyId: signingKeyID, MediaType: mediaType, RecipientKeyId: recipientKeyID,
	}
	switch kind {
	case "configuration":
		descriptor.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
	case "node_secret_bundle":
		descriptor.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
	default:
		return nil, fmt.Errorf("unknown stored artifact kind %q", kind)
	}
	if signatureAlgorithm != "ed25519" {
		return nil, fmt.Errorf("unknown stored artifact signature algorithm %q", signatureAlgorithm)
	}
	descriptor.SignatureAlgorithm = agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519
	switch compression {
	case "none":
		descriptor.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE
	case "zstd":
		descriptor.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD
	default:
		return nil, fmt.Errorf("unknown stored artifact compression %q", compression)
	}
	switch encryption {
	case "none":
		descriptor.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE
	case "hpke_x25519_hkdf_sha256_aes_256_gcm":
		descriptor.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
	default:
		return nil, fmt.Errorf("unknown stored artifact encryption %q", encryption)
	}
	return descriptor, nil
}

func actionStorageValue(action agentv1.DeploymentAction) string {
	if action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK {
		return "rollback"
	}
	return "apply"
}

func parseAction(value string) (agentv1.DeploymentAction, error) {
	switch value {
	case "apply":
		return agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, nil
	case "rollback":
		return agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK, nil
	default:
		return agentv1.DeploymentAction_DEPLOYMENT_ACTION_UNSPECIFIED, fmt.Errorf("unknown stored rollout action %q", value)
	}
}

func cloneDescriptors(values []*agentv1.ArtifactDescriptor) []*agentv1.ArtifactDescriptor {
	result := make([]*agentv1.ArtifactDescriptor, len(values))
	for index, value := range values {
		result[index] = proto.Clone(value).(*agentv1.ArtifactDescriptor)
	}
	return result
}

func marshalDeploymentCommand(command *agentv1.DeploymentCommand) ([]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return nil, fmt.Errorf("marshal deterministic deployment command: %w", err)
	}
	if len(encoded) > maxDeploymentCommandBytes {
		return nil, fmt.Errorf("%w: deployment command exceeds 1 MiB", ErrInvalidInput)
	}
	return encoded, nil
}

func cloneCapabilities(values []*agentv1.Capability) []*agentv1.Capability {
	result := make([]*agentv1.Capability, len(values))
	for index, value := range values {
		result[index] = proto.Clone(value).(*agentv1.Capability)
	}
	return result
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func uuidString(value *uuid.UUID) *string {
	if value == nil {
		return nil
	}
	encoded := value.String()
	return &encoded
}

func translateConfigWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrInvalidInput
	}
	return fmt.Errorf("claim config version: %w", err)
}

// cancelReplacedCommands closes, as a newer deployment of the node and scope
// is queued, every older command of that node and scope still waiting to be
// sent or retried (fix-cfgflow2 §3). One deployment runs per node and scope
// (288/291), so these belong to deployments that already ended (timed out,
// refused, cancelled) whose command the publisher had not given up on. A
// command being published right now is closed by the publisher itself
// (edgeoutbox claim: superseded); the node's revision gate is the backstop.
func cancelReplacedCommands(ctx context.Context, tx pgx.Tx, nodeID, scopeID, deploymentID uuid.UUID, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE edge_command_outbox outbox SET status='cancelled',
			last_error='superseded:newer_deployment',updated_at=$4
		FROM node_deployments deployment
		WHERE outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		  AND deployment.node_id=$1 AND deployment.configuration_scope_id=$2 AND deployment.id<>$3
		  AND outbox.status IN ('held','pending','failed')`, nodeID, scopeID, deploymentID, now); err != nil {
		return fmt.Errorf("cancel replaced edge commands: %w", err)
	}
	return nil
}
