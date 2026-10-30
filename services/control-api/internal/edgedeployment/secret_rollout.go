package edgedeployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrNodeRecipientKeyUnavailable  = errors.New("active node artifact recipient key is unavailable")
	ErrSecretArtifactContract       = errors.New("secret artifact does not match its frozen rollout binding")
	ErrSecretRetryRequiresRepublish = errors.New("secret deployment retry requires a replacement publication")
)

const (
	secretRolloutAuditAction        = "edge_secret_rollout.create"
	secretReplacementAuditAction    = "edge_secret_rollout.replace"
	secretReplacementStoragePrefix  = "secret-replacement-"
	secretRolloutSourceDigestDomain = "cdnca.edge.secret-rollout-from-source/v1"
)

type SecretRolloutRequest struct {
	Actor                Actor
	ConfigurationScopeID uuid.UUID
	NodeIDs              []uuid.UUID
	CanonicalSnapshot    []byte
	GeneratorName        string
	GeneratorVersion     string
	PayloadDigest        [sha256.Size]byte
	RequiredCapabilities []*agentv1.Capability
	HealthCheck          HealthCheckPolicy
	Deadline             time.Time
	IdempotencyKey       string
	RequestID            string
	CorrelationID        string
	Traceparent          string
	TaskID               *string
}

type SecretArtifactBinding struct {
	EventID            uuid.UUID
	DeploymentID       uuid.UUID
	RolloutID          uuid.UUID
	Attempt            uint32
	ConfigVersionID    uuid.UUID
	ArtifactID         uuid.UUID
	NodeID             uuid.UUID
	RecipientKeyID     string
	RecipientPublicKey []byte
}

type SecretArtifactBuilder func(context.Context, SecretArtifactBinding) (ArtifactInput, error)

type SecretRolloutMaterial struct {
	CanonicalSnapshot []byte
	PayloadDigest     [sha256.Size]byte
	Builder           SecretArtifactBuilder
}

type SecretRolloutSource func(context.Context, pgx.Tx) (SecretRolloutMaterial, error)

// CertificateSecretRolloutSource is the certificate-only source contract. It
// keeps certificate publication from accepting a caller-selected generic
// rollout source while reusing the core material shape internally.
type CertificateSecretRolloutSource func(context.Context, pgx.Tx) (SecretRolloutMaterial, error)

type SecretReplacementRequest struct {
	Actor                Actor
	ConfigurationScopeID uuid.UUID
	NodeIDs              []uuid.UUID
	OriginalRolloutID    uuid.UUID
	ExpectedRevision     int64
	GeneratorName        string
	GeneratorVersion     string
	RequiredCapabilities []*agentv1.Capability
	HealthCheck          HealthCheckPolicy
	Deadline             time.Time
	IdempotencyKey       string
	RequestID            string
	CorrelationID        string
	Traceparent          string
	TaskID               *string
}

type SecretReplacementArtifactBuilder func(context.Context, []SecretArtifactBinding) ([]ArtifactInput, error)

type SecretReplacementMaterial struct {
	CanonicalSnapshot []byte
	PayloadDigest     [sha256.Size]byte
}

type SecretReplacementConsume func(SecretReplacementMaterial, SecretReplacementArtifactBuilder) error

type SecretReplacementSource func(context.Context, pgx.Tx, SecretReplacementConsume) error

type SecretReplacementResult struct {
	OriginalRolloutID uuid.UUID
	OriginalRevision  int64
	Rollout           Rollout
	Replayed          bool
}

type normalizedSecretRolloutRequest struct {
	SecretRolloutRequest
	RequestUUID          uuid.UUID
	CorrelationUUID      uuid.UUID
	RequiredCapabilities []*agentv1.Capability
	Digest               [sha256.Size]byte
}

type normalizedSecretReplacementRequest struct {
	SecretReplacementRequest
	RequestUUID          uuid.UUID
	CorrelationUUID      uuid.UUID
	NodeIDs              []uuid.UUID
	RequiredCapabilities []*agentv1.Capability
	Digest               [sha256.Size]byte
}

type secretReplacementResponse struct {
	OriginalRolloutID      uuid.UUID `json:"original_rollout_id"`
	OriginalRevision       int64     `json:"original_revision"`
	ReplacementRolloutID   uuid.UUID `json:"replacement_rollout_id"`
	ReplacementIdempotency string    `json:"replacement_idempotency_key"`
	ReplacementDigest      string    `json:"replacement_digest_sha256"`
}

type secretReplacementOrigin struct {
	CanonicalSnapshot []byte
	Deployments       []commandDeployment
}

type activeArtifactRecipient struct {
	NodeID    uuid.UUID
	ID        string
	PublicKey []byte
}

func (s *Store) CreateSecretRollout(
	ctx context.Context,
	request SecretRolloutRequest,
	builder SecretArtifactBuilder,
) (CreateRolloutResult, error) {
	if err := s.protectedOperationError(); err != nil {
		return CreateRolloutResult{}, err
	}
	if ctx == nil || builder == nil {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	var result CreateRolloutResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = s.CreateSecretRolloutTx(ctx, tx, request, builder)
		return err
	})
	if err != nil {
		return CreateRolloutResult{}, stableSecretOperationError(err)
	}
	return result, nil
}

func (s *Store) CreateSecretRolloutTx(
	ctx context.Context,
	tx pgx.Tx,
	request SecretRolloutRequest,
	builder SecretArtifactBuilder,
) (CreateRolloutResult, error) {
	if err := s.protectedOperationError(); err != nil {
		return CreateRolloutResult{}, err
	}
	if ctx == nil || tx == nil || builder == nil {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	normalized, err := normalizeSecretRolloutRequest(request, now)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	authorization, err := s.authorizeSession(
		ctx, tx, normalized.Actor, normalized.ConfigurationScopeID, PermissionManage,
	)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	if err := lockSecretRolloutIdempotency(ctx, tx, normalized.ConfigurationScopeID, normalized.IdempotencyKey); err != nil {
		return CreateRolloutResult{}, err
	}
	if replay, found, err := loadSecretRolloutReplay(ctx, tx, normalized); err != nil {
		return CreateRolloutResult{}, err
	} else if found {
		return CreateRolloutResult{Rollout: replay, Replayed: true}, nil
	}
	return s.persistSecretRollout(ctx, tx, normalized, authorization.UserID(),
		authorization.AuthenticationScopeID(), builder, now)
}

func (s *Store) CreateSecretRolloutFromSourceTx(
	ctx context.Context,
	tx pgx.Tx,
	request SecretRolloutRequest,
	domainRequestDigest [sha256.Size]byte,
	additionalPermissions []string,
	source SecretRolloutSource,
) (CreateRolloutResult, error) {
	if err := s.protectedOperationError(); err != nil {
		return CreateRolloutResult{}, err
	}
	if ctx == nil || tx == nil || source == nil || len(request.CanonicalSnapshot) != 0 ||
		request.PayloadDigest != ([sha256.Size]byte{}) || domainRequestDigest == ([sha256.Size]byte{}) {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	normalized, err := normalizeSecretRolloutFixedRequest(request, now)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	permissions, err := normalizeSecretRolloutPermissions(additionalPermissions)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	actorUserID, authenticationScopeID, err := s.authorizeSecretRolloutPermissions(
		ctx, tx, normalized.Actor, normalized.ConfigurationScopeID, permissions,
	)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	normalized.Digest, err = secretRolloutSourceDigest(normalized, domainRequestDigest, permissions)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	if err := lockSecretRolloutIdempotency(ctx, tx, normalized.ConfigurationScopeID, normalized.IdempotencyKey); err != nil {
		return CreateRolloutResult{}, err
	}
	if replay, found, err := loadSecretRolloutReplay(ctx, tx, normalized); err != nil {
		return CreateRolloutResult{}, err
	} else if found {
		return CreateRolloutResult{Rollout: replay, Replayed: true}, nil
	}

	material, err := callSecretRolloutSource(ctx, tx, source)
	if err != nil {
		clearBytes(material.CanonicalSnapshot)
		material = SecretRolloutMaterial{}
		return CreateRolloutResult{}, err
	}
	materialRequest := normalized.SecretRolloutRequest
	materialRequest.CanonicalSnapshot = material.CanonicalSnapshot
	materialRequest.PayloadDigest = material.PayloadDigest
	full, normalizeErr := normalizeSecretRolloutRequest(materialRequest, now)
	clearBytes(material.CanonicalSnapshot)
	material.CanonicalSnapshot = nil
	if normalizeErr != nil || material.Builder == nil {
		if normalizeErr != nil {
			return CreateRolloutResult{}, normalizeErr
		}
		return CreateRolloutResult{}, ErrInvalidInput
	}
	full.Digest = normalized.Digest
	defer clearBytes(full.CanonicalSnapshot)
	builder := material.Builder
	material.Builder = nil
	return s.persistSecretRollout(ctx, tx, full, actorUserID, authenticationScopeID, builder, now)
}

func (s *Store) authorizeSecretRolloutPermissions(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	additionalPermissions []string,
) (uuid.UUID, uuid.UUID, error) {
	permissions := append([]string{PermissionManage}, additionalPermissions...)
	slices.Sort(permissions)
	permissions = slices.Compact(permissions)
	authorization, err := s.authorizeSessionPermissions(ctx, tx, actor, targetScopeID, permissions)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return authorization.UserID(), authorization.AuthenticationScopeID(), nil
}

func (s *Store) persistSecretRollout(
	ctx context.Context,
	tx pgx.Tx,
	normalized normalizedSecretRolloutRequest,
	actorUserID, authenticationScopeID uuid.UUID,
	builder SecretArtifactBuilder,
	now time.Time,
) (CreateRolloutResult, error) {
	return s.persistSecretRolloutAs(ctx, tx, normalized,
		secretRolloutAuditActor{userID: &actorUserID, scopeID: authenticationScopeID}, builder, now)
}

// secretRolloutAuditActor is who the rollout audit names: an authorized user,
// or the system (system = the writer, no actor user).
type secretRolloutAuditActor struct {
	userID  *uuid.UUID
	scopeID uuid.UUID
	system  string
}

func (s *Store) persistSecretRolloutAs(
	ctx context.Context,
	tx pgx.Tx,
	normalized normalizedSecretRolloutRequest,
	actor secretRolloutAuditActor,
	builder SecretArtifactBuilder,
	now time.Time,
) (CreateRolloutResult, error) {
	recipients, err := lockSecretRolloutNodes(ctx, tx, normalized, now)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	defer clearArtifactRecipients(recipients)
	configID, rolloutID := uuid.New(), uuid.New()
	bindings := make([]SecretArtifactBinding, len(recipients))
	artifacts := make([]ArtifactInput, len(recipients))
	outboxIDs := make([]uuid.UUID, len(recipients))
	for index, recipient := range recipients {
		binding := SecretArtifactBinding{
			EventID: uuid.New(), DeploymentID: uuid.New(), RolloutID: rolloutID, Attempt: 1,
			ConfigVersionID: configID, ArtifactID: uuid.New(), NodeID: recipient.NodeID,
			RecipientKeyID: recipient.ID, RecipientPublicKey: bytes.Clone(recipient.PublicKey),
		}
		artifact, buildErr := callSecretArtifactBuilder(ctx, builder, binding)
		clearBytes(binding.RecipientPublicKey)
		binding.RecipientPublicKey = nil
		if buildErr != nil {
			return CreateRolloutResult{}, buildErr
		}
		artifact, buildErr = validateSecretArtifactBinding(artifact, binding)
		if buildErr != nil {
			return CreateRolloutResult{}, buildErr
		}
		bindings[index], artifacts[index], outboxIDs[index] = binding, artifact, uuid.New()
	}

	config, err := persistSecretConfig(ctx, tx, normalized, configID, artifacts, now)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	if err := persistSecretRollout(ctx, tx, normalized, rolloutID, configID, now); err != nil {
		return CreateRolloutResult{}, err
	}
	deployments := make([]Deployment, 0, len(bindings))
	for index, binding := range bindings {
		deployment, persistErr := persistSecretDeployment(ctx, tx, normalized, binding, nil, artifacts[index], outboxIDs[index], now)
		if persistErr != nil {
			return CreateRolloutResult{}, persistErr
		}
		deployments = append(deployments, deployment)
	}
	nodeIDs := make([]string, len(bindings))
	deploymentIDs := make([]string, len(bindings))
	eventIDs := make([]string, len(bindings))
	artifactIDs := make([]string, len(bindings))
	recipientKeyIDs := make([]string, len(bindings))
	for index, binding := range bindings {
		nodeIDs[index], deploymentIDs[index] = binding.NodeID.String(), binding.DeploymentID.String()
		eventIDs[index], artifactIDs[index] = binding.EventID.String(), binding.ArtifactID.String()
		recipientKeyIDs[index] = binding.RecipientKeyID
	}
	payload := map[string]any{
		"idempotency_key": normalized.IdempotencyKey,
		"node_ids":        nodeIDs, "config_version_id": configID.String(),
		"deployment_ids": deploymentIDs, "command_event_ids": eventIDs,
		"artifact_ids": artifactIDs, "recipient_key_ids": recipientKeyIDs,
		"payload_digest_sha256": hex.EncodeToString(normalized.PayloadDigest[:]),
	}
	if actor.system != "" {
		payload["actor_kind"], payload["reason"] = "system", actor.system
		payload["accountable_user_id"] = normalized.Actor.UserID.String()
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.scopeID, ActorUserID: actor.userID,
		Action: secretRolloutAuditAction, ResourceType: "edge_rollout", ResourceID: rolloutID.String(),
		RequestID: normalized.RequestID, Result: "success", Payload: payload,
	}); err != nil {
		return CreateRolloutResult{}, fmt.Errorf("audit secret edge rollout: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE rollouts SET status='queued',queued_at=$2,updated_at=$2
		WHERE id=$1 AND status='building'`, rolloutID, now); err != nil {
		return CreateRolloutResult{}, fmt.Errorf("queue secret edge rollout: %w", err)
	}
	return CreateRolloutResult{Rollout: Rollout{
		ID: rolloutID, ConfigurationScopeID: normalized.ConfigurationScopeID, ConfigVersionID: config.ID,
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, Deployments: deployments,
		CreatedAt: now, QueuedAt: now, Revision: 1, MaxAttempts: 1,
	}}, nil
}

func (s *Store) ReplaceSecretRollout(
	ctx context.Context,
	request SecretReplacementRequest,
	source SecretReplacementSource,
) (SecretReplacementResult, error) {
	if err := s.protectedOperationError(); err != nil {
		return SecretReplacementResult{}, err
	}
	if ctx == nil || source == nil {
		return SecretReplacementResult{}, ErrInvalidInput
	}
	var result SecretReplacementResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = s.ReplaceSecretRolloutTx(ctx, tx, request, source)
		return err
	})
	if err != nil {
		return SecretReplacementResult{}, stableSecretOperationError(err)
	}
	return result, nil
}

func (s *Store) ReplaceSecretRolloutTx(
	ctx context.Context,
	tx pgx.Tx,
	request SecretReplacementRequest,
	source SecretReplacementSource,
) (SecretReplacementResult, error) {
	if err := s.protectedOperationError(); err != nil {
		return SecretReplacementResult{}, err
	}
	if ctx == nil || tx == nil || source == nil {
		return SecretReplacementResult{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	normalized, err := normalizeSecretReplacementRequest(request, now)
	if err != nil {
		return SecretReplacementResult{}, err
	}
	authorization, err := s.authorizeSession(
		ctx, tx, normalized.Actor, normalized.ConfigurationScopeID, PermissionManage,
	)
	if err != nil {
		return SecretReplacementResult{}, err
	}
	writeRequestID, replay, found, err := claimSecretReplacement(ctx, tx, normalized, now)
	if err != nil {
		return SecretReplacementResult{}, err
	}
	if found {
		replay.Replayed = true
		return replay, nil
	}
	origin, err := lockSecretReplacementOrigin(ctx, tx, normalized)
	if err != nil {
		return SecretReplacementResult{}, err
	}

	storageKey := secretReplacementStoragePrefix + writeRequestID.String()
	var (
		bindings     []SecretArtifactBinding
		artifacts    []ArtifactInput
		rollout      Rollout
		publication  normalizedSecretRolloutRequest
		consumeCalls int
	)
	err = callSecretReplacementSource(ctx, tx, source, func(
		material SecretReplacementMaterial,
		builder SecretReplacementArtifactBuilder,
	) error {
		consumeCalls++
		if consumeCalls != 1 || builder == nil {
			return ErrSecretArtifactContract
		}
		if !bytes.Equal(material.CanonicalSnapshot, origin.CanonicalSnapshot) {
			return ErrSecretArtifactContract
		}
		publication, err = normalizeSecretRolloutRequest(
			secretReplacementPublicationRequest(normalized, material, storageKey), now,
		)
		if err != nil {
			return err
		}
		publication.Digest = secretReplacementPublicationDigest(normalized.Digest, material)
		recipients, err := lockSecretRolloutNodes(ctx, tx, publication, now)
		if err != nil {
			return err
		}
		defer clearArtifactRecipients(recipients)

		configID, rolloutID := uuid.New(), uuid.New()
		bindings = make([]SecretArtifactBinding, len(recipients))
		outboxIDs := make([]uuid.UUID, len(recipients))
		for index, recipient := range recipients {
			bindings[index] = SecretArtifactBinding{
				EventID: uuid.New(), DeploymentID: uuid.New(), RolloutID: rolloutID, Attempt: 1,
				ConfigVersionID: configID, ArtifactID: uuid.New(), NodeID: recipient.NodeID,
				RecipientKeyID: recipient.ID, RecipientPublicKey: bytes.Clone(recipient.PublicKey),
			}
			outboxIDs[index] = uuid.New()
		}
		artifacts, err = callSecretReplacementBuilder(ctx, builder, bindings)
		for index := range bindings {
			clearBytes(bindings[index].RecipientPublicKey)
			bindings[index].RecipientPublicKey = nil
		}
		if err != nil {
			return err
		}
		if len(artifacts) != len(bindings) {
			return ErrSecretArtifactContract
		}
		for index := range artifacts {
			artifacts[index], err = validateSecretArtifactBinding(artifacts[index], bindings[index])
			if err != nil {
				return err
			}
		}
		config, err := persistSecretConfig(ctx, tx, publication, configID, artifacts, now)
		if err != nil {
			return err
		}
		if err := persistSecretRollout(ctx, tx, publication, rolloutID, configID, now); err != nil {
			return err
		}
		createdDeployments := make([]Deployment, 0, len(bindings))
		for index, binding := range bindings {
			deployment, err := persistSecretDeployment(
				ctx, tx, publication, binding, nil, artifacts[index], outboxIDs[index], now,
			)
			if err != nil {
				return err
			}
			createdDeployments = append(createdDeployments, deployment)
		}
		rollout = Rollout{
			ID: rolloutID, ConfigurationScopeID: publication.ConfigurationScopeID, ConfigVersionID: config.ID,
			Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, Deployments: createdDeployments,
			CreatedAt: now, QueuedAt: now, Revision: 1, MaxAttempts: 1,
		}
		return nil
	})
	if err != nil {
		return SecretReplacementResult{}, err
	}
	if consumeCalls != 1 || rollout.ID == uuid.Nil {
		return SecretReplacementResult{}, ErrSecretArtifactContract
	}

	actorUserID := authorization.UserID()
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: authorization.AuthenticationScopeID(), ActorUserID: &actorUserID,
		Action: secretReplacementAuditAction, ResourceType: "edge_rollout", ResourceID: rollout.ID.String(),
		RequestID: publication.RequestID, Result: "success",
		Payload: map[string]any{
			"idempotency_key":               normalized.IdempotencyKey,
			"original_rollout_id":           normalized.OriginalRolloutID.String(),
			"original_revision":             normalized.ExpectedRevision,
			"original_deployment_ids":       commandDeploymentIDs(origin.Deployments),
			"replacement_rollout_id":        rollout.ID.String(),
			"replacement_config_version_id": rollout.ConfigVersionID.String(),
			"node_ids":                      uuidStrings(publication.NodeIDs),
			"deployment_ids":                bindingUUIDStrings(bindings, func(value SecretArtifactBinding) uuid.UUID { return value.DeploymentID }),
			"command_event_ids":             bindingUUIDStrings(bindings, func(value SecretArtifactBinding) uuid.UUID { return value.EventID }),
			"artifact_ids":                  bindingUUIDStrings(bindings, func(value SecretArtifactBinding) uuid.UUID { return value.ArtifactID }),
			"recipient_key_ids":             bindingRecipientIDs(bindings),
			"payload_digest_sha256":         hex.EncodeToString(publication.PayloadDigest[:]),
		},
	}); err != nil {
		return SecretReplacementResult{}, fmt.Errorf("audit replacement secret edge rollout: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE rollouts SET status='queued',queued_at=$2,updated_at=$2
		WHERE id=$1 AND status='building'`, rollout.ID, now); err != nil {
		return SecretReplacementResult{}, fmt.Errorf("queue replacement secret edge rollout: %w", err)
	}
	updated, err := tx.Exec(ctx, `UPDATE rollouts SET revision=revision+1,updated_at=$3
		WHERE configuration_scope_id=$1 AND id=$2 AND status='queued' AND revision=$4`,
		publication.ConfigurationScopeID, normalized.OriginalRolloutID, now, normalized.ExpectedRevision)
	if err != nil {
		return SecretReplacementResult{}, fmt.Errorf("advance original secret rollout revision: %w", err)
	}
	if updated.RowsAffected() != 1 {
		return SecretReplacementResult{}, ErrRevisionConflict
	}
	result := SecretReplacementResult{
		OriginalRolloutID: normalized.OriginalRolloutID,
		OriginalRevision:  normalized.ExpectedRevision + 1,
		Rollout:           rollout,
	}
	if err := completeSecretReplacement(ctx, tx, normalized, secretReplacementResponse{
		OriginalRolloutID: normalized.OriginalRolloutID, OriginalRevision: result.OriginalRevision,
		ReplacementRolloutID: rollout.ID, ReplacementIdempotency: storageKey,
		ReplacementDigest: hex.EncodeToString(publication.Digest[:]),
	}, now); err != nil {
		return SecretReplacementResult{}, err
	}
	return result, nil
}

func normalizeSecretRolloutRequest(request SecretRolloutRequest, now time.Time) (normalizedSecretRolloutRequest, error) {
	if len(request.CanonicalSnapshot) == 0 || len(request.CanonicalSnapshot) > maxConfigSnapshotBytes ||
		request.PayloadDigest == ([sha256.Size]byte{}) ||
		containsPrivateMaterial(request.CanonicalSnapshot) {
		return normalizedSecretRolloutRequest{}, ErrInvalidInput
	}
	normalized, err := normalizeSecretRolloutFixedRequest(request, now)
	if err != nil {
		return normalizedSecretRolloutRequest{}, err
	}
	digestDocument := struct {
		ScopeID                      string                    `json:"scope_id"`
		NodeIDs                      []string                  `json:"node_ids"`
		Snapshot                     []byte                    `json:"snapshot"`
		GeneratorName                string                    `json:"generator_name"`
		GeneratorVersion             string                    `json:"generator_version"`
		PayloadDigest                string                    `json:"payload_digest_sha256"`
		Capabilities                 []rolloutDigestCapability `json:"capabilities"`
		ActivationTimeoutNS          int64                     `json:"activation_timeout_ns"`
		ObservationWindowNS          int64                     `json:"observation_window_ns"`
		RequiredConsecutiveSuccesses uint32                    `json:"required_consecutive_successes"`
		Deadline                     string                    `json:"deadline"`
		RequestID                    string                    `json:"request_id"`
		CorrelationID                string                    `json:"correlation_id"`
		Traceparent                  string                    `json:"traceparent"`
		TaskID                       *string                   `json:"task_id,omitempty"`
		ActorUserID                  string                    `json:"actor_user_id"`
		ActorScopeID                 string                    `json:"actor_scope_id"`
	}{
		ScopeID: normalized.ConfigurationScopeID.String(), NodeIDs: uuidStrings(normalized.NodeIDs),
		Snapshot: request.CanonicalSnapshot, GeneratorName: normalized.GeneratorName,
		GeneratorVersion: normalized.GeneratorVersion, PayloadDigest: hex.EncodeToString(request.PayloadDigest[:]),
		Capabilities:                 secretDigestCapabilities(normalized.RequiredCapabilities),
		ActivationTimeoutNS:          int64(normalized.HealthCheck.ActivationTimeout),
		ObservationWindowNS:          int64(normalized.HealthCheck.ObservationWindow),
		RequiredConsecutiveSuccesses: normalized.HealthCheck.RequiredConsecutiveSuccesses,
		Deadline:                     normalized.Deadline.UTC().Format(time.RFC3339Nano), RequestID: normalized.RequestUUID.String(),
		CorrelationID: normalized.CorrelationUUID.String(), Traceparent: normalized.Traceparent,
		TaskID: cloneString(normalized.TaskID), ActorUserID: normalized.Actor.UserID.String(),
		ActorScopeID: normalized.Actor.ScopeID.String(),
	}
	encoded, err := json.Marshal(digestDocument)
	if err != nil {
		return normalizedSecretRolloutRequest{}, fmt.Errorf("encode secret rollout digest: %w", err)
	}
	normalized.CanonicalSnapshot = bytes.Clone(request.CanonicalSnapshot)
	normalized.PayloadDigest = request.PayloadDigest
	normalized.Digest = sha256.Sum256(encoded)
	return normalized, nil
}

func normalizeSecretRolloutFixedRequest(
	request SecretRolloutRequest,
	now time.Time,
) (normalizedSecretRolloutRequest, error) {
	if request.ConfigurationScopeID == uuid.Nil || !validActor(request.Actor) || len(request.NodeIDs) == 0 ||
		!validLabel(request.GeneratorName) || !validLabel(request.GeneratorVersion) ||
		!validIdempotencyKey(request.IdempotencyKey) {
		return normalizedSecretRolloutRequest{}, ErrInvalidInput
	}
	nodeIDs := slices.Clone(request.NodeIDs)
	slices.SortFunc(nodeIDs, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
	for index, nodeID := range nodeIDs {
		if nodeID == uuid.Nil || (index > 0 && nodeID == nodeIDs[index-1]) {
			return normalizedSecretRolloutRequest{}, ErrInvalidInput
		}
	}
	rolloutRequest := CreateRolloutRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		ConfigVersionID:      uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		NodeIDs:              nodeIDs,
		RequiredCapabilities: request.RequiredCapabilities,
		HealthCheck:          request.HealthCheck,
		Deadline:             request.Deadline,
		IdempotencyKey:       request.IdempotencyKey,
		RequestID:            request.RequestID,
		CorrelationID:        request.CorrelationID,
		Traceparent:          request.Traceparent,
		TaskID:               request.TaskID,
		MaxAttempts:          1,
		ContractVersion:      0,
	}
	normalizedRollout, err := normalizeRolloutRequest(rolloutRequest, now)
	if err != nil {
		return normalizedSecretRolloutRequest{}, err
	}
	request.CanonicalSnapshot = nil
	request.PayloadDigest = [sha256.Size]byte{}
	request.NodeIDs = nodeIDs
	request.RequiredCapabilities = cloneCapabilities(normalizedRollout.RequiredCapabilities)
	request.TaskID = cloneString(request.TaskID)
	return normalizedSecretRolloutRequest{
		SecretRolloutRequest: request, RequestUUID: normalizedRollout.RequestUUID,
		CorrelationUUID:      normalizedRollout.CorrelationUUID,
		RequiredCapabilities: cloneCapabilities(normalizedRollout.RequiredCapabilities),
	}, nil
}

func normalizeSecretRolloutPermissions(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, ErrInvalidInput
	}
	permissions := slices.Clone(values)
	slices.Sort(permissions)
	permissions = slices.Compact(permissions)
	for _, permission := range permissions {
		if !validSecretRolloutPermission(permission) {
			return nil, ErrInvalidInput
		}
	}
	return permissions, nil
}

func validSecretRolloutPermission(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func secretRolloutSourceDigest(
	request normalizedSecretRolloutRequest,
	domainRequestDigest [sha256.Size]byte,
	additionalPermissions []string,
) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(struct {
		Domain                       string                    `json:"domain"`
		ScopeID                      string                    `json:"scope_id"`
		NodeIDs                      []string                  `json:"node_ids"`
		GeneratorName                string                    `json:"generator_name"`
		GeneratorVersion             string                    `json:"generator_version"`
		Capabilities                 []rolloutDigestCapability `json:"capabilities"`
		ActivationTimeoutNS          int64                     `json:"activation_timeout_ns"`
		ObservationWindowNS          int64                     `json:"observation_window_ns"`
		RequiredConsecutiveSuccesses uint32                    `json:"required_consecutive_successes"`
		Deadline                     string                    `json:"deadline"`
		IdempotencyKey               string                    `json:"idempotency_key"`
		RequestID                    string                    `json:"request_id"`
		CorrelationID                string                    `json:"correlation_id"`
		Traceparent                  string                    `json:"traceparent"`
		TaskID                       *string                   `json:"task_id,omitempty"`
		ActorUserID                  string                    `json:"actor_user_id"`
		ActorScopeID                 string                    `json:"actor_scope_id"`
		ActorScopeKind               string                    `json:"actor_scope_kind"`
		ActorSessionID               string                    `json:"actor_session_id"`
		AdditionalPermissions        []string                  `json:"additional_permissions"`
		DomainRequestDigest          string                    `json:"domain_request_digest_sha256"`
	}{
		Domain:  secretRolloutSourceDigestDomain,
		ScopeID: request.ConfigurationScopeID.String(), NodeIDs: uuidStrings(request.NodeIDs),
		GeneratorName: request.GeneratorName, GeneratorVersion: request.GeneratorVersion,
		Capabilities:                 secretDigestCapabilities(request.RequiredCapabilities),
		ActivationTimeoutNS:          int64(request.HealthCheck.ActivationTimeout),
		ObservationWindowNS:          int64(request.HealthCheck.ObservationWindow),
		RequiredConsecutiveSuccesses: request.HealthCheck.RequiredConsecutiveSuccesses,
		Deadline:                     request.Deadline.UTC().Format(time.RFC3339Nano), IdempotencyKey: request.IdempotencyKey,
		RequestID: request.RequestUUID.String(), CorrelationID: request.CorrelationUUID.String(),
		Traceparent: request.Traceparent, TaskID: cloneString(request.TaskID),
		ActorUserID: request.Actor.UserID.String(), ActorScopeID: request.Actor.ScopeID.String(),
		ActorScopeKind: request.Actor.ScopeKind, ActorSessionID: request.Actor.SessionID.String(),
		AdditionalPermissions: slices.Clone(additionalPermissions),
		DomainRequestDigest:   hex.EncodeToString(domainRequestDigest[:]),
	})
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("encode sourced secret rollout digest: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

func normalizeSecretReplacementRequest(
	request SecretReplacementRequest,
	now time.Time,
) (normalizedSecretReplacementRequest, error) {
	if !validActor(request.Actor) || request.ConfigurationScopeID == uuid.Nil || len(request.NodeIDs) == 0 ||
		request.OriginalRolloutID == uuid.Nil || request.ExpectedRevision <= 0 ||
		!validLabel(request.GeneratorName) || !validLabel(request.GeneratorVersion) ||
		!validIdempotencyKey(request.IdempotencyKey) {
		return normalizedSecretReplacementRequest{}, ErrInvalidInput
	}
	nodeIDs := slices.Clone(request.NodeIDs)
	slices.SortFunc(nodeIDs, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
	for index, nodeID := range nodeIDs {
		if nodeID == uuid.Nil || (index > 0 && nodeID == nodeIDs[index-1]) {
			return normalizedSecretReplacementRequest{}, ErrInvalidInput
		}
	}
	rollout, err := normalizeRolloutRequest(CreateRolloutRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		ConfigVersionID:      uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		NodeIDs:              nodeIDs,
		RequiredCapabilities: request.RequiredCapabilities,
		HealthCheck:          request.HealthCheck,
		Deadline:             request.Deadline,
		IdempotencyKey:       request.IdempotencyKey,
		RequestID:            request.RequestID,
		CorrelationID:        request.CorrelationID,
		Traceparent:          request.Traceparent,
		TaskID:               request.TaskID,
		MaxAttempts:          1,
	}, now)
	if err != nil {
		return normalizedSecretReplacementRequest{}, err
	}
	encoded, err := json.Marshal(struct {
		ScopeID                      string                    `json:"scope_id"`
		NodeIDs                      []string                  `json:"node_ids"`
		OriginalRolloutID            string                    `json:"original_rollout_id"`
		ExpectedRevision             int64                     `json:"expected_revision"`
		GeneratorName                string                    `json:"generator_name"`
		GeneratorVersion             string                    `json:"generator_version"`
		Capabilities                 []rolloutDigestCapability `json:"capabilities"`
		ActivationTimeoutNS          int64                     `json:"activation_timeout_ns"`
		ObservationWindowNS          int64                     `json:"observation_window_ns"`
		RequiredConsecutiveSuccesses uint32                    `json:"required_consecutive_successes"`
		Deadline                     string                    `json:"deadline"`
		RequestID                    string                    `json:"request_id"`
		CorrelationID                string                    `json:"correlation_id"`
		Traceparent                  string                    `json:"traceparent"`
		TaskID                       *string                   `json:"task_id,omitempty"`
	}{
		ScopeID: request.ConfigurationScopeID.String(), NodeIDs: uuidStrings(nodeIDs),
		OriginalRolloutID: request.OriginalRolloutID.String(), ExpectedRevision: request.ExpectedRevision,
		GeneratorName: request.GeneratorName, GeneratorVersion: request.GeneratorVersion,
		Capabilities:                 secretDigestCapabilities(rollout.RequiredCapabilities),
		ActivationTimeoutNS:          int64(request.HealthCheck.ActivationTimeout),
		ObservationWindowNS:          int64(request.HealthCheck.ObservationWindow),
		RequiredConsecutiveSuccesses: request.HealthCheck.RequiredConsecutiveSuccesses,
		Deadline:                     request.Deadline.UTC().Format(time.RFC3339Nano),
		RequestID:                    rollout.RequestUUID.String(),
		CorrelationID:                rollout.CorrelationUUID.String(),
		Traceparent:                  request.Traceparent,
		TaskID:                       cloneString(request.TaskID),
	})
	if err != nil {
		return normalizedSecretReplacementRequest{}, fmt.Errorf("encode secret replacement digest: %w", err)
	}
	request.NodeIDs = nodeIDs
	request.RequiredCapabilities = cloneCapabilities(rollout.RequiredCapabilities)
	request.TaskID = cloneString(request.TaskID)
	return normalizedSecretReplacementRequest{
		SecretReplacementRequest: request, RequestUUID: rollout.RequestUUID,
		CorrelationUUID: rollout.CorrelationUUID, NodeIDs: nodeIDs,
		RequiredCapabilities: cloneCapabilities(rollout.RequiredCapabilities), Digest: sha256.Sum256(encoded),
	}, nil
}

func secretReplacementPublicationRequest(
	request normalizedSecretReplacementRequest,
	material SecretReplacementMaterial,
	idempotencyKey string,
) SecretRolloutRequest {
	return SecretRolloutRequest{
		Actor: request.Actor, ConfigurationScopeID: request.ConfigurationScopeID,
		NodeIDs: slices.Clone(request.NodeIDs), CanonicalSnapshot: bytes.Clone(material.CanonicalSnapshot),
		GeneratorName: request.GeneratorName, GeneratorVersion: request.GeneratorVersion,
		PayloadDigest: material.PayloadDigest, RequiredCapabilities: cloneCapabilities(request.RequiredCapabilities),
		HealthCheck: request.HealthCheck, Deadline: request.Deadline, IdempotencyKey: idempotencyKey,
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, Traceparent: request.Traceparent,
		TaskID: cloneString(request.TaskID),
	}
}

func secretReplacementPublicationDigest(
	semanticDigest [sha256.Size]byte,
	material SecretReplacementMaterial,
) [sha256.Size]byte {
	snapshotDigest := sha256.Sum256(material.CanonicalSnapshot)
	encoded, _ := json.Marshal(struct {
		SemanticDigest string `json:"semantic_digest_sha256"`
		SnapshotDigest string `json:"canonical_snapshot_sha256"`
		PayloadDigest  string `json:"payload_digest_sha256"`
	}{
		SemanticDigest: hex.EncodeToString(semanticDigest[:]),
		SnapshotDigest: hex.EncodeToString(snapshotDigest[:]),
		PayloadDigest:  hex.EncodeToString(material.PayloadDigest[:]),
	})
	return sha256.Sum256(encoded)
}

func claimSecretReplacement(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedSecretReplacementRequest,
	now time.Time,
) (uuid.UUID, SecretReplacementResult, bool, error) {
	writeRequestID := uuid.New()
	command, err := tx.Exec(ctx, `INSERT INTO edge_rollout_write_requests(
		id,actor_user_id,actor_scope_id,configuration_scope_id,rollout_id,operation,
		idempotency_key,request_digest,expected_revision,request_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	ON CONFLICT(actor_user_id,operation,idempotency_key) DO NOTHING`,
		writeRequestID, request.Actor.UserID, request.Actor.ScopeID,
		request.ConfigurationScopeID, request.OriginalRolloutID, rolloutOperationRetry,
		request.IdempotencyKey, request.Digest[:], request.ExpectedRevision,
		request.RequestUUID, now)
	if err != nil {
		return uuid.Nil, SecretReplacementResult{}, false, fmt.Errorf("claim secret replacement: %w", err)
	}
	if command.RowsAffected() == 1 {
		return writeRequestID, SecretReplacementResult{}, false, nil
	}
	var persistedDigest, encoded []byte
	if err := tx.QueryRow(ctx, `SELECT request_digest,response_body
		FROM edge_rollout_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
		request.Actor.UserID, rolloutOperationRetry, request.IdempotencyKey).Scan(
		&persistedDigest, &encoded); err != nil {
		return uuid.Nil, SecretReplacementResult{}, false, fmt.Errorf("read secret replacement replay: %w", err)
	}
	if !bytes.Equal(persistedDigest, request.Digest[:]) || len(encoded) == 0 {
		return uuid.Nil, SecretReplacementResult{}, false, ErrIdempotencyConflict
	}
	var response secretReplacementResponse
	if json.Unmarshal(encoded, &response) != nil || response.OriginalRolloutID != request.OriginalRolloutID ||
		response.OriginalRevision != request.ExpectedRevision+1 || response.ReplacementRolloutID == uuid.Nil ||
		len(response.ReplacementIdempotency) <= len(secretReplacementStoragePrefix) ||
		response.ReplacementIdempotency[:len(secretReplacementStoragePrefix)] != secretReplacementStoragePrefix {
		return uuid.Nil, SecretReplacementResult{}, false, ErrIdempotencyConflict
	}
	replacementDigest, err := hex.DecodeString(response.ReplacementDigest)
	if err != nil || len(replacementDigest) != sha256.Size {
		return uuid.Nil, SecretReplacementResult{}, false, ErrIdempotencyConflict
	}
	publication := normalizedSecretRolloutRequest{SecretRolloutRequest: SecretRolloutRequest{
		ConfigurationScopeID: request.ConfigurationScopeID, NodeIDs: slices.Clone(request.NodeIDs),
		IdempotencyKey: response.ReplacementIdempotency,
	}}
	copy(publication.Digest[:], replacementDigest)
	rollout, found, err := loadSecretRolloutReplay(ctx, tx, publication)
	if err != nil {
		return uuid.Nil, SecretReplacementResult{}, false, err
	}
	if !found {
		return uuid.Nil, SecretReplacementResult{}, false, ErrIdempotencyConflict
	}
	if rollout.ID != response.ReplacementRolloutID {
		return uuid.Nil, SecretReplacementResult{}, false, ErrIdempotencyConflict
	}
	return uuid.Nil, SecretReplacementResult{
		OriginalRolloutID: response.OriginalRolloutID,
		OriginalRevision:  response.OriginalRevision,
		Rollout:           rollout,
	}, true, nil
}

func completeSecretReplacement(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedSecretReplacementRequest,
	response secretReplacementResponse,
	now time.Time,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("encode secret replacement response: %w", err)
	}
	command, err := tx.Exec(ctx, `UPDATE edge_rollout_write_requests
		SET response_body=$4,completed_at=$5
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 AND completed_at IS NULL`,
		request.Actor.UserID, rolloutOperationRetry, request.IdempotencyKey, encoded, now)
	if err != nil {
		return fmt.Errorf("complete secret replacement: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func lockSecretReplacementOrigin(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedSecretReplacementRequest,
) (secretReplacementOrigin, error) {
	var (
		configID          uuid.UUID
		action            string
		status            string
		revision          int64
		maxAttempts       int
		canonicalSnapshot []byte
	)
	err := tx.QueryRow(ctx, `SELECT rollout.config_version_id,rollout.action,rollout.status,
		rollout.revision,rollout.max_attempts,config.canonical_snapshot
		FROM rollouts rollout JOIN config_versions config ON config.id=rollout.config_version_id
		WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2 FOR UPDATE OF rollout`,
		request.ConfigurationScopeID, request.OriginalRolloutID).Scan(
		&configID, &action, &status, &revision, &maxAttempts, &canonicalSnapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return secretReplacementOrigin{}, ErrNotFound
	}
	if err != nil {
		return secretReplacementOrigin{}, fmt.Errorf("lock original secret rollout: %w", err)
	}
	if revision != request.ExpectedRevision {
		return secretReplacementOrigin{}, ErrRevisionConflict
	}
	if action != "apply" || status != "queued" || maxAttempts != 1 {
		return secretReplacementOrigin{}, ErrSecretRetryRequiresRepublish
	}
	rows, err := tx.Query(ctx, `SELECT deployment.id,deployment.node_id,deployment.attempt,
		deployment.config_version_id,deployment.previous_config_version_id,deployment.action,
		deployment.state,deployment.command_bytes
		FROM node_deployments deployment
		WHERE deployment.rollout_id=$1 AND NOT EXISTS(
			SELECT 1 FROM node_deployments newer
			WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt
		)
		ORDER BY deployment.node_id FOR UPDATE OF deployment`, request.OriginalRolloutID)
	if err != nil {
		return secretReplacementOrigin{}, fmt.Errorf("lock original secret deployments: %w", err)
	}
	var deployments []commandDeployment
	for rows.Next() {
		var deployment commandDeployment
		var attempt int
		if err := rows.Scan(&deployment.id, &deployment.nodeID, &attempt, &deployment.configID,
			&deployment.previousID, &deployment.action, &deployment.state, &deployment.commandBytes); err != nil {
			rows.Close()
			return secretReplacementOrigin{}, fmt.Errorf("scan original secret deployment: %w", err)
		}
		deployment.attempt = uint32(attempt)
		deployments = append(deployments, deployment)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return secretReplacementOrigin{}, fmt.Errorf("iterate original secret deployments: %w", err)
	}
	rows.Close()
	if len(deployments) != len(request.NodeIDs) || len(deployments) == 0 {
		return secretReplacementOrigin{}, ErrSecretRetryRequiresRepublish
	}

	seenArtifacts := make(map[uuid.UUID]struct{}, len(deployments))
	for index := range deployments {
		deployment := &deployments[index]
		if deployment.nodeID != request.NodeIDs[index] || deployment.attempt != 1 ||
			deployment.configID != configID || deployment.action != "apply" || !deploymentFailed(deployment.state) {
			return secretReplacementOrigin{}, ErrSecretRetryRequiresRepublish
		}
		if err := tx.QueryRow(ctx, `SELECT status FROM edge_command_outbox
			WHERE deployment_id=$1 AND deployment_attempt=$2 FOR UPDATE`, deployment.id, deployment.attempt).Scan(
			&deployment.outboxStatus); errors.Is(err, pgx.ErrNoRows) {
			return secretReplacementOrigin{}, ErrSecretRetryRequiresRepublish
		} else if err != nil {
			return secretReplacementOrigin{}, fmt.Errorf("lock original secret outbox: %w", err)
		}
		artifactID, descriptor, err := loadExactSecretDeploymentArtifact(ctx, tx, *deployment)
		if err != nil {
			return secretReplacementOrigin{}, err
		}
		if _, duplicate := seenArtifacts[artifactID]; duplicate {
			return secretReplacementOrigin{}, ErrSecretRetryRequiresRepublish
		}
		seenArtifacts[artifactID] = struct{}{}
		command, err := unmarshalDeploymentCommand(deployment.commandBytes)
		if err != nil || command.DeploymentId != deployment.id.String() || command.RolloutId != request.OriginalRolloutID.String() ||
			command.ConfigVersionId != configID.String() || command.Attempt != deployment.attempt ||
			command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || len(command.Artifacts) != 1 ||
			!proto.Equal(command.Artifacts[0], descriptor) {
			return secretReplacementOrigin{}, ErrSecretRetryRequiresRepublish
		}
		var outboxPayload, outboxDigest []byte
		if err := tx.QueryRow(ctx, `SELECT payload,payload_sha256 FROM edge_command_outbox
			WHERE deployment_id=$1 AND deployment_attempt=$2`, deployment.id, deployment.attempt).Scan(
			&outboxPayload, &outboxDigest); err != nil {
			return secretReplacementOrigin{}, fmt.Errorf("verify original secret outbox: %w", err)
		}
		digest := sha256.Sum256(deployment.commandBytes)
		if !bytes.Equal(outboxPayload, deployment.commandBytes) || !bytes.Equal(outboxDigest, digest[:]) {
			return secretReplacementOrigin{}, ErrSecretRetryRequiresRepublish
		}
	}
	var totalArtifacts, secretArtifacts int
	if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE kind='node_secret_bundle'
		AND encryption_algorithm='hpke_x25519_hkdf_sha256_aes_256_gcm' AND recipient_key_id IS NOT NULL)
		FROM configuration_artifacts WHERE config_version_id=$1`, configID).Scan(&totalArtifacts, &secretArtifacts); err != nil {
		return secretReplacementOrigin{}, fmt.Errorf("verify original secret configuration: %w", err)
	}
	if totalArtifacts != len(deployments) || secretArtifacts != len(deployments) {
		return secretReplacementOrigin{}, ErrSecretRetryRequiresRepublish
	}
	return secretReplacementOrigin{
		CanonicalSnapshot: bytes.Clone(canonicalSnapshot), Deployments: deployments,
	}, nil
}

func loadExactSecretDeploymentArtifact(
	ctx context.Context,
	tx pgx.Tx,
	deployment commandDeployment,
) (uuid.UUID, *agentv1.ArtifactDescriptor, error) {
	rows, err := tx.Query(ctx, `SELECT artifact.id,artifact.kind,artifact.size_bytes,artifact.sha256,
		artifact.signature,artifact.signing_key_id,artifact.signature_algorithm,artifact.compression,
		artifact.media_type,artifact.encryption_algorithm,artifact.recipient_key_id
		FROM node_deployment_artifacts binding
		JOIN configuration_artifacts artifact
		  ON artifact.config_version_id=binding.config_version_id AND artifact.id=binding.artifact_id
		WHERE binding.deployment_id=$1 AND binding.deployment_attempt=$2
		ORDER BY binding.ordinal`, deployment.id, deployment.attempt)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("read original secret artifact: %w", err)
	}
	defer rows.Close()
	var (
		artifactID                                                                 uuid.UUID
		kind, signingKeyID, signatureAlgorithm, compression, mediaType, encryption string
		size                                                                       int64
		digest, signature                                                          []byte
		recipientKeyID                                                             *string
		count                                                                      int
	)
	for rows.Next() {
		count++
		if count > 1 {
			return uuid.Nil, nil, ErrSecretRetryRequiresRepublish
		}
		if err := rows.Scan(&artifactID, &kind, &size, &digest, &signature, &signingKeyID,
			&signatureAlgorithm, &compression, &mediaType, &encryption, &recipientKeyID); err != nil {
			return uuid.Nil, nil, fmt.Errorf("scan original secret artifact: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, nil, fmt.Errorf("iterate original secret artifact: %w", err)
	}
	if count != 1 || recipientKeyID == nil {
		return uuid.Nil, nil, ErrSecretRetryRequiresRepublish
	}
	descriptor, err := descriptorFromStorage(artifactID, kind, size, digest, signature, signingKeyID,
		signatureAlgorithm, compression, mediaType, encryption, recipientKeyID)
	if err != nil || descriptor.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
		return uuid.Nil, nil, ErrSecretRetryRequiresRepublish
	}
	return artifactID, descriptor, nil
}

func secretDigestCapabilities(values []*agentv1.Capability) []rolloutDigestCapability {
	result := make([]rolloutDigestCapability, len(values))
	for index, value := range values {
		result[index] = rolloutDigestCapability{Name: int32(value.Name), APIVersion: value.ApiVersion}
	}
	return result
}

func containsPrivateMaterial(value []byte) bool {
	lower := bytes.ToLower(value)
	for _, marker := range [][]byte{
		[]byte("-----begin private key-----"), []byte("-----begin rsa private key-----"),
		[]byte("-----begin ec private key-----"), []byte(`"private_key_pem"`),
		[]byte(`"private_key"`), []byte(`"kek"`),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func lockSecretRolloutIdempotency(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, key string) error {
	digest := sha256.Sum256([]byte("cdnca-edge-secret-rollout-idempotency-v1\x00" + scopeID.String() + "\x00" + key))
	lockKey := int64(binary.BigEndian.Uint64(digest[:8]))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return fmt.Errorf("lock secret rollout idempotency: %w", err)
	}
	return nil
}

func loadSecretRolloutReplay(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedSecretRolloutRequest,
) (Rollout, bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rollouts
		WHERE configuration_scope_id=$1 AND idempotency_key=$2)`,
		request.ConfigurationScopeID, request.IdempotencyKey).Scan(&exists); err != nil {
		return Rollout{}, false, fmt.Errorf("read secret rollout idempotency: %w", err)
	}
	if !exists {
		return Rollout{}, false, nil
	}
	rollout, err := loadRolloutByIdempotencyKey(ctx, tx, request.ConfigurationScopeID, request.IdempotencyKey, request.Digest)
	if err != nil {
		return Rollout{}, false, err
	}
	if rollout.MaxAttempts != 1 || len(rollout.Deployments) != len(request.NodeIDs) {
		return Rollout{}, false, ErrIdempotencyConflict
	}
	artifactIDs := make(map[string]struct{}, len(rollout.Deployments))
	for index, deployment := range rollout.Deployments {
		if deployment.NodeID != request.NodeIDs[index] || deployment.Command == nil ||
			deployment.Command.DeploymentId != deployment.ID.String() ||
			deployment.Command.RolloutId != rollout.ID.String() ||
			deployment.Command.ConfigVersionId != rollout.ConfigVersionID.String() ||
			deployment.Command.Attempt != 1 || len(deployment.Command.Artifacts) != 1 {
			return Rollout{}, false, ErrIdempotencyConflict
		}
		artifact := deployment.Command.Artifacts[0]
		if artifact == nil || artifact.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE ||
			artifact.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
			artifact.RecipientKeyId == nil {
			return Rollout{}, false, ErrIdempotencyConflict
		}
		if _, duplicate := artifactIDs[artifact.ArtifactId]; duplicate {
			return Rollout{}, false, ErrIdempotencyConflict
		}
		artifactIDs[artifact.ArtifactId] = struct{}{}
	}
	var configCount, totalArtifactCount, artifactCount, bindingCount, outboxCount int
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM config_versions WHERE id=$1 AND idempotency_key=$2 AND request_digest=$3 AND status='releasable'),
		(SELECT count(*) FROM configuration_artifacts WHERE config_version_id=$1),
		(SELECT count(*) FROM configuration_artifacts WHERE config_version_id=$1 AND kind='node_secret_bundle'
		 AND encryption_algorithm='hpke_x25519_hkdf_sha256_aes_256_gcm'),
		(SELECT count(*) FROM node_deployment_artifacts binding
		 JOIN node_deployments deployment ON deployment.id=binding.deployment_id
		  AND deployment.attempt=binding.deployment_attempt
		 WHERE deployment.rollout_id=$4 AND deployment.attempt=1),
		(SELECT count(*) FROM edge_command_outbox outbox
		 JOIN node_deployments deployment ON deployment.id=outbox.deployment_id
		  AND deployment.attempt=outbox.deployment_attempt
		 WHERE deployment.rollout_id=$4 AND deployment.attempt=1)`,
		rollout.ConfigVersionID, request.IdempotencyKey, request.Digest[:], rollout.ID).Scan(
		&configCount, &totalArtifactCount, &artifactCount, &bindingCount, &outboxCount); err != nil {
		return Rollout{}, false, fmt.Errorf("verify secret rollout replay: %w", err)
	}
	if configCount != 1 || totalArtifactCount != len(request.NodeIDs) || artifactCount != len(request.NodeIDs) ||
		bindingCount != len(request.NodeIDs) || outboxCount != len(request.NodeIDs) {
		return Rollout{}, false, ErrIdempotencyConflict
	}
	return rollout, true, nil
}

func lockSecretRolloutNodes(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedSecretRolloutRequest,
	now time.Time,
) ([]activeArtifactRecipient, error) {
	recipients := make([]activeArtifactRecipient, 0, len(request.NodeIDs))
	for _, nodeID := range request.NodeIDs {
		recipient, err := lockSecretRolloutNode(ctx, tx, request.ConfigurationScopeID, nodeID, now)
		if err != nil {
			clearArtifactRecipients(recipients)
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

func lockSecretRolloutNode(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, nodeID uuid.UUID,
	now time.Time,
) (activeArtifactRecipient, error) {
	var adminState string
	var carried bool
	// A tenant's secrets may go to its own nodes and to platform nodes that
	// carry its sites (migration 287), never to another tenant's node.
	err := tx.QueryRow(ctx, `SELECT admin_state,tenant_carries_node_287($2,id) FROM nodes WHERE id=$1 FOR UPDATE`,
		nodeID, scopeID).Scan(&adminState, &carried)
	if errors.Is(err, pgx.ErrNoRows) {
		return activeArtifactRecipient{}, ErrNodeNotFound
	}
	if err != nil {
		return activeArtifactRecipient{}, fmt.Errorf("lock secret rollout node: %w", err)
	}
	if !carried {
		return activeArtifactRecipient{}, ErrConfigurationScopeConflict
	}
	if adminState != "active" {
		return activeArtifactRecipient{}, ErrNodeRecipientKeyUnavailable
	}
	recipient := activeArtifactRecipient{NodeID: nodeID}
	var storedDigest []byte
	var activatedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT key.id,key.public_key,key.public_key_sha256,key.activated_at
		FROM node_identity_state identity_state
		JOIN node_artifact_encryption_keys key
		  ON key.node_id=identity_state.node_id AND key.id=identity_state.active_artifact_key_id
		WHERE identity_state.node_id=$1 AND key.status='active' AND key.deactivated_at IS NULL
		FOR UPDATE OF identity_state,key`, nodeID).Scan(
		&recipient.ID, &recipient.PublicKey, &storedDigest, &activatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return activeArtifactRecipient{}, ErrNodeRecipientKeyUnavailable
	}
	if err != nil {
		return activeArtifactRecipient{}, fmt.Errorf("lock active artifact recipient: %w", err)
	}
	digest := sha256.Sum256(recipient.PublicKey)
	if len(recipient.PublicKey) != 32 || len(storedDigest) != sha256.Size ||
		!bytes.Equal(storedDigest, digest[:]) || recipient.ID != "x25519:"+hex.EncodeToString(digest[:]) ||
		activatedAt == nil || activatedAt.After(now) {
		clearBytes(recipient.PublicKey)
		return activeArtifactRecipient{}, ErrNodeRecipientKeyUnavailable
	}
	return recipient, nil
}

func callSecretArtifactBuilder(
	ctx context.Context,
	builder SecretArtifactBuilder,
	binding SecretArtifactBinding,
) (artifact ArtifactInput, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("build secret artifact: %w", ErrSecretArtifactContract)
		}
	}()
	artifact, err = builder(ctx, binding)
	if err != nil {
		return ArtifactInput{}, fmt.Errorf("build secret artifact: %w", err)
	}
	return artifact, nil
}

func callSecretRolloutSource(
	ctx context.Context,
	tx pgx.Tx,
	source SecretRolloutSource,
) (material SecretRolloutMaterial, err error) {
	defer func() {
		if recover() != nil {
			clearBytes(material.CanonicalSnapshot)
			material = SecretRolloutMaterial{}
			err = fmt.Errorf("open secret rollout source: %w", ErrSecretArtifactContract)
		}
	}()
	return source(ctx, tx)
}

func callSecretReplacementSource(
	ctx context.Context,
	tx pgx.Tx,
	source SecretReplacementSource,
	consume SecretReplacementConsume,
) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("open secret replacement source: %w", ErrSecretArtifactContract)
		}
	}()
	if err := source(ctx, tx, consume); err != nil {
		return fmt.Errorf("open secret replacement source: %w", err)
	}
	return nil
}

func callSecretReplacementBuilder(
	ctx context.Context,
	builder SecretReplacementArtifactBuilder,
	bindings []SecretArtifactBinding,
) (artifacts []ArtifactInput, err error) {
	consumerBindings := cloneSecretArtifactBindings(bindings)
	defer func() {
		for index := range consumerBindings {
			clearBytes(consumerBindings[index].RecipientPublicKey)
			consumerBindings[index].RecipientPublicKey = nil
		}
		if recovered := recover(); recovered != nil {
			artifacts = nil
			err = fmt.Errorf("build secret replacement artifacts: %w", ErrSecretArtifactContract)
		}
	}()
	artifacts, err = builder(ctx, consumerBindings)
	if err != nil {
		return nil, fmt.Errorf("build secret replacement artifacts: %w", err)
	}
	return artifacts, nil
}

func cloneSecretArtifactBindings(values []SecretArtifactBinding) []SecretArtifactBinding {
	result := make([]SecretArtifactBinding, len(values))
	for index, value := range values {
		result[index] = value
		result[index].RecipientPublicKey = bytes.Clone(value.RecipientPublicKey)
	}
	return result
}

func validateSecretArtifactBinding(input ArtifactInput, binding SecretArtifactBinding) (ArtifactInput, error) {
	artifact, err := validateArtifact(input)
	if err != nil {
		return ArtifactInput{}, err
	}
	if artifact.ID != binding.ArtifactID || artifact.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE ||
		artifact.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		artifact.RecipientKeyID == nil || *artifact.RecipientKeyID != binding.RecipientKeyID {
		return ArtifactInput{}, ErrSecretArtifactContract
	}
	return artifact, nil
}

func persistSecretConfig(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedSecretRolloutRequest,
	configID uuid.UUID,
	artifacts []ArtifactInput,
	now time.Time,
) (ConfigVersion, error) {
	if len(artifacts) != len(request.NodeIDs) || len(artifacts) == 0 {
		return ConfigVersion{}, ErrSecretArtifactContract
	}
	snapshotDigest := sha256.Sum256(request.CanonicalSnapshot)
	command, err := tx.Exec(ctx, `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,
		status,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$3,$4,$5,$6,'building',$7,$8,$9)
	ON CONFLICT(configuration_scope_id,idempotency_key) DO NOTHING`, configID, request.ConfigurationScopeID,
		request.CanonicalSnapshot, snapshotDigest[:], request.GeneratorName, request.GeneratorVersion,
		request.IdempotencyKey, request.Digest[:], now)
	if err != nil {
		return ConfigVersion{}, translateConfigWriteError(err)
	}
	if command.RowsAffected() != 1 {
		return ConfigVersion{}, ErrIdempotencyConflict
	}
	seenDigests := make(map[string]struct{}, len(artifacts))
	for index, artifact := range artifacts {
		if _, duplicate := seenDigests[string(artifact.SHA256)]; duplicate {
			return ConfigVersion{}, ErrSecretArtifactContract
		}
		seenDigests[string(artifact.SHA256)] = struct{}{}
		if err := persistSigningKey(ctx, tx, artifact, now); err != nil {
			return ConfigVersion{}, err
		}
		kind, compression, encryption, err := artifactStorageValues(artifact)
		if err != nil {
			return ConfigVersion{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO configuration_artifacts(
			id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,signature,signing_key_id,
			signature_algorithm,compression,media_type,encryption_algorithm,recipient_key_id,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'ed25519',$10,$11,$12,$13,$14)`, artifact.ID, configID,
			index+1, kind, artifact.WireBytes, int64(artifact.SizeBytes), artifact.SHA256, artifact.Signature,
			artifact.SigningKeyID, compression, artifact.MediaType, encryption, artifact.RecipientKeyID, now); err != nil {
			return ConfigVersion{}, fmt.Errorf("persist secret configuration artifact: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE config_versions SET status='validating' WHERE id=$1`, configID); err != nil {
		return ConfigVersion{}, fmt.Errorf("advance secret config validation: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`, configID, now); err != nil {
		return ConfigVersion{}, fmt.Errorf("publish secret config version: %w", err)
	}
	return ConfigVersion{
		ID: configID, ConfigurationScopeID: request.ConfigurationScopeID,
		CanonicalSnapshotSHA256: snapshotDigest, GeneratorName: request.GeneratorName,
		GeneratorVersion: request.GeneratorVersion, Artifacts: descriptorsFromInputs(artifacts),
		CreatedAt: now, PublishedAt: now,
	}, nil
}

func persistSecretRollout(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedSecretRolloutRequest,
	rolloutID, configID uuid.UUID,
	now time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO rollouts(
		id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
		request_id,correlation_id,traceparent,task_id,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,deadline_at,created_at,revision,max_attempts,updated_at,contract_version
	) VALUES($1,$2,$3,'apply','building',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1,1,$14,$15)`,
		rolloutID, request.ConfigurationScopeID, configID, request.IdempotencyKey, request.Digest[:],
		request.RequestUUID, request.CorrelationUUID, request.Traceparent, request.TaskID,
		request.HealthCheck.ActivationTimeout.Milliseconds(), request.HealthCheck.ObservationWindow.Milliseconds(),
		int64(request.HealthCheck.RequiredConsecutiveSuccesses), request.Deadline.UTC(), now, 0)
	if err != nil {
		return fmt.Errorf("persist secret rollout: %w", err)
	}
	return nil
}

func persistSecretDeployment(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedSecretRolloutRequest,
	binding SecretArtifactBinding,
	previousConfigID *uuid.UUID,
	artifact ArtifactInput,
	outboxID uuid.UUID,
	now time.Time,
) (Deployment, error) {
	descriptor := descriptorsFromInputs([]ArtifactInput{artifact})[0]
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: binding.EventID.String(), RequestId: request.RequestUUID.String(), OccurredTime: timestamppb.New(now),
			Traceparent: request.Traceparent, CorrelationId: request.CorrelationUUID.String(), TaskId: cloneString(request.TaskID),
		},
		DeploymentId: binding.DeploymentID.String(), Attempt: 1, RolloutId: binding.RolloutID.String(),
		ConfigVersionId: binding.ConfigVersionID.String(), PreviousConfigVersionId: uuidString(previousConfigID),
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, Artifacts: []*agentv1.ArtifactDescriptor{descriptor},
		RequiredCapabilities: cloneCapabilities(request.RequiredCapabilities),
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration:    durationpb.New(request.HealthCheck.ActivationTimeout),
			ObservationWindowDuration:    durationpb.New(request.HealthCheck.ObservationWindow),
			RequiredConsecutiveSuccesses: request.HealthCheck.RequiredConsecutiveSuccesses,
		},
		DeadlineTime:         timestamppb.New(request.Deadline.UTC()),
		ConfigurationScopeId: proto.String(request.ConfigurationScopeID.String()),
	}
	encoded, err := marshalDeploymentCommand(command)
	if err != nil {
		return Deployment{}, err
	}
	digest := sha256.Sum256(encoded)
	queuesPerScope, err := NodeServesSeveralScopes(ctx, tx, binding.NodeID)
	if err != nil {
		return Deployment{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO node_deployments(
		id,rollout_id,node_id,attempt,config_version_id,previous_config_version_id,action,state,
		command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,queued_per_scope
	) VALUES($1,$2,$3,1,$4,$5,'apply','queued',$6,$7,$8,$9,$10,$10,$11)`, binding.DeploymentID,
		binding.RolloutID, binding.NodeID, binding.ConfigVersionID, previousConfigID, binding.EventID,
		encoded, digest[:], request.Deadline.UTC(), now, queuesPerScope)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && activeDeploymentConstraint(pgErr.ConstraintName) {
			return Deployment{}, ErrNodeDeploymentActive
		}
		if errors.As(err, &pgErr) && pgErr.ConstraintName == "node_deployments_reconciliation_gate" {
			return Deployment{}, ErrNodeReconciliationRequired
		}
		return Deployment{}, fmt.Errorf("persist secret node deployment: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO node_deployment_artifacts(
		deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal
	) VALUES($1,1,$2,$3,1)`, binding.DeploymentID, binding.ConfigVersionID, binding.ArtifactID); err != nil {
		return Deployment{}, fmt.Errorf("persist secret deployment artifact binding: %w", err)
	}
	subject := "cdnca.agent.commands." + binding.NodeID.String()
	if _, err := tx.Exec(ctx, `INSERT INTO edge_command_outbox(
		id,deployment_id,deployment_attempt,node_id,subject,payload,payload_sha256,status,available_at,created_at,updated_at
	) VALUES($1,$2,1,$3,$4,$5,$6,'pending',$7,$7,$7)`, outboxID, binding.DeploymentID, binding.NodeID,
		subject, encoded, digest[:], now); err != nil {
		return Deployment{}, fmt.Errorf("persist secret edge command outbox: %w", err)
	}
	return Deployment{
		ID: binding.DeploymentID, NodeID: binding.NodeID, Subject: subject,
		CommandBytes: slices.Clone(encoded), Command: command,
	}, nil
}

func requireConfigurationOnlyRetry(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, attempt uint32) error {
	var total, configurationOnly int
	if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(
		WHERE artifact.kind='configuration' AND artifact.encryption_algorithm='none')
		FROM node_deployment_artifacts binding
		JOIN configuration_artifacts artifact
		  ON artifact.config_version_id=binding.config_version_id AND artifact.id=binding.artifact_id
		WHERE binding.deployment_id=$1 AND binding.deployment_attempt=$2`, deploymentID, attempt).Scan(
		&total, &configurationOnly); err != nil {
		return fmt.Errorf("classify deployment retry artifacts: %w", err)
	}
	if total == 0 || configurationOnly != total {
		return ErrSecretRetryRequiresRepublish
	}
	return nil
}

func uuidStrings(values []uuid.UUID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func clearArtifactRecipients(values []activeArtifactRecipient) {
	for index := range values {
		clearBytes(values[index].PublicKey)
		values[index].PublicKey = nil
	}
}

func bindingUUIDStrings(
	values []SecretArtifactBinding,
	selectID func(SecretArtifactBinding) uuid.UUID,
) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = selectID(value).String()
	}
	return result
}

func bindingRecipientIDs(values []SecretArtifactBinding) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.RecipientKeyID
	}
	return result
}

func commandDeploymentIDs(values []commandDeployment) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.id.String()
	}
	return result
}

func stableSecretOperationError(err error) error {
	for _, domainErr := range []error{
		ErrNodeRecipientKeyUnavailable, ErrSecretArtifactContract, ErrSecretRetryRequiresRepublish,
		ErrConfigNotFound, ErrConfigNotReleasable, ErrNodeNotFound, ErrConfigurationScopeConflict,
		ErrNodeDeploymentActive, ErrNodeReconciliationRequired,
	} {
		if errors.Is(err, domainErr) {
			return domainErr
		}
	}
	return stableOperationError(err)
}
