package edgeartifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type Store struct {
	pool   *pgxpool.Pool
	config Config
	now    func() time.Time
	// siteObjectMembers caches recent publications' member sets.
	siteObjectMembers *siteObjectMemberCache
}

type storedArtifact struct {
	nodeID              uuid.UUID
	commandEventID      uuid.UUID
	configVersionID     uuid.UUID
	rolloutID           uuid.UUID
	previousConfigID    *uuid.UUID
	action              string
	state               string
	configStatus        string
	deadline            time.Time
	hasNewerAttempt     bool
	commandBytes        []byte
	commandSHA256       []byte
	id                  uuid.UUID
	ordinal             int32
	configOrdinal       int32
	kind                string
	wireBytes           []byte
	sizeBytes           int64
	sha256              []byte
	signature           []byte
	signingKeyID        string
	signingPublicKey    []byte
	signingKeyAlgorithm string
	signatureAlgorithm  string
	compression         string
	mediaType           string
	encryption          string
	recipientKeyID      *string
	recipientActive     bool
	boundDescriptors    []storedDescriptor
}

type storedDescriptor struct {
	configVersionID     uuid.UUID
	id                  uuid.UUID
	ordinal             int32
	configOrdinal       int32
	kind                string
	sizeBytes           int64
	sha256              []byte
	signature           []byte
	signingKeyID        string
	signingKeyAlgorithm string
	signatureAlgorithm  string
	compression         string
	mediaType           string
	encryption          string
	recipientKeyID      *string
}

type fetchAudit struct {
	requestID    uuid.UUID
	deploymentID uuid.UUID
	nodeID       uuid.UUID
	attempt      int32
	artifactID   uuid.UUID
	offset       int64
	digest       []byte
	status       string
	bytesServed  int64
}

func NewStore(pool *pgxpool.Pool, config Config) (*Store, error) {
	return NewStoreWithClock(pool, config, time.Now)
}

func NewStoreWithClock(pool *pgxpool.Pool, config Config, now func() time.Time) (*Store, error) {
	if pool == nil || now == nil {
		return nil, fmt.Errorf("%w: PostgreSQL pool and clock are required", ErrInvalidConfig)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Store{pool: pool, config: config, now: now, siteObjectMembers: &siteObjectMemberCache{}}, nil
}

// FetchChunk validates and audits one resumable range. A non-EOF result always
// contains exactly one non-empty chunk no larger than Config.MaxChunkBytes.
func (s *Store) FetchChunk(ctx context.Context, request *controlv1.FetchArtifactRequest) (FetchResult, error) {
	if ctx == nil {
		return FetchResult{}, fmt.Errorf("%w: context", ErrInvalidRequest)
	}
	if request.GetCleanupOnly() {
		// The node's session does not allow deployments (ADR-0003: only a
		// CLEANUP_ONLY ACME HTTP-01 overlay may be fetched).
		return FetchResult{}, ErrDeploymentIneligible
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	normalized, err := normalizeRequest(request, s.config, now)
	if err != nil {
		return FetchResult{}, err
	}
	var result FetchResult
	var domainErr error
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := lockRequestID(ctx, tx, normalized.requestID); err != nil {
			return err
		}
		audit, found, err := findAudit(ctx, tx, normalized.requestID)
		if err != nil {
			return err
		}
		if found {
			if err := verifyAuditIdentity(audit, normalized); err != nil {
				domainErr = err
				return nil
			}
			artifact, err := loadBoundArtifact(ctx, tx, normalized)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					domainErr = ErrBindingConflict
					return nil
				}
				return err
			}
			result, domainErr = s.replay(audit, artifact, normalized, now)
			return nil
		}

		artifact, err := loadBoundArtifact(ctx, tx, normalized)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				domainErr = ErrBindingConflict
				return nil
			}
			return err
		}
		if artifact.nodeID != normalized.nodeID {
			exists, err := nodeExists(ctx, tx, normalized.nodeID)
			if err != nil {
				return err
			}
			if !exists {
				domainErr = ErrBindingConflict
				return nil
			}
		}

		inserted, err := insertStartedAudit(ctx, tx, normalized, now)
		if err != nil {
			return err
		}
		if !inserted {
			audit, found, err = findAudit(ctx, tx, normalized.requestID)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("artifact fetch audit disappeared after conflict")
			}
			if err := verifyAuditIdentity(audit, normalized); err != nil {
				domainErr = err
				return nil
			}
			result, domainErr = s.replay(audit, artifact, normalized, now)
			return nil
		}

		result, domainErr = s.buildResult(artifact, normalized, now, true)
		if domainErr != nil {
			if err := finishAudit(ctx, tx, normalized.requestID, "failed", 0, now); err != nil {
				return err
			}
			return nil
		}
		bytesServed := int64(0)
		if result.Response != nil {
			bytesServed = int64(len(result.Response.GetChunk().GetData()))
		}
		return finishAudit(ctx, tx, normalized.requestID, "completed", bytesServed, now)
	})
	if err != nil {
		return FetchResult{}, fmt.Errorf("%w: transaction: %w", ErrStorage, err)
	}
	if domainErr != nil {
		return FetchResult{}, domainErr
	}
	return result, nil
}

func lockRequestID(ctx context.Context, tx pgx.Tx, requestID uuid.UUID) error {
	digest := sha256.Sum256(requestID[:])
	key := int64(binary.BigEndian.Uint64(digest[:8]))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, key); err != nil {
		return fmt.Errorf("lock artifact fetch request: %w", err)
	}
	return nil
}

func (s *Store) replay(audit fetchAudit, artifact storedArtifact, request normalizedRequest, now time.Time) (FetchResult, error) {
	switch audit.status {
	case "started":
		return FetchResult{}, ErrRequestInProgress
	case "failed":
		_, err := s.buildResult(artifact, request, now, true)
		if err != nil {
			return FetchResult{}, err
		}
		return FetchResult{}, ErrRequestFailed
	case "completed":
		result, err := s.buildResult(artifact, request, now, false)
		if err != nil {
			return FetchResult{}, err
		}
		served := int64(0)
		if result.Response != nil {
			served = int64(len(result.Response.GetChunk().GetData()))
		}
		if served != audit.bytesServed {
			return FetchResult{}, fmt.Errorf("%w: completed audit byte count", ErrArtifactIntegrity)
		}
		result.Replayed = true
		return result, nil
	default:
		return FetchResult{}, fmt.Errorf("%w: unknown audit status", ErrArtifactIntegrity)
	}
}

// fetchableDeploymentState: a node fetches a deployment's artifacts after it
// received the command (queued, delivered) and, for a scoped deployment
// (migration 289), after its own queue took it (agent_queued) and started it
// (started: the node then fetches the release); not once it staged it.
func fetchableDeploymentState(state string) bool {
	switch state {
	case "queued", "delivered", "agent_queued", "started":
		return true
	}
	return false
}

func (s *Store) buildResult(artifact storedArtifact, request normalizedRequest, now time.Time, requireEligible bool) (FetchResult, error) {
	if artifact.nodeID != request.nodeID || artifact.commandEventID != request.eventID || artifact.id != request.artifactID {
		return FetchResult{}, ErrBindingConflict
	}
	if artifact.kind == "configuration" && artifact.encryption == "hpke_x25519_hkdf_sha256_aes_256_gcm" && !artifact.recipientActive {
		return FetchResult{}, ErrBindingConflict
	}
	descriptor, err := artifactDescriptor(artifact)
	if err != nil {
		return FetchResult{}, err
	}
	if err := validateDeploymentCommand(artifact, request, descriptor); err != nil {
		return FetchResult{}, err
	}
	if requireEligible && (artifact.hasNewerAttempt || artifact.action != "apply" || !fetchableDeploymentState(artifact.state) ||
		(artifact.configStatus != "releasable" && artifact.configStatus != "superseded") ||
		!artifact.deadline.After(now)) {
		return FetchResult{}, ErrDeploymentIneligible
	}
	if request.offset > artifact.sizeBytes {
		return FetchResult{}, ErrOffsetOutOfRange
	}
	if request.offset == artifact.sizeBytes {
		return FetchResult{Descriptor: descriptor, EOF: true}, nil
	}
	end := request.offset + int64(s.config.MaxChunkBytes)
	if end > artifact.sizeBytes {
		end = artifact.sizeBytes
	}
	data := bytes.Clone(artifact.wireBytes[request.offset:end])
	if len(data) == 0 {
		return FetchResult{}, fmt.Errorf("%w: empty non-terminal chunk", ErrArtifactIntegrity)
	}
	digest := sha256.Sum256(data)
	return FetchResult{
		Descriptor: descriptor,
		Response: &controlv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
			RequestId: request.requestID.String(), ArtifactId: artifact.id.String(), Offset: uint64(request.offset),
			Data: data, ChunkSha256: bytes.Clone(digest[:]), TotalSizeBytes: uint64(artifact.sizeBytes),
			EndOfArtifact: end == artifact.sizeBytes,
		}},
	}, nil
}

func validateDeploymentCommand(artifact storedArtifact, request normalizedRequest, descriptor *agentv1.ArtifactDescriptor) error {
	if len(artifact.commandBytes) == 0 || len(artifact.commandBytes) > 1<<20 || len(artifact.commandSHA256) != sha256.Size {
		return fmt.Errorf("%w: deployment command bounds", ErrArtifactIntegrity)
	}
	digest := sha256.Sum256(artifact.commandBytes)
	if !bytes.Equal(digest[:], artifact.commandSHA256) {
		return fmt.Errorf("%w: deployment command digest", ErrArtifactIntegrity)
	}
	command := new(agentv1.DeploymentCommand)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(artifact.commandBytes, command); err != nil || hasUnknown(command.ProtoReflect()) {
		return fmt.Errorf("%w: deployment command protobuf", ErrArtifactIntegrity)
	}
	deterministic, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil || !bytes.Equal(deterministic, artifact.commandBytes) {
		return fmt.Errorf("%w: deployment command encoding", ErrArtifactIntegrity)
	}
	if command.Event == nil || command.Event.EventId != artifact.commandEventID.String() ||
		command.Event.EventId != request.eventID.String() || command.DeploymentId != request.deploymentID.String() ||
		command.Attempt != uint32(request.attempt) || command.RolloutId != artifact.rolloutID.String() ||
		command.ConfigVersionId != artifact.configVersionID.String() || command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY ||
		artifact.action != "apply" || command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil ||
		!command.DeadlineTime.AsTime().Equal(artifact.deadline) {
		return fmt.Errorf("%w: deployment command identity", ErrArtifactIntegrity)
	}
	if !optionalUUIDMatches(command.PreviousConfigVersionId, artifact.previousConfigID) ||
		command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil ||
		!validCommandEventMetadata(command) {
		return fmt.Errorf("%w: deployment command metadata", ErrArtifactIntegrity)
	}
	if len(artifact.boundDescriptors) == 0 || len(artifact.boundDescriptors) > 128 ||
		len(command.Artifacts) != len(artifact.boundDescriptors) {
		return fmt.Errorf("%w: deployment command artifact count", ErrArtifactIntegrity)
	}
	seen := make(map[uuid.UUID]struct{}, len(command.Artifacts))
	requestedFound := false
	for index, stored := range artifact.boundDescriptors {
		if stored.configVersionID != artifact.configVersionID || stored.ordinal != int32(index+1) ||
			stored.configOrdinal <= 0 || stored.id == uuid.Nil {
			return fmt.Errorf("%w: deployment artifact ordinal or config binding", ErrArtifactIntegrity)
		}
		if _, duplicate := seen[stored.id]; duplicate {
			return fmt.Errorf("%w: duplicate deployment artifact binding", ErrArtifactIntegrity)
		}
		seen[stored.id] = struct{}{}
		storedValue, err := descriptorFromStorage(stored)
		if err != nil {
			return err
		}
		if command.Artifacts[index] == nil || !proto.Equal(command.Artifacts[index], storedValue) {
			return fmt.Errorf("%w: deployment command artifact descriptor", ErrArtifactIntegrity)
		}
		if stored.id == artifact.id {
			requestedFound = stored.ordinal == artifact.ordinal && stored.configOrdinal == artifact.configOrdinal &&
				proto.Equal(storedValue, descriptor)
		}
	}
	if !requestedFound {
		return fmt.Errorf("%w: requested deployment artifact descriptor", ErrArtifactIntegrity)
	}
	return nil
}

func validCommandEventMetadata(command *agentv1.DeploymentCommand) bool {
	if _, err := canonicalUUID(command.Event.RequestId); err != nil {
		return false
	}
	if _, err := canonicalUUID(command.Event.CorrelationId); err != nil {
		return false
	}
	if command.Event.CausationId != nil {
		if _, err := canonicalUUID(command.Event.GetCausationId()); err != nil {
			return false
		}
	}
	return validTraceparent(command.Event.Traceparent) &&
		(command.Event.TaskId == nil || identifierPattern.MatchString(command.Event.GetTaskId()))
}

func optionalUUIDMatches(commandValue *string, storedValue *uuid.UUID) bool {
	if commandValue == nil || storedValue == nil {
		return commandValue == nil && storedValue == nil
	}
	parsed, err := canonicalUUID(*commandValue)
	return err == nil && parsed == *storedValue
}

func hasUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsMap() {
			if field.MapValue().Kind() != protoreflect.MessageKind {
				return true
			}
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				unknown = hasUnknown(item.Message())
				return !unknown
			})
			return !unknown
		}
		if field.IsList() {
			if field.Kind() != protoreflect.MessageKind {
				return true
			}
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if hasUnknown(list.Get(index).Message()) {
					unknown = true
					return false
				}
			}
			return true
		}
		if field.Kind() == protoreflect.MessageKind {
			unknown = hasUnknown(value.Message())
		}
		return !unknown
	})
	return unknown
}

func artifactDescriptor(artifact storedArtifact) (*agentv1.ArtifactDescriptor, error) {
	if artifact.id == uuid.Nil || artifact.sizeBytes <= 0 || artifact.sizeBytes > maxStoredArtifactBytes ||
		int64(len(artifact.wireBytes)) != artifact.sizeBytes || len(artifact.sha256) != sha256.Size ||
		len(artifact.signature) != ed25519.SignatureSize || len(artifact.signingPublicKey) != ed25519.PublicKeySize ||
		!identifierPattern.MatchString(artifact.signingKeyID) || artifact.signatureAlgorithm != "ed25519" ||
		artifact.signingKeyAlgorithm != artifact.signatureAlgorithm ||
		artifact.mediaType == "" || len(artifact.mediaType) > 128 || artifact.mediaType != bytesToTrimmedString(artifact.mediaType) {
		return nil, fmt.Errorf("%w: descriptor metadata", ErrArtifactIntegrity)
	}
	digest := sha256.Sum256(artifact.wireBytes)
	if !bytes.Equal(digest[:], artifact.sha256) || !ed25519.Verify(ed25519.PublicKey(artifact.signingPublicKey), artifact.wireBytes, artifact.signature) {
		return nil, fmt.Errorf("%w: digest or signature", ErrArtifactIntegrity)
	}
	return descriptorFromStorage(storedDescriptor{
		configVersionID: artifact.configVersionID, id: artifact.id, ordinal: artifact.ordinal,
		configOrdinal: artifact.configOrdinal, kind: artifact.kind, sizeBytes: artifact.sizeBytes,
		sha256: artifact.sha256, signature: artifact.signature, signingKeyID: artifact.signingKeyID,
		signingKeyAlgorithm: artifact.signingKeyAlgorithm, signatureAlgorithm: artifact.signatureAlgorithm,
		compression: artifact.compression, mediaType: artifact.mediaType, encryption: artifact.encryption,
		recipientKeyID: artifact.recipientKeyID,
	})
}

func descriptorFromStorage(artifact storedDescriptor) (*agentv1.ArtifactDescriptor, error) {
	if artifact.id == uuid.Nil || artifact.sizeBytes <= 0 || artifact.sizeBytes > maxStoredArtifactBytes ||
		len(artifact.sha256) != sha256.Size || len(artifact.signature) != ed25519.SignatureSize ||
		!identifierPattern.MatchString(artifact.signingKeyID) || artifact.signatureAlgorithm != "ed25519" ||
		artifact.signingKeyAlgorithm != artifact.signatureAlgorithm || artifact.mediaType == "" ||
		len(artifact.mediaType) > 128 || artifact.mediaType != bytesToTrimmedString(artifact.mediaType) {
		return nil, fmt.Errorf("%w: descriptor metadata", ErrArtifactIntegrity)
	}
	descriptor := &agentv1.ArtifactDescriptor{
		ArtifactId: artifact.id.String(), SizeBytes: uint64(artifact.sizeBytes), Sha256: bytes.Clone(artifact.sha256),
		Signature: bytes.Clone(artifact.signature), SigningKeyId: artifact.signingKeyID,
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		MediaType:          artifact.mediaType,
	}
	switch artifact.kind {
	case "configuration":
		descriptor.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
		if artifact.encryption == "none" && artifact.recipientKeyID == nil {
			descriptor.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE
		} else if artifact.encryption == "hpke_x25519_hkdf_sha256_aes_256_gcm" && artifact.recipientKeyID != nil &&
			artifactRecipientPattern.MatchString(*artifact.recipientKeyID) {
			descriptor.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
			value := *artifact.recipientKeyID
			descriptor.RecipientKeyId = &value
		} else {
			return nil, fmt.Errorf("%w: configuration encryption metadata", ErrArtifactIntegrity)
		}
	case "node_secret_bundle":
		descriptor.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
		if artifact.encryption != "hpke_x25519_hkdf_sha256_aes_256_gcm" || artifact.recipientKeyID == nil ||
			!identifierPattern.MatchString(*artifact.recipientKeyID) {
			return nil, fmt.Errorf("%w: secret encryption metadata", ErrArtifactIntegrity)
		}
		descriptor.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
		value := *artifact.recipientKeyID
		descriptor.RecipientKeyId = &value
	default:
		return nil, fmt.Errorf("%w: artifact kind", ErrArtifactIntegrity)
	}
	switch artifact.compression {
	case "none":
		descriptor.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE
	case "zstd":
		descriptor.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD
	default:
		return nil, fmt.Errorf("%w: artifact compression", ErrArtifactIntegrity)
	}
	return descriptor, nil
}

func bytesToTrimmedString(value string) string {
	return string(bytes.TrimSpace([]byte(value)))
}

func loadBoundArtifact(ctx context.Context, tx pgx.Tx, request normalizedRequest) (storedArtifact, error) {
	var artifact storedArtifact
	err := tx.QueryRow(ctx, `
		SELECT deployment.node_id, deployment.command_event_id, deployment.config_version_id,
		       deployment.rollout_id, deployment.previous_config_version_id,
		       deployment.action, deployment.state, config.status, deployment.deadline_at,
		       EXISTS (
		           SELECT 1 FROM node_deployments newer
		           WHERE newer.id = deployment.id AND newer.attempt > deployment.attempt
		       ), deployment.command_bytes, deployment.command_sha256,
		       stored.id, binding.ordinal, stored.ordinal,
		       stored.kind, stored.wire_bytes, stored.size_bytes, stored.sha256,
		       stored.signature, stored.signing_key_id, signing_key.public_key, signing_key.algorithm,
		       stored.signature_algorithm, stored.compression, stored.media_type,
		       stored.encryption_algorithm, stored.recipient_key_id
		FROM node_deployments deployment
		JOIN node_deployment_artifacts binding
		  ON binding.deployment_id = deployment.id
		 AND binding.deployment_attempt = deployment.attempt
		 AND binding.config_version_id = deployment.config_version_id
		JOIN config_versions config ON config.id = deployment.config_version_id
		JOIN configuration_artifacts stored
		  ON stored.id = binding.artifact_id AND stored.config_version_id = binding.config_version_id
		JOIN artifact_signing_keys signing_key ON signing_key.id = stored.signing_key_id
		WHERE deployment.id = $1 AND deployment.attempt = $2 AND stored.id = $3
		FOR UPDATE OF deployment`, request.deploymentID, request.attempt, request.artifactID).Scan(
		&artifact.nodeID, &artifact.commandEventID, &artifact.configVersionID,
		&artifact.rolloutID, &artifact.previousConfigID,
		&artifact.action, &artifact.state, &artifact.configStatus, &artifact.deadline,
		&artifact.hasNewerAttempt, &artifact.commandBytes, &artifact.commandSHA256,
		&artifact.id, &artifact.ordinal, &artifact.configOrdinal, &artifact.kind, &artifact.wireBytes,
		&artifact.sizeBytes, &artifact.sha256, &artifact.signature, &artifact.signingKeyID,
		&artifact.signingPublicKey, &artifact.signingKeyAlgorithm, &artifact.signatureAlgorithm, &artifact.compression,
		&artifact.mediaType, &artifact.encryption, &artifact.recipientKeyID,
	)
	if err != nil {
		return storedArtifact{}, fmt.Errorf("read bound artifact: %w", err)
	}
	if artifact.kind == "configuration" && artifact.encryption == "hpke_x25519_hkdf_sha256_aes_256_gcm" {
		if artifact.recipientKeyID == nil {
			return storedArtifact{}, fmt.Errorf("%w: encrypted configuration recipient", ErrArtifactIntegrity)
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM node_identity_state identity
			JOIN node_artifact_encryption_keys key
			  ON key.node_id=identity.node_id AND key.id=identity.active_artifact_key_id
			WHERE identity.node_id=$1 AND key.id=$2 AND key.status='active' AND key.deactivated_at IS NULL
		)`, artifact.nodeID, *artifact.recipientKeyID).Scan(&artifact.recipientActive); err != nil {
			return storedArtifact{}, fmt.Errorf("read encrypted configuration recipient: %w", err)
		}
	}
	artifact.boundDescriptors, err = loadBoundDescriptors(ctx, tx, request.deploymentID, request.attempt)
	if err != nil {
		return storedArtifact{}, err
	}
	return artifact, nil
}

func loadBoundDescriptors(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, attempt int32) ([]storedDescriptor, error) {
	rows, err := tx.Query(ctx, `
		SELECT binding.config_version_id, stored.id, binding.ordinal, stored.ordinal,
		       stored.kind, stored.size_bytes, stored.sha256, stored.signature,
		       stored.signing_key_id, signing_key.algorithm, stored.signature_algorithm,
		       stored.compression, stored.media_type, stored.encryption_algorithm, stored.recipient_key_id
		FROM node_deployment_artifacts binding
		JOIN configuration_artifacts stored
		  ON stored.id = binding.artifact_id AND stored.config_version_id = binding.config_version_id
		JOIN artifact_signing_keys signing_key ON signing_key.id = stored.signing_key_id
		WHERE binding.deployment_id = $1 AND binding.deployment_attempt = $2
		ORDER BY binding.ordinal`, deploymentID, attempt)
	if err != nil {
		return nil, fmt.Errorf("read deployment artifact descriptors: %w", err)
	}
	defer rows.Close()
	descriptors := make([]storedDescriptor, 0, 4)
	for rows.Next() {
		var descriptor storedDescriptor
		if err := rows.Scan(
			&descriptor.configVersionID, &descriptor.id, &descriptor.ordinal, &descriptor.configOrdinal,
			&descriptor.kind, &descriptor.sizeBytes, &descriptor.sha256, &descriptor.signature,
			&descriptor.signingKeyID, &descriptor.signingKeyAlgorithm, &descriptor.signatureAlgorithm,
			&descriptor.compression, &descriptor.mediaType, &descriptor.encryption, &descriptor.recipientKeyID,
		); err != nil {
			return nil, fmt.Errorf("scan deployment artifact descriptor: %w", err)
		}
		descriptors = append(descriptors, descriptor)
		if len(descriptors) > 128 {
			return nil, fmt.Errorf("%w: deployment artifact count", ErrArtifactIntegrity)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deployment artifact descriptors: %w", err)
	}
	return descriptors, nil
}

func findAudit(ctx context.Context, tx pgx.Tx, requestID uuid.UUID) (fetchAudit, bool, error) {
	var audit fetchAudit
	err := tx.QueryRow(ctx, `
		SELECT request_id, deployment_id, node_id, attempt, artifact_id, offset_bytes,
		       request_digest, status, bytes_served
		FROM artifact_fetch_requests WHERE request_id = $1 FOR UPDATE`, requestID).Scan(
		&audit.requestID, &audit.deploymentID, &audit.nodeID, &audit.attempt,
		&audit.artifactID, &audit.offset, &audit.digest, &audit.status, &audit.bytesServed,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return fetchAudit{}, false, nil
	}
	if err != nil {
		return fetchAudit{}, false, fmt.Errorf("read artifact fetch audit: %w", err)
	}
	return audit, true, nil
}

func verifyAuditIdentity(audit fetchAudit, request normalizedRequest) error {
	if !bytes.Equal(audit.digest, request.digest[:]) || audit.deploymentID != request.deploymentID ||
		audit.nodeID != request.nodeID || audit.attempt != request.attempt ||
		audit.artifactID != request.artifactID || audit.offset != request.offset {
		return ErrIdempotencyConflict
	}
	return nil
}

func insertStartedAudit(ctx context.Context, tx pgx.Tx, request normalizedRequest, now time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO artifact_fetch_requests (
			request_id, deployment_id, node_id, attempt, artifact_id, offset_bytes,
			request_digest, status, bytes_served, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'started', 0, $8)
		ON CONFLICT (request_id) DO NOTHING`,
		request.requestID, request.deploymentID, request.nodeID, request.attempt,
		request.artifactID, request.offset, request.digest[:], now)
	if err != nil {
		return false, fmt.Errorf("start artifact fetch audit: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func finishAudit(ctx context.Context, tx pgx.Tx, requestID uuid.UUID, status string, bytesServed int64, now time.Time) error {
	tag, err := tx.Exec(ctx, `
		UPDATE artifact_fetch_requests
		SET status = $2, bytes_served = $3, completed_at = $4
		WHERE request_id = $1 AND status = 'started'`, requestID, status, bytesServed, now)
	if err != nil {
		return fmt.Errorf("finish artifact fetch audit: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("finish artifact fetch audit: expected one started request")
	}
	return nil
}

func nodeExists(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id = $1)`, nodeID).Scan(&exists); err != nil {
		return false, fmt.Errorf("read artifact fetch node: %w", err)
	}
	return exists, nil
}
