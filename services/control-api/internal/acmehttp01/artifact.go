package acmehttp01

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeedge"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ArtifactStore struct {
	pool   *pgxpool.Pool
	cipher *Cipher
	config ArtifactConfig
}

type artifactBinding struct {
	delivery      acmeedge.SealedDelivery
	publicationID uuid.UUID
	requestID     uuid.UUID
	createdAt     time.Time
	deadline      time.Time
	hasNewer      bool
	previousID    *uuid.UUID
	previousRev   int64
}

// snapshotPurposeCleanupOnly is the signed purpose of a CLEANUP_ONLY node
// generation (ADR-0003). An apply snapshot carries no purpose member.
const snapshotPurposeCleanupOnly = "cleanup_only"

type snapshot struct {
	SchemaVersion    string          `json:"schema_version"`
	OverlayVersionID string          `json:"overlay_version_id"`
	OverlayRevision  uint64          `json:"overlay_revision"`
	Purpose          string          `json:"purpose,omitempty"`
	GeneratedAt      time.Time       `json:"generated_at"`
	Entries          []snapshotEntry `json:"entries"`
}

type snapshotEntry struct {
	Host      string    `json:"host"`
	Token     string    `json:"token"`
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

type aadDocument struct {
	Schema             string `json:"schema"`
	TenantScopeID      string `json:"tenant_scope_id"`
	SiteID             string `json:"site_id"`
	OperationID        string `json:"operation_id"`
	ChallengeAttemptID string `json:"challenge_attempt_id"`
	TokenSHA256        string `json:"token_sha256"`
}

func NewArtifactStore(pool *pgxpool.Pool, cipher *Cipher, config ArtifactConfig) (*ArtifactStore, error) {
	if pool == nil || cipher == nil || config.Clock == nil || config.SigningKeyID == "" ||
		len(config.SigningKeyID) > 128 || len(config.SigningKey) != ed25519.PrivateKeySize ||
		config.MaxArtifactBytes < 1 || config.MaxArtifactBytes > 8<<20 ||
		config.MaxChunkBytes < 1 || config.MaxChunkBytes > config.MaxArtifactBytes ||
		config.ActivationTimeout <= 0 || config.ObservationWindow < 0 ||
		config.RequiredConsecutiveSuccesses == 0 {
		return nil, ErrInvalidConfig
	}
	config.SigningKey = slices.Clone(config.SigningKey)
	return &ArtifactStore{pool: pool, cipher: cipher, config: config}, nil
}

func (s *ArtifactStore) BuildCommand(ctx context.Context, delivery acmeedge.SealedDelivery) (*agentv1.AcmeHTTP01OverlayCommand, []byte, error) {
	binding, err := s.loadBinding(ctx, delivery.DeploymentID, delivery.DeploymentAttempt)
	if err != nil {
		return nil, nil, err
	}
	if binding.delivery.NodeID != delivery.NodeID || binding.delivery.VersionID != delivery.VersionID ||
		binding.delivery.OutboxID != delivery.OutboxID || binding.delivery.PayloadSHA256 != delivery.PayloadSHA256 ||
		binding.delivery.Subject != delivery.Subject || !sameSealedTokens(binding.delivery.Tokens, delivery.Tokens) {
		return nil, nil, ErrArtifactBinding
	}
	return s.buildCommand(binding)
}

func (s *ArtifactStore) FetchChunk(ctx context.Context, request *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
	if request.GetCleanupOnly() {
		// Site-scoped 063 snapshots have no cleanup_only purpose.
		return edgeartifact.FetchResult{}, edgeartifact.ErrDeploymentIneligible
	}
	if ctx == nil || request == nil || request.Request == nil || request.Request.SentTime == nil ||
		request.Request.SentTime.CheckValid() != nil || request.Attempt == 0 {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	requestID, err := canonicalUUID(request.Request.RequestId)
	if err != nil || requestID == uuid.Nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	eventID, err := canonicalUUID(request.EventId)
	if err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	nodeID, err := canonicalUUID(request.NodeId)
	if err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	deploymentID, err := canonicalUUID(request.DeploymentId)
	if err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	artifactID, err := canonicalUUID(request.ArtifactId)
	if err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	if _, err := canonicalUUID(request.GatewayInstanceId); err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	binding, err := s.loadBinding(ctx, deploymentID, int(request.Attempt))
	if err != nil {
		if errors.Is(err, ErrArtifactBinding) {
			return edgeartifact.FetchResult{}, edgeartifact.ErrBindingConflict
		}
		if errors.Is(err, ErrArtifactIntegrity) {
			return edgeartifact.FetchResult{}, edgeartifact.ErrArtifactIntegrity
		}
		return edgeartifact.FetchResult{}, edgeartifact.ErrStorage
	}
	wantArtifactID := overlayArtifactID(binding.delivery.VersionID)
	wantEventID := overlayCommandEventID(binding.delivery.DeploymentID, binding.delivery.DeploymentAttempt)
	if binding.delivery.NodeID != nodeID || wantArtifactID != artifactID || wantEventID != eventID {
		return edgeartifact.FetchResult{}, edgeartifact.ErrBindingConflict
	}
	if !binding.deadline.After(s.config.Clock().UTC()) {
		return edgeartifact.FetchResult{}, edgeartifact.ErrDeploymentIneligible
	}
	if binding.hasNewer {
		return edgeartifact.FetchResult{}, edgeartifact.ErrDeploymentIneligible
	}
	_, wire, err := s.buildCommand(binding)
	if err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrArtifactIntegrity
	}
	defer clear(wire)
	descriptor, err := s.descriptor(binding.delivery.VersionID, wire)
	if err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrArtifactIntegrity
	}
	if request.Offset > uint64(len(wire)) {
		return edgeartifact.FetchResult{}, edgeartifact.ErrOffsetOutOfRange
	}
	if request.Offset == uint64(len(wire)) {
		return edgeartifact.FetchResult{Descriptor: descriptor, EOF: true}, nil
	}
	end := int(request.Offset) + s.config.MaxChunkBytes
	if end > len(wire) {
		end = len(wire)
	}
	data := slices.Clone(wire[int(request.Offset):end])
	digest := sha256.Sum256(data)
	return edgeartifact.FetchResult{
		Descriptor: descriptor,
		Response: &controlv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
			RequestId: requestID.String(), ArtifactId: descriptor.ArtifactId, Offset: request.Offset,
			Data: data, ChunkSha256: digest[:], TotalSizeBytes: uint64(len(wire)), EndOfArtifact: end == len(wire),
		}},
	}, nil
}

func (s *ArtifactStore) buildCommand(binding artifactBinding) (*agentv1.AcmeHTTP01OverlayCommand, []byte, error) {
	wire, err := s.buildArtifact(binding)
	if err != nil {
		return nil, nil, err
	}
	descriptor, err := s.descriptor(binding.delivery.VersionID, wire)
	if err != nil {
		clear(wire)
		return nil, nil, err
	}
	correlationID := binding.publicationID.String()
	command := &agentv1.AcmeHTTP01OverlayCommand{
		Event: &commonv1.EventMetadata{
			EventId:   overlayCommandEventID(binding.delivery.DeploymentID, binding.delivery.DeploymentAttempt).String(),
			RequestId: binding.requestID.String(), OccurredTime: timestamppb.New(binding.createdAt),
			CorrelationId: correlationID,
		},
		OverlayDeploymentId: binding.delivery.DeploymentID.String(), Attempt: uint32(binding.delivery.DeploymentAttempt),
		OverlayVersionId: binding.delivery.VersionID.String(), OverlayRevision: uint64(binding.delivery.DomainRevision),
		Artifact: descriptor,
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration:    durationpb.New(s.config.ActivationTimeout),
			ObservationWindowDuration:    durationpb.New(s.config.ObservationWindow),
			RequiredConsecutiveSuccesses: s.config.RequiredConsecutiveSuccesses,
		},
		DeadlineTime: timestamppb.New(binding.deadline),
	}
	if binding.previousID != nil {
		previousID := binding.previousID.String()
		previousRevision := uint64(binding.previousRev)
		command.PreviousOverlayVersionId = &previousID
		command.PreviousOverlayRevision = &previousRevision
	}
	return command, wire, nil
}

func (s *ArtifactStore) buildArtifact(binding artifactBinding) ([]byte, error) {
	entries := make([]snapshotEntry, 0, len(binding.delivery.Tokens))
	for _, sealed := range binding.delivery.Tokens {
		aad, err := json.Marshal(aadDocument{
			Schema: "cdnca.acme.http01-overlay-aad/v1", TenantScopeID: binding.delivery.TenantScopeID.String(),
			SiteID: binding.delivery.SiteID.String(), OperationID: sealed.OperationID,
			ChallengeAttemptID: sealed.ChallengeAttemptID.String(), TokenSHA256: fmt.Sprintf("%x", sealed.TokenSHA256[:]),
		})
		if err != nil || sha256.Sum256(aad) != sealed.AADSHA256 {
			clear(aad)
			return nil, ErrArtifactIntegrity
		}
		token, value, err := s.cipher.open(sealed, aad)
		clear(aad)
		if err != nil {
			return nil, err
		}
		if sha256.Sum256(token) != sealed.TokenSHA256 || sha256.Sum256(value) != sealed.ValueSHA256 ||
			!bytes.HasPrefix(value, append(slices.Clone(token), '.')) {
			clearBytes(token, value)
			return nil, ErrArtifactIntegrity
		}
		entries = append(entries, snapshotEntry{
			Host: sealed.Domain, Token: string(token), Value: string(value), ExpiresAt: binding.deadline,
		})
		clearBytes(token, value)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Host != entries[j].Host {
			return entries[i].Host < entries[j].Host
		}
		return entries[i].Token < entries[j].Token
	})
	for index := 1; index < len(entries); index++ {
		if entries[index-1].Host == entries[index].Host && entries[index-1].Token == entries[index].Token {
			return nil, ErrArtifactIntegrity
		}
	}
	wire, err := json.Marshal(snapshot{
		SchemaVersion: ArtifactSchemaVersion, OverlayVersionID: binding.delivery.VersionID.String(),
		OverlayRevision: uint64(binding.delivery.DomainRevision), GeneratedAt: binding.createdAt, Entries: entries,
	})
	for index := range entries {
		entries[index].Token = ""
		entries[index].Value = ""
	}
	if err != nil || len(wire) == 0 || len(wire) > s.config.MaxArtifactBytes {
		clear(wire)
		return nil, ErrArtifactIntegrity
	}
	return wire, nil
}

func (s *ArtifactStore) descriptor(versionID uuid.UUID, wire []byte) (*agentv1.ArtifactDescriptor, error) {
	if len(wire) == 0 || len(wire) > s.config.MaxArtifactBytes {
		return nil, ErrArtifactIntegrity
	}
	digest := sha256.Sum256(wire)
	signature := ed25519.Sign(s.config.SigningKey, wire)
	return &agentv1.ArtifactDescriptor{
		ArtifactId: overlayArtifactID(versionID).String(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_ACME_HTTP01_OVERLAY,
		SizeBytes: uint64(len(wire)), Sha256: digest[:], Signature: signature, SigningKeyId: s.config.SigningKeyID,
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: ArtifactMediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}, nil
}

func (s *ArtifactStore) loadBinding(ctx context.Context, deploymentID uuid.UUID, attempt int) (artifactBinding, error) {
	if ctx == nil || deploymentID == uuid.Nil || attempt < 1 {
		return artifactBinding{}, ErrArtifactBinding
	}
	var binding artifactBinding
	var payloadDigest []byte
	err := s.pool.QueryRow(ctx, `
		SELECT outbox.id,publication.mode,outbox.deployment_id,outbox.deployment_attempt,
		       version.tenant_scope_id,version.site_id,version.revision,version.id,
		       outbox.node_id,outbox.subject,outbox.payload_sha256,
		       publication.id,publication.request_id,publication.created_at,deployment.deadline_at,
		       EXISTS (
		           SELECT 1 FROM acme_http01_overlay_deployments newer
		           WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt
		       )
		FROM acme_http01_overlay_deployments deployment
		JOIN acme_http01_overlay_versions version ON version.id=deployment.version_id
		JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
		JOIN acme_http01_overlay_outbox outbox
		  ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE deployment.id=$1 AND deployment.attempt=$2`, deploymentID, attempt).Scan(
		&binding.delivery.OutboxID, &binding.delivery.Mode, &binding.delivery.DeploymentID,
		&binding.delivery.DeploymentAttempt, &binding.delivery.TenantScopeID, &binding.delivery.SiteID,
		&binding.delivery.DomainRevision, &binding.delivery.VersionID, &binding.delivery.NodeID,
		&binding.delivery.Subject, &payloadDigest, &binding.publicationID, &binding.requestID,
		&binding.createdAt, &binding.deadline, &binding.hasNewer,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return artifactBinding{}, ErrArtifactBinding
	}
	if err != nil {
		return artifactBinding{}, err
	}
	if len(payloadDigest) != sha256.Size {
		return artifactBinding{}, ErrArtifactIntegrity
	}
	copy(binding.delivery.PayloadSHA256[:], payloadDigest)
	binding.createdAt = binding.createdAt.UTC()
	binding.deadline = binding.deadline.UTC()
	tokens, err := s.loadTokens(ctx, binding.delivery.VersionID)
	if err != nil {
		return artifactBinding{}, err
	}
	binding.delivery.Tokens = tokens
	wantDigest, err := sealedDeliveryDigest(binding.delivery)
	if err != nil || wantDigest != binding.delivery.PayloadSHA256 {
		return artifactBinding{}, ErrArtifactIntegrity
	}
	if binding.delivery.DomainRevision > 1 {
		var previousID uuid.UUID
		if err := s.pool.QueryRow(ctx, `
			SELECT id FROM acme_http01_overlay_versions
			WHERE tenant_scope_id=$1 AND site_id=$2 AND revision=$3`, binding.delivery.TenantScopeID,
			binding.delivery.SiteID, binding.delivery.DomainRevision-1).Scan(&previousID); err != nil {
			return artifactBinding{}, ErrArtifactIntegrity
		}
		binding.previousID = &previousID
		binding.previousRev = binding.delivery.DomainRevision - 1
	}
	return binding, nil
}

func (s *ArtifactStore) loadTokens(ctx context.Context, versionID uuid.UUID) ([]acmeedge.SealedToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ordinal,operation_id,challenge_attempt_id,domain,token_sha256,value_sha256,
		       key_id,nonce,ciphertext,aad_sha256
		FROM acme_http01_overlay_token_facts WHERE version_id=$1 ORDER BY ordinal`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []acmeedge.SealedToken
	for rows.Next() {
		var token acmeedge.SealedToken
		var tokenDigest, valueDigest, aadDigest []byte
		if err := rows.Scan(&token.Ordinal, &token.OperationID, &token.ChallengeAttemptID, &token.Domain,
			&tokenDigest, &valueDigest, &token.KeyID, &token.Nonce, &token.Ciphertext, &aadDigest); err != nil {
			return nil, err
		}
		if len(tokenDigest) != sha256.Size || len(valueDigest) != sha256.Size || len(aadDigest) != sha256.Size {
			return nil, ErrArtifactIntegrity
		}
		copy(token.TokenSHA256[:], tokenDigest)
		copy(token.ValueSHA256[:], valueDigest)
		copy(token.AADSHA256[:], aadDigest)
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

func sealedDeliveryDigest(delivery acmeedge.SealedDelivery) ([32]byte, error) {
	document := struct {
		Schema            string                 `json:"schema"`
		Mode              string                 `json:"mode"`
		TenantScopeID     uuid.UUID              `json:"tenant_scope_id"`
		SiteID            uuid.UUID              `json:"site_id"`
		Revision          int64                  `json:"revision"`
		VersionID         uuid.UUID              `json:"version_id"`
		DeploymentID      uuid.UUID              `json:"deployment_id"`
		DeploymentAttempt int                    `json:"deployment_attempt"`
		NodeID            uuid.UUID              `json:"node_id"`
		Tokens            []acmeedge.SealedToken `json:"tokens"`
	}{
		Schema: "cdnca.acme.http01-overlay-delivery/v1", Mode: delivery.Mode,
		TenantScopeID: delivery.TenantScopeID, SiteID: delivery.SiteID, Revision: delivery.DomainRevision,
		VersionID: delivery.VersionID, DeploymentID: delivery.DeploymentID,
		DeploymentAttempt: delivery.DeploymentAttempt, NodeID: delivery.NodeID, Tokens: delivery.Tokens,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(encoded)
	return sha256.Sum256(encoded), nil
}

func sameSealedTokens(left, right []acmeedge.SealedToken) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Ordinal != right[index].Ordinal || left[index].OperationID != right[index].OperationID ||
			left[index].ChallengeAttemptID != right[index].ChallengeAttemptID || left[index].Domain != right[index].Domain ||
			left[index].TokenSHA256 != right[index].TokenSHA256 || left[index].ValueSHA256 != right[index].ValueSHA256 ||
			left[index].KeyID != right[index].KeyID || !bytes.Equal(left[index].Nonce, right[index].Nonce) ||
			!bytes.Equal(left[index].Ciphertext, right[index].Ciphertext) || left[index].AADSHA256 != right[index].AADSHA256 {
			return false
		}
	}
	return true
}

func overlayArtifactID(versionID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(versionID, []byte("acme-http01-overlay/artifact"))
}

func overlayCommandEventID(deploymentID uuid.UUID, attempt int) uuid.UUID {
	return uuid.NewSHA1(deploymentID, []byte(fmt.Sprintf("acme-http01-overlay/command/%d", attempt)))
}

func canonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, ErrArtifactBinding
	}
	return parsed, nil
}

type CompositeStore struct {
	ordinary FetchStore
	overlay  FetchStore
}

func NewCompositeStore(ordinary, overlay FetchStore) (*CompositeStore, error) {
	if ordinary == nil || overlay == nil {
		return nil, ErrInvalidConfig
	}
	return &CompositeStore{ordinary: ordinary, overlay: overlay}, nil
}

func (s *CompositeStore) FetchChunk(ctx context.Context, request *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
	if request.GetCleanupOnly() {
		// A session without deployments may only fetch a CLEANUP_ONLY overlay.
		return s.overlay.FetchChunk(ctx, request)
	}
	result, err := s.ordinary.FetchChunk(ctx, request)
	if !errors.Is(err, edgeartifact.ErrBindingConflict) {
		return result, err
	}
	return s.overlay.FetchChunk(ctx, request)
}
