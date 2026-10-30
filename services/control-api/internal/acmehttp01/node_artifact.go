package acmehttp01

import (
	"context"
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
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NodeArtifactSigner signs overlay snapshots with a key the agents trust
// (the edge publication signing key).
type NodeArtifactSigner interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

type NodeArtifactConfig struct {
	MaxArtifactBytes             int
	MaxChunkBytes                int
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	RequiredConsecutiveSuccesses uint32
	Clock                        func() time.Time
}

func DefaultNodeArtifactConfig() NodeArtifactConfig {
	defaults := DefaultArtifactConfig()
	return NodeArtifactConfig{
		MaxArtifactBytes: defaults.MaxArtifactBytes, MaxChunkBytes: defaults.MaxChunkBytes,
		ActivationTimeout: defaults.ActivationTimeout, ObservationWindow: defaults.ObservationWindow,
		RequiredConsecutiveSuccesses: defaults.RequiredConsecutiveSuccesses, Clock: time.Now,
	}
}

// NodeArtifactStore builds the signed overlay command and artifact of a node
// generation delivery and serves its chunks to the gateway.
type NodeArtifactStore struct {
	store  *NodeStore
	signer NodeArtifactSigner
	config NodeArtifactConfig
}

func NewNodeArtifactStore(store *NodeStore, signer NodeArtifactSigner, config NodeArtifactConfig) (*NodeArtifactStore, error) {
	if store == nil || signer == nil || signer.KeyID() == "" || len(signer.KeyID()) > 128 || config.Clock == nil ||
		config.MaxArtifactBytes < 1 || config.MaxArtifactBytes > 8<<20 || config.MaxChunkBytes < 1 ||
		config.MaxChunkBytes > config.MaxArtifactBytes || config.ActivationTimeout <= 0 ||
		config.ObservationWindow < 0 || config.RequiredConsecutiveSuccesses == 0 {
		return nil, ErrInvalidConfig
	}
	return &NodeArtifactStore{store: store, signer: signer, config: config}, nil
}

func nodeCommandEventID(generationID uuid.UUID, attempt int) uuid.UUID {
	return uuid.NewSHA1(generationID, []byte(fmt.Sprintf("acme-http01-node/command/%d", attempt)))
}

func nodeRequestID(generationID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(generationID, []byte("acme-http01-node/request"))
}

// BuildCommand is the command for one claimed delivery attempt.
func (s *NodeArtifactStore) BuildCommand(ctx context.Context, delivery NodeDelivery) (*agentv1.AcmeHTTP01OverlayCommand, error) {
	binding, err := s.store.loadDeliveryBinding(ctx, delivery.GenerationID, delivery.Attempt)
	if err != nil {
		return nil, err
	}
	if binding.NodeID != delivery.NodeID || binding.Generation != delivery.Generation {
		return nil, ErrArtifactBinding
	}
	wire, descriptor, err := s.artifact(ctx, binding)
	if err != nil {
		return nil, err
	}
	clear(wire)
	purpose := agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_APPLY
	if binding.Purpose == snapshotPurposeCleanupOnly {
		purpose = agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_CLEANUP_ONLY
	}
	return &agentv1.AcmeHTTP01OverlayCommand{
		Event: &commonv1.EventMetadata{
			EventId:   nodeCommandEventID(binding.GenerationID, binding.Attempt).String(),
			RequestId: nodeRequestID(binding.GenerationID).String(), OccurredTime: timestamppb.New(binding.CreatedAt),
			CorrelationId: binding.GenerationID.String(),
		},
		OverlayDeploymentId: binding.GenerationID.String(), Attempt: uint32(binding.Attempt),
		OverlayVersionId: binding.GenerationID.String(), OverlayRevision: uint64(binding.Generation),
		Artifact: descriptor,
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration:    durationpb.New(s.config.ActivationTimeout),
			ObservationWindowDuration:    durationpb.New(s.config.ObservationWindow),
			RequiredConsecutiveSuccesses: s.config.RequiredConsecutiveSuccesses,
		},
		DeadlineTime: timestamppb.New(binding.Deadline),
		Purpose:      purpose,
	}, nil
}

// artifact is the snapshot (entries sorted as the agent requires) and its
// signed descriptor. Ed25519 is deterministic: the command and every fetched
// chunk carry the same bytes. A cleanup_only generation names its purpose in
// the signed bytes, so the command's purpose cannot be changed in transit.
func (s *NodeArtifactStore) artifact(ctx context.Context, binding nodeDeliveryBinding) ([]byte, *agentv1.ArtifactDescriptor, error) {
	entries := slices.Clone(binding.Entries)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Host != entries[j].Host {
			return entries[i].Host < entries[j].Host
		}
		return entries[i].Token < entries[j].Token
	})
	for index := 1; index < len(entries); index++ {
		if entries[index-1].Host == entries[index].Host && entries[index-1].Token == entries[index].Token {
			return nil, nil, ErrArtifactIntegrity
		}
	}
	if entries == nil {
		entries = []snapshotEntry{}
	}
	document := snapshot{
		SchemaVersion: ArtifactSchemaVersion, OverlayVersionID: binding.GenerationID.String(),
		OverlayRevision: uint64(binding.Generation), GeneratedAt: binding.CreatedAt, Entries: entries,
	}
	if binding.Purpose == snapshotPurposeCleanupOnly {
		document.Purpose = snapshotPurposeCleanupOnly
	}
	wire, err := json.Marshal(document)
	if err != nil || len(wire) == 0 || len(wire) > s.config.MaxArtifactBytes {
		clear(wire)
		return nil, nil, ErrArtifactIntegrity
	}
	signature, err := s.signer.Sign(ctx, wire)
	if err != nil || len(signature) == 0 {
		clear(wire)
		return nil, nil, ErrArtifactIntegrity
	}
	digest := sha256.Sum256(wire)
	return wire, &agentv1.ArtifactDescriptor{
		ArtifactId: overlayArtifactID(binding.GenerationID).String(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_ACME_HTTP01_OVERLAY,
		SizeBytes: uint64(len(wire)), Sha256: digest[:], Signature: signature, SigningKeyId: s.signer.KeyID(),
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: ArtifactMediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}, nil
}

// FetchChunk serves the artifact of the newest attempt of the node's current
// generation before its deadline.
func (s *NodeArtifactStore) FetchChunk(ctx context.Context, request *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
	if ctx == nil || request == nil || request.Request == nil || request.Request.SentTime == nil ||
		request.Request.SentTime.CheckValid() != nil || request.Attempt == 0 || request.Attempt > 1000 {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	requestID, err := canonicalUUID(request.Request.RequestId)
	if err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	var ids [4]uuid.UUID
	for index, value := range []string{request.EventId, request.NodeId, request.DeploymentId, request.ArtifactId} {
		if ids[index], err = canonicalUUID(value); err != nil {
			return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
		}
	}
	if _, err := canonicalUUID(request.GatewayInstanceId); err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrInvalidRequest
	}
	eventID, nodeID, generationID, artifactID := ids[0], ids[1], ids[2], ids[3]
	binding, err := s.store.loadDeliveryBinding(ctx, generationID, int(request.Attempt))
	if err != nil {
		switch {
		case errors.Is(err, ErrArtifactBinding):
			return edgeartifact.FetchResult{}, edgeartifact.ErrBindingConflict
		case errors.Is(err, ErrArtifactIntegrity):
			return edgeartifact.FetchResult{}, edgeartifact.ErrArtifactIntegrity
		}
		return edgeartifact.FetchResult{}, edgeartifact.ErrStorage
	}
	if binding.NodeID != nodeID || overlayArtifactID(binding.GenerationID) != artifactID ||
		nodeCommandEventID(binding.GenerationID, binding.Attempt) != eventID {
		return edgeartifact.FetchResult{}, edgeartifact.ErrBindingConflict
	}
	// A session without deployments (cleanup_only fetch) gets only a
	// cleanup_only generation; the purpose comes from the generation.
	if binding.NewerAttempt || binding.NotCurrent || !binding.Deadline.After(s.config.Clock().UTC()) ||
		binding.State == "superseded" || binding.State == "failed" || binding.State == "timed_out" ||
		request.CleanupOnly && binding.Purpose != snapshotPurposeCleanupOnly {
		return edgeartifact.FetchResult{}, edgeartifact.ErrDeploymentIneligible
	}
	wire, descriptor, err := s.artifact(ctx, binding)
	if err != nil {
		return edgeartifact.FetchResult{}, edgeartifact.ErrArtifactIntegrity
	}
	defer clear(wire)
	if request.Offset > uint64(len(wire)) {
		return edgeartifact.FetchResult{}, edgeartifact.ErrOffsetOutOfRange
	}
	if request.Offset == uint64(len(wire)) {
		return edgeartifact.FetchResult{Descriptor: descriptor, EOF: true}, nil
	}
	end := min(int(request.Offset)+s.config.MaxChunkBytes, len(wire))
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
