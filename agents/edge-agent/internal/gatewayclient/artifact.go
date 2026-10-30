package gatewayclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type configurationBundleDocument = edgeconfig.BundleDocument

// fetchDurableArtifactWire transfers an artifact into the record's durable
// artifact file (resuming at the persisted offset) and returns its wire bytes
// once the size, digest and signature are verified.
func fetchDurableArtifactWire(ctx context.Context, client agentv1.AgentGatewayServiceClient, store *durableStore, record *durableRecord, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, maximumChunkBytes uint32, config Config, trust *TrustStore, now func() time.Time) ([]byte, error) {
	file, err := store.openArtifact(record.RecordKey, record.ArtifactOffset)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = transferArtifact(ctx, client, command, descriptor, record.ArtifactOffset, maximumChunkBytes, config, now, func(data []byte, next uint64) error {
		written, err := file.Write(data)
		if err != nil {
			return fmt.Errorf("write artifact part: %w", err)
		}
		if written != len(data) {
			return fmt.Errorf("write artifact part: %w", io.ErrShortWrite)
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync artifact part: %w", err)
		}
		return store.setArtifactOffset(record.RecordKey, next)
	})
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close artifact part: %w", err)
	}
	wireBytes, err := store.readArtifact(record.RecordKey, descriptor.SizeBytes)
	if err != nil {
		return nil, fmt.Errorf("read completed artifact: %w", err)
	}
	if err := verifyArtifactWire(descriptor, wireBytes, trust); err != nil {
		return nil, err
	}
	return wireBytes, nil
}

// fetchArtifactWire transfers a small artifact into memory and verifies it.
func fetchArtifactWire(ctx context.Context, client agentv1.AgentGatewayServiceClient, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, maximumChunkBytes uint32, config Config, trust *TrustStore, now func() time.Time) ([]byte, error) {
	wireBytes := make([]byte, 0, descriptor.SizeBytes)
	err := transferArtifact(ctx, client, command, descriptor, 0, maximumChunkBytes, config, now, func(data []byte, _ uint64) error {
		wireBytes = append(wireBytes, data...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := verifyArtifactWire(descriptor, wireBytes, trust); err != nil {
		return nil, err
	}
	return wireBytes, nil
}

func verifyArtifactWire(descriptor *agentv1.ArtifactDescriptor, wireBytes []byte, trust *TrustStore) error {
	if uint64(len(wireBytes)) != descriptor.SizeBytes {
		return fmt.Errorf("%w: artifact size mismatch", ErrArtifactIntegrity)
	}
	digest := sha256.Sum256(wireBytes)
	if !bytes.Equal(digest[:], descriptor.Sha256) {
		return fmt.Errorf("%w: artifact digest mismatch", ErrArtifactIntegrity)
	}
	return verifyArtifactSignature(descriptor, wireBytes, trust)
}

// transferArtifact streams descriptor from offset to its end, handing each
// verified chunk and the offset after it to write, with a new request per
// resumed range.
func transferArtifact(ctx context.Context, client agentv1.AgentGatewayServiceClient, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, offset uint64, maximumChunkBytes uint32, config Config, now func() time.Time, write func(data []byte, next uint64) error) error {
	for offset < descriptor.SizeBytes {
		requestID := uuid.NewString()
		fetchCtx, cancel := context.WithTimeout(ctx, config.FetchTimeout)
		stream, err := client.FetchArtifact(fetchCtx, &agentv1.FetchArtifactRequest{
			Request: &commonv1.RequestMetadata{
				RequestId:     requestID,
				SentTime:      timestamppb.New(now().UTC()),
				Traceparent:   command.Event.Traceparent,
				CorrelationId: command.Event.CorrelationId,
				TaskId:        command.Event.TaskId,
			},
			EventId:      command.Event.EventId,
			DeploymentId: command.DeploymentId,
			Attempt:      command.Attempt,
			ArtifactId:   descriptor.ArtifactId,
			Offset:       offset,
		})
		if err != nil {
			cancel()
			return err
		}
		startOffset := offset
		ended := false
		for {
			response, receiveErr := stream.Recv()
			if errors.Is(receiveErr, io.EOF) {
				break
			}
			if receiveErr != nil {
				cancel()
				return receiveErr
			}
			chunk := response.GetChunk()
			if err := validateArtifactChunk(chunk, requestID, descriptor, offset, maximumChunkBytes); err != nil {
				cancel()
				return err
			}
			offset += uint64(len(chunk.Data))
			if err := write(chunk.Data, offset); err != nil {
				cancel()
				return err
			}
			if chunk.EndOfArtifact {
				ended = true
				break
			}
		}
		cancel()
		if ended {
			if offset != descriptor.SizeBytes {
				return fmt.Errorf("%w: artifact ended at an unexpected offset", ErrArtifactIntegrity)
			}
			break
		}
		if offset == startOffset {
			return fmt.Errorf("artifact stream ended without progress")
		}
	}
	return nil
}

func validateArtifactChunk(chunk *agentv1.ArtifactChunk, requestID string, descriptor *agentv1.ArtifactDescriptor, offset uint64, maximumChunkBytes uint32) error {
	if chunk == nil || chunk.RequestId != requestID || chunk.ArtifactId != descriptor.ArtifactId || chunk.Offset != offset || chunk.TotalSizeBytes != descriptor.SizeBytes || len(chunk.Data) == 0 || uint32(len(chunk.Data)) > maximumChunkBytes || uint64(len(chunk.Data)) > descriptor.SizeBytes-offset || len(chunk.ChunkSha256) != sha256.Size {
		return fmt.Errorf("%w: artifact chunk metadata is invalid", ErrArtifactIntegrity)
	}
	digest := sha256.Sum256(chunk.Data)
	if !bytes.Equal(digest[:], chunk.ChunkSha256) {
		return fmt.Errorf("%w: artifact chunk digest mismatch", ErrArtifactIntegrity)
	}
	if chunk.EndOfArtifact != (offset+uint64(len(chunk.Data)) == descriptor.SizeBytes) {
		return fmt.Errorf("%w: artifact terminal chunk is inconsistent", ErrArtifactIntegrity)
	}
	return nil
}

func verifyArtifactSignature(descriptor *agentv1.ArtifactDescriptor, wireBytes []byte, trust *TrustStore) error {
	publicKey, exists := trust.key(descriptor.SigningKeyId)
	if !exists {
		return fmt.Errorf("%w: artifact signing key is not trusted", ErrArtifactIntegrity)
	}
	switch descriptor.SignatureAlgorithm {
	case agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519:
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(key, wireBytes, descriptor.Signature) {
			return fmt.Errorf("%w: Ed25519 signature mismatch", ErrArtifactIntegrity)
		}
	case agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256:
		key, ok := publicKey.(*ecdsa.PublicKey)
		digest := sha256.Sum256(wireBytes)
		if !ok || key.Curve.Params().Name != "P-256" || !ecdsa.VerifyASN1(key, digest[:], descriptor.Signature) {
			return fmt.Errorf("%w: ECDSA signature mismatch", ErrArtifactIntegrity)
		}
	default:
		return fmt.Errorf("%w: unsupported signature algorithm", ErrArtifactIntegrity)
	}
	return nil
}

func decompressArtifact(compression agentv1.ArtifactCompression, wireBytes []byte, limit int64) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(wireBytes)
	if compression == agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD {
		decoderMemoryLimit := uint64(limit)
		if decoderMemoryLimit < 1<<20 {
			decoderMemoryLimit = 1 << 20
		}
		decoder, err := zstd.NewReader(bytes.NewReader(wireBytes), zstd.WithDecoderMaxMemory(decoderMemoryLimit))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid zstd artifact", ErrArtifactIntegrity)
		}
		defer decoder.Close()
		reader = decoder
	} else if compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE {
		return nil, fmt.Errorf("%w: unsupported artifact compression", ErrArtifactIntegrity)
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: artifact decompression failed", ErrArtifactIntegrity)
	}
	if int64(len(decoded)) > limit {
		return nil, fmt.Errorf("%w: decompressed artifact exceeds its limit", ErrArtifactIntegrity)
	}
	return decoded, nil
}

func decodeConfigurationBundle(content []byte) (deployment.Bundle, error) {
	bundle, err := edgeconfig.UnmarshalBundle(content)
	if err != nil {
		return deployment.Bundle{}, fmt.Errorf("%w: %v", ErrArtifactIntegrity, err)
	}
	return bundle, nil
}

func rejectDuplicateJSONKeys(content []byte) error {
	return edgeconfig.RejectDuplicateJSONKeys(content)
}
