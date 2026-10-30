package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/urlauth"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func fetchURLAuthArtifact(ctx context.Context, client agentv1.AgentGatewayServiceClient, store *durableStore, record *durableRecord, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, maximumChunkBytes uint32, config Config, trust *TrustStore, now func() time.Time) ([]byte, error) {
	wireBytes, err := fetchSignedArtifact(ctx, client, store, record, command, descriptor, maximumChunkBytes, config, trust, now)
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptArtifactHPKE(command, descriptor, wireBytes, config.ArtifactDecryptionPrivateKey)
	if err != nil {
		return nil, err
	}
	defer clearPlaintext(plaintext)
	limit := config.MaxDecompressedBytes
	if limit > urlauth.MaxArtifactBytes {
		limit = urlauth.MaxArtifactBytes
	}
	decoded, err := decompressArtifact(descriptor.Compression, plaintext, limit)
	if err != nil {
		return nil, err
	}
	if _, err := urlauth.DecodeArtifactBinding(decoded); err != nil {
		clearPlaintext(decoded)
		return nil, fmt.Errorf("%w: URL auth artifact was rejected", ErrInvalidURLAuthArtifact)
	}
	return decoded, nil
}

// fetchSignedArtifact resumably downloads a node secret artifact and returns
// its wire bytes after the digest and signature checks.
func fetchSignedArtifact(ctx context.Context, client agentv1.AgentGatewayServiceClient, store *durableStore, record *durableRecord, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, maximumChunkBytes uint32, config Config, trust *TrustStore, now func() time.Time) ([]byte, error) {
	file, err := store.openArtifact(record.RecordKey, record.ArtifactOffset)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	offset := record.ArtifactOffset
	for offset < descriptor.SizeBytes {
		requestID := uuid.NewString()
		fetchCtx, cancel := context.WithTimeout(ctx, config.FetchTimeout)
		stream, err := client.FetchArtifact(fetchCtx, &agentv1.FetchArtifactRequest{
			Request: &commonv1.RequestMetadata{
				RequestId: requestID, SentTime: timestamppb.New(now().UTC()), Traceparent: command.Event.Traceparent,
				CorrelationId: command.Event.CorrelationId, TaskId: command.Event.TaskId,
			},
			EventId: command.Event.EventId, DeploymentId: command.DeploymentId, Attempt: command.Attempt,
			ArtifactId: descriptor.ArtifactId, Offset: offset,
		})
		if err != nil {
			cancel()
			return nil, err
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
				return nil, receiveErr
			}
			chunk := response.GetChunk()
			if err := validateArtifactChunk(chunk, requestID, descriptor, offset, maximumChunkBytes); err != nil {
				cancel()
				return nil, err
			}
			written, err := file.Write(chunk.Data)
			if err != nil {
				cancel()
				return nil, fmt.Errorf("write artifact ciphertext: %w", err)
			}
			if written != len(chunk.Data) {
				cancel()
				return nil, fmt.Errorf("write artifact ciphertext: %w", io.ErrShortWrite)
			}
			if err := file.Sync(); err != nil {
				cancel()
				return nil, fmt.Errorf("sync artifact ciphertext: %w", err)
			}
			offset += uint64(len(chunk.Data))
			if err := store.setArtifactOffset(record.RecordKey, offset); err != nil {
				cancel()
				return nil, err
			}
			if chunk.EndOfArtifact {
				ended = true
				break
			}
		}
		cancel()
		if ended {
			if offset != descriptor.SizeBytes {
				return nil, fmt.Errorf("%w: artifact ended at an unexpected offset", ErrArtifactIntegrity)
			}
			break
		}
		if offset == startOffset {
			return nil, errors.New("artifact stream ended without progress")
		}
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close artifact ciphertext: %w", err)
	}
	wireBytes, err := store.readArtifact(record.RecordKey, descriptor.SizeBytes)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(wireBytes)
	if !bytes.Equal(digest[:], descriptor.Sha256) {
		return nil, fmt.Errorf("%w: artifact digest mismatch", ErrArtifactIntegrity)
	}
	if err := verifyArtifactSignature(descriptor, wireBytes, trust); err != nil {
		return nil, err
	}
	return wireBytes, nil
}
