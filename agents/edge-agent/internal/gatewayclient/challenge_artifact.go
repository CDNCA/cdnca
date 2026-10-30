package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func fetchChallengeArtifact(ctx context.Context, client agentv1.AgentGatewayServiceClient, store *durableStore, record *durableRecord, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, maximumChunkBytes uint32, config Config, trust *TrustStore, now func() time.Time) ([]byte, challenge.ArtifactBinding, error) {
	file, err := store.openArtifact(record.RecordKey, record.ArtifactOffset)
	if err != nil {
		return nil, challenge.ArtifactBinding{}, err
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
			return nil, challenge.ArtifactBinding{}, err
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
				return nil, challenge.ArtifactBinding{}, receiveErr
			}
			chunk := response.GetChunk()
			if err := validateArtifactChunk(chunk, requestID, descriptor, offset, maximumChunkBytes); err != nil {
				cancel()
				return nil, challenge.ArtifactBinding{}, err
			}
			written, err := file.Write(chunk.Data)
			if err != nil || written != len(chunk.Data) {
				cancel()
				return nil, challenge.ArtifactBinding{}, fmt.Errorf("write challenge ciphertext: %w", err)
			}
			if err := file.Sync(); err != nil {
				cancel()
				return nil, challenge.ArtifactBinding{}, fmt.Errorf("sync challenge ciphertext: %w", err)
			}
			offset += uint64(len(chunk.Data))
			if err := store.setArtifactOffset(record.RecordKey, offset); err != nil {
				cancel()
				return nil, challenge.ArtifactBinding{}, err
			}
			if chunk.EndOfArtifact {
				ended = true
				break
			}
		}
		cancel()
		if ended {
			if offset != descriptor.SizeBytes {
				return nil, challenge.ArtifactBinding{}, fmt.Errorf("%w: challenge artifact ended at an unexpected offset", ErrArtifactIntegrity)
			}
			break
		}
		if offset == startOffset {
			return nil, challenge.ArtifactBinding{}, errors.New("challenge artifact stream ended without progress")
		}
	}
	if err := file.Close(); err != nil {
		return nil, challenge.ArtifactBinding{}, fmt.Errorf("close challenge ciphertext: %w", err)
	}
	wireBytes, err := store.readArtifact(record.RecordKey, descriptor.SizeBytes)
	if err != nil {
		return nil, challenge.ArtifactBinding{}, err
	}
	digest := sha256.Sum256(wireBytes)
	if !bytes.Equal(digest[:], descriptor.Sha256) {
		return nil, challenge.ArtifactBinding{}, fmt.Errorf("%w: challenge artifact digest mismatch", ErrArtifactIntegrity)
	}
	if err := verifyArtifactSignature(descriptor, wireBytes, trust); err != nil {
		return nil, challenge.ArtifactBinding{}, err
	}
	plaintext, err := decryptArtifactHPKE(command, descriptor, wireBytes, config.ArtifactDecryptionPrivateKey)
	if err != nil {
		return nil, challenge.ArtifactBinding{}, err
	}
	defer clearPlaintext(plaintext)
	limit := config.MaxDecompressedBytes
	if limit > challenge.MaxArtifactBytes {
		limit = challenge.MaxArtifactBytes
	}
	decoded, err := decompressArtifact(descriptor.Compression, plaintext, limit)
	if err != nil {
		return nil, challenge.ArtifactBinding{}, err
	}
	document, err := decodeChallengeArtifact(decoded)
	if err != nil {
		clearPlaintext(decoded)
		return nil, challenge.ArtifactBinding{}, err
	}
	binding := challenge.ArtifactBinding{
		EventID: command.Event.EventId, DeploymentID: command.DeploymentId, Attempt: command.Attempt,
		ConfigVersionID: command.ConfigVersionId, ArtifactID: descriptor.ArtifactId, RecipientKeyID: descriptor.GetRecipientKeyId(),
		PolicyID: document.Activation.PolicyID, TenantID: document.Activation.TenantID, PolicyVersion: document.Activation.PolicyVersion,
	}
	if document.Activation.EventID != binding.EventID || document.Activation.DeploymentID != binding.DeploymentID ||
		document.Activation.Attempt != binding.Attempt || document.Activation.ConfigVersionID != binding.ConfigVersionID ||
		document.Activation.ArtifactID != binding.ArtifactID || document.Activation.RecipientKeyID != binding.RecipientKeyID {
		clearPlaintext(decoded)
		return nil, challenge.ArtifactBinding{}, ErrInvalidChallengeArtifact
	}
	clearChallengeDocument(&document)
	return decoded, binding, nil
}

func decodeChallengeArtifact(content []byte) (challenge.ArtifactDocument, error) {
	if len(content) == 0 || len(content) > challenge.MaxArtifactBytes || rejectDuplicateJSONKeys(content) != nil {
		return challenge.ArtifactDocument{}, ErrInvalidChallengeArtifact
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document challenge.ArtifactDocument
	if err := decoder.Decode(&document); err != nil {
		return challenge.ArtifactDocument{}, ErrInvalidChallengeArtifact
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		clearChallengeDocument(&document)
		return challenge.ArtifactDocument{}, ErrInvalidChallengeArtifact
	}
	return document, nil
}

func clearChallengeDocument(document *challenge.ArtifactDocument) {
	for index := range document.Keys {
		clearPlaintext(document.Keys[index].Secret)
	}
	document.Keys = nil
}
