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

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxCertificateArtifactPlaintextBytes = certstore.MaxBundleBytes + 64<<10

type certificateArtifactDocument struct {
	SchemaVersion string                       `json:"schema_version"`
	Activation    certstore.ActivationMetadata `json:"activation"`
	Bundle        certstore.Bundle             `json:"bundle"`
}

func fetchCertificateArtifact(ctx context.Context, client agentv1.AgentGatewayServiceClient, store *durableStore, record *durableRecord, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, maximumChunkBytes uint32, config Config, trust *TrustStore, now func() time.Time) (certificateArtifactDocument, error) {
	file, err := store.openArtifact(record.RecordKey, record.ArtifactOffset)
	if err != nil {
		return certificateArtifactDocument{}, err
	}
	defer file.Close()
	offset := record.ArtifactOffset
	for offset < descriptor.SizeBytes {
		requestID := uuid.NewString()
		fetchCtx, cancel := context.WithTimeout(ctx, config.FetchTimeout)
		stream, err := client.FetchArtifact(fetchCtx, &agentv1.FetchArtifactRequest{
			Request: &commonv1.RequestMetadata{
				RequestId: requestID, SentTime: timestamppb.New(now().UTC()),
				Traceparent: command.Event.Traceparent, CorrelationId: command.Event.CorrelationId, TaskId: command.Event.TaskId,
			},
			EventId: command.Event.EventId, DeploymentId: command.DeploymentId, Attempt: command.Attempt,
			ArtifactId: descriptor.ArtifactId, Offset: offset,
		})
		if err != nil {
			cancel()
			return certificateArtifactDocument{}, err
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
				return certificateArtifactDocument{}, receiveErr
			}
			chunk := response.GetChunk()
			if err := validateArtifactChunk(chunk, requestID, descriptor, offset, maximumChunkBytes); err != nil {
				cancel()
				return certificateArtifactDocument{}, err
			}
			written, err := file.Write(chunk.Data)
			if err != nil {
				cancel()
				return certificateArtifactDocument{}, fmt.Errorf("write certificate ciphertext: %w", err)
			}
			if written != len(chunk.Data) {
				cancel()
				return certificateArtifactDocument{}, fmt.Errorf("write certificate ciphertext: %w", io.ErrShortWrite)
			}
			if err := file.Sync(); err != nil {
				cancel()
				return certificateArtifactDocument{}, fmt.Errorf("sync certificate ciphertext: %w", err)
			}
			offset += uint64(len(chunk.Data))
			if err := store.setArtifactOffset(record.RecordKey, offset); err != nil {
				cancel()
				return certificateArtifactDocument{}, err
			}
			if chunk.EndOfArtifact {
				ended = true
				break
			}
		}
		cancel()
		if ended {
			if offset != descriptor.SizeBytes {
				return certificateArtifactDocument{}, fmt.Errorf("%w: certificate artifact ended at an unexpected offset", ErrArtifactIntegrity)
			}
			break
		}
		if offset == startOffset {
			return certificateArtifactDocument{}, fmt.Errorf("certificate artifact stream ended without progress")
		}
	}
	if err := file.Close(); err != nil {
		return certificateArtifactDocument{}, fmt.Errorf("close certificate ciphertext: %w", err)
	}
	wireBytes, err := store.readArtifact(record.RecordKey, descriptor.SizeBytes)
	if err != nil {
		return certificateArtifactDocument{}, err
	}
	digest := sha256.Sum256(wireBytes)
	if !bytes.Equal(digest[:], descriptor.Sha256) {
		return certificateArtifactDocument{}, fmt.Errorf("%w: certificate artifact digest mismatch", ErrArtifactIntegrity)
	}
	if err := verifyArtifactSignature(descriptor, wireBytes, trust); err != nil {
		return certificateArtifactDocument{}, err
	}
	plaintext, err := decryptArtifactHPKE(command, descriptor, wireBytes, config.ArtifactDecryptionPrivateKey)
	if err != nil {
		return certificateArtifactDocument{}, err
	}
	defer clearPlaintext(plaintext)
	plaintextLimit := config.MaxDecompressedBytes
	if plaintextLimit > maxCertificateArtifactPlaintextBytes {
		plaintextLimit = maxCertificateArtifactPlaintextBytes
	}
	decoded, err := decompressArtifact(descriptor.Compression, plaintext, plaintextLimit)
	if err != nil {
		return certificateArtifactDocument{}, err
	}
	defer clearPlaintext(decoded)
	document, err := decodeCertificateArtifact(decoded)
	if err != nil {
		return certificateArtifactDocument{}, err
	}
	if err := validateCertificateBinding(document, command, descriptor); err != nil {
		clearCertificateDocument(&document)
		return certificateArtifactDocument{}, err
	}
	return document, nil
}

func decodeCertificateArtifact(content []byte) (certificateArtifactDocument, error) {
	if len(content) == 0 || len(content) > maxCertificateArtifactPlaintextBytes {
		return certificateArtifactDocument{}, ErrInvalidCertificateArtifact
	}
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return certificateArtifactDocument{}, ErrInvalidCertificateArtifact
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document certificateArtifactDocument
	if err := decoder.Decode(&document); err != nil {
		return certificateArtifactDocument{}, ErrInvalidCertificateArtifact
	}
	if err := requireCertificateJSONEOF(decoder); err != nil {
		return certificateArtifactDocument{}, ErrInvalidCertificateArtifact
	}
	return document, nil
}

func requireCertificateJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidCertificateArtifact
	}
	return nil
}
