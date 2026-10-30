package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type telemetryService struct {
	config    TelemetryConfig
	publisher TelemetryPublisher
	sessions  SessionCoordinator
	health    *TelemetryHealth
}

func (g *Gateway) ConfigureTelemetry(
	config TelemetryConfig,
	publisher TelemetryPublisher,
	sessions SessionCoordinator,
	health *TelemetryHealth,
) error {
	if g == nil {
		return fmt.Errorf("gateway service is required")
	}
	if err := config.validate(); err != nil {
		return err
	}
	if publisher == nil || sessions == nil || health == nil {
		return fmt.Errorf("telemetry publisher, session coordinator, and health are required")
	}
	if g.telemetry != nil {
		return fmt.Errorf("telemetry is already configured")
	}
	g.telemetry = &telemetryService{config: config, publisher: publisher, sessions: sessions, health: health}
	return nil
}

func (g *Gateway) StreamTelemetry(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
	if g == nil || g.telemetry == nil {
		return status.Error(codes.Unavailable, "telemetry transport is unavailable")
	}
	identity, err := authenticatedNode(stream.Context())
	if err != nil {
		return err
	}
	if err := validateTelemetryCertificate(stream.Context(), g.now()); err != nil {
		return err
	}
	received := pumpTelemetryRequests(stream)
	first, err := receiveTelemetryWithTimeout(stream.Context(), received, g.config.HandshakeTimeout)
	if err != nil {
		return err
	}
	if first.request == nil || first.request.GetHello() == nil {
		return status.Error(codes.FailedPrecondition, "TelemetryClientHello must be the first stream payload")
	}
	if err := g.validateStreamMetadata(first.request.Stream); err != nil || first.request.Stream.Sequence != 1 {
		return status.Error(codes.InvalidArgument, "first telemetry stream metadata is invalid")
	}
	hello := first.request.GetHello()
	if validateVersionRange(hello.SupportedProtocolVersions) != nil || !canonicalUUID(hello.BootId) ||
		hello.LastDurableAcknowledgedSequence == ^uint64(0) ||
		hello.GetLastDurableConnectionsAcknowledgedSequence() == ^uint64(0) {
		return status.Error(codes.InvalidArgument, "telemetry client hello is invalid")
	}
	controlAuthorization, authorization, err := g.authorizeTelemetry(stream.Context(), identity, hello.ScopedRecords)
	if err != nil {
		return err
	}
	selected, ok := negotiateVersion(hello.SupportedProtocolVersions, g.config.SupportedVersions, controlAuthorization.AcceptedProtocolVersions)
	if !ok || selected.Major != telemetryProtocolMajor || selected.Minor != telemetryProtocolMinor {
		responseContext, cancel := context.WithTimeout(stream.Context(), g.config.HandshakeTimeout)
		_ = sendTelemetryResponse(responseContext, stream, telemetryErrorResponse(
			1, g.now(), commonv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION,
			"no mutually supported telemetry protocol version", false, 0, "",
		))
		cancel()
		return status.Error(codes.FailedPrecondition, "no mutually supported telemetry protocol version")
	}
	lease, err := g.telemetry.sessions.Acquire(stream.Context(), identity.NodeID)
	if err != nil {
		return status.Error(codes.Unavailable, "could not acquire the telemetry session")
	}
	defer lease.Release()
	if err := sendTelemetrySessionResponse(lease, stream, &agentv1.StreamTelemetryResponse{
		Stream: responseStreamMetadata(1, g.now()),
		Payload: &agentv1.StreamTelemetryResponse_Hello{Hello: &agentv1.TelemetryGatewayHello{
			SelectedProtocolVersion: selected,
			GatewayVersion:          g.config.GatewayVersion,
			ServerTime:              timestamppb.New(g.now()),
			MaximumRecordsPerBatch:  g.telemetry.config.MaximumRecordsPerBatch,
			MaximumRecordBytes:      uint32(g.telemetry.config.MaximumRecordBytes),
			MaximumBatchBytes:       uint32(g.telemetry.config.MaximumBatchBytes),
			MaximumInflightBatches:  1,
			IndependentQueueCursors: hello.LastDurableConnectionsAcknowledgedSequence != nil,
			ScopedRecords:           authorization.scoped,
		}},
	}); err != nil {
		return err
	}

	return g.serveTelemetry(stream, received, lease, identity, hello.SupportedProtocolVersions, selected,
		authorization, hello.LastDurableAcknowledgedSequence+1, hello.LastDurableConnectionsAcknowledgedSequence)
}

func (g *Gateway) serveTelemetry(
	stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse],
	received <-chan telemetryReceive,
	lease SessionLease,
	identity nodeIdentity,
	agentVersions *commonv1.ProtocolVersionRange,
	selectedVersion *commonv1.ProtocolVersion,
	initialAuthorization telemetryAuthorization,
	expectedSequence uint64,
	connectionsCursor *uint64,
) error {
	requestSequence := uint64(1)
	responseSequence := uint64(1)
	lastConnectionsWatermark := uint64(0)
	// Legacy peers use one queue. New peers explicitly negotiate independent
	// durable sequences while sharing the same authenticated/fenced RPC.
	expectedConnections := &expectedSequence
	if connectionsCursor != nil {
		next := *connectionsCursor + 1
		expectedConnections = &next
	}
	for {
		select {
		case <-stream.Context().Done():
			return rpcError(stream.Context().Err())
		case <-lease.Superseded():
			return status.Error(codes.Aborted, "telemetry session was superseded")
		case incoming := <-received:
			if errors.Is(incoming.err, io.EOF) {
				return nil
			}
			if incoming.err != nil {
				return rpcError(incoming.err)
			}
			request := incoming.request
			if request == nil || g.validateStreamMetadata(request.Stream) != nil ||
				request.Stream.Sequence != requestSequence+1 ||
				(request.GetBatch() == nil && request.GetConnectionsBatch() == nil) ||
				(request.GetBatch() != nil && request.GetConnectionsBatch() != nil) {
				responseSequence++
				_ = sendTelemetrySessionResponse(lease, stream, telemetryErrorResponse(
					responseSequence, g.now(), commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					"telemetry stream payload is invalid", false, 0, "",
				))
				return status.Error(codes.InvalidArgument, "telemetry stream payload is invalid")
			}
			requestSequence = request.Stream.Sequence
			if err := validateTelemetryCertificate(stream.Context(), g.now()); err != nil {
				return err
			}
			controlAuthorization, authorization, err := g.authorizeTelemetry(stream.Context(), identity, initialAuthorization.scoped)
			if err != nil {
				responseSequence++
				_ = sendTelemetrySessionResponse(lease, stream, telemetryErrorResponse(
					responseSequence, g.now(), protocolCodeForStatus(err),
					"telemetry authorization was rejected", status.Code(err) == codes.Unavailable,
					g.telemetry.config.RetryAfter, telemetryRequestBatchID(request),
				))
				return err
			}
			// A scoped session attributes by site scope, not the node owner.
			if authorization.installationID != initialAuthorization.installationID ||
				(!initialAuthorization.scoped && authorization.tenantID != initialAuthorization.tenantID) {
				return status.Error(codes.FailedPrecondition, "telemetry authorization identity changed")
			}
			if _, ok := negotiateVersion(
				&commonv1.ProtocolVersionRange{Minimum: selectedVersion, Maximum: selectedVersion},
				agentVersions, g.config.SupportedVersions, controlAuthorization.AcceptedProtocolVersions,
			); !ok {
				return status.Error(codes.FailedPrecondition, "telemetry protocol version is no longer authorized")
			}
			if connectionsBatch := request.GetConnectionsBatch(); connectionsBatch != nil {
				validated, err := validateConnectionsTelemetryBatch(
					connectionsBatch, *expectedConnections, lastConnectionsWatermark, identity.NodeID, authorization,
					g.telemetry.config, g.now(),
				)
				if err != nil {
					responseSequence++
					_ = sendTelemetrySessionResponse(lease, stream, telemetryErrorResponse(
						responseSequence, g.now(), commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
						"connections telemetry batch validation failed", false, 0, connectionsBatch.BatchId,
					))
					return status.Error(codes.InvalidArgument, "connections telemetry batch validation failed")
				}
				accepted, duplicates, publishErr := g.publishConnectionsTelemetryBatch(
					stream.Context(), lease, identity.NodeID, authorization, connectionsBatch.GetBatchId(), validated,
				)
				if accepted > 0 {
					responseSequence++
					ack := connectionsTelemetryAck(connectionsBatch, validated, accepted, duplicates, g.now())
					if publishErr != nil {
						ack.RetryAfterDuration = durationpb.New(g.telemetry.config.RetryAfter)
					}
					if err := sendTelemetrySessionResponse(lease, stream, &agentv1.StreamTelemetryResponse{
						Stream:  responseStreamMetadata(responseSequence, g.now()),
						Payload: &agentv1.StreamTelemetryResponse_Ack{Ack: ack},
					}); err != nil {
						return err
					}
				}
				if publishErr != nil {
					responseSequence++
					_ = sendTelemetrySessionResponse(lease, stream, telemetryErrorResponse(
						responseSequence, g.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE,
						"connections telemetry durable publication failed", true, g.telemetry.config.RetryAfter,
						connectionsBatch.BatchId,
					))
					if status.Code(publishErr) == codes.Aborted {
						return publishErr
					}
					if stream.Context().Err() != nil {
						return rpcError(stream.Context().Err())
					}
					return status.Error(codes.Unavailable, "connections telemetry durable publication failed")
				}
				if accepted != len(validated) {
					return status.Error(codes.Internal, "connections telemetry durable boundary is inconsistent")
				}
				if connectionsBatch.LastSequence == ^uint64(0) {
					return status.Error(codes.OutOfRange, "telemetry sequence space is exhausted")
				}
				lastConnectionsWatermark = validated[len(validated)-1].envelope.GetSourceWatermark()
				*expectedConnections = connectionsBatch.LastSequence + 1
				continue
			}
			batch := request.GetBatch()
			validated, err := validateTelemetryBatch(batch, expectedSequence, identity, authorization, g.telemetry.config, g.now())
			if err != nil {
				// The stream error is generic on purpose; the reason (e.g. a
				// config version the node authorization does not carry) is
				// for the operator (N11).
				log.Printf("agent-gateway telemetry batch rejected node=%s first_sequence=%d last_sequence=%d records=%d reason=%q",
					identity.NodeID, batch.GetFirstSequence(), batch.GetLastSequence(), len(batch.GetRecords()), err.Error())
				responseSequence++
				_ = sendTelemetrySessionResponse(lease, stream, telemetryErrorResponse(
					responseSequence, g.now(), commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					"telemetry batch validation failed", false, 0, batch.BatchId,
				))
				return status.Error(codes.InvalidArgument, "telemetry batch validation failed")
			}
			accepted, duplicates, publishErr := g.publishTelemetryBatch(stream.Context(), lease, identity.NodeID, authorization, validated)
			if accepted > 0 {
				responseSequence++
				ack := telemetryAck(batch, accepted, duplicates, g.now())
				if publishErr != nil {
					ack.RetryAfterDuration = durationpb.New(g.telemetry.config.RetryAfter)
				}
				if err := sendTelemetrySessionResponse(lease, stream, &agentv1.StreamTelemetryResponse{
					Stream:  responseStreamMetadata(responseSequence, g.now()),
					Payload: &agentv1.StreamTelemetryResponse_Ack{Ack: ack},
				}); err != nil {
					return err
				}
			}
			if publishErr != nil {
				responseSequence++
				_ = sendTelemetrySessionResponse(lease, stream, telemetryErrorResponse(
					responseSequence, g.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE,
					"telemetry durable publication failed", true, g.telemetry.config.RetryAfter, batch.BatchId,
				))
				if status.Code(publishErr) == codes.Aborted {
					return publishErr
				}
				if stream.Context().Err() != nil {
					return rpcError(stream.Context().Err())
				}
				return status.Error(codes.Unavailable, "telemetry durable publication failed")
			}
			if accepted != len(validated) {
				return status.Error(codes.Internal, "telemetry durable boundary is inconsistent")
			}
			if batch.LastSequence == ^uint64(0) {
				return status.Error(codes.OutOfRange, "telemetry sequence space is exhausted")
			}
			expectedSequence = batch.LastSequence + 1
		}
	}
}

func (g *Gateway) publishTelemetryBatch(
	ctx context.Context,
	lease SessionLease,
	nodeID string,
	authorization telemetryAuthorization,
	records []validatedTelemetryRecord,
) (accepted int, duplicates uint32, returnedError error) {
	for _, validated := range records {
		record := validated.record
		var result TelemetryPublishResult
		publisherCalled := false
		operationCtx, cancel := context.WithTimeout(ctx, g.telemetry.config.PublishTimeout)
		err := lease.FencedSend(func() error {
			publisherCalled = true
			var err error
			result, err = g.telemetry.publisher.Publish(operationCtx, TelemetryPublication{
				Kind:   record.Kind,
				NodeID: nodeID, TenantID: validated.tenantID, InstallationID: authorization.installationID,
				SiteID: validated.siteID, ConfigVersionID: validated.configVersionID,
				MessageID: record.MessageId, Payload: record.Payload,
			})
			return err
		})
		cancel()
		if err != nil {
			if publisherCalled && !errors.Is(err, ErrSessionSuperseded) {
				g.telemetry.health.RecordPublishFailure()
			}
			if errors.Is(err, ErrSessionSuperseded) {
				return accepted, duplicates, status.Error(codes.Aborted, "telemetry session was superseded")
			}
			return accepted, duplicates, err
		}
		accepted++
		if result.Duplicate {
			duplicates++
		}
		g.telemetry.health.RecordAccepted(result.Duplicate)
	}
	return accepted, duplicates, nil
}

type connectionsTelemetryPublisher interface {
	PublishConnections(context.Context, TelemetryPublication) (TelemetryPublishResult, error)
	ConnectionsStream() string
}

type validatedConnectionsTelemetryRecord struct {
	record   *agentv1.ConnectionsTelemetryRecordV1
	envelope *agentv1.ConnectionsMetricEnvelopeV1
	payload  []byte
	tenantID string
}

func telemetryRequestBatchID(request *agentv1.StreamTelemetryRequest) string {
	if request == nil {
		return ""
	}
	if batch := request.GetBatch(); batch != nil {
		return batch.GetBatchId()
	}
	if batch := request.GetConnectionsBatch(); batch != nil {
		return batch.GetBatchId()
	}
	return ""
}

func validateConnectionsTelemetryBatch(
	batch *agentv1.ConnectionsTelemetryBatchV1,
	expectedSequence uint64,
	lastSourceWatermark uint64,
	nodeID string,
	authorization telemetryAuthorization,
	config TelemetryConfig,
	now time.Time,
) ([]validatedConnectionsTelemetryRecord, error) {
	if batch == nil || !validTelemetryID(batch.GetBatchId()) || len(batch.GetRecords()) == 0 ||
		len(batch.GetRecords()) > int(config.MaximumRecordsPerBatch) || proto.Size(batch) > config.MaximumBatchBytes ||
		batch.GetFirstSequence() == 0 || batch.GetFirstSequence() != expectedSequence ||
		batch.GetLastSequence() < batch.GetFirstSequence() ||
		batch.GetLastSequence()-batch.GetFirstSequence()+1 != uint64(len(batch.GetRecords())) ||
		cacheControlMessageHasUnknown(batch.ProtoReflect()) {
		return nil, fmt.Errorf("connections telemetry batch is invalid")
	}
	validated := make([]validatedConnectionsTelemetryRecord, 0, len(batch.GetRecords()))
	seenReceipts := make(map[string]struct{}, len(batch.GetRecords()))
	seenEvents := make(map[string][]byte, len(batch.GetRecords()))
	watermark := lastSourceWatermark
	for _, record := range batch.GetRecords() {
		if record == nil || !validConnectionsReceiptID(record.GetReceiptId()) || record.GetEnvelope() == nil ||
			cacheControlMessageHasUnknown(record.ProtoReflect()) {
			return nil, fmt.Errorf("connections telemetry record is invalid")
		}
		recordAuthorization, err := authorization.recordAuthorization(record.ConfigurationScopeId)
		if err != nil {
			return nil, err
		}
		envelope := record.GetEnvelope()
		if err := validateConnectionsTelemetryEnvelope(envelope, nodeID, recordAuthorization, now); err != nil {
			return nil, err
		}
		if record.GetReceiptId() != connectionsTelemetryReceiptID(envelope) {
			return nil, fmt.Errorf("connections telemetry receipt identity is invalid")
		}
		if _, duplicate := seenReceipts[record.GetReceiptId()]; duplicate {
			return nil, fmt.Errorf("connections telemetry receipt identity is duplicated")
		}
		seenReceipts[record.GetReceiptId()] = struct{}{}
		if prior, duplicate := seenEvents[envelope.GetEvent().GetEventId()]; duplicate {
			if !bytes.Equal(prior, envelope.GetCanonicalEventSha256()) {
				return nil, fmt.Errorf("connections telemetry event identity conflicts")
			}
			return nil, fmt.Errorf("connections telemetry event identity is duplicated")
		}
		seenEvents[envelope.GetEvent().GetEventId()] = append([]byte(nil), envelope.GetCanonicalEventSha256()...)
		if envelope.GetSourceWatermark() <= watermark {
			return nil, fmt.Errorf("connections telemetry source watermark is not monotonic")
		}
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
		if err != nil || len(encoded) == 0 || len(encoded) > int(config.MaximumRecordBytes) {
			return nil, fmt.Errorf("connections telemetry envelope exceeds its limit")
		}
		validated = append(validated, validatedConnectionsTelemetryRecord{record: record, envelope: envelope, payload: encoded, tenantID: recordAuthorization.tenantID})
		watermark = envelope.GetSourceWatermark()
	}
	if proto.Size(batch) > config.MaximumBatchBytes {
		return nil, fmt.Errorf("connections telemetry batch exceeds its limit")
	}
	return validated, nil
}

func validateConnectionsTelemetryEnvelope(
	envelope *agentv1.ConnectionsMetricEnvelopeV1,
	nodeID string,
	authorization telemetryAuthorization,
	now time.Time,
) error {
	if envelope == nil || (envelope.GetSchemaVersion() != 1 && envelope.GetSchemaVersion() != 2) || cacheControlMessageHasUnknown(envelope.ProtoReflect()) ||
		envelope.GetDependencyState() != agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY ||
		!canonicalUUID(envelope.GetTenantId()) || envelope.GetTenantId() != authorization.tenantID ||
		!validTelemetryID(envelope.GetInstallationId()) || envelope.GetInstallationId() != authorization.installationID ||
		!canonicalUUID(envelope.GetSiteId()) ||
		(envelope.GetPackageSubscriptionId() != "" && !canonicalUUID(envelope.GetPackageSubscriptionId())) ||
		!connectionsScopeAuthorized(authorization, envelope.GetSiteId(), envelope.GetPackageSubscriptionId()) ||
		!canonicalUUID(nodeID) || !canonicalUUID(envelope.GetNodeId()) || envelope.GetNodeId() != nodeID ||
		!validTelemetryID(envelope.GetDomain()) || envelope.GetListenPort() == 0 || envelope.GetListenPort() > 65535 ||
		(envelope.GetSchemaVersion() == 1 && (envelope.GetConnections() == 0 || envelope.GetPackageSubscriptionId() == "" || envelope.GetConfigVersionId() != "")) ||
		(envelope.GetSchemaVersion() == 2 && (!canonicalUUID(envelope.GetConfigVersionId()) ||
			authorization.configBySite[telemetryScopeKey{siteID: envelope.GetSiteId(), configVersionID: envelope.GetConfigVersionId()}] != authorization.tenantID ||
			authorization.subscriptionBySite[telemetryScopeKey{siteID: envelope.GetSiteId(), configVersionID: envelope.GetConfigVersionId()}] != envelope.GetPackageSubscriptionId())) ||
		!validConnectionsDigest(envelope.GetCanonicalEventSha256()) ||
		!validConnectionsDigest(envelope.GetEvidenceSha256()) || envelope.GetSourceWatermark() == 0 ||
		envelope.GetEvent() == nil || !validTelemetryID(envelope.GetEvent().GetEventId()) ||
		envelope.GetEvent().GetOccurredTime() == nil || envelope.GetEvent().GetOccurredTime().CheckValid() != nil ||
		envelope.GetFinalizedThrough() == nil || envelope.GetFinalizedThrough().CheckValid() != nil {
		return fmt.Errorf("connections telemetry envelope is invalid")
	}
	occurred := envelope.GetEvent().GetOccurredTime().AsTime().UTC()
	finalized := envelope.GetFinalizedThrough().AsTime().UTC()
	if occurred.After(now.UTC().Add(telemetryMaxFutureSkew)) || finalized.Before(occurred) || finalized.After(now.UTC()) {
		return fmt.Errorf("connections telemetry finalization is invalid")
	}
	return nil
}

func connectionsScopeAuthorized(authorization telemetryAuthorization, siteID, subscriptionID string) bool {
	for scope, tenantID := range authorization.configBySite {
		if scope.siteID == siteID && tenantID == authorization.tenantID &&
			authorization.subscriptionBySite[scope] == subscriptionID {
			return true
		}
	}
	return false
}

func validConnectionsReceiptID(value string) bool {
	if len(value) != len("conn_")+sha256.Size*2 || value[:len("conn_")] != "conn_" {
		return false
	}
	for _, character := range value[len("conn_"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validConnectionsDigest(value []byte) bool {
	if len(value) != sha256.Size {
		return false
	}
	for _, byteValue := range value {
		if byteValue != 0 {
			return true
		}
	}
	return false
}

func connectionsTelemetryReceiptID(envelope *agentv1.ConnectionsMetricEnvelopeV1) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("cdnca.connections.identity.v1\x00"))
	writeConnectionsIdentityPart(digest, envelope.GetTenantId())
	writeConnectionsIdentityPart(digest, envelope.GetInstallationId())
	writeConnectionsIdentityPart(digest, envelope.GetSiteId())
	writeConnectionsIdentityPart(digest, envelope.GetPackageSubscriptionId())
	writeConnectionsIdentityPart(digest, envelope.GetNodeId())
	writeConnectionsIdentityPart(digest, envelope.GetDomain())
	var listenPort [4]byte
	binary.BigEndian.PutUint32(listenPort[:], envelope.GetListenPort())
	_, _ = digest.Write(listenPort[:])
	writeConnectionsIdentityPart(digest, envelope.GetEvent().GetEventId())
	if occurred := envelope.GetEvent().GetOccurredTime(); occurred != nil {
		var timestamp [12]byte
		binary.BigEndian.PutUint64(timestamp[:8], uint64(occurred.GetSeconds()))
		binary.BigEndian.PutUint32(timestamp[8:], uint32(occurred.GetNanos()))
		_, _ = digest.Write(timestamp[:])
	}
	writeConnectionsIdentityPart(digest, envelope.GetCanonicalEventSha256())
	return "conn_" + hex.EncodeToString(digest.Sum(nil))
}

func writeConnectionsIdentityPart(destination hash.Hash, value any) {
	var encoded []byte
	switch value := value.(type) {
	case string:
		encoded = []byte(value)
	case []byte:
		encoded = value
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(encoded)
}

func (g *Gateway) publishConnectionsTelemetryBatch(
	ctx context.Context,
	lease SessionLease,
	nodeID string,
	authorization telemetryAuthorization,
	batchID string,
	records []validatedConnectionsTelemetryRecord,
) (accepted int, duplicates uint32, returnedError error) {
	publisher, ok := g.telemetry.publisher.(connectionsTelemetryPublisher)
	if !ok || !validNATSName(publisher.ConnectionsStream()) {
		return 0, 0, fmt.Errorf("connections telemetry publisher is unavailable")
	}
	expectedStream := publisher.ConnectionsStream()
	for _, validated := range records {
		var result TelemetryPublishResult
		publisherCalled := false
		operationCtx, cancel := context.WithTimeout(ctx, g.telemetry.config.PublishTimeout)
		err := lease.FencedSend(func() error {
			publisherCalled = true
			var err error
			result, err = publisher.PublishConnections(operationCtx, TelemetryPublication{
				NodeID: nodeID, TenantID: validated.tenantID, InstallationID: authorization.installationID,
				SiteID: validated.envelope.GetSiteId(), Domain: validated.envelope.GetDomain(),
				ListenPort: validated.envelope.GetListenPort(), BatchID: batchID,
				MessageID: validated.record.GetReceiptId(), Payload: validated.payload,
			})
			return err
		})
		cancel()
		if err != nil {
			if publisherCalled && !errors.Is(err, ErrSessionSuperseded) {
				g.telemetry.health.RecordPublishFailure()
			}
			if errors.Is(err, ErrSessionSuperseded) {
				return accepted, duplicates, status.Error(codes.Aborted, "telemetry session was superseded")
			}
			return accepted, duplicates, err
		}
		if result.Stream != expectedStream || result.Sequence == 0 {
			g.telemetry.health.RecordPublishFailure()
			return accepted, duplicates, fmt.Errorf("connections telemetry PubAck proof is invalid")
		}
		accepted++
		if result.Duplicate {
			duplicates++
		}
		g.telemetry.health.RecordAccepted(result.Duplicate)
	}
	return accepted, duplicates, nil
}

func connectionsTelemetryAck(
	batch *agentv1.ConnectionsTelemetryBatchV1,
	records []validatedConnectionsTelemetryRecord,
	accepted int,
	duplicates uint32,
	now time.Time,
) *agentv1.TelemetryAck {
	record := records[accepted-1]
	return &agentv1.TelemetryAck{
		BatchId: batch.GetBatchId(), AcceptedRecordCount: uint32(accepted),
		AcceptedThroughSequence:  batch.GetFirstSequence() + uint64(accepted) - 1,
		AcceptedThroughMessageId: record.record.GetReceiptId(), AcceptedThroughEventId: record.envelope.GetEvent().GetEventId(),
		DuplicateRecordCount: duplicates, AcceptedTime: timestamppb.New(now.UTC()),
	}
}

func (g *Gateway) authorizeTelemetry(ctx context.Context, identity nodeIdentity, scopedRecords bool) (*controlv1.GetNodeAuthorizationResponse, telemetryAuthorization, error) {
	response, err := g.authorizeConnection(ctx, identity, nil)
	if err != nil {
		return nil, telemetryAuthorization{}, err
	}
	authorization, err := validateTelemetryAuthorization(response, scopedRecords)
	if err != nil {
		return nil, telemetryAuthorization{}, status.Error(codes.Internal, "control plane returned incomplete telemetry authorization")
	}
	return response, authorization, nil
}

func telemetryAck(batch *agentv1.TelemetryBatch, accepted int, duplicates uint32, now time.Time) *agentv1.TelemetryAck {
	record := batch.Records[accepted-1]
	return &agentv1.TelemetryAck{
		BatchId: batch.BatchId, AcceptedRecordCount: uint32(accepted),
		AcceptedThroughSequence: record.LastSequence, AcceptedThroughMessageId: record.MessageId,
		AcceptedThroughEventId: record.LastEventId, DuplicateRecordCount: duplicates,
		AcceptedTime: timestamppb.New(now),
	}
}

func telemetryErrorResponse(
	sequence uint64,
	now time.Time,
	code commonv1.ErrorCode,
	message string,
	retryable bool,
	retryAfter time.Duration,
	batchID string,
) *agentv1.StreamTelemetryResponse {
	protocolError := &commonv1.ProtocolError{Code: code, Message: message, Retryable: retryable}
	if retryAfter > 0 {
		protocolError.RetryAfterDuration = durationpb.New(retryAfter)
	}
	errorPayload := &agentv1.TelemetryError{Error: protocolError}
	if validTelemetryID(batchID) {
		errorPayload.RelatedBatchId = &batchID
	}
	return &agentv1.StreamTelemetryResponse{
		Stream:  responseStreamMetadata(sequence, now),
		Payload: &agentv1.StreamTelemetryResponse_Error{Error: errorPayload},
	}
}

func protocolCodeForStatus(err error) commonv1.ErrorCode {
	switch status.Code(err) {
	case codes.PermissionDenied:
		return commonv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	case codes.FailedPrecondition:
		return commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION
	case codes.DeadlineExceeded:
		return commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED
	case codes.Unavailable:
		return commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE
	default:
		return commonv1.ErrorCode_ERROR_CODE_INTERNAL
	}
}

func validateTelemetryCertificate(ctx context.Context, now time.Time) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "verified client certificate required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return status.Error(codes.Unauthenticated, "verified client certificate required")
	}
	leaf := tlsInfo.State.VerifiedChains[0][0]
	if leaf == nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !allowsClientAuthentication(leaf) {
		return status.Error(codes.Unauthenticated, "client certificate is not valid for telemetry")
	}
	return nil
}

func allowsClientAuthentication(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

type telemetryReceive struct {
	request *agentv1.StreamTelemetryRequest
	err     error
}

func pumpTelemetryRequests(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) <-chan telemetryReceive {
	received := make(chan telemetryReceive, 1)
	go func() {
		for {
			request, err := stream.Recv()
			select {
			case received <- telemetryReceive{request: request, err: err}:
			case <-stream.Context().Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return received
}

func receiveTelemetryWithTimeout(ctx context.Context, received <-chan telemetryReceive, timeout time.Duration) (telemetryReceive, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-received:
		return result, rpcError(result.err)
	case <-timer.C:
		return telemetryReceive{}, status.Error(codes.DeadlineExceeded, "telemetry hello was not received before the handshake deadline")
	case <-ctx.Done():
		return telemetryReceive{}, rpcError(ctx.Err())
	}
}

func sendTelemetrySessionResponse(
	lease SessionLease,
	stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse],
	response *agentv1.StreamTelemetryResponse,
) error {
	err := lease.FencedSend(func() error { return stream.Send(response) })
	if errors.Is(err, ErrSessionSuperseded) {
		return status.Error(codes.Aborted, "telemetry session was superseded")
	}
	return rpcError(err)
}

func sendTelemetryResponse(
	ctx context.Context,
	stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse],
	response *agentv1.StreamTelemetryResponse,
) error {
	sent := make(chan error, 1)
	go func() {
		err := stream.Send(response)
		select {
		case sent <- err:
		case <-ctx.Done():
		}
	}()
	select {
	case err := <-sent:
		return rpcError(err)
	case <-ctx.Done():
		return rpcError(ctx.Err())
	}
}
