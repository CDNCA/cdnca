package telemetryclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Client struct {
	config  Config
	dialer  Dialer
	now     func() time.Time
	jitter  func(time.Duration) time.Duration
	slot    chan struct{}
	session *clientSession
}

type clientSession struct {
	connection Connection
	stream     grpc.BidiStreamingClient[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]
	cancel     context.CancelFunc
	sendSeq    uint64
	recvSeq    uint64
	limits     sessionLimits
}

type sessionLimits struct {
	maxRecords     int
	maxRecordBytes int
	maxBatchBytes  int
	scoped         bool
	scopeForSite   func(string) (string, bool)
}

func New(config Config, dialer Dialer) (*Client, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if dialer == nil {
		return nil, fmt.Errorf("%w: mTLS dialer is required", ErrInvalidConfiguration)
	}
	config.SupportedVersions = proto.Clone(config.SupportedVersions).(*commonv1.ProtocolVersionRange)
	return &Client{
		config: config, dialer: dialer, now: time.Now, slot: make(chan struct{}, 1),
		jitter: func(delay time.Duration) time.Duration {
			return time.Duration(float64(delay) * (0.8 + rand.Float64()*0.4))
		},
	}, nil
}

func (c *Client) Send(ctx context.Context, batch Batch) (SendAck, error) {
	if c == nil || ctx == nil {
		return SendAck{}, ErrInvalidConfiguration
	}
	select {
	case c.slot <- struct{}{}:
		defer func() { <-c.slot }()
	case <-ctx.Done():
		return SendAck{}, ctx.Err()
	}
	if err := validateBatch(batch, c.config); err != nil {
		return SendAck{}, err
	}

	accepted := 0
	backoff := c.config.InitialBackoff
	var current *outboundBatch
	total := len(batch.Records)
	if len(batch.Connections) > 0 {
		total = len(batch.Connections)
	}
	for accepted < total {
		if err := ctx.Err(); err != nil {
			return SendAck{Accepted: accepted}, err
		}
		if c.session == nil {
			if err := c.openSession(ctx); err != nil {
				if permanentTransportError(err) || errors.Is(err, ErrPermanentProtocol) || errors.Is(err, ErrInvalidResponse) {
					return SendAck{Accepted: accepted}, fmt.Errorf("%w: telemetry session rejected", ErrPermanentProtocol)
				}
				return SendAck{Accepted: accepted}, err
			}
			backoff = c.config.InitialBackoff
		}
		if current == nil {
			wire, err := buildOutboundBatch(batch, accepted, c.session.limits)
			if err != nil {
				return SendAck{Accepted: accepted}, err
			}
			current = wire
		} else if !current.fits(c.session.limits) {
			c.closeSession()
			return SendAck{Accepted: accepted}, fmt.Errorf("%w: gateway limits changed during retry", ErrPermanentProtocol)
		}

		count, retryAfter, err := c.sendOutboundBatch(ctx, current)
		if err != nil {
			c.closeSession()
			if errors.Is(err, ErrBackpressure) {
				return SendAck{Accepted: accepted}, err
			}
			if permanentTransportError(err) || errors.Is(err, ErrPermanentProtocol) || errors.Is(err, ErrInvalidResponse) {
				return SendAck{Accepted: accepted}, err
			}
			if accepted > 0 {
				return SendAck{Accepted: accepted}, err
			}
			if err := c.waitBackoff(ctx, backoff); err != nil {
				return SendAck{}, err
			}
			backoff = nextBackoff(backoff, c.config.MaximumBackoff)
			continue
		}
		accepted += count
		if count != current.count() {
			c.closeSession()
			err := error(ErrPartialAcknowledged)
			if retryAfter > 0 {
				err = retryError{cause: err, after: retryAfter}
			}
			return SendAck{Accepted: accepted}, err
		}
		if retryAfter > 0 {
			return SendAck{Accepted: accepted}, retryError{cause: ErrBackpressure, after: retryAfter}
		}
		current = nil
	}
	return SendAck{Accepted: accepted}, nil
}

func (c *Client) openSession(ctx context.Context) error {
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, c.config.HandshakeTimeout)
	connection, err := c.dialer.Dial(handshakeCtx)
	cancelHandshake()
	if err != nil {
		return err
	}
	if connection == nil || connection.Client() == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return ErrInvalidResponse
	}
	sessionCtx, cancelSession := context.WithCancel(ctx)
	stream, err := connection.Client().StreamTelemetry(sessionCtx, grpc.WaitForReady(false))
	if err != nil {
		cancelSession()
		_ = connection.Close()
		return err
	}
	cursor, err := c.config.Cursor.AcknowledgedSequence(sessionCtx)
	if err != nil {
		cancelSession()
		_ = connection.Close()
		return fmt.Errorf("read durable telemetry cursor")
	}
	session := &clientSession{connection: connection, stream: stream, cancel: cancelSession, sendSeq: 1}
	hello := &agentv1.StreamTelemetryRequest{
		Stream: streamMetadata(uuid.NewString(), 1, c.now()),
		Payload: &agentv1.StreamTelemetryRequest_Hello{Hello: &agentv1.TelemetryClientHello{
			SupportedProtocolVersions:       c.config.SupportedVersions,
			LastDurableAcknowledgedSequence: cursor,
			BootId:                          c.config.BootID,
			ScopedRecords:                   c.config.ScopedRecords,
		}},
	}
	if c.config.ConnectionsCursor != nil {
		connectionsCursor, err := c.config.ConnectionsCursor.AcknowledgedSequence(sessionCtx)
		if err != nil {
			session.close()
			return fmt.Errorf("read durable connections cursor")
		}
		hello.GetHello().LastDurableConnectionsAcknowledgedSequence = &connectionsCursor
	}
	if err := stream.Send(hello); err != nil {
		session.close()
		return err
	}
	response, err := receiveWithTimeout(sessionCtx, cancelSession, stream, c.config.HandshakeTimeout)
	if err != nil {
		session.close()
		return err
	}
	if err := validateResponseEnvelope(response, 1); err != nil {
		session.close()
		return err
	}
	limits, err := c.validateHello(response.GetHello())
	if err != nil {
		session.close()
		return err
	}
	session.recvSeq = 1
	session.limits = limits
	c.session = session
	return nil
}

func (c *Client) validateHello(hello *agentv1.TelemetryGatewayHello) (sessionLimits, error) {
	// scoped_records must be echoed exactly as requested: a scoped session
	// cannot fall back to unscoped records, and an echo the Agent did not ask
	// for is a protocol violation.
	if hello == nil || !versionInRange(hello.SelectedProtocolVersion, c.config.SupportedVersions) ||
		(c.config.ConnectionsCursor != nil && !hello.IndependentQueueCursors) ||
		hello.ScopedRecords != c.config.ScopedRecords ||
		!safeMetadataText(hello.GatewayVersion, 128) || hello.ServerTime == nil || hello.ServerTime.CheckValid() != nil ||
		hello.MaximumRecordsPerBatch == 0 || hello.MaximumRecordBytes == 0 || hello.MaximumBatchBytes == 0 ||
		hello.MaximumInflightBatches != 1 || hello.MaximumRecordBytes > hello.MaximumBatchBytes {
		return sessionLimits{}, fmt.Errorf("%w: gateway hello is invalid", ErrPermanentProtocol)
	}
	maxRecords := c.config.MaxRecordsPerBatch
	if hello.MaximumRecordsPerBatch < uint32(maxRecords) {
		maxRecords = int(hello.MaximumRecordsPerBatch)
	}
	maxRecordBytes := c.config.MaxRecordBytes
	if hello.MaximumRecordBytes < uint32(maxRecordBytes) {
		maxRecordBytes = int(hello.MaximumRecordBytes)
	}
	maxBatchBytes := c.config.MaxBatchBytes
	if hello.MaximumBatchBytes < uint32(maxBatchBytes) {
		maxBatchBytes = int(hello.MaximumBatchBytes)
	}
	return sessionLimits{
		maxRecords: maxRecords, maxRecordBytes: maxRecordBytes, maxBatchBytes: maxBatchBytes,
		scoped: hello.ScopedRecords, scopeForSite: c.config.ScopeForSite,
	}, nil
}

type outboundBatch struct {
	legacy      *agentv1.TelemetryBatch
	connections *agentv1.ConnectionsTelemetryBatchV1
}

func buildOutboundBatch(batch Batch, offset int, limits sessionLimits) (*outboundBatch, error) {
	if len(batch.Connections) > 0 {
		wire, err := buildConnectionsWireBatch(batch.Connections[offset:], limits)
		if err != nil {
			return nil, err
		}
		return &outboundBatch{connections: wire}, nil
	}
	wire, err := buildWireBatch(batch.Records[offset:], limits)
	if err != nil {
		return nil, err
	}
	return &outboundBatch{legacy: wire}, nil
}

func (b *outboundBatch) count() int {
	if b == nil {
		return 0
	}
	if b.connections != nil {
		return len(b.connections.Records)
	}
	return len(b.legacy.Records)
}

func (b *outboundBatch) fits(limits sessionLimits) bool {
	if b == nil || (b.legacy == nil) == (b.connections == nil) || b.count() == 0 || b.count() > limits.maxRecords {
		return false
	}
	if b.legacy != nil {
		return batchFits(b.legacy, limits)
	}
	if proto.Size(b.connections) > limits.maxBatchBytes {
		return false
	}
	for _, record := range b.connections.Records {
		if record == nil || record.Envelope == nil || proto.Size(record) > limits.maxRecordBytes {
			return false
		}
	}
	return true
}

func (c *Client) sendOutboundBatch(ctx context.Context, batch *outboundBatch) (int, time.Duration, error) {
	if batch == nil || (batch.legacy == nil) == (batch.connections == nil) {
		return 0, 0, ErrInvalidPublication
	}
	if batch.legacy != nil {
		return c.sendBatch(ctx, batch.legacy)
	}
	return c.sendConnectionsBatch(ctx, batch.connections)
}

func (c *Client) sendBatch(ctx context.Context, batch *agentv1.TelemetryBatch) (int, time.Duration, error) {
	session := c.session
	session.sendSeq++
	requestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(batch.BatchId)).String()
	request := &agentv1.StreamTelemetryRequest{
		Stream:  streamMetadata(requestID, session.sendSeq, c.now()),
		Payload: &agentv1.StreamTelemetryRequest_Batch{Batch: batch},
	}
	if err := session.stream.Send(request); err != nil {
		return 0, 0, err
	}
	response, err := receiveWithTimeout(ctx, session.cancel, session.stream, c.config.AckTimeout)
	if err != nil {
		return 0, 0, err
	}
	session.recvSeq++
	if err := validateResponseEnvelope(response, session.recvSeq); err != nil {
		return 0, 0, err
	}
	if protocolError := response.GetError(); protocolError != nil {
		return 0, 0, validateProtocolError(protocolError, batch.BatchId, c.config.MaximumBackoff)
	}
	ack := response.GetAck()
	if err := validateAck(ack, batch, c.config.MaximumBackoff); err != nil {
		return 0, 0, err
	}
	if ack.AcceptedRecordCount == 0 {
		after := durationValue(ack.RetryAfterDuration)
		return 0, 0, retryError{cause: ErrBackpressure, after: after}
	}
	return int(ack.AcceptedRecordCount), durationValue(ack.RetryAfterDuration), nil
}

func (c *Client) sendConnectionsBatch(ctx context.Context, batch *agentv1.ConnectionsTelemetryBatchV1) (int, time.Duration, error) {
	session := c.session
	session.sendSeq++
	requestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(batch.BatchId)).String()
	request := &agentv1.StreamTelemetryRequest{
		Stream:  streamMetadata(requestID, session.sendSeq, c.now()),
		Payload: &agentv1.StreamTelemetryRequest_ConnectionsBatch{ConnectionsBatch: batch},
	}
	if err := session.stream.Send(request); err != nil {
		return 0, 0, err
	}
	response, err := receiveWithTimeout(ctx, session.cancel, session.stream, c.config.AckTimeout)
	if err != nil {
		return 0, 0, err
	}
	session.recvSeq++
	if err := validateResponseEnvelope(response, session.recvSeq); err != nil {
		return 0, 0, err
	}
	if protocolError := response.GetError(); protocolError != nil {
		return 0, 0, validateProtocolError(protocolError, batch.BatchId, c.config.MaximumBackoff)
	}
	ack := response.GetAck()
	if err := validateConnectionsAck(ack, batch, c.config.MaximumBackoff); err != nil {
		return 0, 0, err
	}
	if ack.AcceptedRecordCount == 0 {
		after := durationValue(ack.RetryAfterDuration)
		return 0, 0, retryError{cause: ErrBackpressure, after: after}
	}
	return int(ack.AcceptedRecordCount), durationValue(ack.RetryAfterDuration), nil
}

func validateBatch(batch Batch, config Config) error {
	if len(batch.Records) > 0 && len(batch.Connections) > 0 {
		return ErrInvalidPublication
	}
	if len(batch.Connections) > 0 {
		return validateConnectionsBatch(batch.Connections, config)
	}
	if len(batch.Records) == 0 {
		return ErrInvalidPublication
	}
	for index, record := range batch.Records {
		if !validAnalyticsRecordKind(record.Kind) || record.MessageID == "" ||
			record.FirstSequence == 0 || record.LastSequence < record.FirstSequence || record.LastEventID == "" ||
			record.EventCount < 1 || record.EventCount != int(record.LastSequence-record.FirstSequence+1) ||
			len(record.Payload) == 0 || len(record.Payload) > config.MaxRecordBytes {
			return ErrInvalidPublication
		}
		if index > 0 && record.FirstSequence != batch.Records[index-1].LastSequence+1 {
			return ErrInvalidPublication
		}
	}
	return nil
}

func validAnalyticsRecordKind(kind string) bool {
	switch kind {
	case "access.v1", "security.v1", "access.v2", "security.v2", "l4_session.v1", "access_window.v1", "subscription_minute.v1":
		return true
	default:
		return false
	}
}

func validateConnectionsBatch(records []ConnectionsRecord, config Config) error {
	if len(records) == 0 || len(records) > config.MaxRecordsPerBatch {
		return ErrInvalidPublication
	}
	for index, record := range records {
		if !validConnectionsRecord(record, config.MaxRecordBytes) ||
			index > 0 && (record.Sequence == 0 || record.Sequence != records[index-1].Sequence+1) {
			return ErrInvalidPublication
		}
	}
	return nil
}

func validConnectionsRecord(record ConnectionsRecord, maximumBytes int) bool {
	if !validConnectionsReceiptID(record.ReceiptID) || record.Sequence == 0 || record.Envelope == nil ||
		(record.Envelope.GetSchemaVersion() != 1 && record.Envelope.GetSchemaVersion() != 2) || record.Envelope.GetEvent() == nil ||
		record.Envelope.GetDependencyState() != agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY ||
		(record.Envelope.GetSchemaVersion() == 1 && (record.Envelope.GetConnections() == 0 || record.Envelope.GetConfigVersionId() != "")) ||
		(record.Envelope.GetSchemaVersion() == 2 && !canonicalUUID(record.Envelope.GetConfigVersionId())) || len(record.Envelope.GetCanonicalEventSha256()) != sha256.Size ||
		len(record.Envelope.GetEvidenceSha256()) != sha256.Size || record.Envelope.GetSourceWatermark() == 0 ||
		record.Envelope.GetEvent().GetOccurredTime() == nil || record.Envelope.GetEvent().GetOccurredTime().CheckValid() != nil ||
		record.Envelope.GetFinalizedThrough() == nil || record.Envelope.GetFinalizedThrough().CheckValid() != nil ||
		proto.Size(&agentv1.ConnectionsTelemetryRecordV1{ReceiptId: record.ReceiptID, Envelope: record.Envelope}) > maximumBytes {
		return false
	}
	if !canonicalUUID(record.Envelope.GetTenantId()) || !canonicalUUID(record.Envelope.GetInstallationId()) ||
		!canonicalUUID(record.Envelope.GetSiteId()) {
		return false
	}
	if record.Envelope.GetEvent().GetOccurredTime().AsTime().After(record.Envelope.GetFinalizedThrough().AsTime()) {
		return false
	}
	return !allZero(record.Envelope.GetCanonicalEventSha256()) && !allZero(record.Envelope.GetEvidenceSha256())
}

func validConnectionsReceiptID(value string) bool {
	if len(value) != len("conn_")+sha256.Size*2 || !strings.HasPrefix(value, "conn_") {
		return false
	}
	digest := value[len("conn_"):]
	decoded, err := hex.DecodeString(digest)
	return err == nil && hex.EncodeToString(decoded) == digest
}

func allZero(value []byte) bool {
	for _, byteValue := range value {
		if byteValue != 0 {
			return false
		}
	}
	return len(value) > 0
}

func buildWireBatch(records []Record, limits sessionLimits) (*agentv1.TelemetryBatch, error) {
	if len(records) == 0 {
		return nil, ErrInvalidPublication
	}
	maximum := min(len(records), limits.maxRecords)
	wireRecords := make([]*agentv1.TelemetryRecord, 0, maximum)
	for index := 0; index < maximum; index++ {
		record := records[index]
		if len(record.Payload) > limits.maxRecordBytes {
			return nil, fmt.Errorf("%w: record exceeds negotiated limit", ErrPermanentProtocol)
		}
		var kind agentv1.TelemetryKind
		switch record.Kind {
		case "access.v1":
			kind = agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1
		case "security.v1":
			kind = agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1
		case "access.v2":
			kind = agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V2
		case "security.v2":
			kind = agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V2
		case "l4_session.v1":
			kind = agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1
		case "access_window.v1":
			kind = agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_WINDOW_V1
		case "subscription_minute.v1":
			kind = agentv1.TelemetryKind_TELEMETRY_KIND_SUBSCRIPTION_MINUTE_V1
		default:
			return nil, ErrInvalidPublication
		}
		subscriptionID := ""
		if record.Kind != "l4_session.v1" {
			var err error
			subscriptionID, err = packageSubscriptionFromPayload(record.Payload)
			if err != nil {
				return nil, ErrInvalidPublication
			}
		}
		wireRecord := &agentv1.TelemetryRecord{
			Kind: kind, MessageId: record.MessageID, FirstSequence: record.FirstSequence,
			LastSequence: record.LastSequence, LastEventId: record.LastEventID,
			EventCount: uint32(record.EventCount), Payload: append([]byte(nil), record.Payload...),
			PackageSubscriptionId: subscriptionID,
		}
		if limits.scoped {
			scopeID, err := recordScope(record, limits.scopeForSite)
			if err != nil {
				return nil, err
			}
			wireRecord.ConfigurationScopeId = &scopeID
		}
		candidate := append(wireRecords, wireRecord)
		batch := wireBatch(candidate)
		if proto.Size(batch) > limits.maxBatchBytes {
			if len(wireRecords) == 0 {
				return nil, fmt.Errorf("%w: record cannot fit negotiated batch limit", ErrPermanentProtocol)
			}
			break
		}
		wireRecords = candidate
	}
	return wireBatch(wireRecords), nil
}

func buildConnectionsWireBatch(records []ConnectionsRecord, limits sessionLimits) (*agentv1.ConnectionsTelemetryBatchV1, error) {
	if len(records) == 0 {
		return nil, ErrInvalidPublication
	}
	maximum := min(len(records), limits.maxRecords)
	wireRecords := make([]*agentv1.ConnectionsTelemetryRecordV1, 0, maximum)
	for index := 0; index < maximum; index++ {
		record := records[index]
		if !validConnectionsRecord(record, limits.maxRecordBytes) {
			return nil, ErrInvalidPublication
		}
		wireRecord := &agentv1.ConnectionsTelemetryRecordV1{
			ReceiptId: record.ReceiptID, Envelope: proto.Clone(record.Envelope).(*agentv1.ConnectionsMetricEnvelopeV1),
		}
		if limits.scoped {
			scopeID, err := siteScope(record.Envelope.GetSiteId(), limits.scopeForSite)
			if err != nil {
				return nil, err
			}
			wireRecord.ConfigurationScopeId = &scopeID
		}
		candidate := append(wireRecords, wireRecord)
		batch := connectionsWireBatch(candidate, records[0].Sequence, record.Sequence)
		if proto.Size(batch) > limits.maxBatchBytes {
			if len(wireRecords) == 0 {
				return nil, fmt.Errorf("%w: connections record cannot fit negotiated batch limit", ErrPermanentProtocol)
			}
			break
		}
		wireRecords = candidate
	}
	return connectionsWireBatch(wireRecords, records[0].Sequence, records[len(wireRecords)-1].Sequence), nil
}

// recordScope is the configuration scope that published the record's site.
// It is resolved from the site, never taken from the payload tenant: scope and
// tenant are distinct identifiers.
func recordScope(record Record, scopeForSite func(string) (string, bool)) (string, error) {
	var siteID string
	if record.Kind == "l4_session.v1" {
		var envelope agentv1.L4SessionEnvelopeV1
		if err := proto.Unmarshal(record.Payload, &envelope); err != nil {
			return "", ErrInvalidPublication
		}
		siteID = envelope.GetSiteId()
	} else {
		var envelope struct {
			Events []struct {
				SiteID string `json:"site_id"`
			} `json:"events"`
		}
		if err := json.Unmarshal(record.Payload, &envelope); err != nil || len(envelope.Events) == 0 {
			return "", ErrInvalidPublication
		}
		siteID = envelope.Events[0].SiteID
		for _, event := range envelope.Events {
			if event.SiteID != siteID {
				return "", ErrInvalidPublication
			}
		}
	}
	return siteScope(siteID, scopeForSite)
}

func siteScope(siteID string, scopeForSite func(string) (string, bool)) (string, error) {
	if !canonicalUUID(siteID) || scopeForSite == nil {
		return "", ErrInvalidPublication
	}
	scopeID, ok := scopeForSite(siteID)
	if !ok || !canonicalUUID(scopeID) {
		return "", ErrInvalidPublication
	}
	return scopeID, nil
}

func packageSubscriptionFromPayload(payload []byte) (string, error) {
	var envelope struct {
		PackageSubscriptionID string            `json:"package_subscription_id,omitempty"`
		Events                []json.RawMessage `json:"events"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF || len(envelope.Events) == 0 {
		// Older durable publications and unit fixtures may not carry an
		// attribution envelope. The Gateway still validates the payload and
		// derives the authoritative value from its immutable config snapshot.
		return "", nil
	}
	for _, raw := range envelope.Events {
		var event struct {
			PackageSubscriptionID string `json:"package_subscription_id,omitempty"`
		}
		if err := json.Unmarshal(raw, &event); err != nil || event.PackageSubscriptionID != envelope.PackageSubscriptionID {
			return "", ErrInvalidPublication
		}
	}
	if envelope.PackageSubscriptionID != "" && !canonicalUUID(envelope.PackageSubscriptionID) {
		return "", ErrInvalidPublication
	}
	return envelope.PackageSubscriptionID, nil
}

func wireBatch(records []*agentv1.TelemetryRecord) *agentv1.TelemetryBatch {
	plain := make([]Record, len(records))
	for index, record := range records {
		plain[index] = Record{MessageID: record.MessageId, FirstSequence: record.FirstSequence, LastSequence: record.LastSequence, LastEventID: record.LastEventId}
	}
	return &agentv1.TelemetryBatch{
		BatchId: batchID(plain), FirstSequence: records[0].FirstSequence,
		LastSequence: records[len(records)-1].LastSequence, Records: records,
	}
}

func connectionsWireBatch(records []*agentv1.ConnectionsTelemetryRecordV1, firstSequence, lastSequence uint64) *agentv1.ConnectionsTelemetryBatchV1 {
	plain := make([]ConnectionsRecord, len(records))
	for index, record := range records {
		plain[index] = ConnectionsRecord{ReceiptID: record.ReceiptId, Sequence: firstSequence + uint64(index), Envelope: record.Envelope}
	}
	return &agentv1.ConnectionsTelemetryBatchV1{
		BatchId: connectionsBatchID(plain), FirstSequence: firstSequence, LastSequence: lastSequence, Records: records,
	}
}

func connectionsBatchID(records []ConnectionsRecord) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.connections.batch.v1\x00"))
	for _, record := range records {
		_, _ = fmt.Fprintf(hash, "%d:%s\n", record.Sequence, record.ReceiptID)
	}
	return "conn_batch_" + hex.EncodeToString(hash.Sum(nil))
}

func batchFits(batch *agentv1.TelemetryBatch, limits sessionLimits) bool {
	if batch == nil || len(batch.Records) == 0 || len(batch.Records) > limits.maxRecords || proto.Size(batch) > limits.maxBatchBytes {
		return false
	}
	for _, record := range batch.Records {
		if record == nil || len(record.Payload) > limits.maxRecordBytes {
			return false
		}
	}
	return true
}

func validateAck(ack *agentv1.TelemetryAck, batch *agentv1.TelemetryBatch, maximumRetry time.Duration) error {
	if ack == nil || ack.BatchId != batch.BatchId || ack.AcceptedRecordCount > uint32(len(batch.Records)) ||
		ack.DuplicateRecordCount > ack.AcceptedRecordCount || ack.AcceptedTime == nil || ack.AcceptedTime.CheckValid() != nil {
		return ErrInvalidResponse
	}
	if durationInvalid(ack.RetryAfterDuration, maximumRetry) {
		return ErrInvalidResponse
	}
	if ack.AcceptedRecordCount == 0 {
		if ack.AcceptedThroughSequence != 0 || ack.AcceptedThroughMessageId != "" || ack.AcceptedThroughEventId != "" {
			return ErrInvalidResponse
		}
		return nil
	}
	last := batch.Records[ack.AcceptedRecordCount-1]
	if ack.AcceptedThroughSequence != last.LastSequence || ack.AcceptedThroughMessageId != last.MessageId || ack.AcceptedThroughEventId != last.LastEventId {
		return ErrInvalidResponse
	}
	return nil
}

func validateConnectionsAck(ack *agentv1.TelemetryAck, batch *agentv1.ConnectionsTelemetryBatchV1, maximumRetry time.Duration) error {
	if ack == nil || ack.BatchId != batch.BatchId || ack.AcceptedRecordCount > uint32(len(batch.Records)) ||
		ack.DuplicateRecordCount > ack.AcceptedRecordCount || ack.AcceptedTime == nil || ack.AcceptedTime.CheckValid() != nil {
		return ErrInvalidResponse
	}
	if durationInvalid(ack.RetryAfterDuration, maximumRetry) {
		return ErrInvalidResponse
	}
	if ack.AcceptedRecordCount == 0 {
		if ack.AcceptedThroughSequence != 0 || ack.AcceptedThroughMessageId != "" || ack.AcceptedThroughEventId != "" {
			return ErrInvalidResponse
		}
		return nil
	}
	last := batch.Records[ack.AcceptedRecordCount-1]
	if last == nil || last.Envelope == nil || ack.AcceptedThroughSequence != batch.FirstSequence+uint64(ack.AcceptedRecordCount)-1 ||
		ack.AcceptedThroughMessageId != last.ReceiptId || ack.AcceptedThroughEventId != last.Envelope.GetEvent().GetEventId() {
		return ErrInvalidResponse
	}
	return nil
}

func validateProtocolError(value *agentv1.TelemetryError, batchID string, maximumRetry time.Duration) error {
	if value == nil || value.Error == nil || value.Error.Code == commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED ||
		!safeMetadataText(value.Error.Message, 256) || value.RelatedBatchId != nil && value.GetRelatedBatchId() != batchID ||
		durationInvalid(value.Error.RetryAfterDuration, maximumRetry) {
		return ErrInvalidResponse
	}
	if !value.Error.Retryable {
		return ErrPermanentProtocol
	}
	return retryError{cause: ErrBackpressure, after: durationValue(value.Error.RetryAfterDuration)}
}

func safeMetadataText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validateResponseEnvelope(response *agentv1.StreamTelemetryResponse, sequence uint64) error {
	if response == nil || response.Stream == nil || !canonicalUUID(response.Stream.MessageId) || response.Stream.Sequence != sequence ||
		response.Stream.SentTime == nil || response.Stream.SentTime.CheckValid() != nil || response.Payload == nil {
		return ErrInvalidResponse
	}
	return nil
}

func receiveWithTimeout(
	ctx context.Context,
	cancel context.CancelFunc,
	stream grpc.BidiStreamingClient[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse],
	timeout time.Duration,
) (*agentv1.StreamTelemetryResponse, error) {
	type result struct {
		response *agentv1.StreamTelemetryResponse
		err      error
	}
	received := make(chan result, 1)
	go func() {
		response, err := stream.Recv()
		received <- result{response: response, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case value := <-received:
		return value.response, value.err
	case <-timer.C:
		cancel()
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

func streamMetadata(messageID string, sequence uint64, now time.Time) *commonv1.StreamMetadata {
	return &commonv1.StreamMetadata{MessageId: messageID, Sequence: sequence, SentTime: timestamppb.New(now.UTC())}
}

func durationInvalid(value *durationpb.Duration, maximum time.Duration) bool {
	return value != nil && (value.CheckValid() != nil || value.AsDuration() < 0 || value.AsDuration() > maximum)
}

func durationValue(value *durationpb.Duration) time.Duration {
	if value == nil {
		return 0
	}
	return value.AsDuration()
}

func permanentTransportError(err error) bool {
	code := status.Code(err)
	return code == codes.Unauthenticated || code == codes.PermissionDenied || code == codes.FailedPrecondition ||
		code == codes.InvalidArgument || code == codes.Unimplemented
}

func (c *Client) waitBackoff(ctx context.Context, delay time.Duration) error {
	delay = c.jitter(delay)
	if delay < 0 || delay > c.config.MaximumBackoff {
		delay = c.config.MaximumBackoff
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum/2 {
		return maximum
	}
	return current * 2
}

func (c *Client) closeSession() {
	if c.session != nil {
		c.session.close()
		c.session = nil
	}
}

func (s *clientSession) close() {
	if s == nil {
		return
	}
	s.cancel()
	_ = s.stream.CloseSend()
	_ = s.connection.Close()
}

var _ Sender = (*Client)(nil)
