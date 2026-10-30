package analytics

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

type IngestWriter interface {
	WriteAccessEvents(context.Context, string, []AccessEvent) error
	WriteSecurityEvents(context.Context, string, []SecurityEvent) error
}

type IngestProcessorConfig struct {
	OperationTimeout       time.Duration
	NakBaseDelay           time.Duration
	NakMaxDelay            time.Duration
	MaxDeliver             int
	MaxBatchEvents         int
	Now                    func() time.Time
	Logger                 *slog.Logger
	History                IngestHistoryAuthorityV1
	HistoryGeneration      IngestHistoryGenerationV1
	WatermarkPolicy        AnalyticsWatermarkPolicyV1
	WatermarkAuthority     AnalyticsWatermarkBatchAuthorityV1
	WatermarkStateProvider AnalyticsWatermarkStateProviderV1
}

type IngestBatchResult struct {
	Fetched      int
	Acknowledged int
	Naked        int
	Terminated   int
	WriteBatches int
}

type IngestProcessor struct {
	decoder                *IngestDecoder
	writer                 IngestWriter
	isolation              IsolationSink
	operationTimeout       time.Duration
	nakBaseDelay           time.Duration
	nakMaxDelay            time.Duration
	maxDeliver             uint64
	maxBatchEvents         int
	now                    func() time.Time
	logger                 *slog.Logger
	history                IngestHistoryAuthorityV1
	historyGeneration      IngestHistoryGenerationV1
	watermarkPolicy        AnalyticsWatermarkPolicyV1
	watermarkAuthority     AnalyticsWatermarkBatchAuthorityV1
	watermarkStateProvider AnalyticsWatermarkStateProviderV1
}

type AnalyticsWatermarkStateProviderV1 interface {
	WatermarkState(context.Context, AnalyticsWatermarkKeyV1) (AnalyticsWatermarkDependencyStateV1, AnalyticsWatermarkStateV1, error)
}

type parsedIngest struct {
	decoded      DecodedIngest
	deliveries   []IngestDelivery
	receipt      IngestReceiptV1
	receiptState IngestReceiptStateV1
}

type installationAuthorityDelivery interface {
	InstallationID() string
}

type terminalEvidenceDelivery interface {
	TerminalEvidenceConfirmed(context.Context) (bool, error)
	ConfirmTerminalEvidence(context.Context, IsolationRecord) error
}

type coordinatedIsolationSink interface {
	RecordTerminal(context.Context, IngestDelivery, IsolationRecord) error
}

const (
	writerPermanentReason   = "WRITER_PERMANENT"
	writerExhaustedReason   = "WRITER_RETRY_EXHAUSTED"
	watermarkRejectedReason = "WATERMARK_REJECTED"
)

type ingestChunk struct {
	kind           string
	items          []*parsedIngest
	accessEvents   []AccessEvent
	securityEvents []SecurityEvent
}

func NewIngestProcessor(
	decoder *IngestDecoder,
	writer IngestWriter,
	isolation IsolationSink,
	config IngestProcessorConfig,
) (*IngestProcessor, error) {
	if decoder == nil || writer == nil || isolation == nil || config.OperationTimeout <= 0 ||
		config.NakBaseDelay <= 0 || config.NakMaxDelay < config.NakBaseDelay || config.MaxDeliver < 2 ||
		config.MaxBatchEvents <= 0 || config.MaxBatchEvents > DefaultMaxEventsPerEnvelope || config.History == nil ||
		ValidateIngestHistoryGenerationV1(config.HistoryGeneration) != nil ||
		(config.WatermarkPolicy.Enabled && (config.WatermarkAuthority == nil || config.WatermarkStateProvider == nil)) {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &IngestProcessor{
		decoder: decoder, writer: writer, isolation: isolation,
		operationTimeout: config.OperationTimeout, nakBaseDelay: config.NakBaseDelay,
		nakMaxDelay: config.NakMaxDelay, maxDeliver: uint64(config.MaxDeliver),
		maxBatchEvents: config.MaxBatchEvents, now: config.Now, logger: config.Logger,
		history: config.History, historyGeneration: config.HistoryGeneration,
		watermarkPolicy: config.WatermarkPolicy, watermarkAuthority: config.WatermarkAuthority,
		watermarkStateProvider: config.WatermarkStateProvider,
	}, nil
}

func (processor *IngestProcessor) Process(ctx context.Context, deliveries []IngestDelivery) (IngestBatchResult, error) {
	result := IngestBatchResult{Fetched: len(deliveries)}
	if processor == nil || ctx == nil || len(deliveries) == 0 {
		return result, ErrInvalidInput
	}
	settlementCtx, cancelSettlement := context.WithTimeout(context.Background(), processor.operationTimeout)
	defer cancelSettlement()
	parsed := make([]*parsedIngest, 0, len(deliveries))
	type receiptCoalescingKey struct {
		messageID      string
		streamSequence uint64
	}
	byReceipt := make(map[receiptCoalescingKey]*parsedIngest, len(deliveries))
	byMessageID := make(map[string]*parsedIngest, len(deliveries))
	var settlementErrors []error
	for _, delivery := range deliveries {
		if delivery == nil {
			settlementErrors = append(settlementErrors, ErrInvalidInput)
			continue
		}
		if terminal, ok := delivery.(terminalEvidenceDelivery); ok {
			confirmed, err := terminal.TerminalEvidenceConfirmed(settlementCtx)
			if err != nil {
				settlementErrors = append(settlementErrors, errors.Join(err, processor.nak(settlementCtx, delivery, &result)))
				continue
			}
			if confirmed {
				if err := processor.termOrRetry(settlementCtx, delivery, &result); err != nil {
					settlementErrors = append(settlementErrors, err)
				}
				continue
			}
		}
		decoded, err := processor.decoder.Decode(delivery.Subject(), delivery.MessageID(), delivery.Data())
		if err != nil {
			if settleErr := processor.isolateOrRetry(settlementCtx, delivery, RejectionCode(err), &result, false); settleErr != nil {
				settlementErrors = append(settlementErrors, settleErr)
			}
			continue
		}
		authority, ok := delivery.(installationAuthorityDelivery)
		if !ok || !validBatchID(authority.InstallationID()) ||
			(decoded.InstallationID != "" && decoded.InstallationID != authority.InstallationID()) {
			if settleErr := processor.isolateOrRetry(settlementCtx, delivery, RejectIdentityMismatch, &result, false); settleErr != nil {
				settlementErrors = append(settlementErrors, settleErr)
			}
			continue
		}
		decoded.InstallationID = authority.InstallationID()
		for index := range decoded.AccessEvents {
			decoded.AccessEvents[index].InstallationID = decoded.InstallationID
		}
		for index := range decoded.SecurityEvents {
			decoded.SecurityEvents[index].InstallationID = decoded.InstallationID
		}
		for index := range decoded.AccessWindowContributions {
			decoded.AccessWindowContributions[index].InstallationID = decoded.InstallationID
		}
		for index := range decoded.SubscriptionMinutes {
			decoded.SubscriptionMinutes[index].InstallationID = decoded.InstallationID
		}
		identity := byMessageID[decoded.MessageID]
		if identity != nil &&
			(identity.decoded.PayloadDigest != decoded.PayloadDigest || identity.decoded.InstallationID != decoded.InstallationID) {
			if settleErr := processor.isolateOrRetry(settlementCtx, delivery, RejectIdentityMismatch, &result, false); settleErr != nil {
				settlementErrors = append(settlementErrors, settleErr)
			}
			continue
		}
		coalescingKey := receiptCoalescingKey{messageID: decoded.MessageID, streamSequence: delivery.StreamSequence()}
		if existing := byReceipt[coalescingKey]; existing != nil {
			existing.deliveries = append(existing.deliveries, delivery)
			continue
		}
		receipt, receiptErr := NewIngestReceiptV1(processor.historyGeneration, delivery.StreamSequence(), decoded)
		if receiptErr != nil {
			if settleErr := processor.isolateOrRetry(settlementCtx, delivery, RejectIdentityMismatch, &result, false); settleErr != nil {
				settlementErrors = append(settlementErrors, settleErr)
			}
			continue
		}
		receiveCtx, cancelReceive := context.WithTimeout(ctx, processor.operationTimeout)
		receiptState, receiptErr := processor.history.Receive(receiveCtx, receipt)
		cancelReceive()
		if receiptErr != nil {
			if errors.Is(receiptErr, ErrIngestReceiptConflict) || errors.Is(receiptErr, ErrIngestHistoryGenerationChanged) {
				if settleErr := processor.isolateOrRetry(settlementCtx, delivery, RejectReceiptConflict, &result, false); settleErr != nil {
					settlementErrors = append(settlementErrors, settleErr)
				}
			} else if settleErr := processor.nak(settlementCtx, delivery, &result); settleErr != nil {
				settlementErrors = append(settlementErrors, errors.Join(receiptErr, settleErr))
			}
			continue
		}
		item := &parsedIngest{decoded: decoded, deliveries: []IngestDelivery{delivery}, receipt: receipt, receiptState: receiptState}
		byReceipt[coalescingKey] = item
		if identity == nil {
			byMessageID[decoded.MessageID] = item
		}
		parsed = append(parsed, item)
	}

	chunk := newIngestChunk()
	flush := func() {
		if len(chunk.items) == 0 {
			return
		}
		if err := processor.processChunk(ctx, settlementCtx, chunk, &result); err != nil {
			settlementErrors = append(settlementErrors, err)
		}
		chunk = newIngestChunk()
	}
	for _, item := range parsed {
		chunk.add(item)
		flush()
	}
	return result, errors.Join(settlementErrors...)
}

func (processor *IngestProcessor) processChunk(
	ctx context.Context,
	settlementCtx context.Context,
	chunk *ingestChunk,
	result *IngestBatchResult,
) error {
	if len(chunk.items) != 1 {
		return ErrInvalidInput
	}
	item := chunk.items[0]
	if item.receiptState >= IngestReceiptStatePrepared {
		return processor.ackChunk(settlementCtx, chunk, result)
	}
	if err := processor.authorizeChunkWatermark(ctx, chunk); err != nil {
		var settlementErrors []error
		for _, delivery := range item.deliveries {
			if errors.Is(err, ErrAnalyticsWatermarkUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				if nakErr := processor.nak(settlementCtx, delivery, result); nakErr != nil {
					settlementErrors = append(settlementErrors, nakErr)
				}
				continue
			}
			if settleErr := processor.isolateOrRetry(settlementCtx, delivery, watermarkRejectedReason, result, false); settleErr != nil {
				settlementErrors = append(settlementErrors, settleErr)
			}
		}
		return errors.Join(append(settlementErrors, err)...)
	}
	token := item.receipt.ClickHouseToken
	operationCtx, cancel := context.WithTimeout(ctx, processor.operationTimeout)
	var writeErr error
	switch chunk.kind {
	case AccessEnvelopeType:
		writeErr = processor.writer.WriteAccessEvents(operationCtx, token, chunk.accessEvents)
	case SecurityEnvelopeType:
		writeErr = processor.writer.WriteSecurityEvents(operationCtx, token, chunk.securityEvents)
	case AccessWindowEnvelopeType:
		// Receive committed the immutable PostgreSQL contribution in the same
		// transaction as the ingest receipt. Coverage is not a ClickHouse event.
	case SubscriptionMinuteEnvelopeType:
		if writer, ok := processor.writer.(SubscriptionMinuteWriter); ok {
			writeErr = writer.WriteSubscriptionMinutes(operationCtx, token, item.decoded.SubscriptionMinutes)
		} else {
			writeErr = ErrInvalidInput
		}
	default:
		writeErr = ErrInvalidInput
	}
	cancel()
	if chunk.kind != AccessWindowEnvelopeType {
		result.WriteBatches++
	}
	if writeErr == nil {
		prepareCtx, cancelPrepare := context.WithTimeout(ctx, processor.operationTimeout)
		_, prepareErr := processor.history.MarkPrepared(prepareCtx, item.receipt)
		cancelPrepare()
		if prepareErr != nil {
			settlementErrors := []error{prepareErr}
			for _, delivery := range item.deliveries {
				if err := processor.nak(settlementCtx, delivery, result); err != nil {
					settlementErrors = append(settlementErrors, errors.Join(prepareErr, err))
				}
			}
			return errors.Join(settlementErrors...)
		}
		item.receiptState = IngestReceiptStatePrepared
		return processor.ackChunk(settlementCtx, chunk, result)
	}
	processor.logger.Warn("analytics ingest write failed",
		"class", writerErrorClass(writeErr), "messages", deliveryCount(chunk.items))
	var settlementErrors []error
	for _, item := range chunk.items {
		for _, delivery := range item.deliveries {
			if retryableWriterError(writeErr) && delivery.Attempts() < processor.maxDeliver {
				if err := processor.nak(settlementCtx, delivery, result); err != nil {
					settlementErrors = append(settlementErrors, err)
				}
				continue
			}
			reason := writerPermanentReason
			if retryableWriterError(writeErr) {
				reason = writerExhaustedReason
			}
			if err := processor.isolateOrRetry(settlementCtx, delivery, reason, result, true); err != nil {
				settlementErrors = append(settlementErrors, err)
			}
		}
	}
	return errors.Join(settlementErrors...)
}

func (processor *IngestProcessor) authorizeChunkWatermark(ctx context.Context, chunk *ingestChunk) error {
	if processor == nil || !processor.watermarkPolicy.Enabled {
		return nil
	}
	if chunk != nil && (chunk.kind == AccessWindowEnvelopeType || chunk.kind == SubscriptionMinuteEnvelopeType) {
		return nil
	}
	if ctx == nil || chunk == nil || len(chunk.items) != 1 || processor.watermarkAuthority == nil || processor.watermarkStateProvider == nil {
		return ErrAnalyticsWatermarkUnavailable
	}
	item := chunk.items[0]
	if item == nil {
		return ErrInvalidInput
	}
	events := make([]AnalyticsWatermarkEventV1, 0)
	key := AnalyticsWatermarkKeyV1{InstallationID: item.receipt.Key.InstallationID, Kind: chunk.kind}
	if chunk.kind == AccessEnvelopeType {
		events = make([]AnalyticsWatermarkEventV1, 0, len(chunk.accessEvents))
		for _, event := range chunk.accessEvents {
			if key.TenantID == "" {
				key.TenantID = event.TenantID
			}
			if event.TenantID != key.TenantID {
				return ErrAnalyticsWatermarkInvalidRequest
			}
			digest, err := CanonicalAccessEventDigestV1(event)
			if err != nil {
				return err
			}
			events = append(events, AnalyticsWatermarkEventV1{Kind: chunk.kind, EventID: event.EventID, OccurredAt: event.OccurredAt, CanonicalDigest: digest})
		}
	} else if chunk.kind == SecurityEnvelopeType {
		events = make([]AnalyticsWatermarkEventV1, 0, len(chunk.securityEvents))
		for _, event := range chunk.securityEvents {
			if key.TenantID == "" {
				key.TenantID = event.TenantID
			}
			if event.TenantID != key.TenantID {
				return ErrAnalyticsWatermarkInvalidRequest
			}
			digest, err := CanonicalSecurityEventDigestV1(event)
			if err != nil {
				return err
			}
			events = append(events, AnalyticsWatermarkEventV1{Kind: chunk.kind, EventID: event.EventID, OccurredAt: event.OccurredAt, CanonicalDigest: digest})
		}
	} else {
		return ErrAnalyticsWatermarkInvalidRequest
	}
	dependency, lastKnownGood, err := processor.watermarkStateProvider.WatermarkState(ctx, key)
	if err != nil {
		return ErrAnalyticsWatermarkUnavailable
	}
	request := AnalyticsWatermarkBatchRequestV1{
		Policy: processor.watermarkPolicy, DependencyState: dependency, Key: key,
		Receipt: item.receipt, LastKnownGood: lastKnownGood, Events: events,
	}
	fenceCtx, cancel := context.WithTimeout(ctx, processor.operationTimeout)
	defer cancel()
	_, err = AuthorizeAnalyticsWriteBatchV1(fenceCtx, processor.watermarkAuthority, request)
	return err
}

func (processor *IngestProcessor) ackChunk(ctx context.Context, chunk *ingestChunk, result *IngestBatchResult) error {
	scheduleRecovery := func() error {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), processor.operationTimeout)
		defer cancel()
		return processor.history.ScheduleRecovery(recoveryCtx, processor.historyGeneration)
	}
	var acknowledgementErrors []error
	for _, item := range chunk.items {
		if err := scheduleRecovery(); err != nil {
			acknowledgementErrors = append(acknowledgementErrors, err)
			for _, delivery := range item.deliveries {
				if nakErr := processor.nak(ctx, delivery, result); nakErr != nil {
					acknowledgementErrors = append(acknowledgementErrors, nakErr)
				}
			}
			continue
		}
		allAcknowledged := true
		for _, delivery := range item.deliveries {
			err := delivery.Ack(ctx)
			if err != nil {
				allAcknowledged = false
				acknowledgementErrors = append(acknowledgementErrors, err)
				continue
			}
			result.Acknowledged++
		}
		if allAcknowledged {
			if err := processor.history.MarkBrokerAckObserved(ctx, item.receipt.Key); err != nil {
				acknowledgementErrors = append(acknowledgementErrors, err)
			}
		}
	}
	return errors.Join(acknowledgementErrors...)
}

func (processor *IngestProcessor) isolateOrRetry(
	ctx context.Context,
	delivery IngestDelivery,
	reason string,
	result *IngestBatchResult,
	evidenceOnly bool,
) error {
	if reason == "" {
		reason = RejectInvalidEvent
	}
	record := isolationRecord(delivery, reason, processor.now().UTC())
	record.WireEvidenceOnly = record.WireEvidenceOnly || evidenceOnly
	var sinkErr error
	if coordinated, ok := processor.isolation.(coordinatedIsolationSink); ok {
		sinkErr = coordinated.RecordTerminal(ctx, delivery, record)
	} else {
		sinkErr = processor.isolation.Record(ctx, record)
	}
	if sinkErr != nil {
		processor.logger.Error("analytics isolation persistence failed", "reason", reason)
		return errors.Join(sinkErr, processor.nak(ctx, delivery, result))
	}
	if _, coordinated := processor.isolation.(coordinatedIsolationSink); !coordinated {
		terminal, ok := delivery.(terminalEvidenceDelivery)
		if !ok {
			return processor.termOrRetry(ctx, delivery, result)
		}
		if err := terminal.ConfirmTerminalEvidence(ctx, record); err != nil {
			return errors.Join(err, processor.nak(ctx, delivery, result))
		}
	}
	return processor.termOrRetry(ctx, delivery, result)
}

func (processor *IngestProcessor) termOrRetry(
	ctx context.Context,
	delivery IngestDelivery,
	result *IngestBatchResult,
) error {
	recoveryCtx, cancel := context.WithTimeout(context.Background(), processor.operationTimeout)
	err := processor.history.ScheduleRecovery(recoveryCtx, processor.historyGeneration)
	cancel()
	if err != nil {
		return errors.Join(err, processor.nak(ctx, delivery, result))
	}
	if err := delivery.Term(ctx); err != nil {
		return errors.Join(err, processor.nak(ctx, delivery, result))
	}
	result.Terminated++
	return nil
}

func (processor *IngestProcessor) nak(ctx context.Context, delivery IngestDelivery, result *IngestBatchResult) error {
	delay := boundedNakDelay(delivery.Attempts(), processor.nakBaseDelay, processor.nakMaxDelay)
	err := delivery.Nak(ctx, delay)
	if err == nil {
		result.Naked++
	}
	return err
}

func newIngestChunk() *ingestChunk {
	return &ingestChunk{}
}

func (chunk *ingestChunk) add(item *parsedIngest) {
	if len(chunk.items) == 0 {
		chunk.kind = item.decoded.Kind
		switch chunk.kind {
		case AccessEnvelopeTypeV2:
			chunk.kind = AccessEnvelopeType
		case SecurityEnvelopeTypeV2:
			chunk.kind = SecurityEnvelopeType
		}
	}
	chunk.items = append(chunk.items, item)
	for _, event := range item.decoded.AccessEvents {
		chunk.accessEvents = append(chunk.accessEvents, event)
	}
	for _, event := range item.decoded.SecurityEvents {
		chunk.securityEvents = append(chunk.securityEvents, event)
	}
}

func deliveryCount(items []*parsedIngest) int {
	total := 0
	for _, item := range items {
		total += len(item.deliveries)
	}
	return total
}

func isolationRecord(delivery IngestDelivery, reason string, isolatedAt time.Time) IsolationRecord {
	payloadDigest := sha256Sum(delivery.Data())
	messageID := delivery.MessageID()
	if !validBatchID(messageID) {
		messageID = ""
	}
	subject := delivery.Subject()
	if len(subject) > 256 {
		subject = "invalid-subject"
	}
	wire := &IsolationWire{Subject: subject, Payload: append([]byte(nil), delivery.Data()...)}
	wireEvidenceOnly := false
	if provider, ok := delivery.(isolationWireProvider); ok {
		wire = provider.IsolationWire()
		if subject == "" && wire != nil {
			subject = wire.Subject
			wireEvidenceOnly = true
		}
	}
	return IsolationRecord{
		SchemaVersion: IngestSchemaVersion, ReasonCode: reason, MessageID: messageID,
		Subject: subject, PayloadSHA256: hex.EncodeToString(payloadDigest[:]), PayloadBytes: len(delivery.Data()),
		Attempts: delivery.Attempts(), StreamSequence: delivery.StreamSequence(), IsolatedAt: isolatedAt,
		WireEvidenceOnly: wireEvidenceOnly, Wire: wire,
	}
}

func boundedNakDelay(attempt uint64, base, maximum time.Duration) time.Duration {
	delay := base
	for current := uint64(1); current < attempt && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	return min(delay, maximum)
}

func retryableWriterError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrTransport) || errors.Is(err, ErrInvalidResponse) || errors.Is(err, ErrResponseTooLarge) ||
		errors.Is(err, ErrIngestWriteOutcomeUnknown) {
		return true
	}
	var httpError *HTTPError
	if !errors.As(err, &httpError) {
		return false
	}
	// 401/403 是写入凭据或权限故障，与消息内容无关：保留原消息退避重试，修复权限后可恢复，
	// 不能当作 poison 隔离（docs/runbooks/analytics-storage.md「ACK、重试与 poison 处置」）。
	return httpError.Retryable() ||
		httpError.StatusCode == http.StatusUnauthorized || httpError.StatusCode == http.StatusForbidden
}

func writerErrorClass(err error) string {
	if retryableWriterError(err) {
		return "retryable"
	}
	return "permanent"
}
