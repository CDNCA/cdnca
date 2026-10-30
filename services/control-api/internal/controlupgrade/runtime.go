package controlupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	StatusDispositionAck  = "ack"
	StatusDispositionNak  = "nak"
	StatusDispositionTerm = "term"
)

type OutboxDispatcherConfig struct {
	WorkerID   string
	ClaimLease time.Duration
	ClaimBatch int
	Clock      func() time.Time
}

type outboxRuntimeStore interface {
	ClaimOutbox(context.Context, string, time.Time, time.Duration, int) ([]RolloutOutboxClaim, error)
	SettleOutbox(context.Context, RolloutOutboxSettlement) error
}

type rolloutPublisher interface {
	Publish(context.Context, RolloutOutboxMessage) (PublishResult, error)
	Stream() string
}

type OutboxDispatcher struct {
	store     outboxRuntimeStore
	publisher rolloutPublisher
	config    OutboxDispatcherConfig
}

func NewOutboxDispatcher(store outboxRuntimeStore, publisher rolloutPublisher,
	config OutboxDispatcherConfig) (*OutboxDispatcher, error) {
	if store == nil || publisher == nil || publisher.Stream() != upgradeCommandStream ||
		!upgradeNATSNamePattern.MatchString(config.WorkerID) || config.ClaimLease < time.Second ||
		config.ClaimLease > time.Hour || config.ClaimBatch < 1 || config.ClaimBatch > 100 || config.Clock == nil {
		return nil, ErrInvalidInput
	}
	return &OutboxDispatcher{store: store, publisher: publisher, config: config}, nil
}

func (dispatcher *OutboxDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	claims, err := dispatcher.store.ClaimOutbox(ctx, dispatcher.config.WorkerID, dispatcher.config.Clock(),
		dispatcher.config.ClaimLease, dispatcher.config.ClaimBatch)
	if err != nil {
		return 0, err
	}
	for index, claim := range claims {
		settlement := RolloutOutboxSettlement{OutboxID: claim.Message.ID, ClaimToken: claim.ClaimToken,
			PayloadSHA256: claim.Message.PayloadSHA256, Stream: dispatcher.publisher.Stream(),
			MessageID: commandMessageID(claim.Message.PayloadBytes)}
		published, publishErr := dispatcher.publisher.Publish(ctx, claim.Message)
		switch {
		case publishErr == nil:
			settlement.Disposition = RolloutOutboxPublished
			settlement.PublishedStream = published.Stream
			settlement.PublishedSequence = published.Sequence
		case errors.Is(publishErr, ErrPublishOutcomeUnknown):
			settlement.Disposition = RolloutOutboxUnknownOutcome
			settlement.ErrorCode = "publish_outcome_unknown"
		case errors.Is(publishErr, ErrPublishRejected):
			settlement.Disposition = RolloutOutboxRejected
			settlement.ErrorCode = "publish_rejected"
		default:
			settlement.Disposition = RolloutOutboxRetryable
			settlement.ErrorCode = "publish_unavailable"
		}
		if err := dispatcher.store.SettleOutbox(ctx, settlement); err != nil {
			return index, err
		}
	}
	return len(claims), nil
}

type StatusRuntimeConfig struct {
	Stream           string
	Consumer         string
	SubjectPrefix    string
	OperationTimeout time.Duration
	NakDelay         time.Duration
	MaxPayloadBytes  int
}

func DefaultStatusRuntimeConfig() StatusRuntimeConfig {
	return StatusRuntimeConfig{Stream: upgradeStatusStream, Consumer: upgradeStatusConsumer,
		SubjectPrefix:    upgradeStatusSubjectPrefix,
		OperationTimeout: 5 * time.Second, NakDelay: time.Second, MaxPayloadBytes: 256 << 10}
}

func (config StatusRuntimeConfig) valid() bool {
	return config.Stream == upgradeStatusStream && config.Consumer == upgradeStatusConsumer &&
		config.SubjectPrefix == upgradeStatusSubjectPrefix &&
		config.OperationTimeout > 0 && config.NakDelay > 0 && config.MaxPayloadBytes > 0 &&
		config.MaxPayloadBytes <= 1<<20
}

type statusDelivery interface {
	Subject() string
	Data() []byte
	Header() nats.Header
	Stream() string
	Consumer() string
	StreamSequence() uint64
	NumDelivered() uint64
	Ack(context.Context) error
	Nak(context.Context, time.Duration) error
	Term(context.Context) error
}

type statusConsumer interface {
	Next(context.Context) (statusDelivery, error)
	Close() error
}

type RolloutStatusRejection struct {
	ID            string
	Stream        string
	Subject       string
	PayloadSHA256 string
	HeaderSHA256  string
	Reason        string
}

type statusRuntimeStore interface {
	ResolveStatusIdentity(context.Context, string) (RolloutIdentity, error)
	RecordStatus(context.Context, RolloutIdentity, RolloutStatusReceipt) (bool, error)
	RejectStatus(context.Context, RolloutStatusRejection) error
}

type StatusProcessor struct {
	store    statusRuntimeStore
	consumer statusConsumer
	config   StatusRuntimeConfig
}

func NewStatusProcessor(store statusRuntimeStore, consumer statusConsumer,
	config StatusRuntimeConfig) (*StatusProcessor, error) {
	if store == nil || consumer == nil || !config.valid() {
		return nil, ErrInvalidInput
	}
	return &StatusProcessor{store: store, consumer: consumer, config: config}, nil
}

func (processor *StatusProcessor) ProcessOnce(ctx context.Context) (string, error) {
	delivery, err := processor.consumer.Next(ctx)
	if err != nil {
		return "", err
	}
	receipt, reason := decodeRolloutStatusDelivery(delivery, processor.config)
	if reason != "" {
		return processor.rejectAndTerm(ctx, delivery, reason)
	}
	identity, err := processor.store.ResolveStatusIdentity(ctx, receipt.CommandID)
	if err == nil {
		_, err = processor.store.RecordStatus(ctx, identity, receipt)
	}
	if err != nil {
		if permanentStatusError(err) {
			return processor.rejectAndTerm(ctx, delivery, "status_rejected")
		}
		return processor.nak(ctx, delivery, err)
	}
	operationCtx, cancel := context.WithTimeout(ctx, processor.config.OperationTimeout)
	defer cancel()
	if err := delivery.Ack(operationCtx); err != nil {
		return StatusDispositionAck, err
	}
	return StatusDispositionAck, nil
}

func (processor *StatusProcessor) rejectAndTerm(ctx context.Context, delivery statusDelivery,
	reason string) (string, error) {
	rejection := rolloutStatusRejection(delivery, processor.config.Stream, reason)
	if err := processor.store.RejectStatus(ctx, rejection); err != nil {
		return processor.nak(ctx, delivery, err)
	}
	operationCtx, cancel := context.WithTimeout(ctx, processor.config.OperationTimeout)
	defer cancel()
	if err := delivery.Term(operationCtx); err != nil {
		return StatusDispositionTerm, err
	}
	return StatusDispositionTerm, nil
}

func (processor *StatusProcessor) nak(ctx context.Context, delivery statusDelivery, cause error) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, processor.config.OperationTimeout)
	defer cancel()
	if err := delivery.Nak(operationCtx, processor.config.NakDelay); err != nil {
		return StatusDispositionNak, errors.Join(cause, err)
	}
	return StatusDispositionNak, cause
}

func permanentStatusError(err error) bool {
	return errors.Is(err, ErrInvalidPlanEvent) || errors.Is(err, ErrInvalidPlanCommand) ||
		errors.Is(err, ErrInvalidPlanTransition) || errors.Is(err, ErrPlanIdempotencyConflict) ||
		errors.Is(err, ErrStaleStatusEvidence)
}

func decodeRolloutStatusDelivery(delivery statusDelivery,
	config StatusRuntimeConfig) (RolloutStatusReceipt, string) {
	if delivery == nil || len(delivery.Data()) == 0 || len(delivery.Data()) > config.MaxPayloadBytes {
		return RolloutStatusReceipt{}, "payload_size"
	}
	if delivery.Stream() != config.Stream || delivery.Consumer() != config.Consumer || delivery.StreamSequence() == 0 {
		return RolloutStatusReceipt{}, "broker_identity"
	}
	var payload rolloutStatusPayload
	decoder := json.NewDecoder(bytes.NewReader(delivery.Data()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return RolloutStatusReceipt{}, "status_invalid"
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return RolloutStatusReceipt{}, "status_invalid"
	}
	canonical, err := json.Marshal(payload)
	if err != nil || string(canonical) != string(delivery.Data()) {
		return RolloutStatusReceipt{}, "status_noncanonical"
	}
	receipt := RolloutStatusReceipt{Schema: payload.Schema, StatusID: payload.StatusID, StatusRevision: payload.StatusRevision,
		CommandID: payload.CommandID, PlanID: payload.PlanID, PlanRevision: payload.PlanRevision,
		InstallationID: payload.InstallationID, NodeID: payload.NodeID, CommandSHA256: payload.CommandSHA256,
		StatusBytes: append([]byte(nil), delivery.Data()...), StatusSHA256: rolloutWireDigest(delivery.Data()),
		State: payload.State, ObservedAt: payload.ObservedAt, DeliveryStream: delivery.Stream(),
		DeliveryConsumer: delivery.Consumer(), DeliverySequence: delivery.StreamSequence(),
		ActiveEvidence: cloneControlActiveProbeEvidence(payload.ActiveEvidence)}
	if !validCanonicalPlanUUID(receipt.StatusID) || !validCanonicalPlanUUID(receipt.CommandID) ||
		!validCanonicalPlanUUID(receipt.PlanID) || !validCanonicalPlanUUID(receipt.InstallationID) ||
		!validCanonicalPlanUUID(receipt.NodeID) || receipt.StatusRevision == 0 ||
		receipt.StatusRevision > maxRolloutRevision || receipt.PlanRevision == 0 ||
		receipt.PlanRevision > maxRolloutRevision {
		return RolloutStatusReceipt{}, "status_identity"
	}
	legacySubject := config.SubjectPrefix + "." + receipt.NodeID
	v2Subject := upgradeStatusV2SubjectPrefix + "." + receipt.StatusID
	if delivery.Subject() != legacySubject && delivery.Subject() != v2Subject {
		return RolloutStatusReceipt{}, "status_identity"
	}
	wantHeaders := map[string]string{nats.MsgIdHdr: receipt.StatusID, nats.ExpectedStreamHdr: config.Stream,
		upgradePayloadSHA256Header: receipt.StatusSHA256, upgradeMessageKeyHeader: receipt.StatusID}
	if delivery.Subject() == v2Subject {
		wantHeaders[nats.MsgIdHdr] = "gateway-upgrade-status-v2-" + receipt.StatusID
		wantHeaders[nats.ExpectedLastSubjSeqHdr] = "0"
	}
	if !exactNATSHeaders(delivery.Header(), wantHeaders) {
		return RolloutStatusReceipt{}, "header_mismatch"
	}
	if !validRolloutStatusPayload(receipt) {
		return RolloutStatusReceipt{}, "status_invalid"
	}
	return receipt, ""
}

func exactNATSHeaders(actual nats.Header, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for name, value := range expected {
		values := actual.Values(name)
		if len(values) != 1 || values[0] != value {
			return false
		}
	}
	return true
}

func rolloutStatusRejection(delivery statusDelivery, stream, reason string) RolloutStatusRejection {
	payloadDigest := sha256.Sum256(delivery.Data())
	headerDigest := sha256.Sum256(canonicalHeaderBytes(delivery.Header()))
	id := uuid.NewSHA1(uuid.NameSpaceOID, append(append([]byte(delivery.Subject()), payloadDigest[:]...), headerDigest[:]...))
	return RolloutStatusRejection{ID: id.String(), Stream: stream, Subject: delivery.Subject(),
		PayloadSHA256: hex.EncodeToString(payloadDigest[:]), HeaderSHA256: hex.EncodeToString(headerDigest[:]), Reason: reason}
}

func canonicalHeaderBytes(header nats.Header) []byte {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	var encoded []byte
	for _, name := range names {
		encoded = append(encoded, name...)
		encoded = append(encoded, 0)
		for _, value := range header.Values(name) {
			encoded = append(encoded, value...)
			encoded = append(encoded, 0)
		}
	}
	return encoded
}

func (processor *StatusProcessor) Close() error {
	if processor == nil || processor.consumer == nil {
		return nil
	}
	return processor.consumer.Close()
}
