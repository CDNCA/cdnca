package analyticsconnections

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	DefaultDeadLetterPageSize = 100
	MaximumDeadLetterPageSize = 1000
	MaximumDeadLetterScan     = 4096
)

var (
	ErrDeadLetterReceiptInvalidRequest = errors.New("invalid connections dead-letter receipt request")
	ErrDeadLetterReceiptUnavailable    = errors.New("connections dead-letter receipt unavailable")
	ErrDeadLetterReceiptNotFound       = errors.New("connections dead-letter receipt not found")
	ErrDeadLetterReceiptInvalid        = errors.New("invalid connections dead-letter receipt")
	ErrDeadLetterReceiptConflict       = errors.New("connections dead-letter receipt conflict")
)

// DeadLetterReceiptView is a digest-only projection of a durable JetStream DLQ fact.
// Stream/SourceStream identify the original delivery stream; DeadLetterStream and
// DeadLetterSequence identify the durable terminal publication.
type DeadLetterReceiptView struct {
	MetadataVersion       uint32                `json:"metadata_version"`
	DeadLetterID          string                `json:"dead_letter_id"`
	MessageID             string                `json:"message_id"`
	EnvelopeSHA256        string                `json:"envelope_sha256,omitempty"`
	BatchID               string                `json:"batch_id,omitempty"`
	ReceiptID             string                `json:"receipt_id,omitempty"`
	EventID               string                `json:"event_id,omitempty"`
	TenantID              string                `json:"tenant_id,omitempty"`
	InstallationID        string                `json:"installation_id,omitempty"`
	SiteID                string                `json:"site_id,omitempty"`
	PackageSubscriptionID string                `json:"package_subscription_id,omitempty"`
	Stream                string                `json:"stream"`
	SourceStream          string                `json:"source_stream"`
	Durable               string                `json:"durable"`
	SourceStreamSequence  uint64                `json:"source_stream_sequence"`
	ConsumerSequence      uint64                `json:"consumer_sequence"`
	Attempt               uint64                `json:"attempt"`
	MaxDeliver            uint64                `json:"max_deliver"`
	FailureReason         DeliveryFailureReason `json:"failure_reason"`
	PayloadSHA256         string                `json:"payload_sha256"`
	CanonicalEventSHA256  string                `json:"canonical_event_sha256,omitempty"`
	EvidenceSHA256        string                `json:"evidence_sha256,omitempty"`
	DeadLetterStream      string                `json:"dead_letter_stream"`
	DeadLetterSequence    uint64                `json:"dead_letter_sequence"`
	CreatedAt             time.Time             `json:"created_at"`
	SettledAt             time.Time             `json:"settled_at"`
	Poison                bool                  `json:"poison,omitempty"`
}

type DeadLetterQuery struct {
	TenantID      string
	AfterSequence uint64
	Limit         int
}

type DeadLetterReceiptStore interface {
	ListDeadLetters(context.Context, DeadLetterQuery) ([]DeadLetterReceiptView, error)
	GetDeadLetter(context.Context, string) (DeadLetterReceiptView, error)
	GetDeadLetterBySequence(context.Context, uint64) (DeadLetterReceiptView, error)
}

type DeadLetterJetStream interface {
	StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error)
	GetMsg(string, uint64, ...nats.JSOpt) (*nats.RawStreamMsg, error)
}

type NATSDlqReceiptStore struct {
	jetstream        DeadLetterJetStream
	operationTimeout time.Duration
}

func NewNATSDlqReceiptStore(jetstream DeadLetterJetStream, operationTimeout time.Duration) (*NATSDlqReceiptStore, error) {
	if jetstream == nil || operationTimeout <= 0 || operationTimeout > 30*time.Second {
		return nil, ErrDeadLetterReceiptInvalidRequest
	}
	store := &NATSDlqReceiptStore{jetstream: jetstream, operationTimeout: operationTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	if _, err := store.streamInfo(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *NATSDlqReceiptStore) ListDeadLetters(ctx context.Context, query DeadLetterQuery) ([]DeadLetterReceiptView, error) {
	receipts, _, err := store.ListDeadLettersPage(ctx, query)
	return receipts, err
}

// ListDeadLettersPage returns the last globally scanned sequence when more
// stream records remain, even if tenant filtering produced no receipts.
func (store *NATSDlqReceiptStore) ListDeadLettersPage(ctx context.Context, query DeadLetterQuery) ([]DeadLetterReceiptView, uint64, error) {
	if store == nil || store.jetstream == nil || ctx == nil || query.Limit < 1 || query.Limit > MaximumDeadLetterPageSize {
		return nil, 0, ErrDeadLetterReceiptInvalidRequest
	}
	if query.TenantID != "" {
		tenantID, err := uuid.Parse(query.TenantID)
		if err != nil || tenantID == uuid.Nil || tenantID.String() != query.TenantID {
			return nil, 0, ErrDeadLetterReceiptInvalidRequest
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	info, err := store.streamInfo(ctx)
	if err != nil {
		return nil, 0, err
	}
	first, last := info.State.FirstSeq, info.State.LastSeq
	if last == 0 || first == 0 || last < first {
		return []DeadLetterReceiptView{}, 0, nil
	}
	start := first
	if query.AfterSequence >= start {
		if query.AfterSequence == ^uint64(0) {
			return []DeadLetterReceiptView{}, 0, nil
		}
		start = query.AfterSequence + 1
	}
	if start > last {
		return []DeadLetterReceiptView{}, 0, nil
	}
	end := last
	if available := uint64(MaximumDeadLetterScan); end-start+1 > available {
		end = start + available - 1
	}
	result := make([]DeadLetterReceiptView, 0, query.Limit)
	seen := make(map[string]DeadLetterReceiptView, query.Limit)
	var lastScanned uint64
	for sequence := start; ; sequence++ {
		lastScanned = sequence
		receipt, getErr := store.GetDeadLetterBySequence(ctx, sequence)
		if getErr != nil && !errors.Is(getErr, ErrDeadLetterReceiptNotFound) {
			return nil, 0, getErr
		}
		if getErr == nil && (query.TenantID == "" || receipt.TenantID == query.TenantID) {
			if previous, exists := seen[receipt.DeadLetterID]; exists {
				if !sameDeadLetterFact(previous, receipt) {
					return nil, 0, ErrDeadLetterReceiptConflict
				}
			} else {
				seen[receipt.DeadLetterID] = receipt
				result = append(result, receipt)
			}
		}
		if len(result) >= query.Limit || sequence == end {
			break
		}
	}
	if lastScanned < last {
		return result, lastScanned, nil
	}
	return result, 0, nil
}

func (store *NATSDlqReceiptStore) GetDeadLetter(ctx context.Context, deadLetterID string) (DeadLetterReceiptView, error) {
	if store == nil || store.jetstream == nil || ctx == nil || !validDeadLetterID(deadLetterID) {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptInvalidRequest
	}
	info, err := store.streamInfo(ctx)
	if err != nil {
		return DeadLetterReceiptView{}, err
	}
	if info.State.FirstSeq == 0 || info.State.LastSeq < info.State.FirstSeq ||
		info.State.LastSeq-info.State.FirstSeq+1 > MaximumDeadLetterScan {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptUnavailable
	}
	var matched DeadLetterReceiptView
	for sequence := info.State.FirstSeq; ; sequence++ {
		receipt, getErr := store.GetDeadLetterBySequence(ctx, sequence)
		if getErr != nil && !errors.Is(getErr, ErrDeadLetterReceiptNotFound) {
			return DeadLetterReceiptView{}, getErr
		}
		if getErr == nil && receipt.DeadLetterID == deadLetterID {
			if matched.DeadLetterID == "" {
				matched = receipt
			} else if !sameDeadLetterFact(matched, receipt) {
				return DeadLetterReceiptView{}, ErrDeadLetterReceiptConflict
			}
		}
		if sequence == info.State.LastSeq {
			break
		}
	}
	if matched.DeadLetterID != "" {
		return matched, nil
	}
	return DeadLetterReceiptView{}, ErrDeadLetterReceiptNotFound
}

func (store *NATSDlqReceiptStore) GetDeadLetterBySequence(ctx context.Context, sequence uint64) (DeadLetterReceiptView, error) {
	if store == nil || store.jetstream == nil || ctx == nil || sequence == 0 {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptInvalidRequest
	}
	operationCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	message, err := store.jetstream.GetMsg(connectionsDeadLetterStream, sequence, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptNotFound
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return DeadLetterReceiptView{}, ctxErr
		}
		return DeadLetterReceiptView{}, fmt.Errorf("get connections dead-letter receipt: %w", err)
	}
	if message == nil || message.Sequence != sequence {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptConflict
	}
	return decodeDeadLetterReceipt(message)
}

func (store *NATSDlqReceiptStore) streamInfo(ctx context.Context) (*nats.StreamInfo, error) {
	if ctx == nil {
		return nil, ErrDeadLetterReceiptInvalidRequest
	}
	operationCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	info, err := store.jetstream.StreamInfo(connectionsDeadLetterStream, nats.Context(operationCtx))
	cancel()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("read connections dead-letter stream: %w", err)
	}
	if info == nil || info.Config.Name != connectionsDeadLetterStream || !containsExactSubject(info.Config.Subjects, connectionsDeadLetterSubject) {
		return nil, ErrDeadLetterReceiptUnavailable
	}
	return info, nil
}

func decodeDeadLetterReceipt(message *nats.RawStreamMsg) (DeadLetterReceiptView, error) {
	if message == nil || message.Sequence == 0 || message.Subject != connectionsDeadLetterSubject || message.Time.IsZero() {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptInvalid
	}
	messageIDs := message.Header.Values(nats.MsgIdHdr)
	if len(messageIDs) != 1 || messageIDs[0] == "" {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptConflict
	}
	var envelope DeadLetterEnvelope
	if err := decodeStrictJSON(message.Data, &envelope); err == nil && validateDeadLetterEnvelope(envelope) == nil {
		receipt, receiptErr := NewDeadLetterReceipt(envelope)
		if receiptErr != nil || messageIDs[0] != receipt.DeadLetterID {
			return DeadLetterReceiptView{}, ErrDeadLetterReceiptConflict
		}
		created := message.Time.UTC()
		return DeadLetterReceiptView{
			MetadataVersion: DeliveryMetadataVersion, DeadLetterID: receipt.DeadLetterID, MessageID: messageIDs[0],
			EnvelopeSHA256: receipt.EnvelopeSHA256, BatchID: envelope.BatchID, ReceiptID: envelope.ReceiptID,
			EventID: envelope.EventID, TenantID: envelope.TenantID, InstallationID: envelope.InstallationID,
			SiteID: envelope.SiteID, PackageSubscriptionID: envelope.PackageSubscriptionID, Stream: envelope.Stream,
			SourceStream: envelope.Stream, Durable: envelope.Durable, SourceStreamSequence: envelope.StreamSequence,
			ConsumerSequence: envelope.ConsumerSequence, Attempt: envelope.Attempt, MaxDeliver: envelope.MaxDeliver,
			FailureReason: envelope.FailureReason, PayloadSHA256: envelope.PayloadSHA256,
			CanonicalEventSHA256: envelope.CanonicalEventSHA256, EvidenceSHA256: envelope.EvidenceSHA256,
			DeadLetterStream: connectionsDeadLetterStream, DeadLetterSequence: message.Sequence,
			CreatedAt: created, SettledAt: created,
		}, nil
	}
	return decodePoisonDeadLetter(message, messageIDs[0])
}

func decodePoisonDeadLetter(message *nats.RawStreamMsg, messageID string) (DeadLetterReceiptView, error) {
	var poison struct {
		MetadataVersion  uint32                `json:"metadata_version"`
		Stream           string                `json:"stream"`
		Durable          string                `json:"durable"`
		StreamSequence   uint64                `json:"stream_sequence"`
		ConsumerSequence uint64                `json:"consumer_sequence"`
		Attempt          uint64                `json:"attempt"`
		MaxDeliver       uint64                `json:"max_deliver"`
		FailureReason    DeliveryFailureReason `json:"failure_reason"`
		PayloadSHA256    string                `json:"payload_sha256"`
	}
	if err := decodeStrictJSON(message.Data, &poison); err != nil || poison.MetadataVersion != DeliveryMetadataVersion ||
		!validID(poison.Stream) || !validID(poison.Durable) || poison.StreamSequence == 0 || poison.ConsumerSequence == 0 ||
		poison.Attempt == 0 || poison.MaxDeliver == 0 || poison.Attempt > poison.MaxDeliver ||
		poison.FailureReason != DeliveryFailureInvalid || !validDeadLetterDigest(poison.PayloadSHA256) {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptInvalid
	}
	identity := DeadLetterIdentityDigest(poison.Stream, poison.StreamSequence, poison.FailureReason)
	if messageID != digestHex(identity) {
		return DeadLetterReceiptView{}, ErrDeadLetterReceiptConflict
	}
	bodyDigest := sha256.Sum256(message.Data)
	created := message.Time.UTC()
	return DeadLetterReceiptView{
		MetadataVersion: DeliveryMetadataVersion, DeadLetterID: messageID, MessageID: messageID,
		EnvelopeSHA256: digestHex(bodyDigest), Stream: poison.Stream, SourceStream: poison.Stream,
		Durable: poison.Durable, SourceStreamSequence: poison.StreamSequence,
		ConsumerSequence: poison.ConsumerSequence, Attempt: poison.Attempt, MaxDeliver: poison.MaxDeliver,
		FailureReason: poison.FailureReason, PayloadSHA256: poison.PayloadSHA256,
		DeadLetterStream: connectionsDeadLetterStream, DeadLetterSequence: message.Sequence,
		CreatedAt: created, SettledAt: created, Poison: true,
	}, nil
}

func decodeStrictJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrDeadLetterReceiptInvalid
	}
	return nil
}

func sameDeadLetterFact(left, right DeadLetterReceiptView) bool {
	left.DeadLetterSequence, right.DeadLetterSequence = 0, 0
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	left.SettledAt, right.SettledAt = time.Time{}, time.Time{}
	return left == right
}

func validDeadLetterID(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && !allZero(decoded)
}

func containsExactSubject(subjects []string, expected string) bool {
	for _, subject := range subjects {
		if subject == expected {
			return true
		}
	}
	return false
}
