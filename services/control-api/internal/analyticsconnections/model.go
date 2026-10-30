package analyticsconnections

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	SchemaVersion            uint32 = 1
	ConnectionsSubjectPrefix        = "cdnca.connections.v1"
	DefaultMaxResponseBytes         = 1 << 20
	DefaultMaxBatchBytes            = 4 << 20
	DefaultOperationTimeout         = 5 * time.Second
	DefaultConnectTimeout           = 3 * time.Second
	Predecessor006Up                = "ad7191e2f4895f489bb3534c314460e01f60c66c7ae7e38abf9cf70bef39f721"
	Predecessor006Down              = "6c08c80b18c9d753175efb5453735b4bd926eca74fb27ab64498a590ec36914a"
	DeliveryMetadataVersion  uint32 = 1
)

var (
	ErrInvalidDelivery          = errors.New("invalid connections delivery")
	ErrReceiptConflict          = errors.New("connections receipt conflict")
	ErrClickHouseUnavailable    = errors.New("connections ClickHouse unavailable")
	ErrClickHouseOutcomeUnknown = errors.New("connections ClickHouse outcome unknown")
	ErrInvalidConfiguration     = errors.New("invalid connections configuration")
)

type ReceiptState string

const (
	StateReceived           ReceiptState = "received"
	StateClickHousePrepared ReceiptState = "ch_prepared"
	StateBrokerAckObserved  ReceiptState = "broker_ack_observed"
)

type PubAck struct {
	Stream    string
	Sequence  uint64
	Duplicate bool
}

type DeliveryFailureReason string

const (
	DeliveryFailureNone                  DeliveryFailureReason = ""
	DeliveryFailureInvalid               DeliveryFailureReason = "invalid_delivery"
	DeliveryFailureReceiptConflict       DeliveryFailureReason = "receipt_conflict"
	DeliveryFailureClickHouseUnavailable DeliveryFailureReason = "clickhouse_unavailable"
	DeliveryFailureOutcomeUnknown        DeliveryFailureReason = "clickhouse_outcome_unknown"
	DeliveryFailureMaxDeliver            DeliveryFailureReason = "max_deliver_exhausted"
)

type Delivery struct {
	BatchID          string
	ReceiptID        string
	NodeID           string
	Domain           string
	ListenPort       uint16
	Payload          []byte
	Envelope         *agentv1.ConnectionsMetricEnvelopeV1
	Stream           string
	Durable          string
	StreamSequence   uint64
	ConsumerSequence uint64
	MetadataVersion  uint32
	Attempt          uint64
	MaxDeliver       uint64
	FailureReason    DeliveryFailureReason
	PubAck           PubAck
	Ack              func(context.Context) error
	Nak              func(context.Context, time.Duration) error
	Term             func(context.Context) error
}

type DeadLetterEnvelope struct {
	MetadataVersion       uint32                `json:"metadata_version"`
	BatchID               string                `json:"batch_id"`
	ReceiptID             string                `json:"receipt_id"`
	EventID               string                `json:"event_id"`
	TenantID              string                `json:"tenant_id"`
	InstallationID        string                `json:"installation_id"`
	SiteID                string                `json:"site_id"`
	PackageSubscriptionID string                `json:"package_subscription_id"`
	Stream                string                `json:"stream"`
	Durable               string                `json:"durable"`
	StreamSequence        uint64                `json:"stream_sequence"`
	ConsumerSequence      uint64                `json:"consumer_sequence"`
	Attempt               uint64                `json:"attempt"`
	MaxDeliver            uint64                `json:"max_deliver"`
	FailureReason         DeliveryFailureReason `json:"failure_reason"`
	PayloadSHA256         string                `json:"payload_sha256"`
	CanonicalEventSHA256  string                `json:"canonical_event_sha256"`
	EvidenceSHA256        string                `json:"evidence_sha256"`
}

type DeadLetterReceipt struct {
	MetadataVersion  uint32                `json:"metadata_version"`
	DeadLetterID     string                `json:"dead_letter_id"`
	EnvelopeSHA256   string                `json:"envelope_sha256"`
	Stream           string                `json:"stream"`
	StreamSequence   uint64                `json:"stream_sequence"`
	ConsumerSequence uint64                `json:"consumer_sequence"`
	Attempt          uint64                `json:"attempt"`
	MaxDeliver       uint64                `json:"max_deliver"`
	FailureReason    DeliveryFailureReason `json:"failure_reason"`
}

type Receipt struct {
	SchemaVersion         uint32
	ConfigVersionID       string
	ReceiptID             string
	BatchID               string
	EventID               string
	TenantID              string
	InstallationID        string
	SiteID                string
	NodeID                string
	Domain                string
	ListenPort            uint16
	PackageSubscriptionID string
	OccurredAt            time.Time
	Connections           uint64
	PayloadSHA256         [sha256.Size]byte
	CanonicalEventSHA256  [sha256.Size]byte
	EvidenceSHA256        [sha256.Size]byte
	SourceWatermark       uint64
	FinalizedThrough      time.Time
	Stream                string
	Durable               string
	StreamSequence        uint64
	ConsumerSequence      uint64
	PubAck                PubAck
	ClickHouseToken       string
	State                 ReceiptState
}

type Store interface {
	Prepare(context.Context, Receipt) error
	MarkBrokerAckObserved(context.Context, Receipt, PubAck) error
}

func ValidateDeliveryMetadata(delivery Delivery) error {
	if delivery.MetadataVersion != DeliveryMetadataVersion || delivery.Attempt == 0 || delivery.MaxDeliver == 0 ||
		delivery.Attempt > delivery.MaxDeliver || !validID(delivery.Stream) || !validID(delivery.Durable) ||
		delivery.StreamSequence == 0 || delivery.ConsumerSequence == 0 || delivery.Ack == nil || delivery.Nak == nil ||
		delivery.Term == nil || !validDeliveryFailureReason(delivery.FailureReason, true) {
		return ErrInvalidDelivery
	}
	return nil
}

func NewDeadLetterEnvelope(delivery Delivery, receipt Receipt) (DeadLetterEnvelope, error) {
	if ValidateDeliveryMetadata(delivery) != nil || delivery.FailureReason == DeliveryFailureNone ||
		validateReceipt(receipt) != nil || receipt.BatchID != delivery.BatchID || receipt.ReceiptID != delivery.ReceiptID ||
		receipt.Stream != delivery.Stream || receipt.Durable != delivery.Durable ||
		receipt.StreamSequence != delivery.StreamSequence || receipt.ConsumerSequence != delivery.ConsumerSequence {
		return DeadLetterEnvelope{}, ErrInvalidDelivery
	}
	return DeadLetterEnvelope{
		MetadataVersion: DeliveryMetadataVersion, BatchID: receipt.BatchID, ReceiptID: receipt.ReceiptID,
		EventID: receipt.EventID, TenantID: receipt.TenantID, InstallationID: receipt.InstallationID,
		SiteID: receipt.SiteID, PackageSubscriptionID: receipt.PackageSubscriptionID,
		Stream: receipt.Stream, Durable: receipt.Durable, StreamSequence: receipt.StreamSequence,
		ConsumerSequence: receipt.ConsumerSequence, Attempt: delivery.Attempt, MaxDeliver: delivery.MaxDeliver,
		FailureReason: delivery.FailureReason, PayloadSHA256: digestHex(receipt.PayloadSHA256),
		CanonicalEventSHA256: digestHex(receipt.CanonicalEventSHA256), EvidenceSHA256: digestHex(receipt.EvidenceSHA256),
	}, nil
}

func NewDeadLetterReceipt(envelope DeadLetterEnvelope) (DeadLetterReceipt, error) {
	if validateDeadLetterEnvelope(envelope) != nil {
		return DeadLetterReceipt{}, ErrInvalidDelivery
	}
	identity := DeadLetterIdentityDigest(envelope.Stream, envelope.StreamSequence, envelope.FailureReason)
	evidence := deadLetterEnvelopeDigest(envelope)
	return DeadLetterReceipt{
		MetadataVersion: DeliveryMetadataVersion, DeadLetterID: digestHex(identity), EnvelopeSHA256: digestHex(evidence),
		Stream: envelope.Stream, StreamSequence: envelope.StreamSequence, ConsumerSequence: envelope.ConsumerSequence,
		Attempt: envelope.Attempt, MaxDeliver: envelope.MaxDeliver, FailureReason: envelope.FailureReason,
	}, nil
}

func DeadLetterIdentityDigest(stream string, streamSequence uint64, reason DeliveryFailureReason) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.connections.dead-letter.identity.v1\x00"))
	writeDeadLetterValue(hash, stream)
	writeDeadLetterValue(hash, strconv.FormatUint(streamSequence, 10))
	writeDeadLetterValue(hash, string(reason))
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func deadLetterEnvelopeDigest(envelope DeadLetterEnvelope) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.connections.dead-letter.envelope.v1\x00"))
	for _, value := range []string{
		strconv.FormatUint(uint64(envelope.MetadataVersion), 10), envelope.BatchID, envelope.ReceiptID,
		envelope.EventID, envelope.TenantID, envelope.InstallationID, envelope.SiteID, envelope.PackageSubscriptionID,
		envelope.Stream, envelope.Durable, strconv.FormatUint(envelope.StreamSequence, 10),
		strconv.FormatUint(envelope.ConsumerSequence, 10), strconv.FormatUint(envelope.Attempt, 10),
		strconv.FormatUint(envelope.MaxDeliver, 10), string(envelope.FailureReason), envelope.PayloadSHA256,
		envelope.CanonicalEventSHA256, envelope.EvidenceSHA256,
	} {
		writeDeadLetterValue(hash, value)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func writeDeadLetterValue(hash interface{ Write([]byte) (int, error) }, value string) {
	_, _ = hash.Write([]byte(value))
	_, _ = hash.Write([]byte{0})
}

func validateDeadLetterEnvelope(envelope DeadLetterEnvelope) error {
	if envelope.MetadataVersion != DeliveryMetadataVersion || !validID(envelope.BatchID) || !validID(envelope.ReceiptID) ||
		!validID(envelope.EventID) || !validID(envelope.TenantID) || !validID(envelope.InstallationID) ||
		!validID(envelope.SiteID) || !validID(envelope.PackageSubscriptionID) || !validID(envelope.Stream) ||
		!validID(envelope.Durable) || envelope.StreamSequence == 0 || envelope.ConsumerSequence == 0 ||
		envelope.Attempt == 0 || envelope.MaxDeliver == 0 || envelope.Attempt > envelope.MaxDeliver ||
		!validDeliveryFailureReason(envelope.FailureReason, false) || !validDeadLetterDigest(envelope.PayloadSHA256) ||
		!validDeadLetterDigest(envelope.CanonicalEventSHA256) || !validDeadLetterDigest(envelope.EvidenceSHA256) {
		return ErrInvalidDelivery
	}
	return nil
}

func validDeliveryFailureReason(reason DeliveryFailureReason, allowNone bool) bool {
	if allowNone && reason == DeliveryFailureNone {
		return true
	}
	switch reason {
	case DeliveryFailureInvalid, DeliveryFailureReceiptConflict, DeliveryFailureClickHouseUnavailable,
		DeliveryFailureOutcomeUnknown, DeliveryFailureMaxDeliver:
		return true
	default:
		return false
	}
}

func validDeadLetterDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	digest, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, item := range digest {
		if item != 0 {
			return true
		}
	}
	return false
}

func ValidateDelivery(delivery Delivery) (Receipt, error) {
	if !validID(delivery.BatchID) || !validID(delivery.ReceiptID) || !validID(delivery.Stream) ||
		!validID(delivery.Durable) || delivery.StreamSequence == 0 || delivery.ConsumerSequence == 0 ||
		delivery.PubAck.Sequence == 0 || !validID(delivery.PubAck.Stream) || delivery.Ack == nil || delivery.Envelope == nil {
		return Receipt{}, ErrInvalidDelivery
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(delivery.Envelope)
	if err != nil {
		return Receipt{}, ErrInvalidDelivery
	}
	metric, err := analytics.DecodeConnectionsMetric(payload)
	if err != nil {
		return Receipt{}, ErrInvalidDelivery
	}
	if delivery.PubAck.Stream != delivery.Stream || (metric.SchemaVersion != SchemaVersion && metric.SchemaVersion != 2) ||
		metric.FinalizedThrough.Before(metric.OccurredAt) || !validConnectionDimensions(metric.NodeID, metric.Domain, metric.ListenPort) {
		return Receipt{}, ErrInvalidDelivery
	}
	payloadDigest := sha256.Sum256(payload)
	receipt := Receipt{
		SchemaVersion: metric.SchemaVersion, ConfigVersionID: metric.ConfigVersionID, ReceiptID: delivery.ReceiptID, BatchID: delivery.BatchID,
		EventID: metric.EventID, TenantID: metric.TenantID, InstallationID: metric.InstallationID,
		SiteID: metric.SiteID, NodeID: metric.NodeID, Domain: metric.Domain, ListenPort: metric.ListenPort,
		PackageSubscriptionID: metric.PackageSubscriptionID, OccurredAt: metric.OccurredAt,
		Connections: metric.Connections, PayloadSHA256: payloadDigest, CanonicalEventSHA256: metric.CanonicalEventSHA256,
		EvidenceSHA256: metric.EvidenceSHA256, SourceWatermark: metric.SourceWatermark, FinalizedThrough: metric.FinalizedThrough,
		Stream: delivery.Stream, Durable: delivery.Durable, StreamSequence: delivery.StreamSequence,
		ConsumerSequence: delivery.ConsumerSequence, PubAck: delivery.PubAck, State: StateReceived,
	}
	receipt.ClickHouseToken = ClickHouseInsertToken(receipt)
	return receipt, nil
}

func Process(ctx context.Context, delivery Delivery, store Store) error {
	if ctx == nil || store == nil {
		return ErrInvalidConfiguration
	}
	receipt, err := ValidateDelivery(delivery)
	if err != nil {
		return err
	}
	if err := store.Prepare(ctx, receipt); err != nil {
		return err
	}
	if err := delivery.Ack(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrClickHouseOutcomeUnknown
	}
	if err := store.MarkBrokerAckObserved(ctx, receipt, receipt.PubAck); err != nil {
		return err
	}
	return nil
}

func ClickHouseInsertToken(receipt Receipt) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.connections.insert.v1\x00"))
	_, _ = hash.Write([]byte(receipt.ReceiptID))
	_, _ = hash.Write([]byte("\x00"))
	_, _ = hash.Write(receipt.CanonicalEventSHA256[:])
	return hex.EncodeToString(hash.Sum(nil))
}

func ReceiptIdentityDigest(receipt Receipt) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.connections.receipt.v1\x00"))
	for _, value := range []string{receipt.TenantID, receipt.InstallationID, receipt.SiteID, receipt.NodeID, receipt.Domain, strconv.FormatUint(uint64(receipt.ListenPort), 10), receipt.PackageSubscriptionID, receipt.EventID} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	_, _ = hash.Write(receipt.CanonicalEventSHA256[:])
	return sha256.Sum256(hash.Sum(nil))
}

func validID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validConnectionDimensions(nodeID, domain string, listenPort uint16) bool {
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed == uuid.Nil || parsed.String() != nodeID || listenPort == 0 || domain == "" ||
		net.ParseIP(domain) != nil || strings.ToLower(domain) != domain || strings.TrimSpace(domain) != domain ||
		strings.HasSuffix(domain, ".") || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func digestHex(value [sha256.Size]byte) string { return hex.EncodeToString(value[:]) }

func parseDigestHex(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != sha256.Size {
		return digest, fmt.Errorf("invalid digest")
	}
	copy(digest[:], decoded)
	return digest, nil
}
