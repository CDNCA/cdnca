package telemetryclient

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
)

var (
	ErrInvalidConfiguration = errors.New("invalid telemetry client configuration")
	ErrInvalidPublication   = errors.New("invalid event spool publication")
	ErrInvalidResponse      = errors.New("invalid telemetry gateway response")
	ErrPermanentProtocol    = errors.New("permanent telemetry protocol failure")
	ErrPartialAcknowledged  = errors.New("telemetry batch was partially acknowledged")
	ErrBackpressure         = errors.New("telemetry gateway applied backpressure")
	// ErrAttributionUnconfirmed: a scoped record's site is carried by no
	// configuration scope the node has confirmed (EDGE-TELEMETRY-
	// a first generation that ran but whose rollback failed
	// leaves its scope without a current release). The record is valid; it
	// stays queued, unsent and unacknowledged, until its scope is confirmed.
	ErrAttributionUnconfirmed = errors.New("telemetry record site has no confirmed configuration scope")
	// errRecordInvalid: the record itself, not its batch or the session, can
	// never be published; the records before it still go.
	errRecordInvalid = fmt.Errorf("%w: record content", ErrInvalidPublication)
)

type Record struct {
	Kind          string
	MessageID     string
	FirstSequence uint64
	LastSequence  uint64
	LastEventID   string
	EventCount    int
	Payload       []byte

	// trusted: built by Publisher.trustedRecord from an event spool
	// envelope whose events all have siteID and no package subscription.
	trusted         bool
	siteID          string
	configVersionID string
}

// ConnectionsRecord is the in-memory form of one eventspool connections
// publication. ReceiptID is the exact durable publication identity and must
// survive reconnects unchanged.
type ConnectionsRecord struct {
	ReceiptID string
	Sequence  uint64
	Envelope  *agentv1.ConnectionsMetricEnvelopeV1
}

type Batch struct {
	Records     []Record
	Connections []ConnectionsRecord
}

type SendAck struct {
	Accepted int
}

type Sender interface {
	Send(context.Context, Batch) (SendAck, error)
}

type DurableCursor interface {
	AcknowledgedSequence(context.Context) (uint64, error)
}

type Config struct {
	NodeID            string
	BootID            string
	SupportedVersions *commonv1.ProtocolVersionRange
	Cursor            DurableCursor
	ConnectionsCursor DurableCursor
	// ScopedRecords is set on MULTI_TENANT_RUNTIME nodes: every record names
	// the configuration scope that published its site and the Gateway must
	// confirm scoped_records before any record is sent. A configuration scope
	// is an access scope ID, never the payload tenant ID. ScopeForSite maps a
	// site to the scope whose current release carries it and is required when
	// ScopedRecords is set; a site it does not map holds the queue
	// (ErrAttributionUnconfirmed).
	ScopedRecords bool
	ScopeForSite  func(siteID string) (string, bool)
	// HeldVersion (optional, scoped records): the scope holds the records of
	// this configuration version. The version ran on the node but the control
	// plane has not confirmed it (an apply whose rollback failed,
	//), so the Gateway's authorization may not
	// carry it: the records wait (ErrAttributionUnconfirmed) instead of being
	// rejected on every retry.
	HeldVersion func(scopeID, configVersionID string) bool

	HandshakeTimeout time.Duration
	AckTimeout       time.Duration
	InitialBackoff   time.Duration
	MaximumBackoff   time.Duration

	MaxRecordsPerBatch int
	MaxRecordBytes     int
	MaxBatchBytes      int
}

func DefaultConfig() Config {
	return Config{
		SupportedVersions: &commonv1.ProtocolVersionRange{
			Minimum: &commonv1.ProtocolVersion{Major: 1},
			Maximum: &commonv1.ProtocolVersion{Major: 1},
		},
		HandshakeTimeout:   10 * time.Second,
		AckTimeout:         10 * time.Second,
		InitialBackoff:     250 * time.Millisecond,
		MaximumBackoff:     30 * time.Second,
		MaxRecordsPerBatch: 64,
		MaxRecordBytes:     1 << 20,
		MaxBatchBytes:      4 << 20,
	}
}

func (c Config) validate() error {
	if !canonicalUUID(c.NodeID) || !canonicalUUID(c.BootID) || c.Cursor == nil {
		return fmt.Errorf("%w: node, boot, and durable cursor are required", ErrInvalidConfiguration)
	}
	if c.ScopedRecords && c.ScopeForSite == nil {
		return fmt.Errorf("%w: scoped records require a site scope resolver", ErrInvalidConfiguration)
	}
	if !validVersionRange(c.SupportedVersions) {
		return fmt.Errorf("%w: supported protocol versions are invalid", ErrInvalidConfiguration)
	}
	if c.HandshakeTimeout <= 0 || c.AckTimeout <= 0 || c.InitialBackoff <= 0 || c.MaximumBackoff < c.InitialBackoff {
		return fmt.Errorf("%w: timeout or reconnect policy is invalid", ErrInvalidConfiguration)
	}
	if c.HandshakeTimeout > time.Hour || c.AckTimeout > time.Hour || c.MaximumBackoff > time.Hour {
		return fmt.Errorf("%w: timeout or reconnect policy exceeds its bound", ErrInvalidConfiguration)
	}
	if c.MaxRecordsPerBatch < 1 || c.MaxRecordsPerBatch > 1000 || c.MaxRecordBytes < 256 || c.MaxRecordBytes > 1<<20 ||
		c.MaxBatchBytes < c.MaxRecordBytes || c.MaxBatchBytes > 16<<20 || c.MaxBatchBytes > math.MaxInt {
		return fmt.Errorf("%w: batch limits are invalid", ErrInvalidConfiguration)
	}
	return nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validVersionRange(value *commonv1.ProtocolVersionRange) bool {
	return value != nil && value.Minimum != nil && value.Maximum != nil && value.Minimum.Major > 0 && value.Maximum.Major > 0 &&
		compareVersion(value.Minimum, value.Maximum) <= 0
}

func compareVersion(left, right *commonv1.ProtocolVersion) int {
	if left.Major < right.Major || left.Major == right.Major && left.Minor < right.Minor {
		return -1
	}
	if left.Major == right.Major && left.Minor == right.Minor {
		return 0
	}
	return 1
}

func versionInRange(value *commonv1.ProtocolVersion, supported *commonv1.ProtocolVersionRange) bool {
	return value != nil && validVersionRange(supported) && compareVersion(value, supported.Minimum) >= 0 && compareVersion(value, supported.Maximum) <= 0
}

type retryError struct {
	cause error
	after time.Duration
}

func (e retryError) Error() string { return e.cause.Error() }
func (e retryError) Unwrap() error { return e.cause }

func RetryAfter(err error) time.Duration {
	var value retryError
	if errors.As(err, &value) {
		return value.after
	}
	return 0
}
