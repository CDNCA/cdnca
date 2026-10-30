package analyticsconnectionshttp

import (
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
)

const (
	defaultDeadLetterLimit         = 50
	maximumDeadLetterLimit         = 200
	maximumDeadLetterQueryBytes    = 2048
	defaultDeadLetterQueryTimeout  = 5 * time.Second
	maximumDeadLetterQueryTimeout  = 30 * time.Second
	defaultDeadLetterResponseBytes = 1 << 20
	maximumDeadLetterResponseBytes = 4 << 20
)

var (
	ErrDeadLetterInvalidRequest  = errors.New("invalid connections dead-letter request")
	ErrDeadLetterUnauthenticated = errors.New("connections dead-letter authentication required")
	ErrDeadLetterPermission      = errors.New("connections dead-letter permission denied")
	ErrDeadLetterInvalidResponse = errors.New("invalid connections dead-letter response")
	ErrDeadLetterTooLarge        = errors.New("connections dead-letter response too large")
	ErrDeadLetterUnavailable     = errors.New("connections dead-letter unavailable")
	ErrDeadLetterNotFound        = errors.New("connections dead-letter not found")
)

type DeadLetterStore = analyticsconnections.DeadLetterReceiptStore

type DeadLetterListRequest struct {
	TenantID      string
	AfterSequence uint64
	Limit         int
}

type DeadLetterItem struct {
	DeadLetterID       string     `json:"dead_letter_id"`
	BatchID            string     `json:"batch_id"`
	ReceiptID          string     `json:"receipt_id"`
	EventID            string     `json:"event_id"`
	TenantID           string     `json:"tenant_id"`
	Reason             string     `json:"reason"`
	Attempt            uint64     `json:"attempt"`
	MaxDeliver         uint64     `json:"max_deliver"`
	SourceStream       string     `json:"source_stream"`
	SourceSequence     uint64     `json:"source_sequence"`
	ConsumerSequence   uint64     `json:"consumer_sequence"`
	DeadLetterStream   string     `json:"dead_letter_stream"`
	DeadLetterSequence uint64     `json:"dead_letter_sequence"`
	CreatedAt          time.Time  `json:"created_at"`
	SettledAt          *time.Time `json:"settled_at,omitempty"`
	PayloadDigest      string     `json:"payload_digest"`
}

type DeadLetterPage struct {
	Items             []DeadLetterItem `json:"items"`
	NextAfterSequence uint64           `json:"next_after_sequence,omitempty"`
}

type DLQHandlerConfig struct {
	QueryTimeout     time.Duration
	MaxResponseBytes int
}
