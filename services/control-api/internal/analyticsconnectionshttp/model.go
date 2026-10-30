package analyticsconnectionshttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

const (
	defaultRetentionLimit         = 100
	maximumRetentionLimit         = 1000
	maximumRetentionWindow        = 31 * 24 * time.Hour
	maximumRetentionQueryBytes    = 4096
	defaultRetentionQueryTimeout  = 5 * time.Second
	maximumRetentionQueryTimeout  = 30 * time.Second
	defaultRetentionResponseBytes = 1 << 20
	maximumRetentionResponseBytes = 16 << 20
)

var (
	ErrInvalidRequest   = errors.New("invalid connections retention request")
	ErrUnauthenticated  = errors.New("connections retention authentication required")
	ErrPermissionDenied = errors.New("connections retention permission denied")
	ErrInvalidResponse  = errors.New("invalid connections retention response")
	ErrResponseTooLarge = errors.New("connections retention response too large")
	ErrUnavailable      = errors.New("connections retention unavailable")
)

type AuthenticateFunc func(*http.Request) (identity.AuthenticatedSession, error)

type RetentionStoreQuery struct {
	analyticsconnections.RetentionQuery
	Limit int
}

type RetentionStore interface {
	QueryRetention(context.Context, RetentionStoreQuery) ([]analyticsconnections.RetentionRow, error)
}

type RetentionRequest struct {
	TenantID       string
	SubscriptionID string
	From           time.Time
	To             time.Time
	Limit          int
}

type RetentionItem struct {
	Metric           string    `json:"metric"`
	TenantID         string    `json:"tenant_id"`
	SubscriptionID   string    `json:"subscription_id"`
	PeriodStart      time.Time `json:"period_start"`
	PeriodEnd        time.Time `json:"period_end"`
	Value            uint64    `json:"value"`
	FinalizedThrough time.Time `json:"finalized_through"`
	SourceWatermark  uint64    `json:"source_watermark"`
	EvidenceDigest   string    `json:"evidence_digest"`
	RetentionUntil   time.Time `json:"retention_until"`
}

type RetentionPage struct {
	Items []RetentionItem `json:"items"`
}

type HandlerConfig struct {
	QueryTimeout     time.Duration
	MaxResponseBytes int
}
