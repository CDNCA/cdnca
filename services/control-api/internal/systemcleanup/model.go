package systemcleanup

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid platform system cleanup settings input")
	ErrInvalidStore        = errors.New("invalid platform system cleanup settings store")
	ErrPermissionDenied    = errors.New("platform system cleanup settings permission denied")
	ErrRevisionConflict    = errors.New("platform system cleanup settings revision conflict")
	ErrIdempotencyConflict = errors.New("platform system cleanup settings idempotency conflict")
	ErrUnavailable         = errors.New("platform system cleanup settings unavailable")
)

const schema = "cdnca.platform-system-cleanup-settings/v1"

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type Settings struct {
	CleanupCacheDays int `json:"cleanup_cache_days"`
	// AuditRetentionDays is the operation-log retention per event category
	// (unified-log, audit.Categories); 0 keeps forever. Missing categories
	// read as their catalog default.
	AuditRetentionDays     map[string]int `json:"audit_retention_days"`
	AccessLogsDays         int            `json:"access_logs_days"`
	NodeMetricsDays        int            `json:"node_metrics_days"`
	BandwidthHistoryDays   int            `json:"bandwidth_history_days"`
	BlacklistHistoryDays   int            `json:"blacklist_history_days"`
	NodeTrafficHistoryDays int            `json:"node_traffic_history_days"`
}

type Document struct {
	Schema    string    `json:"schema"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Value     Settings  `json:"value"`
	Replayed  bool      `json:"-"`
}

type SaveRequest struct {
	ExpectedRevision int64
	Value            Settings
	IdempotencyKey   string
	RequestID        string
}

func DefaultSettings() Settings {
	return Settings{CleanupCacheDays: 30, AuditRetentionDays: DefaultAuditRetention(), AccessLogsDays: 7,
		NodeMetricsDays: 7, BandwidthHistoryDays: 90, BlacklistHistoryDays: 7, NodeTrafficHistoryDays: 45}
}

// DefaultAuditRetention returns the catalog default days per audit category.
func DefaultAuditRetention() map[string]int {
	out := map[string]int{}
	for _, info := range audit.Categories() {
		out[string(info.Category)] = info.RetentionDays
	}
	return out
}

// WithAuditDefaults returns days with every missing category set to its default.
func WithAuditDefaults(days map[string]int) map[string]int {
	out := DefaultAuditRetention()
	for category, value := range days {
		out[category] = value
	}
	return out
}

// ValidAuditRetention reports whether every key is an audit category and
// every value is within 0..3650 days.
func ValidAuditRetention(days map[string]int) bool {
	for category, value := range days {
		if !audit.ValidCategory(audit.Category(category)) || !validDays(value) {
			return false
		}
	}
	return true
}

func Schema() string { return schema }
