package systemothersettings

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid platform system other settings input")
	ErrInvalidStore        = errors.New("invalid platform system other settings store")
	ErrPermissionDenied    = errors.New("platform system other settings permission denied")
	ErrRevisionConflict    = errors.New("platform system other settings revision conflict")
	ErrIdempotencyConflict = errors.New("platform system other settings idempotency conflict")
	ErrUnavailable         = errors.New("platform system other settings unavailable")
)

const schema = "cdnca.platform-system-other-settings/v1"

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Actor struct {
	UserID, ScopeID uuid.UUID
	ScopeKind       string
}

type Settings struct {
	SourceIPHeader         string  `json:"source_ip_header"`
	APIKeyEnabled          bool    `json:"api_key_enabled"`
	DNSProtection          string  `json:"dns_protection"`
	RecordRepairMode       string  `json:"record_repair_mode"`
	SyncBatch              int     `json:"sync_batch"`
	SyncScope              string  `json:"sync_scope"`
	DisableFailedSyncNodes bool    `json:"disable_failed_sync_nodes"`
	ResourceRank           int     `json:"resource_rank"`
	HTTPProxy              string  `json:"http_proxy"`
	TCPFactor              float64 `json:"tcp_factor"`
	// L4DrainMaxSeconds bounds how long existing L4 sessions keep running on
	// the worker generation a configuration change retires; 0 is unlimited.
	// A save that omits it keeps the stored value.
	L4DrainMaxSeconds *int `json:"l4_drain_max_seconds,omitempty"`
	// DomainOwnershipPolicy is the #12 verification level: off,
	// wildcard_only (default) or all. A save that omits it keeps the stored
	// value.
	DomainOwnershipPolicy *string `json:"domain_ownership_policy,omitempty"`
	// CertificateExpiryNoticeDays are the days before expiry a certificate's
	// owner is told (internal/certnotify): descending, 1..60,
	// at most 8. A save that omits it keeps the stored value.
	CertificateExpiryNoticeDays []int `json:"certificate_expiry_notice_days,omitempty"`
	// RuleIntelContribution is "向官方贡献规则情报" (ADR 0011 §4.3:
	// on by default, a platform administrator may turn it off).
	// A save that omits it keeps the stored value.
	RuleIntelContribution *bool `json:"rule_intel_contribution,omitempty"`
}

const (
	// DefaultL4DrainMaxSeconds matches the agent default (24 h).
	DefaultL4DrainMaxSeconds = 86_400
	MaxL4DrainMaxSeconds     = 7 * 86_400
)

type Document struct {
	Schema    string    `json:"schema"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Value     Settings  `json:"value"`
	Replayed  bool      `json:"-"`
}

type SaveRequest struct {
	ExpectedRevision          int64
	Value                     Settings
	IdempotencyKey, RequestID string
}

func DefaultSettings() Settings {
	return Settings{
		SourceIPHeader: "X-Real-IP", APIKeyEnabled: true, DNSProtection: "", RecordRepairMode: "repair",
		SyncBatch: 1000, SyncScope: "line_group", DisableFailedSyncNodes: false,
		ResourceRank: 100, TCPFactor: 1.1, L4DrainMaxSeconds: intPointer(DefaultL4DrainMaxSeconds),
		DomainOwnershipPolicy:       stringPointer(DefaultDomainOwnershipPolicy),
		CertificateExpiryNoticeDays: append([]int(nil), DefaultCertificateExpiryNoticeDays...),
		RuleIntelContribution:       boolPointer(true),
	}
}

// DefaultCertificateExpiryNoticeDays matches certnotify.DefaultNoticeDays.
var DefaultCertificateExpiryNoticeDays = []int{30, 14, 7, 3, 1}

// DefaultDomainOwnershipPolicy matches domaintrust.DefaultPolicy.
const DefaultDomainOwnershipPolicy = "wildcard_only"

func intPointer(value int) *int          { return &value }
func stringPointer(value string) *string { return &value }
func boolPointer(value bool) *bool       { return &value }
func Schema() string                     { return schema }
